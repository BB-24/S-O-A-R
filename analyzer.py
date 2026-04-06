#!/usr/bin/env python3
"""
Malware Analysis Automation Pipeline - Main Entry Point
Orchestrates multi-sandbox analysis with automatic normalization, merging, and report generation.
"""

import sys
import logging
import argparse
import hashlib
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("analysis.log")],
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import pipeline components
from clients.hybrid_analysis import HybridAnalysisClient
from clients.virustotal import VirusTotalClient
from clients.triage import TriageClient
from normalizers.hybrid_analysis import HybridAnalysisNormalizer
from normalizers.virustotal import VirusTotalNormalizer
from normalizers.triage import TriageNormalizer
from merger import ReportMerger
from correlator.correlation_engine import CorrelationEngine
from report_generator.html_generator import HTMLGenerator
from report_generator.json_export import JSONExporter
from schema import UnifiedReport, SandboxSource
from sandbox_guard import SandboxGuard


class MalwareAnalyzer:
    """
    Orchestrator for malware analysis pipeline.
    Manages concurrent sandbox submissions, normalizes responses, merges reports,
    extracts IOCs, performs MITRE correlation, and generates final reports.
    """

    def __init__(self, enable_triage: bool = False):
        """
        Initialize the analyzer with configured sandbox clients.
        
        Args:
            enable_triage: Whether to include Triage.com integration (optional/premium)
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.enable_triage = enable_triage
        
        # Guard: Validate environment and file safety
        self.guard = SandboxGuard()
        
        # Get API keys from environment (supports legacy aliases)
        ha_key = self._get_env_key("HYBRID_ANALYSIS_API_KEY", "HYBRID_ANALYSIS_KEY")
        vt_key = self._get_env_key("VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY")
        triage_key = self._get_env_key("TRIAGE_API_KEY", "TRIAGE_KEY")
        
        # Initialize sandbox clients with API keys
        if ha_key:
            self.ha_client = HybridAnalysisClient(ha_key)
        else:
            self.logger.warning(
                "Hybrid Analysis API key not found. Set HYBRID_ANALYSIS_API_KEY in .env"
            )
            self.ha_client = None
            
        if vt_key:
            self.vt_client = VirusTotalClient(vt_key)
        else:
            self.logger.warning(
                "VirusTotal API key not found. Set VIRUSTOTAL_API_KEY in .env"
            )
            self.vt_client = None
            
        if enable_triage and triage_key:
            self.triage_client = TriageClient(triage_key)
        elif enable_triage:
            self.logger.warning(
                "Triage enabled but TRIAGE_API_KEY not found in .env"
            )
            self.triage_client = None
        else:
            self.triage_client = None
        
        # Initialize normalizers
        self.ha_normalizer = HybridAnalysisNormalizer()
        self.vt_normalizer = VirusTotalNormalizer()
        self.triage_normalizer = TriageNormalizer() if enable_triage else None
        
        # Initialize pipeline components
        self.merger = ReportMerger()
        self.correlation_engine = CorrelationEngine()
        self.html_generator = HTMLGenerator()
        self.json_exporter = JSONExporter()
        
        # Check if at least one sandbox is configured
        if not any([self.ha_client, self.vt_client, self.triage_client]):
            raise RuntimeError(
                "No sandbox API keys configured. Set HYBRID_ANALYSIS_API_KEY, "
                "VIRUSTOTAL_API_KEY, or TRIAGE_API_KEY in .env file"
            )
        
        self.logger.info("MalwareAnalyzer initialized successfully")

    def _get_env_key(self, primary_name: str, *aliases: str) -> Optional[str]:
        """Return first valid API key from env names, ignoring placeholders."""
        candidates = [primary_name, *aliases]
        invalid_tokens = {
            "",
            "your_api_key_here",
            "your_hybrid_analysis_api_key_here",
            "your_virustotal_api_key_here",
            "your_triage_api_key_here",
            "changeme",
            "replace_me",
            "none",
            "null",
        }

        for name in candidates:
            raw_value = os.getenv(name)
            if raw_value is None:
                continue
            value = raw_value.strip().strip('"').strip("'")
            if value.lower() in invalid_tokens:
                self.logger.warning(
                    f"Environment key {name} appears to be a placeholder and will be ignored"
                )
                continue
            if value:
                return value
        return None

    def analyze(self, file_path: str, output_dir: str = "artifacts") -> Dict[str, str]:
        """
        Complete analysis pipeline: submit, fetch, normalize, merge, correlate, report.
        
        Args:
            file_path: Path to the file to analyze
            output_dir: Directory to save reports
            
        Returns:
            Dictionary with paths to generated reports
        """
        try:
            # Step 1: Validate file
            self.logger.info(f"[1/7] Validating file: {file_path}")
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_hash = self._get_file_hash(file_path)
            file_name = Path(file_path).name
            file_size = os.path.getsize(file_path)
            
            self.logger.info(f"  SHA256: {file_hash}")
            self.logger.info(f"  Size: {file_size} bytes")
            
            # Step 2: Guard checks
            self.logger.info("[2/7] Running sandbox guard checks")
            is_safe, warning = self.guard.validate_file(file_path)
            if not is_safe:
                raise ValueError(f"File failed safety checks: {warning}")
            if warning:
                self.logger.warning(f"  [!] {warning}")
            self.logger.info("  [+] File passed safety checks")
            
            # Step 3: Submit to sandboxes (concurrent)
            self.logger.info("[3/7] Submitting to sandboxes in parallel")
            sandbox_reports = self._submit_to_sandboxes(file_path, file_hash)
            
            if not sandbox_reports:
                raise RuntimeError("No sandbox reports received")
            
            self.logger.info(f"  [+] Received reports from {len(sandbox_reports)} sandbox(es)")
            
            # Step 4: Normalize reports
            self.logger.info("[4/7] Normalizing sandbox reports")
            unified_reports = self._normalize_reports(sandbox_reports)
            self.logger.info(f"  [+] Normalized {len(unified_reports)} report(s)")
            
            # Step 5: Merge reports
            self.logger.info("[5/7] Merging multi-source reports")
            merged_report = self.merger.merge(unified_reports)
            self.logger.info(f"  [+] Consensus verdict: {merged_report.consensus_verdict}")
            if merged_report.risk:
                self.logger.info(f"  [+] Risk score: {merged_report.risk.overall_score:.1f}/10")
            else:
                self.logger.info("  [+] Risk score: N/A")
            
            # Step 6: Correlate behaviors (MITRE ATT&CK mapping)
            self.logger.info("[6/7] Correlating behaviors to MITRE ATT&CK")
            merged_report = self.correlation_engine.correlate(merged_report)
            self.logger.info(f"  [+] Mapped to {len(merged_report.mitre_techniques)} MITRE technique(s)")
            
            # Step 7: Generate reports
            self.logger.info("[7/7] Generating final reports")
            output_paths = self._generate_reports(merged_report, output_dir, file_name)
            
            self.logger.info("[+] Analysis complete!")
            return output_paths
            
        except Exception as e:
            self.logger.error(f"[-] Analysis failed: {str(e)}", exc_info=True)
            raise

    def _get_file_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _submit_to_sandboxes(self, file_path: str, file_hash: str) -> Dict[str, Any]:
        """
        Submit file to available sandboxes in parallel.
        Handles API failures gracefully - continues with available services.
        """
        results = {}
        
        def submit_ha():
            if not self.ha_client:
                return None
            try:
                self.logger.info("  Submitting to Hybrid Analysis...")
                report = None
                try:
                    report = self.ha_client.get_report(file_hash)
                except Exception as lookup_error:
                    self.logger.debug(
                        f"    HA direct report lookup unavailable ({lookup_error}); submitting file"
                    )

                if not report:
                    report = self.ha_client.submit_file(file_path)
                    if report and "submission_timestamp" not in report:
                        # Wait for analysis
                        import time
                        max_wait = 300  # 5 minutes
                        elapsed = 0
                        while elapsed < max_wait:
                            time.sleep(10)
                            report = self.ha_client.get_report(file_hash)
                            if report and report.get("analysis_completed"):
                                break
                            elapsed += 10
                results["hybrid_analysis"] = report
                return "hybrid_analysis"
            except Exception as e:
                self.logger.warning(f"    [!] Hybrid Analysis failed: {str(e)}")
                return None

        def submit_vt():
            if not self.vt_client:
                return None
            try:
                self.logger.info("  Submitting to VirusTotal...")
                report = None
                try:
                    report = self.vt_client.get_report(file_hash)
                except Exception as lookup_error:
                    self.logger.debug(
                        f"    VT direct report lookup unavailable ({lookup_error}); submitting file"
                    )

                if not report:
                    submission = self.vt_client.submit_file(file_path)
                    if submission and submission.get("status") == "completed" and submission.get("raw"):
                        report = {"data": submission.get("raw")}
                    else:
                        import time
                        max_wait = 120  # 2 minutes
                        elapsed = 0
                        while elapsed < max_wait:
                            try:
                                report = self.vt_client.get_report(file_hash)
                                if report:
                                    break
                            except Exception:
                                pass
                            time.sleep(10)
                            elapsed += 10

                        if not report:
                            raise RuntimeError("VirusTotal report not available after submission")

                results["virustotal"] = report
                return "virustotal"
            except Exception as e:
                self.logger.warning(f"    [!] VirusTotal failed: {str(e)}")
                return None

        def submit_triage():
            if not self.triage_client:
                return None
            try:
                self.logger.info("  Submitting to Triage...")
                report = self.triage_client.get_report(file_hash)
                if report:
                    results["triage"] = report
                    return "triage"
                return None
            except Exception as e:
                self.logger.warning(f"    [!] Triage failed: {str(e)}")
                return None

        # Submit in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(submit_ha): "HA",
                executor.submit(submit_vt): "VT",
                executor.submit(submit_triage): "Triage"
            }
            
            for future in as_completed(futures):
                try:
                    future.result(timeout=30)
                except Exception as e:
                    self.logger.warning(f"    Task {futures[future]} timeout/error: {str(e)}")
        
        return results

    def _normalize_reports(self, sandbox_reports: Dict[str, Any]) -> List[UnifiedReport]:
        """Normalize sandbox-specific reports to unified schema."""
        unified = []
        
        if "hybrid_analysis" in sandbox_reports and sandbox_reports["hybrid_analysis"]:
            try:
                if self.ha_normalizer:
                    report = self.ha_normalizer.normalize(
                        sandbox_reports["hybrid_analysis"]
                    )
                    unified.append(report)
                    self.logger.info("  [+] HA normalized")
            except Exception as e:
                self.logger.warning(f"  [!] HA normalization failed: {str(e)}")
        
        if "virustotal" in sandbox_reports and sandbox_reports["virustotal"]:
            try:
                if self.vt_normalizer:
                    report = self.vt_normalizer.normalize(
                        sandbox_reports["virustotal"]
                    )
                    unified.append(report)
                    self.logger.info("  [+] VT normalized")
            except Exception as e:
                self.logger.warning(f"  [!] VT normalization failed: {str(e)}")
        
        if "triage" in sandbox_reports and sandbox_reports["triage"]:
            try:
                if self.triage_normalizer:
                    report = self.triage_normalizer.normalize(
                        sandbox_reports["triage"]
                    )
                    unified.append(report)
                    self.logger.info("  [+] Triage normalized")
            except Exception as e:
                self.logger.warning(f"  [!] Triage normalization failed: {str(e)}")
        
        return unified

    def _generate_reports(
        self, merged_report, output_dir: str, file_name: str
    ) -> Dict[str, str]:
        """Generate HTML and JSON reports."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        base_name = Path(file_name).stem
        html_path = Path(output_dir) / f"{base_name}_report.html"
        json_path = Path(output_dir) / f"{base_name}_report.json"
        
        # Generate HTML
        html_content = self.html_generator.generate(merged_report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.logger.info(f"  [+] HTML report: {html_path}")
        
        # Generate JSON
        json_content = self.json_exporter.export(merged_report)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)
        self.logger.info(f"  [+] JSON report: {json_path}")
        
        return {
            "html": str(html_path),
            "json": str(json_path)
        }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Malware Analysis Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py samples/malware.exe
  python analyzer.py samples/payload.bin --output-dir results
  python analyzer.py samples/sample.exe --enable-triage
        """
    )
    parser.add_argument("file", help="Path to file for analysis")
    parser.add_argument(
        "--output-dir", default="artifacts",
        help="Output directory for reports (default: artifacts)"
    )
    parser.add_argument(
        "--enable-triage", action="store_true",
        help="Enable optional Triage.com integration (requires API key)"
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = MalwareAnalyzer(enable_triage=args.enable_triage)
        results = analyzer.analyze(args.file, args.output_dir)
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print(f"HTML Report: {results['html']}")
        print(f"JSON Report: {results['json']}")
        print("="*60)
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        print(f"\n[-] Error: {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
    
    class MalwareAnalyzer:
        def __init__(self):
            self.config = {
                "hybrid_analysis_key": os.getenv("HYBRID_ANALYSIS_API_KEY"),
                "virustotal_key": os.getenv("VIRUSTOTAL_API_KEY"),
                "triage_key": os.getenv("TRIAGE_API_KEY"),
                "timeout": int(os.getenv("API_TIMEOUT", "30")),
                "max_workers": int(os.getenv("MAX_WORKERS", "3")),
            }
            self.clients = {}
            self.normalizers = {}
            self._initialize_clients()            
            self.merger = ReportMerger()
            self.correlator = CorrelationEngine()
        
        def _initialize_clients(self):
            ha_key = self.config.get("hybrid_analysis_key")
            vt_key = self.config.get("virustotal_key")
            triage_key = self.config.get("triage_key")
            
            if ha_key:
                self.clients[SandboxSource.HYBRID_ANALYSIS] = HybridAnalysisClient(ha_key, self.config["timeout"])
                self.normalizers[SandboxSource.HYBRID_ANALYSIS] = HybridAnalysisNormalizer()
                logger.info("✓ Hybrid Analysis client initialized")
            if vt_key:
                self.clients[SandboxSource.VIRUSTOTAL] = VirusTotalClient(vt_key, self.config["timeout"])
                self.normalizers[SandboxSource.VIRUSTOTAL] = VirusTotalNormalizer()
                logger.info("✓ VirusTotal client initialized")
            if triage_key:
                self.clients[SandboxSource.TRIAGE] = TriageClient(triage_key, self.config["timeout"])
                self.normalizers[SandboxSource.TRIAGE] = TriageNormalizer()
                logger.info("✓ Triage client initialized")
            if not self.clients:
                raise RuntimeError("No sandbox clients initialized")
        
        def analyze(self, file_path: str, output_dir: str = "artifacts"):
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            logger.info(f"Starting analysis of {file_path.name}")
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            logger.info(f"Submitting to {len(self.clients)} sandboxes...")
            reports = self._submit_and_fetch(str(file_path))
            if not reports:
                raise RuntimeError("No successful analyses")
            logger.info(f"Merging {len(reports)} reports...")
            merged_report = self.merger.merge(reports)
            logger.info("Correlating intelligence...")
            merged_report = self.correlator.correlate(merged_report)
            logger.info("Generating reports...")
            output_files = self._generate_reports(merged_report, output_path)
            return output_files
        
        def _submit_and_fetch(self, file_path: str):
            reports = []
            with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
                futures = {executor.submit(self._analyze_with_client, source, client, file_path): source for source, client in self.clients.items()}
                for future in as_completed(futures):
                    source = futures[future]
                    try:
                        report = future.result()
                        if report:
                            reports.append(report)
                            logger.info(f"✓ {source.value}: Report received")
                    except Exception as e:
                        logger.error(f"✗ {source.value}: {e}")
            return reports
        
        def _analyze_with_client(self, source, client, file_path):
            try:
                logger.info(f"  Submitting to {source.value}...")
                submission = client.submit_file(file_path)
                submission_id = submission["submission_id"]
                logger.info(f"  Waiting for {source.value}...")
                for attempt in range(12):
                    status = client.check_status(submission_id)
                    if status.get("is_complete"):
                        break
                    time.sleep(10)
                raw_report = client.get_report(submission_id)
                normalizer = self.normalizers[source]
                if not normalizer.validate_response(raw_report):
                    return None
                return normalizer.normalize(raw_report)
            except Exception as e:
                logger.error(f"  {source.value} failed: {e}")
                return None
        
        def _generate_reports(self, merged_report, output_path):
            output_files = {}
            json_exporter = JSONExporter()
            json_file = output_path / "report.json"
            json_exporter.export_file(merged_report, str(json_file))
            output_files["json"] = str(json_file)
            html_generator = HTMLGenerator()
            html_file = output_path / "report.html"
            html_generator.export_file(merged_report, str(html_file))
            output_files["html"] = str(html_file)
            return output_files
    
    parser = argparse.ArgumentParser(description="Malware Analysis Automation Pipeline")
    parser.add_argument("file", help="Path to file to analyze")
    parser.add_argument("-o", "--output", default="artifacts", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        logger = logging.getLogger(__name__)
        logger.info("=== Malware Analysis Pipeline ===")
        analyzer = MalwareAnalyzer()
        output_files = analyzer.analyze(args.file, args.output)
        logger.info("Analysis Results:")
        for report_type, file_path in output_files.items():
            logger.info(f"  {report_type.upper()}: {file_path}")
        logger.info("✓ Complete!")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)