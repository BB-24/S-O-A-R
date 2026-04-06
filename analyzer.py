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
from normalizers.hybrid_analysis import HybridAnalysisNormalizer
from normalizers.virustotal import VirusTotalNormalizer
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

    def __init__(self):
        """
        Initialize the analyzer with configured sandbox clients.
        
        Args:
            None
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Guard: Validate environment and file safety
        self.guard = SandboxGuard()
        
        # Get API keys from environment (supports legacy aliases)
        ha_key = self._get_env_key("HYBRID_ANALYSIS_API_KEY", "HYBRID_ANALYSIS_KEY")
        vt_key = self._get_env_key("VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY")
        
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
            
        # Initialize normalizers
        self.ha_normalizer = HybridAnalysisNormalizer()
        self.vt_normalizer = VirusTotalNormalizer()
        
        # Initialize pipeline components
        self.merger = ReportMerger()
        self.correlation_engine = CorrelationEngine()
        self.html_generator = HTMLGenerator()
        self.json_exporter = JSONExporter()
        
        # Check if at least one sandbox is configured
        if not any([self.ha_client, self.vt_client]):
            raise RuntimeError(
                "No sandbox API keys configured. Set HYBRID_ANALYSIS_API_KEY, "
                "or VIRUSTOTAL_API_KEY in .env file"
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

        # Submit in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(submit_ha): "HA",
                executor.submit(submit_vt): "VT"
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
        """
    )
    parser.add_argument("file", help="Path to file for analysis")
    parser.add_argument(
        "--output-dir", default="artifacts",
        help="Output directory for reports (default: artifacts)"
    )
    args = parser.parse_args()
    
    try:
        analyzer = MalwareAnalyzer()
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
