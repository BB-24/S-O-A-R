"""
Correlation engine for enriching merged reports with intelligence.

Adds IOC extraction, MITRE ATT&CK mapping, YARA scanning, and behavioral analysis.
"""

from typing import List, Dict, Set, Optional
import logging
import json
import os

from schema import MergedReport, IOC, IOCType, MitreAttackTechnique
from correlator.yara_scanner import YARAScanner

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Enrich and correlate data in merged reports."""

    def __init__(self):
        self.mitre_techniques = self._load_mitre_data()
        self.yara_scanner = self._init_yara_scanner()

    def _init_yara_scanner(self) -> Optional[YARAScanner]:
        """Initialize YARA scanner if rules are available."""
        try:
            yara_rules_path = os.getenv('YARA_RULES_PATH')
            scanner = YARAScanner(rules_path=yara_rules_path)
            if scanner.rules:
                logger.info("YARA scanner initialized successfully")
                return scanner
            else:
                logger.info("YARA rules not configured, YARA scanning disabled")
                return None
        except Exception as e:
            logger.warning(f"Failed to initialize YARA scanner: {e}")
            return None

    def correlate(self, merged_report: MergedReport) -> MergedReport:
        """
        Enrich merged report with correlation data.

        Args:
            merged_report: Report to enrich

        Returns:
            Enriched MergedReport
        """
        logger.info("Starting correlation analysis with behavioral IOC extraction and YARA scanning")

        # Perform YARA scanning if available
        if self.yara_scanner:
            self._perform_yara_scanning(merged_report)

        # Extract behavioral IOCs (DNS, registry, dropped files, process behavior)
        self._extract_iocs_from_behavior(merged_report)

        # Map behavioral patterns to MITRE techniques
        self._map_mitre_techniques(merged_report)

        # Perform threat intelligence enrichment
        self._enrich_with_threat_intel(merged_report)

        logger.info(f"Correlation complete: {len(merged_report.iocs)} IOCs, "
                   f"{len(merged_report.mitre_techniques)} MITRE techniques")

        return merged_report

    def _perform_yara_scanning(self, report: MergedReport) -> None:
        """
        Perform YARA scanning on sample and behavioral data.

        Args:
            report: Report to enrich with YARA matches
        """
        if not self.yara_scanner:
            return

        logger.debug("Starting YARA scanning")
        yara_iocs_count = 0

        # Get sample file path from raw metadata if available
        sample_path = report.raw_metadata.get('sample_path') if hasattr(report, 'raw_metadata') else None

        if sample_path and os.path.exists(sample_path):
            try:
                logger.debug(f"Scanning sample with YARA: {sample_path}")
                matches = self.yara_scanner.scan_file(sample_path)
                iocs = self.yara_scanner.extract_iocs_from_matches(matches)

                # Add YARA-extracted IOCs to report
                existing_iocs = {(ioc.ioc_type, ioc.value) for ioc in report.iocs}
                for ioc in iocs:
                    ioc_key = (ioc.ioc_type, ioc.value)
                    if ioc_key not in existing_iocs:
                        report.iocs.append(ioc)
                        existing_iocs.add(ioc_key)
                        yara_iocs_count += 1

                if matches:
                    logger.debug(f"YARA scan found {len(matches)} matches")

            except Exception as e:
                logger.error(f"Error during YARA scanning: {e}")

        # Also scan detections/process behavior text for embedded IOCs
        # Flatten detection lists from all sources
        all_detections = ' '.join(
            detection 
            for src_detections in report.all_detections.values() 
            for detection in src_detections
        )
        if all_detections:
            try:
                matches = self.yara_scanner.scan_string(all_detections.encode('utf-8', errors='ignore'))
                iocs = self.yara_scanner.extract_iocs_from_matches(matches)

                existing_iocs = {(ioc.ioc_type, ioc.value) for ioc in report.iocs}
                for ioc in iocs:
                    ioc_key = (ioc.ioc_type, ioc.value)
                    if ioc_key not in existing_iocs:
                        report.iocs.append(ioc)
                        existing_iocs.add(ioc_key)
                        yara_iocs_count += 1

            except Exception as e:
                logger.debug(f"Error scanning detections with YARA: {e}")

        if yara_iocs_count > 0:
            logger.info(f"YARA scanning extracted {yara_iocs_count} additional IOCs")

    def _extract_iocs_from_behavior(self, report: MergedReport) -> None:
        """Extract IOCs from behavioral data."""
        extracted = set()

        # From network activities
        for activity in report.network_activities:
            if activity.domain and activity.domain not in [
                ioc.value for ioc in report.iocs if ioc.ioc_type == IOCType.DOMAIN
            ]:
                ioc = IOC(
                    ioc_type=IOCType.DOMAIN,
                    value=activity.domain,
                    source=list(set(ioc.source for ioc in report.iocs if ioc.ioc_type == IOCType.DOMAIN if ioc.source)),
                    confidence=0.85,
                )
                report.iocs.append(ioc)
                extracted.add(("domain", activity.domain))

            if activity.destination_ip and activity.destination_ip not in [
                ioc.value for ioc in report.iocs if ioc.ioc_type == IOCType.IP_ADDRESS
            ]:
                ioc = IOC(
                    ioc_type=IOCType.IP_ADDRESS,
                    value=activity.destination_ip,
                    source=[],
                    confidence=0.85,
                )
                report.iocs.append(ioc)
                extracted.add(("ip", activity.destination_ip))

            if activity.url and activity.url not in [
                ioc.value for ioc in report.iocs if ioc.ioc_type == IOCType.URL
            ]:
                ioc = IOC(
                    ioc_type=IOCType.URL,
                    value=activity.url,
                    source=[],
                    confidence=0.85,
                )
                report.iocs.append(ioc)
                extracted.add(("url", activity.url))

        # From file operations
        for op in report.file_operations:
            if op.file_path and "temp" in op.file_path.lower():
                # Suspicious temp file usage
                ioc = IOC(
                    ioc_type=IOCType.FILE_PATH,
                    value=op.file_path,
                    source=[],
                    confidence=0.7,
                )
                report.iocs.append(ioc)

        if extracted:
            logger.debug(f"Extracted {len(extracted)} additional IOCs from behavior")

    def _map_mitre_techniques(self, report: MergedReport) -> None:
        """Map behavioral indicators to MITRE ATT&CK techniques."""
        techniques_found = []

        # Check for suspicious network patterns
        if report.network_activities:
            # Command & Control
            if any(activity.protocol == "https" for activity in report.network_activities):
                technique = self._find_technique("T1071")  # Application Layer Protocol
                if technique:
                    techniques_found.append(technique)

            # DNS C2
            if any(activity.protocol == "dns" for activity in report.network_activities):
                technique = self._find_technique("T1048")  # Exfiltration Over Alternative Protocol
                if technique:
                    techniques_found.append(technique)

        # Check for process behavior
        if report.processes:
            # Process Injection
            if any(proc.parent_pid and proc.parent_pid != proc.pid for proc in report.processes):
                technique = self._find_technique("T1055")  # Process Injection
                if technique:
                    techniques_found.append(technique)

        # Check for file operations
        if report.file_operations:
            writes = [op for op in report.file_operations if op.operation_type == "write"]
            if writes:
                # Modify Registry
                registry_ops = [op for op in writes if "registry" in op.file_path.lower()]
                if registry_ops:
                    technique = self._find_technique("T1112")  # Modify Registry
                    if technique:
                        techniques_found.append(technique)

        # Merge with existing MITRE techniques
        existing_ids = {t.technique_id for t in report.mitre_techniques}
        for technique in techniques_found:
            if technique.technique_id not in existing_ids:
                report.mitre_techniques.append(technique)
                existing_ids.add(technique.technique_id)

        logger.debug(f"Mapped {len(techniques_found)} MITRE techniques")

    def _enrich_with_threat_intel(self, report: MergedReport) -> None:
        """Perform threat intelligence enrichment."""
        # This could integrate with external TI feeds
        # For now, basic enrichment based on indicators

        for ioc in report.iocs:
            # Example: Flag known malicious IPs
            if ioc.ioc_type == IOCType.IP_ADDRESS:
                if self._is_known_malicious_ip(ioc.value):
                    ioc.confidence = min(1.0, ioc.confidence + 0.1)
                    if "known_malicious" not in ioc.metadata:
                        ioc.metadata["known_malicious"] = True

    def _find_technique(self, technique_id: str) -> Optional[MitreAttackTechnique]:
        """Find MITRE technique by ID."""
        for technique in self.mitre_techniques:
            if technique.technique_id == technique_id:
                return technique
        return None

    def _is_known_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known malicious (stub for external feed)."""
        # This would integrate with threat intelligence feeds
        known_bad = []  # Would be populated from TI sources
        return ip in known_bad

    def _load_mitre_data(self) -> List[MitreAttackTechnique]:
        """Load MITRE ATT&CK data."""
        # Simplified MITRE data - in production would load from attackcti
        techniques = [
            MitreAttackTechnique(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="command-and-control",
                confidence=0.8,
            ),
            MitreAttackTechnique(
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                tactic="exfiltration",
                confidence=0.8,
            ),
            MitreAttackTechnique(
                technique_id="T1055",
                technique_name="Process Injection",
                tactic="defense-evasion",
                confidence=0.8,
            ),
            MitreAttackTechnique(
                technique_id="T1112",
                technique_name="Modify Registry",
                tactic="defense-evasion",
                confidence=0.8,
            ),
            MitreAttackTechnique(
                technique_id="T1566",
                technique_name="Phishing",
                tactic="initial-access",
                confidence=0.8,
            ),
        ]
        return techniques
