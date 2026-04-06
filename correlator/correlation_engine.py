"""
Correlation engine for enriching merged reports with intelligence.

Adds IOC extraction, MITRE ATT&CK mapping, MISP enrichment, and behavioral analysis.
"""

from typing import List, Dict, Set, Optional
import logging
import json
import os

from schema import MergedReport, IOC, IOCType, MitreAttackTechnique
from correlator.misp_enricher import MISPEnricher
from clients.misp_client import MISPClient

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Enrich and correlate data in merged reports."""

    def __init__(self):
        self.mitre_techniques = self._load_mitre_data()
        self.misp_enricher = self._init_misp_enricher()

    def _init_misp_enricher(self) -> MISPEnricher:
        """Initialize MISP enricher if credentials are available."""
        try:
            misp_url = os.getenv('MISP_URL', '').strip()
            misp_key = os.getenv('MISP_API_KEY', '').strip()
            
            if misp_url and misp_key and not misp_key.startswith('$'):
                logger.info(f"Initializing MISP enrichment with {misp_url}")
                misp_client = MISPClient(misp_url, misp_key)
                return MISPEnricher(misp_client)
            else:
                logger.info("MISP credentials not configured, using behavioral extraction only")
                return MISPEnricher(None)  # Graceful degradation
        except Exception as e:
            logger.warning(f"Failed to initialize MISP enricher: {e}, continuing without MISP")
            return MISPEnricher(None)

    def correlate(self, merged_report: MergedReport) -> MergedReport:
        """
        Enrich merged report with correlation data.

        Args:
            merged_report: Report to enrich

        Returns:
            Enriched MergedReport
        """
        logger.info("Starting correlation analysis with behavioral IOC extraction")

        # Extract behavioral IOCs (DNS, registry, dropped files, process behavior)
        self.misp_enricher.extract_behavioral_iocs(merged_report)
        
        # Enrich IOCs with MISP intelligence
        self.misp_enricher.enrich_iocs(merged_report)

        # Additional extraction from basic behavior patterns
        self._extract_iocs_from_behavior(merged_report)

        # Map behavioral patterns to MITRE techniques
        self._map_mitre_techniques(merged_report)

        # Perform threat intelligence enrichment
        self._enrich_with_threat_intel(merged_report)

        logger.info(f"Correlation complete: {len(merged_report.iocs)} IOCs, "
                   f"{len(merged_report.mitre_techniques)} MITRE techniques")

        return merged_report

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
