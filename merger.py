"""
Merger for combining multiple UnifiedReports into a MergedReport.

Handles deduplication, conflict resolution, and multi-source enrichment.
"""

from typing import List, Dict, Set, Tuple
from datetime import datetime
import logging

from schema import (
    UnifiedReport,
    MergedReport,
    IOC,
    IOCType,
    SandboxSource,
    ThreatLevel,
    RiskAssessment,
    Process,
    NetworkActivity,
    FileOperation,
)

logger = logging.getLogger(__name__)


class ReportMerger:
    """Merge multiple reports and deduplicate data."""

    def merge(self, reports: List[UnifiedReport]) -> MergedReport:
        """
        Merge multiple reports into a single consolidated report.

        Args:
            reports: List of UnifiedReport objects from different sources

        Returns:
            MergedReport with deduplicated and consolidated data
        """
        if not reports:
            raise ValueError("Cannot merge empty report list")

        # Use primary hash (prefer SHA256)
        primary_hash = self._get_primary_hash(reports)
        all_hashes = self._collect_hashes(reports)

        # Merge processes (deduplicate by name + PID)
        processes = self._merge_processes(reports)

        # Merge network activities
        network_activities = self._merge_network_activity(reports)

        # Merge file operations
        file_operations = self._merge_file_operations(reports)

        # Deduplicate IOCs
        iocs = self._deduplicate_iocs(reports)

        # Collect verdicts
        verdicts = {report.source: report.verdict for report in reports if report.verdict}

        # Determine consensus verdict
        consensus_verdict = self._consensus_verdict(verdicts)

        # Collect all detections
        all_detections = {
            report.source: report.detections for report in reports if report.detections
        }

        # Merge risk assessments
        merged_risk = self._merge_risk(reports)

        # Combine MITRE techniques
        mitre_techniques = self._merge_mitre_techniques(reports)

        file_name = reports[0].file_name

        merged = MergedReport(
            file_name=file_name,
            primary_hash=primary_hash,
            all_hashes=all_hashes,
            processes=processes,
            network_activities=network_activities,
            file_operations=file_operations,
            iocs=iocs,
            mitre_techniques=mitre_techniques,
            verdicts=verdicts,
            consensus_verdict=consensus_verdict,
            all_detections=all_detections,
            risk=merged_risk,
            source_reports=reports,
            merge_timestamp=datetime.utcnow(),
        )

        logger.info(
            f"Merged {len(reports)} reports: {len(iocs)} IOCs, "
            f"{len(network_activities)} network activities"
        )

        return merged

    def _get_primary_hash(self, reports: List[UnifiedReport]) -> str:
        """Get primary hash (SHA256 preferred)."""
        for report in reports:
            if report.file_hash_sha256:
                return report.file_hash_sha256
        for report in reports:
            if report.file_hash_sha1:
                return report.file_hash_sha1
        for report in reports:
            if report.file_hash_md5:
                return report.file_hash_md5
        return "unknown"

    def _collect_hashes(self, reports: List[UnifiedReport]) -> Dict[str, str]:
        """Collect all hashes from all reports."""
        hashes = {}
        for report in reports:
            if report.file_hash_md5:
                hashes["md5"] = report.file_hash_md5
            if report.file_hash_sha1:
                hashes["sha1"] = report.file_hash_sha1
            if report.file_hash_sha256:
                hashes["sha256"] = report.file_hash_sha256
        return hashes

    def _merge_processes(self, reports: List[UnifiedReport]) -> List[Process]:
        """Merge and deduplicate processes."""
        seen: Dict[Tuple, Process] = {}

        for report in reports:
            for process in report.processes:
                # Deduplicate by name + PID
                key = (process.name, process.pid)
                if key not in seen:
                    seen[key] = process

        return list(seen.values())

    def _merge_network_activity(self, reports: List[UnifiedReport]) -> List[NetworkActivity]:
        """Merge and deduplicate network activities."""
        seen: Set[Tuple] = set()
        activities = []

        for report in reports:
            for activity in report.network_activities:
                # Create dedup key
                key = (activity.protocol, activity.domain or activity.destination_ip, activity.url)
                if key not in seen:
                    seen.add(key)
                    activities.append(activity)

        return activities

    def _merge_file_operations(self, reports: List[UnifiedReport]) -> List[FileOperation]:
        """Merge and deduplicate file operations."""
        seen: Set[Tuple] = set()
        operations = []

        for report in reports:
            for op in report.file_operations:
                key = (op.operation_type, op.file_path)
                if key not in seen:
                    seen.add(key)
                    operations.append(op)

        return operations

    def _deduplicate_iocs(self, reports: List[UnifiedReport]) -> List[IOC]:
        """
        Deduplicate IOCs across all reports.

        Merges sources and keeps highest confidence.
        """
        ioc_dict: Dict[Tuple, IOC] = {}

        for report in reports:
            for ioc in report.iocs:
                key = (ioc.ioc_type, ioc.value)

                if key in ioc_dict:
                    # Merge with existing
                    existing = ioc_dict[key]
                    # Add new source if not already present
                    if ioc.source:
                        for source in ioc.source:
                            if source not in existing.source:
                                existing.source.append(source)
                    # Keep highest confidence
                    existing.confidence = max(existing.confidence, ioc.confidence)
                else:
                    # New IOC
                    ioc_dict[key] = ioc

        return list(ioc_dict.values())

    def _consensus_verdict(self, verdicts: Dict[SandboxSource, str]) -> str:
        """Determine consensus verdict from multiple sources."""
        if not verdicts:
            return "unknown"

        # Count verdict types
        malicious_count = sum(1 for v in verdicts.values() if v == "malicious")
        suspicious_count = sum(1 for v in verdicts.values() if v == "suspicious")
        clean_count = sum(1 for v in verdicts.values() if v == "clean")

        total = len(verdicts)

        # Majority voting with threshold
        if malicious_count >= total * 0.5:
            return "malicious"
        elif suspicious_count >= total * 0.4:
            return "suspicious"
        elif clean_count >= total * 0.7:
            return "clean"
        else:
            return "unknown"

    def _merge_risk(self, reports: List[UnifiedReport]) -> RiskAssessment:
        """Merge risk assessments from all reports."""
        if not reports or not any(r.risk for r in reports):
            return RiskAssessment(
                overall_score=0.0,
                threat_level=ThreatLevel.INFORMATIONAL,
                confidence=0.0,
                reasoning=["No risk data available"],
            )

        scores = [r.risk.overall_score for r in reports if r.risk]
        confidences = [r.risk.confidence for r in reports if r.risk]

        # Average score (weighted by confidence)
        if scores:
            weighted_score = sum(s * c for s, c in zip(scores, confidences)) / sum(
                confidences
            )
        else:
            weighted_score = 0.0

        # Determine threat level based on merged score
        if weighted_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif weighted_score >= 60:
            threat_level = ThreatLevel.HIGH
        elif weighted_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif weighted_score >= 20:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.INFORMATIONAL

        reasoning = [
            f"Merged {len(reports)} reports",
            f"Average risk score: {weighted_score:.1f}",
        ]

        return RiskAssessment(
            overall_score=weighted_score,
            threat_level=threat_level,
            confidence=sum(confidences) / len(confidences) if confidences else 0,
            reasoning=reasoning,
        )

    def _merge_mitre_techniques(self, reports: List[UnifiedReport]) -> List[Dict]:
        """Merge MITRE ATT&CK techniques."""
        techniques_dict: Dict[str, Dict] = {}

        for report in reports:
            for technique in report.mitre_techniques:
                if technique.technique_id not in techniques_dict:
                    techniques_dict[technique.technique_id] = technique
                else:
                    # Update confidence to maximum
                    existing = techniques_dict[technique.technique_id]
                    existing.confidence = max(existing.confidence, technique.confidence)

        return list(techniques_dict.values())
