"""
JSON export for analysis reports.

Generates structured, machine-readable JSON output.
"""

import json
from typing import Dict, Any
from datetime import datetime
import logging

from schema import MergedReport

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export MergedReport to JSON format."""

    def export(self, report: MergedReport) -> str:
        """
        Export report to JSON string.

        Args:
            report: MergedReport to export

        Returns:
            JSON string
        """
        report_dict = self._serialize_report(report)
        return json.dumps(report_dict, indent=2, default=str)

    def export_file(self, report: MergedReport, file_path: str) -> None:
        """
        Export report to JSON file.

        Args:
            report: MergedReport to export
            file_path: Path to write JSON file
        """
        report_dict = self._serialize_report(report)
        with open(file_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)
        logger.info(f"JSON report exported to {file_path}")

    def _serialize_report(self, report: MergedReport) -> Dict[str, Any]:
        """Serialize report to dictionary."""
        return {
            "summary": report.summary(),
            "file_metadata": {
                "name": report.file_name,
                "hashes": report.all_hashes,
                "primary_hash": report.primary_hash,
            },
            "verdict_analysis": {
                "consensus_verdict": report.consensus_verdict,
                "verdicts_by_source": {source.value: verdict for source, verdict in report.verdicts.items()},
                "detections_by_source": {
                    source.value: detections
                    for source, detections in report.all_detections.items()
                },
            },
            "risk_assessment": (
                {
                    "overall_score": report.risk.overall_score,
                    "threat_level": report.risk.threat_level.value,
                    "confidence": report.risk.confidence,
                    "reasoning": report.risk.reasoning,
                    "mitigations": report.risk.mitigations,
                }
                if report.risk
                else None
            ),
            "indicators_of_compromise": [self._serialize_ioc(ioc) for ioc in report.iocs],
            "network_activity": [self._serialize_network_activity(activity) for activity in report.network_activities],
            "process_execution": [self._serialize_process(proc) for proc in report.processes],
            "file_operations": [
                {
                    "operation_type": op.operation_type,
                    "file_path": op.file_path,
                    "details": op.details,
                }
                for op in report.file_operations
            ],
            "mitre_attack_techniques": [
                {
                    "technique_id": tech.technique_id,
                    "technique_name": tech.technique_name,
                    "tactic": tech.tactic,
                    "confidence": tech.confidence,
                }
                for tech in report.mitre_techniques
            ],
            "metadata": {
                "merge_timestamp": report.merge_timestamp.isoformat(),
                "sources_count": len(report.source_reports),
                "generators": [source.value if hasattr(source, 'value') else str(source) for source in report.verdicts.keys()],
            },
        }

    def _serialize_ioc(self, ioc) -> Dict[str, Any]:
        """Serialize IOC to dictionary."""
        return {
            "type": ioc.ioc_type.value,
            "value": ioc.value,
            "sources": [source.value for source in ioc.source],
            "confidence": ioc.confidence,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "metadata": ioc.metadata,
        }

    def _serialize_network_activity(self, activity) -> Dict[str, Any]:
        """Serialize network activity."""
        return {
            "protocol": activity.protocol,
            "direction": activity.direction,
            "source_ip": activity.source_ip,
            "destination_ip": activity.destination_ip,
            "source_port": activity.source_port,
            "destination_port": activity.destination_port,
            "domain": activity.domain,
            "url": activity.url,
            "user_agent": activity.user_agent,
            "timestamp": activity.timestamp.isoformat() if activity.timestamp else None,
        }

    def _serialize_process(self, process) -> Dict[str, Any]:
        """Serialize process information."""
        return {
            "name": process.name,
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "command_line": process.command_line,
            "user": process.user,
            "start_time": process.start_time.isoformat() if process.start_time else None,
            "end_time": process.end_time.isoformat() if process.end_time else None,
        }
