"""
Normalizer for Hybrid Analysis API responses.
"""

from typing import Dict, Any, List
from datetime import datetime
import logging

from .base import BaseNormalizer
from schema import (
    UnifiedReport,
    IOC,
    IOCType,
    Process,
    NetworkActivity,
    FileOperation,
    SandboxSource,
    ThreatLevel,
    RiskAssessment,
)

logger = logging.getLogger(__name__)


class HybridAnalysisNormalizer(BaseNormalizer):
    """Normalize Hybrid Analysis API responses."""

    def normalize(self, raw_response: Dict[str, Any]) -> UnifiedReport:
        """Convert Hybrid Analysis response to UnifiedReport."""
        report = raw_response.get("analysis", {})
        system = raw_response.get("system", {})
        metadata = raw_response.get("metadata", {})

        if not metadata and "results" in raw_response:
            first_result = (raw_response.get("results") or [{}])[0]
            if isinstance(first_result, dict):
                metadata = {
                    "filename": first_result.get("filename") or first_result.get("submit_name"),
                    "hashes": {
                        "md5": first_result.get("md5"),
                        "sha1": first_result.get("sha1"),
                        "sha256": first_result.get("sha256"),
                    },
                    "file_size": first_result.get("size") or first_result.get("file_size"),
                    "file_type": first_result.get("type") or first_result.get("file_type"),
                }
                report = {
                    "state": "SUCCESS",
                    "verdict": first_result.get("verdict") or first_result.get("threat_score"),
                    "timestamp": first_result.get("analysis_start_time") or first_result.get("submit_time"),
                }

        if not metadata:
            metadata = {
                "filename": raw_response.get("filename") or raw_response.get("submit_name", "unknown"),
                "hashes": {
                    "md5": raw_response.get("md5"),
                    "sha1": raw_response.get("sha1"),
                    "sha256": raw_response.get("sha256"),
                },
                "file_size": raw_response.get("size") or raw_response.get("file_size"),
                "file_type": raw_response.get("type") or raw_response.get("type_short") or raw_response.get("type_desc"),
            }

        if not report:
            report = {
                "state": "SUCCESS" if raw_response else "UNKNOWN",
                "verdict": raw_response.get("verdict") or raw_response.get("threat_score") or "unknown",
                "timestamp": raw_response.get("analysis_start_time") or raw_response.get("submit_time"),
            }

        # Extract file info
        file_name = metadata.get("filename", "unknown")
        file_hashes = metadata.get("hashes", {})

        # Create base report
        unified = UnifiedReport(
            file_name=file_name,
            file_hash_md5=file_hashes.get("md5"),
            file_hash_sha1=file_hashes.get("sha1"),
            file_hash_sha256=file_hashes.get("sha256"),
            file_size=metadata.get("file_size"),
            file_type=metadata.get("file_type"),
            source=SandboxSource.HYBRID_ANALYSIS,
        )

        # Execution data
        unified.execution_successful = report.get("state") == "SUCCESS"
        unified.verdict = self._map_verdict(report.get("verdict"))

        # Timestamps
        if "timestamp" in report:
            try:
                unified.analysis_timestamp = datetime.fromisoformat(
                    str(report["timestamp"]).replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Extract behavioral data
        unified.processes = self._extract_processes(system.get("processes", []))
        unified.network_activities = self._extract_network_activity(
            system.get("network", {})
        )
        unified.file_operations = self._extract_file_operations(
            system.get("file_operations", [])
        )

        # Extract IOCs
        unified.iocs = self._extract_iocs(raw_response)

        # Fallback detections for flat Hybrid responses
        if not unified.detections:
            unified.detections = self._extract_detections(raw_response)

        # Risk assessment
        unified.risk = self._calculate_risk(report, raw_response)

        # Store raw metadata
        unified.raw_metadata = raw_response

        return unified

    def validate_response(self, raw_response: Dict[str, Any]) -> bool:
        """Validate Hybrid Analysis response."""
        if "analysis" in raw_response and "metadata" in raw_response:
            return True
        if "results" in raw_response and isinstance(raw_response.get("results"), list):
            return True
        return any(key in raw_response for key in ["sha256", "md5", "verdict", "threat_score"])

    def _extract_detections(self, raw_response: Dict[str, Any]) -> List[str]:
        """Extract detection-like fields from HA responses."""
        detections = []

        if raw_response.get("verdict"):
            detections.append(f"Hybrid Analysis Verdict: {raw_response.get('verdict')}")

        threat_score = raw_response.get("threat_score")
        if threat_score is not None:
            detections.append(f"Hybrid Analysis Threat Score: {threat_score}")

        tags = raw_response.get("classification_tags") or raw_response.get("tags") or []
        if isinstance(tags, list):
            for tag in tags[:10]:
                detections.append(f"Tag: {tag}")

        return detections

    def _map_verdict(self, verdict: str) -> str:
        """Map Hybrid Analysis verdict to unified verdict."""
        verdict_lower = str(verdict).lower()
        if "malicious" in verdict_lower:
            return "malicious"
        elif "suspicious" in verdict_lower:
            return "suspicious"
        elif "clean" in verdict_lower:
            return "clean"
        else:
            return "unknown"

    def _extract_processes(self, processes_data: List[Dict]) -> List[Process]:
        """Extract process information."""
        processes = []
        for proc_data in processes_data or []:
            process = Process(
                name=proc_data.get("name", "unknown"),
                pid=self._extract_int(proc_data, "process_id"),
                parent_pid=self._extract_int(proc_data, "parent_process_id"),
                command_line=proc_data.get("command_line"),
                user=proc_data.get("user"),
            )
            processes.append(process)
        return processes

    def _extract_network_activity(self, network_data: Dict) -> List[NetworkActivity]:
        """Extract network connections and DNS requests."""
        activities = []

        # HTTP requests
        for http_req in network_data.get("http_requests", []):
            activity = NetworkActivity(
                direction="outbound",
                protocol="http",
                destination_ip=http_req.get("ip"),
                domain=http_req.get("domain"),
                destination_port=self._extract_int(http_req, "port", 80),
                url=http_req.get("url"),
                user_agent=http_req.get("user_agent"),
            )
            activities.append(activity)

        # DNS queries
        for dns_query in network_data.get("dns_queries", []):
            activity = NetworkActivity(
                direction="outbound",
                protocol="dns",
                domain=dns_query.get("domain"),
            )
            activities.append(activity)

        # TCP connections
        for tcp_conn in network_data.get("tcp_connections", []):
            activity = NetworkActivity(
                direction="outbound",
                protocol="tcp",
                destination_ip=tcp_conn.get("destination_ip"),
                destination_port=self._extract_int(tcp_conn, "destination_port"),
            )
            activities.append(activity)

        return activities

    def _extract_file_operations(self, file_ops_data: List[Dict]) -> List[FileOperation]:
        """Extract file system operations."""
        operations = []
        for op_data in file_ops_data or []:
            operation = FileOperation(
                operation_type=op_data.get("operation", "unknown"),
                file_path=op_data.get("path", "unknown"),
            )
            operations.append(operation)
        return operations

    def _extract_iocs(self, raw_response: Dict[str, Any]) -> List[IOC]:
        """Extract indicators of compromise."""
        iocs = []
        indicators = raw_response.get("indicators", {})

        # Domains
        for domain in indicators.get("domains", []):
            ioc = IOC(
                ioc_type=IOCType.DOMAIN,
                value=domain,
                source=[SandboxSource.HYBRID_ANALYSIS],
                confidence=0.9,
            )
            iocs.append(ioc)

        # IPs
        for ip in indicators.get("ips", []):
            ioc = IOC(
                ioc_type=IOCType.IP_ADDRESS,
                value=ip,
                source=[SandboxSource.HYBRID_ANALYSIS],
                confidence=0.9,
            )
            iocs.append(ioc)

        # URLs
        for url in indicators.get("urls", []):
            ioc = IOC(
                ioc_type=IOCType.URL,
                value=url,
                source=[SandboxSource.HYBRID_ANALYSIS],
                confidence=0.9,
            )
            iocs.append(ioc)

        # Hashes (dropped files)
        for dropped_file in raw_response.get("dropped_files", []):
            for hash_type in ["md5", "sha1", "sha256"]:
                file_hash = dropped_file.get(hash_type)
                if file_hash:
                    ioc_type_map = {
                        "md5": IOCType.MD5,
                        "sha1": IOCType.SHA1,
                        "sha256": IOCType.SHA256,
                    }
                    ioc = IOC(
                        ioc_type=ioc_type_map[hash_type],
                        value=file_hash,
                        source=[SandboxSource.HYBRID_ANALYSIS],
                        confidence=0.95,
                    )
                    iocs.append(ioc)

        return iocs

    def _calculate_risk(self, report: Dict, raw_response: Dict) -> RiskAssessment:
        """Calculate risk score based on analysis."""
        verdict = report.get("verdict", "unknown").lower()
        
        # Base scoring logic
        if "malicious" in verdict:
            score = 85.0
            threat_level = ThreatLevel.CRITICAL
        elif "suspicious" in verdict:
            score = 65.0
            threat_level = ThreatLevel.HIGH
        elif "potentially unwanted" in verdict:
            score = 45.0
            threat_level = ThreatLevel.MEDIUM
        elif "clean" in verdict:
            score = 10.0
            threat_level = ThreatLevel.LOW
        else:
            score = 30.0
            threat_level = ThreatLevel.INFORMATIONAL

        # Adjust score based on activity
        indicators = raw_response.get("indicators", {})
        if indicators.get("domains") or indicators.get("ips"):
            score = min(100, score + 10)
        
        if raw_response.get("dropped_files"):
            score = min(100, score + 15)

        reasoning = [
            f"Verdict: {verdict}",
            f"Network indicators: {len(indicators.get('domains', []))} domains, {len(indicators.get('ips', []))} IPs",
            f"Dropped files: {len(raw_response.get('dropped_files', []))}",
        ]

        return RiskAssessment(
            overall_score=score,
            threat_level=threat_level,
            confidence=0.85,
            reasoning=reasoning,
        )
