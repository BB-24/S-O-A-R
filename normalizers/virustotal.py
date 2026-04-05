"""
Normalizer for VirusTotal API responses.
"""

from typing import Dict, Any, List
from datetime import datetime
import logging

from .base import BaseNormalizer
from schema import (
    UnifiedReport,
    IOC,
    IOCType,
    SandboxSource,
    ThreatLevel,
    RiskAssessment,
)

logger = logging.getLogger(__name__)


class VirusTotalNormalizer(BaseNormalizer):
    """Normalize VirusTotal API responses."""

    def normalize(self, raw_response: Dict[str, Any]) -> UnifiedReport:
        """Convert VirusTotal response to UnifiedReport."""
        
        data = raw_response.get("data", {})
        attributes = data.get("attributes", {})

        # Extract file info
        file_name = attributes.get("meaningful_name", attributes.get("name", "unknown"))
        names = attributes.get("names", [])
        if isinstance(names, list) and names:
            file_name = names[0]

        # Create base report
        unified = UnifiedReport(
            file_name=file_name,
            file_hash_md5=attributes.get("md5"),
            file_hash_sha1=attributes.get("sha1"),
            file_hash_sha256=attributes.get("sha256"),
            file_size=attributes.get("size"),
            file_type=attributes.get("type_description"),
            source=SandboxSource.VIRUSTOTAL,
            execution_successful=True,  # VirusTotal doesn't sandbox, just analyzes
        )

        # Timestamps
        if "creation_date" in attributes:
            try:
                unified.submission_timestamp = datetime.fromtimestamp(
                    attributes["creation_date"]
                )
            except (ValueError, TypeError):
                pass

        if "last_analysis_date" in attributes:
            try:
                unified.analysis_timestamp = datetime.fromtimestamp(
                    attributes["last_analysis_date"]
                )
            except (ValueError, TypeError):
                pass

        # Verdict based on detections
        unified.verdict = self._determine_verdict(attributes)
        
        # Detections from AV vendors
        unified.detections = self._extract_detections(attributes)
        
        # Extract IOCs from analysis results
        unified.iocs = self._extract_iocs(attributes)

        # Risk assessment
        unified.risk = self._calculate_risk(attributes)

        # Store raw metadata
        unified.raw_metadata = raw_response

        return unified

    def validate_response(self, raw_response: Dict[str, Any]) -> bool:
        """Validate VirusTotal response."""
        return "data" in raw_response

    def _determine_verdict(self, attributes: Dict) -> str:
        """Determine verdict based on detection ratio."""
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        undetected = last_analysis_stats.get("undetected", 0)

        if malicious > 0:
            return "malicious"
        elif suspicious > 0:
            return "suspicious"
        elif undetected >= 5:  # Most engines don't see it
            return "clean"
        else:
            return "unknown"

    def _extract_detections(self, attributes: Dict) -> List[str]:
        """Extract detection names from all AV engines."""
        detections = []
        
        last_analysis_results = attributes.get("last_analysis_results", {})
        for engine, result in last_analysis_results.items():
            category = result.get("category")
            if category in ["malicious", "suspicious"]:
                detection = result.get("engine_name", engine)
                classification = result.get("result", "unknown")
                detections.append(f"{detection}: {classification}")

        return detections

    def _extract_iocs(self, attributes: Dict) -> List[IOC]:
        """Extract IOCs from VirusTotal analysis."""
        iocs = []

        # From sandbox analysis if available
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        
        # Extract from attributes
        iocs.extend(self._extract_from_attributes(attributes))

        return iocs

    def _extract_from_attributes(self, attributes: Dict) -> List[IOC]:
        """Extract IOCs from file attributes."""
        iocs = []

        # Some VirusTotal attributes can contain IOCs
        # This is a simplified extraction
        
        return iocs

    def _calculate_risk(self, attributes: Dict) -> RiskAssessment:
        """Calculate risk score based on detection ratio."""
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        total = sum(last_analysis_stats.values())

        # Calculate detection ratio
        detected = malicious + suspicious
        if total > 0:
            detection_ratio = detected / total
        else:
            detection_ratio = 0

        # Score calculation
        if malicious >= 5:
            score = 90.0
            threat_level = ThreatLevel.CRITICAL
        elif malicious > 0:
            score = 75.0
            threat_level = ThreatLevel.HIGH
        elif suspicious >= 3:
            score = 60.0
            threat_level = ThreatLevel.MEDIUM
        elif suspicious > 0 or detection_ratio > 0.1:
            score = 40.0
            threat_level = ThreatLevel.LOW
        else:
            score = 5.0
            threat_level = ThreatLevel.INFORMATIONAL

        reasoning = [
            f"Malicious detections: {malicious}",
            f"Suspicious detections: {suspicious}",
            f"Total engines: {total}",
            f"Detection ratio: {detection_ratio:.1%}",
        ]

        return RiskAssessment(
            overall_score=score,
            threat_level=threat_level,
            confidence=min(1.0, detected / max(1, total)),
            reasoning=reasoning,
        )
