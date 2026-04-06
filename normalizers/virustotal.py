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

        detected = malicious + suspicious
        if total > 0:
            detection_ratio = detected / total
            malicious_ratio = malicious / total
            suspicious_ratio = suspicious / total
        else:
            detection_ratio = 0.0
            malicious_ratio = 0.0
            suspicious_ratio = 0.0

        # Dynamic scoring to avoid fixed plateaus (e.g., constant 90 for many files)
        ratio_component = (malicious_ratio * 75.0) + (suspicious_ratio * 25.0)
        count_component = min(20.0, malicious * 0.8) + min(8.0, suspicious * 0.4)
        score = ratio_component + count_component

        if detected == 0:
            score = 5.0 if total > 0 else 0.0

        score = round(min(100.0, max(0.0, score)), 1)

        if score >= 85:
            threat_level = ThreatLevel.CRITICAL
        elif score >= 65:
            threat_level = ThreatLevel.HIGH
        elif score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif score >= 20:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.INFORMATIONAL

        sample_confidence = min(1.0, total / 60.0)
        signal_confidence = detection_ratio
        confidence = min(1.0, (0.5 * sample_confidence) + (0.5 * signal_confidence))

        reasoning = [
            f"Malicious detections: {malicious}",
            f"Suspicious detections: {suspicious}",
            f"Total engines: {total}",
            f"Detection ratio: {detection_ratio:.1%}",
            f"Computed risk score: {score:.1f}",
        ]

        return RiskAssessment(
            overall_score=score,
            threat_level=threat_level,
            confidence=confidence,
            reasoning=reasoning,
        )
