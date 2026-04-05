"""
Normalizer for Triage API responses (optional).
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


class TriageNormalizer(BaseNormalizer):
    """Normalize Triage API responses."""

    def normalize(self, raw_response: Dict[str, Any]) -> UnifiedReport:
        """Convert Triage response to UnifiedReport."""
        
        # Create base report
        unified = UnifiedReport(
            file_name=raw_response.get("name", "unknown"),
            file_hash_md5=raw_response.get("md5"),
            file_hash_sha1=raw_response.get("sha1"),
            file_hash_sha256=raw_response.get("sha256"),
            file_size=raw_response.get("size"),
            source=SandboxSource.TRIAGE,
        )

        # Analysis data
        analysis = raw_response.get("analysis", {})
        unified.verdict = analysis.get("verdict", "unknown")
        
        # Risk assessment
        unified.risk = self._calculate_risk(analysis)

        # Store raw metadata
        unified.raw_metadata = raw_response

        return unified

    def validate_response(self, raw_response: Dict[str, Any]) -> bool:
        """Validate Triage response."""
        return "id" in raw_response or "sha256" in raw_response

    def _calculate_risk(self, analysis: Dict) -> RiskAssessment:
        """Calculate risk score."""
        verdict = analysis.get("verdict", "unknown").lower()
        
        if "malicious" in verdict:
            score = 85.0
            threat_level = ThreatLevel.CRITICAL
        elif "suspicious" in verdict:
            score = 65.0
            threat_level = ThreatLevel.HIGH
        else:
            score = 30.0
            threat_level = ThreatLevel.INFORMATIONAL

        return RiskAssessment(
            overall_score=score,
            threat_level=threat_level,
            confidence=0.8,
            reasoning=[f"Verdict: {verdict}"],
        )
