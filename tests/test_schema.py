"""Unit tests for schema module."""

import pytest
from datetime import datetime
from schema import (
    IOC,
    IOCType,
    Process,
    UnifiedReport,
    MergedReport,
    SandboxSource,
    ThreatLevel,
    RiskAssessment,
)


class TestIOC:
    """Test IOC data class."""

    def test_ioc_creation(self):
        """Test basic IOC creation."""
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            value="malicious.com",
            confidence=0.95,
        )
        assert ioc.ioc_type == IOCType.DOMAIN
        assert ioc.value == "malicious.com"
        assert ioc.confidence == 0.95

    def test_ioc_deduplication(self):
        """Test IOC deduplication by hash."""
        ioc1 = IOC(ioc_type=IOCType.IP_ADDRESS, value="192.0.2.1")
        ioc2 = IOC(ioc_type=IOCType.IP_ADDRESS, value="192.0.2.1")
        assert hash(ioc1) == hash(ioc2)
        assert ioc1 == ioc2

    def test_ioc_sources(self):
        """Test IOC source tracking."""
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            value="c2.com",
            source=[SandboxSource.HYBRID_ANALYSIS, SandboxSource.VIRUSTOTAL],
        )
        assert len(ioc.source) == 2


class TestProcess:
    """Test Process data class."""

    def test_process_creation(self):
        """Test basic process creation."""
        proc = Process(
            name="malware.exe",
            pid=1234,
            parent_pid=456,
            command_line="malware.exe /c evil",
        )
        assert proc.name == "malware.exe"
        assert proc.pid == 1234
        assert proc.parent_pid == 456


class TestUnifiedReport:
    """Test UnifiedReport data class."""

    def test_report_creation(self):
        """Test basic report creation."""
        report = UnifiedReport(
            file_name="test.exe",
            file_hash_sha256="abc123def456",
            source=SandboxSource.HYBRID_ANALYSIS,
        )
        assert report.file_name == "test.exe"
        assert report.file_hash_sha256 == "abc123def456"

    def test_get_all_hashes(self):
        """Test hash collection."""
        report = UnifiedReport(
            file_name="test.exe",
            file_hash_md5="hash_md5",
            file_hash_sha1="hash_sha1",
            file_hash_sha256="hash_sha256",
        )
        hashes = report.get_all_hashes()
        assert len(hashes) == 3
        assert hashes["md5"] == "hash_md5"

    def test_unique_iocs(self):
        """Test IOC deduplication."""
        ioc1 = IOC(ioc_type=IOCType.DOMAIN, value="test.com")
        ioc2 = IOC(ioc_type=IOCType.DOMAIN, value="test.com")
        report = UnifiedReport(
            file_name="test.exe",
            iocs=[ioc1, ioc2],
        )
        unique = report.unique_iocs()
        assert len(unique) == 1


class TestMergedReport:
    """Test MergedReport data class."""

    def test_merged_report_summary(self):
        """Test summary generation."""
        merged = MergedReport(
            file_name="test.exe",
            primary_hash="abc123",
            all_hashes={"sha256": "abc123"},
        )
        summary = merged.summary()
        assert summary["file_name"] == "test.exe"
        assert summary["primary_hash"] == "abc123"


class TestRiskAssessment:
    """Test RiskAssessment data class."""

    def test_risk_assessment_critical(self):
        """Test critical threat level."""
        risk = RiskAssessment(
            overall_score=95.0,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.95,
        )
        assert risk.threat_level == ThreatLevel.CRITICAL
        assert risk.overall_score == 95.0
