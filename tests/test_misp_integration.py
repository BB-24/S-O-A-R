"""
End-to-end test for MISP-powered IOC extraction and enrichment.

Tests behavioral IOC extraction (DNS, dropped files, registry, process behavior)
and MISP enrichment pipeline.
"""

import unittest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch

from schema import (
    MergedReport,
    IOC,
    IOCType,
    IOCSource,
    NetworkActivity,
    Process,
    FileOperation,
    UnifiedReport,
)
from correlator.misp_enricher import MISPEnricher
from clients.misp_client import MISPClient


class TestMISPBehavioralExtraction(unittest.TestCase):
    """Test behavioral IOC extraction (DNS, files, registry, process behavior)."""

    def setUp(self):
        """Initialize test fixtures."""
        self.mock_misp_client = Mock(spec=MISPClient)
        self.enricher = MISPEnricher(self.mock_misp_client)

        # Create a test merged report with behavioral data
        self.report = MergedReport(
            file_name="test_malware.exe",
            primary_hash="abc123def456",
            all_hashes={"md5": "abc123", "sha1": "def456"},
            consensus_verdict="malicious",
            source_reports=[],
            network_activities=[
                NetworkActivity(
                    direction="outbound",
                    timestamp=datetime.utcnow(),
                    protocol="dns",
                    domain="malicious-c2.com",
                    destination_ip=None,
                    destination_port=None,
                    url=None,
                ),
                NetworkActivity(
                    direction="outbound",
                    timestamp=datetime.utcnow(),
                    protocol="tcp",
                    domain=None,
                    destination_ip="192.168.1.100",
                    destination_port=443,
                    url=None,
                    source_ip=None,
                ),
                NetworkActivity(
                    direction="outbound",
                    timestamp=datetime.utcnow(),
                    protocol="udp",
                    domain=None,
                    destination_ip="10.0.0.5",
                    destination_port=53,
                    url=None,
                    source_ip=None,
                ),
            ],
            processes=[
                Process(
                    name="cmd.exe",
                    pid=1234,
                    parent_pid=100,
                    command_line="cmd.exe /c powershell -enc VADeABYAZABSAGUAcw==",
                    user=None,
                )
            ],
            file_operations=[
                FileOperation(
                    timestamp=datetime.utcnow(),
                    operation_type="write",
                    file_path="C:\\Users\\Admin\\AppData\\Local\\Temp\\dropped.exe",
                ),
                FileOperation(
                    timestamp=datetime.utcnow(),
                    operation_type="read",
                    file_path="C:\\Windows\\System32\\kernel32.dll",
                ),
            ],
        )

    def test_extract_dns_queries(self):
        """Test extraction of DNS queries as IOCs."""
        self.enricher.extract_behavioral_iocs(self.report)

        # Check that DNS query was extracted
        dns_iocs = [ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.DNS_QUERY]
        self.assertGreater(len(dns_iocs), 0)
        self.assertIn("malicious-c2.com", [ioc.value for ioc in dns_iocs])

    def test_extract_dropped_files(self):
        """Test extraction of dropped file IOCs."""
        self.enricher.extract_behavioral_iocs(self.report)

        # Check that dropped file was identified
        file_iocs = [ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.FILE_DROPPED]
        self.assertGreater(len(file_iocs), 0)
        self.assertIn(
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\dropped.exe",
            [ioc.value for ioc in file_iocs],
        )

    def test_extract_ip_connections(self):
        """Test extraction of IP connections as IOCs."""
        self.enricher.extract_behavioral_iocs(self.report)

        # Check that IPs were extracted
        ip_iocs = [ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.IP_ADDRESS]
        self.assertGreater(len(ip_iocs), 0)
        extracted_ips = [ioc.value for ioc in ip_iocs]
        self.assertIn("192.168.1.100", extracted_ips)
        self.assertIn("10.0.0.5", extracted_ips)

    def test_extract_process_behavior(self):
        """Test extraction of suspicious process behavior IOCs."""
        self.enricher.extract_behavioral_iocs(self.report)

        # Check that suspicious command line was detected
        process_iocs = [ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.PROCESS_BEHAVIOR]
        self.assertGreater(len(process_iocs), 0)
        # Powershell with encoding is suspicious
        self.assertTrue(any("powershell" in ioc.value.lower() for ioc in process_iocs))


class TestMISPEnrichment(unittest.TestCase):
    """Test MISP-based IOC enrichment."""

    def setUp(self):
        """Initialize test fixtures."""
        self.mock_misp_client = Mock(spec=MISPClient)
        self.enricher = MISPEnricher(self.mock_misp_client)

        # Create a simple report with IOCs
        self.report = MergedReport(
            file_name="test.exe",
            primary_hash="abc123",
            all_hashes={"md5": "abc"},
            consensus_verdict="malicious",
            source_reports=[],
            iocs=[
                IOC(
                    ioc_type=IOCType.IP_ADDRESS,
                    value="192.168.1.1",
                    confidence=0.8,
                    source=[IOCSource.SANDBOX],
                ),
                IOC(
                    ioc_type=IOCType.DOMAIN,
                    value="malicious.com",
                    confidence=0.9,
                    source=[IOCSource.SANDBOX],
                ),
                IOC(
                    ioc_type=IOCType.SHA256,
                    value="d41d8cd98f00b204e9800998ecf8427e",
                    confidence=0.7,
                    source=[IOCSource.SANDBOX],
                ),
            ],
        )

    def test_enrich_iocs_with_misp(self):
        """Test that enrich_iocs processes all IOC types."""
        # Configure mocks to return proper values
        self.mock_misp_client.get_ip_reputation.return_value = {
            "events": [1, 2],
            "tags": ["malware", "c2"],
            "threat_level": "high",
            "malicious": True,
        }
        self.mock_misp_client.get_domain_reputation.return_value = {
            "events": [3],
            "tags": ["phishing"],
            "threat_level": "medium",
            "malicious": True,
        }
        self.mock_misp_client.get_hash_reputation.return_value = {
            "events": [],
            "tags": [],
            "threat_level": None,
            "malicious": False,
        }

        self.enricher.enrich_iocs(self.report)

        # Should have called MISP for each type
        self.mock_misp_client.get_ip_reputation.assert_called()
        self.mock_misp_client.get_domain_reputation.assert_called()
        self.mock_misp_client.get_hash_reputation.assert_called()

    def test_confidence_boost_not_applied_without_misp_match(self):
        """Test that confidence is not boosted when MISP doesn't have data."""
        original_confidence = 0.6
        ioc = IOC(
            ioc_type=IOCType.IP_ADDRESS,
            value="192.168.1.1",
            confidence=original_confidence,
            source=[IOCSource.SANDBOX],
        )
        self.report.iocs = [ioc]

        # Mock MISP response with no match
        self.mock_misp_client.get_ip_reputation.return_value = {
            "events": [],
            "tags": [],
            "threat_level": None,
            "malicious": False,
        }

        self.enricher.enrich_iocs(self.report)

        # Confidence should remain the same
        enriched_ioc = next(ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.IP_ADDRESS)
        self.assertEqual(enriched_ioc.confidence, original_confidence)

    def test_graceful_degradation_without_misp(self):
        """Test that enricher works without MISP client (graceful degradation)."""
        enricher_no_misp = MISPEnricher(None)
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            value="example.com",
            confidence=0.7,
            source=[IOCSource.SANDBOX],
        )
        self.report.iocs = [ioc]

        # Should not raise error
        enricher_no_misp.enrich_iocs(self.report)

        # IOC should remain unchanged
        enriched_ioc = next(ioc for ioc in self.report.iocs if ioc.ioc_type == IOCType.DOMAIN)
        self.assertEqual(enriched_ioc.value, "example.com")
        self.assertIsNone(enriched_ioc.misp_threat_level)


class TestMISPClientAPI(unittest.TestCase):
    """Test MISP client API interaction."""

    def test_misp_client_initialization(self):
        """Test MISP client can be initialized."""
        try:
            with patch.dict("os.environ", {"MISP_URL": "http://misp.test", "MISP_API_KEY": "testkey"}):
                client = MISPClient("http://misp.test", "testkey")
                self.assertIsNotNone(client)
                self.assertEqual(client.misp_url, "http://misp.test")
        except Exception as e:
            self.fail(f"Failed to initialize MISPClient: {e}")

    def test_misp_client_none_graceful(self):
        """Test that enricher handles None MISP client gracefully."""
        enricher = MISPEnricher(None)
        self.assertIsNotNone(enricher)
        # Should not raise errors
        report = MergedReport(
            file_name="test.exe",
            primary_hash="abc123",
            all_hashes={"md5": "abc"},
            consensus_verdict="malicious",
            source_reports=[],
        )
        enricher.enrich_iocs(report)  # Should complete without error


if __name__ == "__main__":
    unittest.main()
