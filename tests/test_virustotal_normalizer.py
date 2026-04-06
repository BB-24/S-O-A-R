"""Unit tests for VirusTotal normalizer risk scoring."""

from normalizers.virustotal import VirusTotalNormalizer
from schema import ThreatLevel


def _vt_response(last_analysis_stats):
    return {
        "data": {
            "attributes": {
                "name": "sample.bin",
                "sha256": "abc123",
                "last_analysis_stats": last_analysis_stats,
                "last_analysis_results": {},
            }
        }
    }


def test_dynamic_risk_score_varies_for_malicious_counts():
    """Risk score should not collapse to a fixed value for all malicious files."""
    normalizer = VirusTotalNormalizer()

    lower_detection = _vt_response({"malicious": 5, "suspicious": 0, "undetected": 65})
    higher_detection = _vt_response({"malicious": 40, "suspicious": 0, "undetected": 30})

    low_report = normalizer.normalize(lower_detection)
    high_report = normalizer.normalize(higher_detection)

    assert low_report.risk is not None
    assert high_report.risk is not None
    assert high_report.risk.overall_score > low_report.risk.overall_score


def test_clean_file_results_in_low_informational_score():
    """Files with no detections should score as low/informational."""
    normalizer = VirusTotalNormalizer()

    clean_response = _vt_response({"malicious": 0, "suspicious": 0, "undetected": 70})
    report = normalizer.normalize(clean_response)

    assert report.risk is not None
    assert report.risk.overall_score <= 10.0
    assert report.risk.threat_level in {ThreatLevel.INFORMATIONAL, ThreatLevel.LOW}
