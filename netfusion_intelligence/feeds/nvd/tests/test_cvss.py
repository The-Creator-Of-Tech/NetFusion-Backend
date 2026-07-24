"""
Unit tests for CVSS Engine (cvss.py).
"""

from netfusion_intelligence.feeds.nvd.cvss import CvssParser
from netfusion_intelligence.feeds.nvd.models import CvssMetric


def test_cvss_vector_parser():
    parser = CvssParser()
    vector_v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parsed = parser.parse_vector_string(vector_v31)
    
    assert parsed["version"] == "3.1"
    assert parsed["AV"] == "N"
    assert parsed["AC"] == "L"
    assert parsed["C"] == "H"


def test_cvss_metric_parser():
    parser = CvssParser()
    raw = {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL"
        },
        "exploitabilityScore": 3.9,
        "impactScore": 5.9
    }
    
    metric = parser.parse_cvss_metric(raw, version="3.1")
    assert metric.version == "3.1"
    assert metric.base_score == 9.8
    assert metric.severity == "CRITICAL"
    assert metric.exploitability_score == 3.9
    assert metric.impact_score == 5.9


def test_cvss_severity_comparison():
    assert CvssParser.compare_severity("CRITICAL", "HIGH") > 0
    assert CvssParser.compare_severity("HIGH", "HIGH") == 0
    assert CvssParser.compare_severity("LOW", "MEDIUM") < 0


def test_risk_score_calculation():
    metric = CvssMetric(version="3.1", vector_string="", base_score=8.0, severity="HIGH")
    risk_normal = CvssParser.calculate_risk_score(metric, epss_score=0.1, is_kev=False)
    risk_kev = CvssParser.calculate_risk_score(metric, epss_score=0.5, is_kev=True)

    assert risk_normal > 8.0
    assert risk_kev > risk_normal
