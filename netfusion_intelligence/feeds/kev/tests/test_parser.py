"""
Tests for CisaKevParser.
"""

from netfusion_intelligence.feeds.kev.parser import CisaKevParser
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON, SAMPLE_CISA_KEV_CSV


def test_parse_json_dict():
    parser = CisaKevParser()
    result = parser.parse(SAMPLE_CISA_KEV_JSON)
    assert result["count"] == 3
    assert len(result["vulnerabilities"]) == 3
    assert result["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"


def test_parse_csv_string():
    parser = CisaKevParser()
    result = parser.parse(SAMPLE_CISA_KEV_CSV)
    assert result["count"] == 2
    assert len(result["vulnerabilities"]) == 2
    assert result["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"
