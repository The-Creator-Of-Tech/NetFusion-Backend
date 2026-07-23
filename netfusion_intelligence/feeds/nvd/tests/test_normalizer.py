"""
Unit tests for NVD Normalizer (normalizer.py).
"""

from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.parser import NvdParser
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE, SAMPLE_NVD_CVE_2024_1234


def test_normalize_single_cve():
    normalizer = NvdNormalizer()
    cve = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)

    assert cve.cve_id == "CVE-2024-1234"
    assert cve.severity == "CRITICAL"
    assert cve.cvss_score == 10.0
    assert "CWE-89" in cve.cwes
    assert "example" in cve.vendors
    assert "product" in cve.products
    assert len(cve.references) == 1


def test_normalize_parsed_payload():
    parser = NvdParser()
    normalizer = NvdNormalizer()

    parsed = parser.parse(SAMPLE_NVD_JSON_RESPONSE)
    norm = normalizer.normalize(parsed)

    assert norm["count"] == 2
    assert "CVE-2024-1234" in norm["entities"]
    assert "CVE-2024-5678" in norm["entities"]
