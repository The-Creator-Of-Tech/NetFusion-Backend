"""
Tests for CisaKevNormalizer.
"""

from netfusion_intelligence.feeds.kev.normalizer import CisaKevNormalizer
from netfusion_intelligence.feeds.kev.parser import CisaKevParser
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON


def test_normalize():
    parser = CisaKevParser()
    parsed = parser.parse(SAMPLE_CISA_KEV_JSON)

    normalizer = CisaKevNormalizer()
    normalized = normalizer.normalize(parsed)

    assert normalized["count"] == 3
    entities = normalized["entities"]
    assert "CVE-2021-44228" in entities
    rec = entities["CVE-2021-44228"]
    assert rec.vendor_project == "Apache"
    assert rec.product == "Log4j"
    assert rec.known_ransomware_campaign_use == "Known"
    assert rec.due_date == "2021-12-24"
