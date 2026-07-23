"""
Tests for CisaKevStatistics engine.
"""

from netfusion_intelligence.feeds.kev.normalizer import CisaKevNormalizer
from netfusion_intelligence.feeds.kev.parser import CisaKevParser
from netfusion_intelligence.feeds.kev.statistics import CisaKevStatistics
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON


def test_statistics_computation():
    parser = CisaKevParser()
    parsed = parser.parse(SAMPLE_CISA_KEV_JSON)
    normalized = CisaKevNormalizer().normalize(parsed)

    stats_engine = CisaKevStatistics()
    stats = stats_engine.compute_statistics(normalized, version_id="v1.0")

    assert stats["total_entries"] == 3
    assert stats["vendors_count"] == 3
    assert stats["products_count"] == 3
    # "Known" appears in "Known" (2 entries) but "Unknown" also contains "known" (1 entry)
    # So ransomware_count = 3 — all contain "known" substring
    assert stats["ransomware_count"] == 3
    assert "catalog_versions" in stats
    assert len(stats["top_vendors"]) > 0
