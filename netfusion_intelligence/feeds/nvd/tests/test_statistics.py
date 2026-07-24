"""
Unit tests for NVD Statistics Engine (statistics.py).
"""

from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.statistics import NvdStatistics
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_CVE_2024_1234, SAMPLE_NVD_CVE_2024_5678


def test_statistics_calculation():
    normalizer = NvdNormalizer()
    stats_engine = NvdStatistics()

    cve1 = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)
    cve2 = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_5678)

    stats = stats_engine.compute_statistics([cve1, cve2])

    assert stats["total_cves"] == 2
    assert stats["cves_by_severity"]["CRITICAL"] == 1
    assert stats["cves_by_severity"]["MEDIUM"] == 1
    assert stats["average_cvss"] == round((10.0 + 6.1) / 2, 2)
    assert "CWE-89" in stats["cves_by_cwe"]
    assert "CWE-79" in stats["cves_by_cwe"]
