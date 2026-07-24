"""
Unit tests for NVD Repository (repository.py).
"""

from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.repository import NvdRepository
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_CVE_2024_1234, SAMPLE_NVD_CVE_2024_5678
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_nvd_repository_store_and_retrieve():
    sql_repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    nvd_repo = NvdRepository(sql_repo)
    normalizer = NvdNormalizer()

    cve1 = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)
    cve2 = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_5678)

    version_id = "v2.0-test"
    res = nvd_repo.store_cves(version_id, [cve1, cve2])

    assert res["inserted"] == 2

    # Retrieve CVE
    retrieved = nvd_repo.get_cve("CVE-2024-1234", version_id=version_id)
    assert retrieved is not None
    assert retrieved["cve_id"] == "CVE-2024-1234"
    assert retrieved["severity"] == "CRITICAL"

    # Search CVEs
    search_res = nvd_repo.search_cves(severity="CRITICAL", version_id=version_id)
    assert len(search_res) == 1
    assert search_res[0]["cve_id"] == "CVE-2024-1234"

    # Vendors & Products list
    vendors = nvd_repo.list_vendors(version_id=version_id)
    assert "example" in vendors or "acme" in vendors

    # Statistics
    stats = nvd_repo.get_statistics(version_id=version_id)
    assert stats["total_cves"] == 2
    assert stats["cves_by_severity"]["CRITICAL"] == 1
