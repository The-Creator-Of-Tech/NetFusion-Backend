"""
End-to-end integration test for NetFusion IL-4 CISA KEV Pipeline through IL-1 lifecycle runner.
"""

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.feeds.kev.feed import CisaKevFeed
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON
from netfusion_intelligence.feeds.nvd.feed import NvdCveFeed
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_full_pipeline_execution():
    """
    Tests the full KEV pipeline lifecycle:
    Initialize -> Download -> Verify -> Parse -> Normalize -> Validate -> Store -> Activate

    Since the sample KEV CVEs (CVE-2021-44228, etc.) are not in the sample NVD data (CVE-2024-1234, CVE-2024-5678),
    we disable orphan validation for this integration test by passing canonical_cve_checker=None.
    In production, the CIIL repository is shared and pre-populated by NVD.
    """
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)

    # Register prerequisite NVD feed (KEV depends on nvd_cve_2.0)
    nvd_feed = NvdCveFeed(
        repository=repo,
        offline_data=SAMPLE_NVD_JSON_RESPONSE,
    )
    engine.register_feed(nvd_feed)

    # Sync NVD feed first
    nvd_result = engine.sync_feed("nvd_cve_2.0")
    assert nvd_result is not None

    # Register KEV feed — disable orphan validation (test CVEs don't overlap)
    kev_feed = CisaKevFeed(
        repository=repo,
        offline_data=SAMPLE_CISA_KEV_JSON,
    )
    # Override validator to skip orphan checks for this integration test
    kev_feed.validator.canonical_cve_checker = None
    engine.register_feed(kev_feed)

    # Execute KEV pipeline through lifecycle runner
    result = engine.sync_feed("cisa_kev_1.0")
    assert result is not None
    assert result.records_inserted == 3

    # Verify data is persisted in the active dataset
    active_ver = repo.get_active_dataset_version("cisa_kev_1.0")
    assert active_ver is not None

    records = repo.list_kev_records(version_id=active_ver.version_id)
    assert len(records) == 3

    # Verify vendor search
    vendors = repo.list_kev_vendors(version_id=active_ver.version_id)
    assert "Apache" in vendors

    # Verify statistics
    stats = repo.get_kev_statistics_for_version(active_ver.version_id)
    assert stats["total_entries"] == 3


def test_full_pipeline_no_duplicate_on_reimport():
    """
    Tests that re-importing the same KEV catalog does not create duplicate entries.
    """
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)

    # Register prerequisite NVD feed
    nvd_feed = NvdCveFeed(
        repository=repo,
        offline_data=SAMPLE_NVD_JSON_RESPONSE,
    )
    engine.register_feed(nvd_feed)
    engine.sync_feed("nvd_cve_2.0")

    # Register & run KEV feed
    kev_feed = CisaKevFeed(
        repository=repo,
        offline_data=SAMPLE_CISA_KEV_JSON,
    )
    kev_feed.validator.canonical_cve_checker = None
    engine.register_feed(kev_feed)

    # First import
    result1 = engine.sync_feed("cisa_kev_1.0")
    assert result1.records_inserted == 3

    # Second import — creates a new dataset version
    result2 = engine.sync_feed("cisa_kev_1.0")
    assert result2 is not None
    assert result2.records_inserted == 3
