"""
Integration tests for full 13-step IL-1 pipeline lifecycle execution with NvdCveFeed.
"""

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.feeds.nvd.feed import NvdCveFeed
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_nvd_full_pipeline_execution():
    sql_repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    engine = IntelligenceEngine(repository=sql_repo)

    feed = NvdCveFeed(repository=sql_repo, offline_data=SAMPLE_NVD_JSON_RESPONSE)
    engine.register_feed(feed)

    # Trigger full sync execution (Steps 1 through 13)
    result = engine.sync_feed("nvd_cve_2.0")

    assert result.status.value == "COMPLETED"
    assert result.records_processed == 2
    assert result.records_inserted == 2
    assert result.validation_passed is True

    # Verify active version was created and set
    active_ver = sql_repo.get_active_dataset_version("nvd_cve_2.0")
    assert active_ver is not None
    assert active_ver.record_count == 2

    # Verify records persisted in database
    retrieved_cve = sql_repo.get_nvd_cve("CVE-2024-1234")
    assert retrieved_cve is not None
    assert retrieved_cve["cve_id"] == "CVE-2024-1234"
    assert retrieved_cve["severity"] == "CRITICAL"
