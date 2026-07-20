"""
Unit tests for IntelligenceRepository abstractions and table persistence.
"""

import pytest
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion, ValidationStatus
from netfusion_intelligence.models.health import FeedHealth, FeedHealthStatus


def test_repository_feed_and_version_persistence(repo):
    feed_rec = repo.save_feed_record("f1", "Feed 1", "Desc", {"timeout": 100})
    assert feed_rec["feed_id"] == "f1"

    version = DatasetVersion(
        feed_id="f1",
        version_id="v-100",
        checksum="abcd",
        record_count=50,
        status=DatasetStatus.ACTIVE,
        validation_status=ValidationStatus.PASSED,
    )
    repo.save_dataset_version(version)

    fetched = repo.get_dataset_version("v-100")
    assert fetched is not None
    assert fetched.checksum == "abcd"
    assert fetched.record_count == 50

    active = repo.get_active_dataset_version("f1")
    assert active.version_id == "v-100"
