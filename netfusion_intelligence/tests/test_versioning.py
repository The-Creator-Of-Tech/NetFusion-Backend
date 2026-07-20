"""
Unit tests for DatasetVersionManager.
"""

import pytest
from netfusion_intelligence.models.dataset import DatasetStatus, ValidationStatus


def test_immutable_version_creation(engine, sample_feed):
    engine.register_feed(sample_feed)
    engine.sync_feed(sample_feed.feed_id)
    engine.sync_feed(sample_feed.feed_id)

    versions = engine.get_dataset_versions(sample_feed.feed_id)
    assert len(versions) == 2
    # Check that previous version was archived and latest is active
    active = [v for v in versions if v.status == DatasetStatus.ACTIVE]
    archived = [v for v in versions if v.status == DatasetStatus.ARCHIVED]
    assert len(active) == 1
    assert len(archived) == 1
