"""
Unit tests for Dataset Rollback capability.
"""

import pytest
from netfusion_intelligence.models.dataset import DatasetStatus
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed


def test_rollback_to_previous_active_version(engine, sample_feed):
    engine.register_feed(sample_feed)
    res1 = engine.sync_feed(sample_feed.feed_id)
    v1_id = res1.version_id

    res2 = engine.sync_feed(sample_feed.feed_id)
    v2_id = res2.version_id

    assert engine.repository.get_active_dataset_version(sample_feed.feed_id).version_id == v2_id

    # Execute Rollback
    restored = engine.rollback_dataset(sample_feed.feed_id, target_version_id=v1_id)
    assert restored.version_id == v1_id
    assert engine.repository.get_active_dataset_version(sample_feed.feed_id).version_id == v1_id

    rolled_back_v2 = engine.repository.get_dataset_version(v2_id)
    assert rolled_back_v2.status == DatasetStatus.ROLLED_BACK
