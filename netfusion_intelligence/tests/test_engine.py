"""
Unit & Integration tests for IntelligenceEngine.
"""

import pytest
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.models.dataset import DatasetStatus
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed


def test_engine_registration_and_list(engine, sample_feed):
    assert len(engine.list_feeds()) == 0
    engine.register_feed(sample_feed)
    assert len(engine.list_feeds()) == 1
    assert engine.get_feed("sample_intel_feed").feed_name == sample_feed.feed_name


def test_engine_sync_execution(engine, sample_feed):
    engine.register_feed(sample_feed)
    res = engine.sync_feed(sample_feed.feed_id)

    assert res.records_processed == 1
    assert res.validation_passed is True
    assert res.duration_seconds >= 0.0

    versions = engine.get_dataset_versions(sample_feed.feed_id)
    assert len(versions) == 1
    assert versions[0].status == DatasetStatus.ACTIVE


def test_engine_sync_all(engine):
    feed1 = SampleGenericIntelligenceFeed("feed_1")
    feed2 = SampleGenericIntelligenceFeed("feed_2")

    engine.register_feed(feed1)
    engine.register_feed(feed2)

    results = engine.sync_all()
    assert len(results) == 2
    assert len(engine.get_dataset_versions()) == 2
