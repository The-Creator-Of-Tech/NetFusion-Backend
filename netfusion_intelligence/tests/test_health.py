"""
Unit tests for Health System metrics and status calculation.
"""

import pytest
from netfusion_intelligence.models.health import FeedHealthStatus


def test_health_updates_on_sync_success_and_failure(engine, sample_feed):
    engine.register_feed(sample_feed)
    engine.sync_feed(sample_feed.feed_id)

    health = engine.get_health(sample_feed.feed_id)
    assert health.status == FeedHealthStatus.HEALTHY
    assert health.successful_sync_count == 1
    assert health.availability == 100.0

    summary = engine.get_health()
    assert summary.total_feeds == 1
    assert summary.healthy_feeds == 1
