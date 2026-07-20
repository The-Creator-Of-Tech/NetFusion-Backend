"""
Unit tests for IntelligenceScheduler and Concurrency Locks.
"""

import threading
import time
import pytest
from netfusion_intelligence.core.exceptions import SchedulerError
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed


def test_scheduler_manual_sync(engine, sample_feed):
    engine.register_feed(sample_feed)
    res = engine.scheduler.trigger_sync(sample_feed.feed_id)
    assert res.records_processed == 1


def test_scheduler_concurrency_protection(engine, sample_feed):
    engine.register_feed(sample_feed)
    feed_lock = engine.scheduler._get_feed_lock(sample_feed.feed_id)

    # Acquire lock manually
    feed_lock.acquire()
    try:
        with pytest.raises(SchedulerError) as exc_info:
            engine.scheduler.trigger_sync(sample_feed.feed_id)
        assert "already in progress" in str(exc_info.value)
    finally:
        feed_lock.release()


def test_scheduler_retries_on_failure(engine):
    feed = SampleGenericIntelligenceFeed("failing_feed")
    feed.should_fail_download = True
    engine.register_feed(feed)

    with pytest.raises(SchedulerError):
        engine.scheduler.trigger_sync("failing_feed", retry_count=1)
