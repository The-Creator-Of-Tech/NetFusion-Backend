"""
Unit tests for Domain Event Bus.
"""

import pytest
from netfusion_intelligence.core.events import EventBus, FeedCompleted, FeedRegistered, FeedStarted


def test_event_bus_publish_subscribe():
    bus = EventBus()
    received_events = []

    def on_feed_registered(event: FeedRegistered):
        received_events.append(event)

    bus.subscribe(FeedRegistered, on_feed_registered)
    bus.publish(FeedRegistered(feed_id="test_feed", feed_name="Test Feed"))

    assert len(received_events) == 1
    assert received_events[0].feed_id == "test_feed"
    assert len(bus.get_history()) == 1
