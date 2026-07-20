"""
Unit tests for FeedRegistry.
"""

import pytest
from netfusion_intelligence.core.exceptions import FeedNotFoundError, FeedRegistrationError
from netfusion_intelligence.core.registry import FeedRegistry
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed


def test_registry_register_get():
    registry = FeedRegistry()
    feed = SampleGenericIntelligenceFeed("test_feed")

    registry.register(feed)
    assert registry.has("test_feed") is True
    assert registry.get("test_feed") == feed


def test_registry_not_found():
    registry = FeedRegistry()
    with pytest.raises(FeedNotFoundError):
        registry.get("non_existent_feed")


def test_registry_invalid_registration():
    registry = FeedRegistry()
    with pytest.raises(FeedRegistrationError):
        registry.register("invalid_feed_obj")


def test_registry_unregister():
    registry = FeedRegistry()
    feed = SampleGenericIntelligenceFeed("temp_feed")
    registry.register(feed)
    assert registry.has("temp_feed") is True

    registry.unregister("temp_feed")
    assert registry.has("temp_feed") is False
