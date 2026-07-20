"""
Thread-safe Feed Registry and dynamic feed plugin discovery.
"""

import importlib
import inspect
import pkgutil
import threading
from typing import Dict, List, Optional, Type

from netfusion_intelligence.core.config_validator import validate_feed_configuration
from netfusion_intelligence.core.exceptions import FeedNotFoundError, FeedRegistrationError
from netfusion_intelligence.interfaces.feed import FeedInterface


class FeedRegistry:
    """
    Registry for managing intelligence feed plugins.
    Strictly open for extension, closed for modification.
    """

    def __init__(self):
        self._feeds: Dict[str, FeedInterface] = {}
        self._lock = threading.Lock()

    def register(self, feed: FeedInterface) -> None:
        """
        Registers a feed plugin instance after configuration validation.
        """
        if not isinstance(feed, FeedInterface):
            raise FeedRegistrationError(f"Provided feed object '{feed}' does not implement FeedInterface")

        with self._lock:
            existing_ids = list(self._feeds.keys())
            # Allow updating existing registered feed if it's the same object/re-registration
            if hasattr(feed, "feed_id") and feed.feed_id in existing_ids:
                existing_ids.remove(feed.feed_id)
            validate_feed_configuration(feed, existing_feed_ids=existing_ids)
            self._feeds[feed.feed_id] = feed

    def unregister(self, feed_id: str) -> None:
        """
        Unregisters a feed plugin by ID.
        """
        with self._lock:
            if feed_id in self._feeds:
                del self._feeds[feed_id]

    def get(self, feed_id: str) -> FeedInterface:
        """
        Retrieves a registered feed plugin by ID.
        """
        with self._lock:
            feed = self._feeds.get(feed_id)
            if not feed:
                raise FeedNotFoundError(f"Feed '{feed_id}' is not registered in Intelligence Framework")
            return feed

    def has(self, feed_id: str) -> bool:
        """Check if feed ID is registered."""
        with self._lock:
            return feed_id in self._feeds

    def list_feeds(self) -> List[FeedInterface]:
        """
        Returns list of all registered feed instances.
        """
        with self._lock:
            return list(self._feeds.values())

    def discover_feeds(self, package_name: str) -> List[FeedInterface]:
        """
        Dynamically discovers and registers all FeedInterface subclasses in a package.
        """
        discovered: List[FeedInterface] = []
        try:
            package = importlib.import_module(package_name)
        except ImportError as e:
            raise FeedRegistrationError(f"Could not import package '{package_name}' for feed discovery: {e}")

        if hasattr(package, "__path__"):
            for _, modname, ispkg in pkgutil.iter_modules(package.__path__):
                full_mod_name = f"{package_name}.{modname}"
                try:
                    module = importlib.import_module(full_mod_name)
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, FeedInterface) and obj is not FeedInterface and not inspect.isabstract(obj):
                            try:
                                instance = obj()
                                self.register(instance)
                                discovered.append(instance)
                            except Exception as ex:
                                raise FeedRegistrationError(f"Failed to instantiate discovered feed '{obj.__name__}': {ex}")
                except ImportError:
                    continue
        return discovered

    def clear(self) -> None:
        """Clears all registered feeds."""
        with self._lock:
            self._feeds.clear()
