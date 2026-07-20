"""
Background Scheduler and Concurrency Protection Engine for Intelligence feeds.
"""

import asyncio
from datetime import datetime, timezone
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from netfusion_intelligence.core.dependency import FeedDependencyGraph
from netfusion_intelligence.core.events import EventBus, SchedulerStarted, SchedulerStopped
from netfusion_intelligence.core.exceptions import SchedulerError
from netfusion_intelligence.core.lifecycle import FeedLifecycleRunner
from netfusion_intelligence.core.registry import FeedRegistry
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.models.import_result import ImportResult


class IntelligenceScheduler:
    """
    Manages feed schedules, manual triggers, retries, cancellation, and concurrency locks.
    """

    def __init__(self, registry: FeedRegistry, lifecycle_runner: FeedLifecycleRunner, event_bus: EventBus):
        self.registry = registry
        self.lifecycle_runner = lifecycle_runner
        self.event_bus = event_bus

        self._feed_locks: Dict[str, threading.Lock] = {}
        self._cancellation_tokens: Set[str] = set()
        self._active_sync_threads: Dict[str, threading.Thread] = {}
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def _get_feed_lock(self, feed_id: str) -> threading.Lock:
        with self._lock:
            if feed_id not in self._feed_locks:
                self._feed_locks[feed_id] = threading.Lock()
            return self._feed_locks[feed_id]

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def trigger_sync(self, feed_id: str, retry_count: Optional[int] = None) -> ImportResult:
        """
        Manually trigger synchronization for a specific feed.
        Enforces per-feed mutex lock and dependency prerequisite validation.
        """
        feed = self.registry.get(feed_id)

        # Dependency & Prerequisite Check
        all_feeds = self.registry.list_feeds()
        dep_graph = FeedDependencyGraph(all_feeds)
        healths = {h.feed_id: h for h in self.lifecycle_runner.repository.list_feed_healths()}
        satisfied, reason = dep_graph.validate_prerequisites(feed_id, health_map=healths)
        if not satisfied:
            raise SchedulerError(f"Prerequisite failure for feed '{feed_id}': {reason}")

        feed_lock = self._get_feed_lock(feed_id)
        acquired = feed_lock.acquire(blocking=False)
        if not acquired:
            raise SchedulerError(f"Synchronization for feed '{feed_id}' is already in progress")

        try:
            with self._lock:
                self._cancellation_tokens.discard(feed_id)

            max_retries = retry_count if retry_count is not None else feed.config.retry_count
            attempt = 0
            last_exception: Optional[Exception] = None

            while attempt <= max_retries:
                with self._lock:
                    if feed_id in self._cancellation_tokens:
                        raise SchedulerError(f"Synchronization for feed '{feed_id}' was cancelled")

                try:
                    return self.lifecycle_runner.execute(feed)
                except Exception as ex:
                    last_exception = ex
                    attempt += 1
                    if attempt <= max_retries:
                        time.sleep(feed.config.retry_delay)

            raise SchedulerError(f"Sync failed for feed '{feed_id}' after {max_retries + 1} attempts: {last_exception}")

        finally:
            feed_lock.release()

    def cancel_sync(self, feed_id: str) -> bool:
        """
        Requests cancellation of an ongoing feed synchronization.
        """
        with self._lock:
            self._cancellation_tokens.add(feed_id)
            return True

    def start(self) -> None:
        """
        Starts the background scheduler loop.
        """
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self._worker_thread.start()
            self.event_bus.publish(SchedulerStarted(active_feeds_count=len(self.registry.list_feeds())))

    def stop(self) -> None:
        """
        Stops the background scheduler loop.
        """
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self.event_bus.publish(SchedulerStopped(reason="Normal Shutdown"))

    def _scheduler_loop(self) -> None:
        """Background thread loop polling feeds."""
        while self._running:
            feeds = self.registry.list_feeds()
            for feed in feeds:
                if not self._running:
                    break
                if not feed.config.enabled:
                    continue
                # For basic scheduler loop, execute enabled feeds if lock is free
                feed_lock = self._get_feed_lock(feed.feed_id)
                if not feed_lock.locked():
                    thread = threading.Thread(target=self._run_feed_async, args=(feed.feed_id,), daemon=True)
                    thread.start()
            time.sleep(1.0)

    def _run_feed_async(self, feed_id: str) -> None:
        try:
            self.trigger_sync(feed_id)
        except Exception:
            pass
