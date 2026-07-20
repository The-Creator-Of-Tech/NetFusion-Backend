"""
NetFusion Backpressure & Graceful Degradation Module
Bounded queues, rate limiters, and fallback degradation strategies.
"""

import time
import logging
import queue
import threading
from typing import Callable, Any, Optional, Dict

logger = logging.getLogger(__name__)


class QueueFullException(Exception):
    """Raised when bounded backpressure queue capacity is exceeded."""
    pass


class BoundedBackpressureQueue:
    """Thread-safe bounded queue that sheds load or blocks when backpressure threshold is reached."""

    def __init__(self, maxsize: int = 1000, reject_on_overflow: bool = True):
        self._maxsize = maxsize
        self._reject_on_overflow = reject_on_overflow
        self._queue = queue.Queue(maxsize=maxsize)

    def push(self, item: Any, timeout: float = 0.5) -> bool:
        """Push item to queue; raises QueueFullException if full and reject_on_overflow is True."""
        try:
            self._queue.put(item, block=not self._reject_on_overflow, timeout=timeout)
            return True
        except queue.Full:
            if self._reject_on_overflow:
                raise QueueFullException(f"Backpressure Queue capacity ({self._maxsize}) exceeded. Shedding load.")
            return False

    def pop(self, timeout: Optional[float] = 1.0) -> Any:
        """Pop item from queue."""
        try:
            return self._queue.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

    def size(self) -> int:
        return self._queue.qsize()


class GracefulDegradationManager:
    """Manages primary service execution with automatic fallback on failure."""

    def __init__(self):
        self._fallbacks: Dict[str, Callable] = {}

    def register_fallback(self, name: str, fallback_fn: Callable) -> None:
        """Register a fallback function for a named service or provider."""
        self._fallbacks[name] = fallback_fn

    def execute_with_fallback(self, name: str, primary_fn: Callable, *args, **kwargs) -> Any:
        """Attempt primary execution; fall back to fallback_fn if primary fails."""
        try:
            return primary_fn(*args, **kwargs)
        except Exception as primary_error:
            logger.warning("Primary operation '%s' failed (%s). Attempting graceful fallback...", name, primary_error)
            fallback = self._fallbacks.get(name)
            if fallback:
                try:
                    return fallback(*args, **kwargs)
                except Exception as fallback_error:
                    logger.error("Fallback operation '%s' also failed: %s", name, fallback_error)
                    raise primary_error
            else:
                raise primary_error
