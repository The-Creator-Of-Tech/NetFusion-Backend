"""
NetFusion Circuit Breaker Module
Stateful circuit breaker (CLOSED, OPEN, HALF_OPEN) protecting third-party providers & services.
"""

import time
import threading
from enum import Enum
from typing import Callable, Any, Type, Tuple, Optional


class CircuitState(str, Enum):
    CLOSED = "CLOSED"      # Normal operation, passing requests
    OPEN = "OPEN"          # Trip open, failing fast without executing target
    HALF_OPEN = "HALF_OPEN"# Trial state, testing recovery with limited requests


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is executed while circuit breaker is OPEN."""
    def __init__(self, name: str, reset_remaining_seconds: float):
        self.name = name
        self.reset_remaining_seconds = reset_remaining_seconds
        super().__init__(f"Circuit Breaker '{name}' is OPEN. Fast failing request. Try again in {reset_remaining_seconds:.1f}s")


class CircuitBreaker:
    """Thread-safe Circuit Breaker protection wrapper."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
        expected_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.expected_exceptions = expected_exceptions

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._success_count_half_open = 0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._update_state_if_needed()
            return self._state

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute protected function through circuit breaker."""
        with self._lock:
            self._update_state_if_needed()

            if self._state == CircuitState.OPEN:
                remaining = max(0.0, self.recovery_timeout_seconds - (time.time() - self._last_failure_time))
                raise CircuitBreakerOpenException(self.name, remaining)

        # Attempt execution
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as e:
            self._on_failure()
            raise e

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count_half_open = 0

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN

    def _update_state_if_needed(self) -> None:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.recovery_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._success_count_half_open = 0

    def reset(self) -> None:
        """Manually reset circuit breaker to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = 0.0
