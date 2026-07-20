"""
Integration tests for Observability and Resiliency components.
"""

import pytest
import time
from netfusion_platform.observability import (
    PlatformMetricsManager,
    TraceTracer,
    HealthAggregator,
)
from netfusion_platform.resiliency import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerOpenException,
    execute_with_retry,
    BoundedBackpressureQueue,
    QueueFullException,
    GracefulDegradationManager,
)


def test_metrics_manager():
    mm = PlatformMetricsManager()
    mm.increment_counter("requests_total", 1.0)
    mm.set_gauge("active_tasks", 5.0)
    mm.record_histogram("request_latency_ms", 12.5)

    all_metrics = mm.get_all_metrics()
    assert all_metrics["counters"]["requests_total"] == 1.0
    assert all_metrics["gauges"]["active_tasks"] == 5.0
    assert all_metrics["histograms"]["request_latency_ms"]["count"] == 1


def test_circuit_breaker():
    cb = CircuitBreaker("test_cb", failure_threshold=2, recovery_timeout_seconds=0.5)
    assert cb.state == CircuitState.CLOSED

    def failing_fn():
        raise ValueError("simulated error")

    # Failure 1
    with pytest.raises(ValueError):
        cb.call(failing_fn)
    assert cb.state == CircuitState.CLOSED

    # Failure 2 -> Trips OPEN
    with pytest.raises(ValueError):
        cb.call(failing_fn)
    assert cb.state == CircuitState.OPEN

    # Call while OPEN fast-fails
    with pytest.raises(CircuitBreakerOpenException):
        cb.call(failing_fn)


def test_retry_policy():
    attempts = 0

    def flaky_fn():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ValueError("flaky failure")
        return "success"

    res = execute_with_retry(flaky_fn, max_attempts=3, initial_delay=0.01)
    assert res == "success"
    assert attempts == 3


def test_backpressure_and_degradation():
    q = BoundedBackpressureQueue(maxsize=2, reject_on_overflow=True)
    assert q.push("item_1")
    assert q.push("item_2")
    
    with pytest.raises(QueueFullException):
        q.push("item_3")

    dm = GracefulDegradationManager()
    dm.register_fallback("service_a", lambda: "fallback_val")

    def failing_primary():
        raise RuntimeError("Primary crashed")

    res = dm.execute_with_fallback("service_a", failing_primary)
    assert res == "fallback_val"
