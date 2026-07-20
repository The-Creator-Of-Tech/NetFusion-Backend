"""
Tests for NetFusion AIHealthChecker.
"""

import pytest

from netfusion_ai import AIHealthChecker, ProviderAdapter, MockAIProvider, MemoryManager


def test_ai_health_checker():
    p1 = MockAIProvider(healthy=True)
    adapter = ProviderAdapter(primary_provider=p1)

    checker = AIHealthChecker(provider_adapter=adapter)
    status = checker.check_health()

    assert status.status == "HEALTHY"
    assert status.memory_manager_active is True
    assert status.context_builder_ready is True
    assert status.latency_ms >= 0.0
    assert status.details["healthy_providers"] == 1
