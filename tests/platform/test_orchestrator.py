"""
Integration tests for NetFusion PlatformOrchestrator.
"""

import pytest
from netfusion_platform.orchestrator import PlatformOrchestrator


def test_orchestrator_lifecycle():
    orch = PlatformOrchestrator()
    assert not orch._is_started
    
    orch.startup()
    assert orch._is_started
    
    health = orch.get_health()
    assert health.status in ("HEALTHY", "DEGRADED")
    assert "workflow_service" in health.workflow_engine
    assert "sysmon" in health.collectors.get("collector_sysmon", {}).get("name", "")
    
    orch.shutdown()
    assert orch._is_shutdown
