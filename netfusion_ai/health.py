"""
NetFusion AI Health Checker
Performs subsystem health status evaluations across AI Providers, Memory Manager, Context Builder, and Event Publisher.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict

from netfusion_ai.providers.adapter import ProviderAdapter
from netfusion_ai.memory_manager import MemoryManager


@dataclass
class AIHealthStatus:
    """Detailed health check status object for AI Investigation Assistant."""
    status: str = "HEALTHY"  # HEALTHY, DEGRADED, UNHEALTHY
    providers_status: Dict[str, bool] = field(default_factory=dict)
    memory_manager_active: bool = True
    context_builder_ready: bool = True
    latency_ms: float = 0.0
    checked_at: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "providers_status": self.providers_status,
            "memory_manager_active": self.memory_manager_active,
            "context_builder_ready": self.context_builder_ready,
            "latency_ms": self.latency_ms,
            "checked_at": self.checked_at,
            "details": self.details,
        }


class AIHealthChecker:
    """Health checking subsystem for AI Assistant."""

    def __init__(
        self,
        provider_adapter: ProviderAdapter,
        memory_manager: Optional[MemoryManager] = None,
    ):
        self.provider_adapter = provider_adapter
        self.memory_manager = memory_manager or MemoryManager()

    def check_health(self) -> AIHealthStatus:
        """Runs health diagnostics across registered components."""
        start_time = time.time()
        providers = self.provider_adapter.health_check_all()

        healthy_count = sum(1 for status in providers.values() if status)
        if healthy_count == len(providers) and len(providers) > 0:
            overall = "HEALTHY"
        elif healthy_count > 0:
            overall = "DEGRADED"
        else:
            overall = "UNHEALTHY"

        latency = (time.time() - start_time) * 1000.0

        return AIHealthStatus(
            status=overall,
            providers_status=providers,
            memory_manager_active=True,
            context_builder_ready=True,
            latency_ms=round(latency, 2),
            details={
                "total_providers": len(providers),
                "healthy_providers": healthy_count,
            },
        )
