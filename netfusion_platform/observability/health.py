"""
NetFusion Platform Health Aggregator Module
Aggregates health across Collectors, AI Providers, Workflow Engine, and System Resources.
"""

import time
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False


@dataclass
class PlatformHealthReport:
    """Aggregated Health Report structure for Dashboard and Probe APIs."""
    status: str  # HEALTHY, DEGRADED, UNHEALTHY
    uptime_seconds: float
    timestamp: float
    collectors: Dict[str, Any] = field(default_factory=dict)
    ai_providers: Dict[str, Any] = field(default_factory=dict)
    workflow_engine: Dict[str, Any] = field(default_factory=dict)
    system: Dict[str, Any] = field(default_factory=dict)
    components: Dict[str, Any] = field(default_factory=dict)


class HealthAggregator:
    """Aggregates component statuses into platform-wide health report."""

    def __init__(self):
        self._start_time = time.time()
        self._registered_checkers: Dict[str, Any] = {}

    def register_checker(self, name: str, checker_fn: Any) -> None:
        """Register a health checker callback function returning a health status dict or object."""
        self._registered_checkers[name] = checker_fn

    def get_aggregated_health(self) -> PlatformHealthReport:
        """Evaluate all registered health checkers and compute overall platform health."""
        now = time.time()
        uptime = now - self._start_time
        
        collectors_health: Dict[str, Any] = {}
        ai_health: Dict[str, Any] = {}
        workflow_health: Dict[str, Any] = {}
        component_health: Dict[str, Any] = {}
        
        overall_status = "HEALTHY"

        # System Health (CPU, RAM)
        sys_health = self._get_system_health()

        for name, checker in self._registered_checkers.items():
            try:
                res = checker() if callable(checker) else checker
                if hasattr(res, "to_dict"):
                    res_dict = res.to_dict()
                elif hasattr(res, "__dict__"):
                    res_dict = res.__dict__
                elif isinstance(res, dict):
                    res_dict = res
                else:
                    res_dict = {"status": str(res)}

                st = res_dict.get("status", "HEALTHY").upper()
                if st in ("UNHEALTHY", "FAILED", "DOWN", "ERROR"):
                    overall_status = "UNHEALTHY"
                elif st in ("DEGRADED", "WARNING") and overall_status != "UNHEALTHY":
                    overall_status = "DEGRADED"

                if name.startswith("collector_"):
                    collectors_health[name] = res_dict
                elif name.startswith("ai_"):
                    ai_health[name] = res_dict
                elif name.startswith("workflow"):
                    workflow_health[name] = res_dict
                else:
                    component_health[name] = res_dict

            except Exception as e:
                overall_status = "UNHEALTHY"
                component_health[name] = {"status": "UNHEALTHY", "error": str(e)}

        return PlatformHealthReport(
            status=overall_status,
            uptime_seconds=round(uptime, 2),
            timestamp=now,
            collectors=collectors_health,
            ai_providers=ai_health,
            workflow_engine=workflow_health,
            system=sys_health,
            components=component_health,
        )

    def _get_system_health(self) -> Dict[str, Any]:
        """Fetch system CPU and Memory metrics safely."""
        if not HAS_PSUTIL or psutil is None:
            return {"status": "HEALTHY", "info": "psutil not installed; metrics simulated"}
        try:
            cpu_pct = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            return {
                "cpu_percent": cpu_pct,
                "memory_percent": mem.percent,
                "memory_available_mb": round(mem.available / (1024 * 1024), 2),
                "status": "HEALTHY" if mem.percent < 95.0 else "DEGRADED",
            }
        except Exception:
            return {"status": "UNKNOWN", "info": "psutil metrics unavailable"}
