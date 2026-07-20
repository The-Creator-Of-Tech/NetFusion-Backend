from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional
import time


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


@dataclass
class HealthReport:
    status: HealthStatus
    collector_id: str
    collector_type: str
    checks: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class HealthManager:
    """Health Manager coordinating dependency checks, liveness, and readiness probes."""

    @staticmethod
    def run_health_checks(collector_id: str, collector_type: str, checkers: List[Any]) -> HealthReport:
        checks: Dict[str, Any] = {}
        errors: List[str] = []
        overall_status = HealthStatus.HEALTHY

        for checker in checkers:
            try:
                res = checker()
                name = res.get("name", "unknown_check")
                passed = res.get("passed", False)
                details = res.get("details", {})
                checks[name] = {"passed": passed, "details": details}
                if not passed:
                    overall_status = HealthStatus.UNHEALTHY
                    errors.append(f"Check '{name}' failed: {res.get('error', 'Unspecified error')}")
            except Exception as e:
                overall_status = HealthStatus.UNHEALTHY
                errors.append(f"Check exception: {str(e)}")

        return HealthReport(
            status=overall_status,
            collector_id=collector_id,
            collector_type=collector_type,
            checks=checks,
            errors=errors,
        )
