"""
Health models for feeds and the overall intelligence engine.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class FeedHealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


@dataclass
class FeedHealth:
    """
    Health state of a specific intelligence feed.
    """
    feed_id: str
    status: FeedHealthStatus = FeedHealthStatus.UNKNOWN
    availability: float = 100.0
    last_sync_at: Optional[str] = None
    next_sync_at: Optional[str] = None
    last_success_at: Optional[str] = None
    last_failure_at: Optional[str] = None
    consecutive_failures: int = 0
    total_sync_count: int = 0
    successful_sync_count: int = 0
    failed_sync_count: int = 0
    last_error: Optional[str] = None
    validation_state: str = "N/A"
    validation_health: str = "PASSED"
    active_dataset_version: Optional[str] = None
    last_execution_duration_sec: float = 0.0
    average_execution_time: float = 0.0
    dependency_health: str = "HEALTHY"
    trust_status: str = "TRUSTED"
    certificate_status: str = "VALID"
    signature_status: str = "VERIFIED"
    last_successful_verification: Optional[str] = None
    trust_failures: int = 0
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, FeedHealthStatus) else self.status
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedHealth":
        if not data:
            raise ValueError("Data dictionary cannot be empty")
        d = dict(data)
        if "status" in d and isinstance(d["status"], str):
            d["status"] = FeedHealthStatus(d["status"])
        return cls(**d)


@dataclass
class HealthSummary:
    """
    Overall health summary and dashboard for the intelligence subsystem.
    """
    system_status: FeedHealthStatus
    total_feeds: int
    healthy_feeds: int
    degraded_feeds: int
    unhealthy_feeds: int
    scheduler_status: str = "STOPPED"
    overall_framework_health: str = "HEALTHY"
    feed_healths: List[FeedHealth] = field(default_factory=list)
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_status": self.system_status.value if isinstance(self.system_status, FeedHealthStatus) else self.system_status,
            "total_feeds": self.total_feeds,
            "healthy_feeds": self.healthy_feeds,
            "degraded_feeds": self.degraded_feeds,
            "unhealthy_feeds": self.unhealthy_feeds,
            "scheduler_status": self.scheduler_status,
            "overall_framework_health": self.overall_framework_health,
            "feed_healths": [fh.to_dict() for fh in self.feed_healths],
            "timestamp": self.timestamp,
        }
