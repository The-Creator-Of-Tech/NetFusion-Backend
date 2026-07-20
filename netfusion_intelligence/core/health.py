"""
Health Monitor subsystem for netfusion_intelligence.
Computes feed health status, availability percentages, failure tracking, and health summary.
"""

from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional

from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.health import FeedHealth, FeedHealthStatus, HealthSummary


class HealthMonitor:
    """
    Monitors health metrics for all intelligence feeds and the global subsystem.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository
        self._lock = threading.Lock()

    def record_sync_success(
        self,
        feed_id: str,
        duration: float,
        active_version_id: Optional[str] = None,
        validation_state: str = "PASSED",
        next_sync_at: Optional[str] = None,
    ) -> FeedHealth:
        """
        Record a successful synchronization run for a feed.
        """
        with self._lock:
            existing = self.repository.get_feed_health(feed_id)
            now_str = datetime.now(timezone.utc).isoformat()

            if not existing:
                health = FeedHealth(
                    feed_id=feed_id,
                    status=FeedHealthStatus.HEALTHY,
                    availability=100.0,
                    last_sync_at=now_str,
                    next_sync_at=next_sync_at,
                    last_success_at=now_str,
                    consecutive_failures=0,
                    total_sync_count=1,
                    successful_sync_count=1,
                    failed_sync_count=0,
                    last_error=None,
                    validation_state=validation_state,
                    validation_health="PASSED",
                    active_dataset_version=active_version_id,
                    last_execution_duration_sec=duration,
                    average_execution_time=duration,
                    updated_at=now_str,
                )
            else:
                health = existing
                health.total_sync_count += 1
                health.successful_sync_count += 1
                health.consecutive_failures = 0
                health.last_sync_at = now_str
                health.last_success_at = now_str
                health.next_sync_at = next_sync_at or health.next_sync_at
                health.last_error = None
                health.validation_state = validation_state
                health.validation_health = "PASSED"
                health.active_dataset_version = active_version_id or health.active_dataset_version
                health.last_execution_duration_sec = duration

                # Compute average execution duration
                if health.total_sync_count > 1:
                    health.average_execution_time = round(
                        (health.average_execution_time * (health.total_sync_count - 1) + duration) / health.total_sync_count, 4
                    )
                else:
                    health.average_execution_time = duration

                health.updated_at = now_str
                health.availability = (health.successful_sync_count / health.total_sync_count) * 100.0
                health.status = FeedHealthStatus.HEALTHY if health.availability >= 80.0 else FeedHealthStatus.DEGRADED

            self.repository.save_feed_health(health)
            return health

    def record_sync_failure(
        self,
        feed_id: str,
        error_message: str,
        duration: float = 0.0,
        next_sync_at: Optional[str] = None,
    ) -> FeedHealth:
        """
        Record a failed synchronization run for a feed.
        """
        with self._lock:
            existing = self.repository.get_feed_health(feed_id)
            now_str = datetime.now(timezone.utc).isoformat()

            if not existing:
                health = FeedHealth(
                    feed_id=feed_id,
                    status=FeedHealthStatus.UNHEALTHY,
                    availability=0.0,
                    last_sync_at=now_str,
                    next_sync_at=next_sync_at,
                    last_failure_at=now_str,
                    consecutive_failures=1,
                    total_sync_count=1,
                    successful_sync_count=0,
                    failed_sync_count=1,
                    last_error=error_message,
                    validation_state="FAILED",
                    validation_health="FAILED",
                    active_dataset_version=None,
                    last_execution_duration_sec=duration,
                    average_execution_time=duration,
                    updated_at=now_str,
                )
            else:
                health = existing
                health.total_sync_count += 1
                health.failed_sync_count += 1
                health.consecutive_failures += 1
                health.last_sync_at = now_str
                health.last_failure_at = now_str
                health.next_sync_at = next_sync_at or health.next_sync_at
                health.last_error = error_message
                health.validation_state = "FAILED"
                health.validation_health = "FAILED"
                health.last_execution_duration_sec = duration

                if health.total_sync_count > 1:
                    health.average_execution_time = round(
                        (health.average_execution_time * (health.total_sync_count - 1) + duration) / health.total_sync_count, 4
                    )
                else:
                    health.average_execution_time = duration

                health.updated_at = now_str
                health.availability = (health.successful_sync_count / health.total_sync_count) * 100.0
                if health.consecutive_failures >= 3 or health.availability < 50.0:
                    health.status = FeedHealthStatus.UNHEALTHY
                else:
                    health.status = FeedHealthStatus.DEGRADED

            self.repository.save_feed_health(health)
            return health

    def record_trust_verification(
        self,
        feed_id: str,
        trust_status: str,
        cert_status: str = "VALID",
        sig_status: str = "VERIFIED",
        passed: bool = True,
    ) -> FeedHealth:
        """
        Record trust policy evaluation results and update feed health security metrics.
        """
        with self._lock:
            existing = self.repository.get_feed_health(feed_id)
            now_str = datetime.now(timezone.utc).isoformat()

            if not existing:
                health = FeedHealth(
                    feed_id=feed_id,
                    status=FeedHealthStatus.HEALTHY if passed else FeedHealthStatus.UNHEALTHY,
                    trust_status=trust_status,
                    certificate_status=cert_status,
                    signature_status=sig_status,
                    last_successful_verification=now_str if passed else None,
                    trust_failures=0 if passed else 1,
                    updated_at=now_str,
                )
            else:
                health = existing
                health.trust_status = trust_status
                health.certificate_status = cert_status
                health.signature_status = sig_status
                if passed:
                    health.last_successful_verification = now_str
                else:
                    health.trust_failures += 1
                health.updated_at = now_str

            self.repository.save_feed_health(health)
            return health


    def get_health(self, feed_id: str) -> Optional[FeedHealth]:
        """Get current health state of a feed."""
        return self.repository.get_feed_health(feed_id)

    def get_summary(self, scheduler_status: str = "STOPPED") -> HealthSummary:
        """Get overall health summary and framework dashboard across all registered feeds."""
        healths = self.repository.list_feed_healths()
        total = len(healths)
        healthy = len([h for h in healths if h.status == FeedHealthStatus.HEALTHY])
        degraded = len([h for h in healths if h.status == FeedHealthStatus.DEGRADED])
        unhealthy = len([h for h in healths if h.status == FeedHealthStatus.UNHEALTHY])

        if total == 0:
            sys_status = FeedHealthStatus.HEALTHY
        elif unhealthy > 0:
            sys_status = FeedHealthStatus.UNHEALTHY
        elif degraded > 0:
            sys_status = FeedHealthStatus.DEGRADED
        else:
            sys_status = FeedHealthStatus.HEALTHY

        return HealthSummary(
            system_status=sys_status,
            total_feeds=total,
            healthy_feeds=healthy,
            degraded_feeds=degraded,
            unhealthy_feeds=unhealthy,
            scheduler_status=scheduler_status,
            overall_framework_health=sys_status.value if isinstance(sys_status, FeedHealthStatus) else sys_status,
            feed_healths=healths,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
