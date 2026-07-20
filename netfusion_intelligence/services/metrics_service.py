"""
Metrics Service for aggregating structured operational metrics.
"""

from datetime import datetime, timezone
import time
from typing import Dict, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.import_result import ImportStatus
from netfusion_intelligence.models.metrics import SystemMetrics


class MetricsService:
    """
    Computes system-wide structured metrics including import stats, validation failures,
    scheduler uptime, and per-feed availability.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface, registry: Any = None, scheduler: Any = None):
        self.repository = repository
        self.registry = registry
        self.scheduler = scheduler
        self._start_time = time.time()

    def get_metrics(self) -> SystemMetrics:
        """Computes and returns current SystemMetrics."""
        imports = self.repository.list_import_results(limit=1000)
        successful = len([i for i in imports if i.status == ImportStatus.COMPLETED or i.validation_passed])
        failed = len([i for i in imports if i.status == ImportStatus.FAILED or not i.validation_passed])

        durations = [i.duration_seconds for i in imports if i.duration_seconds > 0]
        avg_duration = round(sum(durations) / len(durations), 4) if durations else 0.0

        val_failures = len([i for i in imports if i.validation_errors > 0 or not i.validation_passed])

        # Scheduler Uptime
        sched_running = getattr(self.scheduler, "is_running", False) if self.scheduler else False
        sched_uptime = round(time.time() - self._start_time, 2) if sched_running else 0.0

        # Feed count from registry or healths
        healths = self.repository.list_feed_healths()
        feed_uptimes: Dict[str, float] = {h.feed_id: h.availability for h in healths}

        active_count = 0
        disabled_count = 0
        if self.registry:
            feeds = self.registry.list_feeds()
            active_count = len([f for f in feeds if f.config.enabled])
            disabled_count = len(feeds) - active_count
        else:
            active_count = len(healths)

        return SystemMetrics(
            successful_imports=successful,
            failed_imports=failed,
            average_import_duration=avg_duration,
            validation_failures=val_failures,
            scheduler_uptime=sched_uptime,
            feed_uptime=feed_uptimes,
            active_feeds=active_count,
            disabled_feeds=disabled_count,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
