"""
High-level Intelligence Service exposing domain workflows.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.models.audit import AuditLogEntry
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.health import HealthSummary
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.models.metrics import SystemMetrics
from netfusion_intelligence.models.statistics import IntelligenceStatistics


class IntelligenceService:
    """
    High-level Intelligence Service.
    Acts as the entry point for platform workflows, AI investigation engine, and graph engine.
    """

    def __init__(self, engine: IntelligenceEngine):
        self.engine = engine

    def get_registered_feeds(self) -> List[Dict[str, Any]]:
        """List summary of all registered feeds including manifests."""
        feeds = self.engine.list_feeds()
        return [
            {
                "feed_id": f.feed_id,
                "name": f.feed_name,
                "description": f.description,
                "enabled": f.config.enabled,
                "config": f.config.to_dict(),
                "manifest": f.manifest.to_dict() if f.manifest else None,
            }
            for f in feeds
        ]

    def trigger_feed_sync(self, feed_id: str) -> ImportResult:
        """Trigger sync for a feed."""
        return self.engine.sync_feed(feed_id)

    def get_system_health(self) -> HealthSummary:
        """Get health summary and dashboard."""
        return self.engine.get_health()

    def get_metrics(self) -> SystemMetrics:
        """Get structured system metrics."""
        return self.engine.get_metrics()

    def get_audit_logs(
        self, event_type: Optional[str] = None, feed_id: Optional[str] = None, limit: int = 100
    ) -> List[AuditLogEntry]:
        """Get domain event audit log history."""
        return self.engine.get_audit_logs(event_type=event_type, feed_id=feed_id, limit=limit)

    def get_execution_order(self) -> List[str]:
        """Get topological dependency execution order."""
        return self.engine.get_execution_order()

    def get_versions(self, feed_id: Optional[str] = None) -> List[DatasetVersion]:
        """Get dataset versions."""
        return self.engine.get_dataset_versions(feed_id=feed_id)

    def get_imports(
        self,
        feed_id: Optional[str] = None,
        status: Optional[str] = None,
        trigger: Optional[str] = None,
        limit: int = 100,
    ) -> List[ImportResult]:
        """Get import history."""
        return self.engine.get_import_history(feed_id=feed_id, status=status, trigger=trigger, limit=limit)

    def get_statistics(self) -> IntelligenceStatistics:
        """Get statistics."""
        return self.engine.get_statistics()

    def rollback(self, feed_id: str, target_version_id: Optional[str] = None) -> DatasetVersion:
        """Rollback dataset."""
        return self.version_manager.rollback(feed_id, target_version_id=target_version_id) if hasattr(self, "version_manager") else self.engine.rollback_dataset(feed_id, target_version_id=target_version_id)
