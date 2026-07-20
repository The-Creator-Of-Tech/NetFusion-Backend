from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from netfusion_intelligence.core.config import EngineConfig
from netfusion_intelligence.core.dependency import FeedDependencyGraph
from netfusion_intelligence.core.events import DomainEvent, EventBus, FeedRegistered
from netfusion_intelligence.core.health import HealthMonitor
from netfusion_intelligence.core.lifecycle import FeedLifecycleRunner
from netfusion_intelligence.core.registry import FeedRegistry
from netfusion_intelligence.core.scheduler import IntelligenceScheduler
from netfusion_intelligence.core.version import DatasetVersionManager
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.audit import AuditLogEntry
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.health import FeedHealth, HealthSummary
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.models.metrics import SystemMetrics
from netfusion_intelligence.models.statistics import IntelligenceStatistics
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.services.metrics_service import MetricsService


class IntelligenceEngine:
    """
    Central Intelligence Engine for NetFusion IL-1.
    """

    def __init__(
        self,
        config: Optional[EngineConfig] = None,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        event_bus: Optional[EventBus] = None,
    ):
        self.config = config or EngineConfig()
        self.repository = repository or SQLAlchemyIntelligenceRepository(db_url=self.config.db_url)
        self.event_bus = event_bus or EventBus()

        self.registry = FeedRegistry()
        self.version_manager = DatasetVersionManager(self.repository, self.event_bus)
        self.health_monitor = HealthMonitor(self.repository)
        
        # Security & Trust Verification Framework Components
        from netfusion_intelligence.security.policy_engine import TrustPolicyEngine
        from netfusion_intelligence.security.audit import TrustAuditRepository
        self.policy_engine = TrustPolicyEngine()
        self.trust_audit_repository = TrustAuditRepository()

        self.lifecycle_runner = FeedLifecycleRunner(
            repository=self.repository,
            version_manager=self.version_manager,
            health_monitor=self.health_monitor,
            event_bus=self.event_bus,
            policy_engine=self.policy_engine,
            audit_repository=self.trust_audit_repository,
        )
        self.scheduler = IntelligenceScheduler(
            registry=self.registry,
            lifecycle_runner=self.lifecycle_runner,
            event_bus=self.event_bus,
        )
        self.metrics_service = MetricsService(
            repository=self.repository,
            registry=self.registry,
            scheduler=self.scheduler,
        )

        # Domain Event Audit Persister
        def _on_domain_event(event: DomainEvent):
            try:
                feed_id = getattr(event, "feed_id", None)
                entry = AuditLogEntry(
                    event_id=getattr(event, "event_id", str(uuid.uuid4())),
                    event_type=event.event_type(),
                    feed_id=feed_id,
                    timestamp=getattr(event, "timestamp", datetime.now(timezone.utc).isoformat()),
                    payload=event.to_dict(),
                )
                self.repository.save_audit_event(entry)
            except Exception:
                pass

        self.event_bus.subscribe_all(_on_domain_event)

        if self.config.auto_discover:
            for pkg in self.config.discovery_packages:
                self.registry.discover_feeds(pkg)

    def register_feed(self, feed: FeedInterface) -> None:
        """
        Registers a feed plugin with the framework and updates repository record.
        Enforces configuration validation before registration.
        """
        self.registry.register(feed)
        self.repository.save_feed_record(
            feed_id=feed.feed_id,
            name=feed.feed_name,
            description=feed.description,
            config_data=feed.config.to_dict(),
            enabled=feed.config.enabled,
        )
        self.event_bus.publish(FeedRegistered(feed_id=feed.feed_id, feed_name=feed.feed_name))

    def unregister_feed(self, feed_id: str) -> None:
        """Unregisters a feed plugin."""
        self.registry.unregister(feed_id)

    def get_feed(self, feed_id: str) -> FeedInterface:
        """Get feed plugin by ID."""
        return self.registry.get(feed_id)

    def list_feeds(self) -> List[FeedInterface]:
        """List all registered feed plugins."""
        return self.registry.list_feeds()

    def sync_feed(self, feed_id: str, retry_count: Optional[int] = None) -> ImportResult:
        """
        Executes manual or scheduled synchronization for a feed.
        """
        return self.scheduler.trigger_sync(feed_id, retry_count=retry_count)

    def sync_all_feeds(self) -> List[ImportResult]:
        """
        Executes synchronization for all enabled feeds in topological order.
        """
        return self.sync_all()

    def sync_all(self) -> List[ImportResult]:
        """
        Sync all registered and enabled feeds in dependency topological order.
        """
        order = self.get_execution_order()
        results = []
        for feed_id in order:
            feed = self.registry.get(feed_id)
            if feed.config.enabled:
                res = self.sync_feed(feed.feed_id)
                results.append(res)
        return results

    def get_execution_order(self) -> List[str]:
        """
        Computes topological execution order for all registered feeds.
        """
        graph = FeedDependencyGraph(self.registry.list_feeds())
        return graph.get_topological_order()

    def rollback_dataset(self, feed_id: str, target_version_id: Optional[str] = None) -> DatasetVersion:
        """
        Rolls back dataset for a feed to target version or previous active version.
        """
        return self.version_manager.rollback(feed_id, target_version_id=target_version_id)

    def get_health(self, feed_id: Optional[str] = None) -> Any:
        """
        Returns health for a specific feed or overall health summary dashboard.
        """
        sched_status = "RUNNING" if self.scheduler.is_running else "STOPPED"
        if feed_id:
            return self.health_monitor.get_health(feed_id)
        return self.health_monitor.get_summary(scheduler_status=sched_status)

    def get_metrics(self) -> SystemMetrics:
        """
        Returns structured system metrics.
        """
        return self.metrics_service.get_metrics()

    def get_audit_logs(
        self, event_type: Optional[str] = None, feed_id: Optional[str] = None, limit: int = 100
    ) -> List[AuditLogEntry]:
        """
        Exposes domain event audit trail.
        """
        return self.repository.list_audit_events(event_type=event_type, feed_id=feed_id, limit=limit)

    def get_statistics(self) -> IntelligenceStatistics:
        """
        Exposes system-wide intelligence metrics and stats.
        """
        return self.repository.get_statistics()

    def get_dataset_versions(self, feed_id: Optional[str] = None) -> List[DatasetVersion]:
        """Exposes dataset version history."""
        return self.repository.list_dataset_versions(feed_id=feed_id)

    def get_import_history(
        self,
        feed_id: Optional[str] = None,
        status: Optional[str] = None,
        trigger: Optional[str] = None,
        limit: int = 100,
    ) -> List[ImportResult]:
        """Exposes import history logs with filtering."""
        return self.repository.list_import_results(feed_id=feed_id, status=status, trigger=trigger, limit=limit)

    def start_scheduler(self) -> None:
        """Starts background feed scheduler."""
        self.scheduler.start()

    def stop_scheduler(self) -> None:
        """Stops background feed scheduler."""
        self.scheduler.stop()

    def get_trust_summary(self) -> Dict[str, Any]:
        """Returns overall trust status summary across all feeds."""
        history = self.trust_audit_repository.get_history(limit=500)
        feeds = self.list_feeds()
        trusted_count = len([h for h in history if h.overall_trust == "TRUSTED"])
        partially_trusted_count = len([h for h in history if h.overall_trust == "PARTIALLY_TRUSTED"])
        untrusted_count = len([h for h in history if h.overall_trust == "UNTRUSTED"])
        blocked_count = len([h for h in history if h.overall_trust == "BLOCKED"])

        return {
            "status": "HEALTHY" if blocked_count == 0 else "DEGRADED",
            "total_registered_feeds": len(feeds),
            "total_verifications": len(history),
            "trusted_count": trusted_count,
            "partially_trusted_count": partially_trusted_count,
            "untrusted_count": untrusted_count,
            "blocked_count": blocked_count,
            "latest_verifications": [h.to_dict() for h in history[:10]],
        }

    def get_trust_history(
        self, feed_id: Optional[str] = None, overall_trust: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Returns trust verification audit log history."""
        entries = self.trust_audit_repository.get_history(feed_id=feed_id, overall_trust=overall_trust, limit=limit)
        return [e.to_dict() for e in entries]

    def get_feed_trust(self, feed_id: str) -> Dict[str, Any]:
        """Returns trust evaluation details and TrustProfile for a specific feed."""
        feed = self.registry.get(feed_id)
        latest_audit = self.trust_audit_repository.get_latest_for_feed(feed_id)
        health = self.health_monitor.get_health(feed_id)

        trust_profile = getattr(feed, "trust_profile", None)
        profile_dict = trust_profile.to_dict() if trust_profile else {
            "publisher": getattr(feed.metadata, "publisher", "NetFusion Security Team"),
            "organization": getattr(feed.metadata, "organization", "NetFusion"),
            "official_url": getattr(feed.metadata, "url", "https://localhost/feed"),
            "expected_domain": getattr(feed.metadata, "expected_domain", ""),
            "trust_level": "HIGH",
        }

        return {
            "feed_id": feed_id,
            "feed_name": feed.feed_name,
            "trust_profile": profile_dict,
            "health_trust_status": health.trust_status if health else "UNKNOWN",
            "latest_verification": latest_audit.to_dict() if latest_audit else None,
        }

