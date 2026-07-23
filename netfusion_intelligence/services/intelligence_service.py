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

    # -------------------------------------------------------------------------
    # MITRE ATT&CK Intelligence Domain Methods
    # -------------------------------------------------------------------------

    def get_mitre_object(self, identifier: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get MITRE object by ATT&CK ID or STIX ID."""
        if hasattr(self.engine.repository, "get_mitre_object"):
            return self.engine.repository.get_mitre_object(identifier, version_id=version_id)
        return None

    def list_mitre_techniques(
        self, tactic: Optional[str] = None, platform: Optional[str] = None, version_id: Optional[str] = None, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """List techniques filtered by tactic or platform."""
        if hasattr(self.engine.repository, "search_mitre_objects"):
            return self.engine.repository.search_mitre_objects(
                tactic=tactic, platform=platform, entity_type="attack-pattern", version_id=version_id, limit=limit
            )
        return []

    def get_mitre_relationships(
        self,
        source_ref: Optional[str] = None,
        target_ref: Optional[str] = None,
        relationship_type: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """List STIX relationships."""
        if hasattr(self.engine.repository, "list_mitre_relationships"):
            return self.engine.repository.list_mitre_relationships(
                source_ref=source_ref, target_ref=target_ref, relationship_type=relationship_type, version_id=version_id, limit=limit
            )
        return []

    def list_mitre_groups(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """List intrusion set groups."""
        if hasattr(self.engine.repository, "list_mitre_objects"):
            return self.engine.repository.list_mitre_objects(type="intrusion-set", version_id=version_id, limit=limit)
        return []

    def list_mitre_campaigns(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """List campaigns."""
        if hasattr(self.engine.repository, "list_mitre_objects"):
            return self.engine.repository.list_mitre_objects(type="campaign", version_id=version_id, limit=limit)
        return []

    def list_mitre_software(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """List software (malware & tools)."""
        if hasattr(self.engine.repository, "list_mitre_objects"):
            malware = self.engine.repository.list_mitre_objects(type="malware", version_id=version_id, limit=limit)
            tools = self.engine.repository.list_mitre_objects(type="tool", version_id=version_id, limit=limit)
            return malware + tools
        return []

    def list_mitre_mitigations(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """List mitigations (course-of-action)."""
        if hasattr(self.engine.repository, "list_mitre_objects"):
            return self.engine.repository.list_mitre_objects(type="course-of-action", version_id=version_id, limit=limit)
        return []

    def list_mitre_data_sources(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """List data sources."""
        if hasattr(self.engine.repository, "list_mitre_objects"):
            return self.engine.repository.list_mitre_objects(type="x-mitre-data-source", version_id=version_id, limit=limit)
        return []

    def search_mitre(
        self,
        query: str = "",
        technique_id: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        alias: Optional[str] = None,
        entity_type: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search MITRE objects across technique, tactic, platform, alias, or keyword."""
        if hasattr(self.engine.repository, "search_mitre_objects"):
            return self.engine.repository.search_mitre_objects(
                query=query,
                technique_id=technique_id,
                tactic=tactic,
                platform=platform,
                alias=alias,
                entity_type=entity_type,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_mitre_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Get MITRE dataset statistics."""
        if hasattr(self.engine.repository, "get_mitre_statistics_for_version"):
            return self.engine.repository.get_mitre_statistics_for_version(version_id)
        return {}

    # -------------------------------------------------------------------------
    # FIRST EPSS Intelligence Domain Methods
    # -------------------------------------------------------------------------

    def get_epss_score(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get current EPSS score for a specific CVE."""
        if hasattr(self.engine.repository, "get_epss_score"):
            return self.engine.repository.get_epss_score(cve_id, version_id=version_id)
        return None

    def get_epss_history(self, cve_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical EPSS score snapshots for a CVE."""
        if hasattr(self.engine.repository, "get_epss_history"):
            return self.engine.repository.get_epss_history(cve_id, limit=limit)
        return []

    def list_epss_scores(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List EPSS scores with filters."""
        if hasattr(self.engine.repository, "list_epss_scores"):
            return self.engine.repository.list_epss_scores(
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                trend=trend,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def search_epss(
        self,
        cve_id: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        publication_date: Optional[str] = None,
        model_version: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Multi-parameter search across EPSS scores."""
        if hasattr(self.engine.repository, "search_epss_scores"):
            return self.engine.repository.search_epss_scores(
                cve_id=cve_id,
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                max_percentile=max_percentile,
                trend=trend,
                publication_date=publication_date,
                model_version=model_version,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_trending_epss(
        self,
        trend_type: str = "INCREASING",
        limit: int = 100,
        version_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get CVEs with specific EPSS trend classification."""
        if hasattr(self.engine.repository, "get_trending_epss_cves"):
            return self.engine.repository.get_trending_epss_cves(
                trend_type=trend_type, limit=limit, version_id=version_id
            )
        return []

    def get_epss_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Get EPSS dataset breakdown statistics."""
        if hasattr(self.engine.repository, "get_epss_statistics_for_version"):
            return self.engine.repository.get_epss_statistics_for_version(version_id)
        return {}


