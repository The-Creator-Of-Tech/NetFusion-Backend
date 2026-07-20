"""
IntelligenceRepositoryInterface definition.
Enforces strict decoupling so consumers NEVER query intelligence DB tables directly.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.health import FeedHealth
from netfusion_intelligence.models.import_result import ImportLogEntry, ImportResult
from netfusion_intelligence.models.statistics import IntelligenceStatistics
from netfusion_intelligence.models.audit import AuditLogEntry


class IntelligenceRepositoryInterface(ABC):
    """
    Abstract Base Class for NetFusion Intelligence Repository access.
    """

    @abstractmethod
    def save_feed_record(self, feed_id: str, name: str, description: str, config_data: Dict[str, Any], enabled: bool = True) -> Dict[str, Any]:
        """Save or update a feed metadata & configuration record."""
        pass

    @abstractmethod
    def get_feed_record(self, feed_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve feed record by ID."""
        pass

    @abstractmethod
    def list_feed_records(self) -> List[Dict[str, Any]]:
        """List all feed records."""
        pass

    @abstractmethod
    def save_dataset_version(self, dataset_version: DatasetVersion) -> DatasetVersion:
        """Create or update a dataset version record."""
        pass

    @abstractmethod
    def get_dataset_version(self, version_id: str) -> Optional[DatasetVersion]:
        """Retrieve dataset version by version_id."""
        pass

    @abstractmethod
    def get_active_dataset_version(self, feed_id: str) -> Optional[DatasetVersion]:
        """Retrieve currently ACTIVE dataset version for a given feed."""
        pass

    @abstractmethod
    def list_dataset_versions(self, feed_id: Optional[str] = None) -> List[DatasetVersion]:
        """List dataset versions, optionally filtered by feed_id."""
        pass

    @abstractmethod
    def set_active_dataset_version(self, feed_id: str, version_id: str) -> bool:
        """Atomically set the active dataset version for a feed."""
        pass

    @abstractmethod
    def save_import_result(self, result: ImportResult) -> ImportResult:
        """Record synchronization import execution result."""
        pass

    @abstractmethod
    def list_import_results(
        self,
        feed_id: Optional[str] = None,
        status: Optional[str] = None,
        trigger: Optional[str] = None,
        limit: int = 100,
    ) -> List[ImportResult]:
        """List import execution results with optional filtering."""
        pass

    @abstractmethod
    def save_feed_health(self, health: FeedHealth) -> FeedHealth:
        """Save or update feed health state."""
        pass

    @abstractmethod
    def get_feed_health(self, feed_id: str) -> Optional[FeedHealth]:
        """Get health state for a feed."""
        pass

    @abstractmethod
    def list_feed_healths(self) -> List[FeedHealth]:
        """List health states for all feeds."""
        pass

    @abstractmethod
    def save_import_logs(self, import_id: str, feed_id: str, logs: List[ImportLogEntry]) -> None:
        """Save log entries for an import execution."""
        pass

    @abstractmethod
    def get_statistics(self) -> IntelligenceStatistics:
        """Calculate and return system-wide intelligence statistics."""
        pass

    @abstractmethod
    def save_audit_event(self, entry: AuditLogEntry) -> AuditLogEntry:
        """Persist a domain event audit entry."""
        pass

    @abstractmethod
    def list_audit_events(
        self, event_type: Optional[str] = None, feed_id: Optional[str] = None, limit: int = 100
    ) -> List[AuditLogEntry]:
        """List persisted domain event audit logs."""
        pass
