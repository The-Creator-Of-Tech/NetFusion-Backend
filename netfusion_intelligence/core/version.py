"""
Dataset Versioning & Rollback Manager for netfusion_intelligence.
Ensures immutability of dataset versions and manages version activation / rollback.
"""

from datetime import datetime, timezone
import threading
from typing import List, Optional

from netfusion_intelligence.core.events import DatasetActivated, DatasetRolledBack, EventBus
from netfusion_intelligence.core.exceptions import DatasetActivationError, RollbackError
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion, ValidationStatus


class DatasetVersionManager:
    """
    Manages dataset versions, activations, and rollback operations.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface, event_bus: EventBus):
        self.repository = repository
        self.event_bus = event_bus
        self._lock = threading.Lock()

    def create_version(
        self,
        feed_id: str,
        checksum: str = "",
        source_version: Optional[str] = None,
        record_count: int = 0,
        duration: float = 0.0,
    ) -> DatasetVersion:
        """
        Creates a new immutable dataset version record (status: CREATED).
        """
        version = DatasetVersion(
            feed_id=feed_id,
            checksum=checksum,
            imported_at=datetime.now(timezone.utc).isoformat(),
            source_version=source_version,
            record_count=record_count,
            duration=duration,
            validation_status=ValidationStatus.PENDING,
            status=DatasetStatus.CREATED,
        )
        return self.repository.save_dataset_version(version)

    def activate_version(self, feed_id: str, version_id: str) -> DatasetVersion:
        """
        Activates a specific dataset version for a feed.
        """
        with self._lock:
            version = self.repository.get_dataset_version(version_id)
            if not version:
                raise DatasetActivationError(f"Dataset version '{version_id}' not found for feed '{feed_id}'")

            if version.validation_status == ValidationStatus.FAILED:
                raise DatasetActivationError(f"Cannot activate dataset version '{version_id}': validation failed")

            success = self.repository.set_active_dataset_version(feed_id, version_id)
            if not success:
                raise DatasetActivationError(f"Failed to set dataset version '{version_id}' active in repository")

            active_ver = self.repository.get_dataset_version(version_id)
            self.event_bus.publish(DatasetActivated(feed_id=feed_id, version_id=version_id))
            return active_ver or version

    def rollback(self, feed_id: str, target_version_id: Optional[str] = None) -> DatasetVersion:
        """
        Rolls back the dataset for a feed to a target version or the previous active version.
        """
        with self._lock:
            versions = self.repository.list_dataset_versions(feed_id)
            if not versions:
                raise RollbackError(f"No dataset versions exist for feed '{feed_id}'")

            current_active = next((v for v in versions if v.status == DatasetStatus.ACTIVE), None)
            
            if target_version_id:
                target_version = next((v for v in versions if v.version_id == target_version_id), None)
                if not target_version:
                    raise RollbackError(f"Target rollback version '{target_version_id}' not found for feed '{feed_id}'")
            else:
                # Find previous non-failed version
                candidates = [v for v in versions if v.status in (DatasetStatus.ARCHIVED, DatasetStatus.STORED, DatasetStatus.VALIDATED) and v.validation_status != ValidationStatus.FAILED]
                if not candidates:
                    raise RollbackError(f"No valid previous dataset version available for rollback on feed '{feed_id}'")
                target_version = candidates[0]

            # Mark current active as ROLLED_BACK
            if current_active:
                current_active.status = DatasetStatus.ROLLED_BACK
                self.repository.save_dataset_version(current_active)

            # Activate target version
            success = self.repository.set_active_dataset_version(feed_id, target_version.version_id)
            if not success:
                raise RollbackError(f"Failed to set dataset version '{target_version.version_id}' active in repository")

            restored = self.repository.get_dataset_version(target_version.version_id)
            self.event_bus.publish(
                DatasetRolledBack(
                    feed_id=feed_id,
                    rolled_back_version_id=current_active.version_id if current_active else "",
                    restored_version_id=target_version.version_id,
                )
            )

            return restored or target_version
