"""
Updater Engine for MITRE ATT&CK STIX 2.1 intelligence feed.
Handles dataset sync, version comparisons, dataset replacement, and rollback.
"""

from typing import Any, Dict, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetVersion


class MitreUpdater:
    """
    Manages update engine lifecycle for MITRE ATT&CK dataset.
    Supports full replacement, version comparison, and rollback operations.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def compare_versions(self, feed_id: str, new_checksum: str) -> Dict[str, Any]:
        """
        Compares new checksum with currently active dataset version for feed_id.
        Returns dict indicating whether an update is required.
        """
        active_ver = self.repository.get_active_dataset_version(feed_id)
        if not active_ver:
            return {
                "update_required": True,
                "reason": "No active dataset version currently deployed",
                "active_version_id": None,
            }

        if active_ver.checksum and active_ver.checksum.lower() == new_checksum.lower():
            return {
                "update_required": False,
                "reason": "Dataset checksum matches active version; dataset unchanged",
                "active_version_id": active_ver.version_id,
            }

        return {
            "update_required": True,
            "reason": f"Checksum mismatch: active={active_ver.checksum[:12]}, new={new_checksum[:12]}",
            "active_version_id": active_ver.version_id,
        }

    def activate_dataset(self, feed_id: str, dataset_version: DatasetVersion) -> bool:
        """
        Atomically activates dataset_version for feed_id in the repository.
        """
        return self.repository.set_active_dataset_version(feed_id, dataset_version.version_id)

    def rollback_dataset(self, feed_id: str, target_version_id: Optional[str] = None) -> Optional[DatasetVersion]:
        """
        Rolls back active dataset version for feed_id to target_version_id or previous stored version.
        """
        versions = self.repository.list_dataset_versions(feed_id)
        if not versions:
            return None

        if target_version_id:
            target = next((v for v in versions if v.version_id == target_version_id), None)
            if not target:
                raise ValueError(f"Target dataset version '{target_version_id}' not found for rollback")
        else:
            active_ver = self.repository.get_active_dataset_version(feed_id)
            non_active = [v for v in versions if not active_ver or v.version_id != active_ver.version_id]
            if not non_active:
                raise ValueError("No previous dataset version available for rollback")
            target = non_active[0]

        success = self.repository.set_active_dataset_version(feed_id, target.version_id)
        if success:
            return self.repository.get_dataset_version(target.version_id)
        return None
