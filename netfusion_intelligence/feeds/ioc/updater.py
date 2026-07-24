"""
IL-7 IOC Updater.
Handles dataset version activation, incremental sync comparison, and rollback.
Mirrors the CapecUpdater / MitreUpdater pattern.
"""

from typing import Any, Dict, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetVersion


class IocUpdater:
    """
    Manages update lifecycle for the IOC dataset.
    Supports full sync, incremental comparison, activation, and rollback.
    """

    FEED_ID = "netfusion_ioc_v1"

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def compare_versions(self, new_checksum: str) -> Dict[str, Any]:
        """
        Compare a new payload checksum against the active dataset version.
        Returns update_required flag and reason.
        """
        active = self.repository.get_active_dataset_version(self.FEED_ID)
        if not active:
            return {
                "update_required": True,
                "reason": "No active IOC dataset version deployed",
                "active_version_id": None,
            }
        if active.checksum and active.checksum.lower() == new_checksum.lower():
            return {
                "update_required": False,
                "reason": "Checksum matches active version — IOC dataset unchanged",
                "active_version_id": active.version_id,
            }
        return {
            "update_required": True,
            "reason": f"Checksum mismatch: active={active.checksum[:12]}, new={new_checksum[:12]}",
            "active_version_id": active.version_id,
        }

    def activate_dataset(self, dataset_version: DatasetVersion) -> bool:
        """Atomically activate a new IOC dataset version."""
        return self.repository.set_active_dataset_version(
            self.FEED_ID, dataset_version.version_id
        )

    def rollback_dataset(self, target_version_id: Optional[str] = None) -> Optional[DatasetVersion]:
        """
        Roll back to target_version_id or the most recent non-active version.
        """
        versions = self.repository.list_dataset_versions(self.FEED_ID)
        if not versions:
            return None

        if target_version_id:
            target = next((v for v in versions if v.version_id == target_version_id), None)
            if not target:
                raise ValueError(f"IOC version '{target_version_id}' not found for rollback")
        else:
            active = self.repository.get_active_dataset_version(self.FEED_ID)
            candidates = [v for v in versions if not active or v.version_id != active.version_id]
            if not candidates:
                raise ValueError("No previous IOC dataset version available for rollback")
            target = candidates[0]

        success = self.repository.set_active_dataset_version(self.FEED_ID, target.version_id)
        if success:
            return self.repository.get_dataset_version(target.version_id)
        return None
