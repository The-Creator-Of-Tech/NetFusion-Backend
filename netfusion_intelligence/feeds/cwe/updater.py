"""
Updater Engine for MITRE CWE intelligence feed.
Handles dataset sync, version comparison, activation, and rollback.
"""

from typing import Any, Dict, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetVersion


class CweUpdater:
    """
    Manages update engine lifecycle for CWE dataset.
    Mirrors the MitreUpdater pattern exactly.
    """

    FEED_ID = "mitre_cwe_xml"

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def compare_versions(self, new_checksum: str) -> Dict[str, Any]:
        """
        Compares a new download checksum against the currently active dataset version.
        Returns dict indicating whether an update is required.
        """
        active_ver = self.repository.get_active_dataset_version(self.FEED_ID)
        if not active_ver:
            return {
                "update_required": True,
                "reason": "No active CWE dataset version currently deployed",
                "active_version_id": None,
            }
        if active_ver.checksum and active_ver.checksum.lower() == new_checksum.lower():
            return {
                "update_required": False,
                "reason": "Checksum matches active version — CWE dataset unchanged",
                "active_version_id": active_ver.version_id,
            }
        return {
            "update_required": True,
            "reason": f"Checksum mismatch: active={active_ver.checksum[:12]}, new={new_checksum[:12]}",
            "active_version_id": active_ver.version_id,
        }

    def activate_dataset(self, dataset_version: DatasetVersion) -> bool:
        """Atomically activates a CWE dataset version."""
        return self.repository.set_active_dataset_version(self.FEED_ID, dataset_version.version_id)

    def rollback_dataset(self, target_version_id: Optional[str] = None) -> Optional[DatasetVersion]:
        """
        Rolls back to target_version_id, or the previous stored version if not specified.
        """
        versions = self.repository.list_dataset_versions(self.FEED_ID)
        if not versions:
            return None

        if target_version_id:
            target = next((v for v in versions if v.version_id == target_version_id), None)
            if not target:
                raise ValueError(f"CWE version '{target_version_id}' not found for rollback")
        else:
            active_ver = self.repository.get_active_dataset_version(self.FEED_ID)
            non_active = [v for v in versions if not active_ver or v.version_id != active_ver.version_id]
            if not non_active:
                raise ValueError("No previous CWE dataset version available for rollback")
            target = non_active[0]

        success = self.repository.set_active_dataset_version(self.FEED_ID, target.version_id)
        if success:
            return self.repository.get_dataset_version(target.version_id)
        return None
