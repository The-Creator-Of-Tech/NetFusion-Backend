"""
NVD Dataset Updater and Rollback Manager for NetFusion IL-3 NVD Pipeline.
"""

from typing import Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetVersion


class NvdUpdater:
    """
    Manages activation, incremental updates, and dataset rollback for NVD feed datasets.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def activate_dataset(self, feed_id: str, dataset_version: DatasetVersion) -> bool:
        """
        Activates a stored dataset version for feed_id.
        """
        return self.repository.set_active_dataset_version(feed_id, dataset_version.version_id)

    def rollback_dataset(self, feed_id: str, target_version_id: Optional[str] = None) -> bool:
        """
        Rolls back dataset activation to target_version_id or previous active version.
        """
        if target_version_id:
            return self.repository.set_active_dataset_version(feed_id, target_version_id)
        
        versions = self.repository.list_dataset_versions(feed_id=feed_id)
        if len(versions) > 1:
            prev_version = versions[1]
            return self.repository.set_active_dataset_version(feed_id, prev_version.version_id)
        return False
