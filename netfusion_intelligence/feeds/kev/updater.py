"""
Dataset Version Updater and Rollback Manager for CISA KEV Intelligence Pipeline.
"""

from typing import Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion


class CisaKevUpdater:
    """
    Manages dataset activation, status updates, and rollback operations for CISA KEV pipeline.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self._repository = repository

    def activate_dataset(self, feed_id: str, dataset_version: DatasetVersion) -> bool:
        """
        Activates the specified KEV dataset version.
        """
        if not self._repository:
            return False

        return self._repository.set_active_dataset_version(feed_id, dataset_version.version_id)

    def rollback_dataset(self, feed_id: str, target_version_id: str) -> bool:
        """
        Rolls back active dataset to a target version ID.
        """
        if not self._repository:
            return False

        return self._repository.set_active_dataset_version(feed_id, target_version_id)
