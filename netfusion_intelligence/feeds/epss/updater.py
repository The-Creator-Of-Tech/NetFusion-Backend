"""
Dataset updater and lifecycle manager for FIRST EPSS Intelligence Pipeline.
Handles dataset activation, rollback, and version management.
"""

import logging
from typing import Optional

from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.dataset import DatasetVersion

logger = logging.getLogger(__name__)


class EpssUpdater:
    """
    Manages EPSS dataset versions, activation, and rollback operations.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def activate_dataset(
        self,
        feed_id: str,
        dataset_version: DatasetVersion,
    ) -> bool:
        """
        Activates an EPSS dataset version as the current production version.
        """
        try:
            if hasattr(self.repository, "activate_dataset_version"):
                self.repository.activate_dataset_version(
                    feed_id=feed_id,
                    version_id=dataset_version.version_id,
                )
                logger.info(f"Activated EPSS dataset version: {dataset_version.version_id}")
                return True
            logger.warning("Repository does not support activate_dataset_version")
            return False
        except Exception as e:
            logger.error(f"Failed to activate EPSS dataset {dataset_version.version_id}: {e}")
            return False

    def rollback_dataset(
        self,
        feed_id: str,
        target_version_id: str,
    ) -> bool:
        """
        Rolls back EPSS dataset to a previous version.
        """
        try:
            if hasattr(self.repository, "rollback_dataset_version"):
                self.repository.rollback_dataset_version(
                    feed_id=feed_id,
                    target_version_id=target_version_id,
                )
                logger.info(f"Rolled back EPSS dataset to version: {target_version_id}")
                return True
            logger.warning("Repository does not support rollback_dataset_version")
            return False
        except Exception as e:
            logger.error(f"Failed to rollback EPSS dataset to {target_version_id}: {e}")
            return False

    def get_active_version(self, feed_id: str) -> Optional[str]:
        """
        Retrieves the currently active EPSS dataset version ID.
        """
        try:
            if hasattr(self.repository, "get_active_dataset_version"):
                return self.repository.get_active_dataset_version(feed_id)
            return None
        except Exception as e:
            logger.error(f"Failed to get active EPSS dataset version: {e}")
            return None

    def list_versions(self, feed_id: str, limit: int = 50) -> list:
        """
        Lists all EPSS dataset versions, ordered by import date descending.
        """
        try:
            if hasattr(self.repository, "list_dataset_versions"):
                return self.repository.list_dataset_versions(feed_id, limit=limit)
            return []
        except Exception as e:
            logger.error(f"Failed to list EPSS dataset versions: {e}")
            return []

    def delete_old_versions(
        self,
        feed_id: str,
        keep_count: int = 5,
    ) -> int:
        """
        Deletes old EPSS dataset versions, keeping only the most recent N versions.
        Returns count of deleted versions.
        """
        try:
            if hasattr(self.repository, "delete_old_dataset_versions"):
                return self.repository.delete_old_dataset_versions(
                    feed_id=feed_id,
                    keep_count=keep_count,
                )
            return 0
        except Exception as e:
            logger.error(f"Failed to delete old EPSS dataset versions: {e}")
            return 0
