"""
CWE Feed Repository facade.
Wraps IntelligenceRepositoryInterface to provide domain-specific CWE queries.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class CweRepository:
    """
    Domain repository wrapper for MITRE CWE intelligence storage and search.
    Delegates all persistence to the platform IntelligenceRepositoryInterface.
    """

    FEED_ID = "mitre_cwe_xml"

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def store_weaknesses(self, dataset_version_id: str, entities: List[Any]) -> Dict[str, int]:
        """Persists normalized CWE entities to the repository."""
        if hasattr(self.repository, "save_cwe_weaknesses"):
            return self.repository.save_cwe_weaknesses(dataset_version_id, entities)
        return {"inserted": len(entities), "updated": 0, "duplicates": 0}

    def store_relationships(self, dataset_version_id: str, relationships: List[Any]) -> int:
        """Persists CWE-to-CWE graph relationships."""
        if hasattr(self.repository, "save_cwe_relationships"):
            return self.repository.save_cwe_relationships(dataset_version_id, relationships)
        return len(relationships)

    def get_weakness(self, cwe_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a single CWE weakness by ID."""
        if hasattr(self.repository, "get_cwe_weakness"):
            return self.repository.get_cwe_weakness(cwe_id, version_id=version_id)
        return None

    def list_weaknesses(
        self,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists CWE weaknesses with optional filters."""
        if hasattr(self.repository, "list_cwe_weaknesses"):
            return self.repository.list_cwe_weaknesses(
                abstraction=abstraction,
                status=status,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def search(
        self,
        query: str = "",
        cwe_id: Optional[str] = None,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Executes full-text search over CWE dataset."""
        if hasattr(self.repository, "search_cwe_weaknesses"):
            return self.repository.search_cwe_weaknesses(
                query=query,
                cwe_id=cwe_id,
                abstraction=abstraction,
                status=status,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_relationships(
        self,
        cwe_id: Optional[str] = None,
        nature: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Retrieves CWE-to-CWE relationships."""
        if hasattr(self.repository, "list_cwe_relationships"):
            return self.repository.list_cwe_relationships(
                cwe_id=cwe_id,
                nature=nature,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns statistics for a CWE dataset version."""
        if hasattr(self.repository, "get_cwe_statistics_for_version"):
            return self.repository.get_cwe_statistics_for_version(version_id)
        return {}

    def get_active_version(self) -> Optional[Any]:
        """Returns the currently active CWE dataset version."""
        return self.repository.get_active_dataset_version(self.FEED_ID)
