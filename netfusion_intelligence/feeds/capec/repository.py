"""
CAPEC Feed Repository facade.
Wraps IntelligenceRepositoryInterface to provide domain-specific CAPEC queries.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class CapecRepository:
    """
    Domain repository wrapper for MITRE CAPEC intelligence storage and search.
    Delegates all persistence to the platform IntelligenceRepositoryInterface.
    """

    FEED_ID = "mitre_capec_xml"

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def store_attack_patterns(self, dataset_version_id: str, entities: List[Any]) -> Dict[str, int]:
        """Persists normalized CAPEC entities."""
        if hasattr(self.repository, "save_capec_attack_patterns"):
            return self.repository.save_capec_attack_patterns(dataset_version_id, entities)
        return {"inserted": len(entities), "updated": 0, "duplicates": 0}

    def store_relationships(self, dataset_version_id: str, relationships: List[Any]) -> int:
        """Persists CAPEC-to-CAPEC graph relationships."""
        if hasattr(self.repository, "save_capec_relationships"):
            return self.repository.save_capec_relationships(dataset_version_id, relationships)
        return len(relationships)

    def store_cwe_mappings(self, dataset_version_id: str, mappings: List[Any]) -> int:
        """Persists CAPEC-to-CWE cross-reference mappings."""
        if hasattr(self.repository, "save_capec_cwe_mappings"):
            return self.repository.save_capec_cwe_mappings(dataset_version_id, mappings)
        return len(mappings)

    def get_attack_pattern(self, capec_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a single CAPEC attack pattern by ID."""
        if hasattr(self.repository, "get_capec_attack_pattern"):
            return self.repository.get_capec_attack_pattern(capec_id, version_id=version_id)
        return None

    def list_attack_patterns(
        self,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists CAPEC attack patterns with optional filters."""
        if hasattr(self.repository, "list_capec_attack_patterns"):
            return self.repository.list_capec_attack_patterns(
                abstraction=abstraction,
                status=status,
                severity=severity,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def search(
        self,
        query: str = "",
        capec_id: Optional[str] = None,
        abstraction: Optional[str] = None,
        severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        attack_technique_id: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Executes full-text search over CAPEC dataset."""
        if hasattr(self.repository, "search_capec_attack_patterns"):
            return self.repository.search_capec_attack_patterns(
                query=query,
                capec_id=capec_id,
                abstraction=abstraction,
                severity=severity,
                cwe_id=cwe_id,
                attack_technique_id=attack_technique_id,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_by_cwe(self, cwe_id: str, version_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all CAPEC attack patterns linked to a given CWE ID."""
        if hasattr(self.repository, "list_capec_by_cwe"):
            return self.repository.list_capec_by_cwe(cwe_id, version_id=version_id)
        return []

    def get_by_attack_technique(self, technique_id: str, version_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all CAPEC attack patterns linked to a given ATT&CK technique ID."""
        if hasattr(self.repository, "list_capec_by_attack_technique"):
            return self.repository.list_capec_by_attack_technique(technique_id, version_id=version_id)
        return []

    def get_relationships(
        self,
        capec_id: Optional[str] = None,
        nature: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Retrieves CAPEC-to-CAPEC relationships."""
        if hasattr(self.repository, "list_capec_relationships"):
            return self.repository.list_capec_relationships(
                capec_id=capec_id,
                nature=nature,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns statistics for a CAPEC dataset version."""
        if hasattr(self.repository, "get_capec_statistics_for_version"):
            return self.repository.get_capec_statistics_for_version(version_id)
        return {}

    def get_active_version(self) -> Optional[Any]:
        """Returns the currently active CAPEC dataset version."""
        return self.repository.get_active_dataset_version(self.FEED_ID)
