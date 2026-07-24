"""
MITRE ATT&CK Feed Repository facade.
Wraps IntelligenceRepositoryInterface to provide specialized domain queries for MITRE entities.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class MitreRepository:
    """
    Domain repository wrapper for MITRE ATT&CK STIX 2.1 intelligence storage & search.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def store_entities(self, dataset_version_id: str, entities: List[Any]) -> Dict[str, int]:
        """Persists normalized MITRE entities."""
        if hasattr(self.repository, "save_mitre_objects"):
            return self.repository.save_mitre_objects(dataset_version_id, entities)
        return {"inserted": len(entities), "updated": 0, "duplicates": 0}

    def store_relationships(self, dataset_version_id: str, relationships: List[Any]) -> int:
        """Persists STIX relationships."""
        if hasattr(self.repository, "save_mitre_relationships"):
            return self.repository.save_mitre_relationships(dataset_version_id, relationships)
        return len(relationships)

    def get_object(self, identifier: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves MITRE object by ATT&CK ID or STIX ID."""
        if hasattr(self.repository, "get_mitre_object"):
            return self.repository.get_mitre_object(identifier, version_id=version_id)
        return None

    def list_techniques(
        self, tactic: Optional[str] = None, platform: Optional[str] = None, version_id: Optional[str] = None, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Lists techniques filtered by tactic or platform."""
        if hasattr(self.repository, "search_mitre_objects"):
            return self.repository.search_mitre_objects(
                tactic=tactic, platform=platform, entity_type="attack-pattern", version_id=version_id, limit=limit
            )
        return []

    def list_groups(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Lists intrusion set groups."""
        if hasattr(self.repository, "list_mitre_objects"):
            return self.repository.list_mitre_objects(type="intrusion-set", version_id=version_id, limit=limit)
        return []

    def list_software(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Lists malware and tools."""
        if hasattr(self.repository, "list_mitre_objects"):
            malware = self.repository.list_mitre_objects(type="malware", version_id=version_id, limit=limit)
            tools = self.repository.list_mitre_objects(type="tool", version_id=version_id, limit=limit)
            return malware + tools
        return []

    def list_campaigns(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Lists campaigns."""
        if hasattr(self.repository, "list_mitre_objects"):
            return self.repository.list_mitre_objects(type="campaign", version_id=version_id, limit=limit)
        return []

    def list_mitigations(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Lists mitigations (course-of-action)."""
        if hasattr(self.repository, "list_mitre_objects"):
            return self.repository.list_mitre_objects(type="course-of-action", version_id=version_id, limit=limit)
        return []

    def list_data_sources(self, version_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Lists data sources."""
        if hasattr(self.repository, "list_mitre_objects"):
            return self.repository.list_mitre_objects(type="x-mitre-data-source", version_id=version_id, limit=limit)
        return []

    def get_relationships(
        self, source_ref: Optional[str] = None, target_ref: Optional[str] = None, relationship_type: Optional[str] = None, version_id: Optional[str] = None, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Lists STIX relationships."""
        if hasattr(self.repository, "list_mitre_relationships"):
            return self.repository.list_mitre_relationships(
                source_ref=source_ref, target_ref=target_ref, relationship_type=relationship_type, version_id=version_id, limit=limit
            )
        return []

    def search(
        self,
        query: str = "",
        technique_id: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        alias: Optional[str] = None,
        entity_type: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Executes search over MITRE dataset."""
        if hasattr(self.repository, "search_mitre_objects"):
            return self.repository.search_mitre_objects(
                query=query,
                technique_id=technique_id,
                tactic=tactic,
                platform=platform,
                alias=alias,
                entity_type=entity_type,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns statistics for MITRE dataset version."""
        if hasattr(self.repository, "get_mitre_statistics_for_version"):
            return self.repository.get_mitre_statistics_for_version(version_id)
        return {}
