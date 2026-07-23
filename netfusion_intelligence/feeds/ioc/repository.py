"""
IL-7 IOC Feed Repository Facade.
Domain-level wrapper over IntelligenceRepositoryInterface for all IOC operations.
Follows the CapecRepository / CweRepository pattern exactly.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class IocRepository:
    """
    Domain repository for IOC intelligence storage, retrieval, and search.
    Delegates all persistence to the platform IntelligenceRepositoryInterface.
    """

    FEED_ID = "netfusion_ioc_v1"

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def store_indicators(self, version_id: str, entities: List[Any]) -> Dict[str, int]:
        if hasattr(self.repository, "save_ioc_indicators"):
            return self.repository.save_ioc_indicators(version_id, entities)
        return {"inserted": len(entities), "updated": 0, "duplicates": 0}

    def get_indicator(self, ioc_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if hasattr(self.repository, "get_ioc_indicator"):
            return self.repository.get_ioc_indicator(ioc_id, version_id=version_id)
        return None

    def list_indicators(
        self, ioc_type: Optional[str] = None, status: Optional[str] = None,
        min_confidence: Optional[float] = None, min_reputation: Optional[float] = None,
        provider: Optional[str] = None, severity: Optional[str] = None,
        version_id: Optional[str] = None, limit: int = 100, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if hasattr(self.repository, "list_ioc_indicators"):
            return self.repository.list_ioc_indicators(
                ioc_type=ioc_type, status=status, min_confidence=min_confidence,
                min_reputation=min_reputation, provider=provider, severity=severity,
                version_id=version_id, limit=limit, offset=offset,
            )
        return []

    def search(
        self, query: str = "", ioc_type: Optional[str] = None, value: Optional[str] = None,
        hash_value: Optional[str] = None, ip: Optional[str] = None,
        domain: Optional[str] = None, threat_actor: Optional[str] = None,
        campaign: Optional[str] = None, malware: Optional[str] = None,
        attack_technique: Optional[str] = None, capec_id: Optional[str] = None,
        cwe_id: Optional[str] = None, cve_id: Optional[str] = None,
        provider: Optional[str] = None, min_confidence: Optional[float] = None,
        min_reputation: Optional[float] = None,
        first_seen_start: Optional[str] = None, first_seen_end: Optional[str] = None,
        last_seen_start: Optional[str] = None, last_seen_end: Optional[str] = None,
        version_id: Optional[str] = None, limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if hasattr(self.repository, "search_ioc_indicators"):
            return self.repository.search_ioc_indicators(
                query=query, ioc_type=ioc_type, value=value, hash_value=hash_value,
                ip=ip, domain=domain, threat_actor=threat_actor, campaign=campaign,
                malware=malware, attack_technique=attack_technique, capec_id=capec_id,
                cwe_id=cwe_id, cve_id=cve_id, provider=provider,
                min_confidence=min_confidence, min_reputation=min_reputation,
                first_seen_start=first_seen_start, first_seen_end=first_seen_end,
                last_seen_start=last_seen_start, last_seen_end=last_seen_end,
                version_id=version_id, limit=limit,
            )
        return []

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def store_relationships(self, version_id: str, relationships: List[Any]) -> int:
        if hasattr(self.repository, "save_ioc_relationships"):
            return self.repository.save_ioc_relationships(version_id, relationships)
        return len(relationships)

    def get_relationships(
        self, ioc_id: str, version_id: Optional[str] = None,
        direction: str = "both", limit: int = 200,
    ) -> List[Dict[str, Any]]:
        if hasattr(self.repository, "get_ioc_relationships"):
            return self.repository.get_ioc_relationships(
                ioc_id, version_id=version_id, direction=direction, limit=limit
            )
        return []

    # ------------------------------------------------------------------
    # Reputation
    # ------------------------------------------------------------------

    def store_reputations(self, version_id: str, reputations: List[Any]) -> int:
        if hasattr(self.repository, "save_ioc_reputations"):
            return self.repository.save_ioc_reputations(version_id, reputations)
        return len(reputations)

    def get_reputation(self, ioc_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if hasattr(self.repository, "get_ioc_reputation"):
            return self.repository.get_ioc_reputation(ioc_id, version_id=version_id)
        return None

    # ------------------------------------------------------------------
    # Sightings
    # ------------------------------------------------------------------

    def store_sightings(self, version_id: str, sightings: List[Any]) -> int:
        if hasattr(self.repository, "save_ioc_sightings"):
            return self.repository.save_ioc_sightings(version_id, sightings)
        return len(sightings)

    def get_sightings(
        self, ioc_id: str, version_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if hasattr(self.repository, "get_ioc_sightings"):
            return self.repository.get_ioc_sightings(ioc_id, version_id=version_id, limit=limit)
        return []

    # ------------------------------------------------------------------
    # Statistics & versioning
    # ------------------------------------------------------------------

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        if hasattr(self.repository, "get_ioc_statistics_for_version"):
            return self.repository.get_ioc_statistics_for_version(version_id)
        return {}

    def get_active_version(self):
        return self.repository.get_active_dataset_version(self.FEED_ID)
