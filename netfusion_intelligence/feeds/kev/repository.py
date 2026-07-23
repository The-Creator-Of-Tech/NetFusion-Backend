"""
Repository wrapper for CISA KEV Enterprise Intelligence Pipeline.
Provides query and persistence access over KEV storage tables.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class CisaKevRepository:
    """
    High-level repository manager for CISA KEV dataset persistence.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self._repository = repository

    def store_kev_records(self, version_id: str, records: List[Any]) -> Dict[str, int]:
        if hasattr(self._repository, "store_kev_records"):
            return self._repository.store_kev_records(version_id, records)
        return {"inserted": len(records), "updated": 0, "duplicates": 0}

    def list_kev_records(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        ransomware: Optional[str] = None,
        due_date: Optional[str] = None,
        date_added: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._repository, "list_kev_records"):
            return self._repository.list_kev_records(
                vendor=vendor,
                product=product,
                ransomware=ransomware,
                due_date=due_date,
                date_added=date_added,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def get_kev_record(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if hasattr(self._repository, "get_kev_record"):
            return self._repository.get_kev_record(cve_id, version_id=version_id)
        return None

    def list_kev_vendors(self, version_id: Optional[str] = None) -> List[str]:
        if hasattr(self._repository, "list_kev_vendors"):
            return self._repository.list_kev_vendors(version_id=version_id)
        return []

    def list_kev_products(self, version_id: Optional[str] = None) -> List[str]:
        if hasattr(self._repository, "list_kev_products"):
            return self._repository.list_kev_products(version_id=version_id)
        return []

    def search_kev_records(
        self,
        query: str = "",
        cve_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        due_date: Optional[str] = None,
        ransomware: Optional[str] = None,
        exploitation_status: Optional[str] = None,
        date_added: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._repository, "search_kev_records"):
            return self._repository.search_kev_records(
                query=query,
                cve_id=cve_id,
                vendor=vendor,
                product=product,
                due_date=due_date,
                ransomware=ransomware,
                exploitation_status=exploitation_status,
                date_added=date_added,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_kev_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        if hasattr(self._repository, "get_kev_statistics_for_version"):
            return self._repository.get_kev_statistics_for_version(version_id=version_id)
        return {}
