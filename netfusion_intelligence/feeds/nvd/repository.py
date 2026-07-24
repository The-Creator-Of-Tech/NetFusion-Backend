"""
NVD Enterprise Repository Wrapper for NetFusion IL-3 NVD Pipeline.
Handles persistence, retrieval, search, and version management of NVD CVE records.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.feeds.nvd.models import NvdCve


class NvdRepository:
    """
    Repository layer for NVD Enterprise CVE Intelligence data persistence and querying.
    Delegates ORM operations to IntelligenceRepositoryInterface.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def store_cves(self, version_id: str, cves: List[NvdCve]) -> Dict[str, int]:
        """
        Stores a list of normalized NvdCve objects for a given dataset version_id.
        Returns dict with counts of inserted, updated, and duplicates.
        """
        if hasattr(self.repository, "save_nvd_cves"):
            return self.repository.save_nvd_cves(version_id, cves)
        return {"inserted": len(cves), "updated": 0, "duplicates": 0}

    def get_cve(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single CVE object by CVE ID.
        """
        if hasattr(self.repository, "get_nvd_cve"):
            return self.repository.get_nvd_cve(cve_id, version_id=version_id)
        return None

    def list_cves(
        self,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Lists stored CVE records with optional severity, vendor, or product filter.
        """
        if hasattr(self.repository, "list_nvd_cves"):
            return self.repository.list_nvd_cves(
                severity=severity,
                vendor=vendor,
                product=product,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def search_cves(
        self,
        query: str = "",
        cve_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        cwe: Optional[str] = None,
        severity: Optional[str] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
        pub_start: Optional[str] = None,
        pub_end: Optional[str] = None,
        mod_start: Optional[str] = None,
        mod_end: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Multi-parameter search across CVE ID, vendor, product, CWE, severity, CVSS scores, dates, or keywords.
        """
        if hasattr(self.repository, "search_nvd_cves"):
            return self.repository.search_nvd_cves(
                query=query,
                cve_id=cve_id,
                vendor=vendor,
                product=product,
                cwe=cwe,
                severity=severity,
                min_cvss=min_cvss,
                max_cvss=max_cvss,
                pub_start=pub_start,
                pub_end=pub_end,
                mod_start=mod_start,
                mod_end=mod_end,
                version_id=version_id,
                limit=limit,
            )
        return []

    def list_vendors(self, version_id: Optional[str] = None) -> List[str]:
        """Lists all distinct affected vendors in active or target dataset version."""
        if hasattr(self.repository, "list_nvd_vendors"):
            return self.repository.list_nvd_vendors(version_id=version_id)
        return []

    def list_products(self, version_id: Optional[str] = None) -> List[str]:
        """Lists all distinct affected products in active or target dataset version."""
        if hasattr(self.repository, "list_nvd_products"):
            return self.repository.list_nvd_products(version_id=version_id)
        return []

    def list_cwes(self, version_id: Optional[str] = None) -> List[str]:
        """Lists all distinct CWE weakness IDs in active or target dataset version."""
        if hasattr(self.repository, "list_nvd_cwes"):
            return self.repository.list_nvd_cwes(version_id=version_id)
        return []

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns NVD dataset breakdown statistics."""
        if hasattr(self.repository, "get_nvd_statistics_for_version"):
            return self.repository.get_nvd_statistics_for_version(version_id=version_id)
        return {}
