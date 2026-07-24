"""
EPSS Enterprise Repository Wrapper for NetFusion IL-5 EPSS Pipeline.
Handles persistence, retrieval, search, and historical tracking of EPSS score records.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.feeds.epss.models import EpssRecord, EpssHistoricalScore


class EpssRepository:
    """
    Repository layer for EPSS Enterprise Intelligence data persistence and querying.
    Delegates ORM operations to IntelligenceRepositoryInterface.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    def store_epss_records(self, version_id: str, records: List[EpssRecord]) -> Dict[str, int]:
        """
        Stores a list of normalized EpssRecord objects for a given dataset version_id.
        Returns dict with counts of inserted, updated, and duplicates.
        """
        if hasattr(self.repository, "save_epss_scores"):
            return self.repository.save_epss_scores(version_id, records)
        return {"inserted": len(records), "updated": 0, "duplicates": 0}

    def store_historical_scores(
        self,
        version_id: str,
        historical_scores: List[EpssHistoricalScore]
    ) -> Dict[str, int]:
        """
        Stores historical EPSS score snapshots for trend analysis.
        Returns dict with counts of inserted, updated, and duplicates.
        """
        if hasattr(self.repository, "save_epss_history"):
            return self.repository.save_epss_history(version_id, historical_scores)
        return {"inserted": len(historical_scores), "updated": 0, "duplicates": 0}

    def get_epss_score(
        self,
        cve_id: str,
        version_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves current EPSS score for a specific CVE ID.
        """
        if hasattr(self.repository, "get_epss_score"):
            return self.repository.get_epss_score(cve_id, version_id=version_id)
        return None

    def get_epss_history(
        self,
        cve_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieves historical EPSS score records for a specific CVE ID.
        Ordered by date descending (most recent first).
        """
        if hasattr(self.repository, "get_epss_history"):
            return self.repository.get_epss_history(cve_id, limit=limit)
        return []

    def list_epss_scores(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Lists stored EPSS score records with optional filters.
        """
        if hasattr(self.repository, "list_epss_scores"):
            return self.repository.list_epss_scores(
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                max_percentile=max_percentile,
                trend=trend,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        return []

    def search_epss_scores(
        self,
        cve_id: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        publication_date: Optional[str] = None,
        model_version: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Multi-parameter search across EPSS scores.
        """
        if hasattr(self.repository, "search_epss_scores"):
            return self.repository.search_epss_scores(
                cve_id=cve_id,
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                max_percentile=max_percentile,
                trend=trend,
                publication_date=publication_date,
                model_version=model_version,
                version_id=version_id,
                limit=limit,
            )
        return []

    def get_trending_cves(
        self,
        trend_type: str = "INCREASING",
        limit: int = 100,
        version_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves CVEs with specific trend classifications.
        trend_type: RAPIDLY_INCREASING, INCREASING, STABLE, DECREASING, RAPIDLY_DECREASING
        """
        if hasattr(self.repository, "get_trending_epss_cves"):
            return self.repository.get_trending_epss_cves(
                trend_type=trend_type,
                limit=limit,
                version_id=version_id,
            )
        return []

    def get_high_probability_cves(
        self,
        min_score: float = 0.5,
        limit: int = 100,
        version_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves CVEs with high exploit probability (EPSS score >= threshold).
        """
        return self.search_epss_scores(
            min_score=min_score,
            version_id=version_id,
            limit=limit,
        )

    def get_statistics(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns EPSS dataset breakdown statistics."""
        if hasattr(self.repository, "get_epss_statistics_for_version"):
            return self.repository.get_epss_statistics_for_version(version_id=version_id)
        return {}
