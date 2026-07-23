"""
Identity Statistics Tracker for NetFusion CIIL.
Calculates platform metrics, source coverage, deduplication rates, and entity distributions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.identity.repository import IdentityRepository


@dataclass
class IdentityStatistics:
    """
    Data snapshot of Canonical Identity Layer statistics.
    """
    total_canonical_entities: int = 0
    active_entities: int = 0
    merged_entities: int = 0
    total_external_identifiers: int = 0
    total_relationships: int = 0
    duplicate_prevented_count: int = 0
    deduplication_rate: float = 0.0
    source_count: int = 0
    sources: List[str] = field(default_factory=list)
    entity_types_breakdown: Dict[str, int] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_canonical_entities": self.total_canonical_entities,
            "active_entities": self.active_entities,
            "merged_entities": self.merged_entities,
            "total_external_identifiers": self.total_external_identifiers,
            "total_relationships": self.total_relationships,
            "duplicate_prevented_count": self.duplicate_prevented_count,
            "deduplication_rate": round(self.deduplication_rate, 4),
            "source_count": self.source_count,
            "sources": list(self.sources),
            "entity_types_breakdown": dict(self.entity_types_breakdown),
            "timestamp": self.timestamp.isoformat(),
        }


class IdentityStatisticsTracker:
    """
    Aggregates statistics from the IdentityRepository and IdentityResolver.
    """

    def __init__(self, repository: IdentityRepository):
        self.repository = repository

    def generate_statistics(self, duplicate_prevented_count: int = 0) -> IdentityStatistics:
        counts = self.repository.get_counts()
        sources = self.repository.list_sources()

        total = counts["total_entities"]
        prevented = duplicate_prevented_count
        dedup_rate = 0.0
        if total + prevented > 0:
            dedup_rate = float(prevented) / float(total + prevented)

        return IdentityStatistics(
            total_canonical_entities=counts["total_entities"],
            active_entities=counts["active_entities"],
            merged_entities=counts["merged_entities"],
            total_external_identifiers=counts["total_external_identifiers"],
            total_relationships=counts["total_relationships"],
            duplicate_prevented_count=prevented,
            deduplication_rate=dedup_rate,
            source_count=len(sources),
            sources=sources,
            entity_types_breakdown=counts["entity_types_breakdown"],
            timestamp=datetime.now(timezone.utc),
        )
