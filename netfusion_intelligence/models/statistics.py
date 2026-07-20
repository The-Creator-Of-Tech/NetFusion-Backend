"""
Statistics models for system-wide and feed-level intelligence metrics.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class FeedStatistics:
    """
    Ingestion & dataset metrics for a single feed.
    """
    feed_id: str
    feed_name: str
    total_syncs: int = 0
    successful_syncs: int = 0
    failed_syncs: int = 0
    total_records_ingested: int = 0
    total_datasets_created: int = 0
    active_version_id: Optional[str] = None
    last_sync_duration_seconds: float = 0.0
    avg_sync_duration_seconds: float = 0.0
    last_sync_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntelligenceStatistics:
    """
    Global intelligence subsystem metrics.
    """
    total_feeds_registered: int = 0
    active_feeds_count: int = 0
    total_datasets_managed: int = 0
    total_records_processed: int = 0
    total_records_inserted: int = 0
    total_records_updated: int = 0
    overall_health_score: float = 100.0
    feed_stats: Dict[str, FeedStatistics] = field(default_factory=dict)
    generated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_feeds_registered": self.total_feeds_registered,
            "active_feeds_count": self.active_feeds_count,
            "total_datasets_managed": self.total_datasets_managed,
            "total_records_processed": self.total_records_processed,
            "total_records_inserted": self.total_records_inserted,
            "total_records_updated": self.total_records_updated,
            "overall_health_score": self.overall_health_score,
            "feed_stats": {k: v.to_dict() for k, v in self.feed_stats.items()},
            "generated_at": self.generated_at,
        }
