"""
Domain models for FIRST Exploit Prediction Scoring System (EPSS) Intelligence Pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class EpssTrend(str, Enum):
    """Classification of EPSS score trend direction."""
    RAPIDLY_INCREASING = "RAPIDLY_INCREASING"
    INCREASING = "INCREASING"
    STABLE = "STABLE"
    DECREASING = "DECREASING"
    RAPIDLY_DECREASING = "RAPIDLY_DECREASING"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass(frozen=True)
class EpssScore:
    """
    Represents a single EPSS score record for a CVE.
    This is the primary intelligence entity.
    """
    cve_id: str
    epss_score: float
    epss_percentile: float
    publication_date: str
    model_version: str = "v2023.03.01"
    dataset_version: str = ""
    source: str = "FIRST EPSS"
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modified: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"

    def __post_init__(self):
        if not self.cve_id:
            raise ValueError("cve_id cannot be empty")
        if not (0.0 <= self.epss_score <= 1.0):
            raise ValueError(f"epss_score must be between 0.0 and 1.0, got {self.epss_score}")
        if not (0.0 <= self.epss_percentile <= 1.0):
            raise ValueError(f"epss_percentile must be between 0.0 and 1.0, got {self.epss_percentile}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "publication_date": self.publication_date,
            "model_version": self.model_version,
            "dataset_version": self.dataset_version,
            "source": self.source,
            "created": self.created,
            "modified": self.modified,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EpssScore":
        return cls(
            cve_id=data.get("cve_id", "").strip().upper(),
            epss_score=float(data.get("epss", data.get("epss_score", 0.0))),
            epss_percentile=float(data.get("percentile", data.get("epss_percentile", 0.0))),
            publication_date=data.get("date", data.get("publication_date", "")),
            model_version=data.get("model_version", "v2023.03.01"),
            dataset_version=data.get("dataset_version", ""),
            source=data.get("source", "FIRST EPSS"),
            created=data.get("created", datetime.now(timezone.utc).isoformat()),
            modified=data.get("modified", datetime.now(timezone.utc).isoformat()),
            status=data.get("status", "ACTIVE"),
        )


@dataclass(frozen=True)
class EpssHistoricalScore:
    """
    Represents a historical EPSS score snapshot for trend analysis.
    """
    cve_id: str
    epss_score: float
    epss_percentile: float
    date: str
    dataset_version: str
    model_version: str
    daily_delta_score: float = 0.0
    daily_delta_percentile: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "date": self.date,
            "dataset_version": self.dataset_version,
            "model_version": self.model_version,
            "daily_delta_score": self.daily_delta_score,
            "daily_delta_percentile": self.daily_delta_percentile,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EpssHistoricalScore":
        return cls(
            cve_id=data["cve_id"],
            epss_score=float(data["epss_score"]),
            epss_percentile=float(data["epss_percentile"]),
            date=data["date"],
            dataset_version=data["dataset_version"],
            model_version=data["model_version"],
            daily_delta_score=float(data.get("daily_delta_score", 0.0)),
            daily_delta_percentile=float(data.get("daily_delta_percentile", 0.0)),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass(frozen=True)
class EpssRecord:
    """
    Comprehensive EPSS record with current score and historical metadata.
    This is the normalized entity stored in the repository.
    """
    cve_id: str
    current_score: float
    current_percentile: float
    publication_date: str
    model_version: str = "v2023.03.01"
    dataset_version: str = ""
    trend: str = "INSUFFICIENT_DATA"
    moving_avg_7d: Optional[float] = None
    moving_avg_30d: Optional[float] = None
    historical_high: Optional[float] = None
    historical_low: Optional[float] = None
    first_observed: Optional[str] = None
    last_updated: Optional[str] = None
    observation_count: int = 1
    source: str = "FIRST EPSS"
    status: str = "ACTIVE"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.cve_id:
            raise ValueError("cve_id cannot be empty")
        if not (0.0 <= self.current_score <= 1.0):
            raise ValueError(f"current_score must be between 0.0 and 1.0, got {self.current_score}")
        if not (0.0 <= self.current_percentile <= 1.0):
            raise ValueError(f"current_percentile must be between 0.0 and 1.0, got {self.current_percentile}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "current_score": self.current_score,
            "current_percentile": self.current_percentile,
            "publication_date": self.publication_date,
            "model_version": self.model_version,
            "dataset_version": self.dataset_version,
            "trend": self.trend,
            "moving_avg_7d": self.moving_avg_7d,
            "moving_avg_30d": self.moving_avg_30d,
            "historical_high": self.historical_high,
            "historical_low": self.historical_low,
            "first_observed": self.first_observed,
            "last_updated": self.last_updated,
            "observation_count": self.observation_count,
            "source": self.source,
            "status": self.status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EpssRecord":
        return cls(
            cve_id=data["cve_id"],
            current_score=float(data["current_score"]),
            current_percentile=float(data["current_percentile"]),
            publication_date=data["publication_date"],
            model_version=data.get("model_version", "v2023.03.01"),
            dataset_version=data.get("dataset_version", ""),
            trend=data.get("trend", "INSUFFICIENT_DATA"),
            moving_avg_7d=float(data["moving_avg_7d"]) if data.get("moving_avg_7d") is not None else None,
            moving_avg_30d=float(data["moving_avg_30d"]) if data.get("moving_avg_30d") is not None else None,
            historical_high=float(data["historical_high"]) if data.get("historical_high") is not None else None,
            historical_low=float(data["historical_low"]) if data.get("historical_low") is not None else None,
            first_observed=data.get("first_observed"),
            last_updated=data.get("last_updated"),
            observation_count=int(data.get("observation_count", 1)),
            source=data.get("source", "FIRST EPSS"),
            status=data.get("status", "ACTIVE"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_score(cls, score: EpssScore) -> "EpssRecord":
        """Create an EpssRecord from an EpssScore."""
        return cls(
            cve_id=score.cve_id,
            current_score=score.epss_score,
            current_percentile=score.epss_percentile,
            publication_date=score.publication_date,
            model_version=score.model_version,
            dataset_version=score.dataset_version,
            trend="INSUFFICIENT_DATA",
            first_observed=score.created,
            last_updated=score.modified,
            observation_count=1,
            source=score.source,
            status=score.status,
        )


@dataclass
class EpssDataset:
    """
    Represents the full EPSS dataset container with metadata.
    """
    model_version: str = "v2023.03.01"
    publication_date: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    dataset_version: str = ""
    score_date: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    total_cves: int = 0
    records: Dict[str, EpssScore] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "publication_date": self.publication_date,
            "dataset_version": self.dataset_version,
            "score_date": self.score_date,
            "total_cves": self.total_cves,
            "records": [r.to_dict() for r in self.records.values()],
            "metadata": self.metadata,
        }
