"""
Event definitions for FIRST EPSS Intelligence Pipeline.
Published through the IL-1 Event Bus on lifecycle transitions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass(frozen=True)
class EpssImportStarted:
    """Published when an EPSS import lifecycle begins."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "EpssImportStarted"
    feed_id: str = "first_epss_1.0"
    import_id: str = ""
    triggered_by: str = "scheduler"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "import_id": self.import_id,
            "triggered_by": self.triggered_by,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class EpssImportCompleted:
    """Published when an EPSS import lifecycle completes successfully."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "EpssImportCompleted"
    feed_id: str = "first_epss_1.0"
    import_id: str = ""
    records_processed: int = 0
    records_inserted: int = 0
    records_updated: int = 0
    canonical_entities_enriched: int = 0
    dataset_version: str = ""
    model_version: str = ""
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "import_id": self.import_id,
            "records_processed": self.records_processed,
            "records_inserted": self.records_inserted,
            "records_updated": self.records_updated,
            "canonical_entities_enriched": self.canonical_entities_enriched,
            "dataset_version": self.dataset_version,
            "model_version": self.model_version,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class EpssImportFailed:
    """Published when an EPSS import lifecycle fails."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "EpssImportFailed"
    feed_id: str = "first_epss_1.0"
    import_id: str = ""
    error_message: str = ""
    failure_stage: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "import_id": self.import_id,
            "error_message": self.error_message,
            "failure_stage": self.failure_stage,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class EpssScoreCreated:
    """Published when a new EPSS score record is inserted."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "EpssScoreCreated"
    feed_id: str = "first_epss_1.0"
    cve_id: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    model_version: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "cve_id": self.cve_id,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "model_version": self.model_version,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class EpssScoreUpdated:
    """Published when an existing EPSS score record is updated."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "EpssScoreUpdated"
    feed_id: str = "first_epss_1.0"
    cve_id: str = ""
    previous_score: float = 0.0
    new_score: float = 0.0
    score_delta: float = 0.0
    model_version: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "cve_id": self.cve_id,
            "previous_score": self.previous_score,
            "new_score": self.new_score,
            "score_delta": self.score_delta,
            "model_version": self.model_version,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CanonicalEntityEnriched:
    """Published when a canonical CVE entity is enriched with EPSS data."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CanonicalEntityEnriched"
    feed_id: str = "first_epss_1.0"
    canonical_uuid: str = ""
    cve_id: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    enrichment_type: str = "EPSS_SCORE"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "canonical_uuid": self.canonical_uuid,
            "cve_id": self.cve_id,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "enrichment_type": self.enrichment_type,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class DatasetActivated:
    """Published when an EPSS dataset version is activated."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "DatasetActivated"
    feed_id: str = "first_epss_1.0"
    dataset_version: str = ""
    model_version: str = ""
    record_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "dataset_version": self.dataset_version,
            "model_version": self.model_version,
            "record_count": self.record_count,
            "timestamp": self.timestamp,
        }
