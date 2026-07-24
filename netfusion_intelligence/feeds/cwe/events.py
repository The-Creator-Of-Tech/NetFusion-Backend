"""
Event definitions for MITRE CWE Enterprise Intelligence Pipeline (IL-6).
Published through the IL-1 Event Bus on lifecycle transitions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass(frozen=True)
class CweImportStarted:
    """Published when a CWE import lifecycle begins."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CweImportStarted"
    feed_id: str = "mitre_cwe_xml"
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
class CweImportCompleted:
    """Published when a CWE import lifecycle completes successfully."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CweImportCompleted"
    feed_id: str = "mitre_cwe_xml"
    import_id: str = ""
    records_processed: int = 0
    records_inserted: int = 0
    records_updated: int = 0
    canonical_entities_created: int = 0
    relationships_created: int = 0
    dataset_version: str = ""
    catalog_version: str = ""
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
            "canonical_entities_created": self.canonical_entities_created,
            "relationships_created": self.relationships_created,
            "dataset_version": self.dataset_version,
            "catalog_version": self.catalog_version,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CweImportFailed:
    """Published when a CWE import lifecycle fails."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CweImportFailed"
    feed_id: str = "mitre_cwe_xml"
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
class CanonicalCweCreated:
    """Published when a new Canonical CWE entity is registered in CIIL."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CanonicalCweCreated"
    feed_id: str = "mitre_cwe_xml"
    canonical_uuid: str = ""
    cwe_id: str = ""
    name: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "canonical_uuid": self.canonical_uuid,
            "cwe_id": self.cwe_id,
            "name": self.name,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CweRelationshipCreated:
    """Published when a new CWE-to-CWE relationship is recorded in the knowledge graph."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CweRelationshipCreated"
    feed_id: str = "mitre_cwe_xml"
    source_cwe_id: str = ""
    target_cwe_id: str = ""
    nature: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "source_cwe_id": self.source_cwe_id,
            "target_cwe_id": self.target_cwe_id,
            "nature": self.nature,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CweDatasetActivated:
    """Published when a CWE dataset version is activated."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CweDatasetActivated"
    feed_id: str = "mitre_cwe_xml"
    dataset_version: str = ""
    catalog_version: str = ""
    record_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "dataset_version": self.dataset_version,
            "catalog_version": self.catalog_version,
            "record_count": self.record_count,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class KnowledgeGraphUpdated:
    """Published when the knowledge graph is updated with new CWE data."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "KnowledgeGraphUpdated"
    feed_id: str = "mitre_cwe_xml"
    nodes_added: int = 0
    edges_added: int = 0
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "nodes_added": self.nodes_added,
            "edges_added": self.edges_added,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }
