"""
Event definitions for MITRE CAPEC Enterprise Intelligence Pipeline (IL-6).
Published through the IL-1 Event Bus on lifecycle transitions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass(frozen=True)
class CapecImportStarted:
    """Published when a CAPEC import lifecycle begins."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CapecImportStarted"
    feed_id: str = "mitre_capec_xml"
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
class CapecImportCompleted:
    """Published when a CAPEC import lifecycle completes successfully."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CapecImportCompleted"
    feed_id: str = "mitre_capec_xml"
    import_id: str = ""
    records_processed: int = 0
    records_inserted: int = 0
    records_updated: int = 0
    canonical_entities_created: int = 0
    cwe_mappings_created: int = 0
    attack_mappings_created: int = 0
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
            "cwe_mappings_created": self.cwe_mappings_created,
            "attack_mappings_created": self.attack_mappings_created,
            "dataset_version": self.dataset_version,
            "catalog_version": self.catalog_version,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CapecImportFailed:
    """Published when a CAPEC import lifecycle fails."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CapecImportFailed"
    feed_id: str = "mitre_capec_xml"
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
class CanonicalCapecCreated:
    """Published when a new Canonical CAPEC entity is registered in CIIL."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CanonicalCapecCreated"
    feed_id: str = "mitre_capec_xml"
    canonical_uuid: str = ""
    capec_id: str = ""
    name: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "canonical_uuid": self.canonical_uuid,
            "capec_id": self.capec_id,
            "name": self.name,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CapecCweMappingCreated:
    """Published when a CAPEC-to-CWE mapping is recorded in the knowledge graph."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CapecCweMappingCreated"
    feed_id: str = "mitre_capec_xml"
    capec_id: str = ""
    cwe_id: str = ""
    dataset_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "feed_id": self.feed_id,
            "capec_id": self.capec_id,
            "cwe_id": self.cwe_id,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CapecDatasetActivated:
    """Published when a CAPEC dataset version is activated."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "CapecDatasetActivated"
    feed_id: str = "mitre_capec_xml"
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
    """Published when the knowledge graph is updated with new CAPEC data."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "KnowledgeGraphUpdated"
    feed_id: str = "mitre_capec_xml"
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
