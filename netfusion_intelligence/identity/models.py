"""
Canonical Intelligence Entity Models for NetFusion CIIL.
Defines immutable CanonicalEntity, ExternalIdentifier, EntityProvenance, and EntityMergeRecord.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


class CanonicalEntityType(str, Enum):
    """
    Standard generic entity categories supported by NetFusion CIIL.
    Extensible for custom entity types.
    """
    ATTACK_TECHNIQUE = "ATTACK_TECHNIQUE"
    ATTACK_TACTIC = "ATTACK_TACTIC"
    ATTACK_GROUP = "ATTACK_GROUP"
    ATTACK_CAMPAIGN = "ATTACK_CAMPAIGN"
    ATTACK_SOFTWARE = "ATTACK_SOFTWARE"
    ATTACK_MITIGATION = "ATTACK_MITIGATION"
    ATTACK_DATA_SOURCE = "ATTACK_DATA_SOURCE"

    CVE = "CVE"
    CWE = "CWE"
    CAPEC = "CAPEC"
    EXPLOIT = "EXPLOIT"

    IOC = "IOC"
    HASH = "HASH"
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP_ADDRESS = "IP_ADDRESS"
    EMAIL = "EMAIL"
    FILE = "FILE"

    MALWARE = "MALWARE"
    TOOL = "TOOL"
    THREAT_ACTOR = "THREAT_ACTOR"
    ORGANIZATION = "ORGANIZATION"
    VENDOR = "VENDOR"
    PRODUCT = "PRODUCT"

    SIGNATURE = "SIGNATURE"
    RULE = "RULE"
    CERTIFICATE = "CERTIFICATE"
    OTHER = "OTHER"

    @classmethod
    def is_valid(cls, val: str) -> bool:
        return True  # Extensible, allows custom entity type strings


@dataclass(frozen=True)
class ExternalIdentifier:
    """
    Represents an external identifier associated with a CanonicalEntity.
    """
    source: str
    identifier: str
    identifier_type: str
    url: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def __post_init__(self):
        if not self.source:
            raise ValueError("ExternalIdentifier 'source' cannot be empty")
        if not self.identifier:
            raise ValueError("ExternalIdentifier 'identifier' cannot be empty")
        if not self.identifier_type:
            raise ValueError("ExternalIdentifier 'identifier_type' cannot be empty")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "identifier": self.identifier,
            "identifier_type": self.identifier_type,
            "url": self.url,
            "version": self.version,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalIdentifier":
        first_seen = datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None
        last_seen = datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None
        return cls(
            source=data["source"],
            identifier=data["identifier"],
            identifier_type=data["identifier_type"],
            url=data.get("url"),
            version=data.get("version"),
            confidence=float(data.get("confidence", 1.0)),
            first_seen=first_seen,
            last_seen=last_seen,
        )


@dataclass(frozen=True)
class EntityProvenance:
    """
    Tracks origin and lineage of field contributions to a CanonicalEntity.
    """
    provenance_id: str
    canonical_uuid: str
    feed: str
    dataset_version: str
    timestamp: datetime
    original_object_id: str
    verification_status: str = "VERIFIED"
    trust_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance_id": self.provenance_id,
            "canonical_uuid": self.canonical_uuid,
            "feed": self.feed,
            "dataset_version": self.dataset_version,
            "timestamp": self.timestamp.isoformat(),
            "original_object_id": self.original_object_id,
            "verification_status": self.verification_status,
            "trust_score": self.trust_score,
        }

    @classmethod
    def create(
        cls,
        canonical_uuid: str,
        feed: str,
        dataset_version: str,
        original_object_id: str,
        verification_status: str = "VERIFIED",
        trust_score: float = 1.0,
        provenance_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> "EntityProvenance":
        return cls(
            provenance_id=provenance_id or str(uuid.uuid4()),
            canonical_uuid=canonical_uuid,
            feed=feed,
            dataset_version=dataset_version,
            timestamp=timestamp or datetime.now(timezone.utc),
            original_object_id=original_object_id,
            verification_status=verification_status,
            trust_score=trust_score,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntityProvenance":
        ts = datetime.fromisoformat(data["timestamp"]) if isinstance(data["timestamp"], str) else data["timestamp"]
        return cls(
            provenance_id=data["provenance_id"],
            canonical_uuid=data["canonical_uuid"],
            feed=data["feed"],
            dataset_version=data["dataset_version"],
            timestamp=ts,
            original_object_id=data["original_object_id"],
            verification_status=data.get("verification_status", "VERIFIED"),
            trust_score=float(data.get("trust_score", 1.0)),
        )


@dataclass(frozen=True)
class EntityMergeRecord:
    """
    Audit record capturing entity merge history.
    """
    merge_id: str
    target_canonical_uuid: str
    merged_canonical_uuid: str
    timestamp: datetime
    reason: str
    provenance_transferred: int = 0
    merged_by: str = "CIIL_Resolver"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "merge_id": self.merge_id,
            "target_canonical_uuid": self.target_canonical_uuid,
            "merged_canonical_uuid": self.merged_canonical_uuid,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "provenance_transferred": self.provenance_transferred,
            "merged_by": self.merged_by,
        }

    @classmethod
    def create(
        cls,
        target_canonical_uuid: str,
        merged_canonical_uuid: str,
        reason: str,
        provenance_transferred: int = 0,
        merged_by: str = "CIIL_Resolver",
    ) -> "EntityMergeRecord":
        return cls(
            merge_id=str(uuid.uuid4()),
            target_canonical_uuid=target_canonical_uuid,
            merged_canonical_uuid=merged_canonical_uuid,
            timestamp=datetime.now(timezone.utc),
            reason=reason,
            provenance_transferred=provenance_transferred,
            merged_by=merged_by,
        )


@dataclass(frozen=True)
class CanonicalEntity:
    """
    Immutable Canonical Entity representation in NetFusion CIIL.
    UUIDs are immutable and guaranteed unique.
    """
    canonical_uuid: str
    entity_type: str
    display_name: str
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    description: Optional[str] = None
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    status: str = "ACTIVE"
    active: bool = True
    source_count: int = 1
    relationship_count: int = 0
    tags: Tuple[str, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)
    external_identifiers: Tuple[ExternalIdentifier, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.canonical_uuid:
            raise ValueError("canonical_uuid cannot be empty")
        if not self.entity_type:
            raise ValueError("entity_type cannot be empty")
        if not self.display_name:
            raise ValueError("display_name cannot be empty")

        # Convert mutable parameters to immutable tuples if passed as lists
        if isinstance(self.aliases, list):
            object.__setattr__(self, "aliases", tuple(self.aliases))
        if isinstance(self.tags, list):
            object.__setattr__(self, "tags", tuple(self.tags))
        if isinstance(self.external_identifiers, list):
            object.__setattr__(self, "external_identifiers", tuple(self.external_identifiers))

    def with_updated(self, **kwargs) -> "CanonicalEntity":
        """
        Creates a new CanonicalEntity with updated fields while preserving immutability.
        The canonical_uuid can NEVER be changed.
        """
        if "canonical_uuid" in kwargs and kwargs["canonical_uuid"] != self.canonical_uuid:
            raise ValueError("Canonical UUID is immutable and cannot be changed")

        current = {
            "canonical_uuid": self.canonical_uuid,
            "entity_type": self.entity_type,
            "display_name": self.display_name,
            "aliases": self.aliases,
            "description": self.description,
            "created": self.created,
            "modified": datetime.now(timezone.utc),
            "confidence": self.confidence,
            "status": self.status,
            "active": self.active,
            "source_count": self.source_count,
            "relationship_count": self.relationship_count,
            "tags": self.tags,
            "metadata": self.metadata,
            "external_identifiers": self.external_identifiers,
        }
        current.update(kwargs)
        return CanonicalEntity(**current)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_uuid": self.canonical_uuid,
            "entity_type": self.entity_type,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "description": self.description,
            "created": self.created.isoformat() if isinstance(self.created, datetime) else self.created,
            "modified": self.modified.isoformat() if isinstance(self.modified, datetime) else self.modified,
            "confidence": self.confidence,
            "status": self.status,
            "active": self.active,
            "source_count": self.source_count,
            "relationship_count": self.relationship_count,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "external_identifiers": [ext.to_dict() for ext in self.external_identifiers],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalEntity":
        created = datetime.fromisoformat(data["created"]) if isinstance(data.get("created"), str) else data.get("created", datetime.now(timezone.utc))
        modified = datetime.fromisoformat(data["modified"]) if isinstance(data.get("modified"), str) else data.get("modified", datetime.now(timezone.utc))

        ext_ids = tuple(
            ExternalIdentifier.from_dict(item) if isinstance(item, dict) else item
            for item in data.get("external_identifiers", [])
        )

        return cls(
            canonical_uuid=data["canonical_uuid"],
            entity_type=data["entity_type"],
            display_name=data["display_name"],
            aliases=tuple(data.get("aliases", [])),
            description=data.get("description"),
            created=created,
            modified=modified,
            confidence=float(data.get("confidence", 1.0)),
            status=data.get("status", "ACTIVE"),
            active=bool(data.get("active", True)),
            source_count=int(data.get("source_count", 1)),
            relationship_count=int(data.get("relationship_count", 0)),
            tags=tuple(data.get("tags", [])),
            metadata=dict(data.get("metadata", {})),
            external_identifiers=ext_ids,
        )
