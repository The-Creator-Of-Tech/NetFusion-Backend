"""
Canonical Relationship Layer for NetFusion CIIL.
Defines feed-independent CanonicalRelationship models and RelationshipEngine.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


@dataclass(frozen=True)
class CanonicalRelationship:
    """
    Feed-independent relationship model linking two Canonical Entities.
    """
    relationship_id: str
    source_canonical_uuid: str
    target_canonical_uuid: str
    relationship_type: str
    originating_source: str
    confidence: float = 1.0
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    originating_sources: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.relationship_id:
            raise ValueError("relationship_id cannot be empty")
        if not self.source_canonical_uuid:
            raise ValueError("source_canonical_uuid cannot be empty")
        if not self.target_canonical_uuid:
            raise ValueError("target_canonical_uuid cannot be empty")
        if not self.relationship_type:
            raise ValueError("relationship_type cannot be empty")

        if not self.originating_sources and self.originating_source:
            object.__setattr__(self, "originating_sources", (self.originating_source,))
        elif isinstance(self.originating_sources, list):
            object.__setattr__(self, "originating_sources", tuple(self.originating_sources))

    def with_updated(self, **kwargs) -> "CanonicalRelationship":
        current = {
            "relationship_id": self.relationship_id,
            "source_canonical_uuid": self.source_canonical_uuid,
            "target_canonical_uuid": self.target_canonical_uuid,
            "relationship_type": self.relationship_type,
            "originating_source": self.originating_source,
            "confidence": self.confidence,
            "created": self.created,
            "modified": datetime.now(timezone.utc),
            "version": self.version,
            "metadata": dict(self.metadata),
            "originating_sources": self.originating_sources,
        }
        current.update(kwargs)
        return CanonicalRelationship(**current)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_canonical_uuid": self.source_canonical_uuid,
            "target_canonical_uuid": self.target_canonical_uuid,
            "relationship_type": self.relationship_type,
            "originating_source": self.originating_source,
            "confidence": self.confidence,
            "created": self.created.isoformat() if isinstance(self.created, datetime) else self.created,
            "modified": self.modified.isoformat() if isinstance(self.modified, datetime) else self.modified,
            "version": self.version,
            "metadata": dict(self.metadata),
            "originating_sources": list(self.originating_sources),
        }

    @classmethod
    def create(
        cls,
        source_canonical_uuid: str,
        target_canonical_uuid: str,
        relationship_type: str,
        originating_source: str,
        confidence: float = 1.0,
        version: str = "1.0",
        metadata: Optional[Dict[str, Any]] = None,
        relationship_id: Optional[str] = None,
    ) -> "CanonicalRelationship":
        rel_id = relationship_id or str(uuid.uuid4())
        meta = metadata or {}
        sources = (originating_source,) if originating_source else ()
        return cls(
            relationship_id=rel_id,
            source_canonical_uuid=source_canonical_uuid,
            target_canonical_uuid=target_canonical_uuid,
            relationship_type=relationship_type.upper(),
            originating_source=originating_source,
            confidence=confidence,
            version=version,
            metadata=meta,
            originating_sources=sources,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalRelationship":
        created = datetime.fromisoformat(data["created"]) if isinstance(data.get("created"), str) else data.get("created", datetime.now(timezone.utc))
        modified = datetime.fromisoformat(data["modified"]) if isinstance(data.get("modified"), str) else data.get("modified", datetime.now(timezone.utc))

        sources = tuple(data.get("originating_sources", []))
        if not sources and data.get("originating_source"):
            sources = (data["originating_source"],)

        return cls(
            relationship_id=data["relationship_id"],
            source_canonical_uuid=data["source_canonical_uuid"],
            target_canonical_uuid=data["target_canonical_uuid"],
            relationship_type=data["relationship_type"],
            originating_source=data["originating_source"],
            confidence=float(data.get("confidence", 1.0)),
            created=created,
            modified=modified,
            version=data.get("version", "1.0"),
            metadata=dict(data.get("metadata", {})),
            originating_sources=sources,
        )


class RelationshipEngine:
    """
    Engine for creating, updating, merging, and linking feed-independent canonical relationships.
    """

    def __init__(self):
        self._relationships: Dict[str, CanonicalRelationship] = {}
        # Key: (source_uuid, target_uuid, relationship_type) -> relationship_id
        _index: Dict[Tuple[str, str, str], str] = {}
        self._index = _index

    def link_relationship(
        self,
        source_canonical_uuid: str,
        target_canonical_uuid: str,
        relationship_type: str,
        originating_source: str,
        confidence: float = 1.0,
        version: str = "1.0",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CanonicalRelationship:
        """
        Creates or updates a canonical relationship. Supports multiple sources providing the same link.
        """
        rel_type = relationship_type.upper()
        key = (source_canonical_uuid, target_canonical_uuid, rel_type)

        if key in self._index:
            rel_id = self._index[key]
            existing = self._relationships[rel_id]

            sources = set(existing.originating_sources)
            sources.add(originating_source)

            new_confidence = max(existing.confidence, confidence)
            merged_meta = dict(existing.metadata)
            if metadata:
                merged_meta.update(metadata)

            updated = existing.with_updated(
                confidence=new_confidence,
                originating_sources=tuple(sorted(sources)),
                metadata=merged_meta,
            )
            self._relationships[rel_id] = updated
            return updated

        new_rel = CanonicalRelationship.create(
            source_canonical_uuid=source_canonical_uuid,
            target_canonical_uuid=target_canonical_uuid,
            relationship_type=rel_type,
            originating_source=originating_source,
            confidence=confidence,
            version=version,
            metadata=metadata,
        )
        self._relationships[new_rel.relationship_id] = new_rel
        self._index[key] = new_rel.relationship_id
        return new_rel

    def get_relationship(self, relationship_id: str) -> Optional[CanonicalRelationship]:
        return self._relationships.get(relationship_id)

    def find_relationships(
        self,
        canonical_uuid: str,
        direction: str = "both",
        relationship_type: Optional[str] = None,
    ) -> List[CanonicalRelationship]:
        """
        Finds relationships for a canonical entity.
        direction can be 'source', 'target', or 'both'.
        """
        results = []
        rel_type = relationship_type.upper() if relationship_type else None

        for rel in self._relationships.values():
            if rel_type and rel.relationship_type != rel_type:
                continue

            match = False
            if direction in ("source", "both") and rel.source_canonical_uuid == canonical_uuid:
                match = True
            if direction in ("target", "both") and rel.target_canonical_uuid == canonical_uuid:
                match = True

            if match:
                results.append(rel)

        return results

    def list_all(self) -> List[CanonicalRelationship]:
        return list(self._relationships.values())
