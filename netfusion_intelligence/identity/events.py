"""
Identity Domain Events and Publisher for NetFusion CIIL.
Defines canonical identity events and pub-sub mechanism.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import uuid


@dataclass(frozen=True)
class IdentityDomainEvent:
    """Base identity domain event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.__class__.__name__,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class CanonicalEntityCreated(IdentityDomainEvent):
    """Event fired when a new canonical entity is created."""
    canonical_uuid: str = ""
    entity_type: str = ""
    display_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "canonical_uuid": self.canonical_uuid,
            "entity_type": self.entity_type,
            "display_name": self.display_name,
        })
        return base


@dataclass(frozen=True)
class CanonicalEntityMerged(IdentityDomainEvent):
    """Event fired when two canonical entities are merged."""
    target_canonical_uuid: str = ""
    merged_canonical_uuid: str = ""
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "target_canonical_uuid": self.target_canonical_uuid,
            "merged_canonical_uuid": self.merged_canonical_uuid,
            "reason": self.reason,
        })
        return base


@dataclass(frozen=True)
class ExternalIdentifierAdded(IdentityDomainEvent):
    """Event fired when an external identifier is attached to a canonical entity."""
    canonical_uuid: str = ""
    source: str = ""
    identifier: str = ""
    identifier_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "canonical_uuid": self.canonical_uuid,
            "source": self.source,
            "identifier": self.identifier,
            "identifier_type": self.identifier_type,
        })
        return base


@dataclass(frozen=True)
class RelationshipLinked(IdentityDomainEvent):
    """Event fired when a relationship is established or updated."""
    relationship_id: str = ""
    source_canonical_uuid: str = ""
    target_canonical_uuid: str = ""
    relationship_type: str = ""
    originating_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "relationship_id": self.relationship_id,
            "source_canonical_uuid": self.source_canonical_uuid,
            "target_canonical_uuid": self.target_canonical_uuid,
            "relationship_type": self.relationship_type,
            "originating_source": self.originating_source,
        })
        return base


@dataclass(frozen=True)
class IdentityResolved(IdentityDomainEvent):
    """Event fired when an identity resolution process completes."""
    canonical_uuid: str = ""
    is_new: bool = False
    source: str = ""
    identifier: str = ""

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "canonical_uuid": self.canonical_uuid,
            "is_new": self.is_new,
            "source": self.source,
            "identifier": self.identifier,
        })
        return base


class IdentityEventPublisher:
    """
    Publisher and subscriber bus for identity events.
    """

    def __init__(self):
        self._subscribers: List[Callable[[IdentityDomainEvent], None]] = []
        self._event_history: List[IdentityDomainEvent] = []

    def subscribe(self, handler: Callable[[IdentityDomainEvent], None]) -> None:
        if handler not in self._subscribers:
            self._subscribers.append(handler)

    def publish(self, event: IdentityDomainEvent) -> None:
        self._event_history.append(event)
        for handler in list(self._subscribers):
            try:
                handler(event)
            except Exception:
                pass  # Event handlers must not fail identity resolution

    def get_history(self) -> List[IdentityDomainEvent]:
        return list(self._event_history)

    def clear(self) -> None:
        self._event_history.clear()
