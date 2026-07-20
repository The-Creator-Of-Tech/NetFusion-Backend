"""
Domain Event System and EventBus for netfusion_intelligence.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import threading
from typing import Any, Callable, Dict, List, Type


@dataclass
class DomainEvent:
    """Base domain event class."""
    event_id: str = field(default_factory=lambda: str(__import__("uuid").uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def event_type(self) -> str:
        return self.__class__.__name__

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["event_type"] = self.event_type()
        return data


@dataclass
class FeedRegistered(DomainEvent):
    feed_id: str = ""
    feed_name: str = ""


@dataclass
class FeedStarted(DomainEvent):
    feed_id: str = ""
    import_id: str = ""


@dataclass
class FeedCompleted(DomainEvent):
    feed_id: str = ""
    import_id: str = ""
    version_id: str = ""
    duration_seconds: float = 0.0
    records_count: int = 0


@dataclass
class FeedFailed(DomainEvent):
    feed_id: str = ""
    import_id: str = ""
    error_message: str = ""


@dataclass
class ValidationPassed(DomainEvent):
    feed_id: str = ""
    version_id: str = ""
    total_checked: int = 0


@dataclass
class ValidationFailed(DomainEvent):
    feed_id: str = ""
    version_id: str = ""
    errors_count: int = 0
    error_details: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DatasetActivated(DomainEvent):
    feed_id: str = ""
    version_id: str = ""


@dataclass
class DatasetRolledBack(DomainEvent):
    feed_id: str = ""
    rolled_back_version_id: str = ""
    restored_version_id: str = ""


@dataclass
class SchedulerStarted(DomainEvent):
    active_feeds_count: int = 0


@dataclass
class SchedulerStopped(DomainEvent):
    reason: str = "Normal Shutdown"


# -------------------------------------------------------------------------
# Security & Trust Verification Domain Events
# -------------------------------------------------------------------------

@dataclass
class TrustVerified(DomainEvent):
    feed_id: str = ""
    overall_trust: str = "TRUSTED"
    trust_score: float = 100.0
    publisher: str = ""


@dataclass
class TrustFailed(DomainEvent):
    feed_id: str = ""
    overall_trust: str = "BLOCKED"
    reason: str = ""


@dataclass
class SignatureVerified(DomainEvent):
    feed_id: str = ""
    algorithm: str = "GPG"
    verified: bool = True


@dataclass
class ChecksumVerified(DomainEvent):
    feed_id: str = ""
    algorithm: str = "SHA256"
    checksum: str = ""


@dataclass
class CertificateValidated(DomainEvent):
    feed_id: str = ""
    hostname: str = ""
    status: str = "VALID"



class EventBus:
    """
    Thread-safe Domain Event Bus.
    Supports subscribing listeners to specific event types or all events.
    """

    def __init__(self):
        self._listeners: Dict[Type[DomainEvent], List[Callable[[DomainEvent], None]]] = {}
        self._global_listeners: List[Callable[[DomainEvent], None]] = []
        self._event_history: List[DomainEvent] = []
        self._lock = threading.Lock()

    def subscribe(self, event_type: Type[DomainEvent], listener: Callable[[DomainEvent], None]) -> None:
        """Subscribe to a specific domain event type."""
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            self._listeners[event_type].append(listener)

    def subscribe_all(self, listener: Callable[[DomainEvent], None]) -> None:
        """Subscribe to all domain events."""
        with self._lock:
            self._global_listeners.append(listener)

    def publish(self, event: DomainEvent) -> None:
        """Publish a domain event to all subscribers."""
        with self._lock:
            self._event_history.append(event)
            listeners = list(self._listeners.get(type(event), []))
            globals_copy = list(self._global_listeners)

        for listener in listeners:
            try:
                listener(event)
            except Exception as e:
                # Event handlers should not throw back to publisher
                pass

        for listener in globals_copy:
            try:
                listener(event)
            except Exception as e:
                pass

    def get_history(self, event_type: Optional[Type[DomainEvent]] = None) -> List[DomainEvent]:
        """Returns recorded event history."""
        with self._lock:
            if event_type:
                return [e for e in self._event_history if isinstance(e, event_type)]
            return list(self._event_history)

    def clear(self) -> None:
        """Clear listeners and event history."""
        with self._lock:
            self._listeners.clear()
            self._global_listeners.clear()
            self._event_history.clear()
