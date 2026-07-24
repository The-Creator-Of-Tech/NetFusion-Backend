"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Events

Event definitions and EventBus implementation for investigation lifecycle notifications.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Any, Callable, Dict, List, Optional


@dataclass
class InvestigationEvent:
    event_id: str
    event_type: str = "InvestigationEvent"
    investigation_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


@dataclass
class InvestigationCreated(InvestigationEvent):
    event_type: str = "InvestigationCreated"


@dataclass
class InvestigationUpdated(InvestigationEvent):
    event_type: str = "InvestigationUpdated"


@dataclass
class InvestigationClosed(InvestigationEvent):
    event_type: str = "InvestigationClosed"


@dataclass
class SnapshotCreated(InvestigationEvent):
    event_type: str = "SnapshotCreated"


@dataclass
class ReplayStarted(InvestigationEvent):
    event_type: str = "ReplayStarted"


@dataclass
class ReplayCompleted(InvestigationEvent):
    event_type: str = "ReplayCompleted"


@dataclass
class ComparisonCompleted(InvestigationEvent):
    event_type: str = "ComparisonCompleted"


@dataclass
class ArtifactAdded(InvestigationEvent):
    event_type: str = "ArtifactAdded"


@dataclass
class SessionMerged(InvestigationEvent):
    event_type: str = "SessionMerged"


class EventBus:
    """Thread-safe event publishing and subscription system."""

    def __init__(self):
        self._listeners: Dict[str, List[Callable[[InvestigationEvent], None]]] = {}
        self._global_listeners: List[Callable[[InvestigationEvent], None]] = []
        self._history: List[InvestigationEvent] = []
        self._lock = threading.RLock()

    def subscribe(self, event_type: str, callback: Callable[[InvestigationEvent], None]) -> None:
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            if callback not in self._listeners[event_type]:
                self._listeners[event_type].append(callback)

    def subscribe_all(self, callback: Callable[[InvestigationEvent], None]) -> None:
        with self._lock:
            if callback not in self._global_listeners:
                self._global_listeners.append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[InvestigationEvent], None]) -> None:
        with self._lock:
            if event_type in self._listeners and callback in self._listeners[event_type]:
                self._listeners[event_type].remove(callback)

    def publish(self, event: InvestigationEvent) -> None:
        with self._lock:
            self._history.append(event)
            listeners = list(self._listeners.get(event.event_type, []))
            globals_ = list(self._global_listeners)

        for listener in listeners:
            try:
                listener(event)
            except Exception:
                pass

        for g_listener in globals_:
            try:
                g_listener(event)
            except Exception:
                pass

    def get_history(self, investigation_id: Optional[str] = None, event_type: Optional[str] = None) -> List[InvestigationEvent]:
        with self._lock:
            res = list(self._history)
            if investigation_id:
                res = [e for e in res if e.investigation_id == investigation_id]
            if event_type:
                res = [e for e in res if e.event_type == event_type]
            return res

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
            self._listeners.clear()
            self._global_listeners.clear()
