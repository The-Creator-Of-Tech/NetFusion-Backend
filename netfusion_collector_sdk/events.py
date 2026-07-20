import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BaseCollectorEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    execution_id: str = ""
    collector_id: str = ""
    event_type: str = "BaseCollectorEvent"


@dataclass
class CollectorStartedEvent(BaseCollectorEvent):
    event_type: str = "CollectorStartedEvent"
    config_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProgressEvent(BaseCollectorEvent):
    event_type: str = "ProgressEvent"
    current: int = 0
    total: int = 0
    percent: float = 0.0
    message: str = ""


@dataclass
class CanonicalObjectEvent(BaseCollectorEvent):
    event_type: str = "CanonicalObjectEvent"
    canonical_object: Any = None


@dataclass
class CompletedEvent(BaseCollectorEvent):
    event_type: str = "CompletedEvent"
    metrics_summary: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0


@dataclass
class FailureEvent(BaseCollectorEvent):
    event_type: str = "FailureEvent"
    error_type: str = "Exception"
    error_message: str = ""
    stack_trace: Optional[str] = None


class EventPublisher:
    """Event bus publisher facade for collector lifecycle and canonical data events."""

    def __init__(self, listener_callback: Optional[Any] = None):
        self.published_events: List[BaseCollectorEvent] = []
        self.listener_callback = listener_callback

    def _publish(self, event: BaseCollectorEvent) -> None:
        self.published_events.append(event)
        if self.listener_callback:
            try:
                self.listener_callback(event)
            except Exception:
                pass

    def publish_started(self, execution_id: str, collector_id: str, config_summary: Dict[str, Any]) -> CollectorStartedEvent:
        event = CollectorStartedEvent(
            execution_id=execution_id,
            collector_id=collector_id,
            config_summary=config_summary,
        )
        self._publish(event)
        return event

    def publish_progress(
        self, execution_id: str, collector_id: str, current: int, total: int, percent: float, message: str = ""
    ) -> ProgressEvent:
        event = ProgressEvent(
            execution_id=execution_id,
            collector_id=collector_id,
            current=current,
            total=total,
            percent=percent,
            message=message,
        )
        self._publish(event)
        return event

    def publish_canonical_object(
        self, execution_id: str, collector_id: str, canonical_object: Any
    ) -> CanonicalObjectEvent:
        event = CanonicalObjectEvent(
            execution_id=execution_id,
            collector_id=collector_id,
            canonical_object=canonical_object,
        )
        self._publish(event)
        return event

    def publish_completed(
        self, execution_id: str, collector_id: str, metrics_summary: Dict[str, Any], duration_seconds: float
    ) -> CompletedEvent:
        event = CompletedEvent(
            execution_id=execution_id,
            collector_id=collector_id,
            metrics_summary=metrics_summary,
            duration_seconds=duration_seconds,
        )
        self._publish(event)
        return event

    def publish_failure(
        self, execution_id: str, collector_id: str, error_type: str, error_message: str, stack_trace: Optional[str] = None
    ) -> FailureEvent:
        event = FailureEvent(
            execution_id=execution_id,
            collector_id=collector_id,
            error_type=error_type,
            error_message=error_message,
            stack_trace=stack_trace,
        )
        self._publish(event)
        return event
