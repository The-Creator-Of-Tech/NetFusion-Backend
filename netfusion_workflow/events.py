"""
NetFusion Workflow Events & Event Bus Integration
Defines canonical workflow lifecycle events and publishes them to subscribers or
the NetFusion Collector Event Bus.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .enums import CaseLifecycle, Priority, Severity


@dataclass
class WorkflowEvent:
    """Base event for all workflow activities."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "WorkflowEvent"
    actor: str = "system"


@dataclass
class CaseCreated(WorkflowEvent):
    """Fired when a new Case is created."""
    event_type: str = "CaseCreated"
    case_id: str = ""
    title: str = ""
    owner: str = ""
    priority: str = Priority.MEDIUM.value


@dataclass
class InvestigationStarted(WorkflowEvent):
    """Fired when an Investigation is initialized or started."""
    event_type: str = "InvestigationStarted"
    investigation_id: str = ""
    case_id: Optional[str] = None
    title: str = ""
    owner: str = ""
    priority: str = Priority.MEDIUM.value
    severity: str = Severity.MEDIUM.value


@dataclass
class InvestigationUpdated(WorkflowEvent):
    """Fired when investigation attributes, findings, or notes are updated."""
    event_type: str = "InvestigationUpdated"
    investigation_id: str = ""
    updated_fields: List[str] = field(default_factory=list)


@dataclass
class TaskAssigned(WorkflowEvent):
    """Fired when a task is assigned to an analyst."""
    event_type: str = "TaskAssigned"
    task_id: str = ""
    investigation_id: str = ""
    assignee: str = ""
    title: str = ""


@dataclass
class EvidenceAdded(WorkflowEvent):
    """Fired when digital evidence is added to an investigation."""
    event_type: str = "EvidenceAdded"
    evidence_id: str = ""
    investigation_id: str = ""
    name: str = ""
    source: str = ""
    hash_sha256: str = ""


@dataclass
class TimelineUpdated(WorkflowEvent):
    """Fired when new timeline events are appended to an investigation timeline."""
    event_type: str = "TimelineUpdated"
    investigation_id: str = ""
    timeline_event_id: str = ""
    summary: str = ""


@dataclass
class StatusChanged(WorkflowEvent):
    """Fired when a Case or Investigation lifecycle state changes."""
    event_type: str = "StatusChanged"
    entity_id: str = ""
    entity_type: str = "Investigation"
    old_status: str = ""
    new_status: str = ""
    reason: str = ""


@dataclass
class InvestigationClosed(WorkflowEvent):
    """Fired when an investigation is closed or marked false positive."""
    event_type: str = "InvestigationClosed"
    investigation_id: str = ""
    final_status: str = CaseLifecycle.CLOSED.value
    final_verdict: Optional[str] = None
    closed_time: float = field(default_factory=time.time)


class WorkflowEventPublisher:
    """Event publisher for workflow lifecycle notifications."""

    def __init__(self, listener_callback: Optional[Callable[[WorkflowEvent], None]] = None):
        self.listeners: List[Callable[[WorkflowEvent], None]] = []
        if listener_callback:
            self.listeners.append(listener_callback)
        self.published_events: List[WorkflowEvent] = []

    def subscribe(self, callback: Callable[[WorkflowEvent], None]) -> None:
        """Subscribes an event listener callback."""
        if callback not in self.listeners:
            self.listeners.append(callback)

    def publish(self, event: WorkflowEvent) -> None:
        """Publishes a workflow event to all subscribers."""
        self.published_events.append(event)
        for listener in self.listeners:
            try:
                listener(event)
            except Exception:
                pass
