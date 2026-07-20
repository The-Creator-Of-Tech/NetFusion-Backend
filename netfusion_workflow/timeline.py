"""
NetFusion Timeline Engine
Automated timeline aggregation, sorting, filtering, grouping, and full-text searching
across collector events, canonical objects, notes, tasks, evidence, status changes, and AI findings.
"""

from datetime import datetime
import time
from typing import Any, Dict, List, Optional, Union

from .domain import TimelineEvent
from .enums import Severity


class TimelineEngine:
    """Engine responsible for timeline event creation, indexing, sorting, filtering, and grouping."""

    def __init__(self, events: Optional[List[TimelineEvent]] = None):
        self.events: List[TimelineEvent] = events if events is not None else []

    def add_event(self, event: TimelineEvent) -> None:
        """Adds a single timeline event."""
        self.events.append(event)

    def add_events(self, events: List[TimelineEvent]) -> None:
        """Adds multiple timeline events."""
        self.events.extend(events)

    def create_event(
        self,
        summary: str,
        investigation_id: str = "",
        event_type: str = "MANUAL_EVENT",
        source: str = "SYSTEM",
        severity: Severity = Severity.INFORMATIONAL,
        actor: str = "system",
        description: str = "",
        raw_data: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        related_entity_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        """Constructs and registers a new TimelineEvent."""
        event = TimelineEvent(
            summary=summary,
            investigation_id=investigation_id,
            timestamp=timestamp if timestamp is not None else time.time(),
            event_type=event_type,
            source=source,
            severity=severity,
            actor=actor,
            description=description,
            raw_data=raw_data or {},
            tags=tags or [],
            related_entity_id=related_entity_id,
        )
        self.add_event(event)
        return event

    def sort(self, ascending: bool = True) -> List[TimelineEvent]:
        """Sorts timeline events by timestamp."""
        self.events.sort(key=lambda e: e.timestamp, reverse=not ascending)
        return self.events

    def filter(
        self,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[Union[Severity, str]] = None,
        actor: Optional[str] = None,
        tag: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[TimelineEvent]:
        """Filters timeline events based on multi-attribute criteria."""
        filtered = self.events

        if event_type:
            filtered = [e for e in filtered if e.event_type.upper() == event_type.upper()]
        if source:
            filtered = [e for e in filtered if source.lower() in e.source.lower()]
        if severity:
            sev_val = severity.value if isinstance(severity, Severity) else str(severity)
            filtered = [
                e for e in filtered
                if (e.severity.value if isinstance(e.severity, Severity) else str(e.severity)).upper() == sev_val.upper()
            ]
        if actor:
            filtered = [e for e in filtered if actor.lower() in e.actor.lower()]
        if tag:
            filtered = [e for e in filtered if tag in e.tags]
        if start_time is not None:
            filtered = [e for e in filtered if e.timestamp >= start_time]
        if end_time is not None:
            filtered = [e for e in filtered if e.timestamp <= end_time]

        return filtered

    def group_by(self, key: str = "event_type") -> Dict[str, List[TimelineEvent]]:
        """
        Groups timeline events by a specific field:
        'event_type', 'source', 'actor', 'severity', or 'date' (YYYY-MM-DD).
        """
        groups: Dict[str, List[TimelineEvent]] = {}
        for event in self.events:
            group_key = "UNKNOWN"
            if key == "event_type":
                group_key = event.event_type
            elif key == "source":
                group_key = event.source
            elif key == "actor":
                group_key = event.actor
            elif key == "severity":
                group_key = event.severity.value if isinstance(event.severity, Severity) else str(event.severity)
            elif key == "date":
                group_key = datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d")
            else:
                group_key = str(getattr(event, key, "UNKNOWN"))

            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(event)
        return groups

    def search(self, query: str) -> List[TimelineEvent]:
        """Performs full-text keyword search across summary, description, actor, source, and raw_data."""
        if not query or not query.strip():
            return self.events

        q = query.lower().strip()
        results: List[TimelineEvent] = []

        for event in self.events:
            match = False
            if q in event.summary.lower():
                match = True
            elif q in event.description.lower():
                match = True
            elif q in event.actor.lower():
                match = True
            elif q in event.source.lower():
                match = True
            elif any(q in str(val).lower() for val in event.raw_data.values()):
                match = True
            elif any(q in t.lower() for t in event.tags):
                match = True

            if match:
                results.append(event)

        return results
