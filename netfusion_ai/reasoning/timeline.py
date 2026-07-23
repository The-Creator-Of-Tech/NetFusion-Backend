"""
ATRE Timeline Engine — NetFusion IL-9
======================================
Chronological timeline merger consolidating 7 security event types:
Packets, Flows, Alerts, Logs, IOC Sightings, Workflow Events, and Investigation Events.
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.reasoning.graph_reasoner import TimelineBuilder
from netfusion_ai.reasoning.models import GraphEvidence, Timeline


class TimelineEngine:
    """
    Unified Timeline Engine merging multi-source security telemetry into chronological investigation sequence.
    """

    def __init__(self):
        self.builder = TimelineBuilder()

    def build_timeline(
        self,
        evidence: List[GraphEvidence],
        extra_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Timeline:
        timeline = self.builder.build_timeline(evidence, extra_events)
        # Ensure chronological sorting
        timeline.events.sort(key=lambda e: e.timestamp)
        return timeline
