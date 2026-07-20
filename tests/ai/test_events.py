"""
Tests for NetFusion AI Event Bus Publisher and Events.
"""

import pytest

from netfusion_ai import (
    AIEventPublisher,
    AIAnalysisStarted,
    AIAnalysisCompleted,
    AIRecommendationGenerated,
    AIHypothesisGenerated,
    AIReportGenerated,
    AIProviderFailure,
)


def test_ai_event_publisher():
    received_events = []

    def on_event(ev):
        received_events.append(ev)

    pub = AIEventPublisher(listener_callback=on_event)

    ev_start = AIAnalysisStarted(investigation_id="INV-E1", category="incident_summary")
    ev_comp = AIAnalysisCompleted(investigation_id="INV-E1", category="incident_summary", analysis_id="A-1")

    pub.publish(ev_start)
    pub.publish(ev_comp)

    assert len(received_events) == 2
    assert received_events[0].event_type == "AIAnalysisStarted"
    assert received_events[1].event_type == "AIAnalysisCompleted"
    assert len(pub.published_events) == 2
