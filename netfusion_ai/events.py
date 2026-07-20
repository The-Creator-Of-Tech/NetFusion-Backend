"""
NetFusion AI Events & Event Publisher
Defines AI-specific lifecycle events and subscriber event bus publisher.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AIEvent:
    """Base event for all AI Assistant operations."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "AIEvent"
    investigation_id: str = ""
    actor: str = "ai_assistant"


@dataclass
class AIAnalysisStarted(AIEvent):
    """Fired when an AI analysis job is initiated."""
    event_type: str = "AIAnalysisStarted"
    category: str = ""
    provider_name: str = ""


@dataclass
class AIAnalysisCompleted(AIEvent):
    """Fired when an AI analysis job completes successfully."""
    event_type: str = "AIAnalysisCompleted"
    category: str = ""
    analysis_id: str = ""
    confidence_score: float = 1.0


@dataclass
class AIRecommendationGenerated(AIEvent):
    """Fired when security recommendations are generated."""
    event_type: str = "AIRecommendationGenerated"
    recommendation_count: int = 0
    categories: List[str] = field(default_factory=list)


@dataclass
class AIHypothesisGenerated(AIEvent):
    """Fired when analyst hypotheses are generated."""
    event_type: str = "AIHypothesisGenerated"
    hypothesis_count: int = 0
    top_hypothesis_title: str = ""


@dataclass
class AIReportGenerated(AIEvent):
    """Fired when an AI investigation report is generated."""
    event_type: str = "AIReportGenerated"
    report_id: str = ""
    title: str = ""


@dataclass
class AIProviderFailure(AIEvent):
    """Fired when an AI Provider API call fails or triggers failover."""
    event_type: str = "AIProviderFailure"
    provider_name: str = ""
    error_message: str = ""
    fallback_provider: Optional[str] = None


class AIEventPublisher:
    """Event publisher for AI Assistant events."""

    def __init__(self, listener_callback: Optional[Callable[[AIEvent], None]] = None):
        self.listeners: List[Callable[[AIEvent], None]] = []
        if listener_callback:
            self.listeners.append(listener_callback)
        self.published_events: List[AIEvent] = []

    def subscribe(self, callback: Callable[[AIEvent], None]) -> None:
        """Subscribes an event listener callback."""
        if callback not in self.listeners:
            self.listeners.append(callback)

    def publish(self, event: AIEvent) -> None:
        """Publishes an AI event to all subscribers."""
        self.published_events.append(event)
        for listener in list(self.listeners):
            try:
                listener(event)
            except Exception:
                pass
