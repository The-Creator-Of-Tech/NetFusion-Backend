"""
ATRE Events & Publisher — NetFusion IL-9
==========================================
Domain event definitions and event publishing system.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import time


@dataclass
class ReasoningStarted:
    investigation_id: str
    user_question: str
    question_type: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReasoningCompleted:
    investigation_id: str
    user_question: str
    hypotheses_count: int
    confidence_score: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class HypothesisGenerated:
    investigation_id: str
    hypothesis_id: str
    title: str
    confidence: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class EvidenceCollected:
    investigation_id: str
    evidence_count: int
    sources: List[str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConfidenceCalculated:
    investigation_id: str
    overall_confidence: float
    score_breakdown: Dict[str, float]
    timestamp: float = field(default_factory=time.time)


@dataclass
class AttackChainBuilt:
    investigation_id: str
    stage_count: int
    tactics: List[str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class RecommendationsGenerated:
    investigation_id: str
    recommendation_count: int
    categories: List[str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReportGenerated:
    investigation_id: str
    format: str
    section_count: int
    timestamp: float = field(default_factory=time.time)


class ReasoningEventPublisher:
    """
    Publish/Subscribe event dispatcher for ATRE events.
    """

    def __init__(self):
        self._handlers: Dict[type, List[Callable[[Any], None]]] = {}

    def subscribe(self, event_type: type, handler: Callable[[Any], None]) -> None:
        """Register a handler for a specific event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)


    def publish(self, event: Any) -> None:
        """Dispatch event to registered handlers."""
        event_type = type(event)
        if event_type in self._handlers:
            for handler in self._handlers[event_type]:
                try:
                    handler(event)
                except Exception:
                    pass


# XAI Trace Events (IL-9.1)
from netfusion_ai.reasoning.reasoning_trace import (
    TraceStarted,
    StageCompleted,
    DecisionRecorded,
    EvidenceRecorded,
    ConfidenceRecorded,
    RecommendationRecorded,
    TraceCompleted,
)

