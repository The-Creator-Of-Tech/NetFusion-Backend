"""
NetFusion Collector SDK Package
Enterprise collector execution framework, context models, and lifecycle runtime contracts.
"""

from .base import BaseCollector, CollectorContext, CollectionResult, ExecutionState
from .config import CollectorConfig, ConfigurationManager
from .logging import LoggingManager
from .metrics import MetricsManager
from .events import EventPublisher, CollectorStartedEvent, ProgressEvent, CanonicalObjectEvent, CompletedEvent, FailureEvent
from .subprocess_runner import SubprocessRunner
from .health import HealthManager, HealthReport, HealthStatus
from .testing import MockCollectorRuntimeHost, FakeCollectorEventBus

__all__ = [
    "BaseCollector",
    "CollectorContext",
    "CollectionResult",
    "ExecutionState",
    "CollectorConfig",
    "ConfigurationManager",
    "LoggingManager",
    "MetricsManager",
    "EventPublisher",
    "CollectorStartedEvent",
    "ProgressEvent",
    "CanonicalObjectEvent",
    "CompletedEvent",
    "FailureEvent",
    "SubprocessRunner",
    "HealthManager",
    "HealthReport",
    "HealthStatus",
    "MockCollectorRuntimeHost",
    "FakeCollectorEventBus",
]
