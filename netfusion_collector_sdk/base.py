import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import time


class ExecutionState(str, Enum):
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    STOPPED = "STOPPED"


@dataclass
class CollectorContext:
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collector_type: str = "BaseCollector"
    investigation_id: Optional[str] = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    temp_dir: str = "/tmp/netfusion"
    start_time: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionResult:
    execution_id: str
    collector_id: str
    status: ExecutionState
    packets_captured: int = 0
    packets_processed: int = 0
    flows_generated: int = 0
    objects_generated: int = 0
    dropped_packets: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    emitted_objects: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseCollector(ABC):
    """
    Abstract Base Class for all NetFusion Collectors.
    Enforces deterministic lifecycle, framework inversion of control, metrics, logging,
    and canonical object emission contracts.
    """

    def __init__(self, context: Optional[CollectorContext] = None):
        self.context: CollectorContext = context or CollectorContext()
        self.config: Dict[str, Any] = {}
        self.state: ExecutionState = ExecutionState.UNINITIALIZED
        self.logger = None
        self.metrics = None
        self.event_publisher = None
        self.pipeline = None

    def initialize_runtime(
        self,
        logger: Any = None,
        metrics: Any = None,
        event_publisher: Any = None,
        pipeline: Any = None,
    ) -> None:
        self.logger = logger
        self.metrics = metrics
        self.event_publisher = event_publisher
        self.pipeline = pipeline
        self.state = ExecutionState.READY

    def configure(self, config: Dict[str, Any]) -> None:
        self.validate_configuration(config)
        self.config = config
        self.on_configure(config)

    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate input configuration. Override in subclasses if needed."""
        return True

    def on_configure(self, config: Dict[str, Any]) -> None:
        """Hook called when collector configuration is supplied."""
        pass

    def on_pre_execute(self) -> None:
        """Hook called prior to collection execution."""
        pass

    @abstractmethod
    def execute_collection(self) -> CollectionResult:
        """Core collection routine. Subclasses MUST implement."""
        pass

    def on_post_execute(self, result: CollectionResult) -> None:
        """Hook called after collection execution completes."""
        pass

    def on_success(self, result: CollectionResult) -> None:
        """Hook called upon successful completion."""
        pass

    def on_failure(self, error: Exception) -> None:
        """Hook called upon collection failure."""
        pass

    def on_cancellation(self, reason: str) -> None:
        """Hook called when collection is cancelled."""
        pass

    def on_cleanup(self) -> None:
        """Hook called to release resources (files, sockets, subprocesses)."""
        pass

    def check_health(self) -> Dict[str, Any]:
        """Health check probe."""
        return {
            "status": "HEALTHY" if self.state not in (ExecutionState.FAILED, ExecutionState.STOPPED) else "UNHEALTHY",
            "state": self.state.value,
            "collector_id": self.context.collector_id,
            "collector_type": self.context.collector_type,
        }

    def emit_progress(self, current: int, total: int, message: str = "") -> None:
        if self.event_publisher:
            percent = (current / total * 100.0) if total > 0 else 0.0
            self.event_publisher.publish_progress(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                current=current,
                total=total,
                percent=percent,
                message=message,
            )

    def emit_canonical_object(self, canonical_obj: Any) -> bool:
        """
        Passes a canonical object through the normalization pipeline,
        validates it, and publishes it via EventPublisher.
        Returns True if passed validation and emitted, False if rejected to DLQ.
        """
        success = True
        if self.pipeline:
            success = self.pipeline.process_object(canonical_obj, self.context)

        if success:
            if self.event_publisher:
                self.event_publisher.publish_canonical_object(
                    execution_id=self.context.execution_id,
                    collector_id=self.context.collector_id,
                    canonical_object=canonical_obj,
                )
            if self.metrics:
                self.metrics.increment_objects_generated()
        return success
