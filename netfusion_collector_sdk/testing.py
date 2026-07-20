import time
from typing import Any, Dict, List, Type
from .base import BaseCollector, CollectorContext, CollectionResult, ExecutionState
from .events import EventPublisher, BaseCollectorEvent
from .logging import LoggingManager
from .metrics import MetricsManager


class FakeCollectorEventBus(EventPublisher):
    """In-memory event bus harness for unit and integration testing."""

    def __init__(self):
        super().__init__()
        self.events: List[BaseCollectorEvent] = self.published_events


class MockCollectorRuntimeHost:
    """
    Mock runtime host for executing BaseCollector instances in unit/integration tests
    without full platform infrastructure.
    """

    def __init__(self, collector_class: Type[BaseCollector], config: Dict[str, Any], context: Optional[CollectorContext] = None):
        self.collector_class = collector_class
        self.config = config
        self.context = context or CollectorContext(collector_type=collector_class.__name__)
        self.event_bus = FakeCollectorEventBus()
        self.logger = LoggingManager(
            name=f"test.{self.collector_class.__name__}",
            collector_id=self.context.collector_id,
            execution_id=self.context.execution_id,
        )
        self.metrics = MetricsManager(
            collector_id=self.context.collector_id,
            execution_id=self.context.execution_id,
        )
        self.collector: BaseCollector = self.collector_class(context=self.context)

    def execute(self, pipeline: Any = None) -> CollectionResult:
        self.collector.initialize_runtime(
            logger=self.logger,
            metrics=self.metrics,
            event_publisher=self.event_bus,
            pipeline=pipeline,
        )
        self.collector.configure(self.config)
        self.event_bus.publish_started(
            execution_id=self.context.execution_id,
            collector_id=self.context.collector_id,
            config_summary=self.config,
        )

        start_time = time.time()
        try:
            self.collector.state = ExecutionState.RUNNING
            self.collector.on_pre_execute()
            result = self.collector.execute_collection()
            self.collector.state = ExecutionState.COMPLETED
            self.collector.on_post_execute(result)
            self.collector.on_success(result)

            duration = time.time() - start_time
            result.duration_seconds = duration
            self.event_bus.publish_completed(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                metrics_summary=self.metrics.get_summary(),
                duration_seconds=duration,
            )
            return result

        except Exception as e:
            self.collector.state = ExecutionState.FAILED
            self.collector.on_failure(e)
            self.event_bus.publish_failure(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                error_type=type(e).__name__,
                error_message=str(e),
            )
            raise
        finally:
            self.collector.on_cleanup()
            if self.collector.state not in (ExecutionState.FAILED, ExecutionState.CANCELLED):
                self.collector.state = ExecutionState.STOPPED
