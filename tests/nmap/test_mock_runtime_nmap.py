import pytest
from unittest.mock import MagicMock
from netfusion_collector_sdk import CollectorContext, EventPublisher, MetricsManager, ExecutionState
from netfusion_canonical import NormalizationPipeline, DeadLetterQueue, CanonicalValidator
from netfusion_collectors.nmap import NmapCollector, NmapConfig
from .test_xml_parsing import SAMPLE_NMAP_XML


def test_mock_runtime_integration():
    context = CollectorContext(collector_id="mock-coll", execution_id="mock-exec")
    collector = NmapCollector(context=context)

    publisher = EventPublisher()
    dlq = DeadLetterQueue()
    pipeline = NormalizationPipeline(dlq=dlq)
    metrics = MetricsManager(collector_id=context.collector_id, execution_id=context.execution_id)

    collector.initialize_runtime(
        logger=MagicMock(),
        metrics=metrics,
        event_publisher=publisher,
        pipeline=pipeline,
    )

    collector.configure({"targets": ["192.168.1.50"]})

    # Mock runner execute method
    collector.runner.execute = MagicMock(return_value=(0, SAMPLE_NMAP_XML, ""))

    collector.on_pre_execute()
    result = collector.execute_collection()
    collector.on_post_execute(result)
    collector.on_cleanup()

    assert result.status == ExecutionState.COMPLETED
    assert result.packets_captured == 1
    assert result.objects_generated > 0

    # Event publisher assertions
    event_types = [e.event_type for e in publisher.published_events]
    assert "CollectorStartedEvent" in event_types
    assert "CanonicalObjectEvent" in event_types
    assert "CompletedEvent" in event_types

    # DLQ assertions
    assert len(dlq.messages) == 0
