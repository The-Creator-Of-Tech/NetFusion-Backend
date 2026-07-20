import pytest
from netfusion_collector_sdk import CollectorContext, ExecutionState
from netfusion_collector_sdk.logging import LoggingManager
from netfusion_collector_sdk.metrics import MetricsManager
from netfusion_collector_sdk.events import EventPublisher
from netfusion_canonical.pipeline import NormalizationPipeline
from netfusion_collectors.sysmon import SysmonCollector, CollectionMode


class TestMockRuntimeSysmon:
    def test_mock_runtime_integration(self):
        context = CollectorContext(
            collector_id="sysmon-col-001",
            execution_id="exec-sysmon-999",
            investigation_id="inv-sysmon-101",
        )

        logger = LoggingManager(
            name="sysmon_test",
            collector_id=context.collector_id,
            execution_id=context.execution_id,
        )
        metrics = MetricsManager(
            collector_id=context.collector_id,
            execution_id=context.execution_id,
        )
        event_pub = EventPublisher()
        pipeline = NormalizationPipeline()

        collector = SysmonCollector(context=context)
        collector.initialize_runtime(
            logger=logger,
            metrics=metrics,
            event_publisher=event_pub,
            pipeline=pipeline,
        )
        collector.configure({"collection_mode": CollectionMode.LIVE_EVENT_LOG})

        mock_events = [
            {
                "EventID": 1,
                "Computer": "HOST-TEST",
                "User": "NT AUTHORITY\\SYSTEM",
                "ProcessId": 4040,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c echo hello",
            }
        ]
        collector.set_mock_input_events(mock_events)

        result = collector.execute_collection()

        assert result.status == ExecutionState.COMPLETED
        assert result.packets_captured == 1
        assert result.objects_generated >= 4

        # Check event publisher received lifecycle events
        event_types = [e.event_type for e in event_pub.published_events]
        assert "CollectorStartedEvent" in event_types
        assert "CanonicalObjectEvent" in event_types
        assert "CompletedEvent" in event_types

        # Check metrics summary
        summary = metrics.get_summary()
        assert summary["packets_captured"] == 1
        assert summary["objects_generated"] >= 4
