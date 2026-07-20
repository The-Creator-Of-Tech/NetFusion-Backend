import pytest
from netfusion_collector_sdk import CollectorContext, ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, CollectionMode


class TestFailureResiliency:
    def test_invalid_event_payload_resiliency(self):
        # Mixed valid and malformed events
        mock_events = [
            {"EventID": 1, "Computer": "H1", "ProcessId": 100, "Image": "good.exe"},
            "INVALID_XML_STRING_NON_PARSEABLE",
            {"EventID": 3, "Computer": "H1", "ProcessId": 100, "DestinationIp": "1.1.1.1"},
        ]

        collector = SysmonCollector()
        collector.configure({"collection_mode": CollectionMode.LIVE_EVENT_LOG})
        collector.set_mock_input_events(mock_events)

        result = collector.execute_collection()

        assert result.status == ExecutionState.COMPLETED
        assert result.packets_captured == 2  # Standardized valid events
        assert result.objects_generated >= 4

    def test_uninitialized_runner_raises(self):
        collector = SysmonCollector()
        with pytest.raises(RuntimeError):
            collector.execute_collection()
