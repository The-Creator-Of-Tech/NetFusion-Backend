import pytest
from netfusion_collector_sdk import CollectorContext, ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, SysmonConfig, CollectionMode, EventSourceType


class TestLiveEventLog:
    def test_live_event_log_mode_configuration(self):
        config = {
            "event_source": EventSourceType.WINDOWS_EVENT_LOG,
            "collection_mode": CollectionMode.LIVE_EVENT_LOG,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "batch_size": 25,
            "poll_interval": 0.5,
        }
        collector = SysmonCollector()
        collector.configure(config)

        assert collector.sysmon_config.event_source == EventSourceType.WINDOWS_EVENT_LOG
        assert collector.sysmon_config.collection_mode == CollectionMode.LIVE_EVENT_LOG
        assert collector.sysmon_config.channel == "Microsoft-Windows-Sysmon/Operational"

    def test_simulated_live_ingestion(self):
        mock_events = [
            {
                "EventID": 1,
                "Computer": "LIVE-HOST-01",
                "User": "NT AUTHORITY\\SYSTEM",
                "ProcessId": 1010,
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "CommandLine": "svchost.exe -k netsvcs",
                "EventRecordID": 5001,
            },
            {
                "EventID": 3,
                "Computer": "LIVE-HOST-01",
                "User": "NT AUTHORITY\\SYSTEM",
                "ProcessId": 1010,
                "SourceIp": "10.0.0.1",
                "DestinationIp": "10.0.0.254",
                "DestinationPort": 53,
                "EventRecordID": 5002,
            },
        ]

        collector = SysmonCollector()
        collector.configure({"collection_mode": CollectionMode.LIVE_EVENT_LOG})
        collector.set_mock_input_events(mock_events)

        result = collector.execute_collection()

        assert result.status == ExecutionState.COMPLETED
        assert result.packets_captured == 2
        assert len(result.emitted_objects) >= 4
        assert result.metadata["events_processed"] == 2
