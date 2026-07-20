import pytest
from netfusion_collector_sdk import CollectorContext, ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, SysmonConfig, CollectionMode


class TestSysmonIntegration:
    def test_full_pipeline_sysmon_integration(self):
        ctx = CollectorContext(collector_id="sysmon-int-test")
        collector = SysmonCollector(context=ctx)

        collector.configure({
            "collection_mode": CollectionMode.LIVE_EVENT_LOG,
            "event_ids": [1, 3, 5, 8, 11, 12, 13, 22, 25],
            "batch_size": 10,
        })

        mock_telemetry = [
            # Event 1: Process Create
            {"EventID": 1, "Computer": "INT-HOST", "ProcessId": 1000, "Image": "C:\\malware.exe", "CommandLine": "malware.exe --run"},
            # Event 3: Network Connection
            {"EventID": 3, "Computer": "INT-HOST", "ProcessId": 1000, "SourceIp": "192.168.1.50", "DestinationIp": "203.0.113.5", "DestinationPort": 8080},
            # Event 8: CreateRemoteThread
            {"EventID": 8, "Computer": "INT-HOST", "SourceProcessId": 1000, "SourceImage": "C:\\malware.exe", "TargetProcessId": 800, "TargetImage": "C:\\Windows\\System32\\svchost.exe"},
            # Event 22: DNS Query
            {"EventID": 22, "Computer": "INT-HOST", "ProcessId": 1000, "QueryName": "c2.badsite.org", "QueryResults": "203.0.113.5"},
            # Event 25: Process Tampering
            {"EventID": 25, "Computer": "INT-HOST", "ProcessId": 800, "Image": "C:\\Windows\\System32\\svchost.exe", "Type": "Hollowing"},
        ]

        collector.set_mock_input_events(mock_telemetry)

        result = collector.execute_collection()

        assert result.status == ExecutionState.COMPLETED
        assert result.packets_captured == 5
        assert result.objects_generated > 15
        assert result.dropped_packets == 0
