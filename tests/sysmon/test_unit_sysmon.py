import os
import tempfile
import pytest
from netfusion_collectors.sysmon.config import SysmonConfig, CollectionMode, EventSourceType, AuthMode, HashAlgorithm
from netfusion_collectors.sysmon.health import SysmonHealthChecker
from netfusion_collectors.sysmon.bookmark import BookmarkManager
from netfusion_collectors.sysmon.canonical import (
    ProcessObserved,
    NetworkConnectionObserved,
    FileObserved,
    RegistryObserved,
    DNSQueryObserved,
    EvidenceLineage,
)


class TestSysmonUnit:
    def test_config_defaults_and_validation(self):
        config = SysmonConfig()
        assert config.event_source == EventSourceType.WINDOWS_EVENT_LOG
        assert config.collection_mode == CollectionMode.LIVE_EVENT_LOG
        assert len(config.event_ids) == 23
        assert config.batch_size == 100
        assert config.auth_mode == AuthMode.DEFAULT

    def test_config_overrides(self):
        config = SysmonConfig(
            event_source=EventSourceType.EVTX_FILE,
            collection_mode=CollectionMode.OFFLINE_EVTX,
            evtx_file_path="/tmp/test.evtx",
            filter_process_name="cmd.exe",
            filter_hash_algorithm=HashAlgorithm.SHA256,
        )
        assert config.event_source == EventSourceType.EVTX_FILE
        assert config.collection_mode == CollectionMode.OFFLINE_EVTX
        assert config.evtx_file_path == "/tmp/test.evtx"
        assert config.filter_process_name == "cmd.exe"
        assert config.filter_hash_algorithm == HashAlgorithm.SHA256

    def test_health_checker_probes(self):
        checker = SysmonHealthChecker()
        report = checker.run_all(collector_id="test-sysmon")
        assert report.collector_type == "SysmonCollector"
        assert "win_eventlog_availability" in report.checks
        assert "evtx_parser_check" in report.checks
        assert "sysmon_channel_exists" in report.checks
        assert "required_permissions" in report.checks
        assert report.checks["evtx_parser_check"]["passed"] is True

    def test_bookmark_manager_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bm_path = os.path.join(tmp_dir, "sysmon_bookmark.json")
            bm = BookmarkManager(bm_path)
            assert bm.last_record_id == 0

            bm.update(105, "2026-07-20T12:00:00Z")
            bm.save()

            bm_loaded = BookmarkManager(bm_path)
            assert bm_loaded.last_record_id == 105
            assert bm_loaded.last_timestamp == "2026-07-20T12:00:00Z"

            bm_loaded.clear()
            assert bm_loaded.last_record_id == 0
            assert not os.path.exists(bm_path)

    def test_canonical_objects_instantiation(self):
        proc = ProcessObserved(
            pid=1234,
            process_guid="{12345678-1234-1234-1234-123456789012}",
            image_path="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c echo test",
            user="NT AUTHORITY\\SYSTEM",
            host="WORKSTATION01",
        )
        assert proc.canonical_type == "netfusion.canonical.endpoint.ProcessObserved"
        assert proc.collector_type == "SysmonCollector"
        assert proc.pid == 1234

        net = NetworkConnectionObserved(
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
        )
        assert net.canonical_type == "netfusion.canonical.endpoint.NetworkConnectionObserved"
        assert net.dst_port == 53

        dns = DNSQueryObserved(
            query_name="example.com",
            query_status="0",
            query_results=["93.184.216.34"],
        )
        assert dns.query_name == "example.com"
        assert dns.query_results == ["93.184.216.34"]
