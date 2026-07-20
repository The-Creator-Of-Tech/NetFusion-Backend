import os
import tempfile
import pytest
from netfusion_collector_sdk import ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, EventSourceType, CollectionMode


class TestOfflineEVTX:
    def test_offline_evtx_file_mode(self):
        sample_xml_log = """
        <Events>
          <Event>
            <System>
              <EventID>11</EventID>
              <Computer>OFFLINE-HOST</Computer>
              <TimeCreated SystemTime="2026-07-20T10:00:00Z"/>
              <EventRecordID>9001</EventRecordID>
            </System>
            <EventData>
              <Data Name="ProcessId">2020</Data>
              <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
              <Data Name="TargetFilename">C:\\Users\\User\\Desktop\\notes.txt</Data>
              <Data Name="User">OFFLINE-HOST\\User</Data>
            </EventData>
          </Event>
        </Events>
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(sample_xml_log)
            tmp_path = f.name

        try:
            collector = SysmonCollector()
            collector.configure({
                "event_source": EventSourceType.EVTX_FILE,
                "collection_mode": CollectionMode.OFFLINE_EVTX,
                "evtx_file_path": tmp_path,
            })

            result = collector.execute_collection()
            assert result.status == ExecutionState.COMPLETED
            assert result.packets_captured == 1
            assert result.objects_generated >= 2
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_missing_evtx_file_raises_error(self):
        collector = SysmonCollector()
        collector.configure({
            "event_source": EventSourceType.EVTX_FILE,
            "collection_mode": CollectionMode.OFFLINE_EVTX,
            "evtx_file_path": "/nonexistent/path/sysmon.evtx",
        })

        with pytest.raises(FileNotFoundError):
            collector.execute_collection()
