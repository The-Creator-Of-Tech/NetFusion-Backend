import os
import tempfile
import pytest
from netfusion_collector_sdk import ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, CollectionMode, BookmarkManager


class TestBookmarkPersistence:
    def test_incremental_mode_bookmark_filtering(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bm_file = os.path.join(tmp_dir, "sysmon_bookmark.json")

            events_batch1 = [
                {"EventID": 1, "Computer": "H1", "EventRecordID": 100, "Image": "proc1.exe"},
                {"EventID": 1, "Computer": "H1", "EventRecordID": 101, "Image": "proc2.exe"},
            ]

            events_batch2 = [
                {"EventID": 1, "Computer": "H1", "EventRecordID": 101, "Image": "proc2.exe"},
                {"EventID": 1, "Computer": "H1", "EventRecordID": 102, "Image": "proc3.exe"},
            ]

            # Run 1: process batch 1
            col1 = SysmonCollector()
            col1.configure({
                "collection_mode": CollectionMode.INCREMENTAL,
                "bookmark_path": bm_file,
                "persist_bookmark": True,
            })
            col1.set_mock_input_events(events_batch1)
            res1 = col1.execute_collection()

            assert res1.packets_captured == 2

            # Verify bookmark file contents
            bm = BookmarkManager(bm_file)
            assert bm.last_record_id == 101

            # Run 2: process batch 2 (should skip record_id 101 and process only 102)
            col2 = SysmonCollector()
            col2.configure({
                "collection_mode": CollectionMode.INCREMENTAL,
                "bookmark_path": bm_file,
                "persist_bookmark": True,
            })
            col2.set_mock_input_events(events_batch2)
            res2 = col2.execute_collection()

            assert res2.packets_captured == 1  # Only 102 ingested
            
            bm_final = BookmarkManager(bm_file)
            assert bm_final.last_record_id == 102
