import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Generator
from .config import SysmonConfig, CollectionMode, EventSourceType
from .parsers.factory import SysmonParserFactory
from .bookmark import BookmarkManager


class SysmonEventRunner:
    """
    Execution runner for Sysmon event ingestion.
    Supports Live Windows Event Log querying, Offline EVTX parsing, Incremental bookmarking,
    Historical replay, and Streaming batch execution.
    """

    def __init__(self, config: SysmonConfig, bookmark_manager: Optional[BookmarkManager] = None):
        self.config = config
        self.bookmark_manager = bookmark_manager or BookmarkManager(config.bookmark_path if config.persist_bookmark else None)

    def fetch_events(self, mock_events: Optional[List[Union[Dict[str, Any], str]]] = None) -> List[Dict[str, Any]]:
        """
        Main execution entry point to fetch and parse events based on operational mode and config.
        """
        # If mock events provided (e.g. during testing or simulated runtime)
        if mock_events is not None:
            parser = SysmonParserFactory.get_parser("xml")
            parsed_raw = parser.parse(mock_events)
            return self._apply_incremental_and_bounds(parsed_raw)

        if self.config.collection_mode == CollectionMode.OFFLINE_EVTX or self.config.event_source == EventSourceType.EVTX_FILE:
            return self._fetch_offline_evtx()

        if self.config.collection_mode in (CollectionMode.LIVE_EVENT_LOG, CollectionMode.INCREMENTAL, CollectionMode.STREAMING):
            return self._fetch_live_event_log()

        if self.config.collection_mode == CollectionMode.HISTORICAL_REPLAY:
            if self.config.evtx_file_path:
                return self._fetch_offline_evtx()
            else:
                return self._fetch_live_event_log()

        return []

    def _fetch_offline_evtx(self) -> List[Dict[str, Any]]:
        file_path = self.config.evtx_file_path
        if not file_path or not os.path.exists(file_path):
            raise FileNotFoundError(f"Configured EVTX file not found: {file_path}")

        parser = SysmonParserFactory.get_parser("EVTX")
        parsed_events = parser.parse(file_path)
        return self._apply_incremental_and_bounds(parsed_events)

    def _fetch_live_event_log(self) -> List[Dict[str, Any]]:
        if sys.platform != "win32":
            # On non-Windows platforms, return empty or mock if evtx_file_path provided
            if self.config.evtx_file_path and os.path.exists(self.config.evtx_file_path):
                return self._fetch_offline_evtx()
            return []

        channel = self.config.channel
        max_events = self.config.max_events or 1000

        # Build wevtutil query command
        # e.g., wevtutil qe Microsoft-Windows-Sysmon/Operational /c:100 /rd:true /f:RenderedXml
        cmd = ["wevtutil", "qe", channel, f"/c:{max_events}", "/rd:true", "/f:RenderedXml"]

        if self.config.remote_server:
            cmd.extend(["/r:", self.config.remote_server])
            if self.config.username:
                cmd.extend(["/u:", self.config.username])
            if self.config.password:
                cmd.extend(["/p:", self.config.password])

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout,
            )
            if res.returncode != 0:
                raise RuntimeError(f"wevtutil event query failed: {res.stderr}")

            parser = SysmonParserFactory.get_parser("WIN_XML")
            events = parser.parse(res.stdout)
            return self._apply_incremental_and_bounds(events)

        except Exception:
            raise

    def _apply_incremental_and_bounds(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []

        last_id = self.bookmark_manager.last_record_id if self.config.persist_bookmark else 0

        for ev in events:
            rec_id = int(ev.get("EventRecordID") or 0)
            if self.config.collection_mode == CollectionMode.INCREMENTAL and rec_id > 0 and rec_id <= last_id:
                continue

            filtered.append(ev)

            if rec_id > 0 and self.config.persist_bookmark:
                self.bookmark_manager.update(rec_id, ev.get("TimeCreated"))

            if self.config.max_events and len(filtered) >= self.config.max_events:
                break

        if self.config.persist_bookmark:
            self.bookmark_manager.save()

        return filtered
