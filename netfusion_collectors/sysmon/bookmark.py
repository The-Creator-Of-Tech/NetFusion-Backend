import json
import os
import time
from typing import Any, Dict, Optional


class BookmarkManager:
    """
    Manages persistent state for Sysmon incremental collection mode.
    Reads and writes bookmark JSON files tracking high-watermark record IDs and timestamps.
    """

    def __init__(self, bookmark_path: Optional[str] = None):
        self.bookmark_path = bookmark_path
        self.last_record_id: int = 0
        self.last_timestamp: str = ""
        self.total_processed: int = 0
        if self.bookmark_path and os.path.exists(self.bookmark_path):
            self.load()

    def load(self) -> Dict[str, Any]:
        if not self.bookmark_path or not os.path.exists(self.bookmark_path):
            return {}
        try:
            with open(self.bookmark_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.last_record_id = int(data.get("last_record_id", 0))
                self.last_timestamp = str(data.get("last_timestamp", ""))
                self.total_processed = int(data.get("total_processed", 0))
                return data
        except Exception:
            return {}

    def update(self, record_id: int, timestamp: Optional[str] = None) -> None:
        if record_id > self.last_record_id:
            self.last_record_id = record_id
        if timestamp:
            self.last_timestamp = timestamp
        self.total_processed += 1

    def save(self) -> bool:
        if not self.bookmark_path:
            return False
        try:
            dir_path = os.path.dirname(self.bookmark_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            data = {
                "last_record_id": self.last_record_id,
                "last_timestamp": self.last_timestamp,
                "total_processed": self.total_processed,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            with open(self.bookmark_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def clear(self) -> None:
        self.last_record_id = 0
        self.last_timestamp = ""
        self.total_processed = 0
        if self.bookmark_path and os.path.exists(self.bookmark_path):
            try:
                os.remove(self.bookmark_path)
            except Exception:
                pass
