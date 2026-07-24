"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Persistence Layer

File-backed and SQLite persistence for investigations, snapshots, activities, sessions, and links.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from netfusion_investigation.lifecycle.models import Investigation


class FilePersistence:
    """Manages file-based JSON persistence of investigation records."""

    def __init__(self, storage_dir: Optional[str] = None):
        self._storage_dir = storage_dir or os.path.join(os.getcwd(), "data", "investigations")
        os.makedirs(self._storage_dir, exist_ok=True)
        self._lock = threading.RLock()

    def _get_file_path(self, investigation_id: str) -> str:
        return os.path.join(self._storage_dir, f"{investigation_id}.json")

    def save(self, investigation: Investigation) -> str:
        with self._lock:
            path = self._get_file_path(investigation.id)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(investigation.to_dict(), f, indent=2)
            return path

    def load(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            path = self._get_file_path(investigation_id)
            if not os.path.exists(path):
                return None
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return Investigation.from_dict(data)
            except Exception:
                return None

    def delete(self, investigation_id: str) -> bool:
        with self._lock:
            path = self._get_file_path(investigation_id)
            if os.path.exists(path):
                try:
                    os.remove(path)
                    return True
                except OSError:
                    pass
            return False

    def list_all(self) -> List[Investigation]:
        with self._lock:
            res = []
            if not os.path.exists(self._storage_dir):
                return res
            for filename in os.listdir(self._storage_dir):
                if filename.endswith(".json"):
                    inv_id = filename[:-5]
                    inv = self.load(inv_id)
                    if inv:
                        res.append(inv)
            return res
