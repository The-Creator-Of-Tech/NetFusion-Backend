"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Snapshot Engine

Provides point-in-time state capture, restoration, version history, rollback, and comparison of investigation snapshots.
"""

from datetime import datetime, timezone
import copy
import threading
from typing import Any, Dict, List, Optional, Tuple
import uuid

from netfusion_investigation.lifecycle.models import Investigation, InvestigationSnapshot


class SnapshotEngine:
    """Manages investigation snapshot versions and restoration."""

    def __init__(self):
        self._snapshots: Dict[str, List[InvestigationSnapshot]] = {}  # inv_id -> snapshots list
        self._lock = threading.RLock()

    def create_snapshot(
        self,
        investigation: Investigation,
        label: str = "Point-in-time Snapshot",
        created_by: str = "system",
        additional_state: Optional[Dict[str, Any]] = None,
    ) -> InvestigationSnapshot:
        with self._lock:
            inv_id = investigation.id
            if inv_id not in self._snapshots:
                self._snapshots[inv_id] = []

            version = len(self._snapshots[inv_id]) + 1
            state_dump = investigation.to_dict()
            if additional_state:
                state_dump["extra_state"] = copy.deepcopy(additional_state)

            snapshot = InvestigationSnapshot(
                id=f"snap-{uuid.uuid4().hex[:12]}",
                investigation_id=inv_id,
                version=version,
                label=label,
                created_at=datetime.now(timezone.utc).isoformat(),
                created_by=created_by,
                state_dump=state_dump,
            )
            self._snapshots[inv_id].append(snapshot)
            return snapshot

    def get_snapshot(self, snapshot_id: str) -> Optional[InvestigationSnapshot]:
        with self._lock:
            for snaps in self._snapshots.values():
                for s in snaps:
                    if s.id == snapshot_id:
                        return s
            return None

    def get_version_history(self, investigation_id: str) -> List[InvestigationSnapshot]:
        with self._lock:
            snaps = self._snapshots.get(investigation_id, [])
            return sorted(snaps, key=lambda x: x.version)

    def restore_snapshot(
        self,
        investigation_id: str,
        snapshot_id_or_version: Any,
    ) -> Investigation:
        with self._lock:
            snaps = self._snapshots.get(investigation_id, [])
            target = None
            if isinstance(snapshot_id_or_version, int):
                for s in snaps:
                    if s.version == snapshot_id_or_version:
                        target = s
                        break
            else:
                for s in snaps:
                    if s.id == str(snapshot_id_or_version):
                        target = s
                        break

            if not target:
                raise ValueError(f"Snapshot '{snapshot_id_or_version}' not found for investigation {investigation_id}")

            state_dump = copy.deepcopy(target.state_dump)
            restored = Investigation.from_dict(state_dump)
            restored.updated_at = datetime.now(timezone.utc).isoformat()
            return restored

    def rollback(self, investigation_id: str, version: Optional[int] = None) -> Investigation:
        with self._lock:
            snaps = self.get_version_history(investigation_id)
            if not snaps:
                raise ValueError(f"No snapshots available for investigation {investigation_id}")

            if version is None:
                # Rollback to the previous version before current head (or head if only 1)
                target = snaps[-2] if len(snaps) > 1 else snaps[0]
            else:
                target = None
                for s in snaps:
                    if s.version == version:
                        target = s
                        break
                if not target:
                    raise ValueError(f"Version {version} not found for investigation {investigation_id}")

            return self.restore_snapshot(investigation_id, target.id)

    def compare_snapshots(
        self,
        snapshot_id_1: str,
        snapshot_id_2: str,
    ) -> Dict[str, Any]:
        with self._lock:
            s1 = self.get_snapshot(snapshot_id_1)
            s2 = self.get_snapshot(snapshot_id_2)

            if not s1 or not s2:
                raise ValueError("One or both snapshots were not found")

            d1, d2 = s1.state_dump, s2.state_dump

            diffs = {
                "snapshot_1": {"id": s1.id, "version": s1.version, "label": s1.label},
                "snapshot_2": {"id": s2.id, "version": s2.version, "label": s2.label},
                "modified_fields": {},
                "links_delta": {},
            }

            for key in ["title", "description", "priority", "severity", "status", "owner", "team"]:
                if d1.get(key) != d2.get(key):
                    diffs["modified_fields"][key] = {
                        "from": d1.get(key),
                        "to": d2.get(key),
                    }

            l1 = d1.get("links", {})
            l2 = d2.get("links", {})
            all_link_keys = set(l1.keys()).union(set(l2.keys()))
            for lk in all_link_keys:
                set1 = set(l1.get(lk, []))
                set2 = set(l2.get(lk, []))
                added = list(set2 - set1)
                removed = list(set1 - set2)
                if added or removed:
                    diffs["links_delta"][lk] = {"added": added, "removed": removed}

            return diffs

    def clear(self) -> None:
        with self._lock:
            self._snapshots.clear()
