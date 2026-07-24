"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Activity Logger

Audit logging module to capture all user, AI, workflow, evidence, graph, and timeline actions.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from netfusion_investigation.lifecycle.models import ActivityLogEntry, ActivityType


class ActivityLogger:
    """Stores and queries immutable audit activity entries."""

    def __init__(self):
        self._entries: List[ActivityLogEntry] = []
        self._lock = threading.RLock()

    def log_activity(
        self,
        investigation_id: str,
        activity_type: Union[ActivityType, str],
        actor: str,
        action: str,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ActivityLogEntry:
        with self._lock:
            act_enum = activity_type if isinstance(activity_type, ActivityType) else ActivityType(activity_type)
            entry = ActivityLogEntry(
                id=f"act-{uuid.uuid4().hex[:12]}",
                investigation_id=investigation_id,
                session_id=session_id,
                activity_type=act_enum,
                actor=actor,
                action=action,
                details=details or {},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            self._entries.append(entry)
            return entry

    def get_activities(
        self,
        investigation_id: Optional[str] = None,
        activity_type: Optional[Union[ActivityType, str]] = None,
        session_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[ActivityLogEntry]:
        with self._lock:
            res = list(self._entries)
            if investigation_id:
                res = [e for e in res if e.investigation_id == investigation_id]
            if session_id:
                res = [e for e in res if e.session_id == session_id]
            if activity_type:
                target_type = activity_type.value if isinstance(activity_type, ActivityType) else activity_type
                res = [e for e in res if e.activity_type.value == target_type or e.activity_type == target_type]
            res.sort(key=lambda x: x.timestamp, reverse=True)
            if limit:
                res = res[:limit]
            return res

    def search_activities(self, query: str, investigation_id: Optional[str] = None) -> List[ActivityLogEntry]:
        q_lower = query.lower()
        with self._lock:
            res = list(self._entries)
            if investigation_id:
                res = [e for e in res if e.investigation_id == investigation_id]
            matched = []
            for e in res:
                if (
                    q_lower in e.action.lower()
                    or q_lower in e.actor.lower()
                    or q_lower in str(e.details).lower()
                ):
                    matched.append(e)
            matched.sort(key=lambda x: x.timestamp, reverse=True)
            return matched

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
