"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Session Manager

Manages AI threat reasoning sessions linked to investigations, with support for
creation, pause/resume, cloning, merging, locking, archiving, and restoration.
"""

from datetime import datetime, timezone
import copy
import threading
from typing import Any, Dict, List, Optional
import uuid

from netfusion_investigation.lifecycle.models import ReasoningSession, SessionStatus


class SessionManager:
    """Manages reasoning session lifecycle and operations."""

    def __init__(self):
        self._sessions: Dict[str, ReasoningSession] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        investigation_id: str,
        title: str,
        state: Optional[Dict[str, Any]] = None,
        parent_session_id: Optional[str] = None,
    ) -> ReasoningSession:
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            session = ReasoningSession(
                id=f"sess-{uuid.uuid4().hex[:12]}",
                investigation_id=investigation_id,
                title=title,
                status=SessionStatus.ACTIVE,
                created_at=now,
                updated_at=now,
                state=state or {},
                parent_session_id=parent_session_id,
            )
            self._sessions[session.id] = session
            return session

    def get_session(self, session_id: str) -> Optional[ReasoningSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self, investigation_id: str) -> List[ReasoningSession]:
        with self._lock:
            res = [s for s in self._sessions.values() if s.investigation_id == investigation_id]
            res.sort(key=lambda x: x.created_at)
            return res

    def resume_session(self, session_id: str) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            if session.status == SessionStatus.LOCKED:
                raise ValueError(f"Session {session_id} is locked and cannot be resumed")
            session.status = SessionStatus.ACTIVE
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def pause_session(self, session_id: str) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            session.status = SessionStatus.PAUSED
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def archive_session(self, session_id: str) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            session.status = SessionStatus.ARCHIVED
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def lock_session(self, session_id: str) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            session.status = SessionStatus.LOCKED
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def restore_session(self, session_id: str) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            session.status = SessionStatus.ACTIVE
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def clone_session(self, session_id: str, new_title: Optional[str] = None) -> ReasoningSession:
        with self._lock:
            source = self._sessions.get(session_id)
            if not source:
                raise ValueError(f"Source session {session_id} not found")
            now = datetime.now(timezone.utc).isoformat()
            cloned = ReasoningSession(
                id=f"sess-{uuid.uuid4().hex[:12]}",
                investigation_id=source.investigation_id,
                title=new_title or f"Clone of {source.title}",
                status=SessionStatus.ACTIVE,
                created_at=now,
                updated_at=now,
                state=copy.deepcopy(source.state),
                parent_session_id=source.id,
            )
            self._sessions[cloned.id] = cloned
            return cloned

    def merge_sessions(
        self,
        target_session_id: str,
        source_session_ids: List[str],
        merged_title: Optional[str] = None,
    ) -> ReasoningSession:
        with self._lock:
            target = self._sessions.get(target_session_id)
            if not target:
                raise ValueError(f"Target session {target_session_id} not found")

            merged_state = copy.deepcopy(target.state)
            sources = []
            for sid in source_session_ids:
                s = self._sessions.get(sid)
                if s:
                    sources.append(s)
                    # Merge dictionaries safely
                    for k, v in s.state.items():
                        if isinstance(v, list) and isinstance(merged_state.get(k), list):
                            # Append non-duplicate elements
                            existing = merged_state[k]
                            for item in v:
                                if item not in existing:
                                    existing.append(item)
                        elif isinstance(v, dict) and isinstance(merged_state.get(k), dict):
                            merged_state[k].update(v)
                        else:
                            merged_state[k] = copy.deepcopy(v)

            target.state = merged_state
            if merged_title:
                target.title = merged_title
            target.updated_at = datetime.now(timezone.utc).isoformat()
            return target

    def update_session_state(self, session_id: str, state_update: Dict[str, Any]) -> ReasoningSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            if session.status == SessionStatus.LOCKED:
                raise ValueError(f"Session {session_id} is locked and cannot be updated")
            session.state.update(state_update)
            session.updated_at = datetime.now(timezone.utc).isoformat()
            return session

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
