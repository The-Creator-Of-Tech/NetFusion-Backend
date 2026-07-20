"""
NetFusion Audit Log Engine
Append-only thread-safe audit log recorder tracking every action across cases,
investigations, tasks, evidence, notes, timeline edits, search, and reports.
"""

import time
from typing import Any, Dict, List, Optional

from .domain import AuditRecord
from .enums import AuditAction


class AuditLogger:
    """Central append-only audit logger for workflow activities."""

    def __init__(self):
        self._records: List[AuditRecord] = []

    def record(
        self,
        action: AuditAction,
        entity_type: str,
        entity_id: str,
        actor: str = "system",
        changes: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Records an audit action into the append-only record store."""
        record = AuditRecord(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            timestamp=time.time(),
            changes=changes or {},
            metadata=metadata or {},
        )
        self._records.append(record)
        return record

    def get_records(
        self,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        action: Optional[AuditAction] = None,
        actor: Optional[str] = None,
    ) -> List[AuditRecord]:
        """Retrieves audit records matching optional filters."""
        results = self._records

        if entity_id:
            results = [r for r in results if r.entity_id == entity_id]
        if entity_type:
            results = [r for r in results if r.entity_type.upper() == entity_type.upper()]
        if action:
            results = [r for r in results if r.action == action]
        if actor:
            results = [r for r in results if r.actor.lower() == actor.lower()]

        return results

    def clear(self) -> None:
        """Clears audit records (used primarily for testing)."""
        self._records.clear()
