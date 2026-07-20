"""
Domain Event Audit Log models.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass
class AuditLogEntry:
    """
    Persisted domain event audit log record.
    """
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str = ""
    event_type: str = ""
    feed_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditLogEntry":
        if not data:
            raise ValueError("Data cannot be empty")
        return cls(**data)
