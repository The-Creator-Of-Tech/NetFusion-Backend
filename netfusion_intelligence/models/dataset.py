"""
Dataset and DatasetVersion models.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid


class DatasetStatus(str, Enum):
    CREATED = "CREATED"
    PARSED = "PARSED"
    STORED = "STORED"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class ValidationStatus(str, Enum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class DatasetVersion:
    """
    Represents a immutable dataset version created during a synchronization run.
    """
    feed_id: str
    version_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    checksum: str = ""
    imported_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_version: Optional[str] = None
    duration: float = 0.0
    record_count: int = 0
    validation_status: ValidationStatus = ValidationStatus.PENDING
    status: DatasetStatus = DatasetStatus.CREATED
    activated_at: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["validation_status"] = self.validation_status.value if isinstance(self.validation_status, ValidationStatus) else self.validation_status
        data["status"] = self.status.value if isinstance(self.status, DatasetStatus) else self.status
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetVersion":
        if not data:
            raise ValueError("Data dictionary cannot be empty")
        d = dict(data)
        if "validation_status" in d and isinstance(d["validation_status"], str):
            d["validation_status"] = ValidationStatus(d["validation_status"])
        if "status" in d and isinstance(d["status"], str):
            d["status"] = DatasetStatus(d["status"])
        return cls(**d)
