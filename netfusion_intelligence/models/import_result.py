"""
Import result and import logging models.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ImportStatus(str, Enum):
    STARTED = "STARTED"
    DOWNLOADING = "DOWNLOADING"
    SECURE_DOWNLOADING = "SECURE_DOWNLOADING"
    TLS_VERIFYING = "TLS_VERIFYING"
    SIGNATURE_VERIFYING = "SIGNATURE_VERIFYING"
    CHECKSUM_VERIFYING = "CHECKSUM_VERIFYING"
    TRUST_EVALUATING = "TRUST_EVALUATING"
    VERIFYING = "VERIFYING"
    PARSING = "PARSING"
    NORMALIZING = "NORMALIZING"
    VALIDATING = "VALIDATING"
    STORING = "STORING"
    RELATIONSHIPS_BUILDING = "RELATIONSHIPS_BUILDING"
    ACTIVATING = "ACTIVATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class ImportLogEntry:
    """
    Log message generated during an import run.
    """
    import_id: str
    feed_id: str
    level: str  # INFO, WARNING, ERROR, DEBUG
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ImportResult:
    """
    Detailed result summary of a feed synchronization execution.
    Contains complete 13 import statistics metrics and historical tracking details.
    """
    import_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    feed_id: str = ""
    version_id: Optional[str] = None
    status: ImportStatus = ImportStatus.STARTED
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    execution_time: float = 0.0  # Alias/field for execution duration

    # 13 Import Statistics Metrics
    records_downloaded: int = 0
    records_parsed: int = 0
    records_processed: int = 0
    records_inserted: int = 0
    records_updated: int = 0
    records_deleted: int = 0
    duplicate_records: int = 0
    validation_errors: int = 0
    relationship_count: int = 0
    warnings: List[str] = field(default_factory=list)
    download_size: int = 0
    checksum: Optional[str] = None
    source_version: Optional[str] = None

    # History metadata
    trigger: str = "manual"  # manual or scheduled
    user: Optional[str] = "system"
    rollback_status: str = "NOT_APPLICABLE"  # NOT_APPLICABLE, ACTIVE, ROLLED_BACK
    validation_passed: bool = False
    validation_details: Dict[str, Any] = field(default_factory=dict)
    validation_summary: Dict[str, Any] = field(default_factory=dict)

    error_message: Optional[str] = None
    log_entries: List[ImportLogEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, ImportStatus) else self.status
        data["log_entries"] = [e.to_dict() for e in self.log_entries]
        return data
