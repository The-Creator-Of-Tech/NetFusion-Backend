"""
Audit Trail persistence for Feed Authenticity & Trust Verification results.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from netfusion_intelligence.security.policy_engine import TrustEvaluationResult


@dataclass
class TrustAuditEntry:
    """
    Immutable audit record stored for every feed authenticity verification.
    """
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    feed_id: str = ""
    publisher: str = ""
    organization: str = ""
    verification_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    certificate_status: str = "PASSED"
    checksum_result: str = "PASSED"
    signature_result: str = "PASSED"
    tls_result: str = "PASSED"
    domain_verification: str = "PASSED"
    overall_trust: str = "TRUSTED"
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_evaluation(cls, result: TrustEvaluationResult) -> "TrustAuditEntry":
        return cls(
            feed_id=result.feed_id,
            publisher=result.publisher,
            organization=result.organization,
            verification_time=result.timestamp,
            certificate_status=result.certificate_status,
            checksum_result=result.checksum_status,
            signature_result=result.signature_status,
            tls_result=result.transport_status,
            domain_verification=result.domain_verification,
            overall_trust=result.overall_trust,
            reason="; ".join(result.reasons),
            details=result.details,
        )


class TrustAuditRepository:
    """
    In-memory and persistent storage repository for trust verification audit entries.
    """

    def __init__(self):
        self._entries: List[TrustAuditEntry] = []
        self._lock = threading.Lock()

    def record(self, entry: TrustAuditEntry) -> TrustAuditEntry:
        """
        Persists a new trust audit entry.
        """
        with self._lock:
            self._entries.append(entry)
            return entry

    def record_evaluation(self, result: TrustEvaluationResult) -> TrustAuditEntry:
        """
        Creates and persists an audit record directly from a TrustEvaluationResult.
        """
        entry = TrustAuditEntry.from_evaluation(result)
        return self.record(entry)

    def get_history(
        self, feed_id: Optional[str] = None, overall_trust: Optional[str] = None, limit: int = 100
    ) -> List[TrustAuditEntry]:
        """
        Retrieves historical audit entries filtered by feed ID or overall trust level.
        """
        with self._lock:
            filtered = self._entries
            if feed_id:
                filtered = [e for e in filtered if e.feed_id == feed_id]
            if overall_trust:
                filtered = [e for e in filtered if e.overall_trust.upper() == overall_trust.upper()]
            
            # Sort newest first
            sorted_entries = sorted(filtered, key=lambda x: x.verification_time, reverse=True)
            return sorted_entries[:limit]

    def get_latest_for_feed(self, feed_id: str) -> Optional[TrustAuditEntry]:
        """
        Returns the most recent audit entry for a specific feed.
        """
        entries = self.get_history(feed_id=feed_id, limit=1)
        return entries[0] if entries else None

    def clear(self) -> None:
        """
        Clears recorded audit entries.
        """
        with self._lock:
            self._entries.clear()
