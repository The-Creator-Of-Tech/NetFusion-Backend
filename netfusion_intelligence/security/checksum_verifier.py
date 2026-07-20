"""
Checksum Verification module for NetFusion Intelligence feeds.
Provides multi-algorithm SHA256 and SHA512 integrity checks, checksum history tracking, and mismatch alerting.
"""

from datetime import datetime, timezone
import hashlib
import json
import threading
from typing import Any, Dict, List, Optional, Union

from netfusion_intelligence.core.exceptions import ChecksumVerificationError
from netfusion_intelligence.utils.logging import get_structured_logger

logger = get_structured_logger(__name__)


def content_to_bytes(content: Any) -> bytes:
    """
    Converts bytes, str, dict, list, or arbitrary objects to bytes for hashing.
    """
    if isinstance(content, bytes):
        return content
    elif isinstance(content, str):
        return content.encode("utf-8")
    elif isinstance(content, (dict, list)):
        return json.dumps(content, sort_keys=True).encode("utf-8")
    else:
        return str(content).encode("utf-8")


class ChecksumVerifier:
    """
    Integrity verification framework for intelligence feed payloads.
    Tracks historical checksums and enforces SHA-256 / SHA-512 comparison.
    """

    def __init__(self):
        self._history: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def compute_hash(self, raw_data: Any, algorithm: str = "SHA256") -> str:
        """
        Computes SHA256 or SHA512 digest for raw feed data.
        """
        data_bytes = content_to_bytes(raw_data)
        algo = algorithm.upper()

        if algo in ("SHA512", "SHA-512"):
            return hashlib.sha512(data_bytes).hexdigest()
        else:
            return hashlib.sha256(data_bytes).hexdigest()

    def verify_checksum(
        self,
        feed_id: str,
        raw_data: Any,
        expected_checksum: Optional[str],
        algorithm: str = "SHA256",
        required: bool = True,
    ) -> Dict[str, Any]:
        """
        Verifies computed hash against expected checksum and records entry in checksum history.
        """
        algo = algorithm.upper()
        computed = self.compute_hash(raw_data, algo)
        now_str = datetime.now(timezone.utc).isoformat()

        report = {
            "verified": False,
            "feed_id": feed_id,
            "algorithm": algo,
            "computed_checksum": computed,
            "expected_checksum": expected_checksum,
            "timestamp": now_str,
            "reason": "Checksum verification started",
        }

        # If no expected checksum provided
        if not expected_checksum:
            if required:
                report["reason"] = f"Expected {algo} checksum missing for feed '{feed_id}' when checksum is required"
                self._record_history(feed_id, report)
                logger.error(report["reason"])
                raise ChecksumVerificationError(report["reason"])
            else:
                report["verified"] = True
                report["reason"] = f"Expected checksum not provided for feed '{feed_id}' (not required)"
                self._record_history(feed_id, report)
                return report

        # Compare hashes
        cleaned_expected = expected_checksum.strip().lower()
        cleaned_computed = computed.lower()

        if cleaned_computed == cleaned_expected:
            report["verified"] = True
            report["reason"] = f"{algo} checksum verified successfully for feed '{feed_id}'"
            self._record_history(feed_id, report)
            logger.info(f"Checksum verified for feed '{feed_id}' (SHA-256: {computed[:12]}...)")
            return report

        # Mismatch handling
        report["reason"] = f"Checksum mismatch for feed '{feed_id}': computed '{computed}' vs expected '{expected_checksum}'"
        self._record_history(feed_id, report)
        logger.error(f"CHECKSUM MISMATCH ALERT: {report['reason']}")
        raise ChecksumVerificationError(report["reason"])

    def get_history(self, feed_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves recorded checksum history entries.
        """
        with self._lock:
            if feed_id:
                history = self._history.get(feed_id, [])
                return list(history[-limit:])
            
            all_entries = []
            for entries in self._history.values():
                all_entries.extend(entries)
            all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return all_entries[:limit]

    def _record_history(self, feed_id: str, entry: Dict[str, Any]) -> None:
        """
        Persists a checksum verification attempt to internal thread-safe memory.
        """
        with self._lock:
            if feed_id not in self._history:
                self._history[feed_id] = []
            self._history[feed_id].append(entry)
