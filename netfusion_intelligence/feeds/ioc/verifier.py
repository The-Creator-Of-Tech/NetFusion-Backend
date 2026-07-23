"""
IL-7 IOC Verifier.
Validates payload integrity (checksum) and structural sanity
before the data enters the parse/normalize pipeline.
"""

import hashlib
from typing import Any, Optional


class IocVerifier:
    """
    Verifies raw IOC payload integrity.
    Computes SHA-256 of serialized raw data and optionally compares
    against an expected checksum provided by the feed configuration.
    """

    def verify_checksum(
        self,
        raw_data: Any,
        expected_checksum: Optional[str] = None,
    ) -> bool:
        """
        Compute SHA-256 of raw_data and compare with expected_checksum.
        If no expected_checksum is supplied, returns True (no requirement).
        """
        if expected_checksum is None:
            return True
        computed = self._compute_checksum(raw_data)
        return computed.lower() == expected_checksum.lower().strip()

    def compute_checksum(self, raw_data: Any) -> str:
        """Return SHA-256 hex digest of raw_data."""
        return self._compute_checksum(raw_data)

    @staticmethod
    def _compute_checksum(raw_data: Any) -> str:
        if isinstance(raw_data, bytes):
            payload = raw_data
        elif isinstance(raw_data, str):
            payload = raw_data.encode("utf-8")
        else:
            import json
            try:
                payload = json.dumps(raw_data, sort_keys=True, default=str).encode("utf-8")
            except Exception:
                payload = str(raw_data).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def verify_structure(self, raw_data: Any) -> bool:
        """
        Basic structural sanity check — raw_data must not be None or empty.
        Accepts bytes, str, dict, list.
        """
        if raw_data is None:
            return False
        if isinstance(raw_data, (bytes, str)):
            return len(raw_data) > 0
        if isinstance(raw_data, (list, dict)):
            return True  # empty collections are valid (zero indicators)
        return True
