"""
Integrity and Checksum Verifier for CISA KEV Intelligence Pipeline.
"""

import hashlib
import json
from typing import Any, Optional


class CisaKevVerifier:
    """
    Verifies payload checksum, structure, and integrity for CISA KEV catalog data.
    """

    def compute_checksum(self, raw_data: Any) -> str:
        """
        Computes SHA-256 checksum of raw bytes, string, or dictionary.
        """
        if isinstance(raw_data, bytes):
            return hashlib.sha256(raw_data).hexdigest()
        elif isinstance(raw_data, str):
            return hashlib.sha256(raw_data.encode("utf-8")).hexdigest()
        elif isinstance(raw_data, dict):
            serialized = json.dumps(raw_data, sort_keys=True)
            return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        else:
            return hashlib.sha256(str(raw_data).encode("utf-8")).hexdigest()

    def verify_checksum(self, raw_data: Any, expected_checksum: Optional[str] = None) -> bool:
        """
        Verifies raw data integrity against an expected SHA-256 checksum.
        If no checksum is provided, performs basic non-empty payload check.
        """
        if raw_data is None:
            return False

        if isinstance(raw_data, (bytes, str)) and len(raw_data) == 0:
            return False

        if not expected_checksum:
            return True

        actual = self.compute_checksum(raw_data)
        return actual.lower() == expected_checksum.lower()
