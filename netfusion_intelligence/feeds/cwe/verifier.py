"""
Verifier for MITRE CWE XML raw download payload.
Handles checksum calculation, basic structural validation.
"""

import hashlib
from typing import Optional, Union


class CweVerifier:
    """
    Handles checksum calculation and verification for downloaded CWE XML data.
    """

    @staticmethod
    def compute_sha256(raw_data: Union[str, bytes]) -> str:
        """Computes SHA256 checksum of raw payload."""
        if isinstance(raw_data, str):
            raw_data = raw_data.encode("utf-8")
        return hashlib.sha256(raw_data).hexdigest()

    def verify_checksum(
        self,
        raw_data: Union[str, bytes],
        expected_checksum: Optional[str] = None,
    ) -> bool:
        """
        Verifies checksum of raw payload.
        Returns True if valid or if expected_checksum is None (no verification required).
        """
        if not expected_checksum:
            return True
        computed = self.compute_sha256(raw_data)
        return computed.lower() == expected_checksum.lower()

    @staticmethod
    def verify_xml_structure(raw_data: bytes) -> bool:
        """
        Performs a lightweight structural check to confirm raw bytes look like an XML document.
        Does not perform full schema validation.
        """
        if not raw_data:
            return False
        # Quick heuristic: first 500 bytes should contain XML declaration or root element
        header = raw_data[:500].decode("utf-8", errors="ignore").lower()
        return "<?xml" in header or "<weakness_catalog" in header
