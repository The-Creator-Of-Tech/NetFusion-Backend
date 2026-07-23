"""
Verifier for MITRE CAPEC XML raw download payload.
Handles checksum calculation, basic structural validation.
"""

import hashlib
from typing import Optional, Union


class CapecVerifier:
    """
    Handles checksum calculation and verification for downloaded CAPEC XML data.
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
        Returns True if valid or if expected_checksum is None.
        """
        if not expected_checksum:
            return True
        computed = self.compute_sha256(raw_data)
        return computed.lower() == expected_checksum.lower()

    @staticmethod
    def verify_xml_structure(raw_data: bytes) -> bool:
        """
        Performs a lightweight structural check to confirm raw bytes look like a CAPEC XML document.
        """
        if not raw_data:
            return False
        header = raw_data[:500].decode("utf-8", errors="ignore").lower()
        return "<?xml" in header or "<attack_pattern_catalog" in header
