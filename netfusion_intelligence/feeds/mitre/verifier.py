"""
Verifier for MITRE ATT&CK STIX 2.1 raw download payload.
"""

import hashlib
from typing import Any, Optional, Union
from netfusion_intelligence.utils.checksum import compute_checksum


class MitreVerifier:
    """
    Handles checksum calculation and verification for downloaded MITRE STIX bundles.
    """

    @staticmethod
    def compute_sha256(raw_data: Union[str, bytes]) -> str:
        """Computes SHA256 checksum of raw payload."""
        return compute_checksum(raw_data)

    def verify_checksum(self, raw_data: Union[str, bytes], expected_checksum: Optional[str] = None) -> bool:
        """
        Verifies checksum of raw payload. Returns True if valid or if expected_checksum is None.
        """
        if not expected_checksum:
            return True
        computed = self.compute_sha256(raw_data)
        return computed.lower() == expected_checksum.lower()
