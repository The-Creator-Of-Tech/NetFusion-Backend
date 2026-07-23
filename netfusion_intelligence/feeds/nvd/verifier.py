"""
NVD Payload Verifier for NetFusion IL-3 NVD Pipeline.
"""

from typing import Any, Optional
from netfusion_intelligence.utils.checksum import compute_checksum


class NvdVerifier:
    """
    Verifies payload integrity and checksum for NVD dataset downloads.
    """

    def verify_checksum(self, raw_data: Any, expected_checksum: Optional[str] = None) -> bool:
        """
        Verifies SHA-256 checksum of raw NVD payload.
        If expected_checksum is None, returns True (passes integrity check).
        """
        if not expected_checksum:
            return True

        computed = compute_checksum(raw_data)
        return computed.lower() == expected_checksum.lower()
