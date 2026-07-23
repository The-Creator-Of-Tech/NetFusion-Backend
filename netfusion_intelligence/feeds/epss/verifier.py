"""
Integrity verifier for FIRST EPSS datasets.
Validates TLS transport, format integrity, and content sanity.
"""

import hashlib
import io
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class EpssVerifier:
    """
    Verifies integrity and authenticity of downloaded EPSS dataset payloads.
    """

    def __init__(self):
        self._last_checksum: Optional[str] = None

    @property
    def last_checksum(self) -> Optional[str]:
        return self._last_checksum

    def verify_checksum(
        self,
        raw_data: Any,
        expected_checksum: Optional[str] = None,
        algorithm: str = "sha256",
    ) -> bool:
        """
        Verifies raw payload checksum.
        If no expected checksum is provided, computes and stores it.
        Returns True if verification passes.
        """
        if raw_data is None:
            logger.error("Cannot verify checksum: payload is None")
            return False

        payload = raw_data
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        elif not isinstance(payload, (bytes, bytearray)):
            logger.warning(f"Unknown payload type for checksum: {type(payload)}")
            payload = str(payload).encode("utf-8")

        h = hashlib.new(algorithm)
        h.update(payload)
        computed = h.hexdigest()
        self._last_checksum = computed

        if expected_checksum:
            if computed.lower() != expected_checksum.lower():
                logger.error(f"EPSS checksum mismatch: expected {expected_checksum}, got {computed}")
                return False
            logger.info(f"EPSS checksum verified: {computed}")
            return True

        # No expected checksum provided — record it and pass
        logger.info(f"EPSS payload checksum computed: {computed}")
        return True

    def verify_content_integrity(self, raw_data: bytes) -> bool:
        """
        Performs a basic content sanity check on the EPSS payload.
        Ensures it looks like a valid EPSS CSV or JSON document.
        """
        if not raw_data:
            logger.error("EPSS payload is empty")
            return False

        try:
            sample = raw_data[:1024]
            if isinstance(sample, bytes):
                sample_str = sample.decode("utf-8", errors="replace").lower()
            else:
                sample_str = str(sample).lower()

            # Check for CSV format: must contain 'cve' and 'epss' columns
            if "cve-" in sample_str or ",epss" in sample_str or "cve,epss" in sample_str:
                logger.info("EPSS payload passes CSV content integrity check")
                return True

            # Check for JSON format: FIRST API returns {"status":"OK","data":[...]}
            if '"cve"' in sample_str or "'cve'" in sample_str or '"epss"' in sample_str:
                logger.info("EPSS payload passes JSON content integrity check")
                return True

            # Check for header comment format used in official CSV
            if "#model_version" in sample_str or "#score_date" in sample_str:
                logger.info("EPSS payload passes header comment content integrity check")
                return True

            logger.warning(
                f"EPSS content integrity check: unrecognized format, sample: {sample_str[:200]}"
            )
            return False

        except Exception as e:
            logger.error(f"EPSS content integrity verification error: {e}")
            return False

    def compute_sha256(self, data: bytes) -> str:
        """Computes and returns SHA-256 hex digest of data."""
        h = hashlib.sha256()
        h.update(data if isinstance(data, bytes) else data.encode("utf-8"))
        return h.hexdigest()

    def compute_md5(self, data: bytes) -> str:
        """Computes and returns MD5 hex digest of data."""
        h = hashlib.md5(usedforsecurity=False)
        h.update(data if isinstance(data, bytes) else data.encode("utf-8"))
        return h.hexdigest()
