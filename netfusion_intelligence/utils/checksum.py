"""
Checksum computation and verification utilities.
"""

import hashlib
import json
from typing import Any, Union


def compute_checksum(content: Union[bytes, str, dict, list]) -> str:
    """
    Computes SHA-256 checksum for given content (bytes, string, dict, or list).
    """
    hasher = hashlib.sha256()

    if isinstance(content, bytes):
        hasher.update(content)
    elif isinstance(content, str):
        hasher.update(content.encode("utf-8"))
    elif isinstance(content, (dict, list)):
        serialized = json.dumps(content, sort_keys=True)
        hasher.update(serialized.encode("utf-8"))
    else:
        hasher.update(str(content).encode("utf-8"))

    return hasher.hexdigest()


def verify_checksum(content: Any, expected_checksum: str) -> bool:
    """
    Verifies content SHA-256 checksum against expected hex string.
    """
    if not expected_checksum:
        return True
    calculated = compute_checksum(content)
    return calculated.lower() == expected_checksum.strip().lower()
