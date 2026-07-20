"""
Version metadata and identification models.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


@dataclass
class VersionIdentifier:
    """
    Identifies a version uniquely within a feed context.
    """
    feed_id: str
    version_id: str
    semantic_tag: Optional[str] = None


@dataclass
class VersionMetadata:
    """
    Detailed metadata for a dataset version.
    """
    feed_id: str
    version_id: str
    checksum: str
    record_count: int
    duration_seconds: float
    created_at: str
    activated_at: Optional[str] = None
    is_active: bool = False
    source_version: Optional[str] = None
    validation_passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
