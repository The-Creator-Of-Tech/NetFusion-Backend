"""
Feed Manifest model declaring plugin capabilities, entity/relationship schemas, scheduling metadata, and dependencies.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class FeedManifest:
    """
    Manifest model exposed by all intelligence feed plugins.
    Declares capabilities, schemas, scheduling guidelines, and prerequisites.
    """
    name: str
    description: str
    vendor: str = "NetFusion"
    version: str = "1.0.0"
    feed_type: str = "threat_intel"

    # Capability flags
    supports_incremental_updates: bool = False
    supports_full_sync: bool = True
    supports_relationship_building: bool = True
    supports_checksum_verification: bool = True
    supports_signature_verification: bool = False
    supports_rollback: bool = True
    supports_resume: bool = False
    supports_parallel_download: bool = False
    supports_delta_updates: bool = False

    # Entity & Relationship schemas
    entity_types: List[str] = field(default_factory=list)
    relationship_types: List[str] = field(default_factory=list)

    # Scheduling metadata
    default_schedule: str = "0 * * * *"  # Standard cron expression
    recommended_retry_count: int = 3
    timeout: float = 300.0

    # Validation metadata
    validation_rules: List[str] = field(default_factory=list)

    # Dependency metadata
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedManifest":
        if not data:
            raise ValueError("Manifest dictionary cannot be empty")
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)
