"""
Feed and Feed Configuration models.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


@dataclass
class FeedConfig:
    """
    Configuration model for intelligence feeds.
    Every parameter is dynamic and configurable.
    """
    enabled: bool = True
    schedule: str = "0 * * * *"  # Default cron (hourly)
    timeout: float = 300.0
    retry_count: int = 3
    retry_delay: float = 0.1
    verify_ssl: bool = True
    cache_enabled: bool = True
    checksum_required: bool = False
    auto_activate: bool = True
    custom_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedConfig":
        if not data:
            return cls()
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class FeedMetadata:
    """
    Metadata describing an intelligence feed source.
    """
    feed_id: str
    feed_name: str
    description: str
    version: str = "1.0.0"
    author: str = "NetFusion Team"
    tags: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
