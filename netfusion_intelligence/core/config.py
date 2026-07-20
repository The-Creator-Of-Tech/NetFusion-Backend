"""
Configuration management for netfusion_intelligence engine and feeds.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional
from netfusion_intelligence.models.feed import FeedConfig


@dataclass
class EngineConfig:
    """
    Subsystem-wide intelligence engine configuration.
    """
    db_url: str = "sqlite:///:memory:"
    auto_discover: bool = False
    discovery_packages: list = field(default_factory=list)
    default_sync_timeout: float = 300.0
    max_concurrent_syncs: int = 5
    enable_scheduler: bool = True
    log_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineConfig":
        if not data:
            return cls()
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)
