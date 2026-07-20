"""
Structured Metrics models for Intelligence subsystem.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class SystemMetrics:
    """
    Aggregated operational metrics for the Intelligence Subsystem.
    """
    successful_imports: int = 0
    failed_imports: int = 0
    average_import_duration: float = 0.0
    validation_failures: int = 0
    scheduler_uptime: float = 0.0
    feed_uptime: Dict[str, float] = field(default_factory=dict)
    active_feeds: int = 0
    disabled_feeds: int = 0
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
