from dataclasses import dataclass, field
from typing import Any, Dict
from netfusion_collector_sdk.events import BaseCollectorEvent


@dataclass
class ThreatIntelMatchedEvent(BaseCollectorEvent):
    event_type: str = "ThreatIntelMatchedEvent"
    ioc_value: str = ""
    ioc_type: str = ""
    provider: str = ""
    threat_name: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
