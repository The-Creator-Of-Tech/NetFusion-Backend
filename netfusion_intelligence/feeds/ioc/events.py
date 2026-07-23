"""
IL-7 IOC Domain Events.
Published via the IL-1 EventBus for every significant IOC pipeline lifecycle step.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from netfusion_intelligence.core.events import DomainEvent


@dataclass
class IocImportStarted(DomainEvent):
    feed_id: str = "netfusion_ioc_v1"
    import_id: str = ""
    provider_count: int = 0


@dataclass
class IocImportCompleted(DomainEvent):
    feed_id: str = "netfusion_ioc_v1"
    import_id: str = ""
    version_id: str = ""
    duration_seconds: float = 0.0
    records_imported: int = 0
    duplicates_merged: int = 0
    providers: List[str] = field(default_factory=list)


@dataclass
class CanonicalIocCreated(DomainEvent):
    ioc_id: str = ""
    ioc_type: str = ""
    canonical_uuid: str = ""
    provider: str = ""
    confidence: float = 0.0


@dataclass
class IocMerged(DomainEvent):
    ioc_id: str = ""
    ioc_type: str = ""
    canonical_uuid: str = ""
    merged_from_provider: str = ""
    new_source_count: int = 0
    new_confidence: float = 0.0


@dataclass
class IocCorrelated(DomainEvent):
    ioc_id: str = ""
    relationship_type: str = ""
    target_id: str = ""
    target_type: str = ""
    confidence: float = 0.0


@dataclass
class SightingRecorded(DomainEvent):
    ioc_id: str = ""
    sighting_id: str = ""
    observation_source: str = ""
    count: int = 1


@dataclass
class ReputationUpdated(DomainEvent):
    ioc_id: str = ""
    previous_score: float = 0.0
    new_score: float = 0.0
    reason: str = ""


@dataclass
class IocDatasetActivated(DomainEvent):
    feed_id: str = "netfusion_ioc_v1"
    version_id: str = ""
    total_indicators: int = 0
