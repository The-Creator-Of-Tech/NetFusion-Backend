"""
Domain events for CISA KEV Enterprise Intelligence Pipeline.
"""

from dataclasses import dataclass, field
from netfusion_intelligence.core.events import DomainEvent


@dataclass
class KevImportStarted(DomainEvent):
    feed_id: str = "cisa_kev_1.0"
    import_id: str = ""


@dataclass
class KevImportCompleted(DomainEvent):
    feed_id: str = "cisa_kev_1.0"
    import_id: str = ""
    version_id: str = ""
    duration_seconds: float = 0.0
    records_count: int = 0


@dataclass
class KevImportFailed(DomainEvent):
    feed_id: str = "cisa_kev_1.0"
    import_id: str = ""
    error_message: str = ""


@dataclass
class KevEntryCreated(DomainEvent):
    cve_id: str = ""
    vendor_project: str = ""
    product: str = ""
    due_date: str = ""
    known_ransomware: str = "Unknown"


@dataclass
class KevEntryUpdated(DomainEvent):
    cve_id: str = ""
    vendor_project: str = ""
    product: str = ""
    due_date: str = ""
    known_ransomware: str = "Unknown"


@dataclass
class CanonicalEntityEnriched(DomainEvent):
    canonical_uuid: str = ""
    cve_id: str = ""
    feed_source: str = "cisa_kev_1.0"
    exploitation_status: str = "Known Exploited"
    due_date: str = ""
    ransomware_use: str = "Unknown"


@dataclass
class DatasetActivated(DomainEvent):
    feed_id: str = "cisa_kev_1.0"
    version_id: str = ""
    activated_at: str = ""
