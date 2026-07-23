"""
Domain events for NVD CVE Intelligence Pipeline.
"""

from dataclasses import dataclass, field
from netfusion_intelligence.core.events import DomainEvent


@dataclass
class NvdImportStarted(DomainEvent):
    feed_id: str = "nvd_cve_2.0"
    import_id: str = ""


@dataclass
class NvdImportCompleted(DomainEvent):
    feed_id: str = "nvd_cve_2.0"
    import_id: str = ""
    version_id: str = ""
    duration_seconds: float = 0.0
    records_count: int = 0


@dataclass
class NvdImportFailed(DomainEvent):
    feed_id: str = "nvd_cve_2.0"
    import_id: str = ""
    error_message: str = ""


@dataclass
class CveCreated(DomainEvent):
    cve_id: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float = 0.0
    canonical_uuid: str = ""


@dataclass
class CveUpdated(DomainEvent):
    cve_id: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float = 0.0
    canonical_uuid: str = ""


@dataclass
class CanonicalEntityResolved(DomainEvent):
    canonical_uuid: str = ""
    is_new: bool = True
    source: str = "NVD"
    cve_id: str = ""
