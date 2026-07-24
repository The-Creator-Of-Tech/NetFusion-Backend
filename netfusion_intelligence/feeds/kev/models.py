"""
Domain models for CISA Known Exploited Vulnerabilities (KEV) Intelligence Pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class KevRecord:
    """
    Represents an individual vulnerability entry in the CISA KEV catalog.
    """
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware_campaign_use: str = "Unknown"
    notes: str = ""
    cwes: Tuple[str, ...] = field(default_factory=tuple)
    reference_urls: Tuple[str, ...] = field(default_factory=tuple)
    catalog_version: str = "1.0"
    source: str = "CISA KEV"
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modified: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"

    def __post_init__(self):
        if not self.cve_id:
            raise ValueError("cve_id cannot be empty")
        if isinstance(self.cwes, list):
            object.__setattr__(self, "cwes", tuple(self.cwes))
        if isinstance(self.reference_urls, list):
            object.__setattr__(self, "reference_urls", tuple(self.reference_urls))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "notes": self.notes,
            "cwes": list(self.cwes),
            "reference_urls": list(self.reference_urls),
            "catalog_version": self.catalog_version,
            "source": self.source,
            "created": self.created,
            "modified": self.modified,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KevRecord":
        cve = data.get("cve_id") or data.get("cveID") or ""
        return cls(
            cve_id=cve.strip(),
            vendor_project=data.get("vendor_project") or data.get("vendorProject") or "",
            product=data.get("product") or "",
            vulnerability_name=data.get("vulnerability_name") or data.get("vulnerabilityName") or "",
            date_added=data.get("date_added") or data.get("dateAdded") or "",
            short_description=data.get("short_description") or data.get("shortDescription") or "",
            required_action=data.get("required_action") or data.get("requiredAction") or "",
            due_date=data.get("due_date") or data.get("dueDate") or "",
            known_ransomware_campaign_use=data.get("known_ransomware_campaign_use") or data.get("knownRansomwareCampaignUse") or "Unknown",
            notes=data.get("notes") or "",
            cwes=tuple(data.get("cwes") or data.get("cwes_list") or []),
            reference_urls=tuple(data.get("reference_urls") or data.get("notes_urls") or []),
            catalog_version=str(data.get("catalog_version") or data.get("catalogVersion") or "1.0"),
            source=data.get("source", "CISA KEV"),
            created=data.get("created", datetime.now(timezone.utc).isoformat()),
            modified=data.get("modified", datetime.now(timezone.utc).isoformat()),
            status=data.get("status", "ACTIVE"),
        )


@dataclass
class KevCatalog:
    """
    Represents the full CISA KEV dataset container.
    """
    title: str = "CISA Known Exploited Vulnerabilities Catalog"
    catalog_version: str = "1.0"
    date_released: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    count: int = 0
    records: Dict[str, KevRecord] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "catalog_version": self.catalog_version,
            "date_released": self.date_released,
            "count": self.count,
            "records": [r.to_dict() for r in self.records.values()],
        }
