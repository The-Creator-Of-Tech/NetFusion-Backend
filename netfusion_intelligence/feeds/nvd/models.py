"""
Domain Models for NVD Enterprise CVE Intelligence Pipeline.
Supports complete NVD CVE JSON 2.0 API specifications.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CvssMetric:
    """
    Normalized CVSS Metric representation supporting CVSS v2, v3.0, v3.1, and v4.0.
    """
    version: str  # "2.0", "3.0", "3.1", "4.0"
    vector_string: str
    base_score: float
    source: Optional[str] = None
    metric_type: Optional[str] = None  # "Primary", "Secondary"
    severity: Optional[str] = None  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    
    # Common Impact & Exploitability Scores
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    
    # Vector Components
    attack_vector: Optional[str] = None  # Network, Adjacent, Local, Physical
    attack_complexity: Optional[str] = None  # Low, High
    privileges_required: Optional[str] = None  # None, Low, High
    user_interaction: Optional[str] = None  # None, Required
    scope: Optional[str] = None  # Unchanged, Changed
    confidentiality_impact: Optional[str] = None  # None, Low, High, Partial, Complete
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None

    # Temporal & Environmental
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    
    # Additional v2 Specifics
    access_vector: Optional[str] = None
    access_complexity: Optional[str] = None
    authentication: Optional[str] = None
    
    raw_metric: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "source": self.source,
            "metric_type": self.metric_type,
            "severity": self.severity,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "attack_vector": self.attack_vector or self.access_vector,
            "attack_complexity": self.attack_complexity or self.access_complexity,
            "privileges_required": self.privileges_required or self.authentication,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
            "raw_metric": dict(self.raw_metric),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CvssMetric":
        return cls(
            version=str(data.get("version", "3.1")),
            vector_string=str(data.get("vector_string", "")),
            base_score=float(data.get("base_score", 0.0)),
            source=data.get("source"),
            metric_type=data.get("metric_type"),
            severity=data.get("severity"),
            exploitability_score=float(data["exploitability_score"]) if data.get("exploitability_score") is not None else None,
            impact_score=float(data["impact_score"]) if data.get("impact_score") is not None else None,
            attack_vector=data.get("attack_vector"),
            attack_complexity=data.get("attack_complexity"),
            privileges_required=data.get("privileges_required"),
            user_interaction=data.get("user_interaction"),
            scope=data.get("scope"),
            confidentiality_impact=data.get("confidentiality_impact"),
            integrity_impact=data.get("integrity_impact"),
            availability_impact=data.get("availability_impact"),
            temporal_score=float(data["temporal_score"]) if data.get("temporal_score") is not None else None,
            environmental_score=float(data["environmental_score"]) if data.get("environmental_score") is not None else None,
            access_vector=data.get("access_vector"),
            access_complexity=data.get("access_complexity"),
            authentication=data.get("authentication"),
            raw_metric=dict(data.get("raw_metric", {})),
        )


@dataclass(frozen=True)
class CpeMatchItem:
    """
    Represents a single CPE Match criteria item.
    """
    vulnerable: bool
    criteria: str  # Formatted CPE string, e.g. "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    match_criteria_id: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "criteria": self.criteria,
            "match_criteria_id": self.match_criteria_id,
            "version_start_including": self.version_start_including,
            "version_start_excluding": self.version_start_excluding,
            "version_end_including": self.version_end_including,
            "version_end_excluding": self.version_end_excluding,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CpeMatchItem":
        return cls(
            vulnerable=bool(data.get("vulnerable", True)),
            criteria=str(data.get("criteria", "")),
            match_criteria_id=data.get("match_criteria_id"),
            version_start_including=data.get("version_start_including"),
            version_start_excluding=data.get("version_start_excluding"),
            version_end_including=data.get("version_end_including"),
            version_end_excluding=data.get("version_end_excluding"),
        )


@dataclass(frozen=True)
class ConfigurationNode:
    """
    Represents a logical configuration node (AND/OR tree) in NVD configurations.
    """
    operator: str  # "AND" or "OR"
    negate: bool = False
    cpe_matches: Tuple[CpeMatchItem, ...] = field(default_factory=tuple)
    children: Tuple["ConfigurationNode", ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operator": self.operator,
            "negate": self.negate,
            "cpe_matches": [c.to_dict() for c in self.cpe_matches],
            "children": [child.to_dict() for child in self.children],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigurationNode":
        matches = tuple(CpeMatchItem.from_dict(item) for item in data.get("cpe_matches", []))
        children = tuple(ConfigurationNode.from_dict(child) for child in data.get("children", []))
        return cls(
            operator=str(data.get("operator", "OR")).upper(),
            negate=bool(data.get("negate", False)),
            cpe_matches=matches,
            children=children,
        )


@dataclass(frozen=True)
class WeaknessItem:
    """
    Represents a CWE weakness mapping entry.
    """
    source: str
    type: str
    cwe_ids: Tuple[str, ...]
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "type": self.type,
            "cwe_ids": list(self.cwe_ids),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WeaknessItem":
        return cls(
            source=str(data.get("source", "nvd@nist.gov")),
            type=str(data.get("type", "Primary")),
            cwe_ids=tuple(data.get("cwe_ids", [])),
            description=data.get("description"),
        )


@dataclass(frozen=True)
class ReferenceItem:
    """
    Represents an external reference item.
    """
    url: str
    source: Optional[str] = None
    tags: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReferenceItem":
        return cls(
            url=str(data.get("url", "")),
            source=data.get("source"),
            tags=tuple(data.get("tags", [])),
        )


@dataclass(frozen=True)
class VendorComment:
    """
    Represents official vendor comments attached to a CVE.
    """
    organization: str
    comment: str
    last_modified: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization": self.organization,
            "comment": self.comment,
            "last_modified": self.last_modified,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VendorComment":
        return cls(
            organization=str(data.get("organization", "")),
            comment=str(data.get("comment", "")),
            last_modified=data.get("last_modified"),
        )


@dataclass(frozen=True)
class NvdCve:
    """
    Immutable domain representation of an NVD CVE vulnerability record.
    """
    cve_id: str  # e.g., "CVE-2024-1234"
    published: str
    last_modified: str
    description: str
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    title: Optional[str] = None
    severity: str = "UNKNOWN"
    cvss_score: float = 0.0
    
    descriptions_map: Dict[str, str] = field(default_factory=dict)
    cvss_v2: Optional[CvssMetric] = None
    cvss_v30: Optional[CvssMetric] = None
    cvss_v31: Optional[CvssMetric] = None
    cvss_v40: Optional[CvssMetric] = None
    
    weaknesses: Tuple[WeaknessItem, ...] = field(default_factory=tuple)
    cwes: Tuple[str, ...] = field(default_factory=tuple)
    configurations: Tuple[ConfigurationNode, ...] = field(default_factory=tuple)
    cpe_matches: Tuple[CpeMatchItem, ...] = field(default_factory=tuple)
    vendors: Tuple[str, ...] = field(default_factory=tuple)
    products: Tuple[str, ...] = field(default_factory=tuple)
    references: Tuple[ReferenceItem, ...] = field(default_factory=tuple)
    vendor_comments: Tuple[VendorComment, ...] = field(default_factory=tuple)
    
    raw_nvd: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.cve_id:
            raise ValueError("NvdCve cve_id cannot be empty")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "published": self.published,
            "last_modified": self.last_modified,
            "description": self.description,
            "source_identifier": self.source_identifier,
            "vuln_status": self.vuln_status,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "descriptions_map": dict(self.descriptions_map),
            "cvss_v2": self.cvss_v2.to_dict() if self.cvss_v2 else None,
            "cvss_v30": self.cvss_v30.to_dict() if self.cvss_v30 else None,
            "cvss_v31": self.cvss_v31.to_dict() if self.cvss_v31 else None,
            "cvss_v40": self.cvss_v40.to_dict() if self.cvss_v40 else None,
            "weaknesses": [w.to_dict() for w in self.weaknesses],
            "cwes": list(self.cwes),
            "configurations": [c.to_dict() for c in self.configurations],
            "cpe_matches": [m.to_dict() for m in self.cpe_matches],
            "vendors": list(self.vendors),
            "products": list(self.products),
            "references": [r.to_dict() for r in self.references],
            "vendor_comments": [vc.to_dict() for vc in self.vendor_comments],
            "raw_nvd": dict(self.raw_nvd),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NvdCve":
        cvss_v2 = CvssMetric.from_dict(data["cvss_v2"]) if data.get("cvss_v2") else None
        cvss_v30 = CvssMetric.from_dict(data["cvss_v30"]) if data.get("cvss_v30") else None
        cvss_v31 = CvssMetric.from_dict(data["cvss_v31"]) if data.get("cvss_v31") else None
        cvss_v40 = CvssMetric.from_dict(data["cvss_v40"]) if data.get("cvss_v40") else None

        weaknesses = tuple(WeaknessItem.from_dict(w) for w in data.get("weaknesses", []))
        configs = tuple(ConfigurationNode.from_dict(c) for c in data.get("configurations", []))
        cpe_matches = tuple(CpeMatchItem.from_dict(m) for m in data.get("cpe_matches", []))
        refs = tuple(ReferenceItem.from_dict(r) for r in data.get("references", []))
        vendor_comments = tuple(VendorComment.from_dict(vc) for vc in data.get("vendor_comments", []))

        return cls(
            cve_id=data["cve_id"],
            published=data["published"],
            last_modified=data["last_modified"],
            description=data["description"],
            source_identifier=data.get("source_identifier"),
            vuln_status=data.get("vuln_status"),
            title=data.get("title"),
            severity=data.get("severity", "UNKNOWN"),
            cvss_score=float(data.get("cvss_score", 0.0)),
            descriptions_map=dict(data.get("descriptions_map", {})),
            cvss_v2=cvss_v2,
            cvss_v30=cvss_v30,
            cvss_v31=cvss_v31,
            cvss_v40=cvss_v40,
            weaknesses=weaknesses,
            cwes=tuple(data.get("cwes", [])),
            configurations=configs,
            cpe_matches=cpe_matches,
            vendors=tuple(data.get("vendors", [])),
            products=tuple(data.get("products", [])),
            references=refs,
            vendor_comments=vendor_comments,
            raw_nvd=dict(data.get("raw_nvd", {})),
        )
