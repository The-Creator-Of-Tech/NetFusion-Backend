import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from netfusion_canonical.base import CanonicalDomainObject, CanonicalValueObject
from netfusion_canonical.value_objects import Severity, ConfidenceScore
from netfusion_canonical.threat import (
    VulnerabilityDetected,
    ToolObserved,
    TechniqueObserved,
)


@dataclass(frozen=True)
class EvidenceLineage(CanonicalValueObject):
    provider: str
    lookup_timestamp: str
    raw_reference: str
    verification_method: str = "API_QUERY"
    collector_id: Optional[str] = None
    investigation_id: Optional[str] = None


@dataclass
class IOCObserved(CanonicalDomainObject):
    ioc_type: str = "IPv4"  # IPv4, IPv6, Domain, URL, Hash, Email, CVE, CPE
    ioc_value: str = ""
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    threat_types: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.IOCObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class ThreatIntelMatched(CanonicalDomainObject):
    ioc_value: str = ""
    ioc_type: str = "IPv4"
    provider: str = "Unknown"
    match_severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    threat_name: str = "Unknown Threat"
    category: str = "General"
    description: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None
    raw_response: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.ThreatIntelMatched"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class ThreatActorObserved(CanonicalDomainObject):
    actor_name: str = "Unknown Actor"
    aliases: List[str] = field(default_factory=list)
    provider: str = "Unknown"
    confidence: float = 0.0
    motivation: str = "Unknown"
    country_origin: Optional[str] = None
    target_sectors: List[str] = field(default_factory=list)
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.ThreatActorObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class CampaignObserved(CanonicalDomainObject):
    campaign_name: str = "Unknown Campaign"
    provider: str = "Unknown"
    confidence: float = 0.0
    description: str = ""
    objective: str = "Unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.CampaignObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class MalwareObserved(CanonicalDomainObject):
    malware_name: str = "Unknown Malware"
    malware_type: str = "Unknown"  # Ransomware, Trojan, Botnet, C2, etc.
    family: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)  # md5, sha1, sha256
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.MalwareObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class ExploitObserved(CanonicalDomainObject):
    exploit_id: str = "EXPLOIT-UNKNOWN"
    cve_id: Optional[str] = None
    exploit_type: str = "Remote Code Execution"
    platform: str = "Universal"
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.ExploitObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class RelationshipObserved(CanonicalDomainObject):
    source_id: str = ""
    source_type: str = ""
    relationship_type: str = "INDICATES"  # INDICATES, BELONGS_TO, TARGETS, USES, EXPLOITS
    target_id: str = ""
    target_type: str = ""
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.RelationshipObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class ConfidenceObserved(CanonicalDomainObject):
    target_object_id: str = ""
    score: float = 0.0
    rating: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.ConfidenceObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class RiskObserved(CanonicalDomainObject):
    target_entity: str = ""
    risk_score: float = 0.0  # 0.0 to 100.0
    risk_level: str = "MEDIUM"
    factors: List[str] = field(default_factory=list)
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.RiskObserved"
        self.collector_type = "ThreatIntelCollector"


@dataclass
class MITREMappingObserved(CanonicalDomainObject):
    technique_id: str = "T1000"
    technique_name: str = "Unknown Technique"
    tactic: str = "Unknown Tactic"
    provider: str = "Unknown"
    confidence: float = 0.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    investigation_correlation: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.MITREMappingObserved"
        self.collector_type = "ThreatIntelCollector"


__all__ = [
    "EvidenceLineage",
    "IOCObserved",
    "ThreatIntelMatched",
    "ThreatActorObserved",
    "CampaignObserved",
    "MalwareObserved",
    "ToolObserved",
    "TechniqueObserved",
    "VulnerabilityDetected",
    "ExploitObserved",
    "RelationshipObserved",
    "ConfidenceObserved",
    "RiskObserved",
    "MITREMappingObserved",
]
