from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .base import CanonicalDomainObject
from .value_objects import (
    IPAddress,
    Port,
    Severity,
    ConfidenceScore,
)


@dataclass
class VulnerabilityDetected(CanonicalDomainObject):
    vulnerability_id: str = "CVE-UNKNOWN"
    title: str = "Unknown Vulnerability"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    ip_address: Optional[IPAddress] = None
    port_number: Optional[Port] = None
    script_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    raw_output: str = ""

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.VulnerabilityDetected"


@dataclass
class ToolObserved(CanonicalDomainObject):
    tool_name: str = "Nmap"
    tool_version: Optional[str] = None
    tool_type: str = "Scanner"
    category: str = "Network Discovery"
    execution_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.ToolObserved"


@dataclass
class TechniqueObserved(CanonicalDomainObject):
    technique_id: str = "T1046"
    technique_name: str = "Network Service Discovery"
    tactic: str = "Discovery"
    confidence: Optional[ConfidenceScore] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.threat.TechniqueObserved"
