import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from netfusion_canonical.base import CanonicalDomainObject, CanonicalValueObject


@dataclass(frozen=True)
class EvidenceLineage(CanonicalValueObject):
    provider: str = "Sysmon"
    lookup_timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    raw_reference: str = ""
    verification_method: str = "WINDOWS_EVENT_LOG"
    collector_id: Optional[str] = None
    investigation_id: Optional[str] = None


@dataclass
class ProcessObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    image_path: str = ""
    command_line: str = ""
    user: str = ""
    host: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    current_directory: str = ""
    integrity_level: str = ""
    logon_id: str = ""
    terminal_session_id: str = ""
    parent_pid: int = 0
    parent_guid: str = ""
    parent_image: str = ""
    parent_command_line: str = ""
    event_id: int = 1
    status: str = "STARTED"  # STARTED, TERMINATED, TAMPERED
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ProcessObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class ProcessRelationshipObserved(CanonicalDomainObject):
    parent_pid: int = 0
    parent_guid: str = ""
    parent_image: str = ""
    child_pid: int = 0
    child_guid: str = ""
    child_image: str = ""
    relationship_type: str = "CREATED"  # CREATED, INJECTED, TAMPERED, ACCESSED
    target_pid: Optional[int] = None
    target_guid: Optional[str] = None
    target_image: Optional[str] = None
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ProcessRelationshipObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class NetworkConnectionObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    image_path: str = ""
    user: str = ""
    src_ip: str = "127.0.0.1"
    src_port: int = 0
    dst_ip: str = "127.0.0.1"
    dst_port: int = 0
    dst_hostname: Optional[str] = None
    protocol: str = "tcp"
    initiated: bool = True
    source_is_ipv6: bool = False
    destination_is_ipv6: bool = False
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.NetworkConnectionObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class DNSQueryObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    image_path: str = ""
    query_name: str = ""
    query_status: str = "0"
    query_results: List[str] = field(default_factory=list)
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.DNSQueryObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class RegistryObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    image_path: str = ""
    user: str = ""
    event_type: str = "CREATE_DELETE"  # CREATE_DELETE, VALUE_SET, RENAME
    target_object: str = ""
    details: str = ""
    new_name: Optional[str] = None
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.RegistryObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class FileObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    image_path: str = ""
    user: str = ""
    target_filename: str = ""
    creation_utc_time: str = ""
    previous_creation_utc_time: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    stream_name: Optional[str] = None
    event_type: str = "CREATED"  # CREATED, TIME_CHANGED, STREAM_HASH, DELETED, DELETE_DETECTED
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.FileObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class DriverObserved(CanonicalDomainObject):
    image_loaded: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    signed: bool = False
    signature: str = ""
    signature_status: str = ""
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.DriverObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class ModuleObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    process_image: str = ""
    image_loaded: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    signed: bool = False
    signature: str = ""
    signature_status: str = ""
    original_file_name: str = ""
    description: str = ""
    product: str = ""
    company: str = ""
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ModuleObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class PipeObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    process_image: str = ""
    pipe_name: str = ""
    event_type: str = "CREATED"  # CREATED, CONNECTED
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.PipeObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class ClipboardObserved(CanonicalDomainObject):
    pid: int = 0
    process_guid: str = ""
    process_image: str = ""
    user: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    archived: bool = False
    is_image: bool = False
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ClipboardObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class WMIObserved(CanonicalDomainObject):
    operation_type: str = "FILTER"  # FILTER, CONSUMER, BINDING
    event_namespace: str = ""
    name: str = ""
    query: str = ""
    consumer_type: str = ""
    destination: str = ""
    filter_path: str = ""
    consumer_path: str = ""
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.WMIObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class ServiceObserved(CanonicalDomainObject):
    service_name: str = ""
    display_name: str = ""
    service_type: str = ""
    start_type: str = ""
    binary_path: str = ""
    user_account: str = ""
    host: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ServiceObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class EvidenceObserved(CanonicalDomainObject):
    event_id: int = 1
    event_record_id: int = 0
    raw_xml: str = ""
    host: str = ""
    user: str = ""
    evidence_type: str = "SYSMON_EVENT"
    description: str = ""
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.EvidenceObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class RiskObserved(CanonicalDomainObject):
    target_entity: str = ""
    risk_score: float = 0.0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    factors: List[str] = field(default_factory=list)
    provider: str = "Sysmon"
    confidence: float = 1.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.RiskObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class RelationshipObserved(CanonicalDomainObject):
    source_id: str = ""
    source_type: str = ""
    relationship_type: str = "CONNECTED_TO"
    target_id: str = ""
    target_type: str = ""
    provider: str = "Sysmon"
    confidence: float = 1.0
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.RelationshipObserved"
        self.collector_type = "SysmonCollector"


@dataclass
class ConfidenceObserved(CanonicalDomainObject):
    target_object_id: str = ""
    score: float = 1.0
    rating: str = "HIGH"
    provider: str = "Sysmon"
    evidence_lineage: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.endpoint.ConfidenceObserved"
        self.collector_type = "SysmonCollector"


__all__ = [
    "EvidenceLineage",
    "ProcessObserved",
    "ProcessRelationshipObserved",
    "NetworkConnectionObserved",
    "DNSQueryObserved",
    "RegistryObserved",
    "FileObserved",
    "DriverObserved",
    "ModuleObserved",
    "PipeObserved",
    "ClipboardObserved",
    "WMIObserved",
    "ServiceObserved",
    "EvidenceObserved",
    "RiskObserved",
    "RelationshipObserved",
    "ConfidenceObserved",
]
