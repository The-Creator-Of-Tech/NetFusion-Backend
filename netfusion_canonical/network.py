from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .base import CanonicalDomainObject
from .value_objects import (
    IPAddress,
    Port,
    Hostname,
    MACAddress,
    Protocol,
    Hash,
    Timestamp,
    Severity,
    Direction,
    FlowState,
)


@dataclass
class PacketObserved(CanonicalDomainObject):
    frame_number: int = 1
    frame_length: int = 0
    capture_length: int = 0
    src_mac: Optional[MACAddress] = None
    dst_mac: Optional[MACAddress] = None
    src_ip: Optional[IPAddress] = None
    dst_ip: Optional[IPAddress] = None
    src_port: Optional[Port] = None
    dst_port: Optional[Port] = None
    ip_ttl: Optional[int] = None
    tcp_flags: List[str] = field(default_factory=list)
    payload_sha256: Optional[Hash] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.PacketObserved"


@dataclass
class NetworkFlowObserved(CanonicalDomainObject):
    src_ip: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    dst_ip: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    src_port: Port = field(default_factory=lambda: Port(0))
    dst_port: Port = field(default_factory=lambda: Port(0))
    protocol: Optional[Protocol] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: str = ""
    end_time: str = ""
    direction: Direction = Direction.UNKNOWN
    flow_state: FlowState = FlowState.ACTIVE

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.NetworkFlowObserved"


@dataclass
class DNSTransactionObserved(CanonicalDomainObject):
    query_name: Hostname = field(default_factory=lambda: Hostname("localhost"))
    query_type: str = "A"
    query_class: str = "IN"
    rcode: str = "NOERROR"
    answers: List[Dict[str, str]] = field(default_factory=list)
    ttl: int = 0
    authoritative: bool = False
    truncated: bool = False

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.DNSTransactionObserved"


@dataclass
class HTTPRequestObserved(CanonicalDomainObject):
    http_method: str = "GET"
    uri: str = "/"
    host: Optional[Hostname] = None
    user_agent: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    status_code: int = 200
    request_body_sha256: Optional[Hash] = None
    response_body_sha256: Optional[Hash] = None
    content_type: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.HTTPRequestObserved"


@dataclass
class TLSHandshakeObserved(CanonicalDomainObject):
    tls_version: str = "TLSv1.3"
    cipher_suite: Optional[str] = None
    server_name_indication: Optional[Hostname] = None
    ja3_hash: Optional[Hash] = None
    ja3s_hash: Optional[Hash] = None
    ja4: Optional[str] = None
    handshake_successful: bool = True

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.TLSHandshakeObserved"


@dataclass
class CertificateObserved(CanonicalDomainObject):
    serial_number: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    fingerprint_sha256: Hash = field(
        default_factory=lambda: Hash("SHA256", "0000000000000000000000000000000000000000000000000000000000000000")
    )
    subject_alternative_names: List[Hostname] = field(default_factory=list)
    is_self_signed: bool = False

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.CertificateObserved"


@dataclass
class SessionObserved(CanonicalDomainObject):
    session_id: str = ""
    session_type: str = "WEB_SESSION"
    authenticated_user: Optional[str] = None
    auth_method: Optional[str] = None
    bytes_transferred: int = 0

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.SessionObserved"


@dataclass
class ServiceObserved(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    port: Port = field(default_factory=lambda: Port(0))
    transport: Protocol = field(default_factory=lambda: Protocol("TCP", 6))
    service_name: str = ""
    banner: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.network.ServiceObserved"
