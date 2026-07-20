from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .base import CanonicalDomainObject
from .value_objects import (
    IPAddress,
    Port,
    Hostname,
    MACAddress,
    ConfidenceScore,
)


@dataclass
class HostDiscovered(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    mac_address: Optional[MACAddress] = None
    hostnames: List[Hostname] = field(default_factory=list)
    status: str = "up"
    reason: str = "user-set"

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.HostDiscovered"


@dataclass
class HostFingerprint(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    uptime_seconds: Optional[int] = None
    last_boot: Optional[str] = None
    distance_hops: Optional[int] = None
    tcp_sequence_class: Optional[str] = None
    ip_id_sequence_class: Optional[str] = None
    os_matches: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.HostFingerprint"


@dataclass
class OperatingSystemObserved(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    os_name: str = "Unknown"
    os_family: Optional[str] = None
    vendor: Optional[str] = None
    os_generation: Optional[str] = None
    accuracy: int = 100
    cpe: List[str] = field(default_factory=list)
    device_type: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.OperatingSystemObserved"


@dataclass
class PortObserved(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    port_number: Port = field(default_factory=lambda: Port(0))
    protocol: str = "tcp"
    state: str = "open"
    reason: str = "syn-ack"
    service_name: Optional[str] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.PortObserved"


@dataclass
class ServiceFingerprint(CanonicalDomainObject):
    ip_address: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    port_number: Port = field(default_factory=lambda: Port(0))
    protocol: str = "tcp"
    service_name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    ostype: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    confidence: Optional[ConfidenceScore] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.ServiceFingerprint"


@dataclass
class DeviceObserved(CanonicalDomainObject):
    mac_address: MACAddress = field(default_factory=lambda: MACAddress("00:00:00:00:00:00"))
    vendor: Optional[str] = None
    device_type: str = "Unknown"

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.DeviceObserved"


@dataclass
class InterfaceObserved(CanonicalDomainObject):
    ip_address: Optional[IPAddress] = None
    mac_address: Optional[MACAddress] = None
    interface_name: str = "eth0"
    status: str = "up"

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.InterfaceObserved"


@dataclass
class MACAddressObserved(CanonicalDomainObject):
    mac_address: MACAddress = field(default_factory=lambda: MACAddress("00:00:00:00:00:00"))
    vendor: Optional[str] = None
    associated_ip: Optional[IPAddress] = None

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.MACAddressObserved"


@dataclass
class HostnameObserved(CanonicalDomainObject):
    hostname: Hostname = field(default_factory=lambda: Hostname("localhost"))
    associated_ip: IPAddress = field(default_factory=lambda: IPAddress("127.0.0.1"))
    name_type: str = "user"

    def __post_init__(self):
        self.canonical_type = "netfusion.canonical.asset.HostnameObserved"
