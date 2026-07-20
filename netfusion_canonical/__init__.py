"""
NetFusion Canonical Data Model Package
Universal canonical object hierarchy, value objects, validation engine, and DLQ.
"""

from .base import CanonicalDomainObject, CanonicalValueObject
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
    ConfidenceScore,
)
from .network import (
    PacketObserved,
    NetworkFlowObserved,
    DNSTransactionObserved,
    HTTPRequestObserved,
    TLSHandshakeObserved,
    CertificateObserved,
    SessionObserved,
    ServiceObserved,
)
from .asset import (
    HostDiscovered,
    HostFingerprint,
    OperatingSystemObserved,
    PortObserved,
    ServiceFingerprint,
    DeviceObserved,
    InterfaceObserved,
    MACAddressObserved,
    HostnameObserved,
)
from .threat import (
    VulnerabilityDetected,
    ToolObserved,
    TechniqueObserved,
)
from .validator import CanonicalValidator
from .dlq import DeadLetterQueue
from .pipeline import NormalizationPipeline

__all__ = [
    "CanonicalDomainObject",
    "CanonicalValueObject",
    "IPAddress",
    "Port",
    "Hostname",
    "MACAddress",
    "Protocol",
    "Hash",
    "Timestamp",
    "Severity",
    "Direction",
    "FlowState",
    "ConfidenceScore",
    "PacketObserved",
    "NetworkFlowObserved",
    "DNSTransactionObserved",
    "HTTPRequestObserved",
    "TLSHandshakeObserved",
    "CertificateObserved",
    "SessionObserved",
    "ServiceObserved",
    "HostDiscovered",
    "HostFingerprint",
    "OperatingSystemObserved",
    "PortObserved",
    "ServiceFingerprint",
    "DeviceObserved",
    "InterfaceObserved",
    "MACAddressObserved",
    "HostnameObserved",
    "VulnerabilityDetected",
    "ToolObserved",
    "TechniqueObserved",
    "CanonicalValidator",
    "DeadLetterQueue",
    "NormalizationPipeline",
]
