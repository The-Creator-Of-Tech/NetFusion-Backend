import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from .base import CanonicalValueObject


class Direction(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL = "INTERNAL"
    LATERAL = "LATERAL"
    UNKNOWN = "UNKNOWN"


class FlowState(str, Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"
    RESET = "RESET"
    TIMEOUT = "TIMEOUT"
    ACTIVE = "ACTIVE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class IPAddress(CanonicalValueObject):
    value: str
    version: str = "v4"

    def __post_init__(self):
        try:
            ip_obj = ipaddress.ip_address(self.value)
            object.__setattr__(self, "version", f"v{ip_obj.version}")
        except ValueError:
            raise ValueError(f"Invalid IPAddress format: '{self.value}'")


@dataclass(frozen=True)
class Port(CanonicalValueObject):
    value: int

    def __post_init__(self):
        if not (0 <= self.value <= 65535):
            raise ValueError(f"Port number out of range [0-65535]: {self.value}")


@dataclass(frozen=True)
class Hostname(CanonicalValueObject):
    value: str

    def __post_init__(self):
        if not self.value or len(self.value) > 253:
            raise ValueError(f"Invalid Hostname length: '{self.value}'")


@dataclass(frozen=True)
class MACAddress(CanonicalValueObject):
    value: str

    def __post_init__(self):
        normalized = self.value.upper().replace("-", ":")
        mac_regex = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
        if not mac_regex.match(normalized):
            raise ValueError(f"Invalid MACAddress format: '{self.value}'")
        object.__setattr__(self, "value", normalized)


@dataclass(frozen=True)
class Protocol(CanonicalValueObject):
    name: str
    iana_number: Optional[int] = None

    def __post_init__(self):
        normalized_name = self.name.upper()
        object.__setattr__(self, "name", normalized_name)


@dataclass(frozen=True)
class Hash(CanonicalValueObject):
    algorithm: str
    hex_value: str

    def __post_init__(self):
        alg = self.algorithm.upper()
        val = self.hex_value.lower()
        lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}
        if alg in lengths and len(val) != lengths[alg]:
            raise ValueError(f"Invalid {alg} hash length for '{val}' (expected {lengths[alg]})")
        object.__setattr__(self, "algorithm", alg)
        object.__setattr__(self, "hex_value", val)


@dataclass(frozen=True)
class Timestamp(CanonicalValueObject):
    iso_string: str

    def __post_init__(self):
        if not self.iso_string:
            raise ValueError("Timestamp ISO string cannot be empty")


@dataclass(frozen=True)
class ConfidenceScore(CanonicalValueObject):
    score: float

    def __post_init__(self):
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"ConfidenceScore must be in range [0.0, 1.0], got {self.score}")
