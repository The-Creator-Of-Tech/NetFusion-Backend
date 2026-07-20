"""
Source Trust Model for NetFusion Intelligence feeds.
Defines TrustProfile, TrustLevel, VerificationRequirements, and TransportRequirements.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class TransportRequirements:
    """
    Transport level requirements for feed retrieval.
    """
    require_https: bool = True
    min_tls_version: str = "1.2"
    allow_redirects: bool = True
    allowed_domains: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransportRequirements":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class VerificationRequirements:
    """
    Integrity and authenticity requirements for feed datasets.
    """
    require_signature: bool = False
    allowed_signature_algorithms: List[str] = field(
        default_factory=lambda: ["GPG", "PGP", "SHA256_MANIFEST", "SHA512_MANIFEST"]
    )
    require_checksum: bool = True
    checksum_algorithm: str = "SHA256"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationRequirements":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class TrustProfile:
    """
    Trust Profile definition associated with an intelligence feed source.
    """
    publisher: str
    organization: str
    official_url: str
    expected_domain: str
    expected_certificate: Optional[str] = None  # Cert SHA256 fingerprint / Subject CN / Public key hash
    expected_signing_authority: Optional[str] = None  # CA name / CA Fingerprint
    trust_level: TrustLevel = TrustLevel.MEDIUM
    verification_requirements: VerificationRequirements = field(default_factory=VerificationRequirements)
    transport_requirements: TransportRequirements = field(default_factory=TransportRequirements)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["trust_level"] = self.trust_level.value if isinstance(self.trust_level, TrustLevel) else self.trust_level
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustProfile":
        if not data:
            raise ValueError("Trust profile data cannot be empty")
        d = dict(data)
        if "trust_level" in d and isinstance(d["trust_level"], str):
            d["trust_level"] = TrustLevel(d["trust_level"])
        if "verification_requirements" in d and isinstance(d["verification_requirements"], dict):
            d["verification_requirements"] = VerificationRequirements.from_dict(d["verification_requirements"])
        if "transport_requirements" in d and isinstance(d["transport_requirements"], dict):
            d["transport_requirements"] = TransportRequirements.from_dict(d["transport_requirements"])
        return cls(**d)
