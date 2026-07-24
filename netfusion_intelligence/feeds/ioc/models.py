"""
IL-7 IOC Enterprise Intelligence — Domain Models.
Immutable dataclasses representing every IOC entity, relationship, reputation,
sighting, and source record.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import uuid


# ---------------------------------------------------------------------------
# IOC Type Taxonomy
# ---------------------------------------------------------------------------

class IocType(str, Enum):
    """Exhaustive taxonomy of supported Indicator of Compromise types."""
    # Network indicators
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    URI = "uri"
    # Identity
    EMAIL = "email"
    # Hashes
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    # TLS
    TLS_CERT_FINGERPRINT = "tls_cert_fingerprint"
    JA3 = "ja3"
    JA3S = "ja3s"
    # Host artifacts
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    WINDOWS_SERVICE_NAME = "windows_service_name"
    WINDOWS_EVENT_ID = "windows_event_id"
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    USER_AGENT = "user_agent"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"
    SCHEDULED_TASK = "scheduled_task"
    NAMED_PIPE = "named_pipe"
    # Detection rules
    YARA_RULE_REF = "yara_rule_ref"
    SIGMA_RULE_REF = "sigma_rule_ref"
    SURICATA_SID = "suricata_sid"
    SNORT_SID = "snort_sid"
    # ATT&CK
    ATTACK_DATA_SOURCE = "attack_data_source"
    # Threat intel
    MALWARE_FAMILY = "malware_family"
    CAMPAIGN = "campaign"
    THREAT_ACTOR_REF = "threat_actor_ref"

    @classmethod
    def all_values(cls) -> List[str]:
        return [m.value for m in cls]

    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value.lower() in cls.all_values()


class IocSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class IocStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    WHITELISTED = "whitelisted"
    UNDER_REVIEW = "under_review"


# ---------------------------------------------------------------------------
# Core IOC Entity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocEntity:
    """
    Canonical IOC entity capturing every available field.
    Primary unit of the IL-7 pipeline — every indicator becomes one of these.
    """
    # Identity
    ioc_id: str                                  # Internal UUID
    ioc_type: str                                # IocType value
    value: str                                   # Normalized indicator value
    value_raw: str = ""                          # Original un-normalized value

    # Classification
    severity: str = IocSeverity.UNKNOWN.value
    confidence: float = 0.5                      # 0.0–1.0
    priority: int = 3                            # 1 (highest) – 5 (lowest)
    status: str = IocStatus.ACTIVE.value

    # Reputation
    reputation_score: float = 0.0               # 0.0 (benign) – 10.0 (malicious)
    false_positive_score: float = 0.0           # 0.0–1.0
    source_count: int = 1

    # Temporal
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_updated: Optional[str] = None
    expiration: Optional[str] = None

    # Attribution
    malware_families: Tuple[str, ...] = field(default_factory=tuple)
    campaigns: Tuple[str, ...] = field(default_factory=tuple)
    threat_actors: Tuple[str, ...] = field(default_factory=tuple)
    attack_technique_ids: Tuple[str, ...] = field(default_factory=tuple)
    capec_ids: Tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: Tuple[str, ...] = field(default_factory=tuple)
    cve_ids: Tuple[str, ...] = field(default_factory=tuple)

    # Metadata
    tags: Tuple[str, ...] = field(default_factory=tuple)
    description: Optional[str] = None
    tlp: Optional[str] = None                   # TLP:WHITE / GREEN / AMBER / RED
    provider: Optional[str] = None              # Originating provider/feed
    provider_id: Optional[str] = None           # Provider-assigned indicator ID
    source_url: Optional[str] = None
    aliases: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "value_raw": self.value_raw,
            "severity": self.severity,
            "confidence": self.confidence,
            "priority": self.priority,
            "status": self.status,
            "reputation_score": self.reputation_score,
            "false_positive_score": self.false_positive_score,
            "source_count": self.source_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_updated": self.last_updated,
            "expiration": self.expiration,
            "malware_families": list(self.malware_families),
            "campaigns": list(self.campaigns),
            "threat_actors": list(self.threat_actors),
            "attack_technique_ids": list(self.attack_technique_ids),
            "capec_ids": list(self.capec_ids),
            "cwe_ids": list(self.cwe_ids),
            "cve_ids": list(self.cve_ids),
            "tags": list(self.tags),
            "description": self.description,
            "tlp": self.tlp,
            "provider": self.provider,
            "provider_id": self.provider_id,
            "source_url": self.source_url,
            "aliases": list(self.aliases),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IocEntity":
        return cls(
            ioc_id=d.get("ioc_id") or str(uuid.uuid4()),
            ioc_type=d.get("ioc_type", ""),
            value=d.get("value", ""),
            value_raw=d.get("value_raw", d.get("value", "")),
            severity=d.get("severity", IocSeverity.UNKNOWN.value),
            confidence=float(d.get("confidence", 0.5)),
            priority=int(d.get("priority", 3)),
            status=d.get("status", IocStatus.ACTIVE.value),
            reputation_score=float(d.get("reputation_score", 0.0)),
            false_positive_score=float(d.get("false_positive_score", 0.0)),
            source_count=int(d.get("source_count", 1)),
            first_seen=d.get("first_seen"),
            last_seen=d.get("last_seen"),
            last_updated=d.get("last_updated"),
            expiration=d.get("expiration"),
            malware_families=tuple(d.get("malware_families", [])),
            campaigns=tuple(d.get("campaigns", [])),
            threat_actors=tuple(d.get("threat_actors", [])),
            attack_technique_ids=tuple(d.get("attack_technique_ids", [])),
            capec_ids=tuple(d.get("capec_ids", [])),
            cwe_ids=tuple(d.get("cwe_ids", [])),
            cve_ids=tuple(d.get("cve_ids", [])),
            tags=tuple(d.get("tags", [])),
            description=d.get("description"),
            tlp=d.get("tlp"),
            provider=d.get("provider"),
            provider_id=d.get("provider_id"),
            source_url=d.get("source_url"),
            aliases=tuple(d.get("aliases", [])),
        )


# ---------------------------------------------------------------------------
# IOC Relationship
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocRelationship:
    """Bidirectional relationship between two IOC entities or between an IOC and another entity."""
    relationship_id: str
    source_ioc_id: str
    target_id: str                # IOC ID or external entity ID (e.g. T1059)
    target_type: str              # "ioc", "attack_technique", "malware", "campaign", "cve", etc.
    relationship_type: str        # "ip_to_domain", "hash_to_file", "ioc_to_malware", etc.
    confidence: float = 1.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: Optional[str] = None
    provider: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_ioc_id": self.source_ioc_id,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
            "provider": self.provider,
        }

    @classmethod
    def create(
        cls,
        source_ioc_id: str,
        target_id: str,
        target_type: str,
        relationship_type: str,
        confidence: float = 1.0,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        description: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> "IocRelationship":
        return cls(
            relationship_id=str(uuid.uuid4()),
            source_ioc_id=source_ioc_id,
            target_id=target_id,
            target_type=target_type,
            relationship_type=relationship_type,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            description=description,
            provider=provider,
        )


# ---------------------------------------------------------------------------
# IOC Reputation Record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocReputation:
    """Reputation record for a canonical IOC entity, tracking score history and sources."""
    ioc_id: str
    reputation_score: float        # 0.0 (benign) – 10.0 (malicious)
    false_positive_score: float    # 0.0 – 1.0
    confidence: float              # 0.0 – 1.0
    severity: str
    priority: int
    source_count: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_updated: Optional[str] = None
    expiration: Optional[str] = None
    contributing_sources: Tuple[str, ...] = field(default_factory=tuple)
    reputation_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "reputation_score": self.reputation_score,
            "false_positive_score": self.false_positive_score,
            "confidence": self.confidence,
            "severity": self.severity,
            "priority": self.priority,
            "source_count": self.source_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_updated": self.last_updated,
            "expiration": self.expiration,
            "contributing_sources": list(self.contributing_sources),
            "reputation_notes": self.reputation_notes,
        }


# ---------------------------------------------------------------------------
# IOC Sighting
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocSighting:
    """A sighting observation of an IOC in the wild."""
    sighting_id: str
    ioc_id: str
    observed_at: str
    observation_source: str           # "SIEM", "EDR", "Firewall", "manual", etc.
    organization: Optional[str] = None
    location: Optional[str] = None    # Country code or geo region
    environment: Optional[str] = None # "production", "staging", "lab"
    count: int = 1
    description: Optional[str] = None
    provider: Optional[str] = None
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sighting_id": self.sighting_id,
            "ioc_id": self.ioc_id,
            "observed_at": self.observed_at,
            "observation_source": self.observation_source,
            "organization": self.organization,
            "location": self.location,
            "environment": self.environment,
            "count": self.count,
            "description": self.description,
            "provider": self.provider,
            "confidence": self.confidence,
        }

    @classmethod
    def create(
        cls,
        ioc_id: str,
        observed_at: str,
        observation_source: str,
        organization: Optional[str] = None,
        location: Optional[str] = None,
        environment: Optional[str] = None,
        count: int = 1,
        description: Optional[str] = None,
        provider: Optional[str] = None,
        confidence: float = 1.0,
    ) -> "IocSighting":
        return cls(
            sighting_id=str(uuid.uuid4()),
            ioc_id=ioc_id,
            observed_at=observed_at,
            observation_source=observation_source,
            organization=organization,
            location=location,
            environment=environment,
            count=count,
            description=description,
            provider=provider,
            confidence=confidence,
        )


# ---------------------------------------------------------------------------
# IOC Source Record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocSource:
    """Records a specific source that contributed an indicator."""
    source_id: str
    ioc_id: str
    provider: str
    provider_type: str            # "misp", "opencti", "stix", "taxii", "csv", "json", "yaml", "manual"
    provider_indicator_id: Optional[str] = None
    confidence: float = 0.5
    tlp: Optional[str] = None
    contributed_at: Optional[str] = None
    source_url: Optional[str] = None
    raw_value: Optional[str] = None   # Original unprocessed indicator value from provider

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "ioc_id": self.ioc_id,
            "provider": self.provider,
            "provider_type": self.provider_type,
            "provider_indicator_id": self.provider_indicator_id,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "contributed_at": self.contributed_at,
            "source_url": self.source_url,
            "raw_value": self.raw_value,
        }

    @classmethod
    def create(
        cls,
        ioc_id: str,
        provider: str,
        provider_type: str,
        confidence: float = 0.5,
        tlp: Optional[str] = None,
        contributed_at: Optional[str] = None,
        source_url: Optional[str] = None,
        provider_indicator_id: Optional[str] = None,
        raw_value: Optional[str] = None,
    ) -> "IocSource":
        return cls(
            source_id=str(uuid.uuid4()),
            ioc_id=ioc_id,
            provider=provider,
            provider_type=provider_type,
            provider_indicator_id=provider_indicator_id,
            confidence=confidence,
            tlp=tlp,
            contributed_at=contributed_at,
            source_url=source_url,
            raw_value=raw_value,
        )


# ---------------------------------------------------------------------------
# Provider Registration Record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IocProvider:
    """Metadata record for a registered IOC intelligence provider."""
    provider_id: str
    name: str
    provider_type: str             # "misp", "opencti", "stix", "taxii", "csv", etc.
    description: Optional[str] = None
    url: Optional[str] = None
    enabled: bool = True
    default_confidence: float = 0.5
    default_tlp: str = "TLP:WHITE"
    tags: Tuple[str, ...] = field(default_factory=tuple)
    version: Optional[str] = None
    last_synced: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "name": self.name,
            "provider_type": self.provider_type,
            "description": self.description,
            "url": self.url,
            "enabled": self.enabled,
            "default_confidence": self.default_confidence,
            "default_tlp": self.default_tlp,
            "tags": list(self.tags),
            "version": self.version,
            "last_synced": self.last_synced,
        }
