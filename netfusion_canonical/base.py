import hashlib
import json
import time
import uuid
from abc import ABC
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class CanonicalValueObject(ABC):
    """Abstract immutable value object base."""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalDomainObject(ABC):
    """
    Abstract Root Canonical Domain Object.
    Guarantees standard metadata lineage across all ingested telemetry.
    """

    object_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0.0"
    canonical_type: str = "CanonicalDomainObject"
    timestamp_observed: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    timestamp_normalized: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    collector_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collector_type: str = "TShark"
    tenant_id: str = "default-tenant"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    labels: Dict[str, str] = field(default_factory=dict)
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    checksum: Optional[str] = None

    def compute_checksum(self) -> str:
        """Calculates deterministic SHA-256 checksum over object content."""
        data_dict = self.to_dict()
        data_dict.pop("checksum", None)
        serialized = json.dumps(data_dict, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Computes and assigns cryptographic checksum."""
        self.checksum = self.compute_checksum()

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if isinstance(v, CanonicalValueObject):
                res[k] = v.to_dict()
            elif isinstance(v, list):
                res[k] = [
                    elem.to_dict() if isinstance(elem, CanonicalValueObject) else elem
                    for elem in v
                ]
            else:
                res[k] = v
        return res
