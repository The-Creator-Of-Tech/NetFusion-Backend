import re
from typing import List, Tuple
from .base import CanonicalDomainObject
from .network import PacketObserved, NetworkFlowObserved, DNSTransactionObserved, HTTPRequestObserved

UUID_V4_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


class CanonicalValidator:
    """Canonical Validator enforcing type invariants, regex constraints, and cross-field rules."""

    @staticmethod
    def validate(obj: CanonicalDomainObject) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not isinstance(obj, CanonicalDomainObject):
            return False, ["Object does not inherit from CanonicalDomainObject"]

        # Validate IDs
        for attr_name in ("object_id", "collector_id", "correlation_id"):
            val = getattr(obj, attr_name, None)
            if not val or not isinstance(str(val), str) or len(str(val).strip()) == 0:
                errors.append(f"Field '{attr_name}' must be a non-empty string ID, got '{val}'")

        # Validate Timestamps
        if not getattr(obj, "timestamp_observed", None):
            errors.append("Field 'timestamp_observed' is missing or empty")

        # Specific Cross-Field Validation Rules
        if isinstance(obj, PacketObserved):
            if obj.capture_length > obj.frame_length:
                errors.append(f"PacketObserved capture_length ({obj.capture_length}) cannot exceed frame_length ({obj.frame_length})")

        if isinstance(obj, NetworkFlowObserved):
            if obj.bytes_sent < 0 or obj.bytes_received < 0:
                errors.append("NetworkFlowObserved bytes sent/received cannot be negative")

        if isinstance(obj, HTTPRequestObserved):
            if not (100 <= obj.status_code <= 599):
                errors.append(f"HTTPRequestObserved status_code out of range [100-599]: {obj.status_code}")

        # Seal object if valid
        if not errors:
            obj.seal()

        return len(errors) == 0, errors
