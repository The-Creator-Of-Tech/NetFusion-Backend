"""
IL-7 IOC Validator.
Enforces structural, format, and cross-reference validation rules
on the normalized IOC dataset before it is stored.
Rejects: malformed IPs, invalid domains, malformed URLs, bad hashes,
         duplicate indicators, unknown ATT&CK/CAPEC/CWE/CVE references.
"""

import re
import ipaddress
from typing import Any, Dict, Set

from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocType, IocSeverity, IocStatus


class IocValidator(ValidatorInterface):
    """
    Validates normalized IOC datasets against structural and domain rules.
    """

    # Known valid ATT&CK technique pattern
    _ATK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
    _CAPEC_RE = re.compile(r"^CAPEC-\d+$", re.IGNORECASE)
    _CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
    _CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    def validate(self, dataset: Any) -> ValidationResult:
        result = ValidationResult()

        if not isinstance(dataset, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Normalized IOC dataset is not a dict")
            return result

        entities: Dict[str, IocEntity] = dataset.get("entities", {})
        result.total_checked = len(entities)

        if not entities:
            # Empty dataset is valid (no new indicators)
            result.rules_passed = 1
            return result

        seen_fingerprints: Set[str] = set()

        for fp, entity in entities.items():
            # --- Required fields ---
            if not entity.ioc_id:
                result.add_error("MISSING_IOC_ID", "IOC entity missing ioc_id", entity_id=fp)
                continue
            if not entity.ioc_type:
                result.add_error("MISSING_IOC_TYPE", f"IOC '{entity.ioc_id}' missing ioc_type",
                                 entity_id=entity.ioc_id, field_name="ioc_type")
            if not entity.value:
                result.add_error("MISSING_VALUE", f"IOC '{entity.ioc_id}' missing value",
                                 entity_id=entity.ioc_id, field_name="value")
                continue

            # --- Type validity ---
            if not IocType.is_valid(entity.ioc_type):
                result.add_error("INVALID_IOC_TYPE",
                                 f"IOC type '{entity.ioc_type}' is not recognized",
                                 entity_id=entity.ioc_id, field_name="ioc_type")

            # --- Duplicate fingerprint within this batch ---
            if fp in seen_fingerprints:
                result.add_error("DUPLICATE_INDICATOR",
                                 f"Duplicate indicator: type={entity.ioc_type} value={entity.value}",
                                 entity_id=entity.ioc_id)
            else:
                seen_fingerprints.add(fp)

            # --- Type-specific format validation ---
            self._validate_by_type(entity, result)

            # --- Confidence range ---
            if not (0.0 <= entity.confidence <= 1.0):
                result.add_error("CONFIDENCE_OUT_OF_RANGE",
                                 f"Confidence {entity.confidence} outside [0.0, 1.0]",
                                 entity_id=entity.ioc_id, field_name="confidence")

            # --- Severity ---
            valid_severities = {s.value for s in IocSeverity}
            if entity.severity and entity.severity not in valid_severities:
                result.add_warning("INVALID_SEVERITY",
                                   f"Unrecognized severity '{entity.severity}'",
                                   entity_id=entity.ioc_id)

            # --- Cross-reference validity (warnings for broken refs) ---
            for tech_id in entity.attack_technique_ids:
                if not self._ATK_RE.match(tech_id):
                    result.add_warning("INVALID_ATTACK_ID",
                                       f"ATT&CK ID '{tech_id}' does not match T####[.###]",
                                       entity_id=entity.ioc_id)
            for capec_id in entity.capec_ids:
                if not self._CAPEC_RE.match(capec_id):
                    result.add_warning("INVALID_CAPEC_ID",
                                       f"CAPEC ID '{capec_id}' does not match CAPEC-###",
                                       entity_id=entity.ioc_id)
            for cwe_id in entity.cwe_ids:
                if not self._CWE_RE.match(cwe_id):
                    result.add_warning("INVALID_CWE_ID",
                                       f"CWE ID '{cwe_id}' does not match CWE-###",
                                       entity_id=entity.ioc_id)
            for cve_id in entity.cve_ids:
                if not self._CVE_RE.match(cve_id):
                    result.add_warning("INVALID_CVE_ID",
                                       f"CVE ID '{cve_id}' does not match CVE-####-####",
                                       entity_id=entity.ioc_id)

        if result.is_valid:
            result.rules_passed = result.total_checked
        else:
            result.rules_failed = len(result.errors)
            result.rules_passed = max(0, result.total_checked - result.rules_failed)

        return result

    def _validate_by_type(self, entity: IocEntity, result: ValidationResult) -> None:
        t = entity.ioc_type
        v = entity.value

        if t == IocType.IPV4.value:
            if not self._valid_ipv4(v):
                result.add_error("INVALID_IPV4", f"Malformed IPv4: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.IPV6.value:
            if not self._valid_ipv6(v):
                result.add_error("INVALID_IPV6", f"Malformed IPv6: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t in (IocType.DOMAIN.value, IocType.HOSTNAME.value):
            if not self._valid_domain(v):
                result.add_error("INVALID_DOMAIN", f"Malformed domain/hostname: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t in (IocType.URL.value, IocType.URI.value):
            if not self._valid_url(v):
                result.add_error("INVALID_URL", f"Malformed URL/URI: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.EMAIL.value:
            if not self._valid_email(v):
                result.add_error("INVALID_EMAIL", f"Malformed email: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.MD5.value:
            if not re.match(r"^[0-9A-Fa-f]{32}$", v):
                result.add_error("INVALID_MD5", f"Malformed MD5 hash: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.SHA1.value:
            if not re.match(r"^[0-9A-Fa-f]{40}$", v):
                result.add_error("INVALID_SHA1", f"Malformed SHA-1 hash: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.SHA256.value:
            if not re.match(r"^[0-9A-Fa-f]{64}$", v):
                result.add_error("INVALID_SHA256", f"Malformed SHA-256 hash: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

        elif t == IocType.SHA512.value:
            if not re.match(r"^[0-9A-Fa-f]{128}$", v):
                result.add_error("INVALID_SHA512", f"Malformed SHA-512 hash: '{v}'",
                                 entity_id=entity.ioc_id, field_name="value")

    @staticmethod
    def _valid_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value.split("/")[0].split(":")[0])
            return True
        except ValueError:
            return False

    @staticmethod
    def _valid_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value.split("/")[0])
            return True
        except ValueError:
            return False

    @staticmethod
    def _valid_domain(value: str) -> bool:
        return bool(re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?$",
            value
        ))

    @staticmethod
    def _valid_url(value: str) -> bool:
        return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://\S+$", value))

    @staticmethod
    def _valid_email(value: str) -> bool:
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$", value))
