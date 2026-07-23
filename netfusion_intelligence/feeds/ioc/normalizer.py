"""
IL-7 IOC Normalizer.
Converts raw parsed indicator dicts into canonical IocEntity domain models.
Applies comprehensive normalization:
  - IPv4/IPv6 canonicalization
  - Domain/hostname lowercasing + IDN/Punycode
  - URL/URI normalization
  - Hash uppercase + format validation
  - Email lowercasing
  - Windows/Unix path normalization
  - Registry key normalization
  - Unicode/whitespace normalization
Duplicate elimination is performed here via a normalized-value fingerprint.
"""

import hashlib
import ipaddress
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from netfusion_intelligence.feeds.ioc.models import IocEntity, IocSeverity, IocStatus, IocType


class IocNormalizer:
    """
    Normalizes raw parsed indicator dicts into IocEntity domain models.
    Deduplicates within the current dataset using a (type, normalized_value) fingerprint.
    """

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize all parsed indicators.

        Input:  {"indicators": [...raw dicts...], "provider_metas": [...], ...}
        Output: {
            "entities": {fingerprint: IocEntity},
            "relationships": [],
            "record_count": int,
            "duplicate_count": int,
            "provider_metas": [...],
        }
        """
        raw_indicators: List[Dict[str, Any]] = parsed_data.get("indicators", [])
        provider_metas = parsed_data.get("provider_metas", [])

        entities: Dict[str, IocEntity] = {}
        seen_fingerprints: Set[str] = set()
        duplicate_count = 0

        for raw in raw_indicators:
            try:
                entity = self._normalize_one(raw)
            except Exception:
                continue
            if entity is None:
                continue

            fp = self._fingerprint(entity.ioc_type, entity.value)
            if fp in seen_fingerprints:
                duplicate_count += 1
                # Merge: keep the entity with higher confidence
                existing = entities.get(fp)
                if existing and raw.get("confidence", 0) > existing.confidence:
                    entities[fp] = entity
                continue

            seen_fingerprints.add(fp)
            entities[fp] = entity

        return {
            "entities": entities,
            "relationships": [],
            "record_count": len(entities),
            "duplicate_count": duplicate_count,
            "provider_metas": provider_metas,
        }

    def _normalize_one(self, raw: Dict[str, Any]) -> Optional[IocEntity]:
        """Normalize a single raw indicator dict into an IocEntity."""
        ioc_type_raw = (raw.get("type") or "").strip().lower()
        value_raw = (raw.get("value") or "").strip()

        if not ioc_type_raw or not value_raw:
            return None

        # Normalize value by type
        normalized_value = self._normalize_value(ioc_type_raw, value_raw)
        if not normalized_value:
            return None

        # Validate type membership
        if not IocType.is_valid(ioc_type_raw):
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        confidence = float(raw.get("confidence", 0.5))
        confidence = min(1.0, max(0.0, confidence))

        severity = self._normalize_severity(raw.get("severity", ""))
        priority = int(raw.get("priority", 3))
        priority = max(1, min(5, priority))

        tags = self._normalize_tags(raw.get("tags", []))
        malware_families = self._normalize_list(raw.get("malware_families", []))
        campaigns = self._normalize_list(raw.get("campaigns", []))
        threat_actors = self._normalize_list(raw.get("threat_actors", []))
        attack_ids = self._normalize_list(raw.get("attack_technique_ids", []))
        capec_ids = self._normalize_list(raw.get("capec_ids", []))
        cwe_ids = self._normalize_list(raw.get("cwe_ids", []))
        cve_ids = self._normalize_list(raw.get("cve_ids", []))

        return IocEntity(
            ioc_id=str(uuid.uuid4()),
            ioc_type=ioc_type_raw,
            value=normalized_value,
            value_raw=value_raw,
            severity=severity,
            confidence=confidence,
            priority=priority,
            status=IocStatus.ACTIVE.value,
            reputation_score=self._initial_reputation(confidence, severity),
            false_positive_score=0.0,
            source_count=1,
            first_seen=raw.get("first_seen") or now_iso,
            last_seen=raw.get("last_seen") or now_iso,
            last_updated=now_iso,
            expiration=raw.get("expiration"),
            malware_families=tuple(malware_families),
            campaigns=tuple(campaigns),
            threat_actors=tuple(threat_actors),
            attack_technique_ids=tuple(attack_ids),
            capec_ids=tuple(capec_ids),
            cwe_ids=tuple(cwe_ids),
            cve_ids=tuple(cve_ids),
            tags=tuple(tags),
            description=self._clean_text(raw.get("description", "")),
            tlp=raw.get("tlp", "TLP:WHITE"),
            provider=raw.get("provider", ""),
            provider_id=raw.get("provider_indicator_id", ""),
            source_url=raw.get("source_url", ""),
            aliases=tuple(),
        )

    # ------------------------------------------------------------------
    # Value normalization by type
    # ------------------------------------------------------------------

    def _normalize_value(self, ioc_type: str, value: str) -> Optional[str]:
        """Dispatch to type-specific normalization. Returns None on invalid."""
        try:
            if ioc_type == IocType.IPV4.value:
                return self._normalize_ipv4(value)
            if ioc_type == IocType.IPV6.value:
                return self._normalize_ipv6(value)
            if ioc_type in (IocType.DOMAIN.value, IocType.HOSTNAME.value):
                return self._normalize_domain(value)
            if ioc_type in (IocType.URL.value, IocType.URI.value):
                return self._normalize_url(value)
            if ioc_type == IocType.EMAIL.value:
                return self._normalize_email(value)
            if ioc_type in (IocType.MD5.value, IocType.SHA1.value,
                            IocType.SHA256.value, IocType.SHA512.value):
                return self._normalize_hash(value)
            if ioc_type == IocType.REGISTRY_KEY.value:
                return self._normalize_registry_key(value)
            if ioc_type == IocType.FILE_PATH.value:
                return self._normalize_file_path(value)
            # Default: unicode normalize + strip
            return self._unicode_normalize(value)
        except Exception:
            return None

    @staticmethod
    def _normalize_ipv4(value: str) -> Optional[str]:
        """Canonicalize IPv4 address. Strips port, CIDR notation preserved."""
        v = value.strip()
        # Strip port if present (e.g. 1.2.3.4:80)
        if ":" in v and "/" not in v:
            v = v.rsplit(":", 1)[0]
        try:
            if "/" in v:
                net = ipaddress.IPv4Network(v, strict=False)
                return str(net)
            addr = ipaddress.IPv4Address(v)
            return str(addr)
        except ValueError:
            return None

    @staticmethod
    def _normalize_ipv6(value: str) -> Optional[str]:
        """Canonicalize IPv6 address."""
        v = value.strip()
        try:
            if "/" in v:
                net = ipaddress.IPv6Network(v, strict=False)
                return str(net)
            addr = ipaddress.IPv6Address(v)
            return str(addr)
        except ValueError:
            return None

    @staticmethod
    def _normalize_domain(value: str) -> Optional[str]:
        """Lowercase, strip leading/trailing dots, apply Punycode for IDNs."""
        v = value.strip().lower().rstrip(".")
        # Remove protocol prefix if accidentally included
        for prefix in ("http://", "https://", "ftp://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        # Strip port
        if ":" in v:
            v = v.split(":")[0]
        # Strip path
        if "/" in v:
            v = v.split("/")[0]
        if not v:
            return None
        # Punycode encode IDN labels
        try:
            v = v.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass  # Already ASCII or encoding failed — keep as-is
        # Basic domain format check
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", v):
            # May be hostname without dots — still allow
            if not re.match(r"^[a-z0-9\-\.]+$", v):
                return None
        return v

    @staticmethod
    def _normalize_url(value: str) -> Optional[str]:
        """Normalize URL: strip whitespace, normalize unicode, preserve structure."""
        import urllib.parse
        v = value.strip()
        v = unicodedata.normalize("NFC", v)
        # Attempt to parse and reconstruct for canonical form
        try:
            parsed = urllib.parse.urlparse(v)
            if not parsed.scheme:
                return None
            # Lowercase scheme and netloc
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query
            fragment = parsed.fragment
            reconstructed = urllib.parse.urlunparse((scheme, netloc, path, "", query, fragment))
            return reconstructed if reconstructed else v
        except Exception:
            return v

    @staticmethod
    def _normalize_email(value: str) -> Optional[str]:
        """Lowercase email address, strip whitespace."""
        v = value.strip().lower()
        if "@" not in v:
            return None
        parts = v.split("@", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return None
        return f"{parts[0]}@{parts[1]}"

    @staticmethod
    def _normalize_hash(value: str) -> Optional[str]:
        """Uppercase hash, strip whitespace, validate hex chars."""
        v = value.strip().upper()
        if not re.match(r"^[0-9A-F]+$", v):
            return None
        valid_lengths = {32, 40, 64, 128}  # MD5, SHA1, SHA256, SHA512
        if len(v) not in valid_lengths:
            return None
        return v

    @staticmethod
    def _normalize_registry_key(value: str) -> Optional[str]:
        """Normalize Windows registry key: uppercase hive, preserve rest."""
        v = value.strip()
        # Normalize hive abbreviations
        hive_map = {
            "HKLM": "HKEY_LOCAL_MACHINE",
            "HKCU": "HKEY_CURRENT_USER",
            "HKCR": "HKEY_CLASSES_ROOT",
            "HKU": "HKEY_USERS",
            "HKCC": "HKEY_CURRENT_CONFIG",
        }
        for abbrev, full in hive_map.items():
            if v.upper().startswith(abbrev + "\\"):
                v = full + v[len(abbrev):]
                break
        return v if v else None

    @staticmethod
    def _normalize_file_path(value: str) -> Optional[str]:
        """Normalize file path: strip extra whitespace, unicode NFC."""
        v = value.strip()
        v = unicodedata.normalize("NFC", v)
        # Normalize Windows backslash sequences
        v = re.sub(r"\\+", "\\\\", v)
        return v if v else None

    @staticmethod
    def _unicode_normalize(value: str) -> str:
        """Apply NFC unicode normalization and strip whitespace."""
        return unicodedata.normalize("NFC", value.strip())

    # ------------------------------------------------------------------
    # Supporting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(ioc_type: str, normalized_value: str) -> str:
        """Deterministic fingerprint for deduplication."""
        key = f"{ioc_type.lower()}::{normalized_value.lower()}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_severity(raw: Any) -> str:
        if not raw:
            return IocSeverity.UNKNOWN.value
        v = str(raw).lower().strip()
        mapping = {
            "critical": IocSeverity.CRITICAL.value,
            "high": IocSeverity.HIGH.value,
            "medium": IocSeverity.MEDIUM.value,
            "med": IocSeverity.MEDIUM.value,
            "low": IocSeverity.LOW.value,
            "info": IocSeverity.INFO.value,
            "informational": IocSeverity.INFO.value,
        }
        return mapping.get(v, IocSeverity.UNKNOWN.value)

    @staticmethod
    def _initial_reputation(confidence: float, severity: str) -> float:
        """Compute initial reputation score from confidence and severity."""
        base = confidence * 5.0  # 0-5
        severity_boost = {
            IocSeverity.CRITICAL.value: 5.0,
            IocSeverity.HIGH.value: 4.0,
            IocSeverity.MEDIUM.value: 2.0,
            IocSeverity.LOW.value: 1.0,
            IocSeverity.INFO.value: 0.5,
        }
        boost = severity_boost.get(severity, 0.0)
        return min(10.0, round(base + boost * 0.5, 2))

    @staticmethod
    def _normalize_tags(tags: Any) -> List[str]:
        if isinstance(tags, list):
            return [str(t).strip().lower() for t in tags if t and str(t).strip()]
        if isinstance(tags, str):
            return [t.strip().lower() for t in tags.split(",") if t.strip()]
        return []

    @staticmethod
    def _normalize_list(items: Any) -> List[str]:
        if isinstance(items, list):
            return [str(i).strip() for i in items if i and str(i).strip()]
        if isinstance(items, str) and items.strip():
            return [items.strip()]
        return []

    @staticmethod
    def _clean_text(text: Any) -> Optional[str]:
        if not text:
            return None
        return unicodedata.normalize("NFC", str(text).strip()) or None
