"""
IL-7 IOC Parser.
Converts raw provider payloads into a uniform list of raw indicator dicts.
Handles: MISP JSON, OpenCTI JSON, STIX 2.1 bundles, TAXII responses,
         CSV (bytes/str), JSON lists/dicts, YAML, and offline Python structures.
Output of every parse path is always:
    {"indicators": [{"type": str, "value": str, ...}, ...], "provider_meta": {...}}
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional


class IocParser:
    """
    Dispatches to the correct sub-parser based on provider_type.
    Each sub-parser returns a list of raw indicator dicts with at minimum
    {"type": str, "value": str}.
    """

    def parse(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single provider payload dict.

        Args:
            payload: {"raw": Any, "provider_type": str, "provider_id": str,
                      "default_confidence": float, "default_tlp": str, ...}

        Returns:
            {"indicators": [...], "provider_meta": {...}}
        """
        raw = payload.get("raw")
        provider_type = (payload.get("provider_type") or "json").lower()
        provider_id = payload.get("provider_id", "unknown")
        default_conf = float(payload.get("default_confidence", 0.5))
        default_tlp = payload.get("default_tlp", "TLP:WHITE")
        provider_name = payload.get("provider_name", provider_id)

        meta = {
            "provider_id": provider_id,
            "provider_name": provider_name,
            "provider_type": provider_type,
            "default_confidence": default_conf,
            "default_tlp": default_tlp,
        }

        if raw is None:
            return {"indicators": [], "provider_meta": meta}

        try:
            if provider_type == "misp":
                indicators = self._parse_misp(raw, default_conf, default_tlp, provider_id)
            elif provider_type in ("stix", "taxii"):
                indicators = self._parse_stix(raw, default_conf, default_tlp, provider_id)
            elif provider_type == "opencti":
                indicators = self._parse_opencti(raw, default_conf, default_tlp, provider_id)
            elif provider_type == "csv":
                indicators = self._parse_csv(raw, default_conf, default_tlp, provider_id)
            elif provider_type == "yaml":
                indicators = self._parse_yaml(raw, default_conf, default_tlp, provider_id)
            elif provider_type in ("json", "manual"):
                indicators = self._parse_json_generic(raw, default_conf, default_tlp, provider_id)
            else:
                indicators = self._parse_json_generic(raw, default_conf, default_tlp, provider_id)
        except Exception as exc:
            indicators = []
            meta["parse_error"] = str(exc)

        meta["raw_count"] = len(indicators)
        return {"indicators": indicators, "provider_meta": meta}

    def parse_all(self, payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parse all provider payloads and merge into a single result.
        Returns {"indicators": [...], "provider_metas": [...], "total_raw": int}
        """
        all_indicators: List[Dict[str, Any]] = []
        provider_metas: List[Dict[str, Any]] = []

        for payload in payloads:
            result = self.parse(payload)
            all_indicators.extend(result["indicators"])
            provider_metas.append(result["provider_meta"])

        return {
            "indicators": all_indicators,
            "provider_metas": provider_metas,
            "total_raw": len(all_indicators),
        }

    # ------------------------------------------------------------------
    # MISP parser
    # ------------------------------------------------------------------

    def _parse_misp(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        data = raw if isinstance(raw, dict) else json.loads(raw)
        # MISP REST search returns {"response": {"Attribute": [...]}}
        attributes = (
            data.get("response", {}).get("Attribute", [])
            or data.get("Attribute", [])
        )
        indicators = []
        for attr in attributes:
            ioc_type = self._map_misp_type(attr.get("type", ""))
            if not ioc_type:
                continue
            value = str(attr.get("value", "")).strip()
            if not value:
                continue
            indicators.append({
                "type": ioc_type,
                "value": value,
                "confidence": confidence,
                "tlp": tlp,
                "provider": provider_id,
                "provider_indicator_id": str(attr.get("id", "")),
                "tags": [t.get("name", "") for t in attr.get("Tag", []) if t.get("name")],
                "description": attr.get("comment", ""),
                "first_seen": attr.get("first_seen") or attr.get("timestamp"),
                "last_seen": attr.get("last_seen") or attr.get("timestamp"),
                "malware_families": [],
                "campaigns": [],
                "threat_actors": [],
                "attack_technique_ids": [],
            })
        return indicators

    @staticmethod
    def _map_misp_type(misp_type: str) -> Optional[str]:
        """Maps MISP attribute types to IocType values."""
        mapping = {
            "ip-src": "ipv4", "ip-dst": "ipv4",
            "ip-src|port": "ipv4", "ip-dst|port": "ipv4",
            "domain": "domain", "domain|ip": "domain",
            "hostname": "hostname",
            "url": "url", "uri": "uri",
            "email-src": "email", "email-dst": "email",
            "email": "email",
            "md5": "md5", "sha1": "sha1",
            "sha256": "sha256", "sha512": "sha512",
            "filename|md5": "md5", "filename|sha256": "sha256",
            "filename|sha1": "sha1",
            "ja3-fingerprint-md5": "ja3",
            "tls-fingerprint": "tls_cert_fingerprint",
            "mutex": "mutex",
            "regkey": "registry_key",
            "regkey|value": "registry_key",
            "windows-service-name": "windows_service_name",
            "filename": "file_name",
            "filepath": "file_path",
            "user-agent": "user_agent",
            "process-state": "process_name",
            "yara": "yara_rule_ref",
            "sigma": "sigma_rule_ref",
            "snort": "snort_sid",
        }
        return mapping.get(misp_type.lower())

    # ------------------------------------------------------------------
    # STIX 2.1 / TAXII parser
    # ------------------------------------------------------------------

    def _parse_stix(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        data = raw if isinstance(raw, dict) else json.loads(raw)
        objects = data.get("objects", [])
        indicators = []
        for obj in objects:
            obj_type = obj.get("type", "")
            if obj_type != "indicator":
                continue
            pattern = obj.get("pattern", "")
            ioc_type, value = self._extract_from_stix_pattern(pattern)
            if not ioc_type or not value:
                continue
            # Confidence: STIX uses 0-100 integer; normalize to 0.0-1.0
            stix_conf = obj.get("confidence")
            if stix_conf is not None:
                confidence = float(stix_conf) / 100.0
            # TLP from object_marking_refs
            tlp_val = tlp
            for ref in obj.get("object_marking_refs", []):
                if "tlp" in ref.lower():
                    tlp_val = self._stix_tlp_from_ref(ref)
                    break
            indicators.append({
                "type": ioc_type,
                "value": value,
                "confidence": min(1.0, max(0.0, confidence)),
                "tlp": tlp_val,
                "provider": provider_id,
                "provider_indicator_id": obj.get("id", ""),
                "tags": list(obj.get("labels", [])),
                "description": obj.get("description", ""),
                "first_seen": obj.get("valid_from") or obj.get("created"),
                "last_seen": obj.get("valid_until") or obj.get("modified"),
                "malware_families": [],
                "campaigns": [],
                "threat_actors": [],
                "attack_technique_ids": self._extract_attack_ids_from_stix(obj),
            })
        return indicators

    @staticmethod
    def _extract_from_stix_pattern(pattern: str):
        """Minimal STIX pattern extractor for common indicator types."""
        if not pattern:
            return None, None
        import re
        patterns = [
            (r"\[ipv4-addr:value\s*=\s*'([^']+)'", "ipv4"),
            (r"\[ipv6-addr:value\s*=\s*'([^']+)'", "ipv6"),
            (r"\[domain-name:value\s*=\s*'([^']+)'", "domain"),
            (r"\[url:value\s*=\s*'([^']+)'", "url"),
            (r"\[email-addr:value\s*=\s*'([^']+)'", "email"),
            (r"\[file:hashes\.MD5\s*=\s*'([^']+)'", "md5"),
            (r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'", "sha1"),
            (r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'", "sha256"),
            (r"\[file:hashes\.'SHA-512'\s*=\s*'([^']+)'", "sha512"),
            (r"\[file:name\s*=\s*'([^']+)'", "file_name"),
            (r"\[mutex:name\s*=\s*'([^']+)'", "mutex"),
            (r"\[windows-registry-key:key\s*=\s*'([^']+)'", "registry_key"),
            (r"\[process:name\s*=\s*'([^']+)'", "process_name"),
            (r"\[network-traffic:extensions\.'http-request-ext'\.request_header\.'User-Agent'\s*=\s*'([^']+)'", "user_agent"),
        ]
        for pat, ioc_type in patterns:
            m = re.search(pat, pattern, re.IGNORECASE)
            if m:
                return ioc_type, m.group(1)
        return None, None

    @staticmethod
    def _stix_tlp_from_ref(ref: str) -> str:
        ref_lower = ref.lower()
        if "white" in ref_lower:
            return "TLP:WHITE"
        if "green" in ref_lower:
            return "TLP:GREEN"
        if "amber" in ref_lower:
            return "TLP:AMBER"
        if "red" in ref_lower:
            return "TLP:RED"
        return "TLP:WHITE"

    @staticmethod
    def _extract_attack_ids_from_stix(obj: Dict[str, Any]) -> List[str]:
        ids = []
        for ref in obj.get("external_references", []):
            if ref.get("source_name", "").lower() in ("mitre-attack", "mitre attack"):
                eid = ref.get("external_id", "")
                if eid.startswith("T"):
                    ids.append(eid)
        return ids

    # ------------------------------------------------------------------
    # OpenCTI parser
    # ------------------------------------------------------------------

    def _parse_opencti(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        data = raw if isinstance(raw, dict) else json.loads(raw)
        # Support both direct list and OpenCTI GraphQL envelope
        edges = (
            data.get("data", {}).get("indicators", {}).get("edges", [])
            or data.get("indicators", {}).get("edges", [])
            or (data if isinstance(data, list) else [])
        )
        indicators = []
        for edge in edges:
            node = edge.get("node", edge) if isinstance(edge, dict) else {}
            pattern = node.get("pattern", "")
            ioc_type, value = self._extract_from_stix_pattern(pattern)
            if not ioc_type or not value:
                obs = node.get("observables", {}).get("edges", [])
                if obs:
                    obs_node = obs[0].get("node", {})
                    ioc_type = obs_node.get("entity_type", "").lower().replace("-", "_") or None
                    value = obs_node.get("value", "") or obs_node.get("observable_value", "")
            if not ioc_type or not value:
                continue
            conf_pct = node.get("confidence", int(confidence * 100))
            indicators.append({
                "type": ioc_type,
                "value": str(value).strip(),
                "confidence": float(conf_pct) / 100.0 if conf_pct > 1 else float(conf_pct),
                "tlp": tlp,
                "provider": provider_id,
                "provider_indicator_id": node.get("id", ""),
                "tags": [m.get("definition", "") for m in node.get("markingDefinitions", {}).get("edges", [])],
                "description": node.get("description", ""),
                "first_seen": node.get("valid_from") or node.get("created"),
                "last_seen": node.get("valid_until") or node.get("modified"),
                "malware_families": [],
                "campaigns": [],
                "threat_actors": [],
                "attack_technique_ids": [],
            })
        return indicators

    # ------------------------------------------------------------------
    # CSV parser
    # ------------------------------------------------------------------

    def _parse_csv(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        else:
            text = str(raw)
        reader = csv.DictReader(io.StringIO(text))
        indicators = []
        for row in reader:
            # Try common column names for type and value
            ioc_type = (
                row.get("type") or row.get("ioc_type") or row.get("indicator_type") or ""
            ).strip().lower()
            value = (
                row.get("value") or row.get("ioc") or row.get("indicator") or row.get("ioc_value") or ""
            ).strip()
            if not value:
                continue
            # Auto-detect type from value if column absent
            if not ioc_type:
                ioc_type = self._infer_type(value)
            if not ioc_type:
                continue
            conf = float(row.get("confidence", confidence))
            if conf > 1.0:
                conf = conf / 100.0
            indicators.append({
                "type": ioc_type,
                "value": value,
                "confidence": conf,
                "tlp": row.get("tlp", tlp),
                "provider": provider_id,
                "provider_indicator_id": row.get("id", ""),
                "tags": [t.strip() for t in row.get("tags", "").split(",") if t.strip()],
                "description": row.get("description", row.get("comment", "")),
                "first_seen": row.get("first_seen") or row.get("date"),
                "last_seen": row.get("last_seen"),
                "malware_families": [m.strip() for m in row.get("malware", "").split(",") if m.strip()],
                "campaigns": [],
                "threat_actors": [],
                "attack_technique_ids": [],
            })
        return indicators

    # ------------------------------------------------------------------
    # YAML parser
    # ------------------------------------------------------------------

    def _parse_yaml(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        try:
            import yaml as _yaml
            if isinstance(raw, (bytes, str)):
                data = _yaml.safe_load(raw)
            else:
                data = raw
        except ImportError:
            # Fallback: try JSON
            return self._parse_json_generic(raw, confidence, tlp, provider_id)
        return self._parse_json_generic(data, confidence, tlp, provider_id)

    # ------------------------------------------------------------------
    # Generic JSON / list / dict parser
    # ------------------------------------------------------------------

    def _parse_json_generic(
        self, raw: Any, confidence: float, tlp: str, provider_id: str
    ) -> List[Dict[str, Any]]:
        if isinstance(raw, (bytes, str)):
            try:
                data = json.loads(raw)
            except Exception:
                return []
        else:
            data = raw

        # Unwrap common envelope patterns
        if isinstance(data, dict):
            for key in ("indicators", "iocs", "data", "objects", "results", "items"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                # Treat dict as a single indicator if it has type+value
                data = [data]

        if not isinstance(data, list):
            return []

        indicators = []
        for item in data:
            if not isinstance(item, dict):
                continue
            ioc_type = (
                item.get("type") or item.get("ioc_type") or item.get("indicator_type") or ""
            ).strip().lower()
            value = (
                item.get("value") or item.get("ioc") or item.get("indicator") or
                item.get("ioc_value") or item.get("observable") or ""
            )
            if isinstance(value, dict):
                value = str(value.get("value", "")).strip()
            else:
                value = str(value).strip()
            if not value:
                continue
            if not ioc_type:
                ioc_type = self._infer_type(value)
            if not ioc_type:
                continue
            conf = float(item.get("confidence", confidence))
            if conf > 1.0:
                conf = conf / 100.0
            indicators.append({
                "type": ioc_type,
                "value": value,
                "confidence": min(1.0, max(0.0, conf)),
                "tlp": item.get("tlp", tlp),
                "provider": provider_id,
                "provider_indicator_id": str(item.get("id", item.get("provider_id", ""))),
                "tags": item.get("tags", []) if isinstance(item.get("tags"), list) else [],
                "description": item.get("description", item.get("comment", "")),
                "first_seen": item.get("first_seen") or item.get("created"),
                "last_seen": item.get("last_seen") or item.get("modified"),
                "expiration": item.get("expiration") or item.get("valid_until"),
                "malware_families": item.get("malware_families", item.get("malware", [])) if isinstance(item.get("malware_families", item.get("malware")), list) else [],
                "campaigns": item.get("campaigns", []) if isinstance(item.get("campaigns"), list) else [],
                "threat_actors": item.get("threat_actors", item.get("actors", [])) if isinstance(item.get("threat_actors", item.get("actors")), list) else [],
                "attack_technique_ids": item.get("attack_technique_ids", item.get("techniques", [])) if isinstance(item.get("attack_technique_ids", item.get("techniques")), list) else [],
                "severity": item.get("severity", ""),
                "priority": item.get("priority", 3),
                "source_url": item.get("source_url", item.get("url", "")),
            })
        return indicators

    # ------------------------------------------------------------------
    # Type inference
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_type(value: str) -> Optional[str]:
        """Heuristically infer the IOC type from its value format."""
        import re
        v = value.strip()
        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$", v):
            return "ipv4"
        # IPv6
        if ":" in v and re.match(r"^[0-9a-fA-F:\/]+$", v) and v.count(":") >= 2:
            return "ipv6"
        # SHA-256
        if re.match(r"^[0-9a-fA-F]{64}$", v):
            return "sha256"
        # MD5
        if re.match(r"^[0-9a-fA-F]{32}$", v):
            return "md5"
        # SHA-1
        if re.match(r"^[0-9a-fA-F]{40}$", v):
            return "sha1"
        # SHA-512
        if re.match(r"^[0-9a-fA-F]{128}$", v):
            return "sha512"
        # Email
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            return "email"
        # URL
        if re.match(r"^https?://", v, re.IGNORECASE):
            return "url"
        # Domain
        if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", v):
            return "domain"
        # Registry key
        if v.upper().startswith(("HKEY_", "HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\")):
            return "registry_key"
        return None
