"""
ATRE Entity Resolution Engine — NetFusion IL-9
===============================================
Extracts and resolves natural language text entities into canonical CIIL entities.
"""

import re
from typing import Any, List, Optional
from netfusion_ai.reasoning.models import CIILResolvedEntity


class ATREEntityResolver:
    """
    CIIL Entity Resolution for ATRE questions and contexts.
    Integrates with netfusion_intelligence.identity if available.
    """

    def __init__(self, identity_service: Optional[Any] = None):
        self.identity_service = identity_service

    def extract_and_resolve(
        self, text: str, context_node_ids: Optional[List[str]] = None
    ) -> List[CIILResolvedEntity]:
        """
        Extract mentions from text & context_node_ids and resolve to CIIL entities.
        """
        resolved: List[CIILResolvedEntity] = []
        seen_ids = set()

        # Direct context IDs
        if context_node_ids:
            for cid in context_node_ids:
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    resolved.append(
                        CIILResolvedEntity(
                            canonical_id=cid,
                            entity_type=self._infer_type_from_id(cid),
                            display_name=cid,
                            confidence=1.0,
                        )
                    )

        # Regex extractors
        # 1. CVE
        cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
        for cve in cves:
            cve_upper = cve.upper()
            cid = f"CVE:{cve_upper}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="VULNERABILITY",
                        display_name=cve_upper,
                        external_identifiers=[{"system": "NVD", "value": cve_upper}],
                        confidence=1.0,
                    )
                )

        # 2. MITRE ATT&CK T-codes
        techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.IGNORECASE)
        for tcode in techniques:
            t_upper = tcode.upper()
            cid = f"MITRE:{t_upper}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="ATTACK_PATTERN",
                        display_name=t_upper,
                        external_identifiers=[{"system": "ATTACK", "value": t_upper}],
                        confidence=0.95,
                    )
                )

        # 3. CAPEC
        capecs = re.findall(r"\bCAPEC-\d+\b", text, re.IGNORECASE)
        for capec in capecs:
            capec_upper = capec.upper()
            cid = f"CAPEC:{capec_upper}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="ATTACK_PATTERN",
                        display_name=capec_upper,
                        external_identifiers=[{"system": "CAPEC", "value": capec_upper}],
                        confidence=0.95,
                    )
                )

        # 4. CWE
        cwes = re.findall(r"\bCWE-\d+\b", text, re.IGNORECASE)
        for cwe in cwes:
            cwe_upper = cwe.upper()
            cid = f"CWE:{cwe_upper}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="WEAKNESS",
                        display_name=cwe_upper,
                        external_identifiers=[{"system": "CWE", "value": cwe_upper}],
                        confidence=0.95,
                    )
                )

        # 5. IPv4 addresses
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        for ip in ips:
            cid = f"IP:{ip}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="IP_ADDRESS",
                        display_name=ip,
                        external_identifiers=[{"system": "IP", "value": ip}],
                        confidence=0.9,
                    )
                )

        # 6. Hashes (MD5/SHA1/SHA256)
        hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)
        for h in hashes:
            cid = f"HASH:{h.lower()}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="FILE_HASH",
                        display_name=h.lower(),
                        external_identifiers=[{"system": "HASH", "value": h.lower()}],
                        confidence=0.95,
                    )
                )

        # 7. Threat Actors (e.g. APT29, Lazarus, FIN7, Cozy Bear)
        actors = re.findall(
            r"\b(APT\d+|Lazarus|FIN\d+|Cozy Bear|Fancy Bear|Wizard Spider|TA\d+)\b",
            text,
            re.IGNORECASE,
        )
        for actor in actors:
            act_title = actor.title()
            cid = f"ACTOR:{act_title.upper()}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="THREAT_ACTOR",
                        display_name=act_title,
                        external_identifiers=[{"system": "THREAT_ACTOR", "value": act_title}],
                        confidence=0.9,
                    )
                )

        # 8. Hostnames / Assets
        hosts = re.findall(r"\b([a-zA-Z0-9_-]+(?:-srv|-host|-db|-web|-dc)\w*)\b", text, re.IGNORECASE)
        for h in hosts:
            cid = f"ASSET:{h}"
            if cid not in seen_ids:
                seen_ids.add(cid)
                resolved.append(
                    CIILResolvedEntity(
                        canonical_id=cid,
                        entity_type="ASSET",
                        display_name=h,
                        external_identifiers=[{"system": "HOSTNAME", "value": h}],
                        confidence=0.85,
                    )
                )

        # If identity_service is available, try to resolve via CIIL IdentityService
        if self.identity_service and hasattr(self.identity_service, "resolve_entity"):
            for res in list(resolved):
                try:
                    ciil_ent = self.identity_service.resolve_entity(
                        entity_type=res.entity_type,
                        display_name=res.display_name,
                        external_identifiers=res.external_identifiers,
                    )
                    if hasattr(ciil_ent, "canonical_id"):
                        res.canonical_id = ciil_ent.canonical_id
                except Exception:
                    pass

        return resolved

    def _infer_type_from_id(self, cid: str) -> str:
        cid_u = cid.upper()
        if "CVE" in cid_u:
            return "VULNERABILITY"
        elif "T1" in cid_u or "MITRE" in cid_u:
            return "ATTACK_PATTERN"
        elif "CAPEC" in cid_u:
            return "ATTACK_PATTERN"
        elif "CWE" in cid_u:
            return "WEAKNESS"
        elif "IP" in cid_u:
            return "IP_ADDRESS"
        elif "ACTOR" in cid_u or "APT" in cid_u:
            return "THREAT_ACTOR"
        elif "ASSET" in cid_u or "HOST" in cid_u:
            return "ASSET"
        return "UNKNOWN"
