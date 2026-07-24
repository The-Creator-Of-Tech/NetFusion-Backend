"""
STIX 2.1 Object to NetFusion MITRE Domain Model Mapper.
Extracts ATT&CK IDs, tactics, platforms, aliases, and metadata from raw STIX 2.1 dicts.
"""

from typing import Any, Dict, List, Optional, Tuple
from netfusion_intelligence.feeds.mitre.models import ExternalReference, MitreEntity, MitreRelationship


class MitreMapper:
    """
    Maps STIX 2.1 JSON objects to immutable NetFusion MitreEntity and MitreRelationship domain models.
    Strictly parses fields without hardcoding or string matching.
    """

    @staticmethod
    def extract_attack_id(external_references: List[Dict[str, Any]]) -> Optional[str]:
        """
        Extracts official MITRE ATT&CK ID (e.g. T1059, G0001, S0001, C0001, M1001, DS0001) from external_references.
        """
        if not external_references:
            return None
        valid_sources = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
        for ref in external_references:
            if not isinstance(ref, dict):
                continue
            src = ref.get("source_name", "").lower()
            ext_id = ref.get("external_id")
            if src in valid_sources and ext_id:
                return str(ext_id).strip()
        return None

    @staticmethod
    def extract_mitre_url(external_references: List[Dict[str, Any]]) -> Optional[str]:
        """
        Extracts official MITRE ATT&CK URL from external_references.
        """
        if not external_references:
            return None
        valid_sources = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
        for ref in external_references:
            if not isinstance(ref, dict):
                continue
            src = ref.get("source_name", "").lower()
            url = ref.get("url")
            if src in valid_sources and url:
                return str(url).strip()
        return None

    def map_stix_object(self, obj: Dict[str, Any]) -> MitreEntity:
        """
        Maps a single STIX 2.1 domain object dict into a normalized MitreEntity instance.
        """
        stix_id = str(obj.get("id", ""))
        stix_type = str(obj.get("type", "unknown"))
        name = obj.get("name")
        description = obj.get("description")
        
        ext_refs = obj.get("external_references", [])
        attack_id = self.extract_attack_id(ext_refs)
        url = self.extract_mitre_url(ext_refs)

        # Sub-technique detection & parent resolution
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
        parent_technique_id = None
        if is_subtechnique and attack_id and "." in attack_id:
            parent_technique_id = attack_id.split(".")[0]

        # Kill chain phases & Tactics
        kc_phases = obj.get("kill_chain_phases", [])
        tactics = []
        parsed_kc_phases = []
        for kc in kc_phases:
            if isinstance(kc, dict):
                phase = kc.get("phase_name")
                kc_name = kc.get("kill_chain_name", "mitre-attack")
                if phase:
                    tactics.append(str(phase))
                    parsed_kc_phases.append({"kill_chain_name": str(kc_name), "phase_name": str(phase)})

        # Platforms
        platforms = [str(p) for p in obj.get("x_mitre_platforms", []) if p]

        # Aliases
        aliases = []
        if "aliases" in obj and isinstance(obj["aliases"], list):
            aliases.extend([str(a) for a in obj["aliases"] if a])
        if "x_mitre_aliases" in obj and isinstance(obj["x_mitre_aliases"], list):
            for a in obj["x_mitre_aliases"]:
                if a and str(a) not in aliases:
                    aliases.append(str(a))

        # Permissions required & System requirements
        perms = [str(p) for p in obj.get("x_mitre_permissions_required", []) if p]
        sys_reqs = [str(s) for s in obj.get("x_mitre_system_requirements", []) if s]

        # Detection & Contributors
        detection = obj.get("x_mitre_detection")
        contributors = [str(c) for c in obj.get("x_mitre_contributors", []) if c]

        # Version & Revoked/Deprecated
        version = obj.get("x_mitre_version") or obj.get("spec_version")
        created = obj.get("created")
        modified = obj.get("modified")
        revoked = bool(obj.get("revoked", False))
        deprecated = bool(obj.get("x_mitre_deprecated", False))

        return MitreEntity(
            stix_id=stix_id,
            type=stix_type,
            attack_id=attack_id,
            name=name,
            description=description,
            is_subtechnique=is_subtechnique,
            parent_technique_id=parent_technique_id,
            tactics=tuple(tactics),
            platforms=tuple(platforms),
            aliases=tuple(aliases),
            kill_chain_phases=tuple(parsed_kc_phases),
            permissions_required=tuple(perms),
            system_requirements=tuple(sys_reqs),
            detection=detection,
            contributors=tuple(contributors),
            external_references=tuple(ext_refs),
            url=url,
            version=version,
            created=created,
            modified=modified,
            revoked=revoked,
            deprecated=deprecated,
            raw_stix=obj,
        )

    def map_stix_relationship(self, obj: Dict[str, Any]) -> MitreRelationship:
        """
        Maps a STIX 2.1 relationship object dict into a MitreRelationship instance.
        """
        stix_id = str(obj.get("id", ""))
        source_ref = str(obj.get("source_ref", ""))
        target_ref = str(obj.get("target_ref", ""))
        rel_type = str(obj.get("relationship_type", ""))
        description = obj.get("description")
        confidence = obj.get("confidence")
        created = obj.get("created")
        modified = obj.get("modified")
        ext_refs = obj.get("external_references", [])
        revoked = bool(obj.get("revoked", False))

        return MitreRelationship(
            stix_id=stix_id,
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=rel_type,
            description=description,
            confidence=confidence,
            created=created,
            modified=modified,
            external_references=tuple(ext_refs),
            revoked=revoked,
        )
