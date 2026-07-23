"""
IL-7 IOC Correlation Engine.
Builds bidirectional relationships between IOC entities and between
IOCs and other intelligence entities (ATT&CK, CAPEC, CWE, CVE,
Malware, Campaign, Threat Actor).
Supports bidirectional traversal across the entire knowledge graph.
"""

import uuid
from typing import Any, Dict, List, Optional

from netfusion_intelligence.feeds.ioc.models import IocEntity, IocRelationship, IocType


class IocCorrelationEngine:
    """
    Derives IOC-to-IOC and IOC-to-entity relationships from normalized IocEntity data.
    All relationships are bidirectional — stored once with a directional type,
    queried in both directions by the repository.
    """

    def build_relationships(
        self,
        entities: Dict[str, IocEntity],
    ) -> List[IocRelationship]:
        """
        Build all derivable relationships from the entity set.
        Returns a deduplicated list of IocRelationship objects.
        """
        relationships: List[IocRelationship] = []
        seen: set = set()

        for fp, entity in entities.items():
            # IOC → ATT&CK Technique
            for tech_id in entity.attack_technique_ids:
                r = self._make_rel(entity.ioc_id, tech_id, "attack_technique", "ioc_to_attack_technique",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → CAPEC
            for capec_id in entity.capec_ids:
                r = self._make_rel(entity.ioc_id, capec_id, "capec", "ioc_to_capec",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → CWE
            for cwe_id in entity.cwe_ids:
                r = self._make_rel(entity.ioc_id, cwe_id, "cwe", "ioc_to_cwe",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → CVE
            for cve_id in entity.cve_ids:
                r = self._make_rel(entity.ioc_id, cve_id, "cve", "ioc_to_cve",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → Malware Family
            for mf in entity.malware_families:
                r = self._make_rel(entity.ioc_id, mf, "malware", "ioc_to_malware",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → Campaign
            for camp in entity.campaigns:
                r = self._make_rel(entity.ioc_id, camp, "campaign", "ioc_to_campaign",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

            # IOC → Threat Actor
            for actor in entity.threat_actors:
                r = self._make_rel(entity.ioc_id, actor, "threat_actor", "ioc_to_threat_actor",
                                   entity.confidence, entity.first_seen, entity.last_seen, entity.provider)
                if self._add_unique(r, seen):
                    relationships.append(r)

        # IOC-to-IOC structural relationships (IP→Domain co-occurrence by shared metadata)
        relationships.extend(self._build_ioc_to_ioc(entities, seen))
        return relationships

    def _build_ioc_to_ioc(
        self,
        entities: Dict[str, IocEntity],
        seen: set,
    ) -> List[IocRelationship]:
        """
        Build IOC-to-IOC relationships based on shared attribution fields.
        E.g. two IOCs linked to the same malware family are implicitly co-related.
        We correlate by shared provider_id when they differ in type (e.g. IP + domain same event).
        """
        relationships: List[IocRelationship] = []

        # Group entities by (provider, provider_id) to detect co-observed indicators
        provider_groups: Dict[str, List[IocEntity]] = {}
        for entity in entities.values():
            if entity.provider and entity.provider_id:
                key = f"{entity.provider}::{entity.provider_id}"
                provider_groups.setdefault(key, []).append(entity)

        for group in provider_groups.values():
            if len(group) < 2:
                continue
            # Create co-observed relationships between all pairs in the same event
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    src = group[i]
                    tgt = group[j]
                    rel_type = self._infer_ioc_to_ioc_type(src.ioc_type, tgt.ioc_type)
                    r = self._make_rel(
                        src.ioc_id, tgt.ioc_id, "ioc", rel_type,
                        min(src.confidence, tgt.confidence),
                        src.first_seen, src.last_seen, src.provider,
                    )
                    if self._add_unique(r, seen):
                        relationships.append(r)

        return relationships

    @staticmethod
    def _infer_ioc_to_ioc_type(src_type: str, tgt_type: str) -> str:
        """Infer the most semantically appropriate IOC-to-IOC relationship type."""
        pair = frozenset([src_type, tgt_type])
        if pair == frozenset([IocType.IPV4.value, IocType.DOMAIN.value]):
            return "ip_to_domain"
        if pair == frozenset([IocType.DOMAIN.value, IocType.URL.value]):
            return "domain_to_url"
        if pair == frozenset([IocType.URL.value, IocType.MD5.value]) or \
           pair == frozenset([IocType.URL.value, IocType.SHA256.value]):
            return "url_to_hash"
        if src_type in (IocType.MD5.value, IocType.SHA1.value, IocType.SHA256.value, IocType.SHA512.value) and \
           tgt_type == IocType.FILE_NAME.value:
            return "hash_to_file"
        return "ioc_to_ioc"

    @staticmethod
    def _make_rel(
        source_ioc_id: str,
        target_id: str,
        target_type: str,
        rel_type: str,
        confidence: float,
        first_seen: Optional[str],
        last_seen: Optional[str],
        provider: Optional[str],
    ) -> IocRelationship:
        return IocRelationship(
            relationship_id=str(uuid.uuid4()),
            source_ioc_id=source_ioc_id,
            target_id=target_id,
            target_type=target_type,
            relationship_type=rel_type,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            provider=provider,
        )

    @staticmethod
    def _add_unique(rel: IocRelationship, seen: set) -> bool:
        """Returns True and registers the pair if not already seen."""
        key = f"{rel.source_ioc_id}::{rel.target_id}::{rel.relationship_type}"
        if key in seen:
            return False
        seen.add(key)
        return True
