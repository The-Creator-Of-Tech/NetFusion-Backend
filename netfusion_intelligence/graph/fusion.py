"""
IL-8 UTKG — Knowledge Fusion Engine
=======================================
Automatically connects every canonical intelligence entity from IL-1..IL-7
into the Unified Threat Knowledge Graph.

Fusion chain:
    ATT&CK → CAPEC → CWE → CVE → KEV → EPSS → IOC → Malware → Campaign
    → Threat Actor → Evidence → Investigations → Reports

All nodes reference CIIL canonical UUIDs.
No duplicates — upsert semantics throughout.
"""

import uuid
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.models import (
    GraphEdgeType, GraphNode, GraphNodeType
)
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.relationships import GraphRelationshipManager


class KnowledgeFusionEngine:
    """
    Reads canonical entity data from the intelligence repository
    (IL-1..IL-7) and materialises them as graph nodes + edges.

    The intelligence repository is the SQLAlchemy repo that already
    contains ATT&CK, CVE, KEV, EPSS, CWE, CAPEC, and IOC data.
    """

    def __init__(
        self,
        graph_repository: GraphRepository,
        intelligence_repository: Any,   # SQLAlchemyIntelligenceRepository
    ):
        self.graph = graph_repository
        self.intel = intelligence_repository
        self._rel = GraphRelationshipManager(graph_repository)

    # =========================================================================
    # Full Fusion (runs all layers)
    # =========================================================================

    def fuse_all(self) -> Dict[str, Any]:
        """Run the complete IL-1..IL-7 fusion pipeline."""
        summary: Dict[str, Any] = {}
        summary["mitre"]   = self.fuse_mitre()
        summary["capec"]   = self.fuse_capec()
        summary["cwe"]     = self.fuse_cwe()
        summary["cve"]     = self.fuse_cve()
        summary["kev"]     = self.fuse_kev()
        summary["epss"]    = self.fuse_epss()
        summary["ioc"]     = self.fuse_ioc()
        summary["cross"]   = self.fuse_cross_layer_edges()
        return summary

    # =========================================================================
    # IL-2: MITRE ATT&CK
    # =========================================================================

    def fuse_mitre(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_mitre_objects"):
            return {"skipped": True}
        inserted = updated = edges = 0

        # Techniques
        techniques = self.intel.list_mitre_objects(type="attack-pattern", limit=5000)
        for obj in techniques:
            _n, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=obj.get("stix_id", str(uuid.uuid4())),
                node_type=GraphNodeType.ATTACK_TECHNIQUE.value,
                label=obj.get("attack_id") or obj.get("name", ""),
                name=obj.get("name"),
                description=(obj.get("description") or "")[:500],
                source_feed="mitre_attack_enterprise",
                external_id=obj.get("attack_id"),
                properties={
                    "is_subtechnique": obj.get("is_subtechnique", False),
                    "parent_technique_id": obj.get("parent_technique_id"),
                    "tactics": obj.get("tactics", []),
                    "platforms": obj.get("platforms", []),
                },
            ))
            if created:
                inserted += 1
            else:
                updated += 1

        # Tactics
        tactics = self.intel.list_mitre_objects(type="x-mitre-tactic", limit=1000)
        for obj in tactics:
            self.graph.upsert_node(GraphNode.create(
                canonical_id=obj.get("stix_id", str(uuid.uuid4())),
                node_type=GraphNodeType.ATTACK_TACTIC.value,
                label=obj.get("name", ""),
                name=obj.get("name"),
                source_feed="mitre_attack_enterprise",
                external_id=obj.get("attack_id"),
            ))

        # Intrusion Sets (Threat Actors / Groups)
        groups = self.intel.list_mitre_objects(type="intrusion-set", limit=2000)
        for obj in groups:
            self.graph.upsert_node(GraphNode.create(
                canonical_id=obj.get("stix_id", str(uuid.uuid4())),
                node_type=GraphNodeType.THREAT_ACTOR.value,
                label=obj.get("attack_id") or obj.get("name", ""),
                name=obj.get("name"),
                description=(obj.get("description") or "")[:500],
                source_feed="mitre_attack_enterprise",
                external_id=obj.get("attack_id"),
            ))

        # Malware
        malware_objs = self.intel.list_mitre_objects(type="malware", limit=2000)
        for obj in malware_objs:
            self.graph.upsert_node(GraphNode.create(
                canonical_id=obj.get("stix_id", str(uuid.uuid4())),
                node_type=GraphNodeType.MALWARE.value,
                label=obj.get("name", ""),
                name=obj.get("name"),
                description=(obj.get("description") or "")[:500],
                source_feed="mitre_attack_enterprise",
                external_id=obj.get("attack_id"),
            ))

        # Campaigns
        campaigns = self.intel.list_mitre_objects(type="campaign", limit=2000)
        for obj in campaigns:
            self.graph.upsert_node(GraphNode.create(
                canonical_id=obj.get("stix_id", str(uuid.uuid4())),
                node_type=GraphNodeType.CAMPAIGN.value,
                label=obj.get("name", ""),
                name=obj.get("name"),
                source_feed="mitre_attack_enterprise",
                external_id=obj.get("attack_id"),
            ))

        # STIX relationships
        rels = self.intel.list_mitre_relationships(limit=20000)
        for rel in rels:
            result = self._rel.fuse_intelligence_nodes(
                source_external_id=rel.get("source_attack_id") or rel.get("source_ref", ""),
                source_type="",           # any type
                target_external_id=rel.get("target_attack_id") or rel.get("target_ref", ""),
                target_type="",
                edge_type=_mitre_rel_type(rel.get("relationship_type", "")),
                confidence=float(rel.get("confidence") or 1.0) / 100.0
                    if isinstance(rel.get("confidence"), int) else 1.0,
                source_feed="mitre_attack_enterprise",
            )
            if result:
                edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-6: CAPEC
    # =========================================================================

    def fuse_capec(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_capec_attack_patterns"):
            return {"skipped": True}
        inserted = updated = edges = 0

        patterns = self.intel.list_capec_attack_patterns(limit=5000)
        for obj in patterns:
            capec_id = obj.get("capec_id", "")
            node, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=f"capec-{capec_id}",
                node_type=GraphNodeType.CAPEC.value,
                label=capec_id,
                name=obj.get("name"),
                description=(obj.get("description") or "")[:500],
                source_feed="mitre_capec_xml",
                external_id=capec_id,
                properties={
                    "abstraction": obj.get("abstraction"),
                    "typical_severity": obj.get("typical_severity"),
                    "likelihood_of_attack": obj.get("likelihood_of_attack"),
                },
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # CAPEC → ATT&CK edges
            for tech_id in obj.get("attack_technique_ids", []):
                r = self._rel.fuse_intelligence_nodes(
                    source_external_id=capec_id,
                    source_type=GraphNodeType.CAPEC.value,
                    target_external_id=tech_id,
                    target_type=GraphNodeType.ATTACK_TECHNIQUE.value,
                    edge_type=GraphEdgeType.MAPS_TO.value,
                    confidence=0.9,
                    source_feed="mitre_capec_xml",
                )
                if r:
                    edges += 1

            # CAPEC → CWE edges
            for cwe_id in obj.get("related_weaknesses", []):
                r = self._rel.fuse_intelligence_nodes(
                    source_external_id=capec_id,
                    source_type=GraphNodeType.CAPEC.value,
                    target_external_id=cwe_id,
                    target_type=GraphNodeType.CWE.value,
                    edge_type=GraphEdgeType.USES_WEAKNESS.value,
                    confidence=0.9,
                    source_feed="mitre_capec_xml",
                )
                if r:
                    edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-6: CWE
    # =========================================================================

    def fuse_cwe(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_cwe_weaknesses"):
            return {"skipped": True}
        inserted = updated = edges = 0

        weaknesses = self.intel.list_cwe_weaknesses(limit=5000)
        for obj in weaknesses:
            cwe_id = obj.get("cwe_id", "")
            node, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=f"cwe-{cwe_id}",
                node_type=GraphNodeType.CWE.value,
                label=cwe_id,
                name=obj.get("name"),
                description=(obj.get("description") or "")[:500],
                source_feed="mitre_cwe_xml",
                external_id=cwe_id,
                properties={
                    "abstraction": obj.get("abstraction"),
                    "status": obj.get("status"),
                    "likelihood_of_exploit": obj.get("likelihood_of_exploit"),
                },
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # CWE → parent/child relationships
            for rel_w in obj.get("related_weaknesses", []):
                target_cwe = rel_w.get("cwe_id") if isinstance(rel_w, dict) else str(rel_w)
                if target_cwe:
                    nature = rel_w.get("nature", "related") if isinstance(rel_w, dict) else "related"
                    edge_type = GraphEdgeType.PARENT_OF.value if nature == "ChildOf" \
                                else GraphEdgeType.RELATED_TO.value
                    r = self._rel.fuse_intelligence_nodes(
                        source_external_id=cwe_id,
                        source_type=GraphNodeType.CWE.value,
                        target_external_id=target_cwe,
                        target_type=GraphNodeType.CWE.value,
                        edge_type=edge_type,
                        confidence=1.0,
                        source_feed="mitre_cwe_xml",
                    )
                    if r:
                        edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-3: NVD CVE
    # =========================================================================

    def fuse_cve(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_nvd_cves"):
            return {"skipped": True}
        inserted = updated = edges = 0

        cves = self.intel.list_nvd_cves(limit=50000)
        for obj in cves:
            cve_id = obj.get("cve_id", "")
            node, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=f"cve-{cve_id}",
                node_type=GraphNodeType.CVE.value,
                label=cve_id,
                name=cve_id,
                description=(obj.get("description") or "")[:500],
                source_feed="nvd_cve_2.0",
                external_id=cve_id,
                properties={
                    "severity": obj.get("severity"),
                    "cvss_score": obj.get("cvss_score"),
                    "published": obj.get("published"),
                },
                confidence=min(1.0, float(obj.get("cvss_score", 0.0)) / 10.0)
                    if obj.get("cvss_score") else 0.5,
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # CVE → CWE edges (from NVD weakness data)
            for cwe_id in obj.get("cwes", []):
                if cwe_id:
                    r = self._rel.fuse_intelligence_nodes(
                        source_external_id=cve_id,
                        source_type=GraphNodeType.CVE.value,
                        target_external_id=cwe_id,
                        target_type=GraphNodeType.CWE.value,
                        edge_type=GraphEdgeType.HAS_WEAKNESS.value,
                        confidence=1.0,
                        source_feed="nvd_cve_2.0",
                    )
                    if r:
                        edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-4: CISA KEV
    # =========================================================================

    def fuse_kev(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_kev_records"):
            return {"skipped": True}
        inserted = updated = edges = 0

        kev_records = self.intel.list_kev_records(limit=5000)
        for obj in kev_records:
            cve_id = obj.get("cve_id", "")
            kev_external_id = f"KEV:{cve_id}"   # stable, unique per KEV entry
            _n, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=f"kev-{cve_id}",
                node_type=GraphNodeType.KEV.value,
                label=kev_external_id,
                name=cve_id,
                description=(obj.get("short_description") or "")[:500],
                source_feed="cisa_kev_1.0",
                external_id=kev_external_id,   # use prefixed external_id for stable lookups
                properties={
                    "vendor_project": obj.get("vendor_project"),
                    "product": obj.get("product"),
                    "due_date": obj.get("due_date"),
                    "date_added": obj.get("date_added"),
                    "ransomware": obj.get("known_ransomware_campaign_use"),
                    "cve_id": cve_id,           # store plain cve_id in properties for cross-ref
                },
                confidence=1.0,  # KEV = confirmed exploited
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # KEV → CVE edge (look up KEV by its prefixed external_id, CVE by plain id)
            r = self._rel.fuse_intelligence_nodes(
                source_external_id=kev_external_id,
                source_type=GraphNodeType.KEV.value,
                target_external_id=cve_id,
                target_type=GraphNodeType.CVE.value,
                edge_type=GraphEdgeType.HAS_KEV.value,
                confidence=1.0,
                source_feed="cisa_kev_1.0",
            )
            # CVE → KEV reverse edge
            self._rel.fuse_intelligence_nodes(
                source_external_id=cve_id,
                source_type=GraphNodeType.CVE.value,
                target_external_id=kev_external_id,
                target_type=GraphNodeType.KEV.value,
                edge_type=GraphEdgeType.LINKED_TO.value,
                confidence=1.0,
                source_feed="cisa_kev_1.0",
            )
            if r:
                edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-5: EPSS
    # =========================================================================

    def fuse_epss(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_epss_scores"):
            return {"skipped": True}
        inserted = updated = edges = 0

        scores = self.intel.list_epss_scores(limit=50000)
        for obj in scores:
            cve_id = obj.get("cve_id", "")
            node, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=f"epss-{cve_id}",
                node_type=GraphNodeType.EPSS_RECORD.value,
                label=f"EPSS:{cve_id}",
                name=cve_id,
                source_feed="first_epss_1.0",
                external_id=cve_id,
                properties={
                    "epss_score": obj.get("epss_score"),
                    "epss_percentile": obj.get("epss_percentile"),
                    "trend": obj.get("trend"),
                    "publication_date": obj.get("publication_date"),
                },
                confidence=float(obj.get("epss_score", 0.0)),
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # EPSS → CVE
            r = self._rel.fuse_intelligence_nodes(
                source_external_id=f"epss-{cve_id}",
                source_type=GraphNodeType.EPSS_RECORD.value,
                target_external_id=cve_id,
                target_type=GraphNodeType.CVE.value,
                edge_type=GraphEdgeType.HAS_EPSS.value,
                confidence=float(obj.get("epss_score", 0.0)),
                source_feed="first_epss_1.0",
            )
            if r:
                edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # IL-7: IOC
    # =========================================================================

    def fuse_ioc(self) -> Dict[str, int]:
        if not hasattr(self.intel, "list_ioc_indicators"):
            return {"skipped": True}
        inserted = updated = edges = 0

        indicators = self.intel.list_ioc_indicators(limit=50000)
        for obj in indicators:
            ioc_id = obj.get("ioc_id", "")
            ioc_type = obj.get("ioc_type", "ioc")
            ioc_value = obj.get("value", ioc_id)
            node_type = _ioc_type_to_node_type(ioc_type)

            # Use type:value as the stable canonical_id so fusion is idempotent
            # even when the source ioc_id UUID is regenerated between runs.
            stable_canonical_id = f"{ioc_type}:{ioc_value}"

            node, created = self.graph.upsert_node(GraphNode.create(
                canonical_id=stable_canonical_id,
                node_type=node_type,
                label=ioc_value[:200],
                name=ioc_value,
                description=obj.get("description"),
                source_feed=obj.get("provider") or "netfusion_ioc_v1",
                external_id=stable_canonical_id,
                properties={
                    "ioc_id": ioc_id,
                    "ioc_type": ioc_type,
                    "severity": obj.get("severity"),
                    "reputation_score": obj.get("reputation_score"),
                    "tlp": obj.get("tlp"),
                    "first_seen": obj.get("first_seen"),
                    "last_seen": obj.get("last_seen"),
                },
                confidence=float(obj.get("confidence", 0.5)),
            ))
            if created:
                inserted += 1
            else:
                updated += 1

            # IOC → Malware
            for mf in obj.get("malware_families", []):
                malware_canonical = f"malware-{mf.lower().replace(' ', '-')}"
                malware_node, _ = self.graph.upsert_node(GraphNode.create(
                    canonical_id=malware_canonical,
                    node_type=GraphNodeType.MALWARE.value,
                    label=mf,
                    name=mf,
                    source_feed="netfusion_ioc_v1",
                    external_id=malware_canonical,
                ))
                self._rel.add_relationship(
                    source_node_id=node.node_id,
                    target_node_id=malware_node.node_id,
                    edge_type=GraphEdgeType.IOC_TO_MALWARE.value,
                    confidence=float(obj.get("confidence", 0.5)),
                    source_feed="netfusion_ioc_v1",
                )
                edges += 1

            # IOC → Campaign
            for camp in obj.get("campaigns", []):
                camp_canonical = f"campaign-{camp.lower().replace(' ', '-')}"
                camp_node, _ = self.graph.upsert_node(GraphNode.create(
                    canonical_id=camp_canonical,
                    node_type=GraphNodeType.CAMPAIGN.value,
                    label=camp,
                    name=camp,
                    source_feed="netfusion_ioc_v1",
                    external_id=camp_canonical,
                ))
                self._rel.add_relationship(
                    source_node_id=node.node_id,
                    target_node_id=camp_node.node_id,
                    edge_type=GraphEdgeType.IOC_TO_CAMPAIGN.value,
                    confidence=float(obj.get("confidence", 0.5)),
                    source_feed="netfusion_ioc_v1",
                )
                edges += 1

            # IOC → ATT&CK Technique
            for tech_id in obj.get("attack_technique_ids", []):
                r = self._rel.fuse_intelligence_nodes(
                    source_external_id=stable_canonical_id,
                    source_type=node_type,
                    target_external_id=tech_id,
                    target_type=GraphNodeType.ATTACK_TECHNIQUE.value,
                    edge_type=GraphEdgeType.IOC_TO_TECHNIQUE.value,
                    confidence=float(obj.get("confidence", 0.5)),
                    source_feed="netfusion_ioc_v1",
                )
                if r:
                    edges += 1

            # IOC → CVE
            for cve_id in obj.get("cve_ids", []):
                r = self._rel.fuse_intelligence_nodes(
                    source_external_id=stable_canonical_id,
                    source_type=node_type,
                    target_external_id=cve_id,
                    target_type=GraphNodeType.CVE.value,
                    edge_type=GraphEdgeType.IOC_TO_CVE.value,
                    confidence=float(obj.get("confidence", 0.5)),
                    source_feed="netfusion_ioc_v1",
                )
                if r:
                    edges += 1

        return {"inserted": inserted, "updated": updated, "edges": edges}

    # =========================================================================
    # Cross-Layer Edges (CVE ↔ KEV ↔ EPSS ↔ ATT&CK ↔ CAPEC ↔ CWE)
    # =========================================================================

    def fuse_cross_layer_edges(self) -> Dict[str, int]:
        """Create cross-layer edges not captured during individual fusions."""
        edges = 0

        # CVE → KEV: if CVE node exists and KEV node exists, ensure edge
        # KEV nodes now have external_id = "KEV:{cve_id}"
        kev_nodes = self.graph.list_nodes(node_type=GraphNodeType.KEV.value, limit=5000)
        for kev_node in kev_nodes:
            # Recover the plain cve_id from properties or label
            kev_ext = kev_node.external_id or ""
            plain_cve_id = kev_node.properties.get("cve_id") or (
                kev_ext.replace("KEV:", "") if kev_ext.startswith("KEV:") else kev_ext
            )
            if plain_cve_id:
                cve_node = self.graph.get_node_by_external_id(
                    plain_cve_id, node_type=GraphNodeType.CVE.value
                )
                if cve_node:
                    _, created = self._rel.add_relationship(
                        source_node_id=cve_node.node_id,
                        target_node_id=kev_node.node_id,
                        edge_type=GraphEdgeType.LINKED_TO.value,
                        confidence=1.0,
                        source_feed="fusion_engine",
                    )
                    if created:
                        edges += 1

        # CAPEC → ATT&CK via cross-reference table
        if hasattr(self.intel, "list_capec_attack_patterns"):
            patterns = self.intel.list_capec_attack_patterns(limit=2000)
            for p in patterns:
                capec_id = p.get("capec_id", "")
                for tech_id in p.get("attack_technique_ids", []):
                    r = self._rel.fuse_intelligence_nodes(
                        source_external_id=capec_id,
                        source_type=GraphNodeType.CAPEC.value,
                        target_external_id=tech_id,
                        target_type=GraphNodeType.ATTACK_TECHNIQUE.value,
                        edge_type=GraphEdgeType.MAPS_TO.value,
                        confidence=1.0,
                        source_feed="fusion_engine",
                    )
                    if r and r[1]:
                        edges += 1

        return {"cross_layer_edges": edges}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ioc_type_to_node_type(ioc_type: str) -> str:
    mapping = {
        "ipv4": GraphNodeType.IP.value,
        "ipv6": GraphNodeType.IP.value,
        "domain": GraphNodeType.DOMAIN.value,
        "hostname": GraphNodeType.DOMAIN.value,
        "url": GraphNodeType.URL.value,
        "uri": GraphNodeType.URL.value,
        "email": GraphNodeType.EMAIL.value,
        "md5": GraphNodeType.HASH.value,
        "sha1": GraphNodeType.HASH.value,
        "sha256": GraphNodeType.HASH.value,
        "sha512": GraphNodeType.HASH.value,
        "tls_cert_fingerprint": GraphNodeType.CERTIFICATE.value,
        "ja3": GraphNodeType.JA3.value,
        "ja3s": GraphNodeType.JA3.value,
        "malware_family": GraphNodeType.MALWARE.value,
        "campaign": GraphNodeType.CAMPAIGN.value,
        "threat_actor_ref": GraphNodeType.THREAT_ACTOR.value,
    }
    return mapping.get(ioc_type.lower(), GraphNodeType.IOC.value)


def _mitre_rel_type(rel_type: str) -> str:
    mapping = {
        "uses":             GraphEdgeType.USES.value,
        "mitigates":        GraphEdgeType.MITIGATED_BY.value,
        "subtechnique-of":  GraphEdgeType.SUBTECHNIQUE_OF.value,
        "detects":          GraphEdgeType.DETECTED_BY.value,
        "revoked-by":       GraphEdgeType.RELATED_TO.value,
        "attributed-to":    GraphEdgeType.ASSOCIATED_WITH.value,
        "targets":          GraphEdgeType.TARGETS.value,
    }
    return mapping.get(rel_type.lower(), GraphEdgeType.RELATED_TO.value)
