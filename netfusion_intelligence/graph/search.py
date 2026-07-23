"""
IL-8 UTKG — Graph Search Engine
==================================
Full-text search, entity lookup, and multi-hop correlation queries.
Supports all canonical investigation query patterns defined in IL-8 spec.
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.models import (
    GraphNodeType, SearchResult, SubgraphResult
)
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.traversal import GraphTraversalEngine


class GraphSearchEngine:
    """
    Search and query operations over the UTKG.
    All queries return structured result objects.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository
        self._traversal = GraphTraversalEngine(repository)

    # =========================================================================
    # Text Search
    # =========================================================================

    def search(
        self,
        query: str,
        node_type: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> SearchResult:
        """Full-text search across node labels, names, descriptions, tags."""
        t0 = time.perf_counter()
        nodes = self.repo.search_nodes(
            query=query,
            node_type=node_type,
            min_confidence=min_confidence,
            limit=limit,
        )
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        return SearchResult(
            search_id=str(uuid.uuid4()),
            query=query,
            nodes=[n.to_dict() for n in nodes],
            total_count=len(nodes),
            duration_ms=duration_ms,
        )

    # =========================================================================
    # Entity Lookup by External ID
    # =========================================================================

    def find_by_external_id(self, external_id: str, node_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find a graph node by its external canonical identifier (CVE-ID, T1059, etc.)."""
        node = self.repo.get_node_by_external_id(external_id, node_type=node_type)
        return node.to_dict() if node else None

    def find_by_canonical_id(self, canonical_id: str) -> Optional[Dict[str, Any]]:
        """Find a graph node by CIIL canonical UUID."""
        node = self.repo.get_node_by_canonical(canonical_id)
        return node.to_dict() if node else None

    # =========================================================================
    # Investigation Query: IOCs for CVE
    # =========================================================================

    def find_iocs_for_cve(self, cve_id: str, depth: int = 4) -> Dict[str, Any]:
        """
        Show every IOC linked to a given CVE.
        Path: CVE → CWE → IOC or CVE → direct IOC links.
        """
        cve_node = self.repo.get_node_by_external_id(cve_id, node_type=GraphNodeType.CVE.value)
        if not cve_node:
            return {"cve_id": cve_id, "iocs": [], "path_nodes": [], "path_edges": []}

        result = self._traversal.bfs(
            cve_node.node_id, max_depth=depth, direction="both"
        )
        iocs = [n for n in result.nodes if n.get("node_type") in (
            "ioc", "domain", "url", "ip", "hash", "email", "certificate", "ja3"
        )]
        return {
            "cve_id": cve_id,
            "cve_node": cve_node.to_dict(),
            "iocs": iocs,
            "path_nodes": result.nodes,
            "path_edges": result.edges,
            "ioc_count": len(iocs),
        }

    # =========================================================================
    # Investigation Query: ATT&CK Techniques for Threat Actor
    # =========================================================================

    def find_techniques_for_threat_actor(self, actor_id: str, depth: int = 3) -> Dict[str, Any]:
        """Show all ATT&CK techniques used by a Threat Actor."""
        actor_node = self.repo.get_node_by_external_id(actor_id) or \
                     self.repo.get_node_by_canonical(actor_id)
        if not actor_node:
            return {"actor_id": actor_id, "techniques": []}

        result = self._traversal.bfs(actor_node.node_id, max_depth=depth, direction="out")
        techniques = [n for n in result.nodes if n.get("node_type") in (
            "attack_technique", "attack_tactic"
        )]
        return {
            "actor_id": actor_id,
            "actor_node": actor_node.to_dict(),
            "techniques": techniques,
            "technique_count": len(techniques),
            "all_nodes": result.nodes,
            "all_edges": result.edges,
        }

    # =========================================================================
    # Investigation Query: Campaigns for IOC
    # =========================================================================

    def find_campaigns_for_ioc(self, ioc_value: str, depth: int = 3) -> Dict[str, Any]:
        """Find every Campaign related to an IOC."""
        ioc_node = self.repo.search_nodes(query=ioc_value, node_type=GraphNodeType.IOC.value, limit=1)
        if not ioc_node:
            # Try any IOC-type node
            ioc_node = self.repo.search_nodes(query=ioc_value, limit=1)
        if not ioc_node:
            return {"ioc_value": ioc_value, "campaigns": []}

        node = ioc_node[0]
        result = self._traversal.bfs(node.node_id, max_depth=depth, direction="both")
        campaigns = [n for n in result.nodes if n.get("node_type") == "campaign"]
        return {
            "ioc_value": ioc_value,
            "ioc_node": node.to_dict(),
            "campaigns": campaigns,
            "campaign_count": len(campaigns),
        }

    # =========================================================================
    # Investigation Query: Assets exposed to KEV
    # =========================================================================

    def find_assets_exposed_to_kev(self, kev_cve_id: str, depth: int = 4) -> Dict[str, Any]:
        """Show all assets exposed to a CISA KEV entry."""
        # Try "KEV:{cve_id}" first (new format), then plain cve_id as fallback
        kev_node = (
            self.repo.get_node_by_external_id(f"KEV:{kev_cve_id}", node_type=GraphNodeType.KEV.value)
            or self.repo.get_node_by_external_id(kev_cve_id, node_type=GraphNodeType.KEV.value)
            or self.repo.get_node_by_external_id(kev_cve_id, node_type=GraphNodeType.CVE.value)
        )
        if not kev_node:
            return {"kev_id": kev_cve_id, "assets": []}

        result = self._traversal.bfs(kev_node.node_id, max_depth=depth, direction="both")
        asset_types = {"asset", "host", "device", "software", "application", "service", "network"}
        assets = [n for n in result.nodes if n.get("node_type") in asset_types]
        return {
            "kev_id": kev_cve_id,
            "kev_node": kev_node.to_dict(),
            "assets": assets,
            "asset_count": len(assets),
        }

    # =========================================================================
    # Investigation Query: Investigations containing an IOC
    # =========================================================================

    def find_investigations_for_ioc(self, ioc_value: str, depth: int = 4) -> Dict[str, Any]:
        """Find every investigation containing a given IOC."""
        ioc_nodes = self.repo.search_nodes(query=ioc_value, limit=5)
        all_investigations = []
        for ioc_node in ioc_nodes:
            result = self._traversal.bfs(
                ioc_node.node_id, max_depth=depth, direction="both"
            )
            investigations = [
                n for n in result.nodes
                if n.get("node_type") in ("investigation", "case", "alert", "finding")
            ]
            all_investigations.extend(investigations)

        # Deduplicate
        seen = set()
        unique_investigations = []
        for inv in all_investigations:
            nid = inv.get("node_id")
            if nid not in seen:
                seen.add(nid)
                unique_investigations.append(inv)

        return {
            "ioc_value": ioc_value,
            "investigations": unique_investigations,
            "investigation_count": len(unique_investigations),
        }

    # =========================================================================
    # Investigation Query: Evidence for Report
    # =========================================================================

    def find_evidence_for_report(self, report_node_id: str, depth: int = 4) -> Dict[str, Any]:
        """Find all evidence connected to a Report."""
        report_node = self.repo.get_node(report_node_id)
        if not report_node:
            return {"report_node_id": report_node_id, "evidence": []}

        result = self._traversal.bfs(report_node_id, max_depth=depth, direction="both")
        evidence = [
            n for n in result.nodes
            if n.get("node_type") in ("evidence", "packet", "flow", "dns_record",
                                       "http_session", "tls_session")
        ]
        return {
            "report_node_id": report_node_id,
            "report_node": report_node.to_dict(),
            "evidence": evidence,
            "evidence_count": len(evidence),
        }

    # =========================================================================
    # Subgraph Extraction
    # =========================================================================

    def extract_subgraph(
        self,
        seed_node_ids: List[str],
        depth: int = 2,
        direction: str = "both",
    ) -> SubgraphResult:
        """
        Build a bounded subgraph around a set of seed nodes.
        Used for visualization and focused investigation contexts.
        """
        all_node_dicts: Dict[str, Dict[str, Any]] = {}
        all_edge_dicts: Dict[str, Dict[str, Any]] = {}

        for seed_id in seed_node_ids:
            result = self._traversal.bfs(
                seed_id, max_depth=depth, direction=direction, limit=1000
            )
            for n in result.nodes:
                all_node_dicts[n["node_id"]] = n
            for e in result.edges:
                all_edge_dicts[e["edge_id"]] = e

        return SubgraphResult(
            subgraph_id=str(uuid.uuid4()),
            seed_nodes=seed_node_ids,
            nodes=list(all_node_dicts.values()),
            edges=list(all_edge_dicts.values()),
            depth=depth,
        )

    # =========================================================================
    # Context Expansion (AI Foundation)
    # =========================================================================

    def expand_context(
        self,
        node_id: str,
        depth: int = 2,
        max_nodes: int = 50,
    ) -> Dict[str, Any]:
        """
        Expand context around a node for AI reasoning.
        Returns structured neighborhood for LLM consumption.
        """
        node = self.repo.get_node(node_id)
        if not node:
            return {"node_id": node_id, "context": []}

        result = self._traversal.bfs(node_id, max_depth=depth, limit=max_nodes)

        # Group by node type for structured context
        context_by_type: Dict[str, List[Dict[str, Any]]] = {}
        for n in result.nodes:
            ntype = n.get("node_type", "unknown")
            context_by_type.setdefault(ntype, []).append({
                "node_id": n.get("node_id"),
                "label": n.get("label"),
                "name": n.get("name"),
                "external_id": n.get("external_id"),
                "confidence": n.get("confidence"),
            })

        return {
            "node_id": node_id,
            "node": node.to_dict(),
            "context_by_type": context_by_type,
            "total_context_nodes": len(result.nodes),
            "total_context_edges": len(result.edges),
        }

    # =========================================================================
    # Related Entities (AI Foundation)
    # =========================================================================

    def find_related_entities(
        self,
        node_id: str,
        target_type: str,
        depth: int = 4,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Find all entities of a specific type related to the given node.
        Used by AI reasoning for risk propagation and investigation enrichment.
        """
        result = self._traversal.bfs(node_id, max_depth=depth, direction="both", limit=500)
        return [
            n for n in result.nodes
            if n.get("node_type") == target_type
        ][:limit]

    # =========================================================================
    # Relationship Ranking (AI Foundation)
    # =========================================================================

    def rank_relationships(
        self,
        node_id: str,
        top_n: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Return the top-N most significant relationships for a node,
        ranked by confidence × weight × evidence_count.
        """
        edges = self.repo.get_edges_for_node(node_id, direction="both", limit=500)
        scored = []
        for edge in edges:
            score = edge.confidence * edge.weight * max(1, edge.evidence_count)
            neighbor_id = (
                edge.target_node_id
                if edge.source_node_id == node_id
                else edge.source_node_id
            )
            neighbor = self.repo.get_node(neighbor_id)
            scored.append({
                "edge": edge.to_dict(),
                "neighbor": neighbor.to_dict() if neighbor else None,
                "score": score,
            })

        return sorted(scored, key=lambda x: x["score"], reverse=True)[:top_n]
