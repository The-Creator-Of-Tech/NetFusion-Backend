"""
IL-8 UTKG — Graph Visualization Builder
==========================================
Builds graph models suitable for: Cytoscape.js, React Flow, D3.js,
Sigma.js, Neo4j Browser.
Each builder returns a dict the frontend can consume directly.
"""

import math
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.models import GraphNode, GraphEdge
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.traversal import GraphTraversalEngine


# ---------------------------------------------------------------------------
# Node color / shape registry by node type
# ---------------------------------------------------------------------------

_NODE_COLORS: Dict[str, str] = {
    "cve":              "#E74C3C",   # red
    "kev":              "#C0392B",   # dark red
    "epss_record":      "#E67E22",   # orange
    "cwe":              "#F39C12",   # amber
    "capec":            "#D35400",   # dark orange
    "attack_technique": "#2980B9",   # blue
    "attack_tactic":    "#1A5276",   # dark blue
    "ioc":              "#27AE60",   # green
    "domain":           "#1E8449",
    "url":              "#239B56",
    "ip":               "#16A085",
    "hash":             "#148F77",
    "email":            "#117A65",
    "malware":          "#8E44AD",   # purple
    "campaign":         "#6C3483",   # dark purple
    "threat_actor":     "#922B21",   # crimson
    "attack_group":     "#7B241C",
    "host":             "#2471A3",   # steel blue
    "asset":            "#1F618D",
    "device":           "#1A5276",
    "network":          "#154360",
    "software":         "#21618C",
    "service":          "#1B4F72",
    "investigation":    "#F0B27A",   # peach
    "alert":            "#F1948A",
    "finding":          "#F8C471",
    "evidence":         "#A9CCE3",   # light blue
    "report":           "#A9DFBF",   # light green
    "user":             "#85C1E9",
    "organization":     "#82E0AA",
}

_NODE_SHAPES: Dict[str, str] = {
    "cve":              "triangle",
    "attack_technique": "diamond",
    "ioc":              "ellipse",
    "malware":          "pentagon",
    "campaign":         "hexagon",
    "threat_actor":     "star",
    "host":             "rectangle",
    "asset":            "rectangle",
    "investigation":    "roundrectangle",
    "evidence":         "vee",
    "report":           "tag",
}

_DEFAULT_COLOR = "#95A5A6"
_DEFAULT_SHAPE = "ellipse"


class GraphVisualizationBuilder:
    """
    Builds visualization-ready graph payloads.
    Supports Cytoscape.js, React Flow, D3.js, Sigma.js, and Neo4j Browser.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository
        self._traversal = GraphTraversalEngine(repository)

    # =========================================================================
    # Cytoscape.js  (most feature-rich, default)
    # =========================================================================

    def build_cytoscape(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        max_nodes: int = 200,
    ) -> Dict[str, Any]:
        """
        Build Cytoscape.js-compatible element array.
        Format: {"elements": {"nodes": [...], "edges": [...]}}
        """
        nodes, edges = self._resolve_graph(node_ids, center_node_id, depth, max_nodes)

        cy_nodes = []
        for n in nodes:
            color = _NODE_COLORS.get(n.node_type, _DEFAULT_COLOR)
            shape = _NODE_SHAPES.get(n.node_type, _DEFAULT_SHAPE)
            cy_nodes.append({
                "data": {
                    "id": n.node_id,
                    "label": n.label[:60],
                    "node_type": n.node_type,
                    "canonical_id": n.canonical_id,
                    "external_id": n.external_id,
                    "source_feed": n.source_feed,
                    "confidence": n.confidence,
                    "name": n.name,
                },
                "style": {
                    "background-color": color,
                    "shape": shape,
                    "label": n.label[:40],
                    "width": max(20, min(60, int(n.confidence * 50))),
                    "height": max(20, min(60, int(n.confidence * 50))),
                },
            })

        cy_edges = []
        for e in edges:
            cy_edges.append({
                "data": {
                    "id": e.edge_id,
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "edge_type": e.edge_type,
                    "confidence": e.confidence,
                    "weight": e.weight,
                    "evidence_count": e.evidence_count,
                    "label": e.edge_type.replace("_", " "),
                },
            })

        return {
            "format": "cytoscape",
            "elements": {"nodes": cy_nodes, "edges": cy_edges},
            "node_count": len(cy_nodes),
            "edge_count": len(cy_edges),
        }

    # =========================================================================
    # React Flow
    # =========================================================================

    def build_react_flow(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        max_nodes: int = 150,
    ) -> Dict[str, Any]:
        """
        Build React Flow compatible nodes/edges array.
        Format: {"nodes": [...], "edges": [...]}
        """
        nodes, edges = self._resolve_graph(node_ids, center_node_id, depth, max_nodes)
        positions = _compute_radial_positions(nodes, center_node_id)

        rf_nodes = []
        for i, n in enumerate(nodes):
            pos = positions.get(n.node_id, {"x": i * 150, "y": 0})
            color = _NODE_COLORS.get(n.node_type, _DEFAULT_COLOR)
            rf_nodes.append({
                "id": n.node_id,
                "type": "default",
                "position": pos,
                "data": {
                    "label": n.label[:50],
                    "node_type": n.node_type,
                    "external_id": n.external_id,
                    "confidence": n.confidence,
                    "source_feed": n.source_feed,
                },
                "style": {
                    "background": color,
                    "color": "#fff",
                    "border": "1px solid #555",
                    "borderRadius": "6px",
                    "padding": "8px",
                    "fontSize": "11px",
                },
            })

        rf_edges = []
        for e in edges:
            rf_edges.append({
                "id": e.edge_id,
                "source": e.source_node_id,
                "target": e.target_node_id,
                "label": e.edge_type.replace("_", " "),
                "type": "smoothstep",
                "animated": e.edge_type in ("EXPLOITS", "TARGETS", "USES"),
                "style": {"stroke": "#888"},
                "data": {
                    "edge_type": e.edge_type,
                    "confidence": e.confidence,
                    "weight": e.weight,
                },
            })

        return {
            "format": "react_flow",
            "nodes": rf_nodes,
            "edges": rf_edges,
            "node_count": len(rf_nodes),
            "edge_count": len(rf_edges),
        }

    # =========================================================================
    # D3.js Force Graph
    # =========================================================================

    def build_d3_force(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        max_nodes: int = 200,
    ) -> Dict[str, Any]:
        """
        Build D3.js force-directed graph format.
        Format: {"nodes": [...], "links": [...]}
        """
        nodes, edges = self._resolve_graph(node_ids, center_node_id, depth, max_nodes)
        node_index = {n.node_id: i for i, n in enumerate(nodes)}

        d3_nodes = []
        for n in nodes:
            d3_nodes.append({
                "id": n.node_id,
                "index": node_index[n.node_id],
                "label": n.label[:60],
                "group": n.node_type,
                "color": _NODE_COLORS.get(n.node_type, _DEFAULT_COLOR),
                "confidence": n.confidence,
                "external_id": n.external_id,
                "source_feed": n.source_feed,
                "radius": max(6, min(20, int(n.confidence * 15))),
            })

        d3_links = []
        for e in edges:
            if e.source_node_id in node_index and e.target_node_id in node_index:
                d3_links.append({
                    "id": e.edge_id,
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "type": e.edge_type,
                    "value": e.weight,
                    "confidence": e.confidence,
                })

        return {
            "format": "d3_force",
            "nodes": d3_nodes,
            "links": d3_links,
            "node_count": len(d3_nodes),
            "link_count": len(d3_links),
        }

    # =========================================================================
    # Sigma.js
    # =========================================================================

    def build_sigma(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        max_nodes: int = 200,
    ) -> Dict[str, Any]:
        """
        Build Sigma.js graph format.
        Format: {"nodes": [...], "edges": [...]} with x/y positions.
        """
        nodes, edges = self._resolve_graph(node_ids, center_node_id, depth, max_nodes)
        positions = _compute_radial_positions(nodes, center_node_id)

        sigma_nodes = []
        for n in nodes:
            pos = positions.get(n.node_id, {"x": 0.0, "y": 0.0})
            sigma_nodes.append({
                "id": n.node_id,
                "label": n.label[:50],
                "x": pos["x"],
                "y": pos["y"],
                "size": max(2, min(12, int(n.confidence * 10))),
                "color": _NODE_COLORS.get(n.node_type, _DEFAULT_COLOR),
                "attributes": {
                    "node_type": n.node_type,
                    "external_id": n.external_id,
                    "source_feed": n.source_feed,
                },
            })

        sigma_edges = []
        for e in edges:
            sigma_edges.append({
                "id": e.edge_id,
                "source": e.source_node_id,
                "target": e.target_node_id,
                "label": e.edge_type,
                "size": max(1, int(e.weight)),
                "color": "#aaa",
            })

        return {
            "format": "sigma",
            "nodes": sigma_nodes,
            "edges": sigma_edges,
            "node_count": len(sigma_nodes),
            "edge_count": len(sigma_edges),
        }

    # =========================================================================
    # Neo4j Browser (Cypher-style metadata)
    # =========================================================================

    def build_neo4j_browser(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        max_nodes: int = 200,
    ) -> Dict[str, Any]:
        """
        Build Neo4j Browser-compatible graph format.
        Includes Cypher CREATE statements and node/relationship metadata.
        """
        nodes, edges = self._resolve_graph(node_ids, center_node_id, depth, max_nodes)

        cypher_lines = []
        for n in nodes:
            lbl = n.node_type.upper().replace("_", "")
            props = {
                "node_id": n.node_id,
                "canonical_id": n.canonical_id,
                "label": n.label[:100],
                "external_id": n.external_id or "",
                "source_feed": n.source_feed or "",
                "confidence": n.confidence,
            }
            props_str = ", ".join(f'{k}: {_cypher_val(v)}' for k, v in props.items())
            safe_id = "n" + n.node_id.replace("-", "")[:16]
            cypher_lines.append(f"MERGE ({safe_id}:{lbl} {{{props_str}}})")

        for e in edges:
            src = "n" + e.source_node_id.replace("-", "")[:16]
            tgt = "n" + e.target_node_id.replace("-", "")[:16]
            rel = e.edge_type.upper()
            cypher_lines.append(
                f"MERGE ({src})-[:{rel} {{confidence: {e.confidence}, "
                f"weight: {e.weight}}}]->({tgt})"
            )

        return {
            "format": "neo4j_browser",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "cypher_create": "\n".join(cypher_lines),
        }

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _resolve_graph(
        self,
        node_ids: Optional[List[str]],
        center_node_id: Optional[str],
        depth: int,
        max_nodes: int,
    ):
        if center_node_id:
            result = self._traversal.bfs(center_node_id, max_depth=depth, limit=max_nodes)
            node_id_set = {n["node_id"] for n in result.nodes}
            nodes = [self.repo.get_node(nid) for nid in node_id_set]
            nodes = [n for n in nodes if n]
            # Fetch internal edges
            seen_edges = set()
            edges = []
            for n in nodes:
                for e in self.repo.get_edges_for_node(n.node_id, direction="out", limit=200):
                    if e.edge_id not in seen_edges and e.target_node_id in node_id_set:
                        seen_edges.add(e.edge_id)
                        edges.append(e)
        elif node_ids:
            nodes = [n for nid in node_ids for n in [self.repo.get_node(nid)] if n]
            node_id_set = {n.node_id for n in nodes}
            seen_edges = set()
            edges = []
            for n in nodes:
                for e in self.repo.get_edges_for_node(n.node_id, limit=200):
                    if e.edge_id not in seen_edges:
                        seen_edges.add(e.edge_id)
                        edges.append(e)
        else:
            nodes = self.repo.list_nodes(limit=max_nodes)
            node_id_set = {n.node_id for n in nodes}
            seen_edges = set()
            edges = []
            for n in nodes[:200]:
                for e in self.repo.get_edges_for_node(n.node_id, direction="out", limit=50):
                    if e.edge_id not in seen_edges:
                        seen_edges.add(e.edge_id)
                        edges.append(e)

        return nodes, edges


# ---------------------------------------------------------------------------
# Position Helpers
# ---------------------------------------------------------------------------

def _compute_radial_positions(
    nodes: list,
    center_node_id: Optional[str],
    radius_step: float = 200.0,
) -> Dict[str, Dict[str, float]]:
    """Assign radial x/y positions — center node at origin, others in rings."""
    positions: Dict[str, Dict[str, float]] = {}
    if not nodes:
        return positions

    center_id = center_node_id or nodes[0].node_id
    positions[center_id] = {"x": 0.0, "y": 0.0}
    remaining = [n for n in nodes if n.node_id != center_id]

    ring = 1
    idx = 0
    while idx < len(remaining):
        ring_size = max(1, ring * 6)
        ring_nodes = remaining[idx: idx + ring_size]
        r = radius_step * ring
        for j, n in enumerate(ring_nodes):
            angle = (2 * math.pi * j) / len(ring_nodes)
            positions[n.node_id] = {
                "x": round(r * math.cos(angle), 2),
                "y": round(r * math.sin(angle), 2),
            }
        idx += ring_size
        ring += 1

    return positions


def _cypher_val(v: Any) -> str:
    if isinstance(v, str):
        escaped = v.replace("'", "\\'")
        return f"'{escaped}'"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)
