"""
IL-8 UTKG — Graph Export Service
===================================
Supports: JSON, GraphML, GEXF, CSV, DOT, Mermaid
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.models import (
    GraphEdge, GraphExportFormat, GraphExportRecord, GraphNode
)
from netfusion_intelligence.graph.repository import GraphRepository


class GraphExportService:
    """
    Export the UTKG (or a filtered subgraph) to multiple formats.
    All exports are suitable for external tools: Cytoscape, Gephi, Neo4j, Graphviz.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository

    # =========================================================================
    # Main Export Dispatcher
    # =========================================================================

    def export(
        self,
        fmt: str = GraphExportFormat.JSON.value,
        node_ids: Optional[List[str]] = None,
        node_type: Optional[str] = None,
        limit: int = 10000,
    ) -> GraphExportRecord:
        """
        Export graph data to the requested format.
        Optionally filter to a specific set of node_ids or a node_type.
        """
        nodes, edges = self._collect_data(node_ids, node_type, limit)

        if fmt == GraphExportFormat.JSON.value:
            content = self._to_json(nodes, edges)
        elif fmt == GraphExportFormat.GRAPHML.value:
            content = self._to_graphml(nodes, edges)
        elif fmt == GraphExportFormat.GEXF.value:
            content = self._to_gexf(nodes, edges)
        elif fmt == GraphExportFormat.CSV.value:
            content = self._to_csv(nodes, edges)
        elif fmt == GraphExportFormat.DOT.value:
            content = self._to_dot(nodes, edges)
        elif fmt == GraphExportFormat.MERMAID.value:
            content = self._to_mermaid(nodes, edges)
        else:
            content = self._to_json(nodes, edges)

        record = GraphExportRecord(
            export_id=str(uuid.uuid4()),
            format=fmt,
            node_count=len(nodes),
            edge_count=len(edges),
            content=content,
        )
        self.repo.save_export_record(record)
        return record

    # =========================================================================
    # Data Collection
    # =========================================================================

    def _collect_data(
        self,
        node_ids: Optional[List[str]],
        node_type: Optional[str],
        limit: int,
    ):
        if node_ids:
            nodes = [n for nid in node_ids for n in [self.repo.get_node(nid)] if n]
            # Collect edges between these nodes
            node_id_set = {n.node_id for n in nodes}
            all_edges = []
            seen_edges = set()
            for n in nodes:
                for e in self.repo.get_edges_for_node(n.node_id, limit=500):
                    if e.edge_id not in seen_edges:
                        if e.source_node_id in node_id_set or e.target_node_id in node_id_set:
                            seen_edges.add(e.edge_id)
                            all_edges.append(e)
            edges = all_edges
        else:
            nodes = self.repo.list_nodes(node_type=node_type, limit=limit)
            node_id_set = {n.node_id for n in nodes}
            all_edges = []
            seen_edges = set()
            for n in nodes[:min(len(nodes), 1000)]:  # cap edge collection
                for e in self.repo.get_edges_for_node(n.node_id, direction="out", limit=200):
                    if e.edge_id not in seen_edges:
                        seen_edges.add(e.edge_id)
                        all_edges.append(e)
            edges = all_edges

        return nodes, edges

    # =========================================================================
    # JSON
    # =========================================================================

    def _to_json(self, nodes, edges) -> str:
        return json.dumps(
            {
                "graph": {
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                    "nodes": [n.to_dict() for n in nodes],
                    "edges": [e.to_dict() for e in edges],
                }
            },
            indent=2,
            default=str,
        )

    # =========================================================================
    # GraphML
    # =========================================================================

    def _to_graphml(self, nodes, edges) -> str:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/graphml"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://graphml.graphdrawing.org/graphml '
            'http://graphml.graphdrawing.org/graphml/graphml.xsd">',
            '  <!-- Node attribute keys -->',
            '  <key id="node_type"     for="node" attr.name="node_type"     attr.type="string"/>',
            '  <key id="label"         for="node" attr.name="label"         attr.type="string"/>',
            '  <key id="external_id"   for="node" attr.name="external_id"   attr.type="string"/>',
            '  <key id="canonical_id"  for="node" attr.name="canonical_id"  attr.type="string"/>',
            '  <key id="confidence"    for="node" attr.name="confidence"    attr.type="double"/>',
            '  <key id="source_feed"   for="node" attr.name="source_feed"   attr.type="string"/>',
            '  <!-- Edge attribute keys -->',
            '  <key id="edge_type"     for="edge" attr.name="edge_type"     attr.type="string"/>',
            '  <key id="weight"        for="edge" attr.name="weight"        attr.type="double"/>',
            '  <key id="edge_conf"     for="edge" attr.name="confidence"    attr.type="double"/>',
            '  <key id="evidence_count" for="edge" attr.name="evidence_count" attr.type="int"/>',
            '  <graph id="UTKG" edgedefault="directed">',
        ]

        for n in nodes:
            nid = _xml_escape(n.node_id)
            lines.append(f'    <node id="{nid}">')
            lines.append(f'      <data key="node_type">{_xml_escape(n.node_type)}</data>')
            lines.append(f'      <data key="label">{_xml_escape(n.label[:200])}</data>')
            lines.append(f'      <data key="external_id">{_xml_escape(n.external_id or "")}</data>')
            lines.append(f'      <data key="canonical_id">{_xml_escape(n.canonical_id)}</data>')
            lines.append(f'      <data key="confidence">{n.confidence}</data>')
            lines.append(f'      <data key="source_feed">{_xml_escape(n.source_feed or "")}</data>')
            lines.append("    </node>")

        for e in edges:
            eid = _xml_escape(e.edge_id)
            src = _xml_escape(e.source_node_id)
            tgt = _xml_escape(e.target_node_id)
            lines.append(f'    <edge id="{eid}" source="{src}" target="{tgt}">')
            lines.append(f'      <data key="edge_type">{_xml_escape(e.edge_type)}</data>')
            lines.append(f'      <data key="weight">{e.weight}</data>')
            lines.append(f'      <data key="edge_conf">{e.confidence}</data>')
            lines.append(f'      <data key="evidence_count">{e.evidence_count}</data>')
            lines.append("    </edge>")

        lines += ["  </graph>", "</graphml>"]
        return "\n".join(lines)

    # =========================================================================
    # GEXF (Gephi)
    # =========================================================================

    def _to_gexf(self, nodes, edges) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
            f'  <meta lastmodifieddate="{now}">',
            '    <creator>NetFusion IL-8 UTKG</creator>',
            '    <description>Unified Threat Knowledge Graph</description>',
            "  </meta>",
            '  <graph defaultedgetype="directed">',
            '    <attributes class="node">',
            '      <attribute id="0" title="node_type"   type="string"/>',
            '      <attribute id="1" title="external_id" type="string"/>',
            '      <attribute id="2" title="confidence"  type="float"/>',
            '      <attribute id="3" title="source_feed" type="string"/>',
            "    </attributes>",
            '    <attributes class="edge">',
            '      <attribute id="0" title="edge_type"     type="string"/>',
            '      <attribute id="1" title="evidence_count" type="integer"/>',
            "    </attributes>",
            "    <nodes>",
        ]

        for n in nodes:
            nid = _xml_escape(n.node_id)
            lbl = _xml_escape(n.label[:200])
            lines.append(f'      <node id="{nid}" label="{lbl}">')
            lines.append("        <attvalues>")
            lines.append(f'          <attvalue for="0" value="{_xml_escape(n.node_type)}"/>')
            lines.append(f'          <attvalue for="1" value="{_xml_escape(n.external_id or "")}"/>')
            lines.append(f'          <attvalue for="2" value="{n.confidence}"/>')
            lines.append(f'          <attvalue for="3" value="{_xml_escape(n.source_feed or "")}"/>')
            lines.append("        </attvalues>")
            lines.append("      </node>")

        lines.append("    </nodes>")
        lines.append("    <edges>")

        for i, e in enumerate(edges):
            src = _xml_escape(e.source_node_id)
            tgt = _xml_escape(e.target_node_id)
            lines.append(
                f'      <edge id="{i}" source="{src}" target="{tgt}" weight="{e.weight}">'
            )
            lines.append("        <attvalues>")
            lines.append(f'          <attvalue for="0" value="{_xml_escape(e.edge_type)}"/>')
            lines.append(f'          <attvalue for="1" value="{e.evidence_count}"/>')
            lines.append("        </attvalues>")
            lines.append("      </edge>")

        lines += ["    </edges>", "  </graph>", "</gexf>"]
        return "\n".join(lines)

    # =========================================================================
    # CSV (two files: nodes + edges — returned as combined string with separator)
    # =========================================================================

    def _to_csv(self, nodes, edges) -> str:
        out = io.StringIO()
        writer = csv.writer(out)

        # Nodes section
        writer.writerow(["# NODES"])
        writer.writerow([
            "node_id", "canonical_id", "node_type", "label",
            "external_id", "source_feed", "confidence", "is_active",
        ])
        for n in nodes:
            writer.writerow([
                n.node_id, n.canonical_id, n.node_type,
                n.label[:200], n.external_id or "", n.source_feed or "",
                n.confidence, n.is_active,
            ])

        writer.writerow([])
        writer.writerow(["# EDGES"])
        writer.writerow([
            "edge_id", "source_node_id", "target_node_id",
            "edge_type", "confidence", "weight", "evidence_count", "source_feed",
        ])
        for e in edges:
            writer.writerow([
                e.edge_id, e.source_node_id, e.target_node_id,
                e.edge_type, e.confidence, e.weight,
                e.evidence_count, e.source_feed or "",
            ])

        return out.getvalue()

    # =========================================================================
    # DOT (Graphviz)
    # =========================================================================

    def _to_dot(self, nodes, edges) -> str:
        lines = ["digraph UTKG {", '  rankdir=LR;', '  node [shape=box fontsize=10];']

        color_map = {
            "cve": "lightcoral", "cwe": "lightyellow", "capec": "lightsalmon",
            "attack_technique": "lightblue", "ioc": "lightgreen",
            "malware": "orchid", "campaign": "plum",
            "threat_actor": "tomato", "host": "azure", "asset": "azure",
        }

        for n in nodes:
            color = color_map.get(n.node_type, "white")
            lbl = _dot_escape(n.label[:50])
            ntype = n.node_type
            lines.append(
                f'  "{n.node_id}" [label="{lbl}\\n({ntype})" '
                f'fillcolor="{color}" style=filled];'
            )

        for e in edges:
            etype = _dot_escape(e.edge_type)
            lines.append(
                f'  "{e.source_node_id}" -> "{e.target_node_id}" '
                f'[label="{etype}" weight={e.weight}];'
            )

        lines.append("}")
        return "\n".join(lines)

    # =========================================================================
    # Mermaid
    # =========================================================================

    def _to_mermaid(self, nodes, edges) -> str:
        lines = ["graph LR"]

        # Limit for readability
        max_nodes = min(len(nodes), 50)
        max_edges = min(len(edges), 80)
        node_subset = {n.node_id for n in nodes[:max_nodes]}

        for n in nodes[:max_nodes]:
            lbl = n.label[:40].replace('"', "'")
            safe_id = _mermaid_id(n.node_id)
            lines.append(f'    {safe_id}["{lbl}"]')

        for e in edges[:max_edges]:
            if e.source_node_id in node_subset and e.target_node_id in node_subset:
                src = _mermaid_id(e.source_node_id)
                tgt = _mermaid_id(e.target_node_id)
                etype = e.edge_type.replace("_", " ")
                lines.append(f"    {src} -->|{etype}| {tgt}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _xml_escape(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _dot_escape(s: str) -> str:
    return str(s).replace('"', '\\"').replace("\n", " ")


def _mermaid_id(node_id: str) -> str:
    """Convert UUID to a Mermaid-safe identifier."""
    return "n" + node_id.replace("-", "")[:16]
