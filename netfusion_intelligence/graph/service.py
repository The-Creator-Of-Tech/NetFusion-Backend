"""
IL-8 UTKG — Unified Threat Knowledge Graph Service
=====================================================
High-level orchestration layer.
All consumer code (API, AI, investigations) uses this class.
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.export import GraphExportService
from netfusion_intelligence.graph.fusion import KnowledgeFusionEngine
from netfusion_intelligence.graph.models import (
    GraphEdge, GraphExportFormat, GraphNode, GraphNodeType,
    GraphPath, GraphStatistics, GraphVersion,
    SearchResult, SubgraphResult, TraversalResult,
)
from netfusion_intelligence.graph.pathfinder import GraphPathFinder
from netfusion_intelligence.graph.relationships import GraphRelationshipManager
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.search import GraphSearchEngine
from netfusion_intelligence.graph.statistics import GraphStatisticsEngine
from netfusion_intelligence.graph.traversal import GraphTraversalEngine
from netfusion_intelligence.graph.visualization import GraphVisualizationBuilder


class UnifiedThreatKnowledgeGraph:
    """
    Central facade for IL-8 UTKG.
    Wire up once via dependency injection; use everywhere.
    """

    def __init__(
        self,
        graph_repository: GraphRepository,
        intelligence_repository: Any = None,  # SQLAlchemy repo (IL-1..IL-7)
    ):
        self.repo = graph_repository
        self.intel_repo = intelligence_repository

        # Engine instances
        self.traversal     = GraphTraversalEngine(graph_repository)
        self.search        = GraphSearchEngine(graph_repository)
        self.pathfinder    = GraphPathFinder(graph_repository)
        self.relationships = GraphRelationshipManager(graph_repository)
        self.statistics    = GraphStatisticsEngine(graph_repository)
        self.export        = GraphExportService(graph_repository)
        self.visualization = GraphVisualizationBuilder(graph_repository)

        if intelligence_repository:
            self.fusion = KnowledgeFusionEngine(graph_repository, intelligence_repository)
        else:
            self.fusion = None

    # =========================================================================
    # Node Operations
    # =========================================================================

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """GET /graph/node/{id}"""
        node = self.repo.get_node(node_id)
        return node.to_dict() if node else None

    def get_node_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        edge_type: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """GET /graph/node/{id}/neighbors"""
        neighbors = self.repo.get_neighbors(node_id, direction=direction, edge_type=edge_type, limit=limit)
        edges = self.repo.get_edges_for_node(node_id, direction=direction, edge_type=edge_type, limit=limit)
        return {
            "node_id": node_id,
            "neighbor_count": len(neighbors),
            "neighbors": [n.to_dict() for n in neighbors],
            "edges": [e.to_dict() for e in edges],
        }

    def add_node(
        self,
        canonical_id: str,
        node_type: str,
        label: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        source_feed: Optional[str] = None,
        external_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """Add or update a node. Returns the node dict."""
        node = GraphNode.create(
            canonical_id=canonical_id,
            node_type=node_type,
            label=label,
            name=name,
            description=description,
            source_feed=source_feed,
            external_id=external_id,
            properties=properties,
            confidence=confidence,
        )
        result, created = self.repo.upsert_node(node)
        return {"node": result.to_dict(), "created": created}

    # =========================================================================
    # Traversal
    # =========================================================================

    def traverse(
        self,
        node_id: str,
        algorithm: str = "bfs",
        max_depth: int = 3,
        edge_type: Optional[str] = None,
        direction: str = "both",
        limit: int = 500,
    ) -> Dict[str, Any]:
        """GET /graph/traverse"""
        if algorithm == "dfs":
            result = self.traversal.dfs(node_id, max_depth=max_depth, edge_type=edge_type,
                                         direction=direction, limit=limit)
        elif algorithm.startswith("k_hop"):
            k = int(algorithm.split("_")[-1]) if "_" in algorithm else max_depth
            result = self.traversal.k_hop(node_id, k=k, edge_type=edge_type, direction=direction)
        else:
            result = self.traversal.bfs(node_id, max_depth=max_depth, edge_type=edge_type,
                                         direction=direction, limit=limit)
        return result.to_dict()

    # =========================================================================
    # Path Finding
    # =========================================================================

    def find_path(
        self,
        source_node_id: str,
        target_node_id: str,
        algorithm: str = "shortest",
        max_depth: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """GET /graph/path"""
        if algorithm == "dijkstra":
            path = self.pathfinder.shortest_path_weighted(source_node_id, target_node_id, max_depth)
        elif algorithm == "all_simple":
            paths = self.pathfinder.all_simple_paths(source_node_id, target_node_id, max_depth=max_depth)
            return {
                "paths": [p.to_dict() for p in self.pathfinder.rank_paths(paths)],
                "count": len(paths),
            }
        else:
            path = self.pathfinder.shortest_path(source_node_id, target_node_id, max_depth=max_depth)

        return path.to_dict() if path else None

    def reconstruct_attack_chain(self, investigation_node_id: str, max_depth: int = 8) -> Dict[str, Any]:
        """Reconstruct full attack chain from an investigation node."""
        return self.pathfinder.reconstruct_attack_chain(investigation_node_id, max_depth=max_depth)

    # =========================================================================
    # Search
    # =========================================================================

    def search_graph(
        self,
        query: str,
        node_type: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """GET /graph/search"""
        result = self.search.search(query=query, node_type=node_type,
                                     min_confidence=min_confidence, limit=limit)
        return result.to_dict()

    # =========================================================================
    # Subgraph
    # =========================================================================

    def get_subgraph(
        self,
        node_ids: Optional[List[str]] = None,
        center_node_id: Optional[str] = None,
        depth: int = 2,
        direction: str = "both",
    ) -> Dict[str, Any]:
        """GET /graph/subgraph"""
        if center_node_id:
            result = self.search.extract_subgraph(
                seed_node_ids=[center_node_id], depth=depth, direction=direction
            )
        elif node_ids:
            result = self.search.extract_subgraph(seed_node_ids=node_ids, depth=depth)
        else:
            result = SubgraphResult()
        return result.to_dict()

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_statistics(self, recompute: bool = False) -> Dict[str, Any]:
        """GET /graph/statistics"""
        if recompute:
            stats = self.statistics.compute_statistics(persist=True)
        else:
            stats = self.statistics.get_or_compute_statistics()
        return stats.to_dict()

    # =========================================================================
    # Export
    # =========================================================================

    def export_graph(
        self,
        fmt: str = GraphExportFormat.JSON.value,
        node_ids: Optional[List[str]] = None,
        node_type: Optional[str] = None,
        limit: int = 10000,
    ) -> Dict[str, Any]:
        """GET /graph/export"""
        record = self.export.export(fmt=fmt, node_ids=node_ids, node_type=node_type, limit=limit)
        return {
            "record": record.to_dict(),
            "content": record.content,
        }

    # =========================================================================
    # Visualization
    # =========================================================================

    def build_visualization(
        self,
        fmt: str = "cytoscape",
        center_node_id: Optional[str] = None,
        node_ids: Optional[List[str]] = None,
        depth: int = 2,
        max_nodes: int = 200,
    ) -> Dict[str, Any]:
        """Build visualization payload for frontend."""
        if fmt == "react_flow":
            return self.visualization.build_react_flow(node_ids, center_node_id, depth, max_nodes)
        elif fmt == "d3":
            return self.visualization.build_d3_force(node_ids, center_node_id, depth, max_nodes)
        elif fmt == "sigma":
            return self.visualization.build_sigma(node_ids, center_node_id, depth, max_nodes)
        elif fmt == "neo4j":
            return self.visualization.build_neo4j_browser(node_ids, center_node_id, depth, max_nodes)
        else:
            return self.visualization.build_cytoscape(node_ids, center_node_id, depth, max_nodes)

    # =========================================================================
    # Knowledge Fusion
    # =========================================================================

    def run_fusion(self, layer: Optional[str] = None) -> Dict[str, Any]:
        """
        Run knowledge fusion from IL-1..IL-7.
        layer = None → full fusion; otherwise runs only the named layer.
        """
        if not self.fusion:
            return {"error": "No intelligence repository configured"}

        t0 = time.perf_counter()
        if layer == "mitre":
            result = {"mitre": self.fusion.fuse_mitre()}
        elif layer == "capec":
            result = {"capec": self.fusion.fuse_capec()}
        elif layer == "cwe":
            result = {"cwe": self.fusion.fuse_cwe()}
        elif layer == "cve":
            result = {"cve": self.fusion.fuse_cve()}
        elif layer == "kev":
            result = {"kev": self.fusion.fuse_kev()}
        elif layer == "epss":
            result = {"epss": self.fusion.fuse_epss()}
        elif layer == "ioc":
            result = {"ioc": self.fusion.fuse_ioc()}
        else:
            result = self.fusion.fuse_all()

        duration = round(time.perf_counter() - t0, 3)
        result["duration_seconds"] = duration
        # Recompute stats after fusion
        self.statistics.compute_statistics(persist=True)
        return result

    # =========================================================================
    # Version Management
    # =========================================================================

    def create_version(self, description: Optional[str] = None) -> Dict[str, Any]:
        v = self.repo.create_version(description=description)
        return v.to_dict()

    def rollback_version(self, version_id: str) -> bool:
        return self.repo.rollback_to_version(version_id)

    def list_versions(self) -> List[Dict[str, Any]]:
        return [v.to_dict() for v in self.repo.list_versions()]

    # =========================================================================
    # Investigation Queries
    # =========================================================================

    def iocs_for_cve(self, cve_id: str) -> Dict[str, Any]:
        return self.search.find_iocs_for_cve(cve_id)

    def techniques_for_actor(self, actor_id: str) -> Dict[str, Any]:
        return self.search.find_techniques_for_threat_actor(actor_id)

    def campaigns_for_ioc(self, ioc_value: str) -> Dict[str, Any]:
        return self.search.find_campaigns_for_ioc(ioc_value)

    def assets_exposed_to_kev(self, kev_cve_id: str) -> Dict[str, Any]:
        return self.search.find_assets_exposed_to_kev(kev_cve_id)

    def investigations_for_ioc(self, ioc_value: str) -> Dict[str, Any]:
        return self.search.find_investigations_for_ioc(ioc_value)

    def evidence_for_report(self, report_node_id: str) -> Dict[str, Any]:
        return self.search.find_evidence_for_report(report_node_id)

    # =========================================================================
    # AI Foundation
    # =========================================================================

    def expand_context(self, node_id: str, depth: int = 2, max_nodes: int = 50) -> Dict[str, Any]:
        return self.search.expand_context(node_id, depth=depth, max_nodes=max_nodes)

    def find_related_entities(self, node_id: str, target_type: str, depth: int = 4) -> List[Dict[str, Any]]:
        return self.search.find_related_entities(node_id, target_type=target_type, depth=depth)

    def rank_relationships(self, node_id: str, top_n: int = 20) -> List[Dict[str, Any]]:
        return self.search.rank_relationships(node_id, top_n=top_n)

    def propagate_confidence(self, node_id: str, decay: float = 0.8, max_depth: int = 3) -> Dict[str, float]:
        return self.relationships.propagate_confidence(node_id, decay=decay, max_depth=max_depth)

    def can_reach(self, source_id: str, target_id: str, max_depth: int = 10) -> bool:
        return self.traversal.can_reach(source_id, target_id, max_depth=max_depth)

    def detect_cycle(self, node_id: str) -> bool:
        return self.traversal.has_cycle(node_id)
