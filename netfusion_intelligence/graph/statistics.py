"""
IL-8 UTKG — Graph Statistics Engine
=======================================
Computes: node/edge counts, type distributions, degree distribution,
          connected components, relationship density, average path length.
"""

import math
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional

from netfusion_intelligence.graph.models import GraphStatistics
from netfusion_intelligence.graph.repository import GraphRepository


class GraphStatisticsEngine:
    """
    Compute and persist graph topology statistics.
    All computations are performed via SQL aggregation where possible,
    falling back to in-memory algorithms for topology metrics.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository

    # =========================================================================
    # Main Statistics Computation
    # =========================================================================

    def compute_statistics(self, persist: bool = True) -> GraphStatistics:
        """
        Compute full graph statistics snapshot.
        Persists to DB if persist=True.
        """
        t0 = time.perf_counter()

        node_count = self.repo.count_nodes()
        edge_count = self.repo.count_edges()
        node_types = self.repo.get_node_types_distribution()
        edge_types = self.repo.get_edge_types_distribution()

        # Degree distribution (sampled for large graphs)
        degree_dist = self._compute_degree_distribution(sample_limit=5000)

        # Average degree
        avg_degree = (2 * edge_count / node_count) if node_count > 0 else 0.0

        # Relationship density: actual edges / possible edges
        possible_edges = node_count * (node_count - 1)
        density = (edge_count / possible_edges) if possible_edges > 0 else 0.0

        # Connected components (sampled)
        components = self._compute_connected_components_sample(sample_limit=2000)
        largest_component = max((len(c) for c in components), default=0)
        num_components = len(components)

        # Average path length (approximation via sample BFS)
        avg_path_length = self._estimate_average_path_length(sample_size=20)

        stats = GraphStatistics(
            node_count=node_count,
            edge_count=edge_count,
            node_types=node_types,
            edge_types=edge_types,
            degree_distribution=degree_dist,
            largest_component_size=largest_component,
            connected_components_count=num_components,
            relationship_density=round(density, 6),
            average_path_length=round(avg_path_length, 3),
            average_degree=round(avg_degree, 3),
        )

        if persist:
            self.repo.save_statistics(stats)

        return stats

    def get_current_statistics(self) -> Optional[GraphStatistics]:
        """Return the most recently persisted statistics snapshot."""
        return self.repo.get_latest_statistics()

    def get_or_compute_statistics(self) -> GraphStatistics:
        """Return cached stats if available, else compute fresh."""
        cached = self.get_current_statistics()
        if cached:
            return cached
        return self.compute_statistics(persist=True)

    # =========================================================================
    # Node / Edge Breakdowns
    # =========================================================================

    def get_node_type_breakdown(self) -> Dict[str, Any]:
        """Node count breakdown by type."""
        distribution = self.repo.get_node_types_distribution()
        total = sum(distribution.values())
        return {
            "total": total,
            "by_type": distribution,
            "percentages": {
                k: round((v / total) * 100, 2) if total > 0 else 0.0
                for k, v in distribution.items()
            },
        }

    def get_edge_type_breakdown(self) -> Dict[str, Any]:
        """Edge count breakdown by type."""
        distribution = self.repo.get_edge_types_distribution()
        total = sum(distribution.values())
        return {
            "total": total,
            "by_type": distribution,
            "percentages": {
                k: round((v / total) * 100, 2) if total > 0 else 0.0
                for k, v in distribution.items()
            },
        }

    # =========================================================================
    # Degree Distribution
    # =========================================================================

    def _compute_degree_distribution(self, sample_limit: int = 5000) -> Dict[int, int]:
        """Compute degree distribution over a sample of nodes."""
        nodes = self.repo.list_nodes(limit=sample_limit)
        degree_counts: Dict[int, int] = defaultdict(int)
        for node in nodes:
            deg = self.repo.get_degree(node.node_id)
            degree_counts[deg] += 1
        return dict(degree_counts)

    def get_high_degree_nodes(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """Return top-N nodes by degree (most connected)."""
        nodes = self.repo.list_nodes(limit=2000)
        scored = []
        for node in nodes:
            deg = self.repo.get_degree(node.node_id)
            scored.append({"node": node.to_dict(), "degree": deg})
        return sorted(scored, key=lambda x: x["degree"], reverse=True)[:top_n]

    # =========================================================================
    # Connected Components
    # =========================================================================

    def _compute_connected_components_sample(
        self, sample_limit: int = 2000
    ) -> List[List[str]]:
        """BFS-based connected components on a node sample."""
        from collections import deque
        nodes = self.repo.list_nodes(limit=sample_limit)
        node_id_set = {n.node_id for n in nodes}
        visited = set()
        components = []

        for node in nodes:
            if node.node_id in visited:
                continue
            component = []
            queue = deque([node.node_id])
            visited.add(node.node_id)
            while queue:
                nid = queue.popleft()
                component.append(nid)
                edges = self.repo.get_edges_for_node(nid, direction="both", limit=100)
                for e in edges:
                    neighbor = (
                        e.target_node_id if e.source_node_id == nid
                        else e.source_node_id
                    )
                    if neighbor not in visited and neighbor in node_id_set:
                        visited.add(neighbor)
                        queue.append(neighbor)
            components.append(component)

        return sorted(components, key=len, reverse=True)

    # =========================================================================
    # Average Path Length Estimate
    # =========================================================================

    def _estimate_average_path_length(self, sample_size: int = 20) -> float:
        """
        Estimate average path length via BFS from a random sample of nodes.
        Uses mean of BFS depth sums — O(sample_size × BFS cost).
        """
        from netfusion_intelligence.graph.traversal import GraphTraversalEngine
        traversal = GraphTraversalEngine(self.repo)

        nodes = self.repo.list_nodes(limit=sample_size)
        if len(nodes) < 2:
            return 0.0

        total_path_len = 0
        total_pairs = 0

        for node in nodes:
            result = traversal.bfs(node.node_id, max_depth=6, limit=100)
            depths = list(result.depth_map.values())
            if depths:
                total_path_len += sum(depths)
                total_pairs += len(depths)

        return (total_path_len / total_pairs) if total_pairs > 0 else 0.0

    # =========================================================================
    # Feed Contribution Summary
    # =========================================================================

    def get_feed_contribution_summary(self) -> Dict[str, Any]:
        """Breakdown of graph nodes by originating feed."""
        nodes = self.repo.list_nodes(limit=50000)
        feed_map: Dict[str, int] = defaultdict(int)
        for node in nodes:
            feed_map[node.source_feed or "unknown"] += 1
        return {
            "total_nodes": len(nodes),
            "by_feed": dict(feed_map),
        }
