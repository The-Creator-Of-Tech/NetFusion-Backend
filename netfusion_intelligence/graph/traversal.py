"""
IL-8 UTKG — Graph Traversal Engine
=====================================
Implements: BFS, DFS, K-Hop, Neighborhood Search, Reachability,
            Connected Components, Cycle Detection.
Pure Python — no external graph library required.
Scales via SQL-backed adjacency (repository) rather than in-memory graphs.
"""

import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from netfusion_intelligence.graph.models import (
    GraphEdge, GraphNode, GraphNodeType, TraversalResult
)
from netfusion_intelligence.graph.repository import GraphRepository


class GraphTraversalEngine:
    """
    Traversal operations over the UTKG.
    All traversals use the GraphRepository for adjacency lookups,
    making them scalable without loading the full graph into memory.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository

    # =========================================================================
    # Breadth-First Search
    # =========================================================================

    def bfs(
        self,
        start_node_id: str,
        max_depth: int = 3,
        edge_type: Optional[str] = None,
        node_type_filter: Optional[str] = None,
        direction: str = "both",
        limit: int = 500,
    ) -> TraversalResult:
        """
        Breadth-first search from start_node, up to max_depth hops.
        Returns all reachable nodes and their connecting edges.
        """
        t0 = time.perf_counter()
        traversal_id = str(uuid.uuid4())

        visited_nodes: Dict[str, int] = {}  # node_id → depth
        visited_edges: Set[str] = set()
        result_nodes: List[Dict[str, Any]] = []
        result_edges: List[Dict[str, Any]] = []

        queue: deque = deque()
        start = self.repo.get_node(start_node_id)
        if not start:
            return TraversalResult(
                traversal_id=traversal_id,
                algorithm="bfs",
                start_node_id=start_node_id,
                max_depth=max_depth,
            )

        queue.append((start, 0))
        visited_nodes[start_node_id] = 0
        result_nodes.append(start.to_dict())

        while queue and len(result_nodes) < limit:
            current_node, depth = queue.popleft()
            if depth >= max_depth:
                continue

            edges = self.repo.get_edges_for_node(
                current_node.node_id,
                direction=direction,
                edge_type=edge_type,
            )

            for edge in edges:
                if edge.edge_id not in visited_edges:
                    visited_edges.add(edge.edge_id)
                    result_edges.append(edge.to_dict())

                # Determine the neighbor node id
                neighbor_id = (
                    edge.target_node_id
                    if edge.source_node_id == current_node.node_id
                    else edge.source_node_id
                )

                if neighbor_id not in visited_nodes:
                    neighbor = self.repo.get_node(neighbor_id)
                    if neighbor and neighbor.is_active:
                        if node_type_filter and neighbor.node_type != node_type_filter:
                            continue
                        visited_nodes[neighbor_id] = depth + 1
                        result_nodes.append(neighbor.to_dict())
                        queue.append((neighbor, depth + 1))

                        if len(result_nodes) >= limit:
                            break

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        return TraversalResult(
            traversal_id=traversal_id,
            algorithm="bfs",
            start_node_id=start_node_id,
            max_depth=max_depth,
            nodes=result_nodes,
            edges=result_edges,
            depth_map=visited_nodes,
            duration_ms=duration_ms,
        )

    # =========================================================================
    # Depth-First Search
    # =========================================================================

    def dfs(
        self,
        start_node_id: str,
        max_depth: int = 5,
        edge_type: Optional[str] = None,
        direction: str = "both",
        limit: int = 500,
    ) -> TraversalResult:
        """Iterative depth-first search."""
        t0 = time.perf_counter()
        traversal_id = str(uuid.uuid4())

        visited_nodes: Dict[str, int] = {}
        visited_edges: Set[str] = set()
        result_nodes: List[Dict[str, Any]] = []
        result_edges: List[Dict[str, Any]] = []

        start = self.repo.get_node(start_node_id)
        if not start:
            return TraversalResult(
                traversal_id=traversal_id, algorithm="dfs",
                start_node_id=start_node_id, max_depth=max_depth,
            )

        # Stack: (node, depth)
        stack = [(start, 0)]
        visited_nodes[start_node_id] = 0
        result_nodes.append(start.to_dict())

        while stack and len(result_nodes) < limit:
            current_node, depth = stack.pop()
            if depth >= max_depth:
                continue

            edges = self.repo.get_edges_for_node(
                current_node.node_id, direction=direction, edge_type=edge_type
            )

            for edge in edges:
                if edge.edge_id not in visited_edges:
                    visited_edges.add(edge.edge_id)
                    result_edges.append(edge.to_dict())

                neighbor_id = (
                    edge.target_node_id
                    if edge.source_node_id == current_node.node_id
                    else edge.source_node_id
                )

                if neighbor_id not in visited_nodes:
                    neighbor = self.repo.get_node(neighbor_id)
                    if neighbor and neighbor.is_active:
                        visited_nodes[neighbor_id] = depth + 1
                        result_nodes.append(neighbor.to_dict())
                        stack.append((neighbor, depth + 1))

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        return TraversalResult(
            traversal_id=traversal_id,
            algorithm="dfs",
            start_node_id=start_node_id,
            max_depth=max_depth,
            nodes=result_nodes,
            edges=result_edges,
            depth_map=visited_nodes,
            duration_ms=duration_ms,
        )

    # =========================================================================
    # K-Hop Traversal
    # =========================================================================

    def k_hop(
        self,
        start_node_id: str,
        k: int = 2,
        edge_type: Optional[str] = None,
        direction: str = "both",
    ) -> TraversalResult:
        """
        Return exactly the k-hop neighborhood — nodes exactly k hops away.
        """
        full_result = self.bfs(
            start_node_id, max_depth=k, edge_type=edge_type, direction=direction
        )
        # Filter to only nodes at depth == k
        k_nodes = [
            n for n in full_result.nodes
            if full_result.depth_map.get(n["node_id"], 0) == k
        ]
        return TraversalResult(
            traversal_id=str(uuid.uuid4()),
            algorithm=f"k_hop_{k}",
            start_node_id=start_node_id,
            max_depth=k,
            nodes=k_nodes,
            edges=full_result.edges,
            depth_map={
                nid: d for nid, d in full_result.depth_map.items() if d == k
            },
            duration_ms=full_result.duration_ms,
        )

    # =========================================================================
    # Neighborhood Search
    # =========================================================================

    def neighborhood(
        self,
        node_id: str,
        radius: int = 1,
        direction: str = "both",
    ) -> TraversalResult:
        """All nodes within radius hops (inclusive)."""
        return self.bfs(node_id, max_depth=radius, direction=direction)

    # =========================================================================
    # Reachability
    # =========================================================================

    def can_reach(self, source_node_id: str, target_node_id: str, max_depth: int = 10) -> bool:
        """Returns True if target is reachable from source within max_depth hops."""
        result = self.bfs(source_node_id, max_depth=max_depth)
        return any(n["node_id"] == target_node_id for n in result.nodes)

    # =========================================================================
    # Connected Components (BFS-based, sampling approach)
    # =========================================================================

    def find_connected_components(
        self,
        max_nodes: int = 10000,
    ) -> List[List[str]]:
        """
        Returns list of connected components (as lists of node_ids).
        Operates on the active subset of nodes.
        """
        all_nodes = self.repo.list_nodes(limit=max_nodes)
        node_ids = {n.node_id for n in all_nodes}
        visited: Set[str] = set()
        components: List[List[str]] = []

        for node in all_nodes:
            if node.node_id in visited:
                continue
            # BFS from this node
            component: List[str] = []
            queue: deque = deque([node.node_id])
            visited.add(node.node_id)

            while queue:
                current_id = queue.popleft()
                component.append(current_id)
                edges = self.repo.get_edges_for_node(current_id, direction="both", limit=200)
                for edge in edges:
                    neighbor_id = (
                        edge.target_node_id
                        if edge.source_node_id == current_id
                        else edge.source_node_id
                    )
                    if neighbor_id not in visited and neighbor_id in node_ids:
                        visited.add(neighbor_id)
                        queue.append(neighbor_id)

            components.append(component)

        return sorted(components, key=len, reverse=True)

    # =========================================================================
    # Cycle Detection
    # =========================================================================

    def has_cycle(self, start_node_id: str, max_depth: int = 8) -> bool:
        """
        Detect if any cycle exists starting from start_node_id using DFS.
        """
        visited: Set[str] = set()
        in_stack: Set[str] = set()

        def _dfs(node_id: str, depth: int) -> bool:
            if depth > max_depth:
                return False
            if node_id in in_stack:
                return True  # back-edge — cycle found
            if node_id in visited:
                return False
            visited.add(node_id)
            in_stack.add(node_id)
            edges = self.repo.get_edges_for_node(node_id, direction="out")
            for edge in edges:
                if _dfs(edge.target_node_id, depth + 1):
                    return True
            in_stack.discard(node_id)
            return False

        return _dfs(start_node_id, 0)

    # =========================================================================
    # Relationship Expansion
    # =========================================================================

    def expand_relationships(
        self,
        node_id: str,
        edge_types: Optional[List[str]] = None,
        direction: str = "both",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Returns all direct relationships of a node, grouped by edge type.
        """
        all_edges = self.repo.get_edges_for_node(
            node_id, direction=direction, limit=limit
        )
        if edge_types:
            all_edges = [e for e in all_edges if e.edge_type in edge_types]

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for edge in all_edges:
            grouped.setdefault(edge.edge_type, []).append(edge.to_dict())

        neighbors = self.repo.get_neighbors(node_id, direction=direction, limit=limit)

        return {
            "node_id": node_id,
            "edge_count": len(all_edges),
            "relationships_by_type": grouped,
            "neighbor_count": len(neighbors),
            "neighbors": [n.to_dict() for n in neighbors],
        }
