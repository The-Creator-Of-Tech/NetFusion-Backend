"""
IL-8 UTKG — Graph Path Finder
================================
Implements: Shortest Path (BFS), All Simple Paths, Path Ranking,
            Attack Chain Reconstruction.
"""

import heapq
import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from netfusion_intelligence.graph.models import GraphPath, GraphNode
from netfusion_intelligence.graph.repository import GraphRepository


class GraphPathFinder:
    """
    Path-finding algorithms over the UTKG.
    Uses SQL-backed adjacency — no in-memory full graph required.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository

    # =========================================================================
    # Shortest Path (BFS — unweighted)
    # =========================================================================

    def shortest_path(
        self,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = 10,
        edge_type: Optional[str] = None,
        direction: str = "both",
        use_cache: bool = True,
    ) -> Optional[GraphPath]:
        """
        BFS shortest path between two nodes.
        Optionally uses the path cache for repeated queries.
        """
        if use_cache:
            cached = self.repo.get_cached_path(source_node_id, target_node_id)
            if cached:
                return cached

        path = self._bfs_path(source_node_id, target_node_id, max_depth, edge_type, direction)
        if path and use_cache:
            self.repo.save_path(path)
        return path

    def _bfs_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int,
        edge_type: Optional[str],
        direction: str,
    ) -> Optional[GraphPath]:
        """Internal BFS path finder. Returns None if no path exists."""
        # parent[node_id] = (parent_node_id, edge_id)
        parent: Dict[str, Tuple[Optional[str], Optional[str]]] = {source_id: (None, None)}
        queue: deque = deque([(source_id, 0)])
        found = False

        while queue:
            current_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            if current_id == target_id:
                found = True
                break

            edges = self.repo.get_edges_for_node(
                current_id, direction=direction, edge_type=edge_type
            )
            for edge in edges:
                neighbor_id = (
                    edge.target_node_id
                    if edge.source_node_id == current_id
                    else edge.source_node_id
                )
                if neighbor_id not in parent:
                    parent[neighbor_id] = (current_id, edge.edge_id)
                    queue.append((neighbor_id, depth + 1))
                    if neighbor_id == target_id:
                        found = True
                        break
            if found:
                break

        if not found and target_id not in parent:
            return None

        # Reconstruct path
        node_ids: List[str] = []
        edge_ids: List[str] = []
        current = target_id
        while current is not None:
            node_ids.append(current)
            p, e = parent[current]
            if e:
                edge_ids.append(e)
            current = p

        node_ids.reverse()
        edge_ids.reverse()

        # Fetch full objects
        path_nodes = []
        path_edges = []
        total_weight = 0.0
        confidence_sum = 0.0

        for nid in node_ids:
            n = self.repo.get_node(nid)
            if n:
                path_nodes.append(n.to_dict())

        for eid in edge_ids:
            e = self.repo.get_edge(eid)
            if e:
                path_edges.append(e.to_dict())
                total_weight += e.weight
                confidence_sum += e.confidence

        avg_conf = (confidence_sum / len(path_edges)) if path_edges else 1.0

        return GraphPath(
            path_id=str(uuid.uuid4()),
            source_node_id=source_id,
            target_node_id=target_id,
            nodes=path_nodes,
            edges=path_edges,
            length=len(path_edges),
            total_weight=total_weight,
            avg_confidence=avg_conf,
            algorithm="bfs_shortest",
        )

    # =========================================================================
    # Dijkstra Shortest Path (weighted)
    # =========================================================================

    def shortest_path_weighted(
        self,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = 15,
    ) -> Optional[GraphPath]:
        """
        Dijkstra's algorithm using edge weights.
        Lower weight = stronger relationship = preferred path.
        """
        # Priority queue: (cost, node_id, parent_node_id, edge_id)
        dist: Dict[str, float] = {source_node_id: 0.0}
        parent: Dict[str, Tuple[Optional[str], Optional[str]]] = {source_node_id: (None, None)}
        pq = [(0.0, source_node_id)]
        depth_map: Dict[str, int] = {source_node_id: 0}

        while pq:
            cost, current_id = heapq.heappop(pq)
            if current_id == target_node_id:
                break
            current_depth = depth_map.get(current_id, 0)
            if current_depth >= max_depth:
                continue

            edges = self.repo.get_edges_for_node(current_id, direction="out")
            for edge in edges:
                neighbor_id = edge.target_node_id
                # Invert weight so higher-weight edges are cheaper
                edge_cost = 1.0 / max(edge.weight, 0.001)
                new_cost = cost + edge_cost
                if new_cost < dist.get(neighbor_id, float("inf")):
                    dist[neighbor_id] = new_cost
                    parent[neighbor_id] = (current_id, edge.edge_id)
                    depth_map[neighbor_id] = current_depth + 1
                    heapq.heappush(pq, (new_cost, neighbor_id))

        if target_node_id not in parent:
            return None

        # Reconstruct
        node_ids, edge_ids = [], []
        current = target_node_id
        while current is not None:
            node_ids.append(current)
            p, e = parent[current]
            if e:
                edge_ids.append(e)
            current = p

        node_ids.reverse()
        edge_ids.reverse()

        path_nodes = [n.to_dict() for nid in node_ids for n in [self.repo.get_node(nid)] if n]
        path_edges = [e.to_dict() for eid in edge_ids for e in [self.repo.get_edge(eid)] if e]
        total_weight = sum(e.get("weight", 1.0) for e in path_edges)
        avg_conf = (
            sum(e.get("confidence", 1.0) for e in path_edges) / len(path_edges)
            if path_edges else 1.0
        )

        return GraphPath(
            path_id=str(uuid.uuid4()),
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            nodes=path_nodes,
            edges=path_edges,
            length=len(path_edges),
            total_weight=total_weight,
            avg_confidence=avg_conf,
            algorithm="dijkstra",
        )

    # =========================================================================
    # All Simple Paths (up to limit)
    # =========================================================================

    def all_simple_paths(
        self,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = 6,
        limit: int = 10,
    ) -> List[GraphPath]:
        """
        Returns up to `limit` simple paths between source and target.
        Uses iterative DFS with path backtracking.
        """
        results: List[GraphPath] = []
        # Stack: (current_id, path_node_ids, path_edge_ids, visited)
        stack = [
            (
                source_node_id,
                [source_node_id],
                [],
                {source_node_id},
            )
        ]

        while stack and len(results) < limit:
            current_id, path_nodes, path_edges, visited = stack.pop()

            if current_id == target_node_id and len(path_nodes) > 1:
                # Build GraphPath
                nodes = [n.to_dict() for nid in path_nodes for n in [self.repo.get_node(nid)] if n]
                edges = [e.to_dict() for eid in path_edges for e in [self.repo.get_edge(eid)] if e]
                total_w = sum(e.get("weight", 1.0) for e in edges)
                avg_c = sum(e.get("confidence", 1.0) for e in edges) / len(edges) if edges else 1.0
                results.append(GraphPath(
                    path_id=str(uuid.uuid4()),
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    nodes=nodes,
                    edges=edges,
                    length=len(edges),
                    total_weight=total_w,
                    avg_confidence=avg_c,
                    algorithm="all_simple_paths",
                ))
                continue

            if len(path_nodes) >= max_depth:
                continue

            out_edges = self.repo.get_edges_for_node(current_id, direction="out")
            for edge in out_edges:
                neighbor_id = edge.target_node_id
                if neighbor_id not in visited:
                    stack.append((
                        neighbor_id,
                        path_nodes + [neighbor_id],
                        path_edges + [edge.edge_id],
                        visited | {neighbor_id},
                    ))

        return results

    # =========================================================================
    # Path Ranking
    # =========================================================================

    def rank_paths(self, paths: List[GraphPath]) -> List[GraphPath]:
        """
        Rank paths by: length ASC, avg_confidence DESC, total_weight DESC.
        Shorter, higher-confidence, higher-weight paths rank first.
        """
        return sorted(
            paths,
            key=lambda p: (p.length, -p.avg_confidence, -p.total_weight),
        )

    # =========================================================================
    # Attack Chain Reconstruction
    # =========================================================================

    def reconstruct_attack_chain(
        self,
        investigation_node_id: str,
        max_depth: int = 8,
    ) -> Dict[str, Any]:
        """
        From an investigation or alert node, reconstruct the full attack chain:
        Evidence → IOC → Malware → Campaign → Threat Actor → ATT&CK → CAPEC → CWE → CVE
        """
        from netfusion_intelligence.graph.traversal import GraphTraversalEngine
        traversal = GraphTraversalEngine(self.repo)

        full_traversal = traversal.bfs(
            investigation_node_id,
            max_depth=max_depth,
            direction="both",
        )

        # Classify nodes into chain layers
        chain: Dict[str, List[Dict[str, Any]]] = {
            "evidence": [],
            "ioc": [],
            "malware": [],
            "campaign": [],
            "threat_actor": [],
            "attack_technique": [],
            "capec": [],
            "cwe": [],
            "cve": [],
            "kev": [],
            "epss": [],
            "other": [],
        }

        chain_type_map = {
            "evidence": "evidence",
            "packet": "evidence",
            "flow": "evidence",
            "ioc": "ioc",
            "domain": "ioc",
            "url": "ioc",
            "ip": "ioc",
            "hash": "ioc",
            "email": "ioc",
            "malware": "malware",
            "campaign": "campaign",
            "threat_actor": "threat_actor",
            "attack_group": "threat_actor",
            "attack_technique": "attack_technique",
            "attack_tactic": "attack_technique",
            "capec": "capec",
            "cwe": "cwe",
            "cve": "cve",
            "kev": "kev",
            "epss_record": "epss",
        }

        for node in full_traversal.nodes:
            ntype = node.get("node_type", "")
            bucket = chain_type_map.get(ntype, "other")
            chain[bucket].append(node)

        return {
            "investigation_node_id": investigation_node_id,
            "attack_chain": chain,
            "total_nodes": len(full_traversal.nodes),
            "total_edges": len(full_traversal.edges),
            "edges": full_traversal.edges,
            "computed_at": full_traversal.computed_at,
        }
