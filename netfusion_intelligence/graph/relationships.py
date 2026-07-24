"""
IL-8 UTKG — Graph Relationship Manager
=========================================
Manages creation, deduplication, confidence propagation, and
lifecycle of edges in the knowledge graph.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from netfusion_intelligence.graph.models import (
    GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
)
from netfusion_intelligence.graph.repository import GraphRepository


class GraphRelationshipManager:
    """
    High-level API for adding, updating, and managing graph edges.
    Enforces no-duplicate policy and handles confidence propagation.
    """

    def __init__(self, repository: GraphRepository):
        self.repo = repository

    # =========================================================================
    # Add / Ensure Relationship
    # =========================================================================

    def add_relationship(
        self,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        confidence: float = 1.0,
        weight: float = 1.0,
        evidence_count: int = 0,
        source_feed: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Tuple[GraphEdge, bool]:
        """
        Add or update an edge between two nodes.
        Returns (edge, was_created).
        """
        # Resolve canonical IDs from node records
        src_node = self.repo.get_node(source_node_id)
        tgt_node = self.repo.get_node(target_node_id)

        src_canonical = src_node.canonical_id if src_node else source_node_id
        tgt_canonical = tgt_node.canonical_id if tgt_node else target_node_id

        edge = GraphEdge.create(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            source_canonical_id=src_canonical,
            target_canonical_id=tgt_canonical,
            edge_type=edge_type,
            confidence=confidence,
            weight=weight,
            evidence_count=evidence_count,
            source_feed=source_feed,
            properties=properties,
        )
        return self.repo.upsert_edge(edge)

    def bulk_add_relationships(
        self,
        relationships: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """
        Bulk add edges from a list of relationship dicts.
        Each dict: {source_node_id, target_node_id, edge_type, [confidence, weight, ...]}
        """
        inserted = updated = 0
        for rel in relationships:
            _, created = self.add_relationship(
                source_node_id=rel["source_node_id"],
                target_node_id=rel["target_node_id"],
                edge_type=rel["edge_type"],
                confidence=float(rel.get("confidence", 1.0)),
                weight=float(rel.get("weight", 1.0)),
                evidence_count=int(rel.get("evidence_count", 0)),
                source_feed=rel.get("source_feed"),
                properties=rel.get("properties"),
            )
            if created:
                inserted += 1
            else:
                updated += 1
        return {"inserted": inserted, "updated": updated}

    # =========================================================================
    # Confidence Propagation
    # =========================================================================

    def propagate_confidence(
        self,
        node_id: str,
        decay: float = 0.8,
        max_depth: int = 3,
    ) -> Dict[str, float]:
        """
        Propagate confidence from a high-confidence node outward.
        Returns {node_id: propagated_confidence}.
        Decay factor reduces confidence at each hop.
        """
        from collections import deque
        source = self.repo.get_node(node_id)
        if not source:
            return {}

        confidence_map: Dict[str, float] = {node_id: source.confidence}
        queue: deque = deque([(node_id, source.confidence, 0)])

        while queue:
            current_id, current_conf, depth = queue.popleft()
            if depth >= max_depth:
                continue

            edges = self.repo.get_edges_for_node(current_id, direction="out")
            for edge in edges:
                new_conf = current_conf * decay * edge.confidence
                neighbor_id = edge.target_node_id
                if new_conf > confidence_map.get(neighbor_id, 0.0):
                    confidence_map[neighbor_id] = new_conf
                    queue.append((neighbor_id, new_conf, depth + 1))

        return confidence_map

    # =========================================================================
    # Relationship Queries
    # =========================================================================

    def get_relationships_between(
        self,
        node_id_a: str,
        node_id_b: str,
    ) -> List[GraphEdge]:
        """Get all edges between two specific nodes (in either direction)."""
        edges_a = self.repo.get_edges_for_node(node_id_a, direction="out")
        return [
            e for e in edges_a
            if e.target_node_id == node_id_b
        ]

    def get_incoming_relationships(
        self, node_id: str, edge_type: Optional[str] = None
    ) -> List[GraphEdge]:
        return self.repo.get_edges_for_node(node_id, direction="in", edge_type=edge_type)

    def get_outgoing_relationships(
        self, node_id: str, edge_type: Optional[str] = None
    ) -> List[GraphEdge]:
        return self.repo.get_edges_for_node(node_id, direction="out", edge_type=edge_type)

    def get_all_relationships(
        self, node_id: str, edge_type: Optional[str] = None
    ) -> List[GraphEdge]:
        return self.repo.get_edges_for_node(node_id, direction="both", edge_type=edge_type)

    # =========================================================================
    # Relationship Lifecycle
    # =========================================================================

    def increment_evidence(self, source_node_id: str, target_node_id: str, edge_type: str) -> bool:
        """Increment evidence count on an existing edge."""
        edges = self.get_relationships_between(source_node_id, target_node_id)
        for edge in edges:
            if edge.edge_type == edge_type:
                edge.evidence_count += 1
                self.repo.upsert_edge(edge)
                return True
        return False

    # =========================================================================
    # Canonical Fusion Helpers
    # =========================================================================

    def fuse_intelligence_nodes(
        self,
        source_external_id: str,
        source_type: str,
        target_external_id: str,
        target_type: str,
        edge_type: str,
        confidence: float = 1.0,
        source_feed: Optional[str] = None,
    ) -> Optional[Tuple[GraphEdge, bool]]:
        """
        High-level helper: resolves nodes by external_id and creates an edge.
        Handles cases where nodes don't yet exist gracefully.
        """
        src_node = self.repo.get_node_by_external_id(source_external_id, node_type=source_type)
        tgt_node = self.repo.get_node_by_external_id(target_external_id, node_type=target_type)

        if not src_node or not tgt_node:
            return None

        return self.add_relationship(
            source_node_id=src_node.node_id,
            target_node_id=tgt_node.node_id,
            edge_type=edge_type,
            confidence=confidence,
            source_feed=source_feed,
        )
