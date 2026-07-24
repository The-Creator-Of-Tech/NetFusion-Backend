"""
IL-8 UTKG — Domain Events
============================
All UTKG domain events extending the existing NetFusion EventBus.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from netfusion_intelligence.core.events import DomainEvent


@dataclass
class GraphNodeCreated(DomainEvent):
    """Fired when a new node is inserted into the UTKG."""
    node_id: str = ""
    canonical_id: str = ""
    node_type: str = ""
    source_feed: str = ""
    external_id: str = ""


@dataclass
class GraphEdgeCreated(DomainEvent):
    """Fired when a new edge is inserted into the UTKG."""
    edge_id: str = ""
    source_node_id: str = ""
    target_node_id: str = ""
    edge_type: str = ""
    source_feed: str = ""


@dataclass
class GraphMerged(DomainEvent):
    """Fired when a knowledge fusion run completes."""
    nodes_inserted: int = 0
    nodes_updated: int = 0
    edges_inserted: int = 0
    feeds_fused: int = 0
    duration_seconds: float = 0.0


@dataclass
class GraphTraversalExecuted(DomainEvent):
    """Fired after a traversal operation completes."""
    traversal_id: str = ""
    algorithm: str = ""
    start_node_id: str = ""
    nodes_visited: int = 0
    edges_traversed: int = 0
    duration_ms: float = 0.0


@dataclass
class GraphExported(DomainEvent):
    """Fired when a graph export completes."""
    export_id: str = ""
    format: str = ""
    node_count: int = 0
    edge_count: int = 0


@dataclass
class GraphStatisticsUpdated(DomainEvent):
    """Fired when statistics are recomputed."""
    node_count: int = 0
    edge_count: int = 0
    connected_components: int = 0
    relationship_density: float = 0.0


@dataclass
class GraphVersionCreated(DomainEvent):
    """Fired when a new graph version snapshot is created."""
    version_id: str = ""
    version_number: int = 0


@dataclass
class GraphRolledBack(DomainEvent):
    """Fired when the graph is rolled back to a previous version."""
    target_version_id: str = ""
    rolled_back_from: str = ""
