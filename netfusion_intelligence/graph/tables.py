"""
IL-8 UTKG — SQLAlchemy ORM Tables
===================================
Database schema for the Unified Threat Knowledge Graph.
Supports: versioning, rollback, incremental updates.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Index, Integer, String, Text, UniqueConstraint
)
from netfusion_intelligence.repository.tables import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Graph Versions
# ---------------------------------------------------------------------------

class GraphVersionModel(Base):
    """Snapshot version record — supports rollback."""
    __tablename__ = "graph_version"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version_id = Column(String(100), unique=True, nullable=False, index=True)
    version_number = Column(Integer, nullable=False, default=1, index=True)
    node_count = Column(Integer, default=0, nullable=False)
    edge_count = Column(Integer, default=0, nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime, default=_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_graph_ver_active", "is_active"),
        Index("idx_graph_ver_number", "version_number"),
    )


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------

class GraphNodeModel(Base):
    """
    A vertex in the UTKG.
    canonical_id is the CIIL UUID — globally unique identity.
    node_id is the graph-internal stable UUID.
    """
    __tablename__ = "graph_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(String(100), nullable=False, index=True)
    canonical_id = Column(String(100), nullable=False, index=True)
    node_type = Column(String(60), nullable=False, index=True)
    label = Column(String(500), nullable=False)
    name = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    source_feed = Column(String(100), nullable=True, index=True)
    external_id = Column(String(200), nullable=True, index=True)
    properties_json = Column(Text, nullable=True, default="{}")
    tags_json = Column(Text, nullable=True, default="[]")
    confidence = Column(Float, default=1.0, nullable=False, index=True)
    version = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=_utc_now, nullable=False)
    updated_at = Column(DateTime, default=_utc_now, onupdate=_utc_now, nullable=False)

    __table_args__ = (
        # One canonical node per type per feed — prevents duplicates
        Index("idx_graph_node_canonical_type", "canonical_id", "node_type", unique=True),
        Index("idx_graph_node_type_feed", "node_type", "source_feed"),
        Index("idx_graph_node_external", "external_id"),
        Index("idx_graph_node_active_type", "is_active", "node_type"),
    )


# ---------------------------------------------------------------------------
# Graph Edges
# ---------------------------------------------------------------------------

class GraphEdgeModel(Base):
    """
    A directed edge in the UTKG.
    Uniqueness: (source_node_id, target_node_id, edge_type) — no duplicate edges.
    """
    __tablename__ = "graph_edges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    edge_id = Column(String(100), nullable=False, index=True)
    source_node_id = Column(String(100), nullable=False, index=True)
    target_node_id = Column(String(100), nullable=False, index=True)
    source_canonical_id = Column(String(100), nullable=False, index=True)
    target_canonical_id = Column(String(100), nullable=False, index=True)
    edge_type = Column(String(100), nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False, index=True)
    weight = Column(Float, default=1.0, nullable=False)
    evidence_count = Column(Integer, default=0, nullable=False)
    source_feed = Column(String(100), nullable=True, index=True)
    properties_json = Column(Text, nullable=True, default="{}")
    version = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=_utc_now, nullable=False)
    updated_at = Column(DateTime, default=_utc_now, onupdate=_utc_now, nullable=False)

    __table_args__ = (
        # Canonical deduplication
        Index(
            "idx_graph_edge_src_tgt_type",
            "source_node_id", "target_node_id", "edge_type",
            unique=True,
        ),
        Index("idx_graph_edge_src", "source_node_id"),
        Index("idx_graph_edge_tgt", "target_node_id"),
        Index("idx_graph_edge_type", "edge_type"),
        Index("idx_graph_edge_src_canonical", "source_canonical_id"),
        Index("idx_graph_edge_tgt_canonical", "target_canonical_id"),
        Index("idx_graph_edge_active", "is_active"),
    )


# ---------------------------------------------------------------------------
# Graph Statistics Snapshots
# ---------------------------------------------------------------------------

class GraphStatisticsModel(Base):
    """Persisted statistics snapshots — one per computation run."""
    __tablename__ = "graph_statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stats_id = Column(String(100), unique=True, nullable=False, index=True)
    node_count = Column(Integer, default=0, nullable=False)
    edge_count = Column(Integer, default=0, nullable=False)
    node_types_json = Column(Text, nullable=True, default="{}")
    edge_types_json = Column(Text, nullable=True, default="{}")
    degree_distribution_json = Column(Text, nullable=True, default="{}")
    largest_component_size = Column(Integer, default=0, nullable=False)
    connected_components_count = Column(Integer, default=0, nullable=False)
    relationship_density = Column(Float, default=0.0, nullable=False)
    average_path_length = Column(Float, default=0.0, nullable=False)
    average_degree = Column(Float, default=0.0, nullable=False)
    generated_at = Column(DateTime, default=_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("idx_graph_stats_date", "generated_at"),
    )


# ---------------------------------------------------------------------------
# Graph Path Cache
# ---------------------------------------------------------------------------

class GraphPathModel(Base):
    """Cached computed paths — supports investigation acceleration."""
    __tablename__ = "graph_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    path_id = Column(String(100), unique=True, nullable=False, index=True)
    source_node_id = Column(String(100), nullable=False, index=True)
    target_node_id = Column(String(100), nullable=False, index=True)
    algorithm = Column(String(50), nullable=False, default="bfs")
    length = Column(Integer, default=0, nullable=False)
    total_weight = Column(Float, default=0.0, nullable=False)
    avg_confidence = Column(Float, default=1.0, nullable=False)
    nodes_json = Column(Text, nullable=False, default="[]")
    edges_json = Column(Text, nullable=False, default="[]")
    computed_at = Column(DateTime, default=_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("idx_graph_path_src_tgt", "source_node_id", "target_node_id"),
        Index("idx_graph_path_date", "computed_at"),
    )


# ---------------------------------------------------------------------------
# Graph Export Records
# ---------------------------------------------------------------------------

class GraphExportModel(Base):
    """Record of completed graph export operations."""
    __tablename__ = "graph_exports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    export_id = Column(String(100), unique=True, nullable=False, index=True)
    format = Column(String(30), nullable=False, index=True)
    node_count = Column(Integer, default=0, nullable=False)
    edge_count = Column(Integer, default=0, nullable=False)
    filter_query = Column(Text, nullable=True)
    file_path = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("idx_graph_export_format", "format"),
        Index("idx_graph_export_date", "created_at"),
    )
