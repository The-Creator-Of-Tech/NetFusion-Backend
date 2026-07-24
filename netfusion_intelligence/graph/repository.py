"""
IL-8 UTKG — Graph Repository
==============================
SQLAlchemy-backed persistence for the Unified Threat Knowledge Graph.
Supports: upsert, versioning, rollback, incremental updates, and deduplication.
All canonical UUIDs are enforced — no duplicate nodes or edges.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import create_engine, func, or_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from netfusion_intelligence.graph.models import (
    GraphEdge, GraphEdgeType, GraphExportRecord, GraphNode, GraphNodeType,
    GraphPath, GraphStatistics, GraphVersion,
)
from netfusion_intelligence.graph.tables import (
    GraphEdgeModel, GraphExportModel, GraphNodeModel,
    GraphPathModel, GraphStatisticsModel, GraphVersionModel,
)
from netfusion_intelligence.repository.tables import Base
from netfusion_intelligence.repository.base import deserialize_json, serialize_json


class GraphRepository:
    """
    Full-featured persistence layer for the UTKG.
    Thread-safe. Designed for SQLite (dev/test) and PostgreSQL (production).
    """

    def __init__(self, db_url: str = "sqlite:///:memory:", engine: Any = None):
        if engine is not None:
            self.engine = engine
        elif db_url in ("sqlite:///:memory:", "sqlite://"):
            self.engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        elif db_url.startswith("sqlite"):
            self.engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
            )
        else:
            self.engine = create_engine(db_url)

        # Extend the shared Base metadata with our new tables
        from netfusion_intelligence.graph.tables import (
            GraphVersionModel, GraphNodeModel, GraphEdgeModel,
            GraphStatisticsModel, GraphPathModel, GraphExportModel,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _s(self) -> Session:
        return self.SessionLocal()

    # =========================================================================
    # Version Management
    # =========================================================================

    def create_version(self, description: Optional[str] = None) -> GraphVersion:
        """Create a new graph version snapshot."""
        with self._s() as session:
            latest = session.query(GraphVersionModel).order_by(
                GraphVersionModel.version_number.desc()
            ).first()
            next_num = (latest.version_number + 1) if latest else 1
            vid = str(uuid.uuid4())
            model = GraphVersionModel(
                version_id=vid,
                version_number=next_num,
                description=description,
                is_active=True,
            )
            # Deactivate previous
            session.query(GraphVersionModel).filter_by(is_active=True).update({"is_active": False})
            session.add(model)
            session.commit()
            return GraphVersion(
                version_id=vid,
                version_number=next_num,
                description=description,
                is_active=True,
            )

    def get_active_version(self) -> Optional[GraphVersion]:
        """Return the currently active version."""
        with self._s() as session:
            m = session.query(GraphVersionModel).filter_by(is_active=True).first()
            if not m:
                return None
            return GraphVersion(
                version_id=m.version_id,
                version_number=m.version_number,
                node_count=m.node_count,
                edge_count=m.edge_count,
                description=m.description,
                is_active=m.is_active,
                created_at=m.created_at.isoformat() if m.created_at else "",
            )

    def list_versions(self) -> List[GraphVersion]:
        with self._s() as session:
            rows = session.query(GraphVersionModel).order_by(
                GraphVersionModel.version_number.desc()
            ).all()
            return [
                GraphVersion(
                    version_id=m.version_id,
                    version_number=m.version_number,
                    node_count=m.node_count,
                    edge_count=m.edge_count,
                    description=m.description,
                    is_active=m.is_active,
                    created_at=m.created_at.isoformat() if m.created_at else "",
                )
                for m in rows
            ]

    def rollback_to_version(self, version_id: str) -> bool:
        """Rollback graph to a previous version snapshot."""
        with self._s() as session:
            target = session.query(GraphVersionModel).filter_by(version_id=version_id).first()
            if not target:
                return False
            session.query(GraphVersionModel).filter_by(is_active=True).update({"is_active": False})
            target.is_active = True
            session.commit()
            return True

    # =========================================================================
    # Node Operations
    # =========================================================================

    def upsert_node(self, node: GraphNode) -> Tuple[GraphNode, bool]:
        """
        Insert or update a node.
        Returns (node, was_created).
        Deduplication key: (canonical_id, node_type).
        """
        with self._s() as session:
            existing = session.query(GraphNodeModel).filter_by(
                canonical_id=node.canonical_id,
                node_type=node.node_type,
            ).first()

            if existing:
                existing.label = node.label
                existing.name = node.name
                existing.description = node.description
                existing.source_feed = node.source_feed
                existing.external_id = node.external_id
                existing.properties_json = serialize_json(node.properties)
                existing.tags_json = serialize_json(node.tags)
                existing.confidence = node.confidence
                existing.version += 1
                existing.is_active = node.is_active
                existing.updated_at = datetime.now(timezone.utc)
                node.node_id = existing.node_id
                node.version = existing.version
                session.commit()
                return node, False
            else:
                model = GraphNodeModel(
                    node_id=node.node_id,
                    canonical_id=node.canonical_id,
                    node_type=node.node_type,
                    label=node.label,
                    name=node.name,
                    description=node.description,
                    source_feed=node.source_feed,
                    external_id=node.external_id,
                    properties_json=serialize_json(node.properties),
                    tags_json=serialize_json(node.tags),
                    confidence=node.confidence,
                    version=node.version,
                    is_active=node.is_active,
                )
                session.add(model)
                session.commit()
                return node, True

    def bulk_upsert_nodes(self, nodes: List[GraphNode]) -> Dict[str, int]:
        """Bulk upsert — returns {inserted, updated}."""
        inserted = updated = 0
        for node in nodes:
            _, created = self.upsert_node(node)
            if created:
                inserted += 1
            else:
                updated += 1
        return {"inserted": inserted, "updated": updated}

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by internal node_id."""
        with self._s() as session:
            m = session.query(GraphNodeModel).filter_by(node_id=node_id).first()
            return self._model_to_node(m) if m else None

    def get_node_by_canonical(self, canonical_id: str, node_type: Optional[str] = None) -> Optional[GraphNode]:
        """Get node by CIIL canonical UUID."""
        with self._s() as session:
            q = session.query(GraphNodeModel).filter_by(canonical_id=canonical_id)
            if node_type:
                q = q.filter_by(node_type=node_type)
            m = q.first()
            return self._model_to_node(m) if m else None

    def get_node_by_external_id(self, external_id: str, node_type: Optional[str] = None) -> Optional[GraphNode]:
        """Get node by external ID (CVE-ID, T1059, etc.)."""
        with self._s() as session:
            q = session.query(GraphNodeModel).filter_by(external_id=external_id)
            if node_type:
                q = q.filter_by(node_type=node_type)
            m = q.first()
            return self._model_to_node(m) if m else None

    def list_nodes(
        self,
        node_type: Optional[str] = None,
        source_feed: Optional[str] = None,
        is_active: bool = True,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[GraphNode]:
        with self._s() as session:
            q = session.query(GraphNodeModel).filter_by(is_active=is_active)
            if node_type:
                q = q.filter_by(node_type=node_type)
            if source_feed:
                q = q.filter_by(source_feed=source_feed)
            return [
                self._model_to_node(m)
                for m in q.offset(offset).limit(limit).all()
            ]

    def search_nodes(
        self,
        query: str = "",
        node_type: Optional[str] = None,
        external_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> List[GraphNode]:
        with self._s() as session:
            q = session.query(GraphNodeModel).filter_by(is_active=True)
            if node_type:
                q = q.filter_by(node_type=node_type)
            if external_id:
                q = q.filter_by(external_id=external_id)
            if min_confidence is not None:
                q = q.filter(GraphNodeModel.confidence >= min_confidence)
            if query:
                kw = f"%{query}%"
                q = q.filter(
                    or_(
                        GraphNodeModel.label.ilike(kw),
                        GraphNodeModel.name.ilike(kw),
                        GraphNodeModel.description.ilike(kw),
                        GraphNodeModel.external_id.ilike(kw),
                        GraphNodeModel.tags_json.ilike(kw),
                    )
                )
            return [self._model_to_node(m) for m in q.limit(limit).all()]

    def count_nodes(self, node_type: Optional[str] = None) -> int:
        with self._s() as session:
            q = session.query(func.count(GraphNodeModel.id)).filter_by(is_active=True)
            if node_type:
                q = q.filter(GraphNodeModel.node_type == node_type)
            return q.scalar() or 0

    # =========================================================================
    # Edge Operations
    # =========================================================================

    def upsert_edge(self, edge: GraphEdge) -> Tuple[GraphEdge, bool]:
        """
        Insert or update an edge.
        Deduplication key: (source_node_id, target_node_id, edge_type).
        """
        with self._s() as session:
            existing = session.query(GraphEdgeModel).filter_by(
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                edge_type=edge.edge_type,
            ).first()

            if existing:
                existing.confidence = max(existing.confidence, edge.confidence)
                existing.weight = edge.weight
                existing.evidence_count = existing.evidence_count + edge.evidence_count
                existing.source_feed = edge.source_feed or existing.source_feed
                existing.properties_json = serialize_json(edge.properties)
                existing.version += 1
                existing.is_active = edge.is_active
                existing.updated_at = datetime.now(timezone.utc)
                edge.edge_id = existing.edge_id
                edge.version = existing.version
                session.commit()
                return edge, False
            else:
                model = GraphEdgeModel(
                    edge_id=edge.edge_id,
                    source_node_id=edge.source_node_id,
                    target_node_id=edge.target_node_id,
                    source_canonical_id=edge.source_canonical_id,
                    target_canonical_id=edge.target_canonical_id,
                    edge_type=edge.edge_type,
                    confidence=edge.confidence,
                    weight=edge.weight,
                    evidence_count=edge.evidence_count,
                    source_feed=edge.source_feed,
                    properties_json=serialize_json(edge.properties),
                    version=edge.version,
                    is_active=edge.is_active,
                )
                session.add(model)
                session.commit()
                return edge, True

    def bulk_upsert_edges(self, edges: List[GraphEdge]) -> Dict[str, int]:
        inserted = updated = 0
        for edge in edges:
            _, created = self.upsert_edge(edge)
            if created:
                inserted += 1
            else:
                updated += 1
        return {"inserted": inserted, "updated": updated}

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        with self._s() as session:
            m = session.query(GraphEdgeModel).filter_by(edge_id=edge_id).first()
            return self._model_to_edge(m) if m else None

    def get_edges_for_node(
        self,
        node_id: str,
        direction: str = "both",   # "out", "in", "both"
        edge_type: Optional[str] = None,
        limit: int = 500,
    ) -> List[GraphEdge]:
        with self._s() as session:
            q = session.query(GraphEdgeModel).filter_by(is_active=True)
            if direction == "out":
                q = q.filter_by(source_node_id=node_id)
            elif direction == "in":
                q = q.filter_by(target_node_id=node_id)
            else:
                q = q.filter(
                    or_(
                        GraphEdgeModel.source_node_id == node_id,
                        GraphEdgeModel.target_node_id == node_id,
                    )
                )
            if edge_type:
                q = q.filter_by(edge_type=edge_type)
            return [self._model_to_edge(m) for m in q.limit(limit).all()]

    def count_edges(self, edge_type: Optional[str] = None) -> int:
        with self._s() as session:
            q = session.query(func.count(GraphEdgeModel.id)).filter_by(is_active=True)
            if edge_type:
                q = q.filter(GraphEdgeModel.edge_type == edge_type)
            return q.scalar() or 0

    # =========================================================================
    # Statistics
    # =========================================================================

    def save_statistics(self, stats: GraphStatistics) -> None:
        with self._s() as session:
            model = GraphStatisticsModel(
                stats_id=str(uuid.uuid4()),
                node_count=stats.node_count,
                edge_count=stats.edge_count,
                node_types_json=serialize_json(stats.node_types),
                edge_types_json=serialize_json(stats.edge_types),
                degree_distribution_json=serialize_json(
                    {str(k): v for k, v in stats.degree_distribution.items()}
                ),
                largest_component_size=stats.largest_component_size,
                connected_components_count=stats.connected_components_count,
                relationship_density=stats.relationship_density,
                average_path_length=stats.average_path_length,
                average_degree=stats.average_degree,
            )
            session.add(model)
            # Update version counts
            ver = session.query(GraphVersionModel).filter_by(is_active=True).first()
            if ver:
                ver.node_count = stats.node_count
                ver.edge_count = stats.edge_count
            session.commit()

    def get_latest_statistics(self) -> Optional[GraphStatistics]:
        with self._s() as session:
            m = session.query(GraphStatisticsModel).order_by(
                GraphStatisticsModel.generated_at.desc()
            ).first()
            if not m:
                return None
            return GraphStatistics(
                node_count=m.node_count,
                edge_count=m.edge_count,
                node_types=deserialize_json(m.node_types_json or "{}"),
                edge_types=deserialize_json(m.edge_types_json or "{}"),
                degree_distribution={
                    int(k): v for k, v in
                    deserialize_json(m.degree_distribution_json or "{}").items()
                },
                largest_component_size=m.largest_component_size,
                connected_components_count=m.connected_components_count,
                relationship_density=m.relationship_density,
                average_path_length=m.average_path_length,
                average_degree=m.average_degree,
                generated_at=m.generated_at.isoformat() if m.generated_at else "",
            )

    # =========================================================================
    # Path Cache
    # =========================================================================

    def save_path(self, path: GraphPath) -> None:
        with self._s() as session:
            model = GraphPathModel(
                path_id=path.path_id,
                source_node_id=path.source_node_id,
                target_node_id=path.target_node_id,
                algorithm=path.algorithm,
                length=path.length,
                total_weight=path.total_weight,
                avg_confidence=path.avg_confidence,
                nodes_json=serialize_json(path.nodes),
                edges_json=serialize_json(path.edges),
            )
            session.add(model)
            session.commit()

    def get_cached_path(
        self, source_node_id: str, target_node_id: str
    ) -> Optional[GraphPath]:
        with self._s() as session:
            m = session.query(GraphPathModel).filter_by(
                source_node_id=source_node_id, target_node_id=target_node_id
            ).order_by(GraphPathModel.computed_at.desc()).first()
            if not m:
                return None
            return GraphPath(
                path_id=m.path_id,
                source_node_id=m.source_node_id,
                target_node_id=m.target_node_id,
                nodes=deserialize_json(m.nodes_json or "[]"),
                edges=deserialize_json(m.edges_json or "[]"),
                length=m.length,
                total_weight=m.total_weight,
                avg_confidence=m.avg_confidence,
                algorithm=m.algorithm,
                computed_at=m.computed_at.isoformat() if m.computed_at else "",
            )

    # =========================================================================
    # Export Records
    # =========================================================================

    def save_export_record(self, record: GraphExportRecord) -> None:
        with self._s() as session:
            model = GraphExportModel(
                export_id=record.export_id,
                format=record.format,
                node_count=record.node_count,
                edge_count=record.edge_count,
                filter_query=record.filter_query,
                file_path=record.file_path,
            )
            session.add(model)
            session.commit()

    def list_exports(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._s() as session:
            rows = session.query(GraphExportModel).order_by(
                GraphExportModel.created_at.desc()
            ).limit(limit).all()
            return [
                {
                    "export_id": m.export_id,
                    "format": m.format,
                    "node_count": m.node_count,
                    "edge_count": m.edge_count,
                    "filter_query": m.filter_query,
                    "file_path": m.file_path,
                    "created_at": m.created_at.isoformat() if m.created_at else "",
                }
                for m in rows
            ]

    # =========================================================================
    # Aggregate / Topology Helpers
    # =========================================================================

    def get_node_types_distribution(self) -> Dict[str, int]:
        with self._s() as session:
            rows = session.query(
                GraphNodeModel.node_type,
                func.count(GraphNodeModel.id),
            ).filter_by(is_active=True).group_by(GraphNodeModel.node_type).all()
            return {r[0]: r[1] for r in rows}

    def get_edge_types_distribution(self) -> Dict[str, int]:
        with self._s() as session:
            rows = session.query(
                GraphEdgeModel.edge_type,
                func.count(GraphEdgeModel.id),
            ).filter_by(is_active=True).group_by(GraphEdgeModel.edge_type).all()
            return {r[0]: r[1] for r in rows}

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        edge_type: Optional[str] = None,
        limit: int = 200,
    ) -> List[GraphNode]:
        """Return neighbor nodes of a given node."""
        edges = self.get_edges_for_node(
            node_id, direction=direction, edge_type=edge_type, limit=limit
        )
        neighbor_ids = set()
        for e in edges:
            if e.source_node_id != node_id:
                neighbor_ids.add(e.source_node_id)
            if e.target_node_id != node_id:
                neighbor_ids.add(e.target_node_id)

        nodes = []
        for nid in neighbor_ids:
            n = self.get_node(nid)
            if n:
                nodes.append(n)
        return nodes

    def get_degree(self, node_id: str) -> int:
        """Return total degree (in + out) of a node."""
        with self._s() as session:
            out_deg = session.query(func.count(GraphEdgeModel.id)).filter_by(
                source_node_id=node_id, is_active=True
            ).scalar() or 0
            in_deg = session.query(func.count(GraphEdgeModel.id)).filter_by(
                target_node_id=node_id, is_active=True
            ).scalar() or 0
            return out_deg + in_deg

    # =========================================================================
    # Helpers
    # =========================================================================

    def _model_to_node(self, m: GraphNodeModel) -> GraphNode:
        return GraphNode(
            node_id=m.node_id,
            canonical_id=m.canonical_id,
            node_type=m.node_type,
            label=m.label,
            name=m.name,
            description=m.description,
            source_feed=m.source_feed,
            external_id=m.external_id,
            properties=deserialize_json(m.properties_json or "{}"),
            tags=deserialize_json(m.tags_json or "[]"),
            confidence=m.confidence,
            version=m.version,
            is_active=m.is_active,
            created_at=m.created_at.isoformat() if m.created_at else "",
            updated_at=m.updated_at.isoformat() if m.updated_at else "",
        )

    def _model_to_edge(self, m: GraphEdgeModel) -> GraphEdge:
        return GraphEdge(
            edge_id=m.edge_id,
            source_node_id=m.source_node_id,
            target_node_id=m.target_node_id,
            source_canonical_id=m.source_canonical_id,
            target_canonical_id=m.target_canonical_id,
            edge_type=m.edge_type,
            confidence=m.confidence,
            weight=m.weight,
            evidence_count=m.evidence_count,
            source_feed=m.source_feed,
            properties=deserialize_json(m.properties_json or "{}"),
            version=m.version,
            is_active=m.is_active,
            created_at=m.created_at.isoformat() if m.created_at else "",
            updated_at=m.updated_at.isoformat() if m.updated_at else "",
        )
