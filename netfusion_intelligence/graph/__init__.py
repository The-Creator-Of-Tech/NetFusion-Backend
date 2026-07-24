"""
IL-8: Unified Threat Knowledge Graph (UTKG)
============================================
The central intelligence backbone of NetFusion.
Connects every canonical intelligence object through a unified graph layer.
"""

from netfusion_intelligence.graph.models import (
    GraphNode,
    GraphEdge,
    GraphNodeType,
    GraphEdgeType,
    GraphStatistics,
    GraphPath,
    GraphExportFormat,
    GraphExportRecord,
    GraphVersion,
    TraversalResult,
    SearchResult,
    SubgraphResult,
)
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.traversal import GraphTraversalEngine
from netfusion_intelligence.graph.search import GraphSearchEngine
from netfusion_intelligence.graph.pathfinder import GraphPathFinder
from netfusion_intelligence.graph.relationships import GraphRelationshipManager
from netfusion_intelligence.graph.statistics import GraphStatisticsEngine
from netfusion_intelligence.graph.export import GraphExportService
from netfusion_intelligence.graph.visualization import GraphVisualizationBuilder
from netfusion_intelligence.graph.fusion import KnowledgeFusionEngine
from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph

__all__ = [
    # Models
    "GraphNode",
    "GraphEdge",
    "GraphNodeType",
    "GraphEdgeType",
    "GraphStatistics",
    "GraphPath",
    "GraphExportFormat",
    "GraphExportRecord",
    "GraphVersion",
    "TraversalResult",
    "SearchResult",
    "SubgraphResult",
    # Engines
    "GraphRepository",
    "GraphTraversalEngine",
    "GraphSearchEngine",
    "GraphPathFinder",
    "GraphRelationshipManager",
    "GraphStatisticsEngine",
    "GraphExportService",
    "GraphVisualizationBuilder",
    "KnowledgeFusionEngine",
    # Main Service
    "UnifiedThreatKnowledgeGraph",
]
