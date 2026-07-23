"""
IL-8 UTKG — REST API Routes
==============================
All endpoints under /intelligence/graph/*

GET  /graph/node/{id}
GET  /graph/node/{id}/neighbors
GET  /graph/path
GET  /graph/search
GET  /graph/statistics
GET  /graph/traverse
GET  /graph/subgraph
GET  /graph/export
POST /graph/nodes
POST /graph/fusion
POST /graph/fusion/{layer}
GET  /graph/versions
POST /graph/versions
POST /graph/versions/{version_id}/rollback
GET  /graph/visualization
GET  /graph/query/iocs-for-cve/{cve_id}
GET  /graph/query/techniques-for-actor/{actor_id}
GET  /graph/query/campaigns-for-ioc
GET  /graph/query/assets-exposed-to-kev/{cve_id}
GET  /graph/query/investigations-for-ioc
GET  /graph/query/evidence-for-report/{node_id}
GET  /graph/query/attack-chain/{node_id}
GET  /graph/ai/expand-context/{node_id}
GET  /graph/ai/related-entities/{node_id}
GET  /graph/ai/rank-relationships/{node_id}
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Path, Body
from pydantic import BaseModel

from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph

# ─────────────────────────────────────────────────────────────────────────────
# Singleton management
# ─────────────────────────────────────────────────────────────────────────────

_utkg_instance: Optional[UnifiedThreatKnowledgeGraph] = None


def set_utkg(instance: UnifiedThreatKnowledgeGraph) -> None:
    global _utkg_instance
    _utkg_instance = instance


def get_utkg() -> UnifiedThreatKnowledgeGraph:
    global _utkg_instance
    if _utkg_instance is None:
        # Lazy init with in-memory SQLite for testing / cold start
        from netfusion_intelligence.graph.repository import GraphRepository
        repo = GraphRepository(db_url="sqlite:///./utkg.db")
        _utkg_instance = UnifiedThreatKnowledgeGraph(graph_repository=repo)
    return _utkg_instance


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class AddNodeRequest(BaseModel):
    canonical_id: str
    node_type: str
    label: str
    name: Optional[str] = None
    description: Optional[str] = None
    source_feed: Optional[str] = None
    external_id: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None
    confidence: float = 1.0


class AddEdgeRequest(BaseModel):
    source_node_id: str
    target_node_id: str
    edge_type: str
    confidence: float = 1.0
    weight: float = 1.0
    evidence_count: int = 0
    source_feed: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/graph", tags=["IL-8 Unified Threat Knowledge Graph"])


# ─── Node endpoints ──────────────────────────────────────────────────────────

@router.get("/node/{node_id}")
def get_node(
    node_id: str = Path(..., description="Internal graph node UUID"),
) -> Dict[str, Any]:
    """GET /graph/node/{id} — Retrieve a single graph node by ID."""
    utkg = get_utkg()
    node = utkg.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return {"status": "success", "node": node}


@router.get("/node/{node_id}/neighbors")
def get_neighbors(
    node_id: str = Path(..., description="Graph node UUID"),
    direction: str = Query("both", description="Edge direction: both | in | out"),
    edge_type: Optional[str] = Query(None, description="Filter by edge type"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """GET /graph/node/{id}/neighbors — Return neighbors and connecting edges."""
    utkg = get_utkg()
    result = utkg.get_node_neighbors(node_id, direction=direction, edge_type=edge_type, limit=limit)
    return {"status": "success", **result}


@router.post("/nodes")
def add_node(body: AddNodeRequest) -> Dict[str, Any]:
    """POST /graph/nodes — Add or update a graph node."""
    utkg = get_utkg()
    result = utkg.add_node(
        canonical_id=body.canonical_id,
        node_type=body.node_type,
        label=body.label,
        name=body.name,
        description=body.description,
        source_feed=body.source_feed,
        external_id=body.external_id,
        properties=body.properties,
        confidence=body.confidence,
    )
    return {"status": "success", **result}


@router.post("/edges")
def add_edge(body: AddEdgeRequest) -> Dict[str, Any]:
    """POST /graph/edges — Add or update a graph edge."""
    utkg = get_utkg()
    edge, created = utkg.relationships.add_relationship(
        source_node_id=body.source_node_id,
        target_node_id=body.target_node_id,
        edge_type=body.edge_type,
        confidence=body.confidence,
        weight=body.weight,
        evidence_count=body.evidence_count,
        source_feed=body.source_feed,
        properties=body.properties,
    )
    return {"status": "success", "edge": edge.to_dict(), "created": created}


# ─── Path Finding ─────────────────────────────────────────────────────────────

@router.get("/path")
def find_path(
    source: str = Query(..., description="Source node ID"),
    target: str = Query(..., description="Target node ID"),
    algorithm: str = Query("shortest", description="Algorithm: shortest | dijkstra | all_simple"),
    max_depth: int = Query(10, ge=1, le=20),
) -> Dict[str, Any]:
    """GET /graph/path — Find path between two nodes."""
    utkg = get_utkg()
    result = utkg.find_path(source, target, algorithm=algorithm, max_depth=max_depth)
    if not result:
        return {
            "status": "success",
            "path": None,
            "message": f"No path found between '{source}' and '{target}'",
        }
    return {"status": "success", "path": result}


# ─── Search ───────────────────────────────────────────────────────────────────

@router.get("/search")
def search_graph(
    q: str = Query("", description="Full-text search query"),
    node_type: Optional[str] = Query(None, description="Filter by node type"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """GET /graph/search — Full-text search across graph nodes."""
    utkg = get_utkg()
    result = utkg.search_graph(query=q, node_type=node_type,
                                min_confidence=min_confidence, limit=limit)
    return {"status": "success", **result}


# ─── Traversal ────────────────────────────────────────────────────────────────

@router.get("/traverse")
def traverse(
    node_id: str = Query(..., description="Starting node ID"),
    algorithm: str = Query("bfs", description="Algorithm: bfs | dfs | k_hop_N"),
    max_depth: int = Query(3, ge=1, le=10),
    edge_type: Optional[str] = Query(None),
    direction: str = Query("both"),
    limit: int = Query(500, ge=1, le=5000),
) -> Dict[str, Any]:
    """GET /graph/traverse — Run a traversal from a starting node."""
    utkg = get_utkg()
    result = utkg.traverse(
        node_id=node_id, algorithm=algorithm, max_depth=max_depth,
        edge_type=edge_type, direction=direction, limit=limit,
    )
    return {"status": "success", "traversal": result}


# ─── Subgraph ─────────────────────────────────────────────────────────────────

@router.get("/subgraph")
def get_subgraph(
    center_node_id: Optional[str] = Query(None),
    node_ids: Optional[str] = Query(None, description="Comma-separated node IDs"),
    depth: int = Query(2, ge=1, le=6),
    direction: str = Query("both"),
) -> Dict[str, Any]:
    """GET /graph/subgraph — Extract a bounded subgraph."""
    utkg = get_utkg()
    ids = [n.strip() for n in node_ids.split(",")] if node_ids else None
    result = utkg.get_subgraph(node_ids=ids, center_node_id=center_node_id,
                                depth=depth, direction=direction)
    return {"status": "success", "subgraph": result}


# ─── Statistics ───────────────────────────────────────────────────────────────

@router.get("/statistics")
def get_statistics(
    recompute: bool = Query(False, description="Force fresh computation"),
) -> Dict[str, Any]:
    """GET /graph/statistics — Graph topology statistics."""
    utkg = get_utkg()
    stats = utkg.get_statistics(recompute=recompute)
    return {"status": "success", "statistics": stats}


@router.get("/statistics/nodes")
def get_node_breakdown() -> Dict[str, Any]:
    utkg = get_utkg()
    return {"status": "success", "breakdown": utkg.statistics.get_node_type_breakdown()}


@router.get("/statistics/edges")
def get_edge_breakdown() -> Dict[str, Any]:
    utkg = get_utkg()
    return {"status": "success", "breakdown": utkg.statistics.get_edge_type_breakdown()}


@router.get("/statistics/hub-nodes")
def get_hub_nodes(top_n: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
    utkg = get_utkg()
    return {"status": "success", "hub_nodes": utkg.statistics.get_high_degree_nodes(top_n=top_n)}


# ─── Export ───────────────────────────────────────────────────────────────────

@router.get("/export")
def export_graph(
    fmt: str = Query("json", description="Format: json | graphml | gexf | csv | dot | mermaid"),
    node_type: Optional[str] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
) -> Dict[str, Any]:
    """GET /graph/export — Export graph in the requested format."""
    utkg = get_utkg()
    result = utkg.export_graph(fmt=fmt, node_type=node_type, limit=limit)
    return {"status": "success", **result}


# ─── Visualization ────────────────────────────────────────────────────────────

@router.get("/visualization")
def get_visualization(
    fmt: str = Query("cytoscape", description="Format: cytoscape | react_flow | d3 | sigma | neo4j"),
    center_node_id: Optional[str] = Query(None),
    depth: int = Query(2, ge=1, le=6),
    max_nodes: int = Query(200, ge=1, le=2000),
) -> Dict[str, Any]:
    """GET /graph/visualization — Build frontend-ready visualization payload."""
    utkg = get_utkg()
    result = utkg.build_visualization(
        fmt=fmt, center_node_id=center_node_id, depth=depth, max_nodes=max_nodes
    )
    return {"status": "success", "visualization": result}


# ─── Knowledge Fusion ─────────────────────────────────────────────────────────

@router.post("/fusion")
def run_full_fusion() -> Dict[str, Any]:
    """POST /graph/fusion — Run full IL-1..IL-7 knowledge fusion."""
    utkg = get_utkg()
    result = utkg.run_fusion()
    return {"status": "success", "fusion": result}


@router.post("/fusion/{layer}")
def run_layer_fusion(
    layer: str = Path(..., description="Layer: mitre | capec | cwe | cve | kev | epss | ioc"),
) -> Dict[str, Any]:
    """POST /graph/fusion/{layer} — Run fusion for a specific intelligence layer."""
    utkg = get_utkg()
    result = utkg.run_fusion(layer=layer)
    return {"status": "success", "fusion": result}


# ─── Version Management ───────────────────────────────────────────────────────

@router.get("/versions")
def list_versions() -> Dict[str, Any]:
    utkg = get_utkg()
    return {"status": "success", "versions": utkg.list_versions()}


@router.post("/versions")
def create_version(
    description: Optional[str] = Body(None),
) -> Dict[str, Any]:
    utkg = get_utkg()
    v = utkg.create_version(description=description)
    return {"status": "success", "version": v}


@router.post("/versions/{version_id}/rollback")
def rollback_version(
    version_id: str = Path(...),
) -> Dict[str, Any]:
    utkg = get_utkg()
    success = utkg.rollback_version(version_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Version '{version_id}' not found")
    return {"status": "success", "rolled_back_to": version_id}


# ─── Investigation Queries ────────────────────────────────────────────────────

@router.get("/query/iocs-for-cve/{cve_id}")
def iocs_for_cve(cve_id: str = Path(...)) -> Dict[str, Any]:
    """Show every IOC linked to a CVE."""
    utkg = get_utkg()
    return {"status": "success", **utkg.iocs_for_cve(cve_id)}


@router.get("/query/techniques-for-actor/{actor_id}")
def techniques_for_actor(actor_id: str = Path(...)) -> Dict[str, Any]:
    """Show all ATT&CK techniques used by a Threat Actor."""
    utkg = get_utkg()
    return {"status": "success", **utkg.techniques_for_actor(actor_id)}


@router.get("/query/campaigns-for-ioc")
def campaigns_for_ioc(
    ioc_value: str = Query(..., description="IOC value (IP, domain, hash, etc.)"),
) -> Dict[str, Any]:
    """Find every Campaign related to an IOC."""
    utkg = get_utkg()
    return {"status": "success", **utkg.campaigns_for_ioc(ioc_value)}


@router.get("/query/assets-exposed-to-kev/{cve_id}")
def assets_exposed_to_kev(cve_id: str = Path(...)) -> Dict[str, Any]:
    """Show all assets exposed to a KEV vulnerability."""
    utkg = get_utkg()
    return {"status": "success", **utkg.assets_exposed_to_kev(cve_id)}


@router.get("/query/investigations-for-ioc")
def investigations_for_ioc(
    ioc_value: str = Query(...),
) -> Dict[str, Any]:
    """Find every investigation containing a given IOC."""
    utkg = get_utkg()
    return {"status": "success", **utkg.investigations_for_ioc(ioc_value)}


@router.get("/query/evidence-for-report/{node_id}")
def evidence_for_report(node_id: str = Path(...)) -> Dict[str, Any]:
    """Find all evidence connected to a Report node."""
    utkg = get_utkg()
    return {"status": "success", **utkg.evidence_for_report(node_id)}


@router.get("/query/attack-chain/{node_id}")
def attack_chain(
    node_id: str = Path(...),
    max_depth: int = Query(8, ge=1, le=15),
) -> Dict[str, Any]:
    """Return complete attack chain from an investigation/alert node."""
    utkg = get_utkg()
    return {"status": "success", "attack_chain": utkg.reconstruct_attack_chain(node_id, max_depth=max_depth)}


@router.get("/query/shortest-path")
def shortest_path_query(
    source: str = Query(...),
    target: str = Query(...),
    max_depth: int = Query(10, ge=1, le=20),
) -> Dict[str, Any]:
    """Show shortest path between any two nodes."""
    utkg = get_utkg()
    result = utkg.find_path(source, target, max_depth=max_depth)
    if not result:
        return {"status": "success", "path": None, "found": False}
    return {"status": "success", "path": result, "found": True}


# ─── AI Foundation ────────────────────────────────────────────────────────────

@router.get("/ai/expand-context/{node_id}")
def ai_expand_context(
    node_id: str = Path(...),
    depth: int = Query(2, ge=1, le=5),
    max_nodes: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Expand context around a node for AI reasoning."""
    utkg = get_utkg()
    return {"status": "success", "context": utkg.expand_context(node_id, depth=depth, max_nodes=max_nodes)}


@router.get("/ai/related-entities/{node_id}")
def ai_related_entities(
    node_id: str = Path(...),
    target_type: str = Query(..., description="Target node type to find"),
    depth: int = Query(4, ge=1, le=8),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Find all related entities of a given type."""
    utkg = get_utkg()
    entities = utkg.find_related_entities(node_id, target_type=target_type, depth=depth)[:limit]
    return {"status": "success", "entities": entities, "count": len(entities)}


@router.get("/ai/rank-relationships/{node_id}")
def ai_rank_relationships(
    node_id: str = Path(...),
    top_n: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """Return top-N ranked relationships for a node (AI confidence scoring)."""
    utkg = get_utkg()
    ranked = utkg.rank_relationships(node_id, top_n=top_n)
    return {"status": "success", "ranked_relationships": ranked}


@router.get("/ai/confidence-propagation/{node_id}")
def ai_confidence_propagation(
    node_id: str = Path(...),
    decay: float = Query(0.8, ge=0.1, le=1.0),
    max_depth: int = Query(3, ge=1, le=8),
) -> Dict[str, Any]:
    """Propagate confidence from a node outward."""
    utkg = get_utkg()
    conf_map = utkg.propagate_confidence(node_id, decay=decay, max_depth=max_depth)
    return {"status": "success", "confidence_map": conf_map}
