"""
Attack Graph Router — Phase A4.7.4 (Part A)
============================================
REST interface for the Attack Graph Engine.

Prefix  : /api/v2/attack-graph
Tag     : Attack Graph

Endpoints (Part A)
------------------
GET    /api/v2/attack-graph              — list all nodes
GET    /api/v2/attack-graph/statistics   — aggregate statistics
GET    /api/v2/attack-graph/{nodeId}     — get a single node by ID
POST   /api/v2/attack-graph              — create a node
PUT    /api/v2/attack-graph/{nodeId}     — update a node
DELETE /api/v2/attack-graph/{nodeId}     — delete a node

Design rules
------------
- No business logic here.  All node construction delegated to
  attack_graph_service.py builders.
- Uses only existing attack_graph_service builders / helpers:
    build_node(), build_statistics(), GraphNodeTypeEnum, GraphEdgeTypeEnum.
- No database.  In-memory placeholder collection (_NODE_STORE).
- Returns only build_success_response() or exception_to_api_response().
- Request model validation at the API layer only; service validates
  business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.
- No search, no sorting, no filtering, no pagination, no bulk operations.

In-memory store
---------------
_NODE_STORE is a plain dict keyed by nodeId.  It is module-level and
survives for the lifetime of the process.  It will be replaced by a
proper repository in a future phase.  Tests can reset it via _reset_store().

_EDGE_STORE tracks edges (relationship count) for statistics only.
Edges are not directly managed by this Part A router; the count is
derived from edges built outside this API and stored in _EDGE_STORE.

Statistics endpoint
-------------------
GET /statistics exposes:
  totalNodes        — total node count in _NODE_STORE
  nodeTypeCount     — { nodeType.value → count }
  relationshipCount — total edge count in _EDGE_STORE
  averageRiskScore  — mean riskScore across all nodes (0.0 if empty)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.investigation.attack_graph_models import (
    AttackGraphFilterRequest,
    AttackGraphResponse,
    AttackGraphSearchRequest,
    AttackGraphStatisticsResponse,
    AttackNodeResponse,
    BulkCreateAttackNodesRequest,
    BulkDeleteAttackNodesRequest,
    BulkOperationResult,
    BulkUpdateAttackNodesRequest,
    CreateAttackNodeRequest,
    UpdateAttackNodeRequest,
)
from api.models import APIResponse
from api.responses import build_success_response
from api.utils import exception_to_api_response
from services.attack_graph_service import (
    GraphNodeTypeEnum,
    build_node,
    build_statistics,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

attack_graph_router: APIRouter = APIRouter(
    prefix = "/attack-graph",
    tags   = ["Attack Graph"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder stores
# ---------------------------------------------------------------------------
# Dict[nodeId -> node dict]  — module-level; replaced by a repository later.
_NODE_STORE: Dict[str, Dict[str, Any]] = {}

# Dict[edgeId -> edge dict]  — for relationship count in statistics.
# Populated externally (e.g. integration layer); this router does not
# expose edge creation endpoints in Part A.
_EDGE_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear both in-memory stores.  Used by tests only."""
    _NODE_STORE.clear()
    _EDGE_STORE.clear()


def _all_nodes() -> List[Dict[str, Any]]:
    """Return all nodes as a deterministically-ordered list (by nodeId ASC)."""
    return sorted(_NODE_STORE.values(), key=lambda n: n.get("nodeId", ""))


# ---------------------------------------------------------------------------
# Validation: nodeType enum
# ---------------------------------------------------------------------------

_VALID_NODE_TYPES: set = {v.value for v in GraphNodeTypeEnum}


def _validate_node_type(node_type: str) -> Optional[GraphNodeTypeEnum]:
    """
    Convert a raw string to a GraphNodeTypeEnum value.

    Returns the enum member if valid, None otherwise.
    """
    try:
        return GraphNodeTypeEnum(node_type.strip().upper())
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_to_response(node: Dict[str, Any]) -> AttackNodeResponse:
    """Convert a raw node dict to an AttackNodeResponse model."""
    created_at = node.get("createdAt")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    elif created_at is None:
        created_at = ""

    return AttackNodeResponse(
        nodeId      = node.get("nodeId", ""),
        nodeKey     = node.get("nodeKey", ""),
        nodeType    = node.get("nodeType", ""),
        label       = node.get("label", ""),
        displayName = node.get("displayName", ""),
        riskScore   = node.get("riskScore", 0),
        confidence  = node.get("confidence", 0),
        metadata    = node.get("metadata") or {},
        createdAt   = created_at,
    )


def _node_record_to_dict(node: Any) -> Dict[str, Any]:
    """
    Convert an AttackGraphNode (frozen Pydantic model from attack_graph_service)
    to a mutable plain dict suitable for storage in _NODE_STORE.

    The nodeType value is serialised as its string value so it is JSON-safe
    and does not hold a reference to the enum member.
    """
    d = node.model_dump()
    # Serialise enum to its string value
    node_type = d.get("nodeType")
    if hasattr(node_type, "value"):
        d["nodeType"] = node_type.value
    elif isinstance(node_type, GraphNodeTypeEnum):
        d["nodeType"] = node_type.value
    return d


def _compute_statistics(nodes: List[Dict[str, Any]]) -> AttackGraphStatisticsResponse:
    """
    Compute aggregate statistics over the in-memory node and edge stores.

    Part B: Extended to include nodeTypeCounts, relationshipCounts, and
    averageConfidence.

    Parameters
    ----------
    nodes : List of raw node dicts from _NODE_STORE.

    Returns
    -------
    AttackGraphStatisticsResponse (frozen / immutable)
    """
    total = len(nodes)

    # Node type counts
    node_type_counts: Dict[str, int] = {}
    risk_sum = 0
    confidence_sum = 0
    for n in nodes:
        nt = n.get("nodeType") or "UNKNOWN"
        node_type_counts[nt] = node_type_counts.get(nt, 0) + 1
        risk_sum += n.get("riskScore", 0)
        confidence_sum += n.get("confidence", 0)

    average_risk = round(risk_sum / total, 4) if total > 0 else 0.0
    average_confidence = round(confidence_sum / total, 4) if total > 0 else 0.0

    # Edge type counts
    edge_type_counts: Dict[str, int] = {}
    for e in _EDGE_STORE.values():
        et = e.get("edgeType") or "UNKNOWN"
        edge_type_counts[et] = edge_type_counts.get(et, 0) + 1

    sorted_node_counts = dict(sorted(node_type_counts.items()))
    sorted_edge_counts = dict(sorted(edge_type_counts.items()))

    return AttackGraphStatisticsResponse(
        totalNodes         = total,
        nodeTypeCounts     = sorted_node_counts,
        nodeTypeCount      = sorted_node_counts,  # alias for Part A compatibility
        relationshipCounts = sorted_edge_counts,
        relationshipCount  = len(_EDGE_STORE),
        averageRiskScore   = average_risk,
        averageConfidence  = average_confidence,
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /attack-graph
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List attack graph nodes",
    description         = (
        "Return all attack graph nodes in the in-memory store."
    ),
)
def list_attack_nodes() -> APIResponse:
    """
    GET /api/v2/attack-graph

    Returns all nodes stored in the in-memory store.  No pagination in Part A.
    """
    try:
        nodes = _all_nodes()
        payload = AttackGraphResponse(
            nodes = [_node_to_response(n) for n in nodes],
            total = len(nodes),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(nodes)} attack graph node(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /attack-graph/statistics
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Attack graph statistics",
    description         = (
        "Return aggregate statistics over all attack graph nodes and edges "
        "in the in-memory store.  Exposes totalNodes, nodeTypeCount, "
        "relationshipCount, and averageRiskScore."
    ),
)
def get_attack_graph_statistics() -> APIResponse:
    """
    GET /api/v2/attack-graph/statistics

    Returns AttackGraphStatisticsResponse.
    """
    try:
        stats = _compute_statistics(_all_nodes())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Attack graph statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /attack-graph/{nodeId}
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "/{nodeId}",
    response_model      = APIResponse,
    summary             = "Get attack graph node by ID",
    description         = "Return a single attack graph node by its nodeId.",
)
def get_attack_node(nodeId: str) -> APIResponse:
    """
    GET /api/v2/attack-graph/{nodeId}

    Looks up by nodeId.  Returns 404 if not found.
    """
    try:
        node = _NODE_STORE.get(nodeId)
        if node is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Attack graph node '{nodeId}' not found.")
            )
        return build_success_response(
            data    = _node_to_response(node).model_dump(),
            message = "Attack graph node retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /attack-graph
# ---------------------------------------------------------------------------

@attack_graph_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create attack graph node",
    description         = (
        "Create a new attack graph node in the in-memory store.  "
        "The nodeId is derived deterministically from (namespace, nodeType, label) "
        "via SHA-256; the same inputs always produce the same nodeId."
    ),
    status_code         = 201,
)
def create_attack_node(
    body: CreateAttackNodeRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/attack-graph

    Validates the request, converts nodeType to its enum, delegates node
    construction to build_node() from attack_graph_service.py, checks for
    a duplicate nodeId, then stores the result.

    Returns 409 if a node with the same deterministic nodeId already exists.
    Returns 422 if request validation fails or nodeType is unrecognised.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid attack node request.", details=errors)
            )

        # Validate and convert nodeType
        node_type_enum = _validate_node_type(body.nodeType)
        if node_type_enum is None:
            valid_types = sorted(_VALID_NODE_TYPES)
            return exception_to_api_response(
                APIErrorValidation(
                    "Invalid nodeType value.",
                    details=[
                        f"nodeType '{body.nodeType}' is not a recognised GraphNodeTypeEnum value.",
                        f"Valid values: {valid_types}.",
                    ],
                )
            )

        # Delegate construction to the attack graph engine
        node = build_node(
            node_type    = node_type_enum,
            label        = body.label,
            display_name = body.displayName,
            risk_score   = body.riskScore or 0,
            confidence   = body.confidence or 0,
            metadata     = dict(body.metadata) if body.metadata else {},
            namespace    = body.namespace or "",
        )

        node_id = node.nodeId

        # Duplicate check — same deterministic key means same logical entity
        if node_id in _NODE_STORE:
            return exception_to_api_response(
                APIErrorConflict(
                    f"Attack graph node '{node_id}' already exists "
                    f"(duplicate detected via deterministic key for "
                    f"nodeType='{body.nodeType}', label='{body.label}')."
                )
            )

        # Store as a plain mutable dict
        stored = _node_record_to_dict(node)
        _NODE_STORE[node_id] = stored

        return build_success_response(
            data    = _node_to_response(stored).model_dump(),
            message = "Attack graph node created.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /attack-graph/{nodeId}
# ---------------------------------------------------------------------------

@attack_graph_router.put(
    "/{nodeId}",
    response_model      = APIResponse,
    summary             = "Update attack graph node",
    description         = (
        "Update mutable fields of an existing attack graph node.  "
        "Immutable fields (nodeId, nodeKey, nodeType, label, createdAt) "
        "cannot be changed through this endpoint."
    ),
)
def update_attack_node(
    nodeId: str,
    body  : UpdateAttackNodeRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/attack-graph/{nodeId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.

    Immutable fields: nodeId, nodeKey, nodeType, label, createdAt.

    Returns 404 if the node does not exist.
    Returns 422 if the body contains no fields.
    """
    try:
        # API-layer: require at least one field
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation(
                    "Update request must contain at least one field.",
                    details=["All fields in the request body are null."],
                )
            )

        node = _NODE_STORE.get(nodeId)
        if node is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Attack graph node '{nodeId}' not found.")
            )

        # Apply updates — None fields are skipped (only mutable fields)
        if body.displayName is not None:
            node["displayName"] = body.displayName
        if body.riskScore is not None:
            node["riskScore"] = max(0, min(100, body.riskScore))
        if body.confidence is not None:
            node["confidence"] = max(0, min(100, body.confidence))
        if body.metadata is not None:
            existing_meta = node.get("metadata") or {}
            node["metadata"] = {**existing_meta, **dict(body.metadata)}

        # Persist back to store
        _NODE_STORE[nodeId] = node

        return build_success_response(
            data    = _node_to_response(node).model_dump(),
            message = "Attack graph node updated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /attack-graph/{nodeId}
# ---------------------------------------------------------------------------

@attack_graph_router.delete(
    "/{nodeId}",
    response_model      = APIResponse,
    summary             = "Delete attack graph node",
    description         = "Remove an attack graph node from the in-memory store.",
)
def delete_attack_node(nodeId: str) -> APIResponse:
    """
    DELETE /api/v2/attack-graph/{nodeId}

    Returns 404 if the node does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if nodeId not in _NODE_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Attack graph node '{nodeId}' not found.")
            )

        del _NODE_STORE[nodeId]

        return build_success_response(
            data    = None,
            message = f"Attack graph node '{nodeId}' deleted.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

# Canonical sort-key map
_SORT_KEY_MAP: Dict[str, str] = {
    "nodetype"   : "nodeType",
    "label"      : "label",
    "risk"       : "riskScore",
    "riskscore"  : "riskScore",
    "confidence" : "confidence",
    "created"    : "createdAt",
    "createdat"  : "createdAt",
}


def find_attack_node(
    nodes : List[Dict[str, Any]],
    field : str,
    value : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first node whose ``field`` matches ``value`` (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.

    Parameters
    ----------
    nodes : Ordered list of node dicts to search.
    field : Dict key to match against (e.g. "nodeId", "label").
    value : Value to match (case-insensitive string comparison).

    Returns
    -------
    The first matching node dict, or None if not found.
    """
    target = value.lower()
    for n in nodes:
        v = n.get(field)
        if v is not None and str(v).lower() == target:
            return n
    return None


def sort_attack_nodes(
    nodes      : List[Dict[str, Any]],
    sort_by    : str  = "label",
    sort_order : str  = "asc",
) -> List[Dict[str, Any]]:
    """
    Return a new list of node dicts sorted by the specified field.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values
    -------------------------
    "nodeType"   — sort by nodeType (None/missing sorted last)
    "label"      — sort by label (None/missing sorted last)
    "riskScore"  — sort by riskScore (numeric; None treated as 0)
    "confidence" — sort by confidence (numeric; None treated as 0)
    "createdAt"  — sort by createdAt (datetime; None sorted last)

    Parameters
    ----------
    nodes      : List of node dicts.
    sort_by    : One of the supported sort keys above.  Unrecognised values
                 fall back to "label".
    sort_order : "asc" (default) or "desc".  Any other value treated as "asc".

    Returns
    -------
    New sorted list — input not mutated.
    """
    field = _SORT_KEY_MAP.get(sort_by.lower(), "label")
    reverse = sort_order.lower() == "desc"

    def sort_key(n: Dict[str, Any]):
        v = n.get(field)
        if v is None:
            # Sort None last for asc, first for desc (invert sentinel)
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        if isinstance(v, datetime):
            return (0, v)
        return (0, str(v).lower())

    return sorted(nodes, key=sort_key, reverse=reverse)


def filter_attack_nodes(
    nodes         : List[Dict[str, Any]],
    node_type     : Optional[str]  = None,
    min_risk      : Optional[int]  = None,
    max_risk      : Optional[int]  = None,
    min_confidence: Optional[int]  = None,
    max_confidence: Optional[int]  = None,
) -> List[Dict[str, Any]]:
    """
    Extended filter helper supporting all filter predicates.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    nodes          : Ordered list of node dicts.
    node_type      : Case-insensitive exact match on nodeType.
    min_risk       : Keep nodes with riskScore >= min_risk.
    max_risk       : Keep nodes with riskScore <= max_risk.
    min_confidence : Keep nodes with confidence >= min_confidence.
    max_confidence : Keep nodes with confidence <= max_confidence.

    Returns
    -------
    Filtered list — input not mutated.
    """
    result = []
    for n in nodes:
        if node_type is not None:
            if (n.get("nodeType") or "").lower() != node_type.lower():
                continue
        if min_risk is not None:
            if n.get("riskScore", 0) < min_risk:
                continue
        if max_risk is not None:
            if n.get("riskScore", 0) > max_risk:
                continue
        if min_confidence is not None:
            if n.get("confidence", 0) < min_confidence:
                continue
        if max_confidence is not None:
            if n.get("confidence", 0) > max_confidence:
                continue
        result.append(n)
    return result


def paginate_attack_nodes(
    nodes     : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> tuple[List[Dict[str, Any]], "Pagination"]:  # type: ignore
    """
    Slice a node list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    nodes     : Full ordered list of node dicts (already filtered/sorted).
    page      : 1-based page number (clamped to >= 1).
    page_size : Items per page (clamped to >= 1).

    Returns
    -------
    (page_slice, Pagination) where:
    - page_slice : the sub-list for the requested page.
    - Pagination : metadata model with page, pageSize, totalItems, totalPages.
    """
    import math
    from api.models import Pagination

    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(nodes)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = nodes[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_attack_nodes(
    nodes : List[Dict[str, Any]],
    query : str,
) -> List[Dict[str, Any]]:
    """
    Return nodes where any searchable text field contains *query* as a
    case-insensitive substring.

    Searchable fields: nodeId, nodeKey, label, displayName, nodeType.
    """
    q = query.lower()
    search_fields = ("nodeId", "nodeKey", "label", "displayName", "nodeType")
    result = []
    for n in nodes:
        for f in search_fields:
            v = n.get(f) or ""
            if q in str(v).lower():
                result.append(n)
                break
    return result


def get_connected_nodes(
    node_id : str,
) -> List[Dict[str, Any]]:
    """
    Return all nodes connected to the specified node via edges in _EDGE_STORE.

    Pure read-only helper — returns a list of node dicts that are either
    source or target of edges involving node_id.

    Parameters
    ----------
    node_id : The nodeId to find connections for.

    Returns
    -------
    List of connected node dicts (deduplicated).
    """
    connected_ids: set = set()
    for edge in _EDGE_STORE.values():
        src = edge.get("sourceNodeId")
        tgt = edge.get("targetNodeId")
        if src == node_id and tgt:
            connected_ids.add(tgt)
        if tgt == node_id and src:
            connected_ids.add(src)

    result = []
    for nid in connected_ids:
        node = _NODE_STORE.get(nid)
        if node:
            result.append(node)
    return sorted(result, key=lambda n: n.get("nodeId", ""))


def get_node_relationships(
    node_id : str,
) -> List[Dict[str, Any]]:
    """
    Return all edges (relationships) involving the specified node.

    Pure read-only helper — returns a list of edge dicts where the node
    is either source or target.

    Parameters
    ----------
    node_id : The nodeId to find relationships for.

    Returns
    -------
    List of edge dicts (sorted by edgeId).
    """
    result = []
    for edge in _EDGE_STORE.values():
        src = edge.get("sourceNodeId")
        tgt = edge.get("targetNodeId")
        if src == node_id or tgt == node_id:
            result.append(edge)
    return sorted(result, key=lambda e: e.get("edgeId", ""))


def get_neighbor_nodes(
    node_id : str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Return neighbor nodes categorized by direction.

    Pure read-only helper — returns a dict with "inbound" and "outbound" keys
    containing lists of node dicts.

    Parameters
    ----------
    node_id : The nodeId to find neighbors for.

    Returns
    -------
    {
        "inbound": [nodes that point TO this node],
        "outbound": [nodes that this node points TO],
    }
    """
    inbound_ids: set = set()
    outbound_ids: set = set()

    for edge in _EDGE_STORE.values():
        src = edge.get("sourceNodeId")
        tgt = edge.get("targetNodeId")
        if tgt == node_id and src:
            inbound_ids.add(src)
        if src == node_id and tgt:
            outbound_ids.add(tgt)

    inbound = []
    for nid in inbound_ids:
        node = _NODE_STORE.get(nid)
        if node:
            inbound.append(node)

    outbound = []
    for nid in outbound_ids:
        node = _NODE_STORE.get(nid)
        if node:
            outbound.append(node)

    return {
        "inbound": sorted(inbound, key=lambda n: n.get("nodeId", "")),
        "outbound": sorted(outbound, key=lambda n: n.get("nodeId", "")),
    }


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /attack-graph/search
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search attack graph nodes",
    description    = (
        "Full-text search across nodeId, nodeKey, label, displayName, and "
        "nodeType.  Supports sorting, filtering, and pagination via query parameters."
    ),
)
def search_attack_nodes(
    q             : str,
    sort_by       : Optional[str]  = "label",
    sort_order    : Optional[str]  = "asc",
    page          : Optional[int]  = 1,
    page_size     : Optional[int]  = 20,
    node_type_filter    : Optional[str]  = None,
    min_risk_filter     : Optional[int]  = None,
    max_risk_filter     : Optional[int]  = None,
    min_confidence_filter: Optional[int] = None,
    max_confidence_filter: Optional[int] = None,
) -> APIResponse:
    """
    GET /api/v2/attack-graph/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        # Validate query
        if not q or not q.strip():
            return exception_to_api_response(
                APIErrorValidation("Query parameter 'q' must not be empty.")
            )

        # Validate sort parameters
        allowed_sort = {"nodetype", "label", "risk", "riskscore", "confidence", "created", "createdat"}
        errors = []
        if sort_by and sort_by.lower() not in allowed_sort:
            errors.append(f"sortBy must be one of: nodeType, label, riskScore, confidence, createdAt.")
        if sort_order and sort_order not in ("asc", "desc"):
            errors.append("sortOrder must be 'asc' or 'desc'.")
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errors)
            )

        # Search
        matched = _search_attack_nodes(_all_nodes(), q.strip())

        # Filter
        filtered = filter_attack_nodes(
            matched,
            node_type      = node_type_filter,
            min_risk       = min_risk_filter,
            max_risk       = max_risk_filter,
            min_confidence = min_confidence_filter,
            max_confidence = max_confidence_filter,
        )

        # Sort
        sorted_nodes = sort_attack_nodes(filtered, sort_by or "label", sort_order or "asc")

        # Paginate
        page_slice, pagination = paginate_attack_nodes(
            sorted_nodes,
            page      = page or 1,
            page_size = page_size or 20,
        )

        # Build response
        from api.investigation.attack_graph_models import AttackGraphResponse
        payload = {
            "nodes"      : [_node_to_response(n).model_dump() for n in page_slice],
            "total"      : pagination.totalItems,
            "page"       : pagination.page,
            "pageSize"   : pagination.pageSize,
            "totalPages" : pagination.totalPages,
            "query"      : q.strip(),
            "sortBy"     : sort_by or "label",
            "sortOrder"  : sort_order or "asc",
        }

        return build_success_response(
            data    = payload,
            message = f"{pagination.totalItems} node(s) matched search.",
            metadata= {"pagination": pagination.model_dump()},
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /attack-graph/bulk/create
# ---------------------------------------------------------------------------

@attack_graph_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create attack graph nodes",
    description    = "Create multiple attack graph nodes in a single request.",
    status_code    = 201,
)
def bulk_create_attack_nodes(
    body: BulkCreateAttackNodesRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/attack-graph/bulk/create

    Creates multiple nodes.  Returns a summary with succeeded/failed lists.
    """
    try:
        # Validate request
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, item in enumerate(body.nodes):
            try:
                # Validate and convert nodeType
                node_type_enum = _validate_node_type(item.nodeType)
                if node_type_enum is None:
                    failed.append({
                        "index": str(idx),
                        "reason": f"Invalid nodeType '{item.nodeType}'.",
                    })
                    continue

                # Build node
                node = build_node(
                    node_type    = node_type_enum,
                    label        = item.label,
                    display_name = item.displayName,
                    risk_score   = item.riskScore or 0,
                    confidence   = item.confidence or 0,
                    metadata     = dict(item.metadata) if item.metadata else {},
                    namespace    = item.namespace or "",
                )

                node_id = node.nodeId

                # Check for duplicate
                if node_id in _NODE_STORE:
                    failed.append({
                        "index": str(idx),
                        "nodeId": node_id,
                        "reason": "Node already exists.",
                    })
                    continue

                # Store
                stored = _node_record_to_dict(node)
                _NODE_STORE[node_id] = stored
                succeeded.append(node_id)

            except Exception as e:
                failed.append({
                    "index": str(idx),
                    "reason": str(e),
                })

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.nodes),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /attack-graph/bulk/update
# ---------------------------------------------------------------------------

@attack_graph_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update attack graph nodes",
    description    = "Update multiple attack graph nodes in a single request.",
)
def bulk_update_attack_nodes(
    body: BulkUpdateAttackNodesRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/attack-graph/bulk/update

    Updates multiple nodes.  Returns a summary with succeeded/failed lists.
    """
    try:
        # Validate request
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, item in enumerate(body.items):
            try:
                node_id = item.nodeId.strip()
                node = _NODE_STORE.get(node_id)

                if node is None:
                    failed.append({
                        "index": str(idx),
                        "nodeId": node_id,
                        "reason": "Node not found.",
                    })
                    continue

                # Apply updates
                update = item.update
                if update.displayName is not None:
                    node["displayName"] = update.displayName
                if update.riskScore is not None:
                    node["riskScore"] = max(0, min(100, update.riskScore))
                if update.confidence is not None:
                    node["confidence"] = max(0, min(100, update.confidence))
                if update.metadata is not None:
                    existing_meta = node.get("metadata") or {}
                    node["metadata"] = {**existing_meta, **dict(update.metadata)}

                _NODE_STORE[node_id] = node
                succeeded.append(node_id)

            except Exception as e:
                failed.append({
                    "index": str(idx),
                    "nodeId": item.nodeId,
                    "reason": str(e),
                })

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk update completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /attack-graph/bulk/delete
# ---------------------------------------------------------------------------

@attack_graph_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete attack graph nodes",
    description    = "Delete multiple attack graph nodes in a single request.",
)
def bulk_delete_attack_nodes(
    body: BulkDeleteAttackNodesRequest = Body(...),
) -> APIResponse:
    """
    DELETE /api/v2/attack-graph/bulk/delete

    Deletes multiple nodes.  Returns a summary with succeeded/failed lists.
    """
    try:
        # Validate request
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, node_id in enumerate(body.nodeIds):
            try:
                nid = node_id.strip()
                if nid not in _NODE_STORE:
                    failed.append({
                        "index": str(idx),
                        "nodeId": nid,
                        "reason": "Node not found.",
                    })
                    continue

                del _NODE_STORE[nid]
                succeeded.append(nid)

            except Exception as e:
                failed.append({
                    "index": str(idx),
                    "nodeId": node_id,
                    "reason": str(e),
                })

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.nodeIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /attack-graph/{nodeId}/neighbors
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "/{nodeId}/neighbors",
    response_model = APIResponse,
    summary        = "Get node neighbors",
    description    = (
        "Return all nodes connected to the specified node, categorized by "
        "direction (inbound / outbound)."
    ),
)
def get_attack_node_neighbors(nodeId: str) -> APIResponse:
    """
    GET /api/v2/attack-graph/{nodeId}/neighbors

    Returns a dict with "inbound" and "outbound" lists of nodes.
    """
    try:
        # Check if node exists
        if nodeId not in _NODE_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Attack graph node '{nodeId}' not found.")
            )

        neighbors = get_neighbor_nodes(nodeId)

        payload = {
            "nodeId": nodeId,
            "inbound": [_node_to_response(n).model_dump() for n in neighbors["inbound"]],
            "outbound": [_node_to_response(n).model_dump() for n in neighbors["outbound"]],
            "inboundCount": len(neighbors["inbound"]),
            "outboundCount": len(neighbors["outbound"]),
        }

        return build_success_response(
            data    = payload,
            message = f"Node neighbors retrieved ({len(neighbors['inbound'])} inbound, {len(neighbors['outbound'])} outbound).",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /attack-graph/{nodeId}/relationships
# ---------------------------------------------------------------------------

@attack_graph_router.get(
    "/{nodeId}/relationships",
    response_model = APIResponse,
    summary        = "Get node relationships",
    description    = (
        "Return all edges (relationships) involving the specified node, "
        "both inbound and outbound."
    ),
)
def get_attack_node_relationships(nodeId: str) -> APIResponse:
    """
    GET /api/v2/attack-graph/{nodeId}/relationships

    Returns a list of edge dicts where the node is source or target.
    """
    try:
        # Check if node exists
        if nodeId not in _NODE_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Attack graph node '{nodeId}' not found.")
            )

        relationships = get_node_relationships(nodeId)

        payload = {
            "nodeId": nodeId,
            "relationships": relationships,
            "count": len(relationships),
        }

        return build_success_response(
            data    = payload,
            message = f"{len(relationships)} relationship(s) found for node '{nodeId}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
