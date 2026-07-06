"""
Attack Graph API Models — Phase A4.7.4 (Part A)
================================================
Immutable Pydantic models for Attack Graph API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).  Business-rule validation stays in attack_graph_service.py.
- No UUID generation — callers supply nodeId values.
- No timestamp generation — callers supply timestamps.
- No randomness.
- Response models are plain shaped dicts promoted to typed models so that
  FastAPI can generate correct OpenAPI schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateAttackNodeRequest(BaseModel):
    """
    Request body for POST /api/v2/attack-graph.

    Required fields
    ---------------
    nodeType    : Type of node (e.g. "ASSET", "EVIDENCE", "FINDING").
                  Must be a valid GraphNodeTypeEnum value.
    label       : Natural identity of the entity (e.g. IP, hostname).
                  Must be non-empty.

    Optional fields
    ---------------
    displayName : Human-readable display name; defaults to label if not supplied.
    riskScore   : 0–100 risk score.
    confidence  : 0–100 confidence score.
    metadata    : Arbitrary caller-supplied key-value pairs.
    namespace   : Optional scope prefix to isolate keys across projects.
    """
    nodeType    : str
    label       : str
    displayName : Optional[str]              = None
    riskScore   : Optional[int]              = Field(default=0, ge=0, le=100)
    confidence  : Optional[int]              = Field(default=0, ge=0, le=100)
    metadata    : Optional[Dict[str, Any]]   = None
    namespace   : Optional[str]              = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - nodeType must be non-empty and non-whitespace.
        - label must be non-empty and non-whitespace.
        """
        errors: List[str] = []
        if not self.nodeType or not self.nodeType.strip():
            errors.append("nodeType must not be empty.")
        if not self.label or not self.label.strip():
            errors.append("label must not be empty.")
        return errors


class UpdateAttackNodeRequest(BaseModel):
    """
    Request body for PUT /api/v2/attack-graph/{nodeId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Fields
    ------
    displayName : New display name to set.
    riskScore   : New risk score (0–100).
    confidence  : New confidence score (0–100).
    metadata    : Merge / replace metadata key-value pairs.
    """
    displayName : Optional[str]              = None
    riskScore   : Optional[int]              = Field(default=None, ge=0, le=100)
    confidence  : Optional[int]              = Field(default=None, ge=0, le=100)
    metadata    : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class AttackGraphFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/attack-graph.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    nodeType     : Filter by node type (case-insensitive exact match).
    minRiskScore : Keep only nodes with riskScore >= minRiskScore.
    maxRiskScore : Keep only nodes with riskScore <= maxRiskScore.
    minConfidence: Keep only nodes with confidence >= minConfidence.
    maxConfidence: Keep only nodes with confidence <= maxConfidence.
    """
    nodeType      : Optional[str] = None
    minRiskScore  : Optional[int] = Field(default=None, ge=0, le=100)
    maxRiskScore  : Optional[int] = Field(default=None, ge=0, le=100)
    minConfidence : Optional[int] = Field(default=None, ge=0, le=100)
    maxConfidence : Optional[int] = Field(default=None, ge=0, le=100)

    class Config:
        frozen = True


class AttackGraphSearchRequest(BaseModel):
    """
    Request body / query parameter model for attack graph search operations.

    Fields
    ------
    query : Free-text search string matched against nodeId, label, displayName
            (case-insensitive substring).  Must be non-empty if provided.
    """
    query : str = Field(..., min_length=1, description="Non-empty search string.")

    class Config:
        frozen = True


# ===========================================================================
# Response Models
# ===========================================================================

class AttackNodeResponse(BaseModel):
    """
    Single attack graph node payload returned by GET /api/v2/attack-graph/{nodeId}
    and POST /api/v2/attack-graph.

    Mirrors the shape of AttackGraphNode from attack_graph_service.py so that
    FastAPI can generate a typed OpenAPI schema.

    Fields
    ------
    nodeId      : 32-char deterministic SHA-256 key.
    nodeKey     : 32-char deterministic key (same as nodeId).
    nodeType    : GraphNodeTypeEnum value as string.
    label       : Short machine-readable label.
    displayName : Human-readable display name.
    riskScore   : 0–100 risk score.
    confidence  : 0–100 confidence score.
    metadata    : Arbitrary extension dict.
    createdAt   : ISO-8601 UTC datetime string.
    """
    nodeId      : str
    nodeKey     : str
    nodeType    : str
    label       : str
    displayName : str
    riskScore   : int
    confidence  : int
    metadata    : Dict[str, Any]
    createdAt   : str

    class Config:
        frozen = True


class AttackGraphResponse(BaseModel):
    """
    Payload for GET /api/v2/attack-graph (list).

    Fields
    ------
    nodes : List of AttackNodeResponse objects.
    total : Total count of matching nodes in the in-memory store.
    """
    nodes : List[AttackNodeResponse]
    total : int

    class Config:
        frozen = True


class AttackGraphStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/attack-graph/statistics.

    Fields
    ------
    totalNodes          : Total node count.
    nodeTypeCounts      : Dict mapping nodeType → count  (Part B canonical name).
    nodeTypeCount       : Alias for nodeTypeCounts (Part A compat).
    relationshipCounts  : Dict mapping edgeType → count  (Part B).
    relationshipCount   : Total edge count in the graph (Part A compat).
    averageRiskScore    : Mean riskScore across all nodes (0.0 if empty).
    averageConfidence   : Mean confidence across all nodes (0.0 if empty).
    """
    totalNodes          : int
    nodeTypeCounts      : Dict[str, int]
    nodeTypeCount       : Dict[str, int]          # alias — same data
    relationshipCounts  : Dict[str, int]
    relationshipCount   : int
    averageRiskScore    : float
    averageConfidence   : float

    class Config:
        frozen = True


class AttackGraphSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/attack-graph/search.

    Extends AttackGraphResponse with pagination and search metadata.
    """
    nodes      : List[AttackNodeResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True


# ===========================================================================
# Part B — Bulk Operation Models
# ===========================================================================

class BulkCreateAttackNodesRequest(BaseModel):
    """
    Request body for POST /api/v2/attack-graph/bulk/create.

    Fields
    ------
    nodes : List of CreateAttackNodeRequest items to create.
            Must be non-empty.
    """
    nodes : List[CreateAttackNodeRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.nodes:
            errors.append("nodes list must not be empty.")
        seen: set = set()
        for i, n in enumerate(self.nodes):
            sub = n.validate_request()
            for e in sub:
                errors.append(f"nodes[{i}]: {e}")
            # Check for duplicate labels within the same request
            key = (n.nodeType, n.label, n.namespace or "")
            if key in seen:
                errors.append(f"nodes[{i}]: duplicate (nodeType, label, namespace) within request.")
            if n.label:
                seen.add(key)
        return errors


class BulkUpdateAttackNodesRequest(BaseModel):
    """
    Request body for PUT /api/v2/attack-graph/bulk/update.

    Each item pairs a nodeId with the fields to update.
    """

    class BulkUpdateItem(BaseModel):
        nodeId : str
        update : UpdateAttackNodeRequest

        class Config:
            frozen = True

    items : List[BulkUpdateItem] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.items:
            errors.append("items list must not be empty.")
        for i, item in enumerate(self.items):
            if not item.nodeId or not item.nodeId.strip():
                errors.append(f"items[{i}]: nodeId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteAttackNodesRequest(BaseModel):
    """
    Request body for DELETE /api/v2/attack-graph/bulk/delete.

    Fields
    ------
    nodeIds : List of nodeId strings to delete.  Must be non-empty.
    """
    nodeIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.nodeIds:
            errors.append("nodeIds list must not be empty.")
        for i, nid in enumerate(self.nodeIds):
            if not nid or not nid.strip():
                errors.append(f"nodeIds[{i}]: nodeId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.

    Fields
    ------
    succeeded : List of nodeIds that were successfully processed.
    failed    : List of (nodeId, reason) pairs for items that failed.
    total     : Total items submitted.
    successCount : Number of succeeded items.
    failCount    : Number of failed items.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
