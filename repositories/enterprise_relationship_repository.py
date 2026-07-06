"""
Enterprise Relationship Repository
=====================================
Phase A.3.1 — Persistence only. No business logic. No scoring. No matching.

Stores and retrieves Relationship and RelationshipEvidence records via the
Node.js/Express/Prisma HTTP API.  Mirrors the pattern established by
enterprise_asset_repository.py.

Responsibilities
----------------
- UPSERT Relationship rows by natural key
  (projectId, sourceAssetId, targetAssetId, relationshipType, protocol, port).
- Append-only RelationshipEvidence rows; deduplicate on (relationshipId, evidenceId).
- Chunked batch operations with single-transaction semantics per chunk.
- Return strongly-typed Pydantic models — never raw dicts.
- No print(), no logging, no AI, no heuristics, no scoring.

Dependency chain
----------------
  services → enterprise_relationship_repository → Node Prisma API (HTTP)
"""

from __future__ import annotations

import time
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field

from core.config import (
    PRISMA_API_BASE_URL,
    PRISMA_REQUEST_TIMEOUT,
    RELATIONSHIP_BATCH_CHUNK_SIZE,
    RELATIONSHIP_EVIDENCE_BATCH_CHUNK_SIZE,
)


# ---------------------------------------------------------------------------
# HTTP helpers (private — identical pattern to enterprise_asset_repository)
# ---------------------------------------------------------------------------

def _url(*parts: str) -> str:
    path = "/".join(str(p).strip("/") for p in parts)
    return f"{PRISMA_API_BASE_URL}/{path}"


def _get(url: str, params: Optional[Dict] = None) -> Any:
    r = requests.get(url, params=params, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _post(url: str, body: Dict) -> Any:
    r = requests.post(url, json=body, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _patch(url: str, body: Dict) -> Any:
    r = requests.patch(url, json=body, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _delete(url: str) -> Any:
    r = requests.delete(url, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _parse(model: type, data: Any) -> Any:
    if data is None:
        return None
    if isinstance(data, list):
        return [model(**item) for item in data]
    return model(**data)


# ---------------------------------------------------------------------------
# Strongly-typed return models
# ---------------------------------------------------------------------------

class RelationshipRecord(BaseModel):
    """Maps to the Relationship table in schema.prisma."""
    id               : str
    projectId        : str
    sourceAssetId    : str
    targetAssetId    : str
    relationshipType : str
    protocol         : str
    port             : Optional[int]      = None
    direction        : str                = "UNKNOWN"
    state            : str                = "NEW"
    relationshipKey  : Optional[str]      = None   # SHA-256[:32] natural-key hash
    packetCount      : int                = 0
    byteCount        : int                = 0
    firstSeen        : Optional[datetime] = None
    lastSeen         : Optional[datetime] = None
    confidence       : float              = 0.0
    lastEvidenceId   : Optional[str]      = None
    engineVersion    : Optional[str]      = None
    metadata         : Optional[str]      = None
    createdAt        : Optional[datetime] = None
    updatedAt        : Optional[datetime] = None

    class Config:
        extra = "ignore"


class RelationshipEvidenceRecord(BaseModel):
    """Maps to the RelationshipEvidence table in schema.prisma."""
    id             : str
    relationshipId : str
    evidenceId     : str
    captureId      : Optional[str]      = None
    packetNumber   : Optional[int]      = None
    sourceType     : Optional[str]      = None
    observedAt     : Optional[datetime] = None
    metadata       : Optional[str]      = None
    createdAt      : Optional[datetime] = None

    class Config:
        extra = "ignore"


class PersistedRelationshipResult(BaseModel):
    """
    Returned by batch_upsert_relationships() and batch_insert_relationship_evidence().

    Fields
    ------
    upsertedCount    : Relationship rows created or updated.
    insertedCount    : RelationshipEvidence rows newly inserted.
    duplicateCount   : rows skipped due to deduplication.
    totalProcessed   : total input records processed.
    records          : persisted RelationshipRecord objects.
    warnings         : non-fatal issues (missing projectId, chunk errors, etc.).
    processingTimeMs : wall-clock milliseconds for the entire operation.
    """
    upsertedCount    : int                        = 0
    insertedCount    : int                        = 0
    duplicateCount   : int                        = 0
    totalProcessed   : int                        = 0
    records          : List[RelationshipRecord]   = Field(default_factory=list)
    warnings         : List[str]                  = Field(default_factory=list)
    processingTimeMs : float                      = 0.0

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal: serialise a Relationship engine object to a DB payload dict
# ---------------------------------------------------------------------------

def _relationship_to_payload(
    rel       : "Relationship",   # type: ignore[name-defined]
    project_id: str,
) -> Dict[str, Any]:
    """
    Convert a Relationship engine object into the dict the Node API expects.

    Parameters
    ----------
    rel        : Relationship from relationship_service (duck-typed).
    project_id : project scope — required by the DB natural key.

    Returns
    -------
    dict suitable for POST/PATCH body.
    """
    return {
        "projectId"        : project_id,
        "sourceAssetId"    : rel.sourceAssetId,
        "targetAssetId"    : rel.targetAssetId,
        "relationshipType" : rel.relationshipType.value
                             if hasattr(rel.relationshipType, "value")
                             else str(rel.relationshipType),
        "protocol"         : rel.protocol,
        "port"             : rel.port,
        "direction"        : rel.direction.value
                             if hasattr(rel.direction, "value")
                             else str(rel.direction),
        "state"            : rel.state.value
                             if hasattr(rel.state, "value")
                             else str(rel.state),
        "relationshipKey"  : getattr(rel, "relationshipKey", None),
        "packetCount"      : rel.packetCount,
        "byteCount"        : rel.byteCount,
        "firstSeen"        : rel.firstSeen.isoformat() if rel.firstSeen else None,
        "lastSeen"         : rel.lastSeen.isoformat()  if rel.lastSeen  else None,
        "confidence"       : rel.confidence,
        "lastEvidenceId"   : rel.lastEvidenceId,
        "engineVersion"    : getattr(rel, "engineVersion", None),
        "metadata"         : json.dumps(dict(rel.metadata)) if rel.metadata else None,
    }


# ---------------------------------------------------------------------------
# Relationship — CRUD
# ---------------------------------------------------------------------------

def create_relationship(
    project_id : str,
    rel        : "Relationship",           # type: ignore[name-defined]
    tx_id      : Optional[str] = None,
) -> RelationshipRecord:
    """
    Create a new Relationship row.

    Prefer upsert_relationship() for idempotent writes; use this only when
    you are certain the row does not already exist.

    Parameters
    ----------
    project_id : project scope.
    rel        : Relationship object from relationship_service.
    tx_id      : optional server-side transaction token.

    Returns
    -------
    RelationshipRecord
    """
    body = _relationship_to_payload(rel, project_id)
    if tx_id:
        body["_txId"] = tx_id
    return _parse(RelationshipRecord, _post(_url("api/relationships"), body))


def update_relationship(
    relationship_id : str,
    data            : Dict[str, Any],
    tx_id           : Optional[str] = None,
) -> RelationshipRecord:
    """
    PATCH scalar fields on an existing Relationship row.
    Only fields present in `data` are changed.

    Parameters
    ----------
    relationship_id : Relationship.id primary key.
    data            : partial payload dict.
    tx_id           : optional transaction token.
    """
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(RelationshipRecord,
                  _patch(_url("api/relationships", relationship_id), body))


def upsert_relationship(
    project_id : str,
    rel        : "Relationship",           # type: ignore[name-defined]
    tx_id      : Optional[str] = None,
) -> RelationshipRecord:
    """
    UPSERT one Relationship by its natural key:
    (projectId, sourceAssetId, targetAssetId, relationshipType, protocol, port).

    - If the row exists: updates all mutable fields (packetCount, byteCount,
      lastSeen, confidence, state, direction, lastEvidenceId, metadata).
    - If not: creates a new row.

    Parameters
    ----------
    project_id : project scope.
    rel        : Relationship from relationship_service.
    tx_id      : optional transaction token.

    Returns
    -------
    RelationshipRecord
    """
    body = _relationship_to_payload(rel, project_id)
    if tx_id:
        body["_txId"] = tx_id
    return _parse(RelationshipRecord,
                  _post(_url("api/relationships/upsert"), body))


def delete_relationship(
    relationship_id : str,
    tx_id           : Optional[str] = None,
) -> bool:
    """
    Delete a Relationship and all cascade-linked RelationshipEvidence rows.
    Returns True on success.
    """
    result = _delete(_url("api/relationships", relationship_id))
    return result.get("deleted", False)


# ---------------------------------------------------------------------------
# Relationship — read
# ---------------------------------------------------------------------------

def get_relationship(relationship_id: str) -> Optional[RelationshipRecord]:
    """
    Fetch one Relationship by primary key.
    Returns None if not found.
    """
    try:
        data = _get(_url("api/relationships", relationship_id))
        return _parse(RelationshipRecord, data) if data else None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def get_relationship_by_id(relationship_id: str) -> Optional[RelationshipRecord]:
    """Alias for get_relationship() — explicit name used by AI/graph layers."""
    return get_relationship(relationship_id)


def get_relationship_by_key(relationship_key: str) -> Optional[RelationshipRecord]:
    """
    Fetch one Relationship by its pre-computed natural-key hash
    (relationshipKey = SHA-256[:32] over projectId+src+tgt+type+proto+port).

    This is the preferred lookup path at runtime — callers know the natural
    key components but not the DB primary key.  A single indexed column scan
    is faster than a 6-column composite WHERE clause, and the key is short
    enough to use directly in AI prompts, Redis cache lookups, and Neo4j
    property filters.

    Parameters
    ----------
    relationship_key : 32-character hex string produced by
                       relationship_service.compute_relationship_key().

    Returns
    -------
    RelationshipRecord if found, None otherwise.
    """
    try:
        data = _get(
            _url("api/relationships/by-key"),
            params={"relationshipKey": relationship_key},
        )
        return _parse(RelationshipRecord, data) if data else None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def get_relationships_by_asset(
    asset_id         : str,
    direction        : str            = "both",
    relationship_type: Optional[str]  = None,
    state            : Optional[str]  = None,
    limit            : int            = 200,
    offset           : int            = 0,
) -> List[RelationshipRecord]:
    """
    Retrieve Relationships where sourceAssetId OR targetAssetId == asset_id.

    Parameters
    ----------
    asset_id          : Asset primary key.
    direction         : "from" | "to" | "both" (default: both).
    relationship_type : optional filter on relationshipType.
    state             : optional filter on state.
    limit             : max rows (default 200).
    offset            : pagination offset.

    Returns
    -------
    List[RelationshipRecord]
    """
    params: Dict[str, Any] = {
        "assetId"   : asset_id,
        "direction" : direction,
        "limit"     : limit,
        "offset"    : offset,
    }
    if relationship_type:
        params["relationshipType"] = relationship_type
    if state:
        params["state"] = state
    data = _get(_url("api/relationships"), params=params)
    return _parse(RelationshipRecord, data)


def get_relationships_by_capture(
    capture_id       : str,
    relationship_type: Optional[str] = None,
    limit            : int           = 500,
    offset           : int           = 0,
) -> List[RelationshipRecord]:
    """
    Retrieve Relationships whose evidence links include a given captureId.

    Parameters
    ----------
    capture_id        : CaptureSession.captureId.
    relationship_type : optional filter.
    limit             : max rows.
    offset            : pagination offset.

    Returns
    -------
    List[RelationshipRecord]
    """
    params: Dict[str, Any] = {
        "captureId" : capture_id,
        "limit"     : limit,
        "offset"    : offset,
    }
    if relationship_type:
        params["relationshipType"] = relationship_type
    data = _get(_url("api/relationships/by-capture"), params=params)
    return _parse(RelationshipRecord, data)


def get_relationships_by_project(
    project_id       : str,
    relationship_type: Optional[str] = None,
    state            : Optional[str] = None,
    limit            : int           = 500,
    offset           : int           = 0,
) -> List[RelationshipRecord]:
    """
    Retrieve all Relationships within a project, with optional filters.

    Parameters
    ----------
    project_id        : project scope.
    relationship_type : optional type filter.
    state             : optional state filter (NEW/ACTIVE/INACTIVE/TERMINATED).
    limit             : max rows.
    offset            : pagination offset.

    Returns
    -------
    List[RelationshipRecord]
    """
    params: Dict[str, Any] = {
        "projectId" : project_id,
        "limit"     : limit,
        "offset"    : offset,
    }
    if relationship_type:
        params["relationshipType"] = relationship_type
    if state:
        params["state"] = state
    data = _get(_url("api/relationships"), params=params)
    return _parse(RelationshipRecord, data)


# ---------------------------------------------------------------------------
# Relationship — batch upsert
# ---------------------------------------------------------------------------

def batch_upsert_relationships(
    project_id  : str,
    rels        : List["Relationship"],    # type: ignore[name-defined]
    tx_id       : Optional[str] = None,
) -> PersistedRelationshipResult:
    """
    UPSERT a list of Relationship objects for one project.

    Single-hop design
    -----------------
    Each chunk is sent as ONE POST to /api/relationships/batch-upsert.
    The Node endpoint opens a transaction, upserts each row by natural key,
    commits, and returns { upsertedCount, records }.

    Deduplication
    -------------
    Natural key: (projectId, sourceAssetId, targetAssetId,
                  relationshipType, protocol, port).
    - Existing row → update mutable fields (packetCount, byteCount,
      lastSeen, confidence, state, direction, lastEvidenceId, metadata).
    - Missing row  → insert.

    Parameters
    ----------
    project_id : project scope applied to every row.
    rels       : list of Relationship objects from relationship_service.
    tx_id      : optional server-side transaction token.

    Returns
    -------
    PersistedRelationshipResult
    """
    start_ms = time.monotonic() * 1000

    if not rels:
        return PersistedRelationshipResult(
            upsertedCount=0, insertedCount=0, duplicateCount=0,
            totalProcessed=0, records=[], warnings=[], processingTimeMs=0.0,
        )

    total_processed = len(rels)
    warnings: List[str] = []
    upserted_rows: List[RelationshipRecord] = []
    total_upserted = 0

    for chunk_start in range(0, len(rels), RELATIONSHIP_BATCH_CHUNK_SIZE):
        chunk = rels[chunk_start : chunk_start + RELATIONSHIP_BATCH_CHUNK_SIZE]

        items = [_relationship_to_payload(r, project_id) for r in chunk]
        body: Dict[str, Any] = {"projectId": project_id, "items": items}
        if tx_id:
            body["_txId"] = tx_id

        try:
            resp = _post(_url("api/relationships/batch-upsert"), body)
            # Node returns: { upsertedCount: N, records: [...] }
            chunk_count  = resp.get("upsertedCount", 0)
            raw_records  = resp.get("records", resp if isinstance(resp, list) else [])
            total_upserted += chunk_count

            parsed = _parse(RelationshipRecord, raw_records)
            if isinstance(parsed, list):
                upserted_rows.extend(parsed)
            elif parsed is not None:
                upserted_rows.append(parsed)

        except Exception as exc:
            warnings.append(
                f"Chunk {chunk_start}–{chunk_start + len(chunk) - 1} failed: {exc}"
            )

    elapsed_ms = round((time.monotonic() * 1000) - start_ms, 2)

    return PersistedRelationshipResult(
        upsertedCount    = total_upserted,
        insertedCount    = 0,       # upsert doesn't distinguish insert vs update
        duplicateCount   = 0,
        totalProcessed   = total_processed,
        records          = upserted_rows,
        warnings         = warnings,
        processingTimeMs = elapsed_ms,
    )


# ---------------------------------------------------------------------------
# RelationshipEvidence — create / batch / read
# ---------------------------------------------------------------------------

def create_relationship_evidence(
    relationship_id : str,
    evidence_id     : str,
    capture_id      : Optional[str]      = None,
    packet_number   : Optional[int]      = None,
    source_type     : Optional[str]      = None,
    observed_at     : Optional[datetime] = None,
    extra_meta      : Optional[Dict[str, Any]] = None,
    tx_id           : Optional[str]      = None,
) -> RelationshipEvidenceRecord:
    """
    Append one RelationshipEvidence link.

    Deduplication: the (relationshipId, evidenceId) unique constraint on the
    DB prevents duplicates.  The Node endpoint should return the existing row
    on conflict rather than raising.

    Parameters
    ----------
    relationship_id : Relationship.id primary key.
    evidence_id     : EvidenceRecord.evidenceId (stable UUID v5).
    capture_id      : CaptureSession.captureId for fast scoping queries.
    packet_number   : frame index within capture file.
    source_type     : normalised source key (e.g. "pcap").
    observed_at     : UTC datetime of the original observation.
    extra_meta      : arbitrary JSON metadata.
    tx_id           : optional transaction token.

    Returns
    -------
    RelationshipEvidenceRecord
    """
    body: Dict[str, Any] = {
        "relationshipId" : relationship_id,
        "evidenceId"     : evidence_id,
        "captureId"      : capture_id,
        "packetNumber"   : packet_number,
        "sourceType"     : source_type,
        "observedAt"     : observed_at.isoformat() if observed_at else None,
        "metadata"       : json.dumps(extra_meta) if extra_meta else None,
    }
    if tx_id:
        body["_txId"] = tx_id
    return _parse(RelationshipEvidenceRecord,
                  _post(_url("api/relationships", relationship_id, "evidence"), body))


def batch_insert_relationship_evidence(
    relationship_id : str,
    evidence_ids    : List[str],
    capture_id      : Optional[str]      = None,
    source_type     : Optional[str]      = None,
    observed_at     : Optional[datetime] = None,
    tx_id           : Optional[str]      = None,
) -> PersistedRelationshipResult:
    """
    Append multiple RelationshipEvidence links in one transaction per chunk.

    Append-only design
    ------------------
    The Node endpoint receives all evidenceIds, checks which
    (relationshipId, evidenceId) pairs already exist in one query, inserts
    only the missing ones, and returns { insertedCount, duplicateCount }.

    Parameters
    ----------
    relationship_id : Relationship.id primary key.
    evidence_ids    : list of EvidenceRecord.evidenceId values to link.
    capture_id      : optional CaptureSession.captureId applied to all rows.
    source_type     : optional source key applied to all rows.
    observed_at     : optional observation timestamp applied to all rows.
    tx_id           : optional transaction token.

    Returns
    -------
    PersistedRelationshipResult
    """
    start_ms = time.monotonic() * 1000

    if not evidence_ids:
        return PersistedRelationshipResult(
            upsertedCount=0, insertedCount=0, duplicateCount=0,
            totalProcessed=0, records=[], warnings=[], processingTimeMs=0.0,
        )

    # Deduplicate input list (preserve order)
    deduped = list(dict.fromkeys(evidence_ids))
    total_processed = len(deduped)
    warnings: List[str] = []
    total_inserted  = 0
    total_dupes     = 0

    for chunk_start in range(0, len(deduped), RELATIONSHIP_EVIDENCE_BATCH_CHUNK_SIZE):
        chunk = deduped[chunk_start : chunk_start + RELATIONSHIP_EVIDENCE_BATCH_CHUNK_SIZE]

        body: Dict[str, Any] = {
            "relationshipId" : relationship_id,
            "evidenceIds"    : chunk,
            "captureId"      : capture_id,
            "sourceType"     : source_type,
            "observedAt"     : observed_at.isoformat() if observed_at else None,
        }
        if tx_id:
            body["_txId"] = tx_id

        try:
            resp = _post(
                _url("api/relationships", relationship_id, "evidence/batch-insert"),
                body,
            )
            total_inserted += resp.get("insertedCount", 0)
            total_dupes    += resp.get("duplicateCount", 0)

        except Exception as exc:
            warnings.append(
                f"Evidence chunk {chunk_start}–{chunk_start + len(chunk) - 1} "
                f"failed: {exc}"
            )

    elapsed_ms = round((time.monotonic() * 1000) - start_ms, 2)

    return PersistedRelationshipResult(
        upsertedCount    = 0,
        insertedCount    = total_inserted,
        duplicateCount   = total_dupes,
        totalProcessed   = total_processed,
        records          = [],
        warnings         = warnings,
        processingTimeMs = elapsed_ms,
    )


def get_relationship_evidence(
    relationship_id : str,
    limit           : int = 200,
    offset          : int = 0,
) -> List[RelationshipEvidenceRecord]:
    """
    Retrieve all RelationshipEvidence rows for one Relationship.

    Parameters
    ----------
    relationship_id : Relationship.id primary key.
    limit           : max rows (default 200).
    offset          : pagination offset.

    Returns
    -------
    List[RelationshipEvidenceRecord]
    """
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    data   = _get(_url("api/relationships", relationship_id, "evidence"), params=params)
    return _parse(RelationshipEvidenceRecord, data)


# ---------------------------------------------------------------------------
# RelationshipHistory — strongly-typed return model
# ---------------------------------------------------------------------------

class RelationshipHistoryRecord(BaseModel):
    """Maps to the RelationshipHistory table in schema.prisma."""
    id               : str
    relationshipId   : str
    relationshipKey  : str
    projectId        : str
    sourceAssetId    : str
    targetAssetId    : str
    relationshipType : str
    protocol         : str
    port             : Optional[int]      = None

    eventType        : str
    changedFields    : str                 # JSON array string e.g. '["confidence","state"]'
    changeReason     : str

    previousSnapshot : Optional[str]      = None  # JSON string | None
    currentSnapshot  : str                         # JSON string

    sequenceNumber   : int                = 0
    parentEventId    : Optional[str]      = None
    occurredAt       : Optional[datetime] = None
    summary          : Optional[str]      = None
    engineVersion    : Optional[str]      = None
    metadata         : Optional[str]      = None
    createdAt        : Optional[datetime] = None

    class Config:
        extra = "ignore"


# ---------------------------------------------------------------------------
# Internal: serialise a RelationshipHistoryEvent to a DB payload dict
# ---------------------------------------------------------------------------

def _history_event_to_payload(
    ev         : "RelationshipHistoryEvent",   # type: ignore[name-defined]
    project_id : str,
) -> Dict[str, Any]:
    """
    Convert a RelationshipHistoryEvent engine object into the dict the
    Node API expects for the /api/relationships/history endpoint.

    Parameters
    ----------
    ev         : RelationshipHistoryEvent from relationship_history_service.
    project_id : project scope — used as a guard / override.

    Returns
    -------
    dict suitable for POST body.
    """
    import json as _json

    # Serialise snapshot models → JSON strings
    prev_snap = None
    if ev.previousSnapshot is not None:
        prev_snap = _json.dumps(ev.previousSnapshot.dict())
    curr_snap = _json.dumps(ev.currentSnapshot.dict())

    return {
        "relationshipId"   : ev.relationshipId,
        "relationshipKey"  : ev.relationshipKey,
        "projectId"        : project_id,
        "sourceAssetId"    : ev.sourceAssetId,
        "targetAssetId"    : ev.targetAssetId,
        "relationshipType" : ev.relationshipType.value
                             if hasattr(ev.relationshipType, "value")
                             else str(ev.relationshipType),
        "protocol"         : ev.protocol,
        "port"             : ev.port,
        "eventType"        : ev.eventType.value
                             if hasattr(ev.eventType, "value")
                             else str(ev.eventType),
        "changedFields"    : _json.dumps(list(ev.changedFields)),
        "changeReason"     : ev.changeReason,
        "previousSnapshot" : prev_snap,
        "currentSnapshot"  : curr_snap,
        "sequenceNumber"   : ev.sequenceNumber,
        "parentEventId"    : ev.parentEventId,
        "occurredAt"       : ev.occurredAt.isoformat() if ev.occurredAt else None,
        "summary"          : ev.summary or None,
        "engineVersion"    : ev.metadata.get("engineVersion") if ev.metadata else None,
        "metadata"         : _json.dumps(dict(ev.metadata)) if ev.metadata else None,
    }


# ---------------------------------------------------------------------------
# RelationshipHistory — append / batch / read
# ---------------------------------------------------------------------------

def append_relationship_history(
    ev         : "RelationshipHistoryEvent",   # type: ignore[name-defined]
    project_id : str,
    tx_id      : Optional[str] = None,
) -> RelationshipHistoryRecord:
    """
    Append one RelationshipHistoryEvent to the DB.

    Idempotent: the unique constraint on
    (relationshipId, eventType, occurredAt) prevents exact duplicates.
    The Node endpoint returns the existing row on conflict.

    Parameters
    ----------
    ev         : RelationshipHistoryEvent from relationship_history_service.
    project_id : project scope.
    tx_id      : optional transaction token.

    Returns
    -------
    RelationshipHistoryRecord
    """
    body = _history_event_to_payload(ev, project_id)
    if tx_id:
        body["_txId"] = tx_id
    return _parse(
        RelationshipHistoryRecord,
        _post(_url("api/relationships/history"), body),
    )


def batch_append_relationship_history(
    events     : List["RelationshipHistoryEvent"],  # type: ignore[name-defined]
    project_id : str,
    tx_id      : Optional[str] = None,
) -> PersistedRelationshipResult:
    """
    Append a list of RelationshipHistoryEvents in chunked transactions.

    Append-only — never updates existing rows.
    Duplicate rows (same relationshipId + eventType + occurredAt) are
    silently skipped by the Node endpoint.

    Parameters
    ----------
    events     : list of RelationshipHistoryEvent objects.
    project_id : project scope applied to every row.
    tx_id      : optional transaction token.

    Returns
    -------
    PersistedRelationshipResult
    """
    start_ms = time.monotonic() * 1000

    if not events:
        return PersistedRelationshipResult(
            upsertedCount=0, insertedCount=0, duplicateCount=0,
            totalProcessed=0, records=[], warnings=[], processingTimeMs=0.0,
        )

    total_processed = len(events)
    warnings: List[str]                       = []
    total_inserted  = 0
    total_dupes     = 0

    for chunk_start in range(0, len(events), RELATIONSHIP_BATCH_CHUNK_SIZE):
        chunk = events[chunk_start : chunk_start + RELATIONSHIP_BATCH_CHUNK_SIZE]

        items = [_history_event_to_payload(ev, project_id) for ev in chunk]
        body: Dict[str, Any] = {"projectId": project_id, "items": items}
        if tx_id:
            body["_txId"] = tx_id

        try:
            resp = _post(_url("api/relationships/history/batch-append"), body)
            total_inserted += resp.get("insertedCount", 0)
            total_dupes    += resp.get("duplicateCount", 0)

        except Exception as exc:
            warnings.append(
                f"History chunk {chunk_start}–{chunk_start + len(chunk) - 1} failed: {exc}"
            )

    elapsed_ms = round((time.monotonic() * 1000) - start_ms, 2)

    return PersistedRelationshipResult(
        upsertedCount    = 0,
        insertedCount    = total_inserted,
        duplicateCount   = total_dupes,
        totalProcessed   = total_processed,
        records          = [],
        warnings         = warnings,
        processingTimeMs = elapsed_ms,
    )


def get_relationship_history(
    relationship_id : str,
    event_type      : Optional[str] = None,
    change_reason   : Optional[str] = None,
    changed_field   : Optional[str] = None,
    limit           : int           = 200,
    offset          : int           = 0,
) -> List[RelationshipHistoryRecord]:
    """
    Retrieve history events for one Relationship, newest first.

    Parameters
    ----------
    relationship_id : Relationship.id primary key.
    event_type      : optional filter on eventType.
    change_reason   : optional filter on changeReason (exact match).
    changed_field   : optional filter — returns events where changedFields
                      JSON array contains this field name.
    limit           : max rows (default 200).
    offset          : pagination offset.

    Returns
    -------
    List[RelationshipHistoryRecord]
    """
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if event_type:
        params["eventType"]    = event_type
    if change_reason:
        params["changeReason"] = change_reason
    if changed_field:
        params["changedField"] = changed_field

    data = _get(
        _url("api/relationships", relationship_id, "history"),
        params=params,
    )
    return _parse(RelationshipHistoryRecord, data)


def get_relationship_history_by_key(
    relationship_key : str,
    limit            : int = 200,
    offset           : int = 0,
) -> List[RelationshipHistoryRecord]:
    """
    Retrieve history events using the natural-key hash (relationshipKey).

    Preferred by AI Copilot — it knows the key, not the DB primary key.

    Parameters
    ----------
    relationship_key : 32-char SHA-256 hex produced by
                       relationship_service.compute_relationship_key().
    limit            : max rows.
    offset           : pagination offset.

    Returns
    -------
    List[RelationshipHistoryRecord]
    """
    params: Dict[str, Any] = {
        "relationshipKey" : relationship_key,
        "limit"           : limit,
        "offset"          : offset,
    }
    data = _get(_url("api/relationships/history/by-key"), params=params)
    return _parse(RelationshipHistoryRecord, data)


def get_project_relationship_history(
    project_id    : str,
    event_type    : Optional[str] = None,
    change_reason : Optional[str] = None,
    limit         : int           = 500,
    offset        : int           = 0,
) -> List[RelationshipHistoryRecord]:
    """
    Retrieve relationship history events scoped to an entire project.

    Useful for AI Copilot trend analytics:
        "What changed most in project X over the last 24 hours?"
        "Which relationships had the most state transitions today?"

    Parameters
    ----------
    project_id    : project scope.
    event_type    : optional filter on eventType.
    change_reason : optional filter on changeReason.
    limit         : max rows.
    offset        : pagination offset.

    Returns
    -------
    List[RelationshipHistoryRecord]
    """
    params: Dict[str, Any] = {
        "projectId" : project_id,
        "limit"     : limit,
        "offset"    : offset,
    }
    if event_type:
        params["eventType"]    = event_type
    if change_reason:
        params["changeReason"] = change_reason

    data = _get(_url("api/relationships/history"), params=params)
    return _parse(RelationshipHistoryRecord, data)
