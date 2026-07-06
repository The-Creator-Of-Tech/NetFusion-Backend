"""
Evidence Router — Phase A4.7.2 (Part A)
=========================================
REST interface for the Evidence Engine.

Prefix  : /api/v2/evidence
Tag     : Evidence

Endpoints (Part A)
------------------
GET    /api/v2/evidence              — list all evidence records
GET    /api/v2/evidence/statistics   — aggregate statistics
GET    /api/v2/evidence/{evidenceId} — get a single evidence record by ID
POST   /api/v2/evidence              — create an evidence record
PUT    /api/v2/evidence/{evidenceId} — update an evidence record
DELETE /api/v2/evidence/{evidenceId} — delete an evidence record

Design rules
------------
- No business logic here.  All evidence construction delegated to
  evidence_service.py builders.
- Uses only existing evidence_service builders / helpers:
    build_evidence(), build_metadata(), normalize_field_name(),
    normalize_source().
- No database.  In-memory placeholder collection (_EVIDENCE_STORE).
- Returns only build_success_response() or exception_to_api_response().
- Request model validation at the API layer only; service validates
  business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.
- No search, no sorting, no filtering, no pagination, no bulk operations.

In-memory store
---------------
_EVIDENCE_STORE is a plain dict keyed by evidenceId.  It is module-level
and survives for the lifetime of the process.  It will be replaced by a
proper repository in a future phase.  Tests can reset it via _reset_store().
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body

from api.errors import APIErrorConflict, APIErrorInternal, APIErrorNotFound, APIErrorValidation
from api.investigation.evidence_models import (
    BulkCreateEvidenceRequest,
    BulkDeleteEvidenceRequest,
    BulkEvidenceOperationResult,
    BulkUpdateEvidenceRequest,
    CreateEvidenceRequest,
    EvidenceFilterRequest,
    EvidenceListResponse,
    EvidenceMetadataResponse,
    EvidenceReferenceResponse,
    EvidenceResponse,
    EvidenceSearchQueryRequest,
    EvidenceSearchRequest,
    EvidenceSearchResponse,
    EvidenceStatisticsResponse,
    EvidenceSourceResponse,
    UpdateEvidenceRequest,
)
from api.models import APIResponse
from api.responses import build_success_response
from api.utils import exception_to_api_response
from services.evidence_service import (
    build_evidence,
    build_metadata,
    normalize_field_name,
    normalize_source,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

evidence_router: APIRouter = APIRouter(
    prefix = "/evidence",
    tags   = ["Evidence"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder store
# ---------------------------------------------------------------------------
# Dict[evidenceId -> evidence dict]   — module-level; replaced by repository later.
_EVIDENCE_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store.  Used by tests only."""
    _EVIDENCE_STORE.clear()


def _all_evidence() -> List[Dict[str, Any]]:
    """Return all evidence records as a deterministically-ordered list (by evidenceId ASC)."""
    return sorted(_EVIDENCE_STORE.values(), key=lambda e: e.get("evidenceId", ""))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _evidence_to_response(ev: Dict[str, Any]) -> EvidenceResponse:
    """Convert a raw evidence dict to an EvidenceResponse model."""
    source_raw = ev.get("source") or {}
    reference_raw = ev.get("reference") or {}
    metadata_raw = ev.get("metadata") or {}

    source_resp = EvidenceSourceResponse(
        sourceType = source_raw.get("sourceType", "unknown"),
        sourceId   = source_raw.get("sourceId"),
        confidence = source_raw.get("confidence", 0),
    ) if source_raw else None

    ref_observed = reference_raw.get("observedAt")
    if isinstance(ref_observed, datetime):
        ref_observed = ref_observed.isoformat()

    reference_resp = EvidenceReferenceResponse(
        packetNumber = reference_raw.get("packetNumber"),
        captureId    = reference_raw.get("captureId"),
        sessionId    = reference_raw.get("sessionId"),
        observedAt   = ref_observed,
    ) if reference_raw else None

    metadata_resp = EvidenceMetadataResponse(
        protocol   = metadata_raw.get("protocol"),
        packetInfo = metadata_raw.get("packetInfo"),
        rawValue   = metadata_raw.get("rawValue"),
        tags       = list(metadata_raw.get("tags") or []),
        extra      = dict(metadata_raw.get("extra") or {}),
    )

    observed_at = ev.get("observedAt")
    if isinstance(observed_at, datetime):
        observed_at = observed_at.isoformat()

    created_at = ev.get("createdAt")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()

    return EvidenceResponse(
        evidenceId    = ev.get("evidenceId"),
        evidenceHash  = ev.get("evidenceHash"),
        fieldName     = ev.get("fieldName"),
        fieldValue    = ev.get("fieldValue"),
        assetId       = ev.get("assetId"),
        source        = source_resp,
        reference     = reference_resp,
        confidence    = ev.get("confidence"),
        engineVersion = ev.get("engineVersion"),
        schemaVersion = ev.get("schemaVersion"),
        observedAt    = observed_at,
        createdAt     = created_at,
        metadata      = metadata_resp,
    )


def _record_to_dict(record: Any) -> Dict[str, Any]:
    """
    Convert an EvidenceRecord (frozen Pydantic model from evidence_service)
    to a mutable plain dict suitable for storage in _EVIDENCE_STORE.
    """
    d = record.model_dump()
    # Flatten nested Pydantic models to plain dicts
    for key in ("source", "reference", "metadata"):
        val = d.get(key)
        if hasattr(val, "model_dump"):
            d[key] = val.model_dump()
        elif not isinstance(val, dict):
            d[key] = {}
    return d


def _compute_statistics(records: List[Dict[str, Any]]) -> EvidenceStatisticsResponse:
    """Compute aggregate statistics over a list of evidence record dicts."""
    total = len(records)

    asset_ids: set = set()
    field_names: set = set()
    source_types: set = set()
    source_counts: Dict[str, int] = {}
    field_counts: Dict[str, int] = {}
    asset_counts: Dict[str, int] = {}
    confidence_sum = 0

    for r in records:
        asset_id    = r.get("assetId")
        field_name  = r.get("fieldName") or "unknown"
        source_raw  = r.get("source") or {}
        source_type = source_raw.get("sourceType") or "unknown"
        confidence  = r.get("confidence") or 0

        if asset_id:
            asset_ids.add(asset_id)
            asset_counts[asset_id] = asset_counts.get(asset_id, 0) + 1

        field_names.add(field_name)
        source_types.add(source_type)

        field_counts[field_name]   = field_counts.get(field_name, 0) + 1
        source_counts[source_type] = source_counts.get(source_type, 0) + 1
        confidence_sum += confidence

    avg_confidence = round(confidence_sum / total, 4) if total > 0 else 0.0

    return EvidenceStatisticsResponse(
        totalRecords      = total,
        uniqueAssets      = len(asset_ids),
        uniqueFields      = len(field_names),
        uniqueSources     = len(source_types),
        averageConfidence = avg_confidence,
        sourceCounts      = dict(sorted(source_counts.items())),
        fieldCounts       = dict(sorted(field_counts.items())),
        assetCounts       = dict(sorted(asset_counts.items())),
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /evidence
# ---------------------------------------------------------------------------

@evidence_router.get(
    "",
    response_model = APIResponse,
    summary        = "List evidence records",
    description    = "Return all evidence records in the in-memory store.",
)
def list_evidence() -> APIResponse:
    """
    GET /api/v2/evidence

    Returns all evidence records.  No pagination in Part A.
    """
    try:
        records = _all_evidence()
        payload = EvidenceListResponse(
            evidence = [_evidence_to_response(r) for r in records],
            total    = len(records),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(records)} evidence record(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /evidence/statistics
# ---------------------------------------------------------------------------

@evidence_router.get(
    "/statistics",
    response_model = APIResponse,
    summary        = "Evidence statistics",
    description    = "Return aggregate statistics over all evidence records in the in-memory store.",
)
def get_evidence_statistics() -> APIResponse:
    """
    GET /api/v2/evidence/statistics

    Returns EvidenceStatisticsResponse — totals, unique counts, averages.
    """
    try:
        stats = _compute_statistics(_all_evidence())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Evidence statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /evidence/{evidenceId}
# ---------------------------------------------------------------------------

@evidence_router.get(
    "/{evidenceId}",
    response_model = APIResponse,
    summary        = "Get evidence by ID",
    description    = "Return a single evidence record by its evidenceId.",
)
def get_evidence(evidenceId: str) -> APIResponse:
    """
    GET /api/v2/evidence/{evidenceId}

    Looks up by evidenceId.  Returns 404 if not found.
    """
    try:
        record = _EVIDENCE_STORE.get(evidenceId)
        if record is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Evidence record '{evidenceId}' not found.")
            )
        return build_success_response(
            data    = _evidence_to_response(record).model_dump(),
            message = "Evidence record retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /evidence
# ---------------------------------------------------------------------------

@evidence_router.post(
    "",
    response_model = APIResponse,
    summary        = "Create evidence record",
    description    = "Create a new evidence record in the in-memory store.",
    status_code    = 201,
)
def create_evidence(
    body: CreateEvidenceRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/evidence

    Validates the request, delegates construction to build_evidence() from
    evidence_service.py, checks for duplicate evidenceId (hash-derived),
    then stores the result.

    Returns 409 if a record with the same deterministic evidenceId already exists.
    Returns 422 if request validation fails or if build_evidence() returns None.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid evidence request.", details=errors)
            )

        # Parse observedAt if provided
        observed_at: Optional[datetime] = None
        if body.observedAt:
            try:
                observed_at = datetime.fromisoformat(
                    body.observedAt.replace("Z", "+00:00")
                )
            except ValueError:
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid observedAt format.",
                        details=["observedAt must be a valid ISO-8601 datetime string."],
                    )
                )

        # Build metadata if any metadata fields were provided
        metadata = None
        has_metadata = any([
            body.protocol, body.packetInfo, body.rawValue,
            body.tags, body.extra,
        ])
        if has_metadata:
            metadata = build_metadata(
                protocol    = body.protocol,
                packet_info = body.packetInfo,
                raw_value   = body.rawValue,
                tags        = list(body.tags) if body.tags else None,
                extra       = dict(body.extra) if body.extra else None,
            )

        # Delegate construction to the evidence engine
        record = build_evidence(
            field_name    = body.fieldName,
            field_value   = body.fieldValue,
            source_type   = body.sourceType,
            asset_id      = body.assetId,
            source_id     = body.sourceId,
            confidence    = body.confidence,
            packet_number = body.packetNumber,
            capture_id    = body.captureId,
            session_id    = body.sessionId,
            observed_at   = observed_at,
            metadata      = metadata,
        )

        if record is None:
            return exception_to_api_response(
                APIErrorValidation(
                    "Evidence record could not be built.",
                    details=["fieldValue resolved to an empty string after normalisation."],
                )
            )

        evidence_id = record.evidenceId

        # Duplicate check — same content hash means same observation
        if evidence_id in _EVIDENCE_STORE:
            return exception_to_api_response(
                APIErrorConflict(
                    f"Evidence record '{evidence_id}' already exists "
                    f"(duplicate observation detected via content hash)."
                )
            )

        # Store as a plain mutable dict
        stored = _record_to_dict(record)
        _EVIDENCE_STORE[evidence_id] = stored

        return build_success_response(
            data    = _evidence_to_response(stored).model_dump(),
            message = "Evidence record created.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /evidence/{evidenceId}
# ---------------------------------------------------------------------------

@evidence_router.put(
    "/{evidenceId}",
    response_model = APIResponse,
    summary        = "Update evidence record",
    description    = "Update mutable fields of an existing evidence record.",
)
def update_evidence(
    evidenceId : str,
    body       : UpdateEvidenceRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/evidence/{evidenceId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.

    Immutable fields (evidenceId, evidenceHash, fieldName, fieldValue,
    source.sourceType, engineVersion, schemaVersion) cannot be changed
    through this endpoint — they are content-derived or version-stamped.

    Returns 404 if the record does not exist.
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

        record = _EVIDENCE_STORE.get(evidenceId)
        if record is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Evidence record '{evidenceId}' not found.")
            )

        # Apply updates — None fields are skipped (only mutable fields)
        if body.assetId is not None:
            record["assetId"] = body.assetId

        if body.confidence is not None:
            record["confidence"] = body.confidence
            # Keep source confidence in sync if source dict is present
            src = record.get("source")
            if isinstance(src, dict):
                src["confidence"] = body.confidence

        # Update metadata fields
        meta = dict(record.get("metadata") or {})
        if body.protocol is not None:
            meta["protocol"] = body.protocol
        if body.packetInfo is not None:
            meta["packetInfo"] = body.packetInfo
        if body.rawValue is not None:
            meta["rawValue"] = body.rawValue
        if body.tags is not None:
            meta["tags"] = list(body.tags)
        if body.extra is not None:
            existing_extra = dict(meta.get("extra") or {})
            meta["extra"] = {**existing_extra, **dict(body.extra)}
        record["metadata"] = meta

        # Persist back to store
        _EVIDENCE_STORE[evidenceId] = record

        return build_success_response(
            data    = _evidence_to_response(record).model_dump(),
            message = "Evidence record updated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /evidence/{evidenceId}
# ---------------------------------------------------------------------------

@evidence_router.delete(
    "/{evidenceId}",
    response_model = APIResponse,
    summary        = "Delete evidence record",
    description    = "Remove an evidence record from the in-memory store.",
)
def delete_evidence(evidenceId: str) -> APIResponse:
    """
    DELETE /api/v2/evidence/{evidenceId}

    Returns 404 if the record does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if evidenceId not in _EVIDENCE_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Evidence record '{evidenceId}' not found.")
            )

        del _EVIDENCE_STORE[evidenceId]

        return build_success_response(
            data    = None,
            message = f"Evidence record '{evidenceId}' deleted.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

# Canonical sort-key map
_SORT_KEY_MAP: Dict[str, str] = {
    "confidence"  : "confidence",
    "sourcetype"  : "source.sourceType",
    "fieldname"   : "fieldName",
    "created"     : "createdAt",
}


def find_evidence(
    records : List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first evidence record whose ``field`` matches ``value`` (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.

    Parameters
    ----------
    records : Ordered list of evidence record dicts to search.
    field   : Dict key to match against (e.g. "evidenceId", "assetId").
    value   : Value to match (case-insensitive string comparison).

    Returns
    -------
    The first matching record dict, or None if not found.
    """
    target = value.lower()
    for r in records:
        v = r.get(field)
        if v is not None and str(v).lower() == target:
            return r
    return None


def sort_evidence(
    records    : List[Dict[str, Any]],
    sort_by    : str  = "created",
    sort_order : str  = "asc",
) -> List[Dict[str, Any]]:
    """
    Return a new list of evidence record dicts sorted by the specified field.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values
    -------------------------
    "confidence"  — sort by confidence (numeric; None treated as 0)
    "sourceType"  — sort by source.sourceType (None/missing sorted last)
    "fieldName"   — sort by fieldName (None/missing sorted last)
    "created"     — sort by createdAt (datetime; None sorted last)

    Parameters
    ----------
    records    : List of evidence record dicts.
    sort_by    : One of the supported sort keys above.  Unrecognised values
                 fall back to "created".
    sort_order : "asc" (default) or "desc".  Any other value treated as "asc".

    Returns
    -------
    New sorted list — input not mutated.
    """
    field_path = _SORT_KEY_MAP.get(sort_by.lower(), "createdAt")
    reverse = sort_order.lower() == "desc"

    def sort_key(r: Dict[str, Any]):
        # Handle nested paths like "source.sourceType"
        if "." in field_path:
            parts = field_path.split(".")
            v = r
            for part in parts:
                v = v.get(part) if isinstance(v, dict) else None
                if v is None:
                    break
        else:
            v = r.get(field_path)

        if v is None:
            # Sort None last for asc, first for desc (invert sentinel)
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        if isinstance(v, datetime):
            return (0, v)
        return (0, str(v).lower())

    return sorted(records, key=sort_key, reverse=reverse)


def filter_evidence(
    records       : List[Dict[str, Any]],
    asset_id      : Optional[str] = None,
    source_type   : Optional[str] = None,
    field_name    : Optional[str] = None,
    min_confidence: Optional[int] = None,
    max_confidence: Optional[int] = None,
    capture_id    : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extended filter helper supporting all filter predicates.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    records        : Ordered list of evidence record dicts.
    asset_id       : Exact match on assetId (case-insensitive).
    source_type    : Exact match on source.sourceType (case-insensitive).
    field_name     : Exact match on fieldName (case-insensitive).
    min_confidence : Keep records with confidence >= min_confidence.
    max_confidence : Keep records with confidence <= max_confidence.
    capture_id     : Exact match on reference.captureId (case-insensitive).

    Returns
    -------
    Filtered list — input not mutated.
    """
    result = []
    for r in records:
        if asset_id is not None:
            if (r.get("assetId") or "").lower() != asset_id.lower():
                continue

        if source_type is not None:
            src = r.get("source") or {}
            if (src.get("sourceType") or "").lower() != source_type.lower():
                continue

        if field_name is not None:
            if (r.get("fieldName") or "").lower() != field_name.lower():
                continue

        if min_confidence is not None:
            if r.get("confidence", 0) < min_confidence:
                continue

        if max_confidence is not None:
            if r.get("confidence", 0) > max_confidence:
                continue

        if capture_id is not None:
            ref = r.get("reference") or {}
            if (ref.get("captureId") or "").lower() != capture_id.lower():
                continue

        result.append(r)
    return result


def paginate_evidence(
    records   : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> tuple[List[Dict[str, Any]], "Pagination"]:  # type: ignore
    """
    Slice an evidence record list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    records   : Full ordered list of evidence record dicts (already filtered/sorted).
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
    total          = len(records)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = records[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_evidence(
    records : List[Dict[str, Any]],
    query   : str,
) -> List[Dict[str, Any]]:
    """
    Return evidence records where any searchable text field contains *query*
    as a case-insensitive substring.

    Searchable fields: evidenceId, evidenceHash, fieldName, fieldValue,
                       assetId, source.sourceType, reference.captureId.
    """
    q = query.lower()
    result = []
    for r in records:
        search_values = [
            r.get("evidenceId") or "",
            r.get("evidenceHash") or "",
            r.get("fieldName") or "",
            r.get("fieldValue") or "",
            r.get("assetId") or "",
        ]
        src = r.get("source") or {}
        search_values.append(src.get("sourceType") or "")
        ref = r.get("reference") or {}
        search_values.append(ref.get("captureId") or "")

        for val in search_values:
            if q in str(val).lower():
                result.append(r)
                break
    return result


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /evidence/search
# ---------------------------------------------------------------------------

@evidence_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search evidence records",
    description    = (
        "Full-text search across evidenceId, evidenceHash, fieldName, fieldValue, "
        "assetId, source.sourceType, and reference.captureId.  Supports sorting, "
        "filtering, and pagination via query parameters."
    ),
)
def search_evidence(
    q             : str,
    sort_by       : Optional[str]  = "created",
    sort_order    : Optional[str]  = "asc",
    page          : Optional[int]  = 1,
    page_size     : Optional[int]  = 20,
    asset_id_filter      : Optional[str]  = None,
    source_type_filter   : Optional[str]  = None,
    field_name_filter    : Optional[str]  = None,
    min_confidence_filter: Optional[int]  = None,
    max_confidence_filter: Optional[int]  = None,
    capture_id_filter    : Optional[str]  = None,
) -> APIResponse:
    """
    GET /api/v2/evidence/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        from api.investigation.evidence_models import EvidenceSearchResponse

        # Validate query
        if not q or not q.strip():
            return exception_to_api_response(
                APIErrorValidation("Query parameter 'q' must not be empty.")
            )

        # Validate sort parameters
        allowed_sort = {"confidence", "sourcetype", "fieldname", "created"}
        errors = []
        if sort_by and sort_by.lower() not in allowed_sort:
            errors.append(f"sortBy must be one of: confidence, sourceType, fieldName, created.")
        if sort_order and sort_order not in ("asc", "desc"):
            errors.append("sortOrder must be 'asc' or 'desc'.")
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errors)
            )

        # Search
        matched = _search_evidence(_all_evidence(), q.strip())

        # Filter
        filtered = filter_evidence(
            matched,
            asset_id       = asset_id_filter,
            source_type    = source_type_filter,
            field_name     = field_name_filter,
            min_confidence = min_confidence_filter,
            max_confidence = max_confidence_filter,
            capture_id     = capture_id_filter,
        )

        # Sort
        sorted_records = sort_evidence(filtered, sort_by or "created", sort_order or "asc")

        # Paginate
        page_slice, pagination = paginate_evidence(
            sorted_records,
            page or 1,
            page_size or 20,
        )

        response_payload = EvidenceSearchResponse(
            evidence   = [_evidence_to_response(r) for r in page_slice],
            total      = pagination.totalItems,
            page       = pagination.page,
            pageSize   = pagination.pageSize,
            totalPages = pagination.totalPages,
            query      = q.strip(),
            sortBy     = sort_by or "created",
            sortOrder  = sort_order or "asc",
        )

        return build_success_response(
            data    = response_payload.model_dump(),
            message = f"{len(page_slice)} evidence record(s) found on page {pagination.page}.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /evidence/bulk/create
# ---------------------------------------------------------------------------

@evidence_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create evidence records",
    description    = "Create multiple evidence records in a single request.",
    status_code    = 201,
)
def bulk_create_evidence(
    body: "BulkCreateEvidenceRequest" = Body(...),  # type: ignore
) -> APIResponse:
    """
    POST /api/v2/evidence/bulk/create

    Validates all items, then creates each record.  Returns a summary of
    succeeded / failed items.  Partial success is allowed — some items may
    succeed while others fail.
    """
    try:
        from api.investigation.evidence_models import (
            BulkCreateEvidenceRequest,
            BulkEvidenceOperationResult,
        )

        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for item in body.evidence:
            try:
                # Parse observedAt if provided
                observed_at: Optional[datetime] = None
                if item.observedAt:
                    try:
                        observed_at = datetime.fromisoformat(
                            item.observedAt.replace("Z", "+00:00")
                        )
                    except ValueError:
                        failed.append({
                            "fieldName": item.fieldName,
                            "fieldValue": item.fieldValue,
                            "reason": "Invalid observedAt format.",
                        })
                        continue

                # Build metadata if any metadata fields were provided
                metadata = None
                has_metadata = any([
                    item.protocol, item.packetInfo, item.rawValue,
                    item.tags, item.extra,
                ])
                if has_metadata:
                    metadata = build_metadata(
                        protocol    = item.protocol,
                        packet_info = item.packetInfo,
                        raw_value   = item.rawValue,
                        tags        = list(item.tags) if item.tags else None,
                        extra       = dict(item.extra) if item.extra else None,
                    )

                # Delegate construction to the evidence engine
                record = build_evidence(
                    field_name    = item.fieldName,
                    field_value   = item.fieldValue,
                    source_type   = item.sourceType,
                    asset_id      = item.assetId,
                    source_id     = item.sourceId,
                    confidence    = item.confidence,
                    packet_number = item.packetNumber,
                    capture_id    = item.captureId,
                    session_id    = item.sessionId,
                    observed_at   = observed_at,
                    metadata      = metadata,
                )

                if record is None:
                    failed.append({
                        "fieldName": item.fieldName,
                        "fieldValue": item.fieldValue,
                        "reason": "fieldValue resolved to empty after normalisation.",
                    })
                    continue

                evidence_id = record.evidenceId

                # Duplicate check
                if evidence_id in _EVIDENCE_STORE:
                    failed.append({
                        "evidenceId": evidence_id,
                        "reason": "Duplicate evidence record (same content hash).",
                    })
                    continue

                # Store
                stored = _record_to_dict(record)
                _EVIDENCE_STORE[evidence_id] = stored
                succeeded.append(evidence_id)

            except Exception as item_exc:
                failed.append({
                    "fieldName": item.fieldName,
                    "fieldValue": item.fieldValue,
                    "reason": str(item_exc),
                })

        result = BulkEvidenceOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.evidence),
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
# PUT /evidence/bulk/update
# ---------------------------------------------------------------------------

@evidence_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update evidence records",
    description    = "Update multiple evidence records in a single request.",
)
def bulk_update_evidence(
    body: "BulkUpdateEvidenceRequest" = Body(...),  # type: ignore
) -> APIResponse:
    """
    PUT /api/v2/evidence/bulk/update

    Validates all items, then updates each record.  Returns a summary of
    succeeded / failed items.  Partial success is allowed.
    """
    try:
        from api.investigation.evidence_models import (
            BulkUpdateEvidenceRequest,
            BulkEvidenceOperationResult,
        )

        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for item in body.items:
            try:
                evidence_id = item.evidenceId.strip()
                record = _EVIDENCE_STORE.get(evidence_id)

                if record is None:
                    failed.append({
                        "evidenceId": evidence_id,
                        "reason": "Evidence record not found.",
                    })
                    continue

                update = item.update

                # Apply updates
                if update.assetId is not None:
                    record["assetId"] = update.assetId

                if update.confidence is not None:
                    record["confidence"] = update.confidence
                    src = record.get("source")
                    if isinstance(src, dict):
                        src["confidence"] = update.confidence

                # Update metadata fields
                meta = dict(record.get("metadata") or {})
                if update.protocol is not None:
                    meta["protocol"] = update.protocol
                if update.packetInfo is not None:
                    meta["packetInfo"] = update.packetInfo
                if update.rawValue is not None:
                    meta["rawValue"] = update.rawValue
                if update.tags is not None:
                    meta["tags"] = list(update.tags)
                if update.extra is not None:
                    existing_extra = dict(meta.get("extra") or {})
                    meta["extra"] = {**existing_extra, **dict(update.extra)}
                record["metadata"] = meta

                _EVIDENCE_STORE[evidence_id] = record
                succeeded.append(evidence_id)

            except Exception as item_exc:
                failed.append({
                    "evidenceId": item.evidenceId,
                    "reason": str(item_exc),
                })

        result = BulkEvidenceOperationResult(
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
# DELETE /evidence/bulk/delete
# ---------------------------------------------------------------------------

@evidence_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete evidence records",
    description    = "Delete multiple evidence records in a single request.",
)
def bulk_delete_evidence(
    body: "BulkDeleteEvidenceRequest" = Body(...),  # type: ignore
) -> APIResponse:
    """
    DELETE /api/v2/evidence/bulk/delete

    Validates all IDs, then deletes each record.  Returns a summary of
    succeeded / failed items.  Partial success is allowed.
    """
    try:
        from api.investigation.evidence_models import (
            BulkDeleteEvidenceRequest,
            BulkEvidenceOperationResult,
        )

        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for evidence_id in body.evidenceIds:
            try:
                eid = evidence_id.strip()
                if eid not in _EVIDENCE_STORE:
                    failed.append({
                        "evidenceId": eid,
                        "reason": "Evidence record not found.",
                    })
                    continue

                del _EVIDENCE_STORE[eid]
                succeeded.append(eid)

            except Exception as item_exc:
                failed.append({
                    "evidenceId": evidence_id,
                    "reason": str(item_exc),
                })

        result = BulkEvidenceOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.evidenceIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
