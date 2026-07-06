"""
Finding Router — Phase A4.7.5 (Part A)
=======================================
REST interface for the Finding Engine.

Prefix  : /api/v2/findings
Tag     : Findings

Endpoints (Part A)
------------------
GET    /api/v2/findings              — list all findings
GET    /api/v2/findings/statistics   — aggregate statistics
GET    /api/v2/findings/{findingId}  — get a single finding by ID
POST   /api/v2/findings              — create a finding
PUT    /api/v2/findings/{findingId}  — update a finding
DELETE /api/v2/findings/{findingId}  — delete a finding

Design rules
------------
- No business logic here.  All finding construction delegated to
  finding_service.py builders.
- Uses only existing finding_service builders / helpers:
    build_finding(), update_finding(), FindingSeverity, FindingStatus,
    FindingCategory.
- No database.  In-memory placeholder collection (_FINDING_STORE).
- Returns only build_success_response() or exception_to_api_response().
- Request model validation at the API layer only; service validates
  business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.
- No search, no sorting, no filtering, no pagination, no bulk operations.

In-memory store
---------------
_FINDING_STORE is a plain dict keyed by findingId.  It is module-level and
survives for the lifetime of the process.  It will be replaced by a
proper repository in a future phase.  Tests can reset it via _reset_store().

Statistics endpoint
-------------------
GET /statistics exposes:
  totalFindings     — total finding count in _FINDING_STORE
  severityCounts    — { severity.value → count }
  statusCounts      — { status.value → count }
  categoryCounts    — { category.value → count }
  averageConfidence — mean confidence across all findings (0.0 if empty)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.investigation.finding_models import (
    BulkCreateFindingsRequest,
    BulkDeleteFindingsRequest,
    BulkOperationResult,
    BulkUpdateFindingsRequest,
    CreateFindingRequest,
    FindingFilterRequest,
    FindingListResponse,
    FindingResponse,
    FindingSearchRequest,
    FindingStatisticsResponse,
    UpdateFindingRequest,
)
from api.models import APIResponse
from api.responses import build_success_response
from api.utils import exception_to_api_response
from services.finding_service import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    build_finding,
    update_finding,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

finding_router: APIRouter = APIRouter(
    prefix = "/findings",
    tags   = ["Findings"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder store
# ---------------------------------------------------------------------------
# Dict[findingId -> finding dict]  — module-level; replaced by a repository later.
_FINDING_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store.  Used by tests only."""
    _FINDING_STORE.clear()


def _all_findings() -> List[Dict[str, Any]]:
    """Return all findings as a deterministically-ordered list (by findingId ASC)."""
    return sorted(_FINDING_STORE.values(), key=lambda f: f.get("findingId", ""))


# ---------------------------------------------------------------------------
# Validation: enum conversion
# ---------------------------------------------------------------------------

def _validate_severity(severity_str: Optional[str]) -> Optional[FindingSeverity]:
    """Convert a raw string to a FindingSeverity enum value. Returns None if invalid."""
    if not severity_str:
        return None
    try:
        return FindingSeverity(severity_str.strip().upper())
    except (ValueError, AttributeError):
        return None


def _validate_status(status_str: Optional[str]) -> Optional[FindingStatus]:
    """Convert a raw string to a FindingStatus enum value. Returns None if invalid."""
    if not status_str:
        return None
    try:
        return FindingStatus(status_str.strip().upper())
    except (ValueError, AttributeError):
        return None


def _validate_category(category_str: Optional[str]) -> Optional[FindingCategory]:
    """Convert a raw string to a FindingCategory enum value. Returns None if invalid."""
    if not category_str:
        return None
    try:
        return FindingCategory(category_str.strip().upper())
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _finding_to_response(finding: Dict[str, Any]) -> FindingResponse:
    """Convert a raw finding dict to a FindingResponse model."""
    from api.investigation.finding_models import FindingExplanationResponse

    explanation_raw = finding.get("explanation") or {}
    explanation_resp = None
    if explanation_raw:
        explanation_resp = FindingExplanationResponse(
            reason                = explanation_raw.get("reason", ""),
            evidenceSummary       = explanation_raw.get("evidenceSummary", ""),
            affectedAssets        = list(explanation_raw.get("affectedAssets") or []),
            affectedRelationships = list(explanation_raw.get("affectedRelationships") or []),
            recommendedAction     = explanation_raw.get("recommendedAction", ""),
        )

    return FindingResponse(
        findingId                = finding.get("findingId"),
        findingKey               = finding.get("findingKey"),
        projectId                = finding.get("projectId"),
        investigationId          = finding.get("investigationId"),
        title                    = finding.get("title"),
        description              = finding.get("description"),
        category                 = finding.get("category"),
        severity                 = finding.get("severity"),
        status                   = finding.get("status"),
        confidence               = finding.get("confidence"),
        riskScore                = finding.get("riskScore"),
        assetIds                 = list(finding.get("assetIds") or []),
        relationshipIds          = list(finding.get("relationshipIds") or []),
        evidenceIds              = list(finding.get("evidenceIds") or []),
        timelineEventIds         = list(finding.get("timelineEventIds") or []),
        graphNodeIds             = list(finding.get("graphNodeIds") or []),
        mitreTechniqueIds        = list(finding.get("mitreTechniqueIds") or []),
        graphFingerprint         = finding.get("graphFingerprint"),
        timelineFingerprint      = finding.get("timelineFingerprint"),
        investigationFingerprint = finding.get("investigationFingerprint"),
        findingFingerprint       = finding.get("findingFingerprint"),
        explanation              = explanation_resp,
        tags                     = list(finding.get("tags") or []),
        metadata                 = finding.get("metadata") or {},
        createdBy                = finding.get("createdBy"),
        createdAt                = finding.get("createdAt"),
        updatedAt                = finding.get("updatedAt"),
        closedAt                 = finding.get("closedAt"),
        engineVersion            = finding.get("engineVersion"),
        auditTrail               = list(finding.get("auditTrail") or []),
    )


def _finding_record_to_dict(finding: Finding) -> Dict[str, Any]:
    """
    Convert a Finding (frozen dataclass from finding_service) to a mutable
    plain dict suitable for storage in _FINDING_STORE.

    Enum values are serialized as their string values so they are JSON-safe.
    """
    d: Dict[str, Any] = {
        "findingId"                : finding.findingId,
        "findingKey"               : finding.findingKey,
        "projectId"                : finding.projectId,
        "investigationId"          : finding.investigationId,
        "title"                    : finding.title,
        "description"              : finding.description,
        "category"                 : finding.category.value,
        "severity"                 : finding.severity.value,
        "status"                   : finding.status.value,
        "confidence"               : finding.confidence,
        "riskScore"                : finding.riskScore,
        "assetIds"                 : list(finding.assetIds),
        "relationshipIds"          : list(finding.relationshipIds),
        "evidenceIds"              : list(finding.evidenceIds),
        "timelineEventIds"         : list(finding.timelineEventIds),
        "graphNodeIds"             : list(finding.graphNodeIds),
        "mitreTechniqueIds"        : list(finding.mitreTechniqueIds),
        "graphFingerprint"         : finding.graphFingerprint,
        "timelineFingerprint"      : finding.timelineFingerprint,
        "investigationFingerprint" : finding.investigationFingerprint,
        "findingFingerprint"       : finding.findingFingerprint,
        "explanation"              : {
            "reason"                : finding.explanation.reason,
            "evidenceSummary"       : finding.explanation.evidenceSummary,
            "affectedAssets"        : list(finding.explanation.affectedAssets),
            "affectedRelationships" : list(finding.explanation.affectedRelationships),
            "recommendedAction"     : finding.explanation.recommendedAction,
        },
        "tags"                     : list(finding.tags),
        "metadata"                 : dict(finding.metadata),
        "createdBy"                : finding.createdBy,
        "createdAt"                : finding.createdAt,
        "updatedAt"                : finding.updatedAt,
        "closedAt"                 : finding.closedAt,
        "engineVersion"            : finding.engineVersion,
        "auditTrail"               : list(finding.auditTrail),
    }
    return d


def _compute_statistics(findings: List[Dict[str, Any]]) -> FindingStatisticsResponse:
    """
    Compute aggregate statistics over the in-memory finding store.

    Part B: Extended to include averageRiskScore.

    Parameters
    ----------
    findings : List of raw finding dicts from _FINDING_STORE.

    Returns
    -------
    FindingStatisticsResponse (frozen / immutable)
    """
    total = len(findings)

    severity_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    confidence_sum = 0.0
    risk_sum = 0.0

    for f in findings:
        sev = f.get("severity") or "MEDIUM"
        st  = f.get("status") or "OPEN"
        cat = f.get("category") or "OTHER"

        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        status_counts[st]    = status_counts.get(st, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1

        confidence_sum += f.get("confidence", 0.0)
        risk_sum       += f.get("riskScore", 0.0)

    average_conf = round(confidence_sum / total, 4) if total > 0 else 0.0
    average_risk = round(risk_sum / total, 4)       if total > 0 else 0.0

    return FindingStatisticsResponse(
        totalFindings     = total,
        severityCounts    = dict(sorted(severity_counts.items())),
        statusCounts      = dict(sorted(status_counts.items())),
        categoryCounts    = dict(sorted(category_counts.items())),
        averageConfidence = average_conf,
        averageRiskScore  = average_risk,
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /findings
# ---------------------------------------------------------------------------

@finding_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List findings",
    description         = (
        "Return all findings in the in-memory store."
    ),
)
def list_findings() -> APIResponse:
    """
    GET /api/v2/findings

    Returns all findings stored in the in-memory store.  No pagination in Part A.
    """
    try:
        findings = _all_findings()
        payload = FindingListResponse(
            findings = [_finding_to_response(f) for f in findings],
            total    = len(findings),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(findings)} finding(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /findings/statistics
# ---------------------------------------------------------------------------

@finding_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Finding statistics",
    description         = (
        "Return aggregate statistics over all findings in the in-memory store.  "
        "Exposes totalFindings, severityCounts, statusCounts, categoryCounts, "
        "and averageConfidence."
    ),
)
def get_finding_statistics() -> APIResponse:
    """
    GET /api/v2/findings/statistics

    Returns FindingStatisticsResponse.
    """
    try:
        stats = _compute_statistics(_all_findings())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Finding statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /findings/{findingId}
# ---------------------------------------------------------------------------

@finding_router.get(
    "/{findingId}",
    response_model      = APIResponse,
    summary             = "Get finding by ID",
    description         = "Return a single finding by its findingId.",
)
def get_finding(findingId: str) -> APIResponse:
    """
    GET /api/v2/findings/{findingId}

    Looks up by findingId.  Returns 404 if not found.
    """
    try:
        finding = _FINDING_STORE.get(findingId)
        if finding is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Finding '{findingId}' not found.")
            )
        return build_success_response(
            data    = _finding_to_response(finding).model_dump(),
            message = "Finding retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /findings
# ---------------------------------------------------------------------------

@finding_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create finding",
    description         = (
        "Create a new finding in the in-memory store.  "
        "The findingId is derived deterministically from "
        "(projectId, title, category, investigationId) via SHA-256 + UUIDv5."
    ),
    status_code         = 201,
)
def create_finding(
    body: CreateFindingRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/findings

    Validates the request, converts enums, delegates finding construction to
    build_finding() from finding_service.py, checks for a duplicate findingId,
    then stores the result.

    Returns 409 if a finding with the same deterministic findingId already exists.
    Returns 422 if request validation fails or category/severity/status are invalid.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid finding request.", details=errors)
            )

        # Validate and convert enums
        category_enum = _validate_category(body.category)
        if category_enum is None:
            return exception_to_api_response(
                APIErrorValidation(
                    "Invalid category value.",
                    details=[f"category '{body.category}' is not a recognised FindingCategory value."],
                )
            )

        severity_enum = _validate_severity(body.severity)
        if severity_enum is None:
            return exception_to_api_response(
                APIErrorValidation(
                    "Invalid severity value.",
                    details=[f"severity '{body.severity}' is not a recognised FindingSeverity value."],
                )
            )

        # Delegate construction to the finding engine
        finding = build_finding(
            project_id                = body.projectId,
            investigation_id          = body.investigationId,
            title                     = body.title,
            created_by                = body.createdBy,
            created_at                = body.createdAt,
            category                  = category_enum,
            severity                  = severity_enum,
            description               = body.description or "",
            confidence                = body.confidence or 0.0,
            risk_score                = body.riskScore or 0.0,
            asset_ids                 = body.assetIds,
            relationship_ids          = body.relationshipIds,
            evidence_ids              = body.evidenceIds,
            timeline_event_ids        = body.timelineEventIds,
            graph_node_ids            = body.graphNodeIds,
            mitre_technique_ids       = body.mitreTechniqueIds,
            graph_fingerprint         = body.graphFingerprint or "",
            timeline_fingerprint      = body.timelineFingerprint or "",
            investigation_fingerprint = body.investigationFingerprint or "",
            reason                    = body.reason or "",
            evidence_summary          = body.evidenceSummary or "",
            affected_assets           = body.affectedAssets,
            affected_relationships    = body.affectedRelationships,
            recommended_action        = body.recommendedAction or "",
            tags                      = body.tags,
            metadata                  = body.metadata,
        )

        finding_id = finding.findingId

        # Duplicate check — same deterministic key means same logical entity
        if finding_id in _FINDING_STORE:
            return exception_to_api_response(
                APIErrorConflict(
                    f"Finding '{finding_id}' already exists "
                    f"(duplicate detected via deterministic key for "
                    f"projectId='{body.projectId}', title='{body.title}')."
                )
            )

        # Store as a plain mutable dict
        stored = _finding_record_to_dict(finding)
        _FINDING_STORE[finding_id] = stored

        return build_success_response(
            data    = _finding_to_response(stored).model_dump(),
            message = "Finding created.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /findings/{findingId}
# ---------------------------------------------------------------------------

@finding_router.put(
    "/{findingId}",
    response_model      = APIResponse,
    summary             = "Update finding",
    description         = (
        "Update mutable fields of an existing finding.  "
        "Immutable fields (findingId, findingKey, projectId, investigationId, "
        "createdBy, createdAt) cannot be changed through this endpoint."
    ),
)
def update_finding_endpoint(
    findingId: str,
    body     : UpdateFindingRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/findings/{findingId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.

    Immutable fields: findingId, findingKey, projectId, investigationId,
                      createdBy, createdAt, engineVersion.

    Returns 404 if the finding does not exist.
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

        stored_finding = _FINDING_STORE.get(findingId)
        if stored_finding is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Finding '{findingId}' not found.")
            )

        # Reconstruct Finding dataclass from stored dict
        from datetime import datetime

        # Convert enum string values back to enums
        cat_val = stored_finding.get("category", "OTHER")
        cat_enum = FindingCategory(cat_val) if cat_val else FindingCategory.OTHER
        sev_val = stored_finding.get("severity", "MEDIUM")
        sev_enum = FindingSeverity(sev_val) if sev_val else FindingSeverity.MEDIUM
        st_val = stored_finding.get("status", "OPEN")
        st_enum = FindingStatus(st_val) if st_val else FindingStatus.OPEN

        # Reconstruct explanation
        from services.finding_service import FindingExplanation
        exp_dict = stored_finding.get("explanation") or {}
        explanation_obj = FindingExplanation(
            reason                = exp_dict.get("reason", ""),
            evidenceSummary       = exp_dict.get("evidenceSummary", ""),
            affectedAssets        = tuple(exp_dict.get("affectedAssets") or []),
            affectedRelationships = tuple(exp_dict.get("affectedRelationships") or []),
            recommendedAction     = exp_dict.get("recommendedAction", ""),
        )

        finding_obj = Finding(
            findingId                = stored_finding["findingId"],
            findingKey               = stored_finding["findingKey"],
            projectId                = stored_finding["projectId"],
            investigationId          = stored_finding["investigationId"],
            title                    = stored_finding["title"],
            description              = stored_finding["description"],
            category                 = cat_enum,
            severity                 = sev_enum,
            status                   = st_enum,
            confidence               = stored_finding["confidence"],
            riskScore                = stored_finding["riskScore"],
            assetIds                 = tuple(stored_finding["assetIds"]),
            relationshipIds          = tuple(stored_finding["relationshipIds"]),
            evidenceIds              = tuple(stored_finding["evidenceIds"]),
            timelineEventIds         = tuple(stored_finding["timelineEventIds"]),
            graphNodeIds             = tuple(stored_finding["graphNodeIds"]),
            mitreTechniqueIds        = tuple(stored_finding["mitreTechniqueIds"]),
            graphFingerprint         = stored_finding["graphFingerprint"],
            timelineFingerprint      = stored_finding["timelineFingerprint"],
            investigationFingerprint = stored_finding["investigationFingerprint"],
            findingFingerprint       = stored_finding["findingFingerprint"],
            explanation              = explanation_obj,
            tags                     = tuple(stored_finding["tags"]),
            metadata                 = stored_finding["metadata"],
            createdBy                = stored_finding["createdBy"],
            createdAt                = stored_finding["createdAt"],
            updatedAt                = stored_finding["updatedAt"],
            closedAt                 = stored_finding.get("closedAt"),
            engineVersion            = stored_finding["engineVersion"],
            auditTrail               = tuple(stored_finding["auditTrail"]),
        )

        # Validate and convert new enum values
        new_category = None
        if body.category is not None:
            new_category = _validate_category(body.category)
            if new_category is None:
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid category value.",
                        details=[f"category '{body.category}' is not a recognised FindingCategory value."],
                    )
                )

        new_severity = None
        if body.severity is not None:
            new_severity = _validate_severity(body.severity)
            if new_severity is None:
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid severity value.",
                        details=[f"severity '{body.severity}' is not a recognised FindingSeverity value."],
                    )
                )

        new_status = None
        if body.status is not None:
            new_status = _validate_status(body.status)
            if new_status is None:
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid status value.",
                        details=[f"status '{body.status}' is not a recognised FindingStatus value."],
                    )
                )

        # Use current timestamp for updatedAt
        from datetime import datetime, timezone
        updated_at = datetime.now(timezone.utc).isoformat()

        # Delegate update to finding_service.update_finding()
        updated_finding = update_finding(
            finding                   = finding_obj,
            updated_at                = updated_at,
            title                     = body.title,
            description               = body.description,
            category                  = new_category,
            severity                  = new_severity,
            status                    = new_status,
            confidence                = body.confidence,
            risk_score                = body.riskScore,
            asset_ids                 = body.assetIds,
            relationship_ids          = body.relationshipIds,
            evidence_ids              = body.evidenceIds,
            timeline_event_ids        = body.timelineEventIds,
            graph_node_ids            = body.graphNodeIds,
            mitre_technique_ids       = body.mitreTechniqueIds,
            graph_fingerprint         = body.graphFingerprint,
            timeline_fingerprint      = body.timelineFingerprint,
            investigation_fingerprint = body.investigationFingerprint,
            reason                    = body.reason,
            evidence_summary          = body.evidenceSummary,
            affected_assets           = body.affectedAssets,
            affected_relationships    = body.affectedRelationships,
            recommended_action        = body.recommendedAction,
            tags                      = body.tags,
            metadata                  = body.metadata,
        )

        # Store updated finding
        updated_dict = _finding_record_to_dict(updated_finding)
        _FINDING_STORE[findingId] = updated_dict

        return build_success_response(
            data    = _finding_to_response(updated_dict).model_dump(),
            message = "Finding updated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /findings/{findingId}
# ---------------------------------------------------------------------------

@finding_router.delete(
    "/{findingId}",
    response_model      = APIResponse,
    summary             = "Delete finding",
    description         = "Remove a finding from the in-memory store.",
)
def delete_finding(findingId: str) -> APIResponse:
    """
    DELETE /api/v2/findings/{findingId}

    Returns 404 if the finding does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if findingId not in _FINDING_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Finding '{findingId}' not found.")
            )

        del _FINDING_STORE[findingId]

        return build_success_response(
            data    = None,
            message = f"Finding '{findingId}' deleted.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

# Severity ordering for sort (higher number = higher priority)
_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL" : 5,
    "HIGH"     : 4,
    "MEDIUM"   : 3,
    "LOW"      : 2,
    "INFO"     : 1,
}

# Status ordering (higher = more urgent)
_STATUS_ORDER: Dict[str, int] = {
    "CONFIRMED"      : 6,
    "OPEN"           : 5,
    "RESOLVED"       : 4,
    "SUPPRESSED"     : 3,
    "FALSE_POSITIVE" : 2,
    "CLOSED"         : 1,
}

# Canonical sort-key map: user-supplied → dict key
_SORT_KEY_MAP: Dict[str, str] = {
    "severity"   : "severity",
    "status"     : "status",
    "confidence" : "confidence",
    "riskscore"  : "riskScore",
    "createdat"  : "createdAt",
    "title"      : "title",
}


def find_finding(
    findings : List[Dict[str, Any]],
    field    : str,
    value    : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first finding whose field matches value (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.
    Returns None if not found or list is empty.
    """
    target = value.lower()
    for f in findings:
        v = f.get(field)
        if v is not None and str(v).lower() == target:
            return f
    return None


def sort_findings_api(
    findings   : List[Dict[str, Any]],
    sort_by    : str  = "severity",
    sort_order : str  = "desc",
) -> List[Dict[str, Any]]:
    """
    Return a new sorted list of finding dicts.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values: severity, status, confidence, riskScore,
    createdAt, title.  Unrecognised values fall back to severity.
    sort_order: "asc" or "desc" (default "desc").
    """
    field = _SORT_KEY_MAP.get(sort_by.lower(), "severity")
    reverse = sort_order.lower() != "asc"

    def sort_key(f: Dict[str, Any]):
        if field == "severity":
            v = _SEVERITY_ORDER.get(f.get("severity") or "", 0)
        elif field == "status":
            v = _STATUS_ORDER.get(f.get("status") or "", 0)
        else:
            v = f.get(field)
        if v is None:
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        return (0, str(v).lower())

    return sorted(findings, key=sort_key, reverse=reverse)


def filter_findings_api(
    findings       : List[Dict[str, Any]],
    severity       : Optional[str]   = None,
    status         : Optional[str]   = None,
    category       : Optional[str]   = None,
    min_confidence : Optional[float] = None,
    max_confidence : Optional[float] = None,
    min_risk_score : Optional[float] = None,
    max_risk_score : Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Filter finding dicts by severity, status, category, confidence and
    riskScore ranges.  All predicates are optional.

    Pure deterministic helper — the input list is never mutated.
    """
    result = []
    for f in findings:
        if severity is not None:
            if (f.get("severity") or "").lower() != severity.lower():
                continue
        if status is not None:
            if (f.get("status") or "").lower() != status.lower():
                continue
        if category is not None:
            if (f.get("category") or "").lower() != category.lower():
                continue
        if min_confidence is not None:
            if f.get("confidence", 0.0) < min_confidence:
                continue
        if max_confidence is not None:
            if f.get("confidence", 0.0) > max_confidence:
                continue
        if min_risk_score is not None:
            if f.get("riskScore", 0.0) < min_risk_score:
                continue
        if max_risk_score is not None:
            if f.get("riskScore", 0.0) > max_risk_score:
                continue
        result.append(f)
    return result


def paginate_findings(
    findings  : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> tuple:
    """
    Slice a finding list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.
    Returns (page_slice, Pagination).
    """
    import math
    from api.models import Pagination

    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(findings)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = findings[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_findings(
    findings : List[Dict[str, Any]],
    query    : str,
) -> List[Dict[str, Any]]:
    """
    Return findings where any searchable text field contains query as a
    case-insensitive substring.

    Searchable fields: findingId, findingKey, title, description, category,
                       severity, status, projectId, investigationId.
    """
    q = query.lower()
    search_fields = (
        "findingId", "findingKey", "title", "description",
        "category", "severity", "status", "projectId", "investigationId",
    )
    result = []
    for f in findings:
        for fld in search_fields:
            v = f.get(fld) or ""
            if q in str(v).lower():
                result.append(f)
                break
    return result


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /findings/search
# ---------------------------------------------------------------------------

@finding_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search findings",
    description    = (
        "Full-text search across findingId, findingKey, title, description, "
        "category, severity, status, projectId, and investigationId.  "
        "Supports sorting, filtering, and pagination via query parameters."
    ),
)
def search_findings(
    q                    : str,
    sort_by              : Optional[str]   = "severity",
    sort_order           : Optional[str]   = "desc",
    page                 : Optional[int]   = 1,
    page_size            : Optional[int]   = 20,
    severity_filter      : Optional[str]   = None,
    status_filter        : Optional[str]   = None,
    category_filter      : Optional[str]   = None,
    min_confidence_filter: Optional[float] = None,
    max_confidence_filter: Optional[float] = None,
    min_risk_filter      : Optional[float] = None,
    max_risk_filter      : Optional[float] = None,
) -> APIResponse:
    """
    GET /api/v2/findings/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        if not q or not q.strip():
            return exception_to_api_response(
                APIErrorValidation("Query parameter 'q' must not be empty.")
            )

        allowed_sort = {"severity", "status", "confidence", "riskscore", "createdat", "title"}
        errs = []
        if sort_by and sort_by.lower() not in allowed_sort:
            errs.append(
                "sortBy must be one of: severity, status, confidence, riskScore, createdAt, title."
            )
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        matched   = _search_findings(_all_findings(), q.strip())
        filtered  = filter_findings_api(
            matched,
            severity       = severity_filter,
            status         = status_filter,
            category       = category_filter,
            min_confidence = min_confidence_filter,
            max_confidence = max_confidence_filter,
            min_risk_score = min_risk_filter,
            max_risk_score = max_risk_filter,
        )
        sorted_f  = sort_findings_api(filtered, sort_by or "severity", sort_order or "desc")
        page_slice, pagination = paginate_findings(sorted_f, page or 1, page_size or 20)

        payload = {
            "findings"   : [_finding_to_response(f).model_dump() for f in page_slice],
            "total"      : pagination.totalItems,
            "page"       : pagination.page,
            "pageSize"   : pagination.pageSize,
            "totalPages" : pagination.totalPages,
            "query"      : q.strip(),
            "sortBy"     : sort_by or "severity",
            "sortOrder"  : sort_order or "desc",
        }
        return build_success_response(
            data     = payload,
            message  = f"{pagination.totalItems} finding(s) matched search.",
            metadata = {"pagination": pagination.model_dump()},
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /findings/bulk/create
# ---------------------------------------------------------------------------

@finding_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create findings",
    description    = "Create multiple findings in a single request.",
    status_code    = 201,
)
def bulk_create_findings(
    body: BulkCreateFindingsRequest = Body(...),
) -> APIResponse:
    """POST /api/v2/findings/bulk/create"""
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=errs)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, item in enumerate(body.findings):
            try:
                cat_enum = _validate_category(item.category)
                if cat_enum is None:
                    failed.append({"index": str(idx), "reason": f"Invalid category '{item.category}'."})
                    continue
                sev_enum = _validate_severity(item.severity)
                if sev_enum is None:
                    failed.append({"index": str(idx), "reason": f"Invalid severity '{item.severity}'."})
                    continue

                finding = build_finding(
                    project_id                = item.projectId,
                    investigation_id          = item.investigationId,
                    title                     = item.title,
                    created_by                = item.createdBy,
                    created_at                = item.createdAt,
                    category                  = cat_enum,
                    severity                  = sev_enum,
                    description               = item.description or "",
                    confidence                = item.confidence or 0.0,
                    risk_score                = item.riskScore or 0.0,
                    asset_ids                 = item.assetIds,
                    relationship_ids          = item.relationshipIds,
                    evidence_ids              = item.evidenceIds,
                    timeline_event_ids        = item.timelineEventIds,
                    graph_node_ids            = item.graphNodeIds,
                    mitre_technique_ids       = item.mitreTechniqueIds,
                    graph_fingerprint         = item.graphFingerprint or "",
                    timeline_fingerprint      = item.timelineFingerprint or "",
                    investigation_fingerprint = item.investigationFingerprint or "",
                    reason                    = item.reason or "",
                    evidence_summary          = item.evidenceSummary or "",
                    affected_assets           = item.affectedAssets,
                    affected_relationships    = item.affectedRelationships,
                    recommended_action        = item.recommendedAction or "",
                    tags                      = item.tags,
                    metadata                  = item.metadata,
                )
                fid = finding.findingId
                if fid in _FINDING_STORE:
                    failed.append({"index": str(idx), "findingId": fid, "reason": "Finding already exists."})
                    continue
                _FINDING_STORE[fid] = _finding_record_to_dict(finding)
                succeeded.append(fid)
            except Exception as e:
                failed.append({"index": str(idx), "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded, failed=failed, total=len(body.findings),
            successCount=len(succeeded), failCount=len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /findings/bulk/update
# ---------------------------------------------------------------------------

@finding_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update findings",
    description    = "Update multiple findings in a single request.",
)
def bulk_update_findings(
    body: BulkUpdateFindingsRequest = Body(...),
) -> APIResponse:
    """PUT /api/v2/findings/bulk/update"""
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=errs)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from datetime import datetime, timezone
        from services.finding_service import FindingExplanation

        for idx, item in enumerate(body.items):
            try:
                fid    = item.findingId.strip()
                stored = _FINDING_STORE.get(fid)
                if stored is None:
                    failed.append({"index": str(idx), "findingId": fid, "reason": "Finding not found."})
                    continue

                upd = item.update
                new_category = None
                if upd.category is not None:
                    new_category = _validate_category(upd.category)
                    if new_category is None:
                        failed.append({"index": str(idx), "findingId": fid, "reason": f"Invalid category '{upd.category}'."})
                        continue

                new_severity = None
                if upd.severity is not None:
                    new_severity = _validate_severity(upd.severity)
                    if new_severity is None:
                        failed.append({"index": str(idx), "findingId": fid, "reason": f"Invalid severity '{upd.severity}'."})
                        continue

                new_status = None
                if upd.status is not None:
                    new_status = _validate_status(upd.status)
                    if new_status is None:
                        failed.append({"index": str(idx), "findingId": fid, "reason": f"Invalid status '{upd.status}'."})
                        continue

                exp_dict = stored.get("explanation") or {}
                exp_obj  = FindingExplanation(
                    reason                = exp_dict.get("reason", ""),
                    evidenceSummary       = exp_dict.get("evidenceSummary", ""),
                    affectedAssets        = tuple(exp_dict.get("affectedAssets") or []),
                    affectedRelationships = tuple(exp_dict.get("affectedRelationships") or []),
                    recommendedAction     = exp_dict.get("recommendedAction", ""),
                )
                finding_obj = Finding(
                    findingId=stored["findingId"], findingKey=stored["findingKey"],
                    projectId=stored["projectId"], investigationId=stored["investigationId"],
                    title=stored["title"], description=stored["description"],
                    category=FindingCategory(stored["category"]),
                    severity=FindingSeverity(stored["severity"]),
                    status=FindingStatus(stored["status"]),
                    confidence=stored["confidence"], riskScore=stored["riskScore"],
                    assetIds=tuple(stored["assetIds"]),
                    relationshipIds=tuple(stored["relationshipIds"]),
                    evidenceIds=tuple(stored["evidenceIds"]),
                    timelineEventIds=tuple(stored["timelineEventIds"]),
                    graphNodeIds=tuple(stored["graphNodeIds"]),
                    mitreTechniqueIds=tuple(stored["mitreTechniqueIds"]),
                    graphFingerprint=stored["graphFingerprint"],
                    timelineFingerprint=stored["timelineFingerprint"],
                    investigationFingerprint=stored["investigationFingerprint"],
                    findingFingerprint=stored["findingFingerprint"],
                    explanation=exp_obj, tags=tuple(stored["tags"]),
                    metadata=stored["metadata"], createdBy=stored["createdBy"],
                    createdAt=stored["createdAt"], updatedAt=stored["updatedAt"],
                    closedAt=stored.get("closedAt"), engineVersion=stored["engineVersion"],
                    auditTrail=tuple(stored["auditTrail"]),
                )
                updated_at = datetime.now(timezone.utc).isoformat()
                updated    = update_finding(
                    finding=finding_obj, updated_at=updated_at,
                    title=upd.title, description=upd.description,
                    category=new_category, severity=new_severity, status=new_status,
                    confidence=upd.confidence, risk_score=upd.riskScore,
                    asset_ids=upd.assetIds, relationship_ids=upd.relationshipIds,
                    evidence_ids=upd.evidenceIds, timeline_event_ids=upd.timelineEventIds,
                    graph_node_ids=upd.graphNodeIds, mitre_technique_ids=upd.mitreTechniqueIds,
                    graph_fingerprint=upd.graphFingerprint,
                    timeline_fingerprint=upd.timelineFingerprint,
                    investigation_fingerprint=upd.investigationFingerprint,
                    reason=upd.reason, evidence_summary=upd.evidenceSummary,
                    affected_assets=upd.affectedAssets,
                    affected_relationships=upd.affectedRelationships,
                    recommended_action=upd.recommendedAction,
                    tags=upd.tags, metadata=upd.metadata,
                )
                _FINDING_STORE[fid] = _finding_record_to_dict(updated)
                succeeded.append(fid)
            except Exception as e:
                failed.append({"index": str(idx), "findingId": item.findingId, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded, failed=failed, total=len(body.items),
            successCount=len(succeeded), failCount=len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk update completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /findings/bulk/delete
# ---------------------------------------------------------------------------

@finding_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete findings",
    description    = "Delete multiple findings in a single request.",
)
def bulk_delete_findings(
    body: BulkDeleteFindingsRequest = Body(...),
) -> APIResponse:
    """DELETE /api/v2/findings/bulk/delete"""
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=errs)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, fid in enumerate(body.findingIds):
            try:
                nid = fid.strip()
                if nid not in _FINDING_STORE:
                    failed.append({"index": str(idx), "findingId": nid, "reason": "Finding not found."})
                    continue
                del _FINDING_STORE[nid]
                succeeded.append(nid)
            except Exception as e:
                failed.append({"index": str(idx), "findingId": fid, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded, failed=failed, total=len(body.findingIds),
            successCount=len(succeeded), failCount=len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
