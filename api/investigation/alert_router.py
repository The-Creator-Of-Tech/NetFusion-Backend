"""
Alert Router — Phase A4.7.6 (Part A)
======================================
REST interface for the Alert Engine.

Prefix  : /api/v2/alerts
Tag     : Alerts

Endpoints (Part A)
------------------
GET    /api/v2/alerts              — list all alerts
GET    /api/v2/alerts/statistics   — aggregate statistics
GET    /api/v2/alerts/{alertId}    — get a single alert by ID
POST   /api/v2/alerts              — create an alert
PUT    /api/v2/alerts/{alertId}    — update an alert
DELETE /api/v2/alerts/{alertId}    — delete an alert

Design rules
------------
- No business logic here.  All alert construction delegated to
  alert_service.py builders only: build_alert(), update_alert().
- No database.  In-memory placeholder collection (_ALERT_STORE).
- Returns only build_success_response() or exception_to_api_response().
- Request model validation at the API layer only; service validates
  business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.
- No search, no sorting, no filtering, no pagination, no bulk operations.

In-memory store
---------------
_ALERT_STORE is a plain dict keyed by alertId.  It is module-level and
survives for the lifetime of the process.  It will be replaced by a
proper repository in a future phase.  Tests can reset it via _reset_store().

Statistics endpoint
-------------------
GET /statistics exposes:
  totalAlerts       — total alert count in _ALERT_STORE
  severityCounts    — { severity.value → count }
  statusCounts      — { status.value → count }
  typeCounts        — { source.value → count }
  averageConfidence — mean confidence across all alerts (0.0 if empty)
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
from api.investigation.alert_models import (
    AlertListResponse,
    AlertResponse,
    AlertStatisticsResponse,
    AlertExplanationResponse,
    AlertCorrelationResponse,
    BulkCreateAlertsRequest,
    BulkDeleteAlertsRequest,
    BulkOperationResult,
    BulkUpdateAlertsRequest,
    CreateAlertRequest,
    AlertFilterRequest,
    AlertSearchRequest,
    UpdateAlertRequest,
)
from api.models import APIResponse
from api.responses import build_success_response
from api.utils import exception_to_api_response
from services.alert_service import (
    Alert,
    AlertSource,
    AlertSeverity,
    AlertStatus,
    build_alert,
    update_alert,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

alert_router: APIRouter = APIRouter(
    prefix = "/alerts",
    tags   = ["Alerts"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder store
# ---------------------------------------------------------------------------
# Dict[alertId -> alert dict]  — module-level; replaced by a repository later.
_ALERT_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store.  Used by tests only."""
    _ALERT_STORE.clear()


def _all_alerts() -> List[Dict[str, Any]]:
    """Return all alerts as a deterministically-ordered list (by alertId ASC)."""
    return sorted(_ALERT_STORE.values(), key=lambda a: a.get("alertId", ""))


# ---------------------------------------------------------------------------
# Validation: enum conversion
# ---------------------------------------------------------------------------

def _validate_source(source_str: Optional[str]) -> Optional[AlertSource]:
    """Convert a raw string to an AlertSource enum value. Returns None if invalid."""
    if not source_str:
        return None
    try:
        return AlertSource(source_str.strip().upper())
    except (ValueError, AttributeError):
        return None


def _validate_severity(severity_str: Optional[str]) -> Optional[AlertSeverity]:
    """Convert a raw string to an AlertSeverity enum value. Returns None if invalid."""
    if not severity_str:
        return None
    try:
        return AlertSeverity(severity_str.strip().upper())
    except (ValueError, AttributeError):
        return None


def _validate_status(status_str: Optional[str]) -> Optional[AlertStatus]:
    """Convert a raw string to an AlertStatus enum value. Returns None if invalid."""
    if not status_str:
        return None
    try:
        return AlertStatus(status_str.strip().upper())
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _alert_to_response(alert: Dict[str, Any]) -> AlertResponse:
    """Convert a raw alert dict to an AlertResponse model."""
    explanation_raw = alert.get("explanation") or {}
    explanation_resp = None
    if explanation_raw:
        explanation_resp = AlertExplanationResponse(
            reason            = explanation_raw.get("reason", ""),
            findingSummary    = explanation_raw.get("findingSummary", ""),
            affectedAssets    = list(explanation_raw.get("affectedAssets") or []),
            recommendedAction = explanation_raw.get("recommendedAction", ""),
            escalationReason  = explanation_raw.get("escalationReason", ""),
        )

    correlation_raw = alert.get("correlation") or {}
    correlation_resp = None
    if correlation_raw:
        correlation_resp = AlertCorrelationResponse(
            correlationId     = correlation_raw.get("correlationId", ""),
            relatedAlertIds   = list(correlation_raw.get("relatedAlertIds") or []),
            relatedFindingIds = list(correlation_raw.get("relatedFindingIds") or []),
            sharedEvidenceIds = list(correlation_raw.get("sharedEvidenceIds") or []),
            sharedAssets      = list(correlation_raw.get("sharedAssets") or []),
            correlationScore  = correlation_raw.get("correlationScore", 0.0),
        )

    return AlertResponse(
        alertId                  = alert.get("alertId"),
        alertKey                 = alert.get("alertKey"),
        projectId                = alert.get("projectId"),
        findingId                = alert.get("findingId"),
        investigationId          = alert.get("investigationId"),
        title                    = alert.get("title"),
        description              = alert.get("description"),
        severity                 = alert.get("severity"),
        status                   = alert.get("status"),
        source                   = alert.get("source"),
        confidence               = alert.get("confidence"),
        riskScore                = alert.get("riskScore"),
        assetIds                 = list(alert.get("assetIds") or []),
        relationshipIds          = list(alert.get("relationshipIds") or []),
        evidenceIds              = list(alert.get("evidenceIds") or []),
        graphNodeIds             = list(alert.get("graphNodeIds") or []),
        timelineEventIds         = list(alert.get("timelineEventIds") or []),
        findingFingerprint       = alert.get("findingFingerprint"),
        investigationFingerprint = alert.get("investigationFingerprint"),
        graphFingerprint         = alert.get("graphFingerprint"),
        alertFingerprint         = alert.get("alertFingerprint"),
        tags                     = list(alert.get("tags") or []),
        metadata                 = alert.get("metadata") or {},
        createdBy                = alert.get("createdBy"),
        assignedTo               = alert.get("assignedTo"),
        createdAt                = alert.get("createdAt"),
        updatedAt                = alert.get("updatedAt"),
        closedAt                 = alert.get("closedAt"),
        acknowledgedAt           = alert.get("acknowledgedAt"),
        resolvedAt               = alert.get("resolvedAt"),
        explanation              = explanation_resp,
        correlation              = correlation_resp,
        engineVersion            = alert.get("engineVersion"),
        auditTrail               = list(alert.get("auditTrail") or []),
    )


def _alert_record_to_dict(alert: Alert) -> Dict[str, Any]:
    """
    Convert an Alert (frozen dataclass from alert_service) to a mutable
    plain dict suitable for storage in _ALERT_STORE.

    Enum values are serialised as their string values so they are JSON-safe.
    """
    return {
        "alertId"                  : alert.alertId,
        "alertKey"                 : alert.alertKey,
        "projectId"                : alert.projectId,
        "findingId"                : alert.findingId,
        "investigationId"          : alert.investigationId,
        "title"                    : alert.title,
        "description"              : alert.description,
        "severity"                 : alert.severity.value,
        "status"                   : alert.status.value,
        "source"                   : alert.source.value,
        "confidence"               : alert.confidence,
        "riskScore"                : alert.riskScore,
        "assetIds"                 : list(alert.assetIds),
        "relationshipIds"          : list(alert.relationshipIds),
        "evidenceIds"              : list(alert.evidenceIds),
        "graphNodeIds"             : list(alert.graphNodeIds),
        "timelineEventIds"         : list(alert.timelineEventIds),
        "findingFingerprint"       : alert.findingFingerprint,
        "investigationFingerprint" : alert.investigationFingerprint,
        "graphFingerprint"         : alert.graphFingerprint,
        "alertFingerprint"         : alert.alertFingerprint,
        "tags"                     : list(alert.tags),
        "metadata"                 : dict(alert.metadata),
        "createdBy"                : alert.createdBy,
        "assignedTo"               : alert.assignedTo,
        "createdAt"                : alert.createdAt,
        "updatedAt"                : alert.updatedAt,
        "closedAt"                 : alert.closedAt,
        "acknowledgedAt"           : alert.acknowledgedAt,
        "resolvedAt"               : alert.resolvedAt,
        "explanation"              : {
            "reason"            : alert.explanation.reason,
            "findingSummary"    : alert.explanation.findingSummary,
            "affectedAssets"    : list(alert.explanation.affectedAssets),
            "recommendedAction" : alert.explanation.recommendedAction,
            "escalationReason"  : alert.explanation.escalationReason,
        },
        "correlation"              : {
            "correlationId"     : alert.correlation.correlationId,
            "relatedAlertIds"   : list(alert.correlation.relatedAlertIds),
            "relatedFindingIds" : list(alert.correlation.relatedFindingIds),
            "sharedEvidenceIds" : list(alert.correlation.sharedEvidenceIds),
            "sharedAssets"      : list(alert.correlation.sharedAssets),
            "correlationScore"  : alert.correlation.correlationScore,
        },
        "engineVersion"            : alert.engineVersion,
        "auditTrail"               : list(alert.auditTrail),
    }


def _compute_statistics(alerts: List[Dict[str, Any]]) -> AlertStatisticsResponse:
    """
    Compute aggregate statistics over the in-memory alert store.

    Parameters
    ----------
    alerts : List of raw alert dicts from _ALERT_STORE.

    Returns
    -------
    AlertStatisticsResponse (frozen / immutable)
    """
    total = len(alerts)

    severity_counts: Dict[str, int] = {}
    status_counts:   Dict[str, int] = {}
    type_counts:     Dict[str, int] = {}
    confidence_sum = 0.0
    risk_sum       = 0.0

    for a in alerts:
        sev = a.get("severity") or "MEDIUM"
        st  = a.get("status")   or "NEW"
        src = a.get("source")   or "FINDING"

        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        status_counts[st]    = status_counts.get(st, 0) + 1
        type_counts[src]     = type_counts.get(src, 0) + 1
        confidence_sum += a.get("confidence", 0.0)
        risk_sum       += a.get("riskScore",  0.0)

    average_conf = round(confidence_sum / total, 4) if total > 0 else 0.0
    average_risk = round(risk_sum       / total, 4) if total > 0 else 0.0

    return AlertStatisticsResponse(
        totalAlerts       = total,
        severityCounts    = dict(sorted(severity_counts.items())),
        statusCounts      = dict(sorted(status_counts.items())),
        typeCounts        = dict(sorted(type_counts.items())),
        averageConfidence = average_conf,
        averageRiskScore  = average_risk,
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------

@alert_router.get(
    "",
    response_model = APIResponse,
    summary        = "List alerts",
    description    = "Return all alerts in the in-memory store.",
)
def list_alerts() -> APIResponse:
    """
    GET /api/v2/alerts

    Returns all alerts stored in the in-memory store.  No pagination in Part A.
    """
    try:
        alerts = _all_alerts()
        payload = AlertListResponse(
            alerts = [_alert_to_response(a) for a in alerts],
            total  = len(alerts),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(alerts)} alert(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /alerts/statistics
# ---------------------------------------------------------------------------

@alert_router.get(
    "/statistics",
    response_model = APIResponse,
    summary        = "Alert statistics",
    description    = (
        "Return aggregate statistics over all alerts in the in-memory store.  "
        "Exposes totalAlerts, severityCounts, statusCounts, typeCounts, "
        "and averageConfidence."
    ),
)
def get_alert_statistics() -> APIResponse:
    """
    GET /api/v2/alerts/statistics

    Returns AlertStatisticsResponse.
    """
    try:
        stats = _compute_statistics(_all_alerts())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Alert statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /alerts/{alertId}
# ---------------------------------------------------------------------------

@alert_router.get(
    "/{alertId}",
    response_model = APIResponse,
    summary        = "Get alert by ID",
    description    = "Return a single alert by its alertId.",
)
def get_alert(alertId: str) -> APIResponse:
    """
    GET /api/v2/alerts/{alertId}

    Looks up by alertId.  Returns 404 if not found.
    """
    try:
        alert = _ALERT_STORE.get(alertId)
        if alert is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Alert '{alertId}' not found.")
            )
        return build_success_response(
            data    = _alert_to_response(alert).model_dump(),
            message = "Alert retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /alerts
# ---------------------------------------------------------------------------

@alert_router.post(
    "",
    response_model = APIResponse,
    summary        = "Create alert",
    description    = (
        "Create a new alert in the in-memory store.  "
        "The alertId is derived deterministically from "
        "(projectId, findingId, title, source) via SHA-256 + UUIDv5; "
        "the same inputs always produce the same alertId."
    ),
    status_code    = 201,
)
def create_alert(
    body: CreateAlertRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/alerts

    Validates the request, converts enums, delegates alert construction to
    build_alert() from alert_service.py, checks for a duplicate alertId,
    then stores the result.

    Returns 409 if an alert with the same deterministic alertId already exists.
    Returns 422 if request validation fails or source/severity are invalid.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid alert request.", details=errors)
            )

        # Validate and convert source enum
        source_enum = _validate_source(body.source or "FINDING")
        if source_enum is None:
            valid_sources = sorted(s.value for s in AlertSource)
            return exception_to_api_response(
                APIErrorValidation(
                    "Invalid source value.",
                    details=[
                        f"source '{body.source}' is not a recognised AlertSource value.",
                        f"Valid values: {valid_sources}.",
                    ],
                )
            )

        # Validate and convert severity enum
        severity_enum = _validate_severity(body.severity or "MEDIUM")
        if severity_enum is None:
            valid_severities = sorted(s.value for s in AlertSeverity)
            return exception_to_api_response(
                APIErrorValidation(
                    "Invalid severity value.",
                    details=[
                        f"severity '{body.severity}' is not a recognised AlertSeverity value.",
                        f"Valid values: {valid_severities}.",
                    ],
                )
            )

        # Delegate construction to the alert engine
        alert = build_alert(
            project_id                = body.projectId,
            finding_id                = body.findingId,
            investigation_id          = body.investigationId,
            title                     = body.title,
            created_by                = body.createdBy,
            created_at                = body.createdAt,
            source                    = source_enum,
            severity                  = severity_enum,
            description               = body.description or "",
            confidence                = body.confidence or 0.0,
            risk_score                = body.riskScore or 0.0,
            assigned_to               = body.assignedTo,
            asset_ids                 = body.assetIds,
            relationship_ids          = body.relationshipIds,
            evidence_ids              = body.evidenceIds,
            graph_node_ids            = body.graphNodeIds,
            timeline_event_ids        = body.timelineEventIds,
            finding_fingerprint       = body.findingFingerprint or "",
            investigation_fingerprint = body.investigationFingerprint or "",
            graph_fingerprint         = body.graphFingerprint or "",
            reason                    = body.reason or "",
            finding_summary           = body.findingSummary or "",
            affected_assets           = body.affectedAssets,
            recommended_action        = body.recommendedAction or "",
            escalation_reason         = body.escalationReason or "",
            related_alert_ids         = body.relatedAlertIds,
            related_finding_ids       = body.relatedFindingIds,
            shared_evidence_ids       = body.sharedEvidenceIds,
            shared_assets             = body.sharedAssets,
            correlation_score         = body.correlationScore or 0.0,
            tags                      = body.tags,
            metadata                  = body.metadata,
        )

        alert_id = alert.alertId

        # Duplicate check — same deterministic key means same logical entity
        if alert_id in _ALERT_STORE:
            return exception_to_api_response(
                APIErrorConflict(
                    f"Alert '{alert_id}' already exists "
                    f"(duplicate detected via deterministic key for "
                    f"projectId='{body.projectId}', findingId='{body.findingId}', "
                    f"title='{body.title}')."
                )
            )

        # Store as a plain mutable dict
        stored = _alert_record_to_dict(alert)
        _ALERT_STORE[alert_id] = stored

        return build_success_response(
            data    = _alert_to_response(stored).model_dump(),
            message = "Alert created.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /alerts/{alertId}
# ---------------------------------------------------------------------------

@alert_router.put(
    "/{alertId}",
    response_model = APIResponse,
    summary        = "Update alert",
    description    = (
        "Update mutable fields of an existing alert.  "
        "Immutable fields (alertId, alertKey, projectId, findingId, "
        "investigationId, createdBy, createdAt, engineVersion) cannot be "
        "changed through this endpoint."
    ),
)
def update_alert_endpoint(
    alertId: str,
    body   : UpdateAlertRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/alerts/{alertId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.

    Immutable fields: alertId, alertKey, projectId, findingId,
                      investigationId, createdBy, createdAt, engineVersion.

    Returns 404 if the alert does not exist.
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

        stored_alert = _ALERT_STORE.get(alertId)
        if stored_alert is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Alert '{alertId}' not found.")
            )

        # Validate new enum values before touching the store
        new_severity = None
        if body.severity is not None:
            new_severity = _validate_severity(body.severity)
            if new_severity is None:
                valid_severities = sorted(s.value for s in AlertSeverity)
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid severity value.",
                        details=[
                            f"severity '{body.severity}' is not a recognised AlertSeverity value.",
                            f"Valid values: {valid_severities}.",
                        ],
                    )
                )

        new_status = None
        if body.status is not None:
            new_status = _validate_status(body.status)
            if new_status is None:
                valid_statuses = sorted(s.value for s in AlertStatus)
                return exception_to_api_response(
                    APIErrorValidation(
                        "Invalid status value.",
                        details=[
                            f"status '{body.status}' is not a recognised AlertStatus value.",
                            f"Valid values: {valid_statuses}.",
                        ],
                    )
                )

        # Reconstruct Alert dataclass from stored dict so we can pass it
        # to update_alert() from alert_service.py
        from services.alert_service import (
            AlertExplanation, AlertCorrelation,
        )
        from datetime import datetime, timezone

        sev_val = stored_alert.get("severity", "MEDIUM")
        sev_enum = AlertSeverity(sev_val) if sev_val else AlertSeverity.MEDIUM
        st_val = stored_alert.get("status", "NEW")
        st_enum = AlertStatus(st_val) if st_val else AlertStatus.NEW
        src_val = stored_alert.get("source", "FINDING")
        src_enum = AlertSource(src_val) if src_val else AlertSource.FINDING

        exp_dict = stored_alert.get("explanation") or {}
        explanation_obj = AlertExplanation(
            reason            = exp_dict.get("reason", ""),
            findingSummary    = exp_dict.get("findingSummary", ""),
            affectedAssets    = tuple(exp_dict.get("affectedAssets") or []),
            recommendedAction = exp_dict.get("recommendedAction", ""),
            escalationReason  = exp_dict.get("escalationReason", ""),
        )

        cor_dict = stored_alert.get("correlation") or {}
        correlation_obj = AlertCorrelation(
            correlationId     = cor_dict.get("correlationId", ""),
            relatedAlertIds   = tuple(cor_dict.get("relatedAlertIds") or []),
            relatedFindingIds = tuple(cor_dict.get("relatedFindingIds") or []),
            sharedEvidenceIds = tuple(cor_dict.get("sharedEvidenceIds") or []),
            sharedAssets      = tuple(cor_dict.get("sharedAssets") or []),
            correlationScore  = cor_dict.get("correlationScore", 0.0),
        )

        alert_obj = Alert(
            alertId                  = stored_alert["alertId"],
            alertKey                 = stored_alert["alertKey"],
            projectId                = stored_alert["projectId"],
            findingId                = stored_alert["findingId"],
            investigationId          = stored_alert["investigationId"],
            title                    = stored_alert["title"],
            description              = stored_alert["description"],
            severity                 = sev_enum,
            status                   = st_enum,
            source                   = src_enum,
            confidence               = stored_alert["confidence"],
            riskScore                = stored_alert["riskScore"],
            assetIds                 = tuple(stored_alert["assetIds"]),
            relationshipIds          = tuple(stored_alert["relationshipIds"]),
            evidenceIds              = tuple(stored_alert["evidenceIds"]),
            graphNodeIds             = tuple(stored_alert["graphNodeIds"]),
            timelineEventIds         = tuple(stored_alert["timelineEventIds"]),
            findingFingerprint       = stored_alert["findingFingerprint"],
            investigationFingerprint = stored_alert["investigationFingerprint"],
            graphFingerprint         = stored_alert["graphFingerprint"],
            alertFingerprint         = stored_alert["alertFingerprint"],
            tags                     = tuple(stored_alert["tags"]),
            metadata                 = stored_alert["metadata"],
            createdBy                = stored_alert["createdBy"],
            assignedTo               = stored_alert.get("assignedTo"),
            createdAt                = stored_alert["createdAt"],
            updatedAt                = stored_alert["updatedAt"],
            closedAt                 = stored_alert.get("closedAt"),
            acknowledgedAt           = stored_alert.get("acknowledgedAt"),
            resolvedAt               = stored_alert.get("resolvedAt"),
            explanation              = explanation_obj,
            correlation              = correlation_obj,
            engineVersion            = stored_alert["engineVersion"],
            auditTrail               = tuple(stored_alert["auditTrail"]),
        )

        # Use current timestamp for updatedAt
        updated_at = datetime.now(timezone.utc).isoformat()

        # Delegate update to alert_service.update_alert()
        updated_alert = update_alert(
            alert                    = alert_obj,
            updated_at               = updated_at,
            title                    = body.title,
            description              = body.description,
            severity                 = new_severity,
            status                   = new_status,
            confidence               = body.confidence,
            risk_score               = body.riskScore,
            assigned_to              = body.assignedTo,
            asset_ids                = body.assetIds,
            relationship_ids         = body.relationshipIds,
            evidence_ids             = body.evidenceIds,
            graph_node_ids           = body.graphNodeIds,
            timeline_event_ids       = body.timelineEventIds,
            finding_fingerprint      = body.findingFingerprint,
            investigation_fingerprint= body.investigationFingerprint,
            graph_fingerprint        = body.graphFingerprint,
            reason                   = body.reason,
            finding_summary          = body.findingSummary,
            affected_assets          = body.affectedAssets,
            recommended_action       = body.recommendedAction,
            escalation_reason        = body.escalationReason,
            related_alert_ids        = body.relatedAlertIds,
            related_finding_ids      = body.relatedFindingIds,
            shared_evidence_ids      = body.sharedEvidenceIds,
            shared_assets            = body.sharedAssets,
            correlation_score        = body.correlationScore,
            tags                     = body.tags,
            metadata                 = body.metadata,
        )

        # Store updated alert
        updated_dict = _alert_record_to_dict(updated_alert)
        _ALERT_STORE[alertId] = updated_dict

        return build_success_response(
            data    = _alert_to_response(updated_dict).model_dump(),
            message = "Alert updated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /alerts/{alertId}
# ---------------------------------------------------------------------------

@alert_router.delete(
    "/{alertId}",
    response_model = APIResponse,
    summary        = "Delete alert",
    description    = "Remove an alert from the in-memory store.",
)
def delete_alert(alertId: str) -> APIResponse:
    """
    DELETE /api/v2/alerts/{alertId}

    Returns 404 if the alert does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if alertId not in _ALERT_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Alert '{alertId}' not found.")
            )

        del _ALERT_STORE[alertId]

        return build_success_response(
            data    = None,
            message = f"Alert '{alertId}' deleted.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

import math
from typing import Annotated, Tuple
from fastapi import Query
from api.models import Pagination
from api.investigation.alert_models import AlertSearchResponse

# Canonical sort-key map
_SORT_KEY_MAP: Dict[str, str] = {
    "severity"   : "severity",
    "status"     : "status",
    "type"       : "source",
    "source"     : "source",
    "confidence" : "confidence",
    "riskscore"  : "riskScore",
    "risk"       : "riskScore",
    "created"    : "createdAt",
    "createdat"  : "createdAt",
}


def find_alert(
    alerts : List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first alert whose ``field`` matches ``value`` (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.

    Parameters
    ----------
    alerts : Ordered list of alert dicts to search.
    field  : Dict key to match against (e.g. "alertId", "projectId").
    value  : Value to match (case-insensitive string comparison).

    Returns
    -------
    The first matching alert dict, or None if not found.
    """
    target = value.lower()
    for a in alerts:
        v = a.get(field)
        if v is not None and str(v).lower() == target:
            return a
    return None


def sort_alerts(
    alerts     : List[Dict[str, Any]],
    sort_by    : str  = "createdAt",
    sort_order : str  = "asc",
) -> List[Dict[str, Any]]:
    """
    Return a new list of alert dicts sorted by the specified field.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values
    -------------------------
    "severity"   — sort by severity string (lexicographic)
    "status"     — sort by status string (lexicographic)
    "type"       — sort by source string (lexicographic)
    "confidence" — sort by confidence (numeric; None treated as 0)
    "riskScore"  — sort by riskScore (numeric; None treated as 0)
    "createdAt"  — sort by createdAt (lexicographic ISO-8601 string)

    Parameters
    ----------
    alerts     : List of alert dicts.
    sort_by    : One of the supported sort keys above.  Unrecognised values
                 fall back to "createdAt".
    sort_order : "asc" (default) or "desc".  Any other value treated as "asc".

    Returns
    -------
    New sorted list — input not mutated.
    """
    field   = _SORT_KEY_MAP.get(sort_by.lower(), "createdAt")
    reverse = sort_order.lower() == "desc"

    def sort_key(a: Dict[str, Any]):
        v = a.get(field)
        if v is None:
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        return (0, str(v).lower())

    return sorted(alerts, key=sort_key, reverse=reverse)


def filter_alerts(
    alerts          : List[Dict[str, Any]],
    severity        : Optional[str]   = None,
    status          : Optional[str]   = None,
    source          : Optional[str]   = None,
    project_id      : Optional[str]   = None,
    investigation_id: Optional[str]   = None,
    finding_id      : Optional[str]   = None,
    min_confidence  : Optional[float] = None,
    max_confidence  : Optional[float] = None,
    min_risk_score  : Optional[float] = None,
    max_risk_score  : Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Extended filter helper supporting all filter predicates.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    alerts           : Ordered list of alert dicts.
    severity         : Case-insensitive exact match on severity.
    status           : Case-insensitive exact match on status.
    source           : Case-insensitive exact match on source.
    project_id       : Exact match on projectId.
    investigation_id : Exact match on investigationId.
    finding_id       : Exact match on findingId.
    min_confidence   : Keep alerts with confidence >= min_confidence.
    max_confidence   : Keep alerts with confidence <= max_confidence.
    min_risk_score   : Keep alerts with riskScore >= min_risk_score.
    max_risk_score   : Keep alerts with riskScore <= max_risk_score.

    Returns
    -------
    Filtered list — input not mutated.
    """
    result = []
    for a in alerts:
        if severity is not None:
            if (a.get("severity") or "").upper() != severity.upper():
                continue
        if status is not None:
            if (a.get("status") or "").upper() != status.upper():
                continue
        if source is not None:
            if (a.get("source") or "").upper() != source.upper():
                continue
        if project_id is not None:
            if (a.get("projectId") or "") != project_id:
                continue
        if investigation_id is not None:
            if (a.get("investigationId") or "") != investigation_id:
                continue
        if finding_id is not None:
            if (a.get("findingId") or "") != finding_id:
                continue
        if min_confidence is not None:
            if a.get("confidence", 0.0) < min_confidence:
                continue
        if max_confidence is not None:
            if a.get("confidence", 0.0) > max_confidence:
                continue
        if min_risk_score is not None:
            if a.get("riskScore", 0.0) < min_risk_score:
                continue
        if max_risk_score is not None:
            if a.get("riskScore", 0.0) > max_risk_score:
                continue
        result.append(a)
    return result


def paginate_alerts(
    alerts    : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """
    Slice an alert list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    alerts    : Full ordered list of alert dicts (already filtered/sorted).
    page      : 1-based page number (clamped to >= 1).
    page_size : Items per page (clamped to >= 1).

    Returns
    -------
    (page_slice, Pagination) where:
    - page_slice : the sub-list for the requested page.
    - Pagination : metadata model with page, pageSize, totalItems, totalPages.
    """
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(alerts)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = alerts[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_alerts(
    alerts : List[Dict[str, Any]],
    query  : str,
) -> List[Dict[str, Any]]:
    """
    Return alerts where any searchable text field contains *query* as a
    case-insensitive substring.

    Searchable fields: alertId, alertKey, title, description,
                       projectId, findingId, investigationId, source, severity.
    """
    q = query.lower()
    if not q:  # Empty query returns empty results
        return []
    search_fields = (
        "alertId", "alertKey", "title", "description",
        "projectId", "findingId", "investigationId",
        "source", "severity",
    )
    result = []
    for a in alerts:
        for f in search_fields:
            v = a.get(f) or ""
            if q in str(v).lower():
                result.append(a)
                break
    return result


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /alerts/search
# ---------------------------------------------------------------------------

@alert_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search alerts",
    description    = (
        "Full-text search across alertId, alertKey, title, description, "
        "projectId, findingId, investigationId, source, and severity.  "
        "Supports sorting, filtering, and pagination via query parameters."
    ),
)
def search_alerts(
    q                  : Annotated[str,            Query(min_length=1,  description="Search string (>= 1 char).")],
    sort_by            : Annotated[Optional[str],  Query(alias="sortBy",    description="Sort field: severity|status|type|confidence|riskScore|createdAt.")] = "createdAt",
    sort_order         : Annotated[Optional[str],  Query(alias="sortOrder", description="Sort direction: asc|desc.")] = "asc",
    page               : Annotated[Optional[int],  Query(ge=1,              description="1-based page number.")] = 1,
    page_size          : Annotated[Optional[int],  Query(alias="pageSize",  ge=1, le=500, description="Items per page.")] = 20,
    severity_filter    : Annotated[Optional[str],  Query(alias="severity",        description="Exact severity filter.")] = None,
    status_filter      : Annotated[Optional[str],  Query(alias="status",          description="Exact status filter.")] = None,
    source_filter      : Annotated[Optional[str],  Query(alias="source",          description="Exact source/type filter.")] = None,
    project_filter     : Annotated[Optional[str],  Query(alias="projectId",       description="Exact projectId filter.")] = None,
    investigation_filter: Annotated[Optional[str], Query(alias="investigationId", description="Exact investigationId filter.")] = None,
    finding_filter     : Annotated[Optional[str],  Query(alias="findingId",       description="Exact findingId filter.")] = None,
    min_confidence     : Annotated[Optional[float],Query(alias="minConfidence",   ge=0, le=100, description="Minimum confidence.")] = None,
    max_confidence     : Annotated[Optional[float],Query(alias="maxConfidence",   ge=0, le=100, description="Maximum confidence.")] = None,
    min_risk_score     : Annotated[Optional[float],Query(alias="minRiskScore",    ge=0, le=100, description="Minimum riskScore.")] = None,
    max_risk_score     : Annotated[Optional[float],Query(alias="maxRiskScore",    ge=0, le=100, description="Maximum riskScore.")] = None,
) -> APIResponse:
    """
    GET /api/v2/alerts/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        allowed_sort = {
            "severity", "status", "type", "source",
            "confidence", "riskscore", "risk", "created", "createdat",
        }
        errs: List[str] = []
        if sort_by and sort_by.lower() not in allowed_sort:
            errs.append(
                "sortBy must be one of: severity, status, type, confidence, riskScore, createdAt."
            )
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        # Search — empty q after strip returns all alerts
        q_stripped = q.strip()
        if q_stripped:
            matched = _search_alerts(_all_alerts(), q_stripped)
        else:
            matched = _all_alerts()

        # Filter
        filtered = filter_alerts(
            matched,
            severity         = severity_filter,
            status           = status_filter,
            source           = source_filter,
            project_id       = project_filter,
            investigation_id = investigation_filter,
            finding_id       = finding_filter,
            min_confidence   = min_confidence,
            max_confidence   = max_confidence,
            min_risk_score   = min_risk_score,
            max_risk_score   = max_risk_score,
        )

        # Sort
        sorted_alerts = sort_alerts(filtered, sort_by or "createdAt", sort_order or "asc")

        # Paginate
        page_slice, pagination = paginate_alerts(
            sorted_alerts,
            page      = page or 1,
            page_size = page_size or 20,
        )

        payload = AlertSearchResponse(
            alerts     = [_alert_to_response(a) for a in page_slice],
            total      = len(sorted_alerts),
            page       = pagination.page,
            pageSize   = pagination.pageSize,
            totalPages = pagination.totalPages,
            query      = q_stripped,
            sortBy     = sort_by or "createdAt",
            sortOrder  = sort_order or "asc",
        )

        return build_success_response(
            data    = payload.model_dump(),
            message = (
                f"{len(sorted_alerts)} alert(s) matched; "
                f"showing page {pagination.page} of {pagination.totalPages}."
            ),
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /alerts/bulk/create
# ---------------------------------------------------------------------------

@alert_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create alerts",
    description    = "Create multiple alerts in a single request.",
    status_code    = 201,
)
def bulk_create_alerts(
    body: BulkCreateAlertsRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/alerts/bulk/create

    Creates multiple alerts.  Returns a summary of successes and failures.
    Does NOT abort on first failure — processes all items and reports results.

    Returns 422 if the top-level request is invalid (empty list).
    Individual item failures are reported in the BulkOperationResult.
    """
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for idx, alert_req in enumerate(body.alerts):
            try:
                item_errors = alert_req.validate_request()
                if item_errors:
                    failed.append({
                        "alertId": f"item[{idx}]",
                        "reason": "; ".join(item_errors),
                    })
                    continue

                source_enum = _validate_source(alert_req.source or "FINDING")
                if source_enum is None:
                    failed.append({
                        "alertId": f"item[{idx}]",
                        "reason": f"Invalid source '{alert_req.source}'.",
                    })
                    continue

                severity_enum = _validate_severity(alert_req.severity or "MEDIUM")
                if severity_enum is None:
                    failed.append({
                        "alertId": f"item[{idx}]",
                        "reason": f"Invalid severity '{alert_req.severity}'.",
                    })
                    continue

                alert = build_alert(
                    project_id                = alert_req.projectId,
                    finding_id                = alert_req.findingId,
                    investigation_id          = alert_req.investigationId,
                    title                     = alert_req.title,
                    created_by                = alert_req.createdBy,
                    created_at                = alert_req.createdAt,
                    source                    = source_enum,
                    severity                  = severity_enum,
                    description               = alert_req.description or "",
                    confidence                = alert_req.confidence or 0.0,
                    risk_score                = alert_req.riskScore or 0.0,
                    assigned_to               = alert_req.assignedTo,
                    asset_ids                 = alert_req.assetIds,
                    relationship_ids          = alert_req.relationshipIds,
                    evidence_ids              = alert_req.evidenceIds,
                    graph_node_ids            = alert_req.graphNodeIds,
                    timeline_event_ids        = alert_req.timelineEventIds,
                    finding_fingerprint       = alert_req.findingFingerprint or "",
                    investigation_fingerprint = alert_req.investigationFingerprint or "",
                    graph_fingerprint         = alert_req.graphFingerprint or "",
                    reason                    = alert_req.reason or "",
                    finding_summary           = alert_req.findingSummary or "",
                    affected_assets           = alert_req.affectedAssets,
                    recommended_action        = alert_req.recommendedAction or "",
                    escalation_reason         = alert_req.escalationReason or "",
                    related_alert_ids         = alert_req.relatedAlertIds,
                    related_finding_ids       = alert_req.relatedFindingIds,
                    shared_evidence_ids       = alert_req.sharedEvidenceIds,
                    shared_assets             = alert_req.sharedAssets,
                    correlation_score         = alert_req.correlationScore or 0.0,
                    tags                      = alert_req.tags,
                    metadata                  = alert_req.metadata,
                )

                if alert.alertId in _ALERT_STORE:
                    failed.append({
                        "alertId": alert.alertId,
                        "reason": f"Alert '{alert.alertId}' already exists (duplicate).",
                    })
                    continue

                _ALERT_STORE[alert.alertId] = _alert_record_to_dict(alert)
                succeeded.append(alert.alertId)

            except Exception as item_exc:
                failed.append({
                    "alertId": f"item[{idx}]",
                    "reason": str(item_exc),
                })

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.alerts),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = (
                f"Bulk create completed: {len(succeeded)} succeeded, "
                f"{len(failed)} failed."
            ),
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /alerts/bulk/update
# ---------------------------------------------------------------------------

@alert_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update alerts",
    description    = "Update multiple alerts in a single request.",
)
def bulk_update_alerts(
    body: BulkUpdateAlertsRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/alerts/bulk/update

    Updates multiple alerts.  Processes all items regardless of individual
    failures and reports a BulkOperationResult summary.

    Returns 422 if the top-level request is invalid (empty list).
    Individual item failures (404, invalid enum) are collected in the result.
    """
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=errors)
            )

        from services.alert_service import AlertExplanation, AlertCorrelation
        from datetime import datetime, timezone
        updated_at = datetime.now(timezone.utc).isoformat()

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for item in body.items:
            alert_id   = item.alertId.strip()
            update_req = item.update

            try:
                stored = _ALERT_STORE.get(alert_id)
                if stored is None:
                    failed.append({
                        "alertId": alert_id,
                        "reason": f"Alert '{alert_id}' not found.",
                    })
                    continue

                if not update_req.has_any_field():
                    failed.append({
                        "alertId": alert_id,
                        "reason": "Update request contains no fields.",
                    })
                    continue

                # Validate enum fields
                new_severity = None
                if update_req.severity is not None:
                    new_severity = _validate_severity(update_req.severity)
                    if new_severity is None:
                        failed.append({
                            "alertId": alert_id,
                            "reason": f"Invalid severity '{update_req.severity}'.",
                        })
                        continue

                new_status = None
                if update_req.status is not None:
                    new_status = _validate_status(update_req.status)
                    if new_status is None:
                        failed.append({
                            "alertId": alert_id,
                            "reason": f"Invalid status '{update_req.status}'.",
                        })
                        continue

                sev_enum = AlertSeverity(stored.get("severity", "MEDIUM"))
                st_enum  = AlertStatus(stored.get("status", "NEW"))
                src_enum = AlertSource(stored.get("source", "FINDING"))

                exp_d = stored.get("explanation") or {}
                exp_obj = AlertExplanation(
                    reason            = exp_d.get("reason", ""),
                    findingSummary    = exp_d.get("findingSummary", ""),
                    affectedAssets    = tuple(exp_d.get("affectedAssets") or []),
                    recommendedAction = exp_d.get("recommendedAction", ""),
                    escalationReason  = exp_d.get("escalationReason", ""),
                )

                cor_d = stored.get("correlation") or {}
                cor_obj = AlertCorrelation(
                    correlationId     = cor_d.get("correlationId", ""),
                    relatedAlertIds   = tuple(cor_d.get("relatedAlertIds") or []),
                    relatedFindingIds = tuple(cor_d.get("relatedFindingIds") or []),
                    sharedEvidenceIds = tuple(cor_d.get("sharedEvidenceIds") or []),
                    sharedAssets      = tuple(cor_d.get("sharedAssets") or []),
                    correlationScore  = cor_d.get("correlationScore", 0.0),
                )

                alert_obj = Alert(
                    alertId                  = stored["alertId"],
                    alertKey                 = stored["alertKey"],
                    projectId                = stored["projectId"],
                    findingId                = stored["findingId"],
                    investigationId          = stored["investigationId"],
                    title                    = stored["title"],
                    description              = stored["description"],
                    severity                 = sev_enum,
                    status                   = st_enum,
                    source                   = src_enum,
                    confidence               = stored["confidence"],
                    riskScore                = stored["riskScore"],
                    assetIds                 = tuple(stored["assetIds"]),
                    relationshipIds          = tuple(stored["relationshipIds"]),
                    evidenceIds              = tuple(stored["evidenceIds"]),
                    graphNodeIds             = tuple(stored["graphNodeIds"]),
                    timelineEventIds         = tuple(stored["timelineEventIds"]),
                    findingFingerprint       = stored["findingFingerprint"],
                    investigationFingerprint = stored["investigationFingerprint"],
                    graphFingerprint         = stored["graphFingerprint"],
                    alertFingerprint         = stored["alertFingerprint"],
                    tags                     = tuple(stored["tags"]),
                    metadata                 = stored["metadata"],
                    createdBy                = stored["createdBy"],
                    assignedTo               = stored.get("assignedTo"),
                    createdAt                = stored["createdAt"],
                    updatedAt                = stored["updatedAt"],
                    closedAt                 = stored.get("closedAt"),
                    acknowledgedAt           = stored.get("acknowledgedAt"),
                    resolvedAt               = stored.get("resolvedAt"),
                    explanation              = exp_obj,
                    correlation              = cor_obj,
                    engineVersion            = stored["engineVersion"],
                    auditTrail               = tuple(stored["auditTrail"]),
                )

                updated = update_alert(
                    alert                     = alert_obj,
                    updated_at                = updated_at,
                    title                     = update_req.title,
                    description               = update_req.description,
                    severity                  = new_severity,
                    status                    = new_status,
                    confidence                = update_req.confidence,
                    risk_score                = update_req.riskScore,
                    assigned_to               = update_req.assignedTo,
                    asset_ids                 = update_req.assetIds,
                    relationship_ids          = update_req.relationshipIds,
                    evidence_ids              = update_req.evidenceIds,
                    graph_node_ids            = update_req.graphNodeIds,
                    timeline_event_ids        = update_req.timelineEventIds,
                    finding_fingerprint       = update_req.findingFingerprint,
                    investigation_fingerprint = update_req.investigationFingerprint,
                    graph_fingerprint         = update_req.graphFingerprint,
                    reason                    = update_req.reason,
                    finding_summary           = update_req.findingSummary,
                    affected_assets           = update_req.affectedAssets,
                    recommended_action        = update_req.recommendedAction,
                    escalation_reason         = update_req.escalationReason,
                    related_alert_ids         = update_req.relatedAlertIds,
                    related_finding_ids       = update_req.relatedFindingIds,
                    shared_evidence_ids       = update_req.sharedEvidenceIds,
                    shared_assets             = update_req.sharedAssets,
                    correlation_score         = update_req.correlationScore,
                    tags                      = update_req.tags,
                    metadata                  = update_req.metadata,
                )

                _ALERT_STORE[alert_id] = _alert_record_to_dict(updated)
                succeeded.append(alert_id)

            except Exception as item_exc:
                failed.append({"alertId": alert_id, "reason": str(item_exc)})

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = (
                f"Bulk update completed: {len(succeeded)} succeeded, "
                f"{len(failed)} failed."
            ),
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))

# ---------------------------------------------------------------------------
# DELETE /alerts/bulk/delete
# ---------------------------------------------------------------------------

@alert_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete alerts",
    description    = "Delete multiple alerts in a single request.",
)
def bulk_delete_alerts(
    body: BulkDeleteAlertsRequest = Body(...),
) -> APIResponse:
    """
    DELETE /api/v2/alerts/bulk/delete

    Deletes multiple alerts.  Processes all IDs regardless of individual
    failures and reports a BulkOperationResult summary.

    Returns 422 if the top-level request is invalid (empty list).
    Individual item failures (404, blank ID) are collected in the result.
    """
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=errors)
            )

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for aid in body.alertIds:
            alert_id = (aid or "").strip()
            if not alert_id:
                failed.append({"alertId": repr(aid), "reason": "alertId must not be empty."})
                continue
            if alert_id not in _ALERT_STORE:
                failed.append({"alertId": alert_id, "reason": f"Alert '{alert_id}' not found."})
                continue
            del _ALERT_STORE[alert_id]
            succeeded.append(alert_id)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.alertIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )

        return build_success_response(
            data    = result.model_dump(),
            message = (
                f"Bulk delete completed: {len(succeeded)} succeeded, "
                f"{len(failed)} failed."
            ),
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
