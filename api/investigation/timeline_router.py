"""
Timeline Router — Phase A4.7.3 (Part A + Part B)
=================================================
REST interface for the Timeline Engine.

Prefix  : /api/v2/timeline
Tag     : Timeline

Endpoints (Part A)
------------------
GET    /api/v2/timeline              — list all timeline events
GET    /api/v2/timeline/statistics   — aggregate statistics (extended in Part B)
GET    /api/v2/timeline/{eventId}    — get a single timeline event by ID
POST   /api/v2/timeline              — create a timeline event
PUT    /api/v2/timeline/{eventId}    — update a timeline event
DELETE /api/v2/timeline/{eventId}    — delete a timeline event

Endpoints (Part B)
------------------
GET    /api/v2/timeline/search       — search + sort + filter + paginate
POST   /api/v2/timeline/bulk/create  — create multiple events
PUT    /api/v2/timeline/bulk/update  — update multiple events
DELETE /api/v2/timeline/bulk/delete  — delete multiple events

Pure helpers (Part B)
---------------------
find_timeline_event()      — locate a single event by field/value
sort_timeline_events()     — deterministic multi-key sort
filter_timeline_events()   — extended filter (protocol, severity, type,
                             sourceIp, destinationIp, date range)
paginate_timeline_events() — slice a list and return a Pagination object

Design rules
------------
- No business logic here.  Timeline construction delegated to
  timeline_service.py builders only (build_capture_timeline,
  build_host_timeline).
- No database.  In-memory placeholder collection (_TIMELINE_STORE).
- Returns only build_success_response() or exception_to_api_response().
- Request model validation at the API layer only; service validates
  business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.

In-memory store
---------------
_TIMELINE_STORE is a plain dict keyed by eventId.  It is module-level and
survives for the lifetime of the process.  It will be replaced by a proper
repository in a future phase.  Tests can reset it via _reset_store().
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Query
from typing import Annotated

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.investigation.timeline_models import (
    BulkCreateTimelineEventsRequest,
    BulkDeleteTimelineEventsRequest,
    BulkOperationResult,
    BulkUpdateTimelineEventsRequest,
    CreateTimelineEventRequest,
    TimelineEventResponse,
    TimelineListResponse,
    TimelineSearchResponse,
    TimelineStatisticsResponse,
    UpdateTimelineEventRequest,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

timeline_router: APIRouter = APIRouter(
    prefix = "/timeline",
    tags   = ["Timeline"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_timeline_event
_TIMELINE_STORE = RepositoryBackedDict("timeline", "eventId", map_timeline_event)


def _reset_store() -> None:
    """Clear the in-memory store.  Used by tests only."""
    _TIMELINE_STORE.clear()


def _all_events() -> List[Dict[str, Any]]:
    """Return all timeline events as a deterministically-ordered list (by eventId ASC)."""
    return sorted(_TIMELINE_STORE.values(), key=lambda e: e.get("eventId", ""))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _event_to_response(event: Dict[str, Any]) -> TimelineEventResponse:
    """Convert a raw event dict to a TimelineEventResponse model."""
    return TimelineEventResponse(
        eventId      = event.get("eventId", ""),
        time         = event.get("time", ""),
        title        = event.get("title", ""),
        description  = event.get("description"),
        protocol     = event.get("protocol"),
        src          = event.get("src"),
        dst          = event.get("dst"),
        severity     = event.get("severity"),
        eventType    = event.get("eventType"),
        packetNumber = event.get("packetNumber"),
        metadata     = event.get("metadata"),
    )


def _compute_statistics(events: List[Dict[str, Any]]) -> TimelineStatisticsResponse:
    """Compute aggregate statistics over a list of event dicts."""
    from datetime import datetime
    
    protocol_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    type_counts:     Dict[str, int] = {}
    hourly_dist:     Dict[str, int] = {}
    daily_dist:      Dict[str, int] = {}

    for ev in events:
        protocol = ev.get("protocol") or "unknown"
        severity = ev.get("severity") or "unknown"
        event_type = ev.get("eventType") or "unknown"

        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[event_type]   = type_counts.get(event_type, 0) + 1

        # Parse time field for hourly/daily distribution
        time_str = ev.get("time", "")
        if time_str:
            try:
                # Try ISO-8601 parsing
                dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                hour_key = f"{dt.hour:02d}"
                date_key = dt.strftime("%Y-%m-%d")
                hourly_dist[hour_key] = hourly_dist.get(hour_key, 0) + 1
                daily_dist[date_key] = daily_dist.get(date_key, 0) + 1
            except (ValueError, AttributeError):
                # If parsing fails, skip distribution for this event
                pass

    return TimelineStatisticsResponse(
        totalEvents        = len(events),
        protocolCounts     = dict(sorted(protocol_counts.items())),
        severityCounts     = dict(sorted(severity_counts.items())),
        typeCounts         = dict(sorted(type_counts.items())),
        hourlyDistribution = dict(sorted(hourly_dist.items())),
        dailyDistribution  = dict(sorted(daily_dist.items())),
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /timeline
# ---------------------------------------------------------------------------

@timeline_router.get(
    "",
    response_model = APIResponse,
    summary        = "List timeline events",
    description    = "Return all timeline events in the in-memory store.",
)
def list_timeline_events() -> APIResponse:
    """
    GET /api/v2/timeline

    Returns all timeline events.  No pagination in Part A.
    """
    try:
        events = _all_events()
        payload = TimelineListResponse(
            events = [_event_to_response(e) for e in events],
            total  = len(events),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(events)} timeline event(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /timeline/statistics
# ---------------------------------------------------------------------------

@timeline_router.get(
    "/statistics",
    response_model = APIResponse,
    summary        = "Timeline statistics",
    description    = "Return aggregate statistics over all timeline events in the in-memory store.",
)
def get_timeline_statistics() -> APIResponse:
    """
    GET /api/v2/timeline/statistics

    Returns TimelineStatisticsResponse — totals, protocol/severity/type counts.
    """
    try:
        stats = _compute_statistics(_all_events())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Timeline statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /timeline/{eventId}
# ---------------------------------------------------------------------------

@timeline_router.get(
    "/{eventId}",
    response_model = APIResponse,
    summary        = "Get timeline event by ID",
    description    = "Return a single timeline event by its eventId.",
)
def get_timeline_event(eventId: str) -> APIResponse:
    """
    GET /api/v2/timeline/{eventId}

    Looks up by eventId.  Returns 404 if not found.
    """
    try:
        event = _TIMELINE_STORE.get(eventId)
        if event is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Timeline event '{eventId}' not found.")
            )
        return build_success_response(
            data    = _event_to_response(event).model_dump(),
            message = "Timeline event retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /timeline
# ---------------------------------------------------------------------------

@timeline_router.post(
    "",
    response_model = APIResponse,
    summary        = "Create timeline event",
    description    = "Create a new timeline event in the in-memory store.",
    status_code    = 201,
)
def create_timeline_event(
    body: CreateTimelineEventRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/timeline

    Validates the request, checks for duplicate eventId, then builds and
    stores a new event dict using fields from the request body.

    Returns 409 if an event with the same eventId already exists.
    Returns 422 if request validation fails.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid timeline event request.", details=errors)
            )

        event_id = body.eventId.strip()

        # Duplicate check
        if event_id in _TIMELINE_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Timeline event '{event_id}' already exists.")
            )

        # Build event dict — mirrors the shape produced by timeline_service builders
        new_event: Dict[str, Any] = {
            "eventId"     : event_id,
            "time"        : body.time.strip(),
            "title"       : body.title.strip(),
            "description" : body.description,
            "protocol"    : body.protocol,
            "src"         : body.src,
            "dst"         : body.dst,
            "severity"    : body.severity,
            "eventType"   : body.eventType,
            "packetNumber": None,
            "metadata"    : dict(body.metadata) if body.metadata else {},
        }

        _TIMELINE_STORE[event_id] = new_event

        return build_success_response(
            data    = _event_to_response(new_event).model_dump(),
            message = "Timeline event created.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /timeline/{eventId}
# ---------------------------------------------------------------------------

@timeline_router.put(
    "/{eventId}",
    response_model = APIResponse,
    summary        = "Update timeline event",
    description    = "Update an existing timeline event in the in-memory store.",
)
def update_timeline_event(
    eventId : str,
    body    : UpdateTimelineEventRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/timeline/{eventId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.
    Returns 404 if the event does not exist.
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

        event = _TIMELINE_STORE.get(eventId)
        if event is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Timeline event '{eventId}' not found.")
            )

        # Apply updates — None fields are skipped
        if body.title       is not None: event["title"]       = body.title
        if body.description is not None: event["description"] = body.description
        if body.protocol    is not None: event["protocol"]    = body.protocol
        if body.src         is not None: event["src"]         = body.src
        if body.dst         is not None: event["dst"]         = body.dst
        if body.severity    is not None: event["severity"]    = body.severity
        if body.eventType   is not None: event["eventType"]   = body.eventType
        if body.metadata    is not None:
            existing_meta = event.get("metadata") or {}
            event["metadata"] = {**existing_meta, **dict(body.metadata)}

        # Persist back to store
        _TIMELINE_STORE[eventId] = event

        return build_success_response(
            data    = _event_to_response(event).model_dump(),
            message = "Timeline event updated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /timeline/{eventId}
# ---------------------------------------------------------------------------

@timeline_router.delete(
    "/{eventId}",
    response_model = APIResponse,
    summary        = "Delete timeline event",
    description    = "Remove a timeline event from the in-memory store.",
)
def delete_timeline_event(eventId: str) -> APIResponse:
    """
    DELETE /api/v2/timeline/{eventId}

    Returns 404 if the event does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if eventId not in _TIMELINE_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Timeline event '{eventId}' not found.")
            )

        del _TIMELINE_STORE[eventId]

        return build_success_response(
            data    = None,
            message = f"Timeline event '{eventId}' deleted.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

# Canonical sort-key map
_SORT_KEY_MAP: Dict[str, str] = {
    "time"     : "time",
    "severity" : "severity",
    "protocol" : "protocol",
    "type"     : "eventType",
    "title"    : "title",
}


def find_timeline_event(
    events : List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first event whose ``field`` matches ``value`` (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.

    Parameters
    ----------
    events : Ordered list of event dicts to search.
    field  : Dict key to match against (e.g. "eventId", "protocol").
    value  : Value to match (case-insensitive string comparison).

    Returns
    -------
    The first matching event dict, or None if not found.
    """
    target = value.lower()
    for ev in events:
        v = ev.get(field)
        if v is not None and str(v).lower() == target:
            return ev
    return None


def sort_timeline_events(
    events     : List[Dict[str, Any]],
    sort_by    : str  = "time",
    sort_order : str  = "asc",
) -> List[Dict[str, Any]]:
    """
    Return a new list of event dicts sorted by the specified field.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values
    -------------------------
    "time"     — sort by time (lexicographic; None/missing sorted last)
    "severity" — sort by severity (lexicographic; None/missing sorted last)
    "protocol" — sort by protocol (lexicographic; None/missing sorted last)
    "type"     — sort by eventType (lexicographic; None/missing sorted last)
    "title"    — sort by title (lexicographic; None/missing sorted last)

    Parameters
    ----------
    events     : List of event dicts.
    sort_by    : One of the supported sort keys above.  Unrecognised values
                 fall back to "time".
    sort_order : "asc" (default) or "desc".  Any other value treated as "asc".

    Returns
    -------
    New sorted list — input not mutated.
    """
    field = _SORT_KEY_MAP.get(sort_by, "time")
    reverse = sort_order.lower() == "desc"

    def sort_key(ev: Dict[str, Any]):
        v = ev.get(field)
        if v is None:
            # Sort None last for asc, first for desc (invert sentinel)
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())

    return sorted(events, key=sort_key, reverse=reverse)


def filter_timeline_events(
    events         : List[Dict[str, Any]],
    protocol       : Optional[str] = None,
    severity       : Optional[str] = None,
    event_type     : Optional[str] = None,
    source_ip      : Optional[str] = None,
    destination_ip : Optional[str] = None,
    start_time     : Optional[str] = None,
    end_time       : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extended filter helper supporting protocol, severity, type, IPs, and date range.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    events         : Ordered list of event dicts.
    protocol       : Case-insensitive exact match on protocol.
    severity       : Case-insensitive exact match on severity.
    event_type     : Case-insensitive exact match on eventType.
    source_ip      : Case-insensitive exact match on src (source IP).
    destination_ip : Case-insensitive exact match on dst (destination IP).
    start_time     : ISO-8601 timestamp — keep events with time >= start_time.
    end_time       : ISO-8601 timestamp — keep events with time <= end_time.

    Returns
    -------
    Filtered list — input not mutated.
    """
    result = []
    for ev in events:
        if protocol is not None:
            if (ev.get("protocol") or "").lower() != protocol.lower():
                continue
        if severity is not None:
            if (ev.get("severity") or "").lower() != severity.lower():
                continue
        if event_type is not None:
            if (ev.get("eventType") or "").lower() != event_type.lower():
                continue
        if source_ip is not None:
            if (ev.get("src") or "").lower() != source_ip.lower():
                continue
        if destination_ip is not None:
            if (ev.get("dst") or "").lower() != destination_ip.lower():
                continue
        if start_time is not None:
            ev_time = ev.get("time") or ""
            if ev_time < start_time:
                continue
        if end_time is not None:
            ev_time = ev.get("time") or ""
            if ev_time > end_time:
                continue
        result.append(ev)
    return result


def paginate_timeline_events(
    events    : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """
    Slice an event list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    events    : Full ordered list of event dicts (already filtered/sorted).
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
    total          = len(events)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = events[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_timeline_events(
    events : List[Dict[str, Any]],
    query  : str,
) -> List[Dict[str, Any]]:
    """
    Return events where any searchable text field contains *query* as a
    case-insensitive substring.

    Searchable fields: eventId, title, description, protocol, src, dst,
                       severity, eventType.
    """
    q = query.lower()
    if not q:
        return []  # Empty query returns nothing
    search_fields = (
        "eventId", "title", "description", "protocol",
        "src", "dst", "severity", "eventType",
    )
    result = []
    for ev in events:
        for f in search_fields:
            v = ev.get(f) or ""
            if q in str(v).lower():
                result.append(ev)
                break
    return result


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /timeline/search
# ---------------------------------------------------------------------------

@timeline_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search timeline events",
    description    = (
        "Full-text search across eventId, title, description, protocol, src, "
        "dst, severity, and eventType.  Supports sorting, filtering, and "
        "pagination via query parameters."
    ),
)
def search_timeline_events(
    q              : Annotated[str,            Query(min_length=1, description="Search string (>= 1 char).")],
    sort_by        : Annotated[Optional[str],  Query(alias="sortBy",    description="Sort field: time|severity|protocol|type|title.")] = "time",
    sort_order     : Annotated[Optional[str],  Query(alias="sortOrder", description="Sort direction: asc|desc.")] = "asc",
    page           : Annotated[Optional[int],  Query(ge=1,             description="1-based page number.")] = 1,
    page_size      : Annotated[Optional[int],  Query(alias="pageSize", ge=1, le=500, description="Items per page.")] = 20,
    protocol_filter: Annotated[Optional[str],  Query(alias="protocol",   description="Exact protocol filter.")] = None,
    severity_filter: Annotated[Optional[str],  Query(alias="severity",   description="Exact severity filter.")] = None,
    type_filter    : Annotated[Optional[str],  Query(alias="type",       description="Exact eventType filter.")] = None,
    source_ip      : Annotated[Optional[str],  Query(alias="sourceIp",   description="Exact src IP filter.")] = None,
    dest_ip        : Annotated[Optional[str],  Query(alias="destinationIp", description="Exact dst IP filter.")] = None,
    start_time     : Annotated[Optional[str],  Query(alias="startTime",  description="ISO-8601 start time (inclusive).")] = None,
    end_time       : Annotated[Optional[str],  Query(alias="endTime",    description="ISO-8601 end time (inclusive).")] = None,
) -> APIResponse:
    """
    GET /api/v2/timeline/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        # Validate sort parameters
        allowed_sort = {"time", "severity", "protocol", "type", "title"}
        errs = []
        if sort_by and sort_by not in allowed_sort:
            errs.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if sort_order and sort_order not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        # Search
        matched = _search_timeline_events(_all_events(), q.strip())

        # Filter
        filtered = filter_timeline_events(
            matched,
            protocol       = protocol_filter,
            severity       = severity_filter,
            event_type     = type_filter,
            source_ip      = source_ip,
            destination_ip = dest_ip,
            start_time     = start_time,
            end_time       = end_time,
        )

        # Sort
        sorted_events = sort_timeline_events(filtered, sort_by or "time", sort_order or "asc")

        # Paginate
        page_slice, pagination = paginate_timeline_events(
            sorted_events,
            page      = page or 1,
            page_size = page_size or 20,
        )

        payload = TimelineSearchResponse(
            events     = [_event_to_response(e) for e in page_slice],
            total      = len(sorted_events),
            pagination = pagination.model_dump(),
        )

        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sorted_events)} event(s) matched; showing page {pagination.page} of {pagination.totalPages}.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /timeline/bulk/create
# ---------------------------------------------------------------------------

@timeline_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create timeline events",
    description    = "Create multiple timeline events in a single request.",
    status_code    = 201,
)
def bulk_create_timeline_events(
    body: BulkCreateTimelineEventsRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/timeline/bulk/create

    Creates multiple events.  Returns a summary of successes and failures.
    Does NOT abort on first failure — processes all events.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=errors)
            )

        success_count = 0
        failure_count = 0
        error_messages: List[str] = []

        for idx, event_req in enumerate(body.events):
            event_id = event_req.eventId.strip()

            # Duplicate check
            if event_id in _TIMELINE_STORE:
                failure_count += 1
                error_messages.append(f"Event {idx} ({event_id}): already exists.")
                continue

            # Build event dict
            new_event: Dict[str, Any] = {
                "eventId"     : event_id,
                "time"        : event_req.time.strip(),
                "title"       : event_req.title.strip(),
                "description" : event_req.description,
                "protocol"    : event_req.protocol,
                "src"         : event_req.src,
                "dst"         : event_req.dst,
                "severity"    : event_req.severity,
                "eventType"   : event_req.eventType,
                "packetNumber": None,
                "metadata"    : dict(event_req.metadata) if event_req.metadata else {},
            }

            _TIMELINE_STORE[event_id] = new_event
            success_count += 1

        result = BulkOperationResult(
            successCount = success_count,
            failureCount = failure_count,
            errors       = error_messages,
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create completed: {success_count} succeeded, {failure_count} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /timeline/bulk/update
# ---------------------------------------------------------------------------

@timeline_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update timeline events",
    description    = "Update multiple timeline events in a single request.",
)
def bulk_update_timeline_events(
    body: BulkUpdateTimelineEventsRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/timeline/bulk/update

    Updates multiple events.  Returns a summary of successes and failures.
    Does NOT abort on first failure — processes all updates.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=errors)
            )

        success_count = 0
        failure_count = 0
        error_messages: List[str] = []

        for idx, item in enumerate(body.updates):
            event_id = item.get("eventId", "").strip()
            updates_raw = item.get("updates", {})

            # Parse updates dict into UpdateTimelineEventRequest
            try:
                update_req = UpdateTimelineEventRequest(**updates_raw)
            except Exception as e:
                failure_count += 1
                error_messages.append(f"Update {idx} ({event_id}): invalid updates format — {str(e)}.")
                continue

            # Check at least one field
            if not update_req.has_any_field():
                failure_count += 1
                error_messages.append(f"Update {idx} ({event_id}): no fields provided.")
                continue

            # Check event exists
            event = _TIMELINE_STORE.get(event_id)
            if event is None:
                failure_count += 1
                error_messages.append(f"Update {idx} ({event_id}): event not found.")
                continue

            # Apply updates
            if update_req.title       is not None: event["title"]       = update_req.title
            if update_req.description is not None: event["description"] = update_req.description
            if update_req.protocol    is not None: event["protocol"]    = update_req.protocol
            if update_req.src         is not None: event["src"]         = update_req.src
            if update_req.dst         is not None: event["dst"]         = update_req.dst
            if update_req.severity    is not None: event["severity"]    = update_req.severity
            if update_req.eventType   is not None: event["eventType"]   = update_req.eventType
            if update_req.metadata    is not None:
                existing_meta = event.get("metadata") or {}
                event["metadata"] = {**existing_meta, **dict(update_req.metadata)}

            _TIMELINE_STORE[event_id] = event
            success_count += 1

        result = BulkOperationResult(
            successCount = success_count,
            failureCount = failure_count,
            errors       = error_messages,
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk update completed: {success_count} succeeded, {failure_count} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /timeline/bulk/delete
# ---------------------------------------------------------------------------

@timeline_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete timeline events",
    description    = "Delete multiple timeline events in a single request.",
)
def bulk_delete_timeline_events(
    body: BulkDeleteTimelineEventsRequest = Body(...),
) -> APIResponse:
    """
    DELETE /api/v2/timeline/bulk/delete

    Deletes multiple events.  Returns a summary of successes and failures.
    Does NOT abort on first failure — processes all deletions.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=errors)
            )

        success_count = 0
        failure_count = 0
        error_messages: List[str] = []

        for idx, event_id in enumerate(body.eventIds):
            event_id_clean = str(event_id).strip()

            if event_id_clean not in _TIMELINE_STORE:
                failure_count += 1
                error_messages.append(f"Event {idx} ({event_id_clean}): not found.")
                continue

            del _TIMELINE_STORE[event_id_clean]
            success_count += 1

        result = BulkOperationResult(
            successCount = success_count,
            failureCount = failure_count,
            errors       = error_messages,
        )

        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete completed: {success_count} succeeded, {failure_count} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
