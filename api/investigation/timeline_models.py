"""
Timeline API Models — Phase A4.7.3 (Part A)
===========================================
Immutable Pydantic models for Timeline API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).  Business-rule validation stays in timeline_service.py.
- No UUID generation — callers supply eventId values.
- No timestamp generation — callers supply timestamps.
- No randomness.
- Response models are plain shaped dicts promoted to typed models so that
  FastAPI can generate correct OpenAPI schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


# ===========================================================================
# Request Models
# ===========================================================================

class CreateTimelineEventRequest(BaseModel):
    """
    Request body for POST /api/v2/timeline.

    Required fields
    ---------------
    eventId     : Caller-supplied identifier for the new event.
                  Must be non-empty.
    title       : Human-readable event title.
    time        : Event timestamp (ISO-8601 or epoch string).

    Optional fields
    ---------------
    description : Longer description of the event.
    protocol    : Network protocol associated with the event.
    src         : Source IP/identifier.
    dst         : Destination IP/identifier.
    severity    : Event severity (e.g. "low", "medium", "high").
    eventType   : Event type classification.
    metadata    : Arbitrary caller-supplied key-value pairs.
    """
    eventId     : str
    title       : str
    time        : str
    description : Optional[str]              = None
    protocol    : Optional[str]              = None
    src         : Optional[str]              = None
    dst         : Optional[str]              = None
    severity    : Optional[str]              = None
    eventType   : Optional[str]              = None
    metadata    : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - eventId must be non-empty and non-whitespace.
        - title must be non-empty and non-whitespace.
        - time must be non-empty and non-whitespace.
        """
        errors: List[str] = []
        if not self.eventId or not self.eventId.strip():
            errors.append("eventId must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.time or not self.time.strip():
            errors.append("time must not be empty.")
        return errors


class UpdateTimelineEventRequest(BaseModel):
    """
    Request body for PUT /api/v2/timeline/{eventId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Fields
    ------
    title       : New event title.
    description : New event description.
    protocol    : New protocol value.
    src         : New source identifier.
    dst         : New destination identifier.
    severity    : New severity level.
    eventType   : New event type.
    metadata    : Merge / replace metadata key-value pairs.
    """
    title       : Optional[str]              = None
    description : Optional[str]              = None
    protocol    : Optional[str]              = None
    src         : Optional[str]              = None
    dst         : Optional[str]              = None
    severity    : Optional[str]              = None
    eventType   : Optional[str]              = None
    metadata    : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class TimelineFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/timeline.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    protocol  : Filter by protocol (case-insensitive exact match).
    src       : Filter by source identifier (case-insensitive exact match).
    dst       : Filter by destination identifier (case-insensitive exact match).
    severity  : Filter by severity level (case-insensitive exact match).
    eventType : Filter by event type (case-insensitive exact match).
    """
    protocol  : Optional[str] = None
    src       : Optional[str] = None
    dst       : Optional[str] = None
    severity  : Optional[str] = None
    eventType : Optional[str] = None

    class Config:
        frozen = True


class TimelineSearchRequest(BaseModel):
    """
    Query-parameter model for GET /api/v2/timeline/search (Part B only).

    Not implemented in Part A.
    """
    pass


# ===========================================================================
# Response Models
# ===========================================================================

class TimelineEventResponse(BaseModel):
    """
    Single timeline event response shape.

    Fields mirror the internal event dict structure used by
    timeline_service.py builders.

    Fields
    ------
    eventId      : Unique event identifier.
    time         : Event timestamp string.
    title        : Human-readable event title.
    description  : Optional longer description.
    protocol     : Optional network protocol.
    src          : Optional source identifier.
    dst          : Optional destination identifier.
    severity     : Optional severity level.
    eventType    : Optional event type classification.
    packetNumber : Optional packet number reference.
    metadata     : Optional arbitrary key-value pairs.
    """
    eventId      : str
    time         : str
    title        : str
    description  : Optional[str]              = None
    protocol     : Optional[str]              = None
    src          : Optional[str]              = None
    dst          : Optional[str]              = None
    severity     : Optional[str]              = None
    eventType    : Optional[str]              = None
    packetNumber : Optional[int]              = None
    metadata     : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True


class TimelineListResponse(BaseModel):
    """
    Response shape for GET /api/v2/timeline.

    Fields
    ------
    events : List of timeline events.
    total  : Total number of events returned.
    """
    events : List[TimelineEventResponse]
    total  : int

    class Config:
        frozen = True


class TimelineStatisticsResponse(BaseModel):
    """
    Response shape for GET /api/v2/timeline/statistics.

    Fields
    ------
    totalEvents        : Total number of timeline events.
    protocolCounts     : Count of events by protocol (dict: protocol → count).
    severityCounts     : Count of events by severity (dict: severity → count).
    typeCounts         : Count of events by eventType (dict: eventType → count).
    hourlyDistribution : Count of events by hour-of-day (dict: "HH" → count).
                         Derived from the time field when it is ISO-8601.
                         Omitted keys mean zero events in that hour.
    dailyDistribution  : Count of events by date (dict: "YYYY-MM-DD" → count).
                         Derived from the time field when it is ISO-8601.
                         Omitted keys mean zero events on that date.
    """
    totalEvents        : int
    protocolCounts     : Dict[str, int]
    severityCounts     : Dict[str, int]
    typeCounts         : Dict[str, int]
    hourlyDistribution : Dict[str, int]
    dailyDistribution  : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Part B — Bulk Operation Models
# ===========================================================================

class BulkCreateTimelineEventsRequest(BaseModel):
    """
    Request body for POST /api/v2/timeline/bulk/create.

    Fields
    ------
    events : List of CreateTimelineEventRequest objects to create in bulk.
    """
    events : List[CreateTimelineEventRequest]

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Validate all events in the bulk request."""
        errors: List[str] = []
        if not self.events:
            errors.append("events list must not be empty.")
        for idx, event in enumerate(self.events):
            event_errors = event.validate_request()
            for err in event_errors:
                errors.append(f"Event {idx}: {err}")
        return errors


class BulkUpdateTimelineEventsRequest(BaseModel):
    """
    Request body for PUT /api/v2/timeline/bulk/update.

    Fields
    ------
    updates : List of tuples (eventId, UpdateTimelineEventRequest).
              Represented as a list of dicts with "eventId" and "updates" keys.
    """
    updates : List[Dict[str, Any]]

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Validate all updates in the bulk request."""
        errors: List[str] = []
        if not self.updates:
            errors.append("updates list must not be empty.")
        for idx, item in enumerate(self.updates):
            if not isinstance(item, dict):
                errors.append(f"Update {idx}: must be a dict with eventId and updates keys.")
                continue
            if "eventId" not in item or not item["eventId"]:
                errors.append(f"Update {idx}: eventId is required.")
            if "updates" not in item:
                errors.append(f"Update {idx}: updates field is required.")
        return errors


class BulkDeleteTimelineEventsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/timeline/bulk/delete.

    Fields
    ------
    eventIds : List of event IDs to delete.
    """
    eventIds : List[str]

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Validate the bulk delete request."""
        errors: List[str] = []
        if not self.eventIds:
            errors.append("eventIds list must not be empty.")
        for idx, event_id in enumerate(self.eventIds):
            if not event_id or not str(event_id).strip():
                errors.append(f"eventIds[{idx}]: must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Response shape for bulk operations.

    Fields
    ------
    successCount : Number of successfully processed items.
    failureCount : Number of failed items.
    errors       : List of error messages (indexed by position in request).
    """
    successCount : int
    failureCount : int
    errors       : List[str]

    class Config:
        frozen = True


# ===========================================================================
# Part B — Search Response Model
# ===========================================================================

class TimelineSearchResponse(BaseModel):
    """
    Response shape for GET /api/v2/timeline/search.

    Fields
    ------
    events     : List of matched timeline events.
    total      : Total number of matched events.
    pagination : Optional pagination metadata.
    """
    events     : List[TimelineEventResponse]
    total      : int
    pagination : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True
