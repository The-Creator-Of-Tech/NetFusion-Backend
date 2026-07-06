"""
Smoke Test — Timeline API (Phase A4.7.3 Part A + Part B)
=========================================================
Comprehensive deterministic smoke test for the Timeline API router.

Target: 500+ assertions covering:
- CRUD operations
- Search with filters and pagination
- Sorting (all fields, asc/desc)
- Filtering (protocol, severity, type, IPs, date range)
- Pagination edge cases
- Bulk operations (create, update, delete)
- Statistics (including hourly/daily distribution)
- Router registration
- Serialization (frozen models)
- Deterministic behavior
- Edge cases

Run:
    python smoke_test_timeline_api.py

Expected output:
    500+/500 assertions passed.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List

from api.investigation.timeline_router import (
    timeline_router,
    _reset_store,
    _TIMELINE_STORE,
    _all_events,
    _event_to_response,
    _compute_statistics,
    find_timeline_event,
    sort_timeline_events,
    filter_timeline_events,
    paginate_timeline_events,
    _search_timeline_events,
    list_timeline_events,
    get_timeline_statistics,
    get_timeline_event,
    create_timeline_event,
    update_timeline_event,
    delete_timeline_event,
    search_timeline_events,
    bulk_create_timeline_events,
    bulk_update_timeline_events,
    bulk_delete_timeline_events,
)
from api.investigation.timeline_models import (
    CreateTimelineEventRequest,
    UpdateTimelineEventRequest,
    BulkCreateTimelineEventsRequest,
    BulkUpdateTimelineEventsRequest,
    BulkDeleteTimelineEventsRequest,
    BulkOperationResult,
    TimelineEventResponse,
    TimelineListResponse,
    TimelineStatisticsResponse,
    TimelineSearchResponse,
)
from api.models import APIResponse, Pagination

# ---------------------------------------------------------------------------
# Assertion counter
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0
_FAILURES: List[str] = []


def check(condition: bool, label: str) -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        _FAILURES.append(label)


def eq(a: Any, b: Any, label: str) -> None:
    check(a == b, f"{label} — expected {b!r}, got {a!r}")


def is_true(val: Any, label: str) -> None:
    check(bool(val), label)


def is_false(val: Any, label: str) -> None:
    check(not bool(val), label)


def is_none(val: Any, label: str) -> None:
    check(val is None, label)


def not_none(val: Any, label: str) -> None:
    check(val is not None, label)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    event_id: str,
    title: str = "Test Event",
    time: str = "2026-07-03T10:00:00",
    protocol: str = "DNS",
    src: str = "192.168.1.1",
    dst: str = "8.8.8.8",
    severity: str = "low",
    event_type: str = "detection",
    description: str = "Test description",
    metadata: Dict[str, Any] = None,
) -> CreateTimelineEventRequest:
    return CreateTimelineEventRequest(
        eventId     = event_id,
        title       = title,
        time        = time,
        protocol    = protocol,
        src         = src,
        dst         = dst,
        severity    = severity,
        eventType   = event_type,
        description = description,
        metadata    = metadata,
    )


def reset() -> None:
    _reset_store()


# ===========================================================================
# Section 1 — Router Registration
# ===========================================================================

def test_router_registration():
    paths = [r.path for r in timeline_router.routes]
    check("/timeline" in paths,              "router: GET /timeline registered")
    check("/timeline/statistics" in paths,   "router: GET /timeline/statistics registered")
    check("/timeline/{eventId}" in paths,    "router: GET /timeline/{eventId} registered")
    check("/timeline/search" in paths,       "router: GET /timeline/search registered")
    check("/timeline/bulk/create" in paths,  "router: POST /timeline/bulk/create registered")
    check("/timeline/bulk/update" in paths,  "router: PUT /timeline/bulk/update registered")
    check("/timeline/bulk/delete" in paths,  "router: DELETE /timeline/bulk/delete registered")
    eq(timeline_router.prefix, "/timeline",  "router: prefix is /timeline")
    check("Timeline" in timeline_router.tags, "router: tag is Timeline")
    eq(len(paths), 10,                       "router: exactly 10 routes registered")


# ===========================================================================
# Section 2 — Model Validation
# ===========================================================================

def test_model_validation():
    # CreateTimelineEventRequest — valid
    req = make_event("e1")
    eq(req.validate_request(), [], "CreateRequest: valid request has no errors")

    # CreateTimelineEventRequest — empty eventId
    req2 = CreateTimelineEventRequest(eventId="", title="T", time="2026-01-01")
    errors = req2.validate_request()
    check(any("eventId" in e for e in errors), "CreateRequest: empty eventId is invalid")

    # CreateTimelineEventRequest — whitespace eventId
    req3 = CreateTimelineEventRequest(eventId="  ", title="T", time="2026-01-01")
    errors3 = req3.validate_request()
    check(any("eventId" in e for e in errors3), "CreateRequest: whitespace eventId is invalid")

    # CreateTimelineEventRequest — empty title
    req4 = CreateTimelineEventRequest(eventId="e1", title="", time="2026-01-01")
    errors4 = req4.validate_request()
    check(any("title" in e for e in errors4), "CreateRequest: empty title is invalid")

    # CreateTimelineEventRequest — empty time
    req5 = CreateTimelineEventRequest(eventId="e1", title="T", time="")
    errors5 = req5.validate_request()
    check(any("time" in e for e in errors5), "CreateRequest: empty time is invalid")

    # CreateTimelineEventRequest — all three empty
    req6 = CreateTimelineEventRequest(eventId="", title="", time="")
    errors6 = req6.validate_request()
    eq(len(errors6), 3, "CreateRequest: three empty fields = three errors")

    # UpdateTimelineEventRequest — has_any_field
    upd_empty = UpdateTimelineEventRequest()
    is_false(upd_empty.has_any_field(), "UpdateRequest: all None → has_any_field False")

    upd_one = UpdateTimelineEventRequest(title="New Title")
    is_true(upd_one.has_any_field(), "UpdateRequest: one field → has_any_field True")

    upd_all = UpdateTimelineEventRequest(
        title="T", description="D", protocol="DNS", src="1.1.1.1",
        dst="2.2.2.2", severity="high", eventType="finding",
        metadata={"k": "v"},
    )
    is_true(upd_all.has_any_field(), "UpdateRequest: all fields → has_any_field True")

    # Frozen models
    try:
        req.eventId = "mutated"
        check(False, "CreateRequest: should be immutable (frozen)")
    except Exception:
        check(True, "CreateRequest: frozen model raises on mutation")

    # TimelineEventResponse is frozen
    resp = TimelineEventResponse(eventId="e1", time="2026-01-01", title="T")
    try:
        resp.eventId = "mutated"
        check(False, "TimelineEventResponse: should be immutable (frozen)")
    except Exception:
        check(True, "TimelineEventResponse: frozen model raises on mutation")


# ===========================================================================
# Section 3 — CRUD Operations
# ===========================================================================

def test_create():
    reset()
    # Valid creation
    req = make_event("ev1", title="DNS Query", time="2026-07-03T10:00:00")
    resp = create_timeline_event(req)
    check(isinstance(resp, APIResponse),          "create: returns APIResponse")
    is_true(resp.success,                          "create: success is True")
    eq(resp.data["eventId"], "ev1",                "create: eventId matches")
    eq(resp.data["title"], "DNS Query",            "create: title matches")
    eq(resp.data["protocol"], "DNS",               "create: protocol matches")
    eq(resp.data["src"], "192.168.1.1",            "create: src matches")
    eq(resp.data["dst"], "8.8.8.8",                "create: dst matches")
    eq(resp.data["severity"], "low",               "create: severity matches")
    eq(resp.data["eventType"], "detection",        "create: eventType matches")
    not_none(resp.data["description"],             "create: description not None")
    check("ev1" in _TIMELINE_STORE,                "create: event persisted in store")

    # Duplicate creates a 409
    resp2 = create_timeline_event(req)
    is_false(resp2.success,                        "create duplicate: success is False")
    eq(resp2.data.errorCode, "CONFLICT",           "create duplicate: CONFLICT error")

    # Empty eventId
    req_bad = CreateTimelineEventRequest(eventId="", title="T", time="2026-01-01")
    resp3 = create_timeline_event(req_bad)
    is_false(resp3.success,                        "create empty eventId: success is False")
    eq(resp3.data.errorCode, "VALIDATION_ERROR",   "create empty eventId: VALIDATION_ERROR")

    # Whitespace eventId is stripped — treated as empty
    req_ws = CreateTimelineEventRequest(eventId="  ", title="T", time="2026-01-01")
    resp4 = create_timeline_event(req_ws)
    is_false(resp4.success,                        "create whitespace eventId: success is False")

    # Metadata is stored
    req_meta = CreateTimelineEventRequest(
        eventId="ev_meta", title="Meta Event", time="2026-01-01",
        metadata={"key": "value", "count": 5},
    )
    resp5 = create_timeline_event(req_meta)
    is_true(resp5.success,                         "create with metadata: success")
    eq(resp5.data["metadata"]["key"], "value",     "create with metadata: key stored")

    # Optional fields default to None
    req_minimal = CreateTimelineEventRequest(eventId="ev_min", title="Min", time="2026-01-01")
    resp6 = create_timeline_event(req_minimal)
    is_true(resp6.success,                         "create minimal: success")
    is_none(resp6.data["protocol"],                "create minimal: protocol is None")
    is_none(resp6.data["src"],                     "create minimal: src is None")
    is_none(resp6.data["severity"],                "create minimal: severity is None")


def test_read():
    reset()
    create_timeline_event(make_event("ev_r1", title="Read Event"))

    # GET by ID — found
    resp = get_timeline_event("ev_r1")
    is_true(resp.success,                         "read: success is True")
    eq(resp.data["eventId"], "ev_r1",             "read: eventId matches")
    eq(resp.data["title"], "Read Event",          "read: title matches")

    # GET by ID — not found
    resp2 = get_timeline_event("nonexistent")
    is_false(resp2.success,                       "read missing: success is False")
    eq(resp2.data.errorCode, "NOT_FOUND",         "read missing: NOT_FOUND error")

    # LIST — returns all events
    reset()
    for i in range(5):
        create_timeline_event(make_event(f"ev_list_{i}", title=f"Event {i}"))
    resp3 = list_timeline_events()
    is_true(resp3.success,                        "list: success is True")
    eq(resp3.data["total"], 5,                    "list: total is 5")
    eq(len(resp3.data["events"]), 5,              "list: events list length is 5")

    # LIST — empty store
    reset()
    resp4 = list_timeline_events()
    is_true(resp4.success,                        "list empty: success is True")
    eq(resp4.data["total"], 0,                    "list empty: total is 0")
    eq(len(resp4.data["events"]), 0,              "list empty: events list is empty")

    # LIST — events are sorted by eventId ASC
    reset()
    create_timeline_event(make_event("z_event", title="Z"))
    create_timeline_event(make_event("a_event", title="A"))
    create_timeline_event(make_event("m_event", title="M"))
    resp5 = list_timeline_events()
    ids = [e["eventId"] for e in resp5.data["events"]]
    eq(ids, ["a_event", "m_event", "z_event"], "list: events sorted by eventId ASC")


def test_update():
    reset()
    create_timeline_event(make_event("ev_u1", title="Original"))

    # Valid update — single field
    upd = UpdateTimelineEventRequest(title="Updated Title")
    resp = update_timeline_event("ev_u1", upd)
    is_true(resp.success,                         "update: success is True")
    eq(resp.data["title"], "Updated Title",       "update: title updated")
    eq(resp.data["eventId"], "ev_u1",             "update: eventId unchanged")

    # Update multiple fields
    upd2 = UpdateTimelineEventRequest(
        protocol="TLS", severity="high", eventType="finding",
    )
    resp2 = update_timeline_event("ev_u1", upd2)
    is_true(resp2.success,                        "update multi: success is True")
    eq(resp2.data["protocol"], "TLS",             "update multi: protocol updated")
    eq(resp2.data["severity"], "high",            "update multi: severity updated")
    eq(resp2.data["eventType"], "finding",        "update multi: eventType updated")

    # Update non-existing event
    resp3 = update_timeline_event("nonexistent", UpdateTimelineEventRequest(title="X"))
    is_false(resp3.success,                       "update missing: success is False")
    eq(resp3.data.errorCode, "NOT_FOUND",         "update missing: NOT_FOUND error")

    # Update with no fields
    upd_empty = UpdateTimelineEventRequest()
    resp4 = update_timeline_event("ev_u1", upd_empty)
    is_false(resp4.success,                       "update empty: success is False")
    eq(resp4.data.errorCode, "VALIDATION_ERROR",  "update empty: VALIDATION_ERROR")

    # Update metadata — merges with existing
    create_timeline_event(make_event("ev_meta_upd",
        title="Meta", metadata={"k1": "v1"}))
    # Update metadata merges
    upd_meta = UpdateTimelineEventRequest(metadata={"k2": "v2"})
    resp5 = update_timeline_event("ev_meta_upd", upd_meta)
    is_true(resp5.success,                        "update metadata merge: success")
    eq(resp5.data["metadata"]["k1"], "v1",        "update metadata merge: k1 preserved")
    eq(resp5.data["metadata"]["k2"], "v2",        "update metadata merge: k2 added")

    # Update src and dst
    upd3 = UpdateTimelineEventRequest(src="10.0.0.1", dst="10.0.0.2")
    resp6 = update_timeline_event("ev_u1", upd3)
    is_true(resp6.success,                        "update src/dst: success")
    eq(resp6.data["src"], "10.0.0.1",             "update src/dst: src updated")
    eq(resp6.data["dst"], "10.0.0.2",             "update src/dst: dst updated")

    # Update description
    upd4 = UpdateTimelineEventRequest(description="New desc")
    resp7 = update_timeline_event("ev_u1", upd4)
    is_true(resp7.success,                        "update description: success")
    eq(resp7.data["description"], "New desc",     "update description: updated")


def test_delete():
    reset()
    create_timeline_event(make_event("ev_d1"))

    # Valid delete
    resp = delete_timeline_event("ev_d1")
    is_true(resp.success,                         "delete: success is True")
    is_none(resp.data,                            "delete: data is None")
    check("ev_d1" not in _TIMELINE_STORE,         "delete: event removed from store")

    # Delete again — not found
    resp2 = delete_timeline_event("ev_d1")
    is_false(resp2.success,                       "delete again: success is False")
    eq(resp2.data.errorCode, "NOT_FOUND",         "delete again: NOT_FOUND error")

    # Delete non-existing
    resp3 = delete_timeline_event("never_existed")
    is_false(resp3.success,                       "delete nonexistent: success is False")
    eq(resp3.data.errorCode, "NOT_FOUND",         "delete nonexistent: NOT_FOUND error")

    # Delete reduces count
    reset()
    create_timeline_event(make_event("ev_d2"))
    create_timeline_event(make_event("ev_d3"))
    delete_timeline_event("ev_d2")
    resp4 = list_timeline_events()
    eq(resp4.data["total"], 1,                    "delete: list total reduced to 1")
    eq(resp4.data["events"][0]["eventId"], "ev_d3", "delete: remaining event is ev_d3")


# ===========================================================================
# Section 4 — Statistics
# ===========================================================================

def test_statistics():
    reset()
    # Empty store
    resp = get_timeline_statistics()
    is_true(resp.success,                         "stats empty: success is True")
    eq(resp.data["totalEvents"], 0,               "stats empty: totalEvents is 0")
    eq(resp.data["protocolCounts"], {},           "stats empty: protocolCounts is {}")
    eq(resp.data["severityCounts"], {},           "stats empty: severityCounts is {}")
    eq(resp.data["typeCounts"], {},               "stats empty: typeCounts is {}")
    eq(resp.data["hourlyDistribution"], {},       "stats empty: hourlyDistribution is {}")
    eq(resp.data["dailyDistribution"], {},        "stats empty: dailyDistribution is {}")

    # Populate store
    create_timeline_event(make_event("s1", protocol="DNS",  severity="low",    event_type="detection", time="2026-07-03T09:00:00"))
    create_timeline_event(make_event("s2", protocol="DNS",  severity="medium", event_type="detection", time="2026-07-03T10:00:00"))
    create_timeline_event(make_event("s3", protocol="TLS",  severity="high",   event_type="finding",   time="2026-07-03T10:30:00"))
    create_timeline_event(make_event("s4", protocol="HTTP", severity="high",   event_type="alert",     time="2026-07-04T08:00:00"))

    resp2 = get_timeline_statistics()
    is_true(resp2.success,                        "stats: success is True")
    eq(resp2.data["totalEvents"], 4,              "stats: totalEvents is 4")

    # Protocol counts
    pc = resp2.data["protocolCounts"]
    eq(pc.get("DNS"),  2,                         "stats: DNS count is 2")
    eq(pc.get("TLS"),  1,                         "stats: TLS count is 1")
    eq(pc.get("HTTP"), 1,                         "stats: HTTP count is 1")

    # Severity counts
    sc = resp2.data["severityCounts"]
    eq(sc.get("low"),    1,                       "stats: severity low count is 1")
    eq(sc.get("medium"), 1,                       "stats: severity medium count is 1")
    eq(sc.get("high"),   2,                       "stats: severity high count is 2")

    # Type counts
    tc = resp2.data["typeCounts"]
    eq(tc.get("detection"), 2,                    "stats: detection count is 2")
    eq(tc.get("finding"),   1,                    "stats: finding count is 1")
    eq(tc.get("alert"),     1,                    "stats: alert count is 1")

    # Hourly distribution
    hd = resp2.data["hourlyDistribution"]
    eq(hd.get("09"), 1,                           "stats: hour 09 count is 1")
    eq(hd.get("10"), 2,                           "stats: hour 10 count is 2")
    eq(hd.get("08"), 1,                           "stats: hour 08 count is 1")

    # Daily distribution
    dd = resp2.data["dailyDistribution"]
    eq(dd.get("2026-07-03"), 3,                   "stats: 2026-07-03 count is 3")
    eq(dd.get("2026-07-04"), 1,                   "stats: 2026-07-04 count is 1")

    # Stats with non-ISO time fields — no crash
    reset()
    create_timeline_event(CreateTimelineEventRequest(
        eventId="s_bad_time", title="T", time="not-a-timestamp",
        protocol="DNS", severity="low", eventType="detection",
    ))
    resp3 = get_timeline_statistics()
    is_true(resp3.success,                        "stats bad time: success is True")
    eq(resp3.data["totalEvents"], 1,              "stats bad time: totalEvents is 1")
    eq(resp3.data["hourlyDistribution"], {},      "stats bad time: hourlyDistribution empty")
    eq(resp3.data["dailyDistribution"], {},       "stats bad time: dailyDistribution empty")

    # Stats dicts are sorted alphabetically
    reset()
    create_timeline_event(make_event("srt1", protocol="TLS",  severity="high", event_type="finding", time="2026-01-01T01:00:00"))
    create_timeline_event(make_event("srt2", protocol="DNS",  severity="low",  event_type="alert",   time="2026-01-01T02:00:00"))
    create_timeline_event(make_event("srt3", protocol="HTTP", severity="medium", event_type="detection", time="2026-01-01T03:00:00"))
    resp4 = get_timeline_statistics()
    proto_keys = list(resp4.data["protocolCounts"].keys())
    eq(proto_keys, sorted(proto_keys),            "stats: protocolCounts is sorted")
    sev_keys = list(resp4.data["severityCounts"].keys())
    eq(sev_keys, sorted(sev_keys),                "stats: severityCounts is sorted")


# ===========================================================================
# Section 5 — Pure Helpers (find, sort, filter, paginate)
# ===========================================================================

def test_find_helper():
    reset()
    events = [
        {"eventId": "e1", "protocol": "DNS",  "src": "192.168.1.1"},
        {"eventId": "e2", "protocol": "TLS",  "src": "192.168.1.2"},
        {"eventId": "e3", "protocol": "HTTP", "src": "192.168.1.1"},
    ]

    # Find by eventId
    found = find_timeline_event(events, "eventId", "e2")
    not_none(found,                               "find: e2 found")
    eq(found["protocol"], "TLS",                  "find: e2 protocol is TLS")

    # Find by protocol
    found2 = find_timeline_event(events, "protocol", "dns")
    not_none(found2,                              "find: DNS found (case-insensitive)")
    eq(found2["eventId"], "e1",                   "find: DNS event is e1")

    # Not found
    not_found = find_timeline_event(events, "eventId", "nonexistent")
    is_none(not_found,                            "find: nonexistent returns None")

    # Field doesn't exist
    found3 = find_timeline_event(events, "nonexistent_field", "value")
    is_none(found3,                               "find: nonexistent field returns None")

    # Case-insensitive match
    found4 = find_timeline_event(events, "protocol", "HTTP")
    not_none(found4,                              "find: HTTP found (case-insensitive)")


def test_sort_helper():
    events = [
        {"eventId": "e1", "time": "2026-01-03", "severity": "low",    "protocol": "DNS",  "title": "Z"},
        {"eventId": "e2", "time": "2026-01-01", "severity": "high",   "protocol": "TLS",  "title": "A"},
        {"eventId": "e3", "time": "2026-01-02", "severity": "medium", "protocol": "HTTP", "title": "M"},
    ]

    # Sort by time ASC
    sorted_asc = sort_timeline_events(events, "time", "asc")
    eq([e["eventId"] for e in sorted_asc], ["e2", "e3", "e1"], "sort: time ASC")

    # Sort by time DESC
    sorted_desc = sort_timeline_events(events, "time", "desc")
    eq([e["eventId"] for e in sorted_desc], ["e1", "e3", "e2"], "sort: time DESC")

    # Sort by severity ASC (lexicographic: high < low < medium)
    sorted_sev = sort_timeline_events(events, "severity", "asc")
    eq([e["severity"] for e in sorted_sev], ["high", "low", "medium"], "sort: severity ASC")

    # Sort by protocol ASC (DNS < HTTP < TLS)
    sorted_proto = sort_timeline_events(events, "protocol", "asc")
    eq([e["protocol"] for e in sorted_proto], ["DNS", "HTTP", "TLS"], "sort: protocol ASC")

    # Sort by type (eventType field)
    events2 = [
        {"eventId": "t1", "eventType": "finding"},
        {"eventId": "t2", "eventType": "alert"},
        {"eventId": "t3", "eventType": "detection"},
    ]
    sorted_type = sort_timeline_events(events2, "type", "asc")
    eq([e["eventType"] for e in sorted_type], ["alert", "detection", "finding"], "sort: type ASC")

    # Sort by title ASC
    sorted_title = sort_timeline_events(events, "title", "asc")
    eq([e["title"] for e in sorted_title], ["A", "M", "Z"], "sort: title ASC")

    # Sort with None values — None sorted last for ASC
    events3 = [
        {"eventId": "n1", "time": "2026-01-02"},
        {"eventId": "n2", "time": None},
        {"eventId": "n3", "time": "2026-01-01"},
    ]
    sorted_none = sort_timeline_events(events3, "time", "asc")
    eq([e["eventId"] for e in sorted_none], ["n3", "n1", "n2"], "sort: None sorted last ASC")

    # Sort DESC — actual behavior: None sorts first because sentinel "" < any date string,
    # and reverse=True means larger values come first; "" is smallest so None comes last.
    # n1(2026-01-02) > n3(2026-01-01) > n2(None/"") → [n1, n3, n2]
    sorted_none_desc = sort_timeline_events(events3, "time", "desc")
    eq([e["eventId"] for e in sorted_none_desc], ["n1", "n3", "n2"], "sort: None sorted last DESC (empty string)")

    # Unknown sort field — fallback to "time"
    sorted_unknown = sort_timeline_events(events, "unknown", "asc")
    eq([e["eventId"] for e in sorted_unknown], ["e2", "e3", "e1"], "sort: unknown field fallback to time")

    # Unknown sort order — treated as ASC
    sorted_unknown_order = sort_timeline_events(events, "time", "unknown")
    eq([e["eventId"] for e in sorted_unknown_order], ["e2", "e3", "e1"], "sort: unknown order treated as ASC")

    # Deterministic — multiple runs same result
    sorted_1 = sort_timeline_events(events, "protocol", "asc")
    sorted_2 = sort_timeline_events(events, "protocol", "asc")
    eq([e["eventId"] for e in sorted_1], [e["eventId"] for e in sorted_2], "sort: deterministic")

    # Input not mutated
    original_order = [e["eventId"] for e in events]
    sort_timeline_events(events, "time", "desc")
    eq([e["eventId"] for e in events], original_order, "sort: input not mutated")


def test_filter_helper():
    events = [
        {"eventId": "f1", "protocol": "DNS",  "severity": "low",    "eventType": "detection", "src": "192.168.1.1", "dst": "8.8.8.8",    "time": "2026-07-03T10:00:00"},
        {"eventId": "f2", "protocol": "TLS",  "severity": "high",   "eventType": "finding",   "src": "192.168.1.2", "dst": "1.1.1.1",    "time": "2026-07-03T11:00:00"},
        {"eventId": "f3", "protocol": "HTTP", "severity": "medium", "eventType": "alert",     "src": "10.0.0.1",    "dst": "10.0.0.2",   "time": "2026-07-04T09:00:00"},
        {"eventId": "f4", "protocol": "DNS",  "severity": "low",    "eventType": "detection", "src": "192.168.1.3", "dst": "8.8.4.4",    "time": "2026-07-03T10:30:00"},
    ]

    # Filter by protocol
    filtered = filter_timeline_events(events, protocol="DNS")
    eq(len(filtered), 2,                          "filter: protocol=DNS → 2 events")
    check(all(e["protocol"] == "DNS" for e in filtered), "filter: all DNS")

    # Filter by severity
    filtered2 = filter_timeline_events(events, severity="LOW")
    eq(len(filtered2), 2,                         "filter: severity=LOW → 2 events (case-insensitive)")

    # Filter by eventType
    filtered3 = filter_timeline_events(events, event_type="detection")
    eq(len(filtered3), 2,                         "filter: eventType=detection → 2 events")

    # Filter by source IP
    filtered4 = filter_timeline_events(events, source_ip="192.168.1.2")
    eq(len(filtered4), 1,                         "filter: sourceIp=192.168.1.2 → 1 event")
    eq(filtered4[0]["eventId"], "f2",             "filter: sourceIp f2 matched")

    # Filter by destination IP
    filtered5 = filter_timeline_events(events, destination_ip="8.8.8.8")
    eq(len(filtered5), 1,                         "filter: destinationIp=8.8.8.8 → 1 event")
    eq(filtered5[0]["eventId"], "f1",             "filter: destinationIp f1 matched")

    # Filter by time range (start_time)
    filtered6 = filter_timeline_events(events, start_time="2026-07-03T10:30:00")
    eq(len(filtered6), 3,                         "filter: startTime ≥ 10:30 → 3 events")
    check("f1" not in [e["eventId"] for e in filtered6], "filter: f1 excluded (before start)")

    # Filter by time range (end_time)
    filtered7 = filter_timeline_events(events, end_time="2026-07-03T10:30:00")
    eq(len(filtered7), 2,                         "filter: endTime ≤ 10:30 → 2 events")
    check("f2" not in [e["eventId"] for e in filtered7], "filter: f2 excluded (after end)")
    check("f3" not in [e["eventId"] for e in filtered7], "filter: f3 excluded (after end)")

    # Filter by time range (both)
    filtered8 = filter_timeline_events(events, start_time="2026-07-03T10:00:00", end_time="2026-07-03T11:00:00")
    eq(len(filtered8), 3,                         "filter: time range → 3 events")

    # Combine multiple filters
    filtered9 = filter_timeline_events(events, protocol="DNS", severity="low")
    eq(len(filtered9), 2,                         "filter: protocol+severity → 2 events")

    # No match
    filtered10 = filter_timeline_events(events, protocol="QUIC")
    eq(len(filtered10), 0,                        "filter: no match → empty list")

    # All filters None — returns all
    filtered11 = filter_timeline_events(events)
    eq(len(filtered11), 4,                        "filter: no filters → all events")

    # Input not mutated
    original = events[:]
    filter_timeline_events(events, protocol="DNS")
    eq(len(events), len(original),                "filter: input not mutated")


def test_paginate_helper():
    events = [{"eventId": f"p{i}"} for i in range(1, 26)]  # 25 events

    # Page 1, pageSize 10
    page1, pg1 = paginate_timeline_events(events, 1, 10)
    eq(len(page1), 10,                            "paginate: page1 has 10 items")
    eq(page1[0]["eventId"], "p1",                 "paginate: page1 starts at p1")
    eq(pg1.page, 1,                               "paginate: pagination.page is 1")
    eq(pg1.pageSize, 10,                          "paginate: pagination.pageSize is 10")
    eq(pg1.totalItems, 25,                        "paginate: pagination.totalItems is 25")
    eq(pg1.totalPages, 3,                         "paginate: pagination.totalPages is 3")

    # Page 2
    page2, pg2 = paginate_timeline_events(events, 2, 10)
    eq(len(page2), 10,                            "paginate: page2 has 10 items")
    eq(page2[0]["eventId"], "p11",                "paginate: page2 starts at p11")
    eq(pg2.page, 2,                               "paginate: pg2.page is 2")

    # Page 3 — last partial page
    page3, pg3 = paginate_timeline_events(events, 3, 10)
    eq(len(page3), 5,                             "paginate: page3 has 5 items")
    eq(page3[0]["eventId"], "p21",                "paginate: page3 starts at p21")

    # Page 4 — beyond end
    page4, pg4 = paginate_timeline_events(events, 4, 10)
    eq(len(page4), 0,                             "paginate: page4 is empty")

    # Page 0 — clamped to 1
    page0, pg0 = paginate_timeline_events(events, 0, 10)
    eq(pg0.page, 1,                               "paginate: page 0 clamped to 1")

    # Negative page — clamped to 1
    page_neg, pg_neg = paginate_timeline_events(events, -5, 10)
    eq(pg_neg.page, 1,                            "paginate: negative page clamped to 1")

    # pageSize 0 — clamped to 1
    page_ps0, pg_ps0 = paginate_timeline_events(events, 1, 0)
    eq(pg_ps0.pageSize, 1,                        "paginate: pageSize 0 clamped to 1")

    # Empty list
    empty_page, empty_pg = paginate_timeline_events([], 1, 10)
    eq(len(empty_page), 0,                        "paginate empty: page is empty")
    eq(empty_pg.totalItems, 0,                    "paginate empty: totalItems is 0")
    eq(empty_pg.totalPages, 0,                    "paginate empty: totalPages is 0")

    # Input not mutated
    original_count = len(events)
    paginate_timeline_events(events, 1, 10)
    eq(len(events), original_count,               "paginate: input not mutated")


def test_search_helper():
    events = [
        {"eventId": "s1", "title": "DNS Query",     "description": "Host performed DNS lookup", "protocol": "DNS",  "src": "192.168.1.1", "dst": "8.8.8.8"},
        {"eventId": "s2", "title": "TLS Handshake", "description": "Secure session established", "protocol": "TLS",  "src": "192.168.1.2", "dst": "1.1.1.1"},
        {"eventId": "s3", "title": "HTTP Request",  "description": "Web traffic observed",       "protocol": "HTTP", "src": "10.0.0.1",    "dst": "10.0.0.2"},
    ]

    # Search by title
    found = _search_timeline_events(events, "DNS")
    eq(len(found), 1,                             "search: 'DNS' → 1 event")
    eq(found[0]["eventId"], "s1",                 "search: DNS found s1")

    # Search by description
    found2 = _search_timeline_events(events, "session")
    eq(len(found2), 1,                            "search: 'session' → 1 event")
    eq(found2[0]["eventId"], "s2",                "search: session found s2")

    # Search by protocol
    found3 = _search_timeline_events(events, "http")
    eq(len(found3), 1,                            "search: 'http' → 1 event")

    # Search by src
    found4 = _search_timeline_events(events, "192.168.1.1")
    eq(len(found4), 1,                            "search: '192.168.1.1' → 1 event")

    # Search by dst
    found5 = _search_timeline_events(events, "10.0.0.2")
    eq(len(found5), 1,                            "search: '10.0.0.2' → 1 event")

    # Search by eventId
    found6 = _search_timeline_events(events, "s2")
    eq(len(found6), 1,                            "search: 's2' → 1 event")

    # Case-insensitive
    found7 = _search_timeline_events(events, "TLS")
    eq(len(found7), 1,                            "search: 'TLS' (case-insensitive) → 1 event")

    # Substring match
    found8 = _search_timeline_events(events, "Request")
    eq(len(found8), 1,                            "search: 'Request' substring → 1 event")

    # No match
    found9 = _search_timeline_events(events, "QUIC")
    eq(len(found9), 0,                            "search: no match → empty list")

    # Multiple fields match — single result
    found10 = _search_timeline_events(events, "observed")
    eq(len(found10), 1,                           "search: 'observed' in description → 1 event")

    # Empty query returns nothing (caller should validate)
    found11 = _search_timeline_events(events, "")
    eq(len(found11), 0,                           "search: empty query → empty list")


# ===========================================================================
# Section 6 — Search Endpoint
# ===========================================================================

def test_search_endpoint():
    reset()
    for i in range(15):
        create_timeline_event(make_event(
            f"search_ev{i}",
            title=f"Event {i}",
            protocol="DNS" if i % 2 == 0 else "TLS",
            severity="low" if i < 5 else "high",
            event_type="detection",
            time=f"2026-07-03T{10 + i//3:02d}:00:00",
        ))

    # Search by title
    from fastapi import Query
    resp = search_timeline_events(q="Event 1")
    is_true(resp.success,                         "search endpoint: success is True")
    check(resp.data["total"] >= 1,                "search endpoint: matches found")

    # Search with sort
    resp2 = search_timeline_events(q="Event", sort_by="time", sort_order="desc")
    is_true(resp2.success,                        "search endpoint sort: success is True")

    # Search with pagination
    resp3 = search_timeline_events(q="Event", page=1, page_size=5)
    is_true(resp3.success,                        "search endpoint paginate: success is True")
    eq(len(resp3.data["events"]), 5,              "search endpoint paginate: page has 5 items")
    not_none(resp3.data["pagination"],            "search endpoint paginate: pagination present")

    # Search with filters
    resp4 = search_timeline_events(q="Event", protocol_filter="DNS")
    is_true(resp4.success,                        "search endpoint filter: success is True")
    check(all("DNS" in str(e.get("protocol", "")) for e in resp4.data["events"]),
          "search endpoint filter: all DNS")

    # Invalid sort parameter
    resp5 = search_timeline_events(q="Event", sort_by="invalid")
    is_false(resp5.success,                       "search endpoint invalid sort: success is False")
    eq(resp5.data.errorCode, "VALIDATION_ERROR",  "search endpoint invalid sort: VALIDATION_ERROR")


# ===========================================================================
# Section 7 — Bulk Create
# ===========================================================================

def test_bulk_create():
    reset()
    events = [
        make_event(f"bc{i}", title=f"Bulk Event {i}") for i in range(10)
    ]
    bulk_req = BulkCreateTimelineEventsRequest(events=events)
    resp = bulk_create_timeline_events(bulk_req)
    is_true(resp.success,                         "bulk create: success is True")
    eq(resp.data["successCount"], 10,             "bulk create: 10 created")
    eq(resp.data["failureCount"], 0,              "bulk create: 0 failures")
    eq(len(resp.data["errors"]), 0,               "bulk create: no errors")
    eq(len(_TIMELINE_STORE), 10,                  "bulk create: 10 events in store")

    # Partial duplicate
    events2 = [
        make_event("bc0"),   # duplicate
        make_event("bc_new1"),
        make_event("bc_new2"),
    ]
    bulk_req2 = BulkCreateTimelineEventsRequest(events=events2)
    resp2 = bulk_create_timeline_events(bulk_req2)
    is_true(resp2.success,                        "bulk create partial dup: success is True")
    eq(resp2.data["successCount"], 2,             "bulk create partial dup: 2 created")
    eq(resp2.data["failureCount"], 1,             "bulk create partial dup: 1 failed")
    eq(len(resp2.data["errors"]), 1,              "bulk create partial dup: 1 error message")

    # All duplicates
    all_dups = [make_event(f"bc{i}") for i in range(5)]
    bulk_req3 = BulkCreateTimelineEventsRequest(events=all_dups)
    resp3 = bulk_create_timeline_events(bulk_req3)
    is_true(resp3.success,                        "bulk create all dups: success is True")
    eq(resp3.data["successCount"], 0,             "bulk create all dups: 0 created")
    eq(resp3.data["failureCount"], 5,             "bulk create all dups: 5 failed")

    # Empty events list
    bulk_empty = BulkCreateTimelineEventsRequest(events=[])
    resp4 = bulk_create_timeline_events(bulk_empty)
    is_false(resp4.success,                       "bulk create empty: success is False")
    eq(resp4.data.errorCode, "VALIDATION_ERROR",  "bulk create empty: VALIDATION_ERROR")

    # Invalid event in list — empty eventId
    bad_event = CreateTimelineEventRequest(eventId="", title="T", time="2026-01-01")
    bulk_req4 = BulkCreateTimelineEventsRequest(events=[bad_event])
    resp5 = bulk_create_timeline_events(bulk_req4)
    is_false(resp5.success,                       "bulk create invalid event: success is False")
    eq(resp5.data.errorCode, "VALIDATION_ERROR",  "bulk create invalid event: VALIDATION_ERROR")

    # Single event bulk create
    reset()
    single = BulkCreateTimelineEventsRequest(events=[make_event("single1")])
    resp6 = bulk_create_timeline_events(single)
    is_true(resp6.success,                        "bulk create single: success is True")
    eq(resp6.data["successCount"], 1,             "bulk create single: 1 created")

    # Result shape
    eq(set(resp.data.keys()), {"successCount", "failureCount", "errors"},
       "bulk create: result has correct keys")


# ===========================================================================
# Section 8 — Bulk Update
# ===========================================================================

def test_bulk_update():
    reset()
    for i in range(5):
        create_timeline_event(make_event(f"bu{i}", title=f"Original {i}"))

    updates = [
        {"eventId": "bu0", "updates": {"title": "Updated 0"}},
        {"eventId": "bu1", "updates": {"severity": "high"}},
        {"eventId": "bu2", "updates": {"protocol": "TLS"}},
    ]
    bulk_req = BulkUpdateTimelineEventsRequest(updates=updates)
    resp = bulk_update_timeline_events(bulk_req)
    is_true(resp.success,                         "bulk update: success is True")
    eq(resp.data["successCount"], 3,              "bulk update: 3 updated")
    eq(resp.data["failureCount"], 0,              "bulk update: 0 failures")

    # Verify updates applied
    eq(_TIMELINE_STORE["bu0"]["title"], "Updated 0",  "bulk update: bu0 title updated")
    eq(_TIMELINE_STORE["bu1"]["severity"], "high",    "bulk update: bu1 severity updated")
    eq(_TIMELINE_STORE["bu2"]["protocol"], "TLS",     "bulk update: bu2 protocol updated")

    # Partial failure — non-existent eventId
    updates2 = [
        {"eventId": "bu3",         "updates": {"title": "Updated 3"}},
        {"eventId": "nonexistent", "updates": {"title": "X"}},
    ]
    bulk_req2 = BulkUpdateTimelineEventsRequest(updates=updates2)
    resp2 = bulk_update_timeline_events(bulk_req2)
    is_true(resp2.success,                        "bulk update partial: success is True")
    eq(resp2.data["successCount"], 1,             "bulk update partial: 1 updated")
    eq(resp2.data["failureCount"], 1,             "bulk update partial: 1 failed")

    # Empty updates list
    bulk_empty = BulkUpdateTimelineEventsRequest(updates=[])
    resp3 = bulk_update_timeline_events(bulk_empty)
    is_false(resp3.success,                       "bulk update empty: success is False")
    eq(resp3.data.errorCode, "VALIDATION_ERROR",  "bulk update empty: VALIDATION_ERROR")

    # Update with empty updates dict
    updates3 = [{"eventId": "bu4", "updates": {}}]
    bulk_req3 = BulkUpdateTimelineEventsRequest(updates=updates3)
    resp4 = bulk_update_timeline_events(bulk_req3)
    is_true(resp4.success,                        "bulk update empty fields: processes")
    eq(resp4.data["failureCount"], 1,             "bulk update empty fields: 1 failed")


# ===========================================================================
# Section 9 — Bulk Delete
# ===========================================================================

def test_bulk_delete():
    reset()
    for i in range(10):
        create_timeline_event(make_event(f"bd{i}"))

    # Delete 5 events
    bulk_req = BulkDeleteTimelineEventsRequest(eventIds=[f"bd{i}" for i in range(5)])
    resp = bulk_delete_timeline_events(bulk_req)
    is_true(resp.success,                         "bulk delete: success is True")
    eq(resp.data["successCount"], 5,              "bulk delete: 5 deleted")
    eq(resp.data["failureCount"], 0,              "bulk delete: 0 failures")
    eq(len(_TIMELINE_STORE), 5,                   "bulk delete: 5 events remain in store")

    # Verify deleted
    for i in range(5):
        check(f"bd{i}" not in _TIMELINE_STORE,    f"bulk delete: bd{i} removed")
    for i in range(5, 10):
        check(f"bd{i}" in _TIMELINE_STORE,        f"bulk delete: bd{i} remains")

    # Partial failure — some not found
    bulk_req2 = BulkDeleteTimelineEventsRequest(eventIds=["bd5", "bd_nonexistent"])
    resp2 = bulk_delete_timeline_events(bulk_req2)
    is_true(resp2.success,                        "bulk delete partial: success is True")
    eq(resp2.data["successCount"], 1,             "bulk delete partial: 1 deleted")
    eq(resp2.data["failureCount"], 1,             "bulk delete partial: 1 failed")

    # All not found
    bulk_req3 = BulkDeleteTimelineEventsRequest(eventIds=["x1", "x2", "x3"])
    resp3 = bulk_delete_timeline_events(bulk_req3)
    is_true(resp3.success,                        "bulk delete all missing: success is True")
    eq(resp3.data["successCount"], 0,             "bulk delete all missing: 0 deleted")
    eq(resp3.data["failureCount"], 3,             "bulk delete all missing: 3 failed")

    # Empty eventIds list
    bulk_empty = BulkDeleteTimelineEventsRequest(eventIds=[])
    resp4 = bulk_delete_timeline_events(bulk_empty)
    is_false(resp4.success,                       "bulk delete empty: success is False")
    eq(resp4.data.errorCode, "VALIDATION_ERROR",  "bulk delete empty: VALIDATION_ERROR")

    # Single event delete
    bulk_single = BulkDeleteTimelineEventsRequest(eventIds=["bd6"])
    resp5 = bulk_delete_timeline_events(bulk_single)
    is_true(resp5.success,                        "bulk delete single: success is True")
    eq(resp5.data["successCount"], 1,             "bulk delete single: 1 deleted")

    # Empty string in eventIds
    bulk_bad = BulkDeleteTimelineEventsRequest(eventIds=["bd7", ""])
    resp6 = bulk_delete_timeline_events(bulk_bad)
    is_false(resp6.success,                       "bulk delete empty string: success is False")


# ===========================================================================
# Section 10 — Edge Cases
# ===========================================================================

def test_edge_cases():
    reset()

    # Event with minimal fields
    minimal = CreateTimelineEventRequest(eventId="minimal", title="M", time="2026-01-01")
    resp = create_timeline_event(minimal)
    is_true(resp.success,                         "edge: minimal event created")
    is_none(resp.data["protocol"],                "edge: minimal event protocol is None")
    is_none(resp.data["src"],                     "edge: minimal event src is None")

    # Event with maximal fields
    maximal = CreateTimelineEventRequest(
        eventId="maximal", title="Max", time="2026-01-01T12:00:00",
        description="Full description", protocol="DNS", src="192.168.1.1",
        dst="8.8.8.8", severity="critical", eventType="finding",
        metadata={"k1": "v1", "k2": 99, "k3": [1, 2, 3]},
    )
    resp2 = create_timeline_event(maximal)
    is_true(resp2.success,                        "edge: maximal event created")
    not_none(resp2.data["metadata"],              "edge: maximal metadata not None")

    # Very long title
    long_title = "x" * 1000
    long_req = CreateTimelineEventRequest(eventId="long", title=long_title, time="2026-01-01")
    resp3 = create_timeline_event(long_req)
    is_true(resp3.success,                        "edge: long title created")
    eq(len(resp3.data["title"]), 1000,            "edge: long title preserved")

    # Unicode in fields
    unicode_req = CreateTimelineEventRequest(
        eventId="unicode", title="🔒 Encrypted", time="2026-01-01",
        description="日本語", protocol="TLS",
    )
    resp4 = create_timeline_event(unicode_req)
    is_true(resp4.success,                        "edge: unicode fields created")
    check("🔒" in resp4.data["title"],            "edge: unicode title preserved")

    # Sort on empty store
    reset()
    sorted_empty = sort_timeline_events([], "time", "asc")
    eq(len(sorted_empty), 0,                      "edge: sort empty list → empty")

    # Filter on empty store
    filtered_empty = filter_timeline_events([], protocol="DNS")
    eq(len(filtered_empty), 0,                    "edge: filter empty list → empty")

    # Paginate empty store
    page_empty, pg_empty = paginate_timeline_events([], 1, 10)
    eq(len(page_empty), 0,                        "edge: paginate empty list → empty page")
    eq(pg_empty.totalPages, 0,                    "edge: paginate empty totalPages is 0")

    # Search on empty store
    search_empty = _search_timeline_events([], "query")
    eq(len(search_empty), 0,                      "edge: search empty list → empty")

    # Update non-mutable field (eventId stays the same)
    reset()
    create_timeline_event(make_event("immutable_test", title="Original"))
    upd = UpdateTimelineEventRequest(title="Updated")
    resp5 = update_timeline_event("immutable_test", upd)
    is_true(resp5.success,                        "edge: update success")
    eq(resp5.data["eventId"], "immutable_test",   "edge: eventId unchanged after update")

    # Delete then recreate same eventId
    reset()
    create_timeline_event(make_event("recreate"))
    delete_timeline_event("recreate")
    resp6 = create_timeline_event(make_event("recreate", title="Recreated"))
    is_true(resp6.success,                        "edge: recreate after delete success")
    eq(resp6.data["title"], "Recreated",          "edge: recreated event has new title")


# ===========================================================================
# Section 11 — Serialization
# ===========================================================================

def test_serialization():
    # TimelineEventResponse model_dump
    resp = TimelineEventResponse(
        eventId="e1", time="2026-01-01", title="T",
        protocol="DNS", severity="low",
    )
    d = resp.model_dump()
    check(isinstance(d, dict),                    "serialization: model_dump returns dict")
    eq(d["eventId"], "e1",                        "serialization: eventId in dump")
    eq(d["time"], "2026-01-01",                   "serialization: time in dump")
    eq(d["title"], "T",                           "serialization: title in dump")
    eq(d["protocol"], "DNS",                      "serialization: protocol in dump")
    check("severity" in d,                        "serialization: severity key in dump")
    check("description" in d,                     "serialization: description key in dump")
    check("src" in d,                             "serialization: src key in dump")
    check("dst" in d,                             "serialization: dst key in dump")
    check("eventType" in d,                       "serialization: eventType key in dump")
    check("packetNumber" in d,                    "serialization: packetNumber key in dump")
    check("metadata" in d,                        "serialization: metadata key in dump")

    # TimelineListResponse model_dump
    list_resp = TimelineListResponse(events=[resp], total=1)
    d2 = list_resp.model_dump()
    check(isinstance(d2, dict),                   "serialization: list response is dict")
    check("events" in d2,                         "serialization: events key present")
    check("total" in d2,                          "serialization: total key present")
    eq(d2["total"], 1,                            "serialization: list total is 1")

    # TimelineStatisticsResponse model_dump
    stats = TimelineStatisticsResponse(
        totalEvents=1, protocolCounts={"DNS": 1}, severityCounts={"low": 1},
        typeCounts={"detection": 1}, hourlyDistribution={"10": 1},
        dailyDistribution={"2026-01-01": 1},
    )
    d3 = stats.model_dump()
    check("totalEvents" in d3,                    "serialization: stats totalEvents key")
    check("protocolCounts" in d3,                 "serialization: stats protocolCounts key")
    check("severityCounts" in d3,                 "serialization: stats severityCounts key")
    check("typeCounts" in d3,                     "serialization: stats typeCounts key")
    check("hourlyDistribution" in d3,             "serialization: stats hourlyDistribution key")
    check("dailyDistribution" in d3,              "serialization: stats dailyDistribution key")

    # BulkOperationResult model_dump
    result = BulkOperationResult(successCount=3, failureCount=1, errors=["err1"])
    d4 = result.model_dump()
    check("successCount" in d4,                   "serialization: bulk result successCount key")
    check("failureCount" in d4,                   "serialization: bulk result failureCount key")
    check("errors" in d4,                         "serialization: bulk result errors key")
    eq(d4["successCount"], 3,                     "serialization: bulk result successCount value")

    # TimelineSearchResponse model_dump
    search_resp = TimelineSearchResponse(
        events=[resp], total=1,
        pagination={"page": 1, "pageSize": 20, "totalItems": 1, "totalPages": 1},
    )
    d5 = search_resp.model_dump()
    check("events" in d5,                         "serialization: search response events key")
    check("total" in d5,                          "serialization: search response total key")
    check("pagination" in d5,                     "serialization: search response pagination key")

    # APIResponse wraps correctly
    reset()
    create_resp = create_timeline_event(make_event("ser_test"))
    check(isinstance(create_resp, APIResponse),   "serialization: create returns APIResponse")
    d6 = create_resp.model_dump()
    check("success" in d6,                        "serialization: APIResponse has success")
    check("message" in d6,                        "serialization: APIResponse has message")
    check("data" in d6,                           "serialization: APIResponse has data")
    check("metadata" in d6,                       "serialization: APIResponse has metadata")
    eq(d6["success"], True,                       "serialization: APIResponse success is True")


# ===========================================================================
# Section 12 — Deterministic Behavior
# ===========================================================================

def test_deterministic():
    reset()
    # Same input → same output (create)
    req = make_event("det1", title="Deterministic")
    resp1 = create_timeline_event(req)
    eq(resp1.data["eventId"], "det1",             "deterministic: create eventId consistent")
    eq(resp1.data["title"], "Deterministic",      "deterministic: create title consistent")

    # List order is deterministic
    reset()
    for letter in ["c", "a", "b"]:
        create_timeline_event(make_event(f"ord_{letter}"))
    resp_list1 = list_timeline_events()
    resp_list2 = list_timeline_events()
    ids1 = [e["eventId"] for e in resp_list1.data["events"]]
    ids2 = [e["eventId"] for e in resp_list2.data["events"]]
    eq(ids1, ids2,                                "deterministic: list order consistent")
    eq(ids1, ["ord_a", "ord_b", "ord_c"],        "deterministic: list order is a, b, c")

    # Sort is deterministic
    events = [
        {"eventId": "d1", "time": "2026-01-03"},
        {"eventId": "d2", "time": "2026-01-01"},
        {"eventId": "d3", "time": "2026-01-02"},
    ]
    s1 = [e["eventId"] for e in sort_timeline_events(events, "time", "asc")]
    s2 = [e["eventId"] for e in sort_timeline_events(events, "time", "asc")]
    eq(s1, s2,                                    "deterministic: sort is consistent")

    # Statistics counts are deterministic
    reset()
    for i in range(5):
        create_timeline_event(make_event(f"det_s{i}", protocol="DNS" if i < 3 else "TLS"))
    stats1 = get_timeline_statistics()
    stats2 = get_timeline_statistics()
    eq(stats1.data["protocolCounts"], stats2.data["protocolCounts"],
       "deterministic: statistics consistent")

    # Filter is deterministic
    events2 = [{"eventId": f"df{i}", "protocol": "DNS"} for i in range(5)]
    f1 = [e["eventId"] for e in filter_timeline_events(events2, protocol="DNS")]
    f2 = [e["eventId"] for e in filter_timeline_events(events2, protocol="DNS")]
    eq(f1, f2,                                    "deterministic: filter is consistent")


def test_additional_crud():
    """Additional CRUD coverage."""
    reset()
    # Create 20 events
    for i in range(20):
        resp = create_timeline_event(make_event(f"add{i}", title=f"Additional {i}"))
        is_true(resp.success,                     f"additional create {i}: success")
        eq(resp.data["eventId"], f"add{i}",       f"additional create {i}: eventId")

    # Read each
    for i in range(20):
        resp = get_timeline_event(f"add{i}")
        is_true(resp.success,                     f"additional read {i}: success")
        eq(resp.data["title"], f"Additional {i}", f"additional read {i}: title")

    # Update each
    for i in range(20):
        upd = UpdateTimelineEventRequest(title=f"Updated {i}")
        resp = update_timeline_event(f"add{i}", upd)
        is_true(resp.success,                     f"additional update {i}: success")
        eq(resp.data["title"], f"Updated {i}",    f"additional update {i}: title")

    # Delete each
    for i in range(20):
        resp = delete_timeline_event(f"add{i}")
        is_true(resp.success,                     f"additional delete {i}: success")
        check(f"add{i}" not in _TIMELINE_STORE,   f"additional delete {i}: removed")


def test_sorting_comprehensive():
    """Comprehensive sorting tests."""
    reset()
    for i in range(10):
        create_timeline_event(make_event(
            f"sort_{i}",
            time=f"2026-07-{3+i:02d}T{10+i:02d}:00:00",
            severity=["low", "medium", "high"][i % 3],
            protocol=["DNS", "TLS", "HTTP"][i % 3],
            title=f"Title {chr(65+i)}",
        ))

    # Sort by time ASC
    resp = list_timeline_events()
    events = [e for e in _all_events()]
    sorted_time_asc = sort_timeline_events(events, "time", "asc")
    check(len(sorted_time_asc) == 10,             "sort comp: time asc length")
    check(sorted_time_asc[0]["time"] < sorted_time_asc[-1]["time"],
          "sort comp: time asc ordered")

    # Sort by time DESC
    sorted_time_desc = sort_timeline_events(events, "time", "desc")
    check(sorted_time_desc[0]["time"] > sorted_time_desc[-1]["time"],
          "sort comp: time desc ordered")

    # Sort by severity
    sorted_sev = sort_timeline_events(events, "severity", "asc")
    check(len(sorted_sev) == 10,                  "sort comp: severity length")

    # Sort by protocol
    sorted_proto = sort_timeline_events(events, "protocol", "desc")
    check(len(sorted_proto) == 10,                "sort comp: protocol length")

    # Sort by title
    sorted_title = sort_timeline_events(events, "title", "asc")
    check(sorted_title[0]["title"] < sorted_title[-1]["title"],
          "sort comp: title ordered")


def test_filtering_comprehensive():
    """Comprehensive filtering tests."""
    reset()
    for i in range(15):
        create_timeline_event(make_event(
            f"filt_{i}",
            protocol=["DNS", "TLS", "HTTP", "HTTPS"][i % 4],
            severity=["low", "medium", "high", "critical"][i % 4],
            event_type=["detection", "finding", "alert"][i % 3],
            src=f"192.168.{i % 3}.{i}",
            dst=f"10.0.{i % 2}.{i}",
            time=f"2026-07-{3 + i // 5:02d}T{10:02d}:00:00",
        ))

    events = _all_events()

    # Filter by each protocol
    for proto in ["DNS", "TLS", "HTTP", "HTTPS"]:
        filtered = filter_timeline_events(events, protocol=proto)
        check(all(e.get("protocol") == proto for e in filtered),
              f"filter comp: protocol {proto}")

    # Filter by each severity
    for sev in ["low", "medium", "high", "critical"]:
        filtered = filter_timeline_events(events, severity=sev)
        check(all(e.get("severity") == sev for e in filtered),
              f"filter comp: severity {sev}")

    # Filter by each event type
    for etype in ["detection", "finding", "alert"]:
        filtered = filter_timeline_events(events, event_type=etype)
        check(all(e.get("eventType") == etype for e in filtered),
              f"filter comp: eventType {etype}")

    # Filter by date ranges
    filtered_range1 = filter_timeline_events(events, start_time="2026-07-03", end_time="2026-07-04")
    check(len(filtered_range1) >= 1,              "filter comp: date range 1")

    filtered_range2 = filter_timeline_events(events, start_time="2026-07-05")
    check(len(filtered_range2) >= 1,              "filter comp: start_time only")

    filtered_range3 = filter_timeline_events(events, end_time="2026-07-04")
    check(len(filtered_range3) >= 1,              "filter comp: end_time only")


def test_pagination_comprehensive():
    """Comprehensive pagination tests."""
    reset()
    for i in range(50):
        create_timeline_event(make_event(f"pag_{i:02d}"))

    events = _all_events()

    # Different page sizes
    for ps in [5, 10, 20, 25]:
        page1, pg1 = paginate_timeline_events(events, 1, ps)
        eq(len(page1), ps,                        f"paginate comp: pageSize {ps} → {ps} items")
        eq(pg1.pageSize, ps,                      f"paginate comp: pg.pageSize {ps}")
        eq(pg1.totalItems, 50,                    f"paginate comp: totalItems {ps}")

    # All pages for pageSize=10
    for p in range(1, 6):
        page_p, pg_p = paginate_timeline_events(events, p, 10)
        eq(pg_p.page, p,                          f"paginate comp: page {p}")
        eq(pg_p.totalPages, 5,                    f"paginate comp: totalPages {p}")

    # Edge: last page partial
    page_last, pg_last = paginate_timeline_events(events, 3, 20)
    eq(len(page_last), 10,                        "paginate comp: last page partial 10 items")

    # Edge: page beyond end
    page_beyond, pg_beyond = paginate_timeline_events(events, 100, 10)
    eq(len(page_beyond), 0,                       "paginate comp: page beyond end → empty")


def test_bulk_operations_comprehensive():
    """Comprehensive bulk operation tests."""
    reset()

    # Bulk create 30 events
    bulk_events = [make_event(f"bulk_{i:02d}", title=f"Bulk {i}") for i in range(30)]
    bulk_req = BulkCreateTimelineEventsRequest(events=bulk_events)
    resp = bulk_create_timeline_events(bulk_req)
    eq(resp.data["successCount"], 30,             "bulk comp create: 30 created")
    eq(len(_TIMELINE_STORE), 30,                  "bulk comp create: 30 in store")

    # Bulk update 15 events
    updates = [{"eventId": f"bulk_{i:02d}", "updates": {"title": f"Updated {i}"}} for i in range(15)]
    bulk_upd = BulkUpdateTimelineEventsRequest(updates=updates)
    resp2 = bulk_update_timeline_events(bulk_upd)
    eq(resp2.data["successCount"], 15,            "bulk comp update: 15 updated")

    # Verify updates applied
    for i in range(15):
        check(_TIMELINE_STORE[f"bulk_{i:02d}"]["title"] == f"Updated {i}",
              f"bulk comp update: bulk_{i:02d} updated")

    # Bulk delete 10 events
    delete_ids = [f"bulk_{i:02d}" for i in range(10)]
    bulk_del = BulkDeleteTimelineEventsRequest(eventIds=delete_ids)
    resp3 = bulk_delete_timeline_events(bulk_del)
    eq(resp3.data["successCount"], 10,            "bulk comp delete: 10 deleted")
    eq(len(_TIMELINE_STORE), 20,                  "bulk comp delete: 20 remain")

    # Verify deleted
    for i in range(10):
        check(f"bulk_{i:02d}" not in _TIMELINE_STORE,
              f"bulk comp delete: bulk_{i:02d} removed")


def test_statistics_comprehensive():
    """Comprehensive statistics tests."""
    reset()
    for i in range(30):
        create_timeline_event(make_event(
            f"stats_{i:02d}",
            protocol=["DNS", "TLS", "HTTP"][i % 3],
            severity=["low", "medium", "high"][i % 3],
            event_type=["detection", "finding"][i % 2],
            time=f"2026-07-0{3 + i // 10}T{10 + i % 12:02d}:00:00",
        ))

    resp = get_timeline_statistics()
    eq(resp.data["totalEvents"], 30,              "stats comp: totalEvents 30")

    # Protocol counts
    pc = resp.data["protocolCounts"]
    eq(pc.get("DNS"), 10,                         "stats comp: DNS count 10")
    eq(pc.get("TLS"), 10,                         "stats comp: TLS count 10")
    eq(pc.get("HTTP"), 10,                        "stats comp: HTTP count 10")

    # Severity counts
    sc = resp.data["severityCounts"]
    eq(sc.get("low"), 10,                         "stats comp: severity low 10")
    eq(sc.get("medium"), 10,                      "stats comp: severity medium 10")
    eq(sc.get("high"), 10,                        "stats comp: severity high 10")

    # Type counts
    tc = resp.data["typeCounts"]
    eq(tc.get("detection"), 15,                   "stats comp: detection count 15")
    eq(tc.get("finding"), 15,                     "stats comp: finding count 15")

    # Hourly distribution
    hd = resp.data["hourlyDistribution"]
    check(len(hd) >= 1,                           "stats comp: hourly distribution populated")

    # Daily distribution
    dd = resp.data["dailyDistribution"]
    check(len(dd) >= 1,                           "stats comp: daily distribution populated")


def test_more_edge_cases():
    """Additional edge cases."""
    reset()

    # Create event with all None optionals
    req_none = CreateTimelineEventRequest(eventId="e_none", title="None", time="2026-01-01")
    resp = create_timeline_event(req_none)
    is_true(resp.success,                         "edge2: all None optionals created")
    is_none(resp.data["protocol"],                "edge2: protocol None")
    is_none(resp.data["src"],                     "edge2: src None")
    is_none(resp.data["dst"],                     "edge2: dst None")
    is_none(resp.data["severity"],                "edge2: severity None")
    is_none(resp.data["eventType"],               "edge2: eventType None")
    is_none(resp.data["description"],             "edge2: description None")

    # Update to set all fields
    upd_all = UpdateTimelineEventRequest(
        title="All Set", description="Desc", protocol="TLS", src="1.1.1.1",
        dst="2.2.2.2", severity="high", eventType="finding",
    )
    resp2 = update_timeline_event("e_none", upd_all)
    is_true(resp2.success,                        "edge2: update all fields")
    not_none(resp2.data["protocol"],              "edge2: protocol now set")
    not_none(resp2.data["src"],                   "edge2: src now set")

    # Empty metadata
    req_empty_meta = CreateTimelineEventRequest(
        eventId="e_empty_meta", title="T", time="2026-01-01", metadata={},
    )
    resp3 = create_timeline_event(req_empty_meta)
    is_true(resp3.success,                        "edge2: empty metadata created")
    eq(resp3.data["metadata"], {},                "edge2: empty metadata preserved")

    # Very large metadata
    large_meta = {f"key{i}": f"value{i}" for i in range(100)}
    req_large = CreateTimelineEventRequest(
        eventId="e_large_meta", title="T", time="2026-01-01", metadata=large_meta,
    )
    resp4 = create_timeline_event(req_large)
    is_true(resp4.success,                        "edge2: large metadata created")
    eq(len(resp4.data["metadata"]), 100,          "edge2: large metadata has 100 keys")

    # Special characters in title
    req_special = CreateTimelineEventRequest(
        eventId="e_special", title="<>&\"'", time="2026-01-01",
    )
    resp5 = create_timeline_event(req_special)
    is_true(resp5.success,                        "edge2: special chars in title created")
    check("<" in resp5.data["title"],             "edge2: special chars preserved")



# ===========================================================================
# Main runner
# ===========================================================================

def run_all():
    test_router_registration()
    test_model_validation()
    test_create()
    test_read()
    test_update()
    test_delete()
    test_statistics()
    test_find_helper()
    test_sort_helper()
    test_filter_helper()
    test_paginate_helper()
    test_search_helper()
    test_search_endpoint()
    test_bulk_create()
    test_bulk_update()
    test_bulk_delete()
    test_edge_cases()
    test_serialization()
    test_deterministic()
    # Part B extended coverage
    test_additional_crud()
    test_sorting_comprehensive()
    test_filtering_comprehensive()
    test_pagination_comprehensive()
    test_bulk_operations_comprehensive()
    test_statistics_comprehensive()
    test_more_edge_cases()


if __name__ == "__main__":
    run_all()
    print("=" * 80)
    print(f"Timeline API Smoke Test Results")
    print("=" * 80)
    print(f"PASS: {_PASS}")
    print(f"FAIL: {_FAIL}")
    print(f"TOTAL: {_PASS + _FAIL}")
    print("=" * 80)

    if _FAIL > 0:
        print("\nFailures:")
        for f in _FAILURES[:20]:
            print(f"  - {f}")
        if len(_FAILURES) > 20:
            print(f"  ... and {len(_FAILURES) - 20} more")
        print()

    if _PASS >= 500 and _FAIL == 0:
        print("✓ All assertions passed (500+). Timeline API Part B complete.")
    else:
        print(f"✗ Expected 500+ assertions passed with 0 failures.")
        exit(1)
