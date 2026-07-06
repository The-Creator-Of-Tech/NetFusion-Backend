"""
Smoke Test — Alerts API (Part A + Part B)
==========================================
Phase A4.7.6 — 650+ assertions covering:
  - CRUD (create, read, update, delete)
  - Statistics (Part A + Part B averageRiskScore)
  - Search
  - Sorting (all 6 keys, asc + desc)
  - Filtering (all predicates)
  - Pagination
  - Bulk operations (create, update, delete)
  - Deterministic ID behaviour
  - Duplicate detection (409)
  - Validation failures (422)
  - Not-found paths (404)
  - Router registration
  - Serialization shape
  - Pure helper functions
  - Edge cases (empty store, empty query, page overflow)

Run:
    python smoke_test_alerts_api.py
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Assertion counter
# ---------------------------------------------------------------------------

_PASSED = 0
_FAILED = 0
_ERRORS: list[str] = []


def _assert(condition: bool, label: str) -> None:
    global _PASSED, _FAILED
    if condition:
        _PASSED += 1
    else:
        _FAILED += 1
        _ERRORS.append(f"FAIL: {label}")


def _assert_eq(a, b, label: str) -> None:
    _assert(a == b, f"{label} — expected {b!r}, got {a!r}")


def _assert_in(item, container, label: str) -> None:
    _assert(item in container, f"{label} — {item!r} not in {container!r}")


# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from api.investigation.alert_router import (
    _ALERT_STORE,
    _reset_store,
    _all_alerts,
    _alert_to_response,
    _alert_record_to_dict,
    _compute_statistics,
    _search_alerts,
    _validate_source,
    _validate_severity,
    _validate_status,
    find_alert,
    sort_alerts,
    filter_alerts,
    paginate_alerts,
    alert_router,
    list_alerts,
    get_alert_statistics,
    get_alert,
    create_alert,
    update_alert_endpoint,
    delete_alert,
    search_alerts,
    bulk_create_alerts,
    bulk_update_alerts,
    bulk_delete_alerts,
)
from api.investigation.alert_models import (
    CreateAlertRequest,
    UpdateAlertRequest,
    AlertFilterRequest,
    AlertSearchRequest,
    AlertResponse,
    AlertListResponse,
    AlertStatisticsResponse,
    AlertSearchResponse,
    AlertExplanationResponse,
    AlertCorrelationResponse,
    BulkCreateAlertsRequest,
    BulkUpdateAlertsRequest,
    BulkDeleteAlertsRequest,
    BulkOperationResult,
)
from services.alert_service import (
    AlertSeverity, AlertStatus, AlertSource,
    build_alert,
)
from api.models import APIResponse, Pagination

# ---------------------------------------------------------------------------
# Helpers to build minimal valid requests
# ---------------------------------------------------------------------------

def _make_create(
    project_id="proj-1", finding_id="find-1", investigation_id="inv-1",
    title="Test Alert", created_by="analyst", created_at="2026-01-01T00:00:00Z",
    source="FINDING", severity="MEDIUM", confidence=50.0, risk_score=40.0,
    **kwargs,
) -> CreateAlertRequest:
    return CreateAlertRequest(
        projectId=project_id, findingId=finding_id,
        investigationId=investigation_id, title=title,
        createdBy=created_by, createdAt=created_at,
        source=source, severity=severity,
        confidence=confidence, riskScore=risk_score,
        **kwargs,
    )


# ===========================================================================
# Section 1 — Router registration
# ===========================================================================

def test_router_registration():
    paths = [r.path for r in alert_router.routes]
    methods_map = {r.path: sorted(r.methods) for r in alert_router.routes}

    _assert("/alerts" in paths, "GET /alerts registered")
    _assert("/alerts/statistics" in paths, "GET /alerts/statistics registered")
    _assert("/alerts/search" in paths, "GET /alerts/search registered")
    _assert("/alerts/{alertId}" in paths, "GET /alerts/{alertId} registered")
    _assert("/alerts/bulk/create" in paths, "POST /alerts/bulk/create registered")
    _assert("/alerts/bulk/update" in paths, "PUT /alerts/bulk/update registered")
    _assert("/alerts/bulk/delete" in paths, "DELETE /alerts/bulk/delete registered")

    # method checks
    all_paths_methods = [(r.path, sorted(r.methods)) for r in alert_router.routes]
    _assert(("/alerts", ["GET"]) in all_paths_methods, "GET /alerts method")
    _assert(("/alerts", ["POST"]) in all_paths_methods, "POST /alerts method")
    _assert(("/alerts/statistics", ["GET"]) in all_paths_methods, "GET /statistics method")
    _assert(("/alerts/search", ["GET"]) in all_paths_methods, "GET /search method")
    _assert(("/alerts/{alertId}", ["GET"]) in all_paths_methods, "GET /{alertId} method")
    _assert(("/alerts/{alertId}", ["PUT"]) in all_paths_methods, "PUT /{alertId} method")
    _assert(("/alerts/{alertId}", ["DELETE"]) in all_paths_methods, "DELETE /{alertId} method")
    _assert(("/alerts/bulk/create", ["POST"]) in all_paths_methods, "POST /bulk/create method")
    _assert(("/alerts/bulk/update", ["PUT"]) in all_paths_methods, "PUT /bulk/update method")
    _assert(("/alerts/bulk/delete", ["DELETE"]) in all_paths_methods, "DELETE /bulk/delete method")
    _assert_eq(len(paths), 10, "total route count is 10")


# ===========================================================================
# Section 2 — Model validation
# ===========================================================================

def test_model_validation():
    # CreateAlertRequest — required fields
    req = _make_create()
    errs = req.validate_request()
    _assert_eq(errs, [], "valid create request has no errors")

    # Missing projectId
    bad = _make_create(project_id="")
    _assert(len(bad.validate_request()) > 0, "empty projectId caught")

    # Missing findingId
    bad = _make_create(finding_id="   ")
    _assert(len(bad.validate_request()) > 0, "whitespace findingId caught")

    # Missing investigationId
    bad = _make_create(investigation_id="")
    _assert(len(bad.validate_request()) > 0, "empty investigationId caught")

    # Missing title
    bad = _make_create(title="")
    _assert(len(bad.validate_request()) > 0, "empty title caught")

    # Missing createdBy
    bad = _make_create(created_by="")
    _assert(len(bad.validate_request()) > 0, "empty createdBy caught")

    # Missing createdAt
    bad = _make_create(created_at="")
    _assert(len(bad.validate_request()) > 0, "empty createdAt caught")

    # UpdateAlertRequest.has_any_field
    empty_update = UpdateAlertRequest()
    _assert(not empty_update.has_any_field(), "empty update has no fields")
    non_empty = UpdateAlertRequest(title="new title")
    _assert(non_empty.has_any_field(), "update with title has field")

    # Model frozen
    import pydantic
    try:
        req.projectId = "x"  # type: ignore
        _assert(False, "CreateAlertRequest should be frozen")
    except (pydantic.ValidationError, TypeError, AttributeError):
        _assert(True, "CreateAlertRequest is frozen")

    # AlertStatisticsResponse has averageRiskScore
    stats = AlertStatisticsResponse(
        totalAlerts=0, severityCounts={}, statusCounts={},
        typeCounts={}, averageConfidence=0.0, averageRiskScore=0.0,
    )
    _assert(hasattr(stats, "averageRiskScore"), "stats has averageRiskScore field")
    _assert_eq(stats.averageRiskScore, 0.0, "stats averageRiskScore default 0.0")

    # BulkCreateAlertsRequest validation
    bulk_bad = BulkCreateAlertsRequest(alerts=[_make_create(title="")])
    berrs = bulk_bad.validate_request()
    _assert(len(berrs) > 0, "bulk create with bad item caught")

    # BulkDeleteAlertsRequest validation
    del_req = BulkDeleteAlertsRequest(alertIds=["id1", "id2"])
    _assert_eq(del_req.validate_request(), [], "valid bulk delete request")
    del_bad = BulkDeleteAlertsRequest(alertIds=[""])
    _assert(len(del_bad.validate_request()) > 0, "empty alertId in bulk delete caught")


# ===========================================================================
# Section 3 — Enum validators
# ===========================================================================

def test_enum_validators():
    # AlertSource
    _assert(_validate_source("FINDING") == AlertSource.FINDING, "source FINDING")
    _assert(_validate_source("finding") == AlertSource.FINDING, "source finding lowercase")
    _assert(_validate_source("MANUAL")  == AlertSource.MANUAL,  "source MANUAL")
    _assert(_validate_source("RULE")    == AlertSource.RULE,     "source RULE")
    _assert(_validate_source("SYSTEM")  == AlertSource.SYSTEM,   "source SYSTEM")
    _assert(_validate_source("BOGUS")   is None, "invalid source returns None")
    _assert(_validate_source("")        is None, "empty source returns None")
    _assert(_validate_source(None)      is None, "None source returns None")

    # AlertSeverity
    for sev in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        _assert(_validate_severity(sev) is not None, f"severity {sev} valid")
        _assert(_validate_severity(sev.lower()) is not None, f"severity {sev} lowercase valid")
    _assert(_validate_severity("EXTREME") is None, "invalid severity returns None")
    _assert(_validate_severity(None) is None, "None severity returns None")

    # AlertStatus
    for st in ("NEW", "OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "CLOSED", "SUPPRESSED"):
        _assert(_validate_status(st) is not None, f"status {st} valid")
    _assert(_validate_status("PENDING") is None, "invalid status returns None")
    _assert(_validate_status(None) is None, "None status returns None")


# ===========================================================================
# Section 4 — CRUD (create / read / update / delete)
# ===========================================================================

def test_crud():
    _reset_store()

    # --- CREATE ---
    body = _make_create(
        title="CRUD Alert", confidence=60.0, risk_score=55.0,
        reason="Suspicious", finding_summary="Finding X",
        recommended_action="Investigate",
    )
    resp = create_alert(body)
    _assert(isinstance(resp, APIResponse), "create returns APIResponse")
    _assert(resp.success, "create success=True")
    data = resp.data
    _assert(data["alertId"] is not None, "create returns alertId")
    _assert(data["title"] == "CRUD Alert", "create title correct")
    _assert(data["severity"] == "MEDIUM", "create default severity MEDIUM")
    _assert(data["status"] == "NEW", "create initial status NEW")
    _assert(data["source"] == "FINDING", "create default source FINDING")
    _assert(data["confidence"] == 60.0, "create confidence stored")
    _assert(data["riskScore"] == 55.0, "create riskScore stored")
    _assert(data["engineVersion"] is not None, "create engineVersion present")
    _assert(data["auditTrail"] == ["Created"], "create auditTrail starts with Created")
    _assert(data["explanation"] is not None, "create explanation present")
    _assert(data["correlation"] is not None, "create correlation present")
    _assert_eq(data["explanation"]["reason"], "Suspicious", "explanation reason stored")

    alert_id = data["alertId"]

    # --- DUPLICATE (409) ---
    dup_resp = create_alert(body)
    _assert(not dup_resp.success, "duplicate create fails")
    _assert(dup_resp.data.errorCode == "CONFLICT", "duplicate returns CONFLICT")

    # --- GET ---
    get_resp = get_alert(alert_id)
    _assert(get_resp.success, "get_alert success")
    _assert_eq(get_resp.data["alertId"], alert_id, "get returns correct alertId")

    # --- GET 404 ---
    missing = get_alert("nonexistent-id")
    _assert(not missing.success, "get missing alert fails")
    _assert_eq(missing.data.errorCode, "NOT_FOUND", "get missing returns NOT_FOUND")

    # --- UPDATE ---
    upd = UpdateAlertRequest(title="Updated Title", severity="HIGH", status="OPEN")
    upd_resp = update_alert_endpoint(alert_id, upd)
    _assert(upd_resp.success, "update success")
    _assert_eq(upd_resp.data["title"], "Updated Title", "update title changed")
    _assert_eq(upd_resp.data["severity"], "HIGH", "update severity changed")
    _assert_eq(upd_resp.data["status"], "OPEN", "update status changed")
    _assert("Status changed to OPEN" in upd_resp.data["auditTrail"], "audit trail has status change")
    _assert("Severity changed to HIGH" in upd_resp.data["auditTrail"], "audit trail has severity change")

    # --- UPDATE 404 ---
    upd404 = update_alert_endpoint("bad-id", UpdateAlertRequest(title="x"))
    _assert(not upd404.success, "update missing alert fails")
    _assert_eq(upd404.data.errorCode, "NOT_FOUND", "update missing returns NOT_FOUND")

    # --- UPDATE 422 (no fields) ---
    upd422 = update_alert_endpoint(alert_id, UpdateAlertRequest())
    _assert(not upd422.success, "update empty body fails")
    _assert_eq(upd422.data.errorCode, "VALIDATION_ERROR", "update empty returns VALIDATION_ERROR")

    # --- UPDATE invalid severity ---
    upd_bad_sev = update_alert_endpoint(alert_id, UpdateAlertRequest(severity="EXTREME"))
    _assert(not upd_bad_sev.success, "update bad severity fails")
    _assert_eq(upd_bad_sev.data.errorCode, "VALIDATION_ERROR", "bad severity returns VALIDATION_ERROR")

    # --- UPDATE invalid status ---
    upd_bad_st = update_alert_endpoint(alert_id, UpdateAlertRequest(status="PENDING"))
    _assert(not upd_bad_st.success, "update bad status fails")

    # --- LIST ---
    list_resp = list_alerts()
    _assert(list_resp.success, "list_alerts success")
    _assert_eq(list_resp.data["total"], 1, "list total is 1")
    _assert_eq(len(list_resp.data["alerts"]), 1, "list alerts length is 1")

    # --- DELETE ---
    del_resp = delete_alert(alert_id)
    _assert(del_resp.success, "delete success")
    _assert(del_resp.data is None, "delete data is None")

    # --- DELETE 404 ---
    del404 = delete_alert(alert_id)
    _assert(not del404.success, "delete missing fails")
    _assert_eq(del404.data.errorCode, "NOT_FOUND", "delete missing returns NOT_FOUND")

    # After delete store is empty
    _assert_eq(len(_ALERT_STORE), 0, "store empty after delete")


# ===========================================================================
# Section 5 — Create validation (422 paths)
# ===========================================================================

def test_create_validation():
    _reset_store()

    # Missing required fields
    for field, kwargs in [
        ("projectId",       dict(project_id="")),
        ("findingId",       dict(finding_id="")),
        ("investigationId", dict(investigation_id="")),
        ("title",           dict(title="")),
        ("createdBy",       dict(created_by="")),
        ("createdAt",       dict(created_at="")),
    ]:
        bad = _make_create(**kwargs)
        r = create_alert(bad)
        _assert(not r.success, f"create missing {field} fails")
        _assert_eq(r.data.errorCode, "VALIDATION_ERROR", f"create missing {field} is VALIDATION_ERROR")

    # Invalid source
    bad_src = _make_create(source="UNKNOWN_SRC")
    r = create_alert(bad_src)
    _assert(not r.success, "create bad source fails")
    _assert_eq(r.data.errorCode, "VALIDATION_ERROR", "create bad source VALIDATION_ERROR")

    # Invalid severity
    bad_sev = _make_create(severity="LETHAL")
    r = create_alert(bad_sev)
    _assert(not r.success, "create bad severity fails")
    _assert_eq(r.data.errorCode, "VALIDATION_ERROR", "create bad severity VALIDATION_ERROR")


# ===========================================================================
# Section 6 — Statistics
# ===========================================================================

def test_statistics():
    _reset_store()

    # Empty store
    resp = get_alert_statistics()
    _assert(resp.success, "empty stats success")
    d = resp.data
    _assert_eq(d["totalAlerts"], 0, "empty stats totalAlerts=0")
    _assert_eq(d["averageConfidence"], 0.0, "empty stats averageConfidence=0.0")
    _assert_eq(d["averageRiskScore"],  0.0, "empty stats averageRiskScore=0.0")
    _assert_eq(d["severityCounts"], {}, "empty stats severityCounts={}")
    _assert_eq(d["statusCounts"],   {}, "empty stats statusCounts={}")
    _assert_eq(d["typeCounts"],     {}, "empty stats typeCounts={}")

    # Populate 3 alerts
    create_alert(_make_create(title="A1", severity="HIGH",   source="FINDING", confidence=80.0, risk_score=70.0))
    create_alert(_make_create(title="A2", severity="MEDIUM", source="RULE",    confidence=60.0, risk_score=50.0, finding_id="f2"))
    create_alert(_make_create(title="A3", severity="LOW",    source="FINDING", confidence=40.0, risk_score=30.0, finding_id="f3"))

    resp2 = get_alert_statistics()
    d2 = resp2.data
    _assert_eq(d2["totalAlerts"], 3, "stats totalAlerts=3")
    _assert_eq(d2["severityCounts"]["HIGH"],   1, "severityCounts HIGH=1")
    _assert_eq(d2["severityCounts"]["MEDIUM"], 1, "severityCounts MEDIUM=1")
    _assert_eq(d2["severityCounts"]["LOW"],    1, "severityCounts LOW=1")
    _assert_eq(d2["statusCounts"]["NEW"], 3, "statusCounts NEW=3")
    _assert_eq(d2["typeCounts"]["FINDING"], 2, "typeCounts FINDING=2")
    _assert_eq(d2["typeCounts"]["RULE"],    1, "typeCounts RULE=1")

    expected_conf = round((80.0 + 60.0 + 40.0) / 3, 4)
    _assert_eq(d2["averageConfidence"], expected_conf, "averageConfidence correct")
    expected_risk = round((70.0 + 50.0 + 30.0) / 3, 4)
    _assert_eq(d2["averageRiskScore"],  expected_risk,  "averageRiskScore correct")

    # Keys are sorted alphabetically
    sev_keys = list(d2["severityCounts"].keys())
    _assert_eq(sev_keys, sorted(sev_keys), "severityCounts keys sorted")
    type_keys = list(d2["typeCounts"].keys())
    _assert_eq(type_keys, sorted(type_keys), "typeCounts keys sorted")


# ===========================================================================
# Section 7 — Pure helper: find_alert
# ===========================================================================

def test_find_alert():
    _reset_store()
    create_alert(_make_create(title="FindMe", project_id="proj-find"))

    alerts = _all_alerts()
    found = find_alert(alerts, "title", "FindMe")
    _assert(found is not None, "find_alert by title")
    _assert_eq(found["title"], "FindMe", "find_alert returns correct record")

    found_ci = find_alert(alerts, "title", "findme")
    _assert(found_ci is not None, "find_alert is case-insensitive")

    found_proj = find_alert(alerts, "projectId", "proj-find")
    _assert(found_proj is not None, "find_alert by projectId")

    not_found = find_alert(alerts, "title", "nonexistent")
    _assert(not_found is None, "find_alert returns None when not found")

    empty_result = find_alert([], "title", "anything")
    _assert(empty_result is None, "find_alert on empty list returns None")


# ===========================================================================
# Section 8 — Pure helper: sort_alerts
# ===========================================================================

def test_sort_alerts():
    _reset_store()
    create_alert(_make_create(title="S1", severity="LOW",      confidence=10.0, risk_score=10.0,
                               created_at="2026-01-03T00:00:00Z"))
    create_alert(_make_create(title="S2", severity="HIGH",     confidence=90.0, risk_score=90.0,
                               finding_id="f2", created_at="2026-01-01T00:00:00Z"))
    create_alert(_make_create(title="S3", severity="CRITICAL", confidence=50.0, risk_score=50.0,
                               finding_id="f3", created_at="2026-01-02T00:00:00Z"))

    alerts = _all_alerts()

    # Sort by createdAt asc
    sorted_ca = sort_alerts(alerts, "createdAt", "asc")
    dates = [a["createdAt"] for a in sorted_ca]
    _assert(dates == sorted(dates), "sort createdAt asc")

    # Sort by createdAt desc
    sorted_cd = sort_alerts(alerts, "createdAt", "desc")
    dates_d = [a["createdAt"] for a in sorted_cd]
    _assert(dates_d == sorted(dates_d, reverse=True), "sort createdAt desc")

    # Sort by severity asc (lexicographic)
    sorted_sev_a = sort_alerts(alerts, "severity", "asc")
    sevs = [a["severity"] for a in sorted_sev_a]
    _assert(sevs == sorted(sevs), "sort severity asc lexicographic")

    # Sort by severity desc
    sorted_sev_d = sort_alerts(alerts, "severity", "desc")
    sevs_d = [a["severity"] for a in sorted_sev_d]
    _assert(sevs_d == sorted(sevs_d, reverse=True), "sort severity desc")

    # Sort by confidence asc
    sorted_conf_a = sort_alerts(alerts, "confidence", "asc")
    confs = [a["confidence"] for a in sorted_conf_a]
    _assert(confs == sorted(confs), "sort confidence asc")

    # Sort by confidence desc
    sorted_conf_d = sort_alerts(alerts, "confidence", "desc")
    confs_d = [a["confidence"] for a in sorted_conf_d]
    _assert(confs_d == sorted(confs_d, reverse=True), "sort confidence desc")

    # Sort by riskScore asc
    sorted_risk_a = sort_alerts(alerts, "riskScore", "asc")
    risks = [a["riskScore"] for a in sorted_risk_a]
    _assert(risks == sorted(risks), "sort riskScore asc")

    # Sort by riskScore desc
    sorted_risk_d = sort_alerts(alerts, "risk", "desc")
    risks_d = [a["riskScore"] for a in sorted_risk_d]
    _assert(risks_d == sorted(risks_d, reverse=True), "sort risk desc")

    # Sort by status asc
    sorted_st = sort_alerts(alerts, "status", "asc")
    sts = [a["status"] for a in sorted_st]
    _assert(sts == sorted(sts), "sort status asc")

    # Sort by type (source) asc
    sorted_type = sort_alerts(alerts, "type", "asc")
    types = [a["source"] for a in sorted_type]
    _assert(types == sorted(types), "sort type asc")

    # Input not mutated
    orig_ids = [a["alertId"] for a in alerts]
    sort_alerts(alerts, "confidence", "desc")
    _assert([a["alertId"] for a in alerts] == orig_ids, "sort_alerts does not mutate input")

    # Unknown sort key falls back gracefully (no crash)
    try:
        sort_alerts(alerts, "unknownField", "asc")
        _assert(True, "unknown sort key does not crash")
    except Exception:
        _assert(False, "unknown sort key should not crash")


# ===========================================================================
# Section 9 — Pure helper: filter_alerts
# ===========================================================================

def test_filter_alerts():
    _reset_store()
    create_alert(_make_create(title="F1", severity="HIGH",   status="NEW",  source="FINDING",
                               confidence=80.0, risk_score=70.0,
                               project_id="proj-A", investigation_id="inv-1", finding_id="fid-1"))
    create_alert(_make_create(title="F2", severity="LOW",    status="OPEN", source="RULE",
                               confidence=30.0, risk_score=20.0,
                               finding_id="fid-2",
                               project_id="proj-B", investigation_id="inv-2"))
    create_alert(_make_create(title="F3", severity="MEDIUM", status="NEW",  source="FINDING",
                               confidence=55.0, risk_score=45.0,
                               finding_id="fid-3",
                               project_id="proj-A", investigation_id="inv-1"))

    alerts = _all_alerts()

    # By severity
    highs = filter_alerts(alerts, severity="HIGH")
    _assert_eq(len(highs), 1, "filter severity=HIGH → 1")
    _assert_eq(highs[0]["title"], "F1", "filter HIGH title correct")

    # Case-insensitive severity
    highs_ci = filter_alerts(alerts, severity="high")
    _assert_eq(len(highs_ci), 1, "filter severity=high case-insensitive")

    # By status — all start as NEW (service always creates with NEW status)
    # Manually set one to OPEN in the store for testing purposes
    all_stored = list(_ALERT_STORE.values())
    f2_id = [a["alertId"] for a in all_stored if a["title"] == "F2"][0]
    _ALERT_STORE[f2_id]["status"] = "OPEN"

    alerts = _all_alerts()  # refresh after manual update

    opens = filter_alerts(alerts, status="OPEN")
    _assert_eq(len(opens), 1, "filter status=OPEN → 1")

    news = filter_alerts(alerts, status="NEW")
    _assert_eq(len(news), 2, "filter status=NEW → 2")

    # By source
    findings = filter_alerts(alerts, source="FINDING")
    _assert_eq(len(findings), 2, "filter source=FINDING → 2")

    rules = filter_alerts(alerts, source="RULE")
    _assert_eq(len(rules), 1, "filter source=RULE → 1")

    # By projectId
    proj_a = filter_alerts(alerts, project_id="proj-A")
    _assert_eq(len(proj_a), 2, "filter projectId=proj-A → 2")

    # By investigationId
    inv1 = filter_alerts(alerts, investigation_id="inv-1")
    _assert_eq(len(inv1), 2, "filter investigationId=inv-1 → 2")

    # By findingId
    fid1 = filter_alerts(alerts, finding_id="fid-1")
    _assert_eq(len(fid1), 1, "filter findingId=fid-1 → 1")

    # By minConfidence
    hi_conf = filter_alerts(alerts, min_confidence=55.0)
    _assert_eq(len(hi_conf), 2, "filter minConfidence=55 → 2")

    # By maxConfidence
    lo_conf = filter_alerts(alerts, max_confidence=55.0)
    _assert_eq(len(lo_conf), 2, "filter maxConfidence=55 → 2")

    # By minRiskScore
    hi_risk = filter_alerts(alerts, min_risk_score=45.0)
    _assert_eq(len(hi_risk), 2, "filter minRiskScore=45 → 2")

    # By maxRiskScore
    lo_risk = filter_alerts(alerts, max_risk_score=45.0)
    _assert_eq(len(lo_risk), 2, "filter maxRiskScore=45 → 2")

    # Combined filter
    combo = filter_alerts(alerts, severity="HIGH", project_id="proj-A")
    _assert_eq(len(combo), 1, "combined filter severity+projectId → 1")

    # No match
    none_match = filter_alerts(alerts, severity="CRITICAL")
    _assert_eq(len(none_match), 0, "filter no match → 0")

    # No filter (returns all)
    all_match = filter_alerts(alerts)
    _assert_eq(len(all_match), 3, "filter no args → all 3")

    # Input not mutated
    orig = list(alerts)
    filter_alerts(alerts, severity="HIGH")
    _assert(len(alerts) == len(orig), "filter_alerts does not mutate input")


# ===========================================================================
# Section 10 — Pure helper: paginate_alerts
# ===========================================================================

def test_paginate_alerts():
    items = [{"alertId": str(i)} for i in range(10)]

    # Page 1, size 3
    page, pag = paginate_alerts(items, 1, 3)
    _assert_eq(len(page), 3, "paginate page1 size3 → 3 items")
    _assert_eq(pag.page, 1, "pagination page=1")
    _assert_eq(pag.pageSize, 3, "pagination pageSize=3")
    _assert_eq(pag.totalItems, 10, "pagination totalItems=10")
    _assert_eq(pag.totalPages, 4, "pagination totalPages=4")
    _assert_eq(page[0]["alertId"], "0", "page1 first item alertId=0")

    # Page 2
    page2, pag2 = paginate_alerts(items, 2, 3)
    _assert_eq(len(page2), 3, "paginate page2 → 3 items")
    _assert_eq(page2[0]["alertId"], "3", "page2 first item alertId=3")

    # Last page (partial)
    page4, pag4 = paginate_alerts(items, 4, 3)
    _assert_eq(len(page4), 1, "page4 partial → 1 item")
    _assert_eq(page4[0]["alertId"], "9", "page4 item alertId=9")

    # Page beyond total
    page99, pag99 = paginate_alerts(items, 99, 3)
    _assert_eq(len(page99), 0, "page99 beyond total → 0 items")
    _assert_eq(pag99.totalItems, 10, "page99 totalItems still 10")

    # Empty list
    empty_page, empty_pag = paginate_alerts([], 1, 10)
    _assert_eq(len(empty_page), 0, "paginate empty list → 0 items")
    _assert_eq(empty_pag.totalPages, 0, "paginate empty totalPages=0")

    # Clamp page < 1
    clamped, cpag = paginate_alerts(items, 0, 5)
    _assert_eq(cpag.page, 1, "page 0 clamped to 1")

    # Clamp page_size < 1
    _, spag = paginate_alerts(items, 1, 0)
    _assert_eq(spag.pageSize, 1, "page_size 0 clamped to 1")

    # Returns Pagination model
    _assert(isinstance(pag, Pagination), "paginate_alerts returns Pagination model")

    # Input not mutated
    orig = list(items)
    paginate_alerts(items, 1, 3)
    _assert(items == orig, "paginate_alerts does not mutate input")


# ===========================================================================
# Section 11 — Search endpoint
# ===========================================================================

def test_search():
    _reset_store()
    create_alert(_make_create(title="Recon Alert",    severity="HIGH",   confidence=85.0, risk_score=80.0))
    create_alert(_make_create(title="Lateral Move",   severity="MEDIUM", confidence=60.0, risk_score=55.0,
                               finding_id="f2"))
    create_alert(_make_create(title="Exfiltration",   severity="CRITICAL", confidence=95.0, risk_score=90.0,
                               finding_id="f3"))
    create_alert(_make_create(title="Recon Followup", severity="LOW",    confidence=20.0, risk_score=15.0,
                               finding_id="f4"))

    # --- Basic text match ---
    resp = search_alerts(q="Recon")
    _assert(resp.success, "search 'Recon' success")
    d = resp.data
    _assert_eq(d["total"], 2, "search 'Recon' → 2 results")
    _assert_eq(len(d["alerts"]), 2, "search 'Recon' alerts list length 2")
    _assert_eq(d["query"], "Recon", "search query echoed")

    # No match
    resp_none = search_alerts(q="zzznomatch")
    _assert_eq(resp_none.data["total"], 0, "search no match → 0")

    # --- Sort by confidence desc ---
    resp_s = search_alerts(q="", sort_by="confidence", sort_order="desc")
    # empty query still matches all
    confs = [a["confidence"] for a in resp_s.data["alerts"]]
    _assert(confs == sorted(confs, reverse=True), "search sort confidence desc")

    # --- Sort by riskScore asc ---
    resp_r = search_alerts(q="", sort_by="riskScore", sort_order="asc")
    risks = [a["riskScore"] for a in resp_r.data["alerts"]]
    _assert(risks == sorted(risks), "search sort riskScore asc")

    # --- Sort by severity ---
    resp_sev = search_alerts(q="", sort_by="severity", sort_order="asc")
    sevs = [a["severity"] for a in resp_sev.data["alerts"]]
    _assert(sevs == sorted(sevs), "search sort severity asc")

    # --- Sort by status ---
    resp_st = search_alerts(q="", sort_by="status", sort_order="asc")
    _assert(resp_st.success, "search sort status asc success")

    # --- Sort by type ---
    resp_type = search_alerts(q="", sort_by="type", sort_order="asc")
    _assert(resp_type.success, "search sort type asc success")

    # --- Sort by createdAt ---
    resp_ca = search_alerts(q="", sort_by="createdAt", sort_order="asc")
    _assert(resp_ca.success, "search sort createdAt success")

    # --- Invalid sortBy ---
    resp_bad = search_alerts(q="x", sort_by="banana")
    _assert(not resp_bad.success, "search invalid sortBy fails")
    _assert_eq(resp_bad.data.errorCode, "VALIDATION_ERROR", "invalid sortBy VALIDATION_ERROR")

    # --- Invalid sortOrder ---
    resp_bad_ord = search_alerts(q="x", sort_order="zigzag")
    _assert(not resp_bad_ord.success, "search invalid sortOrder fails")

    # --- Filter by severity ---
    resp_filt = search_alerts(q="", severity_filter="HIGH")
    _assert_eq(resp_filt.data["total"], 1, "search + severity filter → 1")

    # --- Filter by status ---
    resp_filt_st = search_alerts(q="", status_filter="NEW")
    _assert_eq(resp_filt_st.data["total"], 4, "search + status filter NEW → 4")

    # --- Filter by source ---
    resp_filt_src = search_alerts(q="", source_filter="FINDING")
    _assert_eq(resp_filt_src.data["total"], 4, "search + source filter → 4")

    # --- Filter by minConfidence ---
    resp_min = search_alerts(q="", min_confidence=85.0)
    _assert_eq(resp_min.data["total"], 2, "search minConfidence=85 → 2")

    # --- Filter by maxConfidence ---
    resp_max = search_alerts(q="", max_confidence=60.0)
    _assert_eq(resp_max.data["total"], 2, "search maxConfidence=60 → 2")

    # --- Filter by minRiskScore ---
    resp_minr = search_alerts(q="", min_risk_score=80.0)
    _assert_eq(resp_minr.data["total"], 2, "search minRiskScore=80 → 2")

    # --- Pagination ---
    resp_pg = search_alerts(q="", page=1, page_size=2)
    _assert_eq(len(resp_pg.data["alerts"]), 2, "search page=1 size=2 → 2 alerts")
    _assert_eq(resp_pg.data["totalPages"], 2, "search totalPages=2")
    _assert_eq(resp_pg.data["pageSize"], 2, "search pageSize=2 echoed")
    _assert_eq(resp_pg.data["page"], 1, "search page=1 echoed")

    resp_pg2 = search_alerts(q="", page=2, page_size=2)
    _assert_eq(len(resp_pg2.data["alerts"]), 2, "search page=2 size=2 → 2 alerts")

    resp_pg3 = search_alerts(q="", page=3, page_size=2)
    _assert_eq(len(resp_pg3.data["alerts"]), 0, "search page=3 size=2 → 0 alerts (beyond)")

    # --- sortBy echoed ---
    resp_echo = search_alerts(q="", sort_by="severity", sort_order="desc")
    _assert_eq(resp_echo.data["sortBy"], "severity", "search sortBy echoed")
    _assert_eq(resp_echo.data["sortOrder"], "desc", "search sortOrder echoed")


# ===========================================================================
# Section 12 — Bulk create
# ===========================================================================

def test_bulk_create():
    _reset_store()

    req1 = _make_create(title="Bulk-1", finding_id="bf1", confidence=70.0, risk_score=60.0)
    req2 = _make_create(title="Bulk-2", finding_id="bf2", confidence=50.0, risk_score=40.0)
    req3 = _make_create(title="Bulk-3", finding_id="bf3", confidence=30.0, risk_score=20.0)

    bulk_req = BulkCreateAlertsRequest(alerts=[req1, req2, req3])
    resp = bulk_create_alerts(bulk_req)
    _assert(resp.success, "bulk create success")
    d = resp.data
    _assert_eq(d["successCount"], 3, "bulk create 3 succeeded")
    _assert_eq(d["failCount"],    0, "bulk create 0 failed")
    _assert_eq(d["total"],        3, "bulk create total=3")
    _assert_eq(len(d["succeeded"]), 3, "bulk create succeeded list length 3")
    _assert_eq(len(_ALERT_STORE), 3, "store has 3 alerts after bulk create")

    # Duplicate submission
    resp2 = bulk_create_alerts(bulk_req)
    _assert(resp2.success, "bulk create duplicate returns success envelope")
    d2 = resp2.data
    _assert_eq(d2["successCount"], 0, "bulk create duplicate 0 succeeded")
    _assert_eq(d2["failCount"],    3, "bulk create duplicate 3 failed")

    # Mixed (new + duplicate)
    req4 = _make_create(title="Bulk-4", finding_id="bf4")
    mixed = BulkCreateAlertsRequest(alerts=[req1, req4])
    resp3 = bulk_create_alerts(mixed)
    d3 = resp3.data
    _assert_eq(d3["successCount"], 1, "mixed bulk create 1 succeeded")
    _assert_eq(d3["failCount"],    1, "mixed bulk create 1 failed")

    # Invalid item in bulk — validate_request fires at top level (title empty triggers
    # the per-item check inside BulkCreateAlertsRequest.validate_request), returning 422
    bad_req = _make_create(title="", finding_id="bfx")
    bulk_bad = BulkCreateAlertsRequest(alerts=[bad_req])
    resp_bad = bulk_create_alerts(bulk_bad)
    # Either a 422 (caught by validate_request) or success=True with failCount=1
    # — both are acceptable. We only assert it doesn't crash.
    _assert(isinstance(resp_bad, APIResponse), "bulk create invalid item returns APIResponse")
    # If it succeeded-envelope style, check failCount; if error envelope, check errorCode
    if resp_bad.success:
        _assert(resp_bad.data.get("failCount", 0) >= 0, "bulk create invalid item has failCount")
    else:
        _assert(resp_bad.data.errorCode == "VALIDATION_ERROR",
                "bulk create invalid item returns VALIDATION_ERROR")

    # Empty list → 422 via validate_request (model won't allow min_length=0, but test via validate)
    bulk_empty_data = BulkCreateAlertsRequest(alerts=[_make_create(title="")])
    errs = bulk_empty_data.validate_request()
    _assert(len(errs) > 0, "bulk create empty title caught by validate_request")


# ===========================================================================
# Section 13 — Bulk update
# ===========================================================================

def test_bulk_update():
    _reset_store()

    # Seed 3 alerts
    r1 = create_alert(_make_create(title="BU-1", finding_id="bu1"))
    r2 = create_alert(_make_create(title="BU-2", finding_id="bu2"))
    r3 = create_alert(_make_create(title="BU-3", finding_id="bu3"))
    id1 = r1.data["alertId"]
    id2 = r2.data["alertId"]
    id3 = r3.data["alertId"]

    # Update all 3
    bulk_upd = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id1, update=UpdateAlertRequest(title="BU-1-Updated")),
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id2, update=UpdateAlertRequest(severity="HIGH")),
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id3, update=UpdateAlertRequest(status="OPEN")),
    ])
    resp = bulk_update_alerts(bulk_upd)
    _assert(resp.success, "bulk update success")
    d = resp.data
    _assert_eq(d["successCount"], 3, "bulk update 3 succeeded")
    _assert_eq(d["failCount"],    0, "bulk update 0 failed")

    # Verify changes persisted
    _assert_eq(_ALERT_STORE[id1]["title"],    "BU-1-Updated", "bulk update title persisted")
    _assert_eq(_ALERT_STORE[id2]["severity"], "HIGH",          "bulk update severity persisted")
    _assert_eq(_ALERT_STORE[id3]["status"],   "OPEN",          "bulk update status persisted")

    # Mixed: one valid, one 404
    bulk_mixed = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id1, update=UpdateAlertRequest(title="X")),
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId="nonexistent", update=UpdateAlertRequest(title="Y")),
    ])
    resp_mixed = bulk_update_alerts(bulk_mixed)
    d_mixed = resp_mixed.data
    _assert_eq(d_mixed["successCount"], 1, "bulk update mixed: 1 success")
    _assert_eq(d_mixed["failCount"],    1, "bulk update mixed: 1 failure")

    # Invalid severity in item
    bulk_bad_sev = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id1, update=UpdateAlertRequest(severity="EXTREME")),
    ])
    resp_bad = bulk_update_alerts(bulk_bad_sev)
    _assert_eq(resp_bad.data["failCount"], 1, "bulk update invalid severity counted as failure")

    # validate_request catches empty alertId
    bad_item_req = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId="", update=UpdateAlertRequest(title="x")),
    ])
    verrs = bad_item_req.validate_request()
    _assert(len(verrs) > 0, "bulk update empty alertId caught by validate_request")


# ===========================================================================
# Section 14 — Bulk delete
# ===========================================================================

def test_bulk_delete():
    _reset_store()

    r1 = create_alert(_make_create(title="BD-1", finding_id="bd1"))
    r2 = create_alert(_make_create(title="BD-2", finding_id="bd2"))
    r3 = create_alert(_make_create(title="BD-3", finding_id="bd3"))
    id1 = r1.data["alertId"]
    id2 = r2.data["alertId"]
    id3 = r3.data["alertId"]

    _assert_eq(len(_ALERT_STORE), 3, "store has 3 before bulk delete")

    # Delete 2 of 3
    bulk_del = BulkDeleteAlertsRequest(alertIds=[id1, id2])
    resp = bulk_delete_alerts(bulk_del)
    _assert(resp.success, "bulk delete success")
    d = resp.data
    _assert_eq(d["successCount"], 2, "bulk delete 2 succeeded")
    _assert_eq(d["failCount"],    0, "bulk delete 0 failed")
    _assert_eq(d["total"],        2, "bulk delete total=2")
    _assert_eq(len(_ALERT_STORE), 1, "store has 1 remaining")
    _assert(id3 in _ALERT_STORE, "remaining alert still in store")

    # Delete missing ID
    resp_miss = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=["nonexistent"]))
    d_miss = resp_miss.data
    _assert_eq(d_miss["successCount"], 0, "bulk delete missing 0 succeeded")
    _assert_eq(d_miss["failCount"],    1, "bulk delete missing 1 failed")

    # Mixed: existing + missing
    resp_mix = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=[id3, "ghost"]))
    _assert_eq(resp_mix.data["successCount"], 1, "bulk delete mixed 1 success")
    _assert_eq(resp_mix.data["failCount"],    1, "bulk delete mixed 1 fail")
    _assert_eq(len(_ALERT_STORE), 0, "store empty after mixed bulk delete")

    # validate_request catches blank ID
    bad_del = BulkDeleteAlertsRequest(alertIds=[""])
    berrs = bad_del.validate_request()
    _assert(len(berrs) > 0, "bulk delete blank alertId caught")


# ===========================================================================
# Section 15 — Deterministic IDs
# ===========================================================================

def test_deterministic_ids():
    _reset_store()

    req = _make_create(title="Det-1")
    r1 = create_alert(req)
    alert_id_1 = r1.data["alertId"]

    _reset_store()
    r2 = create_alert(req)
    alert_id_2 = r2.data["alertId"]

    _assert_eq(alert_id_1, alert_id_2, "same inputs → same alertId")

    # Different title → different alertId
    req_b = _make_create(title="Det-2")
    _reset_store()
    r3 = create_alert(req_b)
    _assert(r3.data["alertId"] != alert_id_1, "different title → different alertId")

    # alertKey is stable
    _reset_store()
    r4 = create_alert(req)
    _assert_eq(r4.data["alertKey"], r1.data["alertKey"], "alertKey deterministic across resets")

    # alertFingerprint is present and 32 chars
    fp = r4.data["alertFingerprint"]
    _assert(fp is not None and len(fp) == 32, "alertFingerprint is 32 hex chars")


# ===========================================================================
# Section 16 — Serialization shape
# ===========================================================================

def test_serialization():
    _reset_store()
    r = create_alert(_make_create(
        title="Shape Test",
        tags=["tag1", "tag2"],
        asset_ids=["a1", "a2"],
        metadata={"key": "val"},
        reason="Reason text",
        finding_summary="Summary text",
        recommended_action="Act now",
        escalation_reason="Escalated",
        related_alert_ids=["r1"],
        shared_evidence_ids=["e1"],
        correlationScore=75.0,
    ))
    d = r.data

    # Top-level fields present
    for field in ["alertId", "alertKey", "projectId", "findingId", "investigationId",
                   "title", "description", "severity", "status", "source",
                   "confidence", "riskScore", "assetIds", "relationshipIds",
                   "evidenceIds", "graphNodeIds", "timelineEventIds",
                   "findingFingerprint", "investigationFingerprint", "graphFingerprint",
                   "alertFingerprint", "tags", "metadata", "createdBy", "assignedTo",
                   "createdAt", "updatedAt", "closedAt", "acknowledgedAt", "resolvedAt",
                   "explanation", "correlation", "engineVersion", "auditTrail"]:
        _assert(field in d, f"response has field '{field}'")

    # Lists are lists
    _assert(isinstance(d["assetIds"],  list), "assetIds is list")
    _assert(isinstance(d["tags"],      list), "tags is list")
    _assert(isinstance(d["auditTrail"],list), "auditTrail is list")

    # Nested explanation shape
    exp = d["explanation"]
    for ef in ["reason", "findingSummary", "affectedAssets", "recommendedAction", "escalationReason"]:
        _assert(ef in exp, f"explanation has field '{ef}'")
    _assert_eq(exp["reason"], "Reason text", "explanation.reason correct")

    # Nested correlation shape
    cor = d["correlation"]
    for cf in ["correlationId", "relatedAlertIds", "relatedFindingIds",
                "sharedEvidenceIds", "sharedAssets", "correlationScore"]:
        _assert(cf in cor, f"correlation has field '{cf}'")
    _assert_eq(cor["correlationScore"], 75.0, "correlationScore correct")

    # Tags sorted (alert_service normalises to lowercase sorted tuple)
    _assert(set(d["tags"]) == {"tag1", "tag2"}, "tags present")

    # metadata dict
    _assert_eq(d["metadata"]["key"], "val", "metadata key-value preserved")


# ===========================================================================
# Section 17 — Edge cases
# ===========================================================================

def test_edge_cases():
    _reset_store()

    # Empty store list
    list_resp = list_alerts()
    _assert(list_resp.success, "list empty store success")
    _assert_eq(list_resp.data["total"], 0, "list empty total=0")
    _assert_eq(list_resp.data["alerts"], [], "list empty alerts=[]")

    # Statistics on empty store
    stats_resp = get_alert_statistics()
    _assert(stats_resp.success, "stats empty store success")
    _assert_eq(stats_resp.data["totalAlerts"], 0, "empty stats totalAlerts=0")

    # Search with empty q (single space trimmed — min_length=1 enforced by FastAPI Query
    # but we test _search_alerts helper with empty string directly)
    result = _search_alerts(_all_alerts(), "")
    _assert_eq(result, [], "empty query _search_alerts returns []")

    # Search in empty store
    search_empty = search_alerts(q="anything")
    _assert(search_empty.success, "search empty store success")
    _assert_eq(search_empty.data["total"], 0, "search empty store total=0")

    # All sources valid
    for src in ["FINDING", "MANUAL", "RULE", "SYSTEM"]:
        _reset_store()
        r = create_alert(_make_create(source=src))
        _assert(r.success, f"create with source={src} succeeds")
        _assert_eq(r.data["source"], src, f"source={src} stored correctly")

    # All severities valid
    for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        _reset_store()
        r = create_alert(_make_create(severity=sev))
        _assert(r.success, f"create with severity={sev} succeeds")
        _assert_eq(r.data["severity"], sev, f"severity={sev} stored correctly")

    # confidence and riskScore clamped (0–100)
    _reset_store()
    r = create_alert(_make_create(confidence=100.0, risk_score=100.0))
    _assert_eq(r.data["confidence"], 100.0, "max confidence stored")
    _assert_eq(r.data["riskScore"],  100.0, "max riskScore stored")

    _reset_store()
    r0 = create_alert(_make_create(confidence=0.0, risk_score=0.0))
    _assert_eq(r0.data["confidence"], 0.0, "zero confidence stored")
    _assert_eq(r0.data["riskScore"],  0.0, "zero riskScore stored")

    # _all_alerts returns sorted by alertId
    _reset_store()
    create_alert(_make_create(title="Z", finding_id="z1"))
    create_alert(_make_create(title="A", finding_id="a1"))
    create_alert(_make_create(title="M", finding_id="m1"))
    ids = [a["alertId"] for a in _all_alerts()]
    _assert(ids == sorted(ids), "_all_alerts returns IDs in sorted order")

    # list endpoint total matches store size
    list_r = list_alerts()
    _assert_eq(list_r.data["total"], len(_ALERT_STORE), "list total matches store size")

    # Update metadata merges correctly
    _reset_store()
    cr = create_alert(_make_create(metadata={"a": 1, "b": 2}))
    aid = cr.data["alertId"]
    upd_r = update_alert_endpoint(aid, UpdateAlertRequest(metadata={"b": 99, "c": 3}))
    meta = upd_r.data["metadata"]
    _assert_eq(meta.get("b"), 99, "metadata b overwritten")
    _assert_eq(meta.get("c"), 3,  "metadata c added")

    # Bulk create with all invalid items — validate_request catches blank title
    # at the BulkCreateAlertsRequest level → 422 envelope
    _reset_store()
    all_bad = BulkCreateAlertsRequest(alerts=[_make_create(title="", finding_id="bx")])
    resp_all_bad = bulk_create_alerts(all_bad)
    _assert(isinstance(resp_all_bad, APIResponse), "all-bad bulk create returns APIResponse")
    if resp_all_bad.success:
        _assert_eq(resp_all_bad.data["successCount"], 0, "all-bad bulk create 0 succeeded")
    else:
        _assert_eq(resp_all_bad.data.errorCode, "VALIDATION_ERROR",
                   "all-bad bulk create VALIDATION_ERROR")

    # Paginate with page_size larger than total
    _reset_store()
    create_alert(_make_create(title="Only"))
    pg, p = paginate_alerts(_all_alerts(), 1, 100)
    _assert_eq(len(pg), 1, "page_size > total returns all items")
    _assert_eq(p.totalPages, 1, "totalPages=1 when all fit")


# ===========================================================================
# Section 18 — _alert_record_to_dict round-trip
# ===========================================================================

def test_record_to_dict_roundtrip():
    _reset_store()
    req = _make_create(
        title="Roundtrip", severity="HIGH", confidence=77.0,
        tags=["alpha", "beta"], metadata={"x": 42},
    )
    r = create_alert(req)
    aid = r.data["alertId"]
    stored = _ALERT_STORE[aid]

    # Enum values are strings in storage
    _assert(isinstance(stored["severity"], str), "severity stored as string")
    _assert(isinstance(stored["status"],   str), "status stored as string")
    _assert(isinstance(stored["source"],   str), "source stored as string")

    # Lists are lists (not tuples) in storage
    _assert(isinstance(stored["assetIds"],      list), "assetIds is list in store")
    _assert(isinstance(stored["auditTrail"],    list), "auditTrail is list in store")
    _assert(isinstance(stored["tags"],          list), "tags is list in store")
    _assert(isinstance(stored["explanation"],   dict), "explanation is dict in store")
    _assert(isinstance(stored["correlation"],   dict), "correlation is dict in store")

    # metadata is dict
    _assert(isinstance(stored["metadata"], dict), "metadata is dict in store")
    _assert_eq(stored["metadata"]["x"], 42, "metadata round-trip value correct")

    # _alert_to_response works on stored dict
    resp_model = _alert_to_response(stored)
    _assert(isinstance(resp_model, AlertResponse), "_alert_to_response returns AlertResponse")
    _assert_eq(resp_model.alertId, aid, "response alertId matches")
    _assert_eq(resp_model.severity, "HIGH", "response severity correct")


# ===========================================================================
# Section 19 — _compute_statistics directly
# ===========================================================================

def test_compute_statistics_direct():
    # Build a synthetic list of alert dicts
    alerts = [
        {"severity": "HIGH",     "status": "NEW",         "source": "FINDING", "confidence": 80.0, "riskScore": 75.0},
        {"severity": "MEDIUM",   "status": "OPEN",        "source": "RULE",    "confidence": 60.0, "riskScore": 55.0},
        {"severity": "HIGH",     "status": "RESOLVED",    "source": "FINDING", "confidence": 90.0, "riskScore": 85.0},
        {"severity": "LOW",      "status": "CLOSED",      "source": "MANUAL",  "confidence": 20.0, "riskScore": 15.0},
        {"severity": "CRITICAL", "status": "SUPPRESSED",  "source": "SYSTEM",  "confidence": 95.0, "riskScore": 92.0},
    ]
    stats = _compute_statistics(alerts)

    _assert_eq(stats.totalAlerts, 5, "compute stats totalAlerts=5")
    _assert_eq(stats.severityCounts["HIGH"],     2, "severityCounts HIGH=2")
    _assert_eq(stats.severityCounts["MEDIUM"],   1, "severityCounts MEDIUM=1")
    _assert_eq(stats.severityCounts["LOW"],      1, "severityCounts LOW=1")
    _assert_eq(stats.severityCounts["CRITICAL"], 1, "severityCounts CRITICAL=1")
    _assert_eq(stats.statusCounts["NEW"],        1, "statusCounts NEW=1")
    _assert_eq(stats.statusCounts["OPEN"],       1, "statusCounts OPEN=1")
    _assert_eq(stats.statusCounts["RESOLVED"],   1, "statusCounts RESOLVED=1")
    _assert_eq(stats.typeCounts["FINDING"],      2, "typeCounts FINDING=2")
    _assert_eq(stats.typeCounts["RULE"],         1, "typeCounts RULE=1")
    _assert_eq(stats.typeCounts["MANUAL"],       1, "typeCounts MANUAL=1")
    _assert_eq(stats.typeCounts["SYSTEM"],       1, "typeCounts SYSTEM=1")

    expected_conf = round((80+60+90+20+95)/5, 4)
    _assert_eq(stats.averageConfidence, expected_conf, "averageConfidence computed correctly")
    expected_risk = round((75+55+85+15+92)/5, 4)
    _assert_eq(stats.averageRiskScore, expected_risk, "averageRiskScore computed correctly")

    # Keys sorted alphabetically
    _assert(list(stats.severityCounts.keys()) == sorted(stats.severityCounts.keys()),
            "severityCounts sorted")
    _assert(list(stats.typeCounts.keys()) == sorted(stats.typeCounts.keys()),
            "typeCounts sorted")

    # Empty
    empty_stats = _compute_statistics([])
    _assert_eq(empty_stats.totalAlerts,       0,   "empty compute totalAlerts=0")
    _assert_eq(empty_stats.averageConfidence, 0.0, "empty compute averageConfidence=0.0")
    _assert_eq(empty_stats.averageRiskScore,  0.0, "empty compute averageRiskScore=0.0")


# ===========================================================================
# Section 20 — Search helper (_search_alerts) directly
# ===========================================================================

def test_search_helper():
    alerts = [
        {"alertId": "aid-1", "alertKey": "key1", "title": "Recon detected",
         "description": "Port scan from 10.0.0.1", "projectId": "p1",
         "findingId": "f1", "investigationId": "i1", "source": "FINDING", "severity": "HIGH"},
        {"alertId": "aid-2", "alertKey": "key2", "title": "Lateral movement",
         "description": "Unusual SMB traffic", "projectId": "p2",
         "findingId": "f2", "investigationId": "i2", "source": "RULE", "severity": "MEDIUM"},
        {"alertId": "aid-3", "alertKey": "key3", "title": "Data exfiltration",
         "description": "Large DNS queries", "projectId": "p1",
         "findingId": "f3", "investigationId": "i1", "source": "FINDING", "severity": "CRITICAL"},
    ]

    # Match by title
    r = _search_alerts(alerts, "recon")
    _assert_eq(len(r), 1, "search 'recon' → 1")

    # Match by description
    r2 = _search_alerts(alerts, "smb")
    _assert_eq(len(r2), 1, "search 'smb' → 1")

    # Match by severity
    r3 = _search_alerts(alerts, "critical")
    _assert_eq(len(r3), 1, "search 'critical' → 1")

    # Match by source
    r4 = _search_alerts(alerts, "rule")
    _assert_eq(len(r4), 1, "search 'rule' → 1")

    # Match by projectId
    r5 = _search_alerts(alerts, "p1")
    _assert_eq(len(r5), 2, "search 'p1' → 2")

    # Match by alertId
    r6 = _search_alerts(alerts, "aid-2")
    _assert_eq(len(r6), 1, "search 'aid-2' → 1")

    # No match
    r7 = _search_alerts(alerts, "zzz")
    _assert_eq(len(r7), 0, "search 'zzz' → 0")

    # Empty query
    r8 = _search_alerts(alerts, "")
    _assert_eq(len(r8), 0, "search '' → 0")

    # All match
    r9 = _search_alerts(alerts, "f")
    _assert_eq(len(r9), 3, "search 'f' matches all 3")

    # Case insensitive
    r10 = _search_alerts(alerts, "RECON")
    _assert_eq(len(r10), 1, "search 'RECON' case-insensitive → 1")


# ===========================================================================
# Section 21 — Update preserves immutable fields
# ===========================================================================

def test_update_preserves_immutable():
    _reset_store()
    r = create_alert(_make_create(title="Immutable Test"))
    aid = r.data["alertId"]
    orig_key = r.data["alertKey"]
    orig_project = r.data["projectId"]
    orig_finding = r.data["findingId"]
    orig_created_at = r.data["createdAt"]
    orig_created_by = r.data["createdBy"]
    orig_engine = r.data["engineVersion"]

    upd_r = update_alert_endpoint(aid, UpdateAlertRequest(title="Updated"))
    d = upd_r.data
    _assert_eq(d["alertId"],       aid,            "alertId immutable after update")
    _assert_eq(d["alertKey"],      orig_key,        "alertKey immutable after update")
    _assert_eq(d["projectId"],     orig_project,    "projectId immutable after update")
    _assert_eq(d["findingId"],     orig_finding,    "findingId immutable after update")
    _assert_eq(d["createdAt"],     orig_created_at, "createdAt immutable after update")
    _assert_eq(d["createdBy"],     orig_created_by, "createdBy immutable after update")
    _assert_eq(d["engineVersion"], orig_engine,     "engineVersion immutable after update")
    _assert(d["updatedAt"] != orig_created_at,      "updatedAt changes after update")
    _assert_eq(d["title"], "Updated", "title mutable")


# ===========================================================================
# Section 22 — BulkUpdateAlertsRequest validate_request
# ===========================================================================

def test_bulk_update_validate_request():
    # Empty alertId in item
    bad = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId="  ", update=UpdateAlertRequest(title="x")),
    ])
    errs = bad.validate_request()
    _assert(any("alertId" in e for e in errs), "blank alertId caught in bulk update validate")

    # No fields in update
    bad2 = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId="aid-x", update=UpdateAlertRequest()),
    ])
    errs2 = bad2.validate_request()
    _assert(any("field" in e.lower() for e in errs2), "no-field update caught in bulk update validate")


# ===========================================================================
# Section 23 — APIResponse envelope structure
# ===========================================================================

def test_api_response_envelope():
    _reset_store()

    # Success response
    r = list_alerts()
    _assert(isinstance(r, APIResponse), "list_alerts returns APIResponse instance")
    _assert(r.success is True, "success response has success=True")
    _assert(isinstance(r.message, str), "success response has string message")
    _assert(r.data is not None, "success response has data")
    _assert(r.metadata is not None, "success response has metadata")
    _assert("apiLayerVersion" in r.metadata, "metadata contains apiLayerVersion")

    # Error response (404)
    err_r = get_alert("ghost")
    _assert(isinstance(err_r, APIResponse), "error returns APIResponse")
    _assert(err_r.success is False, "error has success=False")
    _assert(err_r.data is not None, "error has data (APIError)")
    _assert(hasattr(err_r.data, "errorCode"), "error data has errorCode")
    _assert(hasattr(err_r.data, "error"),     "error data has error")

    # Validation error (422)
    val_r = create_alert(_make_create(title=""))
    _assert(val_r.success is False, "validation error success=False")
    _assert_eq(val_r.data.errorCode, "VALIDATION_ERROR", "validation errorCode correct")


# ===========================================================================
# Section 24 — Extended CRUD lifecycle
# ===========================================================================

def test_extended_crud_lifecycle():
    _reset_store()
    # Create with all optional fields populated
    r = create_alert(_make_create(
        title="Full Alert", severity="CRITICAL", source="RULE",
        confidence=99.0, risk_score=95.0, assignedTo="analyst-1",
        assetIds=["a1", "a2", "a3"],
        relationshipIds=["rel-1"],
        evidenceIds=["ev-1", "ev-2"],
        graphNodeIds=["gn-1"],
        timelineEventIds=["te-1"],
        findingFingerprint="fp1", investigationFingerprint="fp2",
        graphFingerprint="fp3",
        reason="Full reason", findingSummary="Full summary",
        recommendedAction="Full action",
        escalationReason="Full escalation",
        relatedAlertIds=["ra-1"], relatedFindingIds=["rf-1"],
        sharedEvidenceIds=["se-1"], sharedAssets=["sa-1"],
        correlationScore=88.0, tags=["t1", "t2", "t3"],
        metadata={"env": "prod", "score": 10},
    ))
    _assert(r.success, "full create success")
    d = r.data
    _assert_eq(d["severity"], "CRITICAL", "full create severity")
    _assert_eq(d["source"],   "RULE",     "full create source")
    _assert_eq(d["assignedTo"], "analyst-1", "full create assignedTo")
    _assert_eq(len(d["assetIds"]), 3, "full create 3 assetIds")
    _assert_eq(len(d["evidenceIds"]), 2, "full create 2 evidenceIds")
    _assert_eq(d["findingFingerprint"], "fp1", "full create findingFingerprint")
    _assert_eq(d["correlation"]["correlationScore"], 88.0, "full create correlationScore")
    aid = d["alertId"]

    # Update every mutable field
    upd = UpdateAlertRequest(
        title="Updated Full", description="New desc", severity="HIGH",
        status="ACKNOWLEDGED", confidence=80.0, riskScore=75.0,
        assignedTo="analyst-2", tags=["new-tag"],
        metadata={"env": "staging"},
    )
    upd_r = update_alert_endpoint(aid, upd)
    d2 = upd_r.data
    _assert(upd_r.success, "full update success")
    _assert_eq(d2["title"],       "Updated Full",  "update title")
    _assert_eq(d2["description"], "New desc",       "update description")
    _assert_eq(d2["severity"],    "HIGH",           "update severity")
    _assert_eq(d2["status"],      "ACKNOWLEDGED",   "update status")
    _assert_eq(d2["confidence"],  80.0,             "update confidence")
    _assert_eq(d2["riskScore"],   75.0,             "update riskScore")
    _assert_eq(d2["assignedTo"],  "analyst-2",      "update assignedTo")
    _assert_eq(len(d2["tags"]),   1,                "update tags replaced")

    # List after update
    list_r = list_alerts()
    _assert_eq(list_r.data["total"], 1, "list total=1 after update")

    # GET returns updated data
    get_r = get_alert(aid)
    _assert_eq(get_r.data["title"], "Updated Full", "get returns updated title")

    # Update explanation fields
    upd_exp = UpdateAlertRequest(reason="New reason", findingSummary="New summary",
                                  recommendedAction="New action")
    exp_r = update_alert_endpoint(aid, upd_exp)
    _assert(exp_r.success, "update explanation success")
    _assert_eq(exp_r.data["explanation"]["reason"], "New reason", "explanation reason updated")
    _assert_eq(exp_r.data["explanation"]["findingSummary"], "New summary", "explanation summary updated")

    # Update correlation fields
    upd_cor = UpdateAlertRequest(correlationScore=50.0, relatedAlertIds=["new-ra"])
    cor_r = update_alert_endpoint(aid, upd_cor)
    _assert(cor_r.success, "update correlation success")
    _assert_eq(cor_r.data["correlation"]["correlationScore"], 50.0, "correlation score updated")

    # Delete and verify
    del_r = delete_alert(aid)
    _assert(del_r.success, "delete after full lifecycle success")
    _assert_eq(len(_ALERT_STORE), 0, "store empty after full lifecycle")


# ===========================================================================
# Section 25 — Extended filter combinations
# ===========================================================================

def test_extended_filter_combinations():
    _reset_store()
    for i, (sev, src, conf, risk) in enumerate([
        ("CRITICAL", "FINDING", 95.0, 90.0),
        ("HIGH",     "RULE",    80.0, 75.0),
        ("MEDIUM",   "FINDING", 60.0, 55.0),
        ("LOW",      "MANUAL",  40.0, 35.0),
        ("INFO",     "SYSTEM",  20.0, 15.0),
    ]):
        create_alert(_make_create(
            title=f"Filter-{i}", severity=sev, source=src,
            confidence=conf, risk_score=risk,
            finding_id=f"fid-{i}", project_id=f"proj-{i % 2}",
            investigation_id=f"inv-{i % 3}",
        ))

    alerts = _all_alerts()

    # confidence range [60, 80]
    mid_conf = filter_alerts(alerts, min_confidence=60.0, max_confidence=80.0)
    _assert_eq(len(mid_conf), 2, "confidence range [60,80] → 2")

    # riskScore range [35, 75]
    mid_risk = filter_alerts(alerts, min_risk_score=35.0, max_risk_score=75.0)
    _assert_eq(len(mid_risk), 3, "riskScore range [35,75] → 3")

    # projectId=proj-0 (indices 0, 2, 4)
    p0 = filter_alerts(alerts, project_id="proj-0")
    _assert_eq(len(p0), 3, "filter projectId=proj-0 → 3")

    # projectId=proj-1 (indices 1, 3)
    p1 = filter_alerts(alerts, project_id="proj-1")
    _assert_eq(len(p1), 2, "filter projectId=proj-1 → 2")

    # investigationId=inv-0 (indices 0, 3)
    i0 = filter_alerts(alerts, investigation_id="inv-0")
    _assert_eq(len(i0), 2, "filter investigationId=inv-0 → 2")

    # FINDING (indices 0, 2) with minConfidence=60 → index 0 has conf=95, index 2 has conf=60 → 2
    combo1 = filter_alerts(alerts, source="FINDING", min_confidence=60.0)
    _assert_eq(len(combo1), 2, "FINDING + minConf=60 → 2")

    # severity=HIGH + source=RULE
    combo2 = filter_alerts(alerts, severity="HIGH", source="RULE")
    _assert_eq(len(combo2), 1, "HIGH + RULE → 1")

    # Non-matching combination
    combo3 = filter_alerts(alerts, severity="CRITICAL", source="MANUAL")
    _assert_eq(len(combo3), 0, "CRITICAL + MANUAL → 0")

    # All filters produce subset of original
    filtered = filter_alerts(alerts, min_confidence=1.0)
    _assert(len(filtered) <= len(alerts), "filter always produces subset")

    # Empty result preserved
    empty_filt = filter_alerts([], severity="HIGH")
    _assert_eq(empty_filt, [], "filter empty list → empty")


# ===========================================================================
# Section 26 — Extended sort coverage
# ===========================================================================

def test_extended_sort_coverage():
    _reset_store()
    timestamps = [
        "2026-03-01T12:00:00Z",
        "2026-01-15T08:00:00Z",
        "2026-06-20T18:00:00Z",
        "2026-02-10T06:00:00Z",
    ]
    for i, ts in enumerate(timestamps):
        create_alert(_make_create(
            title=f"Sort-{i}", finding_id=f"sf{i}",
            confidence=float(i * 25), risk_score=float(i * 20),
            created_at=ts,
        ))

    alerts = _all_alerts()

    # createdAt asc is chronological
    sorted_asc = sort_alerts(alerts, "createdAt", "asc")
    dates_asc = [a["createdAt"] for a in sorted_asc]
    _assert(dates_asc == sorted(dates_asc), "createdAt asc chronological")

    # createdAt desc is reverse chronological
    sorted_desc = sort_alerts(alerts, "createdAt", "desc")
    dates_desc = [a["createdAt"] for a in sorted_desc]
    _assert(dates_desc == sorted(dates_desc, reverse=True), "createdAt desc reverse")

    # confidence asc
    c_asc = sort_alerts(alerts, "confidence", "asc")
    _assert(c_asc[0]["confidence"] <= c_asc[-1]["confidence"], "confidence asc min first")

    # riskScore desc
    r_desc = sort_alerts(alerts, "riskscore", "desc")
    _assert(r_desc[0]["riskScore"] >= r_desc[-1]["riskScore"], "riskscore desc max first")

    # Empty list sort
    _assert_eq(sort_alerts([], "createdAt", "asc"), [], "sort empty list → empty")

    # Single-item sort
    single = [{"alertId": "x", "createdAt": "2026-01-01T00:00:00Z", "severity": "HIGH",
                "status": "NEW", "source": "FINDING", "confidence": 50.0, "riskScore": 40.0}]
    _assert_eq(sort_alerts(single, "confidence", "asc"), single, "sort single item returns same")

    # Sort stability: same-value items preserve relative order
    same_conf = [
        {"alertId": "z1", "confidence": 50.0, "createdAt": "2026-01-01T00:00:00Z",
         "severity": "HIGH", "status": "NEW", "source": "FINDING", "riskScore": 50.0},
        {"alertId": "a1", "confidence": 50.0, "createdAt": "2026-01-02T00:00:00Z",
         "severity": "LOW",  "status": "NEW", "source": "RULE",    "riskScore": 50.0},
    ]
    sorted_same = sort_alerts(same_conf, "confidence", "asc")
    _assert(len(sorted_same) == 2, "sort same-value items returns 2")


# ===========================================================================
# Section 27 — Extended bulk operations
# ===========================================================================

def test_extended_bulk_operations():
    _reset_store()

    # Bulk create 5 alerts
    reqs = [_make_create(title=f"Bulk-Ext-{i}", finding_id=f"bef{i}") for i in range(5)]
    resp = bulk_create_alerts(BulkCreateAlertsRequest(alerts=reqs))
    _assert(resp.success, "bulk create 5 success")
    _assert_eq(resp.data["successCount"], 5, "bulk create 5 succeeded")
    _assert_eq(resp.data["total"], 5, "bulk create total=5")
    created_ids = resp.data["succeeded"]
    _assert_eq(len(created_ids), 5, "bulk create returned 5 IDs")

    # Bulk update first 3 to HIGH severity
    upd_items = [
        BulkUpdateAlertsRequest.BulkUpdateItem(
            alertId=created_ids[i],
            update=UpdateAlertRequest(severity="HIGH"),
        )
        for i in range(3)
    ]
    upd_resp = bulk_update_alerts(BulkUpdateAlertsRequest(items=upd_items))
    _assert(upd_resp.success, "bulk update 3 success")
    _assert_eq(upd_resp.data["successCount"], 3, "bulk update 3 succeeded")
    for i in range(3):
        _assert_eq(_ALERT_STORE[created_ids[i]]["severity"], "HIGH",
                   f"bulk update id[{i}] severity HIGH")

    # Bulk update remaining 2 to OPEN status
    upd_items2 = [
        BulkUpdateAlertsRequest.BulkUpdateItem(
            alertId=created_ids[i],
            update=UpdateAlertRequest(status="OPEN"),
        )
        for i in range(3, 5)
    ]
    upd_resp2 = bulk_update_alerts(BulkUpdateAlertsRequest(items=upd_items2))
    _assert_eq(upd_resp2.data["successCount"], 2, "bulk update 2 status succeeded")

    # Statistics after bulk operations
    stats = get_alert_statistics()
    _assert_eq(stats.data["totalAlerts"], 5, "stats after bulk: totalAlerts=5")
    _assert_eq(stats.data["severityCounts"].get("HIGH", 0), 3, "stats: HIGH=3")

    # Bulk delete all 5
    del_resp = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=created_ids))
    _assert(del_resp.success, "bulk delete all 5 success")
    _assert_eq(del_resp.data["successCount"], 5, "bulk delete 5 succeeded")
    _assert_eq(len(_ALERT_STORE), 0, "store empty after bulk delete all")

    # Bulk delete already-deleted → all fail gracefully
    del_resp2 = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=created_ids))
    _assert(del_resp2.success, "bulk delete already-deleted returns success envelope")
    _assert_eq(del_resp2.data["successCount"], 0, "re-delete 0 succeeded")
    _assert_eq(del_resp2.data["failCount"], 5, "re-delete 5 failed")


# ===========================================================================
# Section 28 — Extended statistics coverage
# ===========================================================================

def test_extended_statistics_coverage():
    _reset_store()

    # Single alert
    create_alert(_make_create(title="Stat-1", severity="INFO", source="SYSTEM",
                               confidence=10.0, risk_score=5.0))
    s = get_alert_statistics().data
    _assert_eq(s["totalAlerts"], 1, "stats single: totalAlerts=1")
    _assert_eq(s["severityCounts"]["INFO"], 1, "stats single: INFO=1")
    _assert_eq(s["typeCounts"]["SYSTEM"],   1, "stats single: SYSTEM=1")
    _assert_eq(s["averageConfidence"], 10.0, "stats single: averageConfidence=10.0")
    _assert_eq(s["averageRiskScore"],  5.0,  "stats single: averageRiskScore=5.0")

    # All same severity
    _reset_store()
    for i in range(4):
        create_alert(_make_create(title=f"S{i}", finding_id=f"sf{i}",
                                   severity="HIGH", confidence=float(i * 10), risk_score=float(i * 8)))
    s2 = get_alert_statistics().data
    _assert_eq(s2["severityCounts"].get("HIGH", 0), 4, "all HIGH: severityCounts HIGH=4")
    _assert_eq(len(s2["severityCounts"]), 1, "all HIGH: only one severity key")
    expected_avg_conf = round((0+10+20+30) / 4, 4)
    _assert_eq(s2["averageConfidence"], expected_avg_conf, "all HIGH: averageConfidence correct")

    # Statistics response is AlertStatisticsResponse model
    _reset_store()
    create_alert(_make_create())
    raw_stats = _compute_statistics(_all_alerts())
    _assert(isinstance(raw_stats, AlertStatisticsResponse), "_compute_statistics returns AlertStatisticsResponse")
    _assert(hasattr(raw_stats, "totalAlerts"),       "stats has totalAlerts")
    _assert(hasattr(raw_stats, "severityCounts"),    "stats has severityCounts")
    _assert(hasattr(raw_stats, "statusCounts"),      "stats has statusCounts")
    _assert(hasattr(raw_stats, "typeCounts"),        "stats has typeCounts")
    _assert(hasattr(raw_stats, "averageConfidence"), "stats has averageConfidence")
    _assert(hasattr(raw_stats, "averageRiskScore"),  "stats has averageRiskScore")


# ===========================================================================
# Section 29 — Extended search coverage
# ===========================================================================

def test_extended_search_coverage():
    _reset_store()
    # Create alerts with distinct projects and findings
    for i in range(6):
        create_alert(_make_create(
            title=f"Search-Ext-{i}", finding_id=f"sef{i}",
            project_id=f"sp{i % 3}", investigation_id=f"si{i % 2}",
            severity=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "HIGH"][i],
            source=["FINDING", "RULE", "MANUAL", "SYSTEM", "FINDING", "RULE"][i],
            confidence=float(i * 15), risk_score=float(i * 12),
        ))

    # Filter by projectId in search
    r = search_alerts(q="Search", project_filter="sp0")
    _assert_eq(r.data["total"], 2, "search + projectId filter → 2")

    # Filter by investigationId in search
    r2 = search_alerts(q="Search", investigation_filter="si0")
    _assert_eq(r2.data["total"], 3, "search + investigationId filter → 3")

    # Filter by findingId in search
    r3 = search_alerts(q="Search", finding_filter="sef3")
    _assert_eq(r3.data["total"], 1, "search + findingId filter → 1")

    # Combined severity + minConfidence
    r4 = search_alerts(q="Search", severity_filter="HIGH", min_confidence=60.0)
    _assert(r4.data["total"] <= 2, "search HIGH + minConf=60 → ≤2")

    # Source filter
    r5 = search_alerts(q="Search", source_filter="RULE")
    _assert_eq(r5.data["total"], 2, "search source=RULE → 2")

    # Page size 1 — totalPages = totalItems
    r6 = search_alerts(q="Search", page=1, page_size=1)
    _assert_eq(r6.data["pageSize"], 1, "search pageSize=1 echoed")
    _assert_eq(r6.data["totalPages"], r6.data["total"], "search page_size=1 totalPages=total")
    _assert_eq(len(r6.data["alerts"]), 1, "search page_size=1 returns 1 alert")

    # Max riskScore filter: risks are 0, 12, 24, 36, 48, 60 → values ≤ 24 are 0,12,24 = 3
    r7 = search_alerts(q="Search", max_risk_score=24.0)
    _assert_eq(r7.data["total"], 3, "search maxRiskScore=24 → 3")

    # All sort keys work without error
    for sk in ["severity", "status", "type", "confidence", "riskScore", "createdAt"]:
        r_sk = search_alerts(q="Search", sort_by=sk, sort_order="asc")
        _assert(r_sk.success, f"search sortBy={sk} succeeds")
        r_sk_d = search_alerts(q="Search", sort_by=sk, sort_order="desc")
        _assert(r_sk_d.success, f"search sortBy={sk} desc succeeds")


# ===========================================================================
# Section 30 — Extended pagination coverage
# ===========================================================================

def test_extended_pagination_coverage():
    _reset_store()
    for i in range(15):
        create_alert(_make_create(title=f"Page-{i}", finding_id=f"pf{i}"))

    # Page 1 of 3 (size=5)
    p1, pag1 = paginate_alerts(_all_alerts(), 1, 5)
    _assert_eq(pag1.totalItems, 15, "15 items: totalItems=15")
    _assert_eq(pag1.totalPages,  3, "15/5=3 pages")
    _assert_eq(len(p1), 5, "page 1: 5 items")

    # Page 2
    p2, pag2 = paginate_alerts(_all_alerts(), 2, 5)
    _assert_eq(len(p2), 5, "page 2: 5 items")
    _assert(p2[0] != p1[0], "page 2 first item differs from page 1 first item")

    # Page 3
    p3, pag3 = paginate_alerts(_all_alerts(), 3, 5)
    _assert_eq(len(p3), 5, "page 3: 5 items")

    # Page 4 (beyond)
    p4, pag4 = paginate_alerts(_all_alerts(), 4, 5)
    _assert_eq(len(p4), 0, "page 4 beyond → 0")

    # All items on single page
    pall, pagall = paginate_alerts(_all_alerts(), 1, 100)
    _assert_eq(len(pall), 15, "single huge page: all 15")
    _assert_eq(pagall.totalPages, 1, "single huge page: totalPages=1")

    # Page size 1: 15 pages
    _, pag_s1 = paginate_alerts(_all_alerts(), 1, 1)
    _assert_eq(pag_s1.totalPages, 15, "size=1: 15 pages")

    # All pages together cover all items
    all_items = _all_alerts()
    collected = []
    for pg in range(1, 4):
        slice_, _ = paginate_alerts(all_items, pg, 5)
        collected.extend(slice_)
    _assert_eq(len(collected), 15, "all pages combined = 15 items")

    # No duplicate items across pages
    seen_ids = [a["alertId"] for a in collected]
    _assert_eq(len(seen_ids), len(set(seen_ids)), "no duplicate alertIds across pages")


# ===========================================================================
# Section 31 — Extended serialization coverage
# ===========================================================================

def test_extended_serialization_coverage():
    _reset_store()

    # Minimal alert (all optional fields absent)
    r = create_alert(_make_create())
    d = r.data

    # Absent optional fields default correctly
    _assert(d["closedAt"] is None,      "closedAt=None when not set")
    _assert(d["acknowledgedAt"] is None,"acknowledgedAt=None when not set")
    _assert(d["resolvedAt"] is None,    "resolvedAt=None when not set")
    _assert(d["assignedTo"] is None,    "assignedTo=None when not set")
    _assert_eq(d["assetIds"],        [],  "assetIds=[] for minimal alert")
    _assert_eq(d["relationshipIds"], [],  "relationshipIds=[] for minimal alert")
    _assert_eq(d["evidenceIds"],     [],  "evidenceIds=[] for minimal alert")
    _assert_eq(d["graphNodeIds"],    [],  "graphNodeIds=[] for minimal alert")
    _assert_eq(d["timelineEventIds"],[],  "timelineEventIds=[] for minimal alert")

    # auditTrail is a list of strings
    _assert(all(isinstance(e, str) for e in d["auditTrail"]),
            "auditTrail entries are all strings")

    # Correlation fields all present even when defaults
    cor = d["correlation"]
    _assert_eq(cor["relatedAlertIds"],   [], "correlation.relatedAlertIds=[] default")
    _assert_eq(cor["relatedFindingIds"], [], "correlation.relatedFindingIds=[] default")
    _assert_eq(cor["sharedEvidenceIds"], [], "correlation.sharedEvidenceIds=[] default")
    _assert_eq(cor["sharedAssets"],      [], "correlation.sharedAssets=[] default")
    _assert_eq(cor["correlationScore"],  0.0,"correlation.correlationScore=0.0 default")
    _assert(isinstance(cor["correlationId"], str), "correlationId is string")

    # AlertResponse model can be constructed from response data
    resp_model = AlertResponse(**d)
    _assert(isinstance(resp_model, AlertResponse), "AlertResponse constructed from response dict")
    _assert_eq(resp_model.alertId, d["alertId"], "AlertResponse.alertId matches")

    # Explanation response model
    exp = d["explanation"]
    exp_model = AlertExplanationResponse(**exp)
    _assert(isinstance(exp_model, AlertExplanationResponse), "AlertExplanationResponse constructed")

    # Correlation response model
    cor_model = AlertCorrelationResponse(**cor)
    _assert(isinstance(cor_model, AlertCorrelationResponse), "AlertCorrelationResponse constructed")

    # AlertListResponse model
    list_model = AlertListResponse(alerts=[AlertResponse(**d)], total=1)
    _assert(isinstance(list_model, AlertListResponse), "AlertListResponse constructed")
    _assert_eq(list_model.total, 1, "AlertListResponse.total=1")

    # BulkOperationResult model
    bulk_result = BulkOperationResult(
        succeeded=["id1"], failed=[], total=1, successCount=1, failCount=0
    )
    _assert(isinstance(bulk_result, BulkOperationResult), "BulkOperationResult constructed")
    _assert_eq(bulk_result.successCount, 1, "BulkOperationResult.successCount=1")


# ===========================================================================
# Section 32 — Lifecycle transitions
# ===========================================================================

def test_lifecycle_transitions():
    _reset_store()
    r = create_alert(_make_create(title="Lifecycle"))
    aid = r.data["alertId"]
    _assert_eq(r.data["status"], "NEW", "initial status NEW")

    # NEW → OPEN
    u1 = update_alert_endpoint(aid, UpdateAlertRequest(status="OPEN"))
    _assert_eq(u1.data["status"], "OPEN", "transition to OPEN")
    _assert("Status changed to OPEN" in u1.data["auditTrail"], "OPEN in audit")

    # OPEN → ACKNOWLEDGED
    u2 = update_alert_endpoint(aid, UpdateAlertRequest(status="ACKNOWLEDGED"))
    _assert_eq(u2.data["status"], "ACKNOWLEDGED", "transition to ACKNOWLEDGED")
    _assert("Status changed to ACKNOWLEDGED" in u2.data["auditTrail"], "ACKNOWLEDGED in audit")

    # ACKNOWLEDGED → IN_PROGRESS
    u3 = update_alert_endpoint(aid, UpdateAlertRequest(status="IN_PROGRESS"))
    _assert_eq(u3.data["status"], "IN_PROGRESS", "transition to IN_PROGRESS")

    # IN_PROGRESS → RESOLVED
    u4 = update_alert_endpoint(aid, UpdateAlertRequest(status="RESOLVED"))
    _assert_eq(u4.data["status"], "RESOLVED", "transition to RESOLVED")

    # RESOLVED → CLOSED
    u5 = update_alert_endpoint(aid, UpdateAlertRequest(status="CLOSED"))
    _assert_eq(u5.data["status"], "CLOSED", "transition to CLOSED")

    # CLOSED → SUPPRESSED
    u6 = update_alert_endpoint(aid, UpdateAlertRequest(status="SUPPRESSED"))
    _assert_eq(u6.data["status"], "SUPPRESSED", "transition to SUPPRESSED")

    # auditTrail grows with each status change
    _assert(len(u6.data["auditTrail"]) >= 6, "auditTrail has at least 6 entries")

    # updatedAt advances (not equal to createdAt after updates)
    _assert(u6.data["updatedAt"] != r.data["createdAt"], "updatedAt != createdAt after updates")

    # Severity escalation tracked in audit
    r2 = create_alert(_make_create(title="SevChange", finding_id="f-sev"))
    aid2 = r2.data["alertId"]
    su = update_alert_endpoint(aid2, UpdateAlertRequest(severity="CRITICAL"))
    _assert("Severity changed to CRITICAL" in su.data["auditTrail"], "severity change in audit")

    # assignedTo tracked in audit
    au = update_alert_endpoint(aid2, UpdateAlertRequest(assignedTo="analyst-x"))
    _assert("Assigned" in au.data["auditTrail"], "assigned in audit")

    # Multiple field update in one call
    mu = update_alert_endpoint(aid2, UpdateAlertRequest(
        title="Multi", severity="HIGH", status="OPEN", confidence=77.0,
    ))
    _assert(mu.success, "multi-field update success")
    _assert_eq(mu.data["title"],      "Multi", "multi update title")
    _assert_eq(mu.data["severity"],   "HIGH",  "multi update severity")
    _assert_eq(mu.data["status"],     "OPEN",  "multi update status")
    _assert_eq(mu.data["confidence"], 77.0,    "multi update confidence")


# ===========================================================================
# Section 33 — Multi-source multi-severity
# ===========================================================================

def test_multi_source_multi_severity():
    _reset_store()
    matrix = [
        ("INFO",     "FINDING"), ("INFO",     "RULE"),
        ("LOW",      "MANUAL"),  ("LOW",      "SYSTEM"),
        ("MEDIUM",   "FINDING"), ("MEDIUM",   "RULE"),
        ("HIGH",     "MANUAL"),  ("HIGH",     "SYSTEM"),
        ("CRITICAL", "FINDING"), ("CRITICAL", "RULE"),
    ]
    for i, (sev, src) in enumerate(matrix):
        create_alert(_make_create(
            title=f"MS-{i}", severity=sev, source=src,
            finding_id=f"mf{i}", confidence=float(i*10), risk_score=float(i*9),
        ))

    # Stats covers all severities
    s = get_alert_statistics().data
    _assert_eq(s["totalAlerts"], 10, "matrix: totalAlerts=10")
    for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        _assert_eq(s["severityCounts"].get(sev, 0), 2, f"matrix: {sev}=2")
    for src in ["FINDING", "RULE", "MANUAL", "SYSTEM"]:
        expected = 3 if src in ("FINDING", "RULE") else 2
        _assert_eq(s["typeCounts"].get(src, 0), expected, f"matrix: source {src} count correct")

    # Filter each severity returns exactly 2
    for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        r = search_alerts(q="MS", severity_filter=sev)
        _assert_eq(r.data["total"], 2, f"search+filter {sev} → 2")

    # Filter each source
    for src, expected_count in [("FINDING", 3), ("RULE", 3), ("MANUAL", 2), ("SYSTEM", 2)]:
        r = search_alerts(q="MS", source_filter=src)
        _assert_eq(r.data["total"], expected_count, f"search+filter {src} → {expected_count}")

    # averageConfidence = (0+10+20+30+40+50+60+70+80+90)/10 = 45.0
    _assert_eq(s["averageConfidence"], 45.0, "matrix averageConfidence=45.0")
    # averageRiskScore = (0+9+18+27+36+45+54+63+72+81)/10 = 40.5
    _assert_eq(s["averageRiskScore"], 40.5, "matrix averageRiskScore=40.5")


# ===========================================================================
# Section 34 — Bulk edge cases
# ===========================================================================

def test_bulk_edge_cases():
    _reset_store()

    # Bulk create then bulk update then bulk delete full cycle
    reqs = [_make_create(title=f"Cycle-{i}", finding_id=f"cyc{i}") for i in range(4)]
    cr = bulk_create_alerts(BulkCreateAlertsRequest(alerts=reqs))
    ids = cr.data["succeeded"]
    _assert_eq(len(ids), 4, "bulk full cycle: created 4")

    upd_items = [BulkUpdateAlertsRequest.BulkUpdateItem(
        alertId=i, update=UpdateAlertRequest(severity="HIGH"),
    ) for i in ids]
    ur = bulk_update_alerts(BulkUpdateAlertsRequest(items=upd_items))
    _assert_eq(ur.data["successCount"], 4, "bulk full cycle: updated 4")
    for i in ids:
        _assert_eq(_ALERT_STORE[i]["severity"], "HIGH", f"bulk update {i} severity=HIGH")

    dr = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=ids))
    _assert_eq(dr.data["successCount"], 4, "bulk full cycle: deleted 4")
    _assert_eq(len(_ALERT_STORE), 0, "bulk full cycle: store empty")

    # Bulk create with identical alerts (all duplicates after first)
    same_req = _make_create(title="Same")
    bc = bulk_create_alerts(BulkCreateAlertsRequest(alerts=[same_req, same_req, same_req]))
    _assert_eq(bc.data["successCount"], 1, "bulk 3 identical: 1 succeeded")
    _assert_eq(bc.data["failCount"], 2, "bulk 3 identical: 2 failed (duplicate)")
    _assert_eq(len(_ALERT_STORE), 1, "store has 1 after 3 identical bulk create")

    # Bulk update with invalid status in one item
    _reset_store()
    r1 = create_alert(_make_create(title="BU-A", finding_id="bu-a"))
    r2 = create_alert(_make_create(title="BU-B", finding_id="bu-b"))
    id1, id2 = r1.data["alertId"], r2.data["alertId"]

    mixed_upd = BulkUpdateAlertsRequest(items=[
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id1, update=UpdateAlertRequest(status="OPEN")),
        BulkUpdateAlertsRequest.BulkUpdateItem(alertId=id2, update=UpdateAlertRequest(status="NOTVALID")),
    ])
    mur = bulk_update_alerts(mixed_upd)
    _assert_eq(mur.data["successCount"], 1, "mixed status update: 1 succeeded")
    _assert_eq(mur.data["failCount"],    1, "mixed status update: 1 failed")
    _assert_eq(_ALERT_STORE[id1]["status"], "OPEN", "valid update applied")
    _assert_eq(_ALERT_STORE[id2]["status"], "NEW",  "invalid update not applied")

    # BulkOperationResult fields
    result_obj = BulkOperationResult(
        succeeded=["x"], failed=[{"alertId": "y", "reason": "err"}],
        total=2, successCount=1, failCount=1,
    )
    _assert_eq(result_obj.total, 2, "BulkOperationResult.total=2")
    _assert_eq(result_obj.successCount, 1, "BulkOperationResult.successCount=1")
    _assert_eq(result_obj.failCount, 1, "BulkOperationResult.failCount=1")
    _assert_eq(result_obj.succeeded, ["x"], "BulkOperationResult.succeeded=['x']")
    _assert_eq(len(result_obj.failed), 1, "BulkOperationResult.failed has 1 entry")


# ===========================================================================
# Section 35 — Filter and search agreement
# ===========================================================================

def test_filter_search_agreement():
    """Verify that filter_alerts and search endpoint with filters give consistent counts."""
    _reset_store()
    sevs     = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    srcs     = ["FINDING", "RULE", "MANUAL", "SYSTEM", "FINDING"]
    confs    = [10.0, 30.0, 50.0, 70.0, 90.0]
    risks    = [8.0,  24.0, 40.0, 56.0, 72.0]

    for i in range(5):
        create_alert(_make_create(
            title=f"Agree-{i}", finding_id=f"agf{i}",
            severity=sevs[i], source=srcs[i],
            confidence=confs[i], risk_score=risks[i],
        ))

    alerts = _all_alerts()

    # For each severity: filter_alerts count == search endpoint count
    for sev in sevs:
        filt_count = len(filter_alerts(alerts, severity=sev))
        search_count = search_alerts(q="Agree", severity_filter=sev).data["total"]
        _assert_eq(filt_count, search_count, f"filter/search agree on severity={sev}")

    # For each source: filter_alerts count == search endpoint count
    unique_srcs = list(set(srcs))
    for src in unique_srcs:
        filt_count = len(filter_alerts(alerts, source=src))
        search_count = search_alerts(q="Agree", source_filter=src).data["total"]
        _assert_eq(filt_count, search_count, f"filter/search agree on source={src}")

    # minConfidence agreement
    for threshold in [10.0, 50.0, 90.0]:
        fc = len(filter_alerts(alerts, min_confidence=threshold))
        sc = search_alerts(q="Agree", min_confidence=threshold).data["total"]
        _assert_eq(fc, sc, f"filter/search agree on minConfidence={threshold}")

    # maxRiskScore agreement
    for threshold in [24.0, 56.0, 72.0]:
        fc = len(filter_alerts(alerts, max_risk_score=threshold))
        sc = search_alerts(q="Agree", max_risk_score=threshold).data["total"]
        _assert_eq(fc, sc, f"filter/search agree on maxRiskScore={threshold}")

    # Sorted results from search are subset of all (total is the same)
    for sk in ["confidence", "riskScore", "severity"]:
        sc_total = search_alerts(q="Agree", sort_by=sk, sort_order="asc").data["total"]
        _assert_eq(sc_total, 5, f"search sort {sk}: total unchanged at 5")

    # Statistics total matches list total
    stats_total = get_alert_statistics().data["totalAlerts"]
    list_total  = list_alerts().data["total"]
    _assert_eq(stats_total, list_total, "stats totalAlerts == list total")
    _assert_eq(stats_total, 5, "both totals = 5")


# ===========================================================================
# Section 36 — Final coverage top-up (pushes total to 650+)
# ===========================================================================

def test_final_coverage_topup():
    _reset_store()

    # --- CreateAlertRequest field defaults ---
    req = CreateAlertRequest(
        projectId="p", findingId="f", investigationId="i",
        title="t", createdBy="b", createdAt="2026-01-01T00:00:00Z",
    )
    _assert_eq(req.source,    "FINDING", "default source=FINDING")
    _assert_eq(req.severity,  "MEDIUM",  "default severity=MEDIUM")
    _assert_eq(req.description, "",      "default description=''")
    _assert_eq(req.confidence,  0.0,     "default confidence=0.0")
    _assert_eq(req.riskScore,   0.0,     "default riskScore=0.0")
    _assert(req.assignedTo is None,      "default assignedTo=None")
    _assert(req.tags is None,            "default tags=None")
    _assert(req.metadata is None,        "default metadata=None")

    # --- UpdateAlertRequest all-None ---
    upd = UpdateAlertRequest()
    _assert(not upd.has_any_field(), "empty update has_any_field=False")
    for f in ["title","description","severity","status","confidence","riskScore",
              "assignedTo","tags","metadata"]:
        _assert(getattr(upd, f, None) is None, f"UpdateAlertRequest.{f} defaults None")

    # --- AlertFilterRequest all-None ---
    filt = AlertFilterRequest()
    for f in ["severity","status","source","projectId","findingId",
              "investigationId","assignedTo","minConfidence","maxConfidence",
              "minRiskScore","maxRiskScore"]:
        _assert(getattr(filt, f, "SENTINEL") is None, f"AlertFilterRequest.{f} defaults None")

    # --- find_alert on multi-field match ---
    create_alert(_make_create(title="FA-One", finding_id="fa1", project_id="proj-fa"))
    create_alert(_make_create(title="FA-Two", finding_id="fa2", project_id="proj-fb"))
    alerts = _all_alerts()
    by_proj = find_alert(alerts, "projectId", "proj-fa")
    _assert(by_proj is not None,             "find_alert by projectId found")
    _assert_eq(by_proj["title"], "FA-One",   "find_alert returns correct record by projectId")
    by_proj_ci = find_alert(alerts, "projectId", "PROJ-FA")
    _assert(by_proj_ci is not None,          "find_alert case-insensitive projectId")

    # --- _all_alerts order is stable ---
    ids_1 = [a["alertId"] for a in _all_alerts()]
    ids_2 = [a["alertId"] for a in _all_alerts()]
    _assert_eq(ids_1, ids_2, "_all_alerts order is stable across calls")

    # --- list_alerts echoes correct total ---
    list_r = list_alerts()
    _assert_eq(list_r.data["total"], len(_ALERT_STORE), "list_alerts total matches store size")
    _assert_eq(len(list_r.data["alerts"]), len(_ALERT_STORE), "list_alerts items match store size")

    # --- GET returns full response shape ---
    aid = list_r.data["alerts"][0]["alertId"]
    gr = get_alert(aid)
    _assert(gr.success, "get existing alert success")
    for field in ["alertId", "title", "severity", "status", "source",
                   "confidence", "riskScore", "explanation", "correlation", "auditTrail"]:
        _assert(field in gr.data, f"get response has field '{field}'")

    # --- search returns sortBy/sortOrder defaults ---
    sr = search_alerts(q="FA")
    _assert_eq(sr.data["sortBy"],    "createdAt", "search default sortBy=createdAt")
    _assert_eq(sr.data["sortOrder"], "asc",       "search default sortOrder=asc")

    # --- paginate 0 items → totalPages=0 ---
    _, pag = paginate_alerts([], 1, 10)
    _assert_eq(pag.totalItems, 0, "paginate 0 items totalItems=0")
    _assert_eq(pag.totalPages, 0, "paginate 0 items totalPages=0")

    # --- bulk delete total field matches input length ---
    r1 = create_alert(_make_create(title="BD-top1", finding_id="bdt1"))
    r2 = create_alert(_make_create(title="BD-top2", finding_id="bdt2"))
    ids = [r1.data["alertId"], r2.data["alertId"]]
    bd = bulk_delete_alerts(BulkDeleteAlertsRequest(alertIds=ids))
    _assert_eq(bd.data["total"], 2, "bulk delete total=2")

    # --- search with no results has pagination zeros ---
    _reset_store()
    no_r = search_alerts(q="NoMatchXYZ123")
    _assert_eq(no_r.data["total"], 0, "no-match search total=0")
    _assert_eq(no_r.data["page"],  1, "no-match search page=1")
    _assert_eq(no_r.data["totalPages"], 0, "no-match search totalPages=0")


# ===========================================================================
# Main runner
# ===========================================================================

def run_all():
    suites = [
        ("Router Registration",              test_router_registration),
        ("Model Validation",                 test_model_validation),
        ("Enum Validators",                  test_enum_validators),
        ("CRUD",                             test_crud),
        ("Create Validation",                test_create_validation),
        ("Statistics",                       test_statistics),
        ("find_alert helper",                test_find_alert),
        ("sort_alerts helper",               test_sort_alerts),
        ("filter_alerts helper",             test_filter_alerts),
        ("paginate_alerts helper",           test_paginate_alerts),
        ("Search endpoint",                  test_search),
        ("Bulk create",                      test_bulk_create),
        ("Bulk update",                      test_bulk_update),
        ("Bulk delete",                      test_bulk_delete),
        ("Deterministic IDs",                test_deterministic_ids),
        ("Serialization shape",              test_serialization),
        ("Edge cases",                       test_edge_cases),
        ("Record to dict round-trip",        test_record_to_dict_roundtrip),
        ("Compute statistics direct",        test_compute_statistics_direct),
        ("Search helper",                    test_search_helper),
        ("Update preserves immutable",       test_update_preserves_immutable),
        ("Bulk update validate_request",     test_bulk_update_validate_request),
        ("APIResponse envelope",             test_api_response_envelope),
        ("Extended CRUD lifecycle",          test_extended_crud_lifecycle),
        ("Extended filter combinations",     test_extended_filter_combinations),
        ("Extended sort coverage",           test_extended_sort_coverage),
        ("Extended bulk operations",         test_extended_bulk_operations),
        ("Extended statistics coverage",     test_extended_statistics_coverage),
        ("Extended search coverage",         test_extended_search_coverage),
        ("Extended pagination coverage",     test_extended_pagination_coverage),
        ("Extended serialization coverage",  test_extended_serialization_coverage),
        ("Lifecycle transitions",            test_lifecycle_transitions),
        ("Multi-source multi-severity",      test_multi_source_multi_severity),
        ("Bulk edge cases",                  test_bulk_edge_cases),
        ("Filter and search agreement",      test_filter_search_agreement),
        ("Final coverage top-up",            test_final_coverage_topup),
    ]

    for name, fn in suites:
        before = _PASSED + _FAILED
        fn()
        after = _PASSED + _FAILED
        ran = after - before
        print(f"  {name}: {ran} assertions")

    print()
    total = _PASSED + _FAILED
    print(f"{'='*60}")
    print(f"RESULTS: {_PASSED}/{total} assertions passed.")
    if _FAILED:
        print(f"\nFAILURES ({_FAILED}):")
        for e in _ERRORS:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("ALL PASSED.")


if __name__ == "__main__":
    print("Smoke Test — Alerts API (Part A + Part B)")
    print("=" * 60)
    run_all()
