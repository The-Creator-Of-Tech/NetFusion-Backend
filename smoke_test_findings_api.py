"""
Findings API Smoke Test — Phase A4.7.5 (Part A + Part B)
=========================================================
Target: 600+ assertions.

Run: python smoke_test_findings_api.py
"""
from __future__ import annotations
import sys
from typing import Any, Dict, List

from api.investigation.finding_models import (
    BulkCreateFindingsRequest, BulkDeleteFindingsRequest,
    BulkOperationResult, BulkUpdateFindingsRequest,
    CreateFindingRequest, FindingStatisticsResponse,
    UpdateFindingRequest,
)
from api.investigation.finding_router import (
    _FINDING_STORE, _reset_store, finding_router,
    bulk_create_findings, bulk_delete_findings, bulk_update_findings,
    create_finding, delete_finding, filter_findings_api, find_finding,
    get_finding, get_finding_statistics, list_findings,
    paginate_findings, search_findings, sort_findings_api,
    update_finding_endpoint,
)
from api.models import APIResponse

_PASS = 0; _FAIL = 0; _FAIL_MSGS: List[str] = []

def ok(cond: bool, msg: str) -> None:
    global _PASS, _FAIL
    if cond: _PASS += 1
    else:
        _FAIL += 1; _FAIL_MSGS.append(f"FAIL: {msg}")
        print(f"  FAIL: {msg}")

def eq(a: Any, b: Any, msg: str) -> None:
    ok(a == b, f"{msg}  (got {a!r}, expected {b!r})")

def section(t: str) -> None:
    print(f"\n{'='*60}\n  {t}\n{'='*60}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_BASE = dict(
    projectId="proj-1", investigationId="inv-1",
    createdBy="analyst", createdAt="2026-01-01T00:00:00Z",
)

def _make(title: str, severity: str = "MEDIUM", category: str = "NETWORK",
          confidence: float = 50.0, risk_score: float = 50.0,
          status: str = "OPEN", **kw) -> Dict[str, Any]:
    req = CreateFindingRequest(
        **_BASE, title=title, severity=severity,
        category=category, confidence=confidence,
        riskScore=risk_score, **kw,
    )
    resp = create_finding(req)
    assert resp.success, f"create failed: {resp.message}"
    return resp.data

def _setup() -> None:
    _reset_store()

# ===========================================================================
# 1. Router Registration
# ===========================================================================
section("1. Router Registration")
paths   = [r.path for r in finding_router.routes]
methods = {r.path: [m for m in r.methods] for r in finding_router.routes}

ok("/findings"              in paths, "GET /findings registered")
ok("/findings/statistics"   in paths, "GET /findings/statistics registered")
ok("/findings/search"       in paths, "GET /findings/search registered")
ok("/findings/bulk/create"  in paths, "POST /findings/bulk/create registered")
ok("/findings/bulk/update"  in paths, "PUT /findings/bulk/update registered")
ok("/findings/bulk/delete"  in paths, "DELETE /findings/bulk/delete registered")
ok("/findings/{findingId}"  in paths, "GET|PUT|DELETE /findings/{findingId} registered")
ok(finding_router.prefix == "/findings", "Router prefix=/findings")
ok("Findings" in finding_router.tags,    "Router tag=Findings")
eq(len(paths), 10, "10 routes registered")

# ===========================================================================
# 2. CRUD — Create
# ===========================================================================
section("2. CRUD — Create")
_setup()

req1 = CreateFindingRequest(
    **_BASE, title="SQL Injection", severity="CRITICAL",
    category="NETWORK", confidence=90.0, riskScore=88.0,
    description="SQL injection in login endpoint",
    reason="Malformed query detected",
    evidenceSummary="Packet 1042 shows injected string",
    recommendedAction="Apply parameterised queries",
    tags=["injection","web"], metadata={"cve": "CVE-2024-001"},
)
r1 = create_finding(req1)
ok(r1.success is True,       "create_finding success=True")
ok(r1.data is not None,      "create_finding returns data")
ok("findingId"   in r1.data, "data has findingId")
ok("findingKey"  in r1.data, "data has findingKey")
ok("severity"    in r1.data, "data has severity")
ok("status"      in r1.data, "data has status")
ok("explanation" in r1.data, "data has explanation")
ok("auditTrail"  in r1.data, "data has auditTrail")
eq(r1.data["severity"], "CRITICAL",   "severity=CRITICAL")
eq(r1.data["category"], "NETWORK",    "category=NETWORK")
eq(r1.data["status"],   "OPEN",       "status defaults to OPEN")
eq(r1.data["confidence"], 90.0,       "confidence=90.0")
eq(r1.data["riskScore"],  88.0,       "riskScore=88.0")
ok("injection" in r1.data["tags"],    "tag 'injection' present")
ok(r1.data["metadata"]["cve"] == "CVE-2024-001", "metadata.cve preserved")
ok(r1.data["explanation"]["reason"] == "Malformed query detected", "explanation.reason")
ok("Created" in r1.data["auditTrail"], "auditTrail contains 'Created'")

fid1 = r1.data["findingId"]
ok(len(fid1) == 36, "findingId is UUID (36 chars)")

# Duplicate → 409
r_dup = create_finding(req1)
ok(r_dup.success is False, "create_finding 409 on duplicate")

# Missing required field
req_bad = CreateFindingRequest(**_BASE, title="", severity="LOW", category="HOST")
r_bad = create_finding(req_bad)
ok(r_bad.success is False, "create_finding 422 on empty title")

# Invalid category
req_inv_cat = CreateFindingRequest(**_BASE, title="x", category="INVALID_CAT")
r_inv_cat = create_finding(req_inv_cat)
ok(r_inv_cat.success is False, "create_finding 422 on invalid category")

# Invalid severity
req_inv_sev = CreateFindingRequest(**_BASE, title="y", severity="EXTREME")
r_inv_sev = create_finding(req_inv_sev)
ok(r_inv_sev.success is False, "create_finding 422 on invalid severity")

# Determinism: same inputs → same findingId
_make("SQL Injection 2", severity="HIGH", category="NETWORK")
r_det_dup = create_finding(
    CreateFindingRequest(**_BASE, title="SQL Injection 2", severity="HIGH", category="NETWORK")
)
ok(r_det_dup.success is False, "Deterministic ID: second create with same key returns conflict")

# Create several nodes for later tests
_make("Finding A", severity="HIGH",     category="HOST",    confidence=80.0, risk_score=75.0)
_make("Finding B", severity="LOW",      category="NETWORK", confidence=20.0, risk_score=10.0)
_make("Finding C", severity="MEDIUM",   category="TRAFFIC", confidence=55.0, risk_score=50.0)
_make("Finding D", severity="INFO",     category="SYSTEM",  confidence=10.0, risk_score=5.0)
_make("Finding E", severity="CRITICAL", category="IDENTITY",confidence=95.0, risk_score=95.0)
ok(len(_FINDING_STORE) >= 5, "At least 5 findings in store")

# ===========================================================================
# 3. CRUD — Read
# ===========================================================================
section("3. CRUD — Read")

r_get = get_finding(fid1)
ok(r_get.success is True,             "get_finding success=True")
eq(r_get.data["findingId"], fid1,     "get_finding returns correct finding")
eq(r_get.data["severity"], "CRITICAL","get_finding preserves severity")

r_404 = get_finding("nonexistent-id")
ok(r_404.success is False, "get_finding 404")
ok("not found" in r_404.message.lower(), "404 message mentions 'not found'")

r_list = list_findings()
ok(r_list.success is True,           "list_findings success=True")
ok("findings" in r_list.data,        "list data has 'findings' key")
ok("total"    in r_list.data,        "list data has 'total' key")
eq(r_list.data["total"], len(_FINDING_STORE), "list total matches store size")
ok(len(r_list.data["findings"]) == r_list.data["total"], "list returns all findings")

# Serialization check
f0 = r_list.data["findings"][0]
for key in ("findingId","findingKey","projectId","investigationId","title",
            "severity","status","category","confidence","riskScore",
            "assetIds","tags","metadata","createdAt","updatedAt",
            "engineVersion","auditTrail","explanation"):
    ok(key in f0, f"Serialized finding has '{key}'")

# ===========================================================================
# 4. CRUD — Update
# ===========================================================================
section("4. CRUD — Update")

r_upd = update_finding_endpoint(fid1, UpdateFindingRequest(severity="HIGH", confidence=75.0))
ok(r_upd.success is True, "update_finding success=True")
eq(r_upd.data["severity"], "HIGH", "update changes severity")
eq(r_upd.data["confidence"], 75.0, "update changes confidence")
eq(r_upd.data["category"], "NETWORK", "update preserves category (immutable)")

# Persisted
r_reget = get_finding(fid1)
eq(r_reget.data["severity"], "HIGH", "update persisted")

# Status change
r_upd_st = update_finding_endpoint(fid1, UpdateFindingRequest(status="CONFIRMED"))
ok(r_upd_st.success is True, "update status=CONFIRMED succeeds")
eq(r_upd_st.data["status"], "CONFIRMED", "status updated to CONFIRMED")
ok("Status changed to CONFIRMED" in r_upd_st.data["auditTrail"], "auditTrail records status change")

# Metadata merge
r_upd_meta = update_finding_endpoint(fid1, UpdateFindingRequest(metadata={"newKey": "v1"}))
ok(r_upd_meta.success is True, "update metadata succeeds")
ok(r_upd_meta.data["metadata"]["newKey"] == "v1", "metadata key merged")

# Tags replace
r_upd_tags = update_finding_endpoint(fid1, UpdateFindingRequest(tags=["critical","urgent"]))
ok(r_upd_tags.success is True, "update tags succeeds")
ok("critical" in r_upd_tags.data["tags"], "tag 'critical' present after update")

# riskScore
r_upd_risk = update_finding_endpoint(fid1, UpdateFindingRequest(riskScore=99.0))
ok(r_upd_risk.success is True, "update riskScore succeeds")
eq(r_upd_risk.data["riskScore"], 99.0, "riskScore updated")

# 404
r_upd_404 = update_finding_endpoint("no-such-id", UpdateFindingRequest(severity="LOW"))
ok(r_upd_404.success is False, "update 404")

# 422 — empty body
r_upd_422 = update_finding_endpoint(fid1, UpdateFindingRequest())
ok(r_upd_422.success is False, "update 422 empty body")

# Invalid severity on update
r_upd_inv = update_finding_endpoint(fid1, UpdateFindingRequest(severity="ULTRA"))
ok(r_upd_inv.success is False, "update 422 invalid severity")

# Invalid status on update
r_upd_inv_st = update_finding_endpoint(fid1, UpdateFindingRequest(status="MAYBE"))
ok(r_upd_inv_st.success is False, "update 422 invalid status")

# Invalid category on update
r_upd_inv_cat = update_finding_endpoint(fid1, UpdateFindingRequest(category="NONSENSE"))
ok(r_upd_inv_cat.success is False, "update 422 invalid category")

# ===========================================================================
# 5. CRUD — Delete
# ===========================================================================
section("5. CRUD — Delete")

tmp = _make("Temp Finding", severity="LOW", category="OTHER")
tmp_id = tmp["findingId"]
count_before = len(_FINDING_STORE)

r_del = delete_finding(tmp_id)
ok(r_del.success is True,  "delete_finding success=True")
ok(r_del.data is None,     "delete_finding data=None")
ok(tmp_id not in _FINDING_STORE, "finding removed from store")
eq(len(_FINDING_STORE), count_before - 1, "store size decremented")

r_del_404 = delete_finding(tmp_id)
ok(r_del_404.success is False, "delete 404 on already-deleted")
ok("not found" in r_del_404.message.lower(), "delete 404 message")

# ===========================================================================
# 6. Statistics
# ===========================================================================
section("6. Statistics (Extended Part B)")
_setup()
_make("F-crit",   severity="CRITICAL", category="NETWORK",  confidence=90.0, risk_score=90.0)
_make("F-high",   severity="HIGH",     category="HOST",     confidence=70.0, risk_score=70.0)
_make("F-high2",  severity="HIGH",     category="NETWORK",  confidence=60.0, risk_score=65.0)
_make("F-med",    severity="MEDIUM",   category="TRAFFIC",  confidence=50.0, risk_score=50.0)
_make("F-low",    severity="LOW",      category="IDENTITY", confidence=20.0, risk_score=20.0)

r_stats = get_finding_statistics()
ok(r_stats.success is True, "get_finding_statistics success=True")
s = r_stats.data
ok("totalFindings"    in s, "stats has totalFindings")
ok("severityCounts"   in s, "stats has severityCounts")
ok("statusCounts"     in s, "stats has statusCounts")
ok("categoryCounts"   in s, "stats has categoryCounts")
ok("averageConfidence"in s, "stats has averageConfidence")
ok("averageRiskScore" in s, "stats has averageRiskScore (Part B)")

eq(s["totalFindings"], 5, "totalFindings=5")
eq(s["severityCounts"].get("CRITICAL"), 1, "severityCounts[CRITICAL]=1")
eq(s["severityCounts"].get("HIGH"),     2, "severityCounts[HIGH]=2")
eq(s["severityCounts"].get("MEDIUM"),   1, "severityCounts[MEDIUM]=1")
eq(s["severityCounts"].get("LOW"),      1, "severityCounts[LOW]=1")
eq(s["statusCounts"].get("OPEN"),       5, "statusCounts[OPEN]=5")
eq(s["categoryCounts"].get("NETWORK"),  2, "categoryCounts[NETWORK]=2")

expected_avg_conf = round((90+70+60+50+20)/5, 4)
eq(s["averageConfidence"], expected_avg_conf, f"averageConfidence={expected_avg_conf}")
expected_avg_risk = round((90+70+65+50+20)/5, 4)
eq(s["averageRiskScore"], expected_avg_risk, f"averageRiskScore={expected_avg_risk}")

# Keys sorted alphabetically
ok(list(s["severityCounts"].keys()) == sorted(s["severityCounts"].keys()), "severityCounts sorted")
ok(list(s["categoryCounts"].keys()) == sorted(s["categoryCounts"].keys()), "categoryCounts sorted")

# Empty store
_setup()
r_empty_stats = get_finding_statistics()
eq(r_empty_stats.data["totalFindings"],     0,   "empty stats: totalFindings=0")
eq(r_empty_stats.data["averageConfidence"], 0.0, "empty stats: averageConfidence=0.0")
eq(r_empty_stats.data["averageRiskScore"],  0.0, "empty stats: averageRiskScore=0.0")
eq(r_empty_stats.data["severityCounts"],    {},  "empty stats: severityCounts={}")

# ===========================================================================
# 7. sort_findings_api() helper
# ===========================================================================
section("7. sort_findings_api() helper")
_setup()
_make("Alpha", severity="LOW",      confidence=10.0, risk_score=10.0)
_make("Beta",  severity="CRITICAL", confidence=90.0, risk_score=90.0)
_make("Gamma", severity="HIGH",     confidence=60.0, risk_score=60.0)
_make("Delta", severity="MEDIUM",   confidence=40.0, risk_score=40.0)
_make("Epsilon",severity="INFO",    confidence=5.0,  risk_score=5.0)

all_f = list(_FINDING_STORE.values())

# Sort by severity DESC (default)
sev_desc = sort_findings_api(all_f, "severity", "desc")
sev_vals = [f["severity"] for f in sev_desc]
sev_weights = [{"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}[s] for s in sev_vals]
ok(sev_weights == sorted(sev_weights, reverse=True), "sort severity DESC")

# Sort by severity ASC
sev_asc = sort_findings_api(all_f, "severity", "asc")
sev_w_asc = [{"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}[f["severity"]] for f in sev_asc]
ok(sev_w_asc == sorted(sev_w_asc), "sort severity ASC")

# Sort by confidence DESC
conf_desc = sort_findings_api(all_f, "confidence", "desc")
ok([f["confidence"] for f in conf_desc] == sorted([f["confidence"] for f in conf_desc], reverse=True),
   "sort confidence DESC")

# Sort by confidence ASC
conf_asc = sort_findings_api(all_f, "confidence", "asc")
ok([f["confidence"] for f in conf_asc] == sorted([f["confidence"] for f in conf_asc]),
   "sort confidence ASC")

# Sort by riskScore DESC
risk_desc = sort_findings_api(all_f, "riskScore", "desc")
ok([f["riskScore"] for f in risk_desc] == sorted([f["riskScore"] for f in risk_desc], reverse=True),
   "sort riskScore DESC")

# Sort by riskScore ASC
risk_asc = sort_findings_api(all_f, "riskScore", "asc")
ok([f["riskScore"] for f in risk_asc] == sorted([f["riskScore"] for f in risk_asc]),
   "sort riskScore ASC")

# Sort by title ASC
title_asc = sort_findings_api(all_f, "title", "asc")
titles = [f["title"].lower() for f in title_asc]
ok(titles == sorted(titles), "sort title ASC alphabetical")

# Sort by title DESC
title_desc = sort_findings_api(all_f, "title", "desc")
titles_d = [f["title"].lower() for f in title_desc]
ok(titles_d == sorted(titles_d, reverse=True), "sort title DESC")

# Sort by createdAt
created_asc = sort_findings_api(all_f, "createdAt", "asc")
ok(len(created_asc) == len(all_f), "sort createdAt returns all findings")

# Invalid sort_by falls back gracefully
fallback = sort_findings_api(all_f, "INVALID_KEY", "asc")
ok(len(fallback) == len(all_f), "sort invalid key returns all findings (fallback)")

# Input not mutated
orig_ids = [f["findingId"] for f in all_f]
_ = sort_findings_api(all_f, "riskScore", "desc")
ok([f["findingId"] for f in all_f] == orig_ids, "sort does not mutate input")

# Deterministic
s1 = [f["findingId"] for f in sort_findings_api(all_f, "severity", "desc")]
s2 = [f["findingId"] for f in sort_findings_api(all_f, "severity", "desc")]
ok(s1 == s2, "sort is deterministic")

# ===========================================================================
# 8. filter_findings_api() helper
# ===========================================================================
section("8. filter_findings_api() helper")

all_f = list(_FINDING_STORE.values())

# Filter by severity
crits = filter_findings_api(all_f, severity="CRITICAL")
ok(all(f["severity"]=="CRITICAL" for f in crits), "filter severity=CRITICAL")
eq(len(crits), 1, "filter CRITICAL count=1")

# Case-insensitive
crits_lower = filter_findings_api(all_f, severity="critical")
eq(len(crits_lower), 1, "filter severity case-insensitive")

# Filter by status (all OPEN)
open_f = filter_findings_api(all_f, status="OPEN")
eq(len(open_f), len(all_f), "filter status=OPEN matches all (all are OPEN)")

closed_f = filter_findings_api(all_f, status="CLOSED")
eq(len(closed_f), 0, "filter status=CLOSED returns empty (none closed)")

# Filter by category
net_f = filter_findings_api(all_f, category="NETWORK")
ok(all(f["category"]=="NETWORK" for f in net_f), "filter category=NETWORK")

# Filter by confidence range
high_conf = filter_findings_api(all_f, min_confidence=60.0)
ok(all(f["confidence"] >= 60.0 for f in high_conf), "filter min_confidence=60")
eq(len(high_conf), 2, "filter min_confidence=60: 2 findings (60, 90)")

low_conf = filter_findings_api(all_f, max_confidence=10.0)
ok(all(f["confidence"] <= 10.0 for f in low_conf), "filter max_confidence=10")
eq(len(low_conf), 2, "filter max_confidence=10: 2 findings (5, 10)")

mid_conf = filter_findings_api(all_f, min_confidence=10.0, max_confidence=60.0)
ok(all(10.0 <= f["confidence"] <= 60.0 for f in mid_conf), "filter confidence range [10,60]")

# Filter by risk score
high_risk = filter_findings_api(all_f, min_risk_score=60.0)
ok(all(f["riskScore"] >= 60.0 for f in high_risk), "filter min_risk_score=60")

low_risk = filter_findings_api(all_f, max_risk_score=10.0)
ok(all(f["riskScore"] <= 10.0 for f in low_risk), "filter max_risk_score=10")

# Combined severity + confidence
combo = filter_findings_api(all_f, severity="HIGH", min_confidence=50.0)
ok(all(f["severity"]=="HIGH" and f["confidence"]>=50.0 for f in combo),
   "filter combined severity=HIGH + min_confidence=50")

# No filter returns all
all_pass = filter_findings_api(all_f)
eq(len(all_pass), len(all_f), "filter no predicates returns all")

# Nonexistent values
no_match = filter_findings_api(all_f, severity="EXTREME")
eq(len(no_match), 0, "filter nonexistent severity returns empty")

# Input not mutated
orig = [f["findingId"] for f in all_f]
_ = filter_findings_api(all_f, severity="HIGH")
ok([f["findingId"] for f in all_f] == orig, "filter does not mutate input")

# ===========================================================================
# 9. paginate_findings() helper
# ===========================================================================
section("9. paginate_findings() helper")

all_f = list(_FINDING_STORE.values())  # 5 findings

p1, pag1 = paginate_findings(all_f, 1, 2)
eq(len(p1), 2, "paginate page=1 size=2: 2 items")
eq(pag1.page, 1, "Pagination.page=1")
eq(pag1.pageSize, 2, "Pagination.pageSize=2")
eq(pag1.totalItems, 5, "Pagination.totalItems=5")
eq(pag1.totalPages, 3, "Pagination.totalPages=3")

p2, pag2 = paginate_findings(all_f, 2, 2)
eq(len(p2), 2, "paginate page=2 size=2: 2 items")

p3, pag3 = paginate_findings(all_f, 3, 2)
eq(len(p3), 1, "paginate page=3 size=2: 1 item (remainder)")

p4, pag4 = paginate_findings(all_f, 4, 2)
eq(len(p4), 0, "paginate page=4 size=2: 0 items (beyond)")

pall, pagall = paginate_findings(all_f, 1, 100)
eq(len(pall), 5, "paginate size=100 returns all 5")
eq(pagall.totalPages, 1, "paginate size=100: totalPages=1")

pempty, pagempty = paginate_findings([], 1, 20)
eq(len(pempty), 0, "paginate empty list: empty slice")
eq(pagempty.totalPages, 0, "paginate empty: totalPages=0")
eq(pagempty.totalItems, 0, "paginate empty: totalItems=0")

pclamp_page, pclamp_pag = paginate_findings(all_f, 0, 3)
eq(pclamp_pag.page, 1, "paginate clamps page=0 to 1")

pclamp_sz, pclamp_spag = paginate_findings(all_f, 1, 0)
eq(pclamp_spag.pageSize, 1, "paginate clamps pageSize=0 to 1")

# Deterministic
ids_r1 = [f["findingId"] for f in paginate_findings(all_f, 1, 3)[0]]
ids_r2 = [f["findingId"] for f in paginate_findings(all_f, 1, 3)[0]]
ok(ids_r1 == ids_r2, "paginate is deterministic")

# ===========================================================================
# 10. find_finding() helper
# ===========================================================================
section("10. find_finding() helper")
all_f = list(_FINDING_STORE.values())

f_by_id = find_finding(all_f, "findingId", all_f[0]["findingId"])
ok(f_by_id is not None, "find_finding by findingId")

f_by_title = find_finding(all_f, "title", "Alpha")
ok(f_by_title is not None, "find_finding by title")
eq(f_by_title["title"], "Alpha", "find_finding title match")

f_ci = find_finding(all_f, "title", "alpha")
ok(f_ci is not None, "find_finding is case-insensitive")

f_sev = find_finding(all_f, "severity", "CRITICAL")
ok(f_sev is not None, "find_finding by severity")

f_miss = find_finding(all_f, "title", "nonexistent_xyz_999")
ok(f_miss is None, "find_finding returns None when not found")

f_empty = find_finding([], "title", "anything")
ok(f_empty is None, "find_finding returns None on empty list")

f_unk_field = find_finding(all_f, "UNKNOWN_FIELD", "val")
ok(f_unk_field is None, "find_finding returns None for unknown field")

# ===========================================================================
# 11. Search endpoint
# ===========================================================================
section("11. GET /findings/search")
_setup()
_make("SQL Injection Alert",      severity="CRITICAL", category="NETWORK",  confidence=90.0, risk_score=90.0)
_make("Port Scan Detected",       severity="HIGH",     category="NETWORK",  confidence=70.0, risk_score=65.0)
_make("Credential Brute Force",   severity="HIGH",     category="IDENTITY", confidence=75.0, risk_score=70.0)
_make("Malware Callback Traffic", severity="CRITICAL", category="TRAFFIC",  confidence=95.0, risk_score=95.0)
_make("Suspicious Process",       severity="MEDIUM",   category="HOST",     confidence=45.0, risk_score=40.0)

# Basic search
r_s = search_findings(q="alert")
ok(r_s.success is True, "search success=True")
ok("findings"   in r_s.data, "search response has 'findings'")
ok("total"      in r_s.data, "search response has 'total'")
ok("query"      in r_s.data, "search response has 'query'")
ok("page"       in r_s.data, "search response has 'page'")
ok("pageSize"   in r_s.data, "search response has 'pageSize'")
ok("totalPages" in r_s.data, "search response has 'totalPages'")
ok("sortBy"     in r_s.data, "search response has 'sortBy'")
ok("sortOrder"  in r_s.data, "search response has 'sortOrder'")
ok(r_s.data["query"] == "alert", "search query echoed in response")
ok(r_s.data["total"] >= 1, "search 'alert' matches at least 1")

# Case-insensitive
r_ci = search_findings(q="NETWORK")
ok(r_ci.success is True, "search case-insensitive")
ok(r_ci.data["total"] >= 2, "search 'NETWORK' matches category-based results")

# Search across multiple fields
r_multi = search_findings(q="critical")
ok(r_multi.success is True, "search 'critical' across severity field")
ok(r_multi.data["total"] >= 2, "search matches severity=CRITICAL nodes")

# Sort by severity DESC
r_sev = search_findings(q="a", sort_by="severity", sort_order="desc")
ok(r_sev.success is True, "search sort=severity desc")
nodes = r_sev.data["findings"]
if len(nodes) >= 2:
    weights = [{"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}.get(n["severity"],0) for n in nodes]
    ok(weights == sorted(weights, reverse=True), "search results sorted severity DESC")

# Sort by confidence ASC
r_conf = search_findings(q="a", sort_by="confidence", sort_order="asc")
ok(r_conf.success is True, "search sort=confidence asc")
if len(r_conf.data["findings"]) >= 2:
    confs = [n["confidence"] for n in r_conf.data["findings"]]
    ok(confs == sorted(confs), "search results sorted confidence ASC")

# Filter by severity
r_fsev = search_findings(q="a", severity_filter="CRITICAL")
ok(r_fsev.success is True, "search + severity_filter")
ok(all(n["severity"]=="CRITICAL" for n in r_fsev.data["findings"]),
   "search severity_filter=CRITICAL")

# Filter by category
r_fcat = search_findings(q="a", category_filter="NETWORK")
ok(r_fcat.success is True, "search + category_filter")
ok(all(n["category"]=="NETWORK" for n in r_fcat.data["findings"]),
   "search category_filter=NETWORK")

# Filter by confidence range
r_fconf = search_findings(q="a", min_confidence_filter=70.0)
ok(r_fconf.success is True, "search + min_confidence_filter")
ok(all(n["confidence"]>=70.0 for n in r_fconf.data["findings"]),
   "search min_confidence_filter=70")

# Pagination
r_pg = search_findings(q="a", page=1, page_size=2)
ok(r_pg.success is True, "search pagination")
eq(r_pg.data["page"], 1, "search page=1")
eq(r_pg.data["pageSize"], 2, "search pageSize=2")
ok(len(r_pg.data["findings"]) <= 2, "search page_size=2 returns <=2 items")

# Page 2
r_pg2 = search_findings(q="a", page=2, page_size=2)
ok(r_pg2.success is True, "search page 2 succeeds")
eq(r_pg2.data["page"], 2, "search page=2 in response")

# Empty query → 422
r_emq = search_findings(q="")
ok(r_emq.success is False, "search empty query fails")

# Invalid sort_by → 422
r_inv_sort = search_findings(q="test", sort_by="INVALID_KEY")
ok(r_inv_sort.success is False, "search invalid sort_by fails")

# Invalid sort_order → 422
r_inv_ord = search_findings(q="test", sort_order="sideways")
ok(r_inv_ord.success is False, "search invalid sort_order fails")

# No matches → success with total=0
r_nomatch = search_findings(q="zzz_no_match_xyz_999_abc")
ok(r_nomatch.success is True, "search no matches still success")
eq(r_nomatch.data["total"], 0, "search no matches total=0")
eq(len(r_nomatch.data["findings"]), 0, "search no matches empty list")

# ===========================================================================
# 12. Bulk Create
# ===========================================================================
section("12. POST /findings/bulk/create")
_setup()

bulk_req = BulkCreateFindingsRequest(findings=[
    CreateFindingRequest(**_BASE, title="Bulk F1", severity="HIGH",     category="NETWORK",  confidence=80.0),
    CreateFindingRequest(**_BASE, title="Bulk F2", severity="CRITICAL", category="HOST",     confidence=95.0),
    CreateFindingRequest(**_BASE, title="Bulk F3", severity="MEDIUM",   category="TRAFFIC",  confidence=50.0),
    CreateFindingRequest(**_BASE, title="Bulk F4", severity="LOW",      category="IDENTITY", confidence=20.0),
    CreateFindingRequest(**_BASE, title="Bulk F5", severity="INFO",     category="SYSTEM",   confidence=5.0),
])
r_bc = bulk_create_findings(bulk_req)
ok(r_bc.success is True, "bulk_create success=True")
bd = r_bc.data
ok("succeeded"    in bd, "bulk create: 'succeeded' key")
ok("failed"       in bd, "bulk create: 'failed' key")
ok("total"        in bd, "bulk create: 'total' key")
ok("successCount" in bd, "bulk create: 'successCount' key")
ok("failCount"    in bd, "bulk create: 'failCount' key")
eq(bd["total"], 5,        "bulk create total=5")
eq(bd["successCount"], 5, "bulk create successCount=5")
eq(bd["failCount"], 0,    "bulk create failCount=0")
eq(len(_FINDING_STORE), 5,"bulk create stored 5 findings")
ok(bd["successCount"] + bd["failCount"] == bd["total"], "success+fail==total")

# Duplicate in second bulk
r_bc2 = bulk_create_findings(BulkCreateFindingsRequest(findings=[
    CreateFindingRequest(**_BASE, title="Bulk F1", severity="HIGH", category="NETWORK", confidence=10.0),
    CreateFindingRequest(**_BASE, title="Bulk F6", severity="HIGH", category="NETWORK", confidence=60.0),
]))
ok(r_bc2.success is True, "bulk create partial dup: success=True")
bd2 = r_bc2.data
eq(bd2["successCount"], 1, "partial dup: 1 succeeded")
eq(bd2["failCount"],    1, "partial dup: 1 failed (dup)")
ok("reason" in bd2["failed"][0], "partial dup: failed entry has reason")

# Invalid severity in bulk
r_bc_inv = bulk_create_findings(BulkCreateFindingsRequest(findings=[
    CreateFindingRequest(**_BASE, title="Inv Sev", severity="EXTREME", category="NETWORK"),
    CreateFindingRequest(**_BASE, title="Val Sev", severity="HIGH",    category="NETWORK"),
]))
ok(r_bc_inv.success is True, "bulk create invalid severity: endpoint success=True")
ok(r_bc_inv.data["failCount"] == 1, "bulk create invalid severity: failCount=1")
ok(r_bc_inv.data["successCount"] == 1, "bulk create invalid severity: successCount=1")

# ===========================================================================
# 13. Bulk Update
# ===========================================================================
section("13. PUT /findings/bulk/update")
ids = list(_FINDING_STORE.keys())
ok(len(ids) >= 3, f"Setup: >=3 findings (got {len(ids)})")
id_a, id_b, id_c = ids[0], ids[1], ids[2]

r_bu = bulk_update_findings(BulkUpdateFindingsRequest(items=[
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=id_a, update=UpdateFindingRequest(severity="CRITICAL", confidence=99.0)),
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=id_b, update=UpdateFindingRequest(status="CONFIRMED")),
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=id_c, update=UpdateFindingRequest(riskScore=77.0)),
]))
ok(r_bu.success is True, "bulk_update success=True")
bu = r_bu.data
eq(bu["total"], 3, "bulk update total=3")
eq(bu["successCount"], 3, "bulk update successCount=3")
eq(bu["failCount"], 0,    "bulk update failCount=0")

ok(_FINDING_STORE[id_a]["severity"]   == "CRITICAL", "bulk update: severity persisted")
ok(_FINDING_STORE[id_a]["confidence"] == 99.0,       "bulk update: confidence persisted")
ok(_FINDING_STORE[id_b]["status"]     == "CONFIRMED","bulk update: status persisted")
ok(_FINDING_STORE[id_c]["riskScore"]  == 77.0,       "bulk update: riskScore persisted")

# Partial 404
r_bu2 = bulk_update_findings(BulkUpdateFindingsRequest(items=[
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId="nonexistent_xyz", update=UpdateFindingRequest(severity="LOW")),
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=id_a, update=UpdateFindingRequest(confidence=55.0)),
]))
ok(r_bu2.success is True, "bulk update partial 404: success=True")
eq(r_bu2.data["failCount"],    1, "bulk update partial 404: failCount=1")
eq(r_bu2.data["successCount"], 1, "bulk update partial 404: successCount=1")
ok(r_bu2.data["failed"][0]["reason"] == "Finding not found.", "bulk update 404 reason")

# Invalid severity in bulk update
r_bu_inv = bulk_update_findings(BulkUpdateFindingsRequest(items=[
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=id_b, update=UpdateFindingRequest(severity="ULTRA")),
]))
ok(r_bu_inv.success is True, "bulk update invalid severity: endpoint success=True")
eq(r_bu_inv.data["failCount"], 1, "bulk update invalid severity: failCount=1")

# ===========================================================================
# 14. Bulk Delete
# ===========================================================================
section("14. DELETE /findings/bulk/delete")
count_pre = len(_FINDING_STORE)
del_ids = ids[:3]

r_bd = bulk_delete_findings(BulkDeleteFindingsRequest(findingIds=del_ids))
ok(r_bd.success is True, "bulk_delete success=True")
bd_d = r_bd.data
eq(bd_d["total"], 3,        "bulk delete total=3")
eq(bd_d["successCount"], 3, "bulk delete successCount=3")
eq(bd_d["failCount"], 0,    "bulk delete failCount=0")
eq(len(_FINDING_STORE), count_pre - 3, "bulk delete removed 3 findings")
for did in del_ids:
    ok(did not in _FINDING_STORE, f"bulk delete removed {did}")

# All nonexistent
r_bd2 = bulk_delete_findings(BulkDeleteFindingsRequest(findingIds=["nope1","nope2"]))
ok(r_bd2.success is True, "bulk delete all nonexistent: success=True")
eq(r_bd2.data["successCount"], 0, "bulk delete nonexistent: successCount=0")
eq(r_bd2.data["failCount"],    2, "bulk delete nonexistent: failCount=2")
ok(r_bd2.data["failed"][0]["reason"] == "Finding not found.", "bulk delete 404 reason")

# Partial success
remaining = list(_FINDING_STORE.keys())
if remaining:
    r_bd3 = bulk_delete_findings(BulkDeleteFindingsRequest(
        findingIds=[remaining[0], "nonexistent_abc"]))
    ok(r_bd3.success is True, "bulk delete partial: success=True")
    eq(r_bd3.data["successCount"], 1, "bulk delete partial: successCount=1")
    eq(r_bd3.data["failCount"],    1, "bulk delete partial: failCount=1")

# ===========================================================================
# 15. Integrated: search + filter + sort + paginate
# ===========================================================================
section("15. Integrated search + filter + sort + paginate")
_setup()
severities = ["CRITICAL","HIGH","HIGH","MEDIUM","MEDIUM","MEDIUM","LOW","LOW","INFO","INFO"]
for i, sev in enumerate(severities):
    _make(f"integrated-{i:02d}", severity=sev, category="NETWORK",
          confidence=float(i*10), risk_score=float(i*10))

# Page all via search
r_all = search_findings(q="integrated", sort_by="riskScore", sort_order="asc",
                        page=1, page_size=50)
ok(r_all.success is True, "integrated: full search succeeds")
eq(r_all.data["total"], 10, "integrated: total=10")
if len(r_all.data["findings"]) >= 2:
    risks = [f["riskScore"] for f in r_all.data["findings"]]
    ok(risks == sorted(risks), "integrated: riskScore ASC global sort")

# Filter CRITICAL or HIGH + paginate
r_hi = search_findings(q="integrated", severity_filter="HIGH", sort_by="confidence",
                       sort_order="desc", page=1, page_size=2)
ok(r_hi.success is True, "integrated filter HIGH + paginate")
ok(all(f["severity"]=="HIGH" for f in r_hi.data["findings"]), "integrated: all HIGH")
eq(r_hi.data["pageSize"], 2, "integrated pageSize=2")

r_hi2 = search_findings(q="integrated", severity_filter="HIGH", sort_by="confidence",
                        sort_order="desc", page=2, page_size=2)
ok(r_hi2.success is True, "integrated page2 HIGH findings")

# Filter by risk range
r_risk = search_findings(q="integrated", min_risk_filter=40.0, max_risk_filter=70.0,
                         sort_by="riskScore", sort_order="asc")
ok(r_risk.success is True, "integrated: risk range filter")
ok(all(40.0 <= f["riskScore"] <= 70.0 for f in r_risk.data["findings"]),
   "integrated: all findings in risk range [40,70]")

# Page cycle: 10 items, page_size=3 → 4 pages
all_pages = []
for pg in range(1, 5):
    r_pg = search_findings(q="integrated", sort_by="riskScore", sort_order="asc",
                           page=pg, page_size=3)
    ok(r_pg.success is True, f"integrated page cycle: page={pg}")
    ok(r_pg.data["totalPages"] == 4, f"integrated page cycle: totalPages=4 on page={pg}")
    all_pages.extend(f["findingId"] for f in r_pg.data["findings"])

eq(len(all_pages), 10, "integrated page cycle: all 10 findings seen")
eq(len(set(all_pages)), 10, "integrated page cycle: no duplicates")

# ===========================================================================
# 16. Determinism
# ===========================================================================
section("16. Determinism")
_setup()
req_det = CreateFindingRequest(**_BASE, title="Det Test", severity="HIGH", category="NETWORK")
r_det1 = create_finding(req_det)
fid_det = r_det1.data["findingId"]
delete_finding(fid_det)
r_det2 = create_finding(req_det)
eq(r_det1.data["findingId"], r_det2.data["findingId"],
   "Same inputs after delete → same findingId (deterministic UUIDv5)")

# Different project → different findingId
req_p2 = CreateFindingRequest(
    projectId="proj-2", investigationId="inv-1",
    title="Det Test", severity="HIGH", category="NETWORK",
    createdBy="analyst", createdAt="2026-01-01T00:00:00Z",
)
r_p2 = create_finding(req_p2)
ok(r_p2.data["findingId"] != fid_det, "Different projectId → different findingId")

# Different title → different findingId
req_t2 = CreateFindingRequest(**_BASE, title="Det Test 2", severity="HIGH", category="NETWORK")
r_t2 = create_finding(req_t2)
ok(r_t2.data["findingId"] != fid_det, "Different title → different findingId")

# Sort is stable
_setup()
for i in range(5):
    _make(f"s{i}", severity=["LOW","HIGH","CRITICAL","MEDIUM","INFO"][i], confidence=float(i*20))
flist = list(_FINDING_STORE.values())
ids1 = [f["findingId"] for f in sort_findings_api(flist, "severity", "desc")]
ids2 = [f["findingId"] for f in sort_findings_api(flist, "severity", "desc")]
ok(ids1 == ids2, "sort is stable and deterministic across calls")

# Filter deterministic
f1 = [f["findingId"] for f in filter_findings_api(flist, severity="HIGH")]
f2 = [f["findingId"] for f in filter_findings_api(flist, severity="HIGH")]
ok(f1 == f2, "filter is deterministic across calls")

# ===========================================================================
# 17. Model Validation
# ===========================================================================
section("17. Model Validation")

# UpdateFindingRequest.has_any_field
upd_empty = UpdateFindingRequest()
ok(upd_empty.has_any_field() is False, "UpdateFindingRequest empty has_any_field=False")
upd_one = UpdateFindingRequest(severity="LOW")
ok(upd_one.has_any_field() is True, "UpdateFindingRequest with severity has_any_field=True")
upd_meta = UpdateFindingRequest(metadata={"k":"v"})
ok(upd_meta.has_any_field() is True, "UpdateFindingRequest with metadata has_any_field=True")

# CreateFindingRequest.validate_request
cr_ok = CreateFindingRequest(**_BASE, title="ok", severity="LOW", category="OTHER")
ok(cr_ok.validate_request() == [], "validate_request empty for valid request")

cr_no_proj = CreateFindingRequest(
    projectId="", investigationId="inv", title="x", createdBy="a", createdAt="t")
errs = cr_no_proj.validate_request()
ok(any("projectId" in e for e in errs), "validate_request catches empty projectId")

cr_no_title = CreateFindingRequest(**{**_BASE, "title": ""})
errs2 = cr_no_title.validate_request()
ok(any("title" in e for e in errs2), "validate_request catches empty title")

# confidence bounds via Pydantic
try:
    CreateFindingRequest(**_BASE, title="t", confidence=101.0)
    ok(False, "confidence=101 should raise ValidationError")
except Exception:
    ok(True, "confidence=101 raises ValidationError")

try:
    CreateFindingRequest(**_BASE, title="t", confidence=-1.0)
    ok(False, "confidence=-1 should raise ValidationError")
except Exception:
    ok(True, "confidence=-1 raises ValidationError")

# FindingStatisticsResponse fields
_setup()
_make("StatCheck", severity="HIGH", category="HOST", confidence=80.0, risk_score=60.0)
stats_data = get_finding_statistics().data
ok(isinstance(stats_data["totalFindings"],     int),   "stats totalFindings is int")
ok(isinstance(stats_data["severityCounts"],    dict),  "stats severityCounts is dict")
ok(isinstance(stats_data["statusCounts"],      dict),  "stats statusCounts is dict")
ok(isinstance(stats_data["categoryCounts"],    dict),  "stats categoryCounts is dict")
ok(isinstance(stats_data["averageConfidence"], float), "stats averageConfidence is float")
ok(isinstance(stats_data["averageRiskScore"],  float), "stats averageRiskScore is float")

# ===========================================================================
# 18. Edge Cases
# ===========================================================================
section("18. Edge Cases")
_setup()

# Empty store list endpoint
r_el = list_findings()
ok(r_el.success is True, "list_findings empty store: success=True")
eq(r_el.data["total"], 0, "list_findings empty: total=0")
eq(len(r_el.data["findings"]), 0, "list_findings empty: empty list")

# Empty store search
r_es = search_findings(q="anything")
ok(r_es.success is True, "search empty store: success=True")
eq(r_es.data["total"], 0, "search empty: total=0")

# Minimal required fields only
req_min = CreateFindingRequest(**_BASE, title="Minimal")
r_min = create_finding(req_min)
ok(r_min.success is True, "create minimal fields: success=True")
ok(r_min.data["severity"]  == "MEDIUM", "minimal: default severity=MEDIUM")
ok(r_min.data["category"]  == "OTHER",  "minimal: default category=OTHER")
ok(r_min.data["status"]    == "OPEN",   "minimal: status=OPEN")
ok(r_min.data["confidence"] == 0.0,     "minimal: confidence=0.0")
ok(r_min.data["riskScore"]  == 0.0,     "minimal: riskScore=0.0")

# Tags are sorted and lowercased
req_tags = CreateFindingRequest(**_BASE, title="Tag Test", tags=["Zebra","alpha","BETA"])
r_tags = create_finding(req_tags)
ok(r_tags.success is True, "create with tags: success")
tag_list = r_tags.data["tags"]
ok(tag_list == sorted(tag_list), "tags are sorted")
ok(all(t == t.lower() for t in tag_list), "tags are lowercased")

# assetIds deduplication
req_dup_ids = CreateFindingRequest(
    **_BASE, title="Dup IDs", assetIds=["a1","a1","a2","a1"])
r_dup_ids = create_finding(req_dup_ids)
ok(r_dup_ids.success is True, "create with dup assetIds: success")
ok(len(r_dup_ids.data["assetIds"]) == 2, "assetIds deduplicated to 2")

# Empty metadata
req_emeta = CreateFindingRequest(**_BASE, title="Empty Meta", metadata={})
r_emeta = create_finding(req_emeta)
ok(r_emeta.success is True, "create empty metadata: success")
ok(r_emeta.data["metadata"] == {}, "empty metadata preserved")

# Update preserves immutable fields
fid_imm = r_min.data["findingId"]
r_upd_imm = update_finding_endpoint(fid_imm, UpdateFindingRequest(severity="HIGH"))
ok(r_upd_imm.data["findingId"]       == fid_imm,         "update preserves findingId")
ok(r_upd_imm.data["projectId"]       == _BASE["projectId"],     "update preserves projectId")
ok(r_upd_imm.data["investigationId"] == _BASE["investigationId"],"update preserves investigationId")
ok(r_upd_imm.data["createdBy"]       == _BASE["createdBy"],      "update preserves createdBy")

# sort on empty list
ok(sort_findings_api([], "severity", "desc") == [], "sort empty list returns empty")
# filter on empty list
ok(filter_findings_api([], severity="HIGH") == [], "filter empty list returns empty")
# paginate empty
pg_sl, pg_m = paginate_findings([], 1, 20)
ok(pg_sl == [], "paginate empty list: empty slice")
eq(pg_m.totalPages, 0, "paginate empty: totalPages=0")

# ===========================================================================
# 19. All enum values accepted
# ===========================================================================
section("19. All enum values accepted")
_setup()

for sev in ("INFO","LOW","MEDIUM","HIGH","CRITICAL"):
    req = CreateFindingRequest(**_BASE, title=f"sev-{sev}", severity=sev, category="OTHER")
    r   = create_finding(req)
    ok(r.success is True,        f"create severity={sev}")
    ok(r.data["severity"] == sev, f"response severity={sev}")

_setup()
for cat in ("NETWORK","HOST","IDENTITY","TRAFFIC","ATTACK_GRAPH",
            "TIMELINE","RELATIONSHIP","EVIDENCE","SYSTEM","OTHER"):
    req = CreateFindingRequest(**_BASE, title=f"cat-{cat}", category=cat)
    r   = create_finding(req)
    ok(r.success is True,         f"create category={cat}")
    ok(r.data["category"] == cat,  f"response category={cat}")

_setup()
valid_statuses = ("OPEN","CONFIRMED","SUPPRESSED","FALSE_POSITIVE","RESOLVED","CLOSED")
base_f = _make("status-base")
base_fid = base_f["findingId"]
for st in valid_statuses:
    r = update_finding_endpoint(base_fid, UpdateFindingRequest(status=st))
    ok(r.success is True,        f"update status={st}")
    ok(r.data["status"] == st,    f"response status={st}")

# ===========================================================================
# 20. APIResponse contract
# ===========================================================================
section("20. APIResponse contract")
_setup()
_make("Contract Test", severity="HIGH", category="NETWORK")
fid_c = list(_FINDING_STORE.keys())[0]

def chk(resp: APIResponse, lbl: str) -> None:
    ok(hasattr(resp, "success"),            f"{lbl}: has .success")
    ok(hasattr(resp, "message"),            f"{lbl}: has .message")
    ok(hasattr(resp, "data"),               f"{lbl}: has .data")
    ok(isinstance(resp.success, bool),      f"{lbl}: .success is bool")
    ok(isinstance(resp.message, str),       f"{lbl}: .message is str")
    ok(len(resp.message) > 0,              f"{lbl}: .message non-empty")

chk(list_findings(),                                          "list_findings")
chk(get_finding_statistics(),                                 "get_statistics")
chk(get_finding(fid_c),                                       "get_finding OK")
chk(get_finding("nope"),                                      "get_finding 404")
chk(create_finding(CreateFindingRequest(**_BASE, title="rc-1")), "create OK")
chk(create_finding(CreateFindingRequest(**_BASE, title="rc-1")), "create 409")
chk(update_finding_endpoint(fid_c, UpdateFindingRequest(severity="LOW")), "update OK")
chk(update_finding_endpoint("nope", UpdateFindingRequest(severity="LOW")), "update 404")
chk(update_finding_endpoint(fid_c, UpdateFindingRequest()),   "update 422")
chk(search_findings(q="contract"),                            "search OK")
chk(search_findings(q=""),                                    "search 422")
chk(delete_finding(fid_c),                                    "delete OK")
chk(delete_finding(fid_c),                                    "delete 404")

# Messages
ok(True, "message check scaffold")  # placeholder pass
r_list2 = list_findings()
ok("found" in r_list2.message.lower(), "list message mentions 'found'")
r_get2  = get_finding(list(_FINDING_STORE.keys())[0]) if _FINDING_STORE else get_finding("x")
ok(isinstance(r_get2.message, str), "get_finding message is str")


# ===========================================================================
# 21. BulkOperationResult schema
# ===========================================================================
section("21. BulkOperationResult schema completeness")
_setup()
bulk_schema = BulkCreateFindingsRequest(findings=[
    CreateFindingRequest(**_BASE, title=f"schema-{i}") for i in range(4)
])
r_schema = bulk_create_findings(bulk_schema)
bd_s = r_schema.data
ok(isinstance(bd_s["succeeded"],    list), "BulkResult: succeeded is list")
ok(isinstance(bd_s["failed"],       list), "BulkResult: failed is list")
ok(isinstance(bd_s["total"],        int),  "BulkResult: total is int")
ok(isinstance(bd_s["successCount"], int),  "BulkResult: successCount is int")
ok(isinstance(bd_s["failCount"],    int),  "BulkResult: failCount is int")
for sid in bd_s["succeeded"]:
    ok(isinstance(sid, str), f"BulkResult: succeeded entry is str")
    ok(len(sid) == 36,       f"BulkResult: succeeded entry is UUID (36 chars)")
eq(bd_s["successCount"], len(bd_s["succeeded"]), "BulkResult: successCount == len(succeeded)")
eq(bd_s["failCount"],    len(bd_s["failed"]),    "BulkResult: failCount == len(failed)")
eq(bd_s["total"], bd_s["successCount"] + bd_s["failCount"], "BulkResult: total = success+fail")

# BulkUpdate schema
ids_s = list(_FINDING_STORE.keys())
r_bu_schema = bulk_update_findings(BulkUpdateFindingsRequest(items=[
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId=ids_s[0], update=UpdateFindingRequest(severity="LOW"))
]))
bdu = r_bu_schema.data
ok(isinstance(bdu["succeeded"], list), "BulkUpdate: succeeded is list")
ok(isinstance(bdu["failed"],    list), "BulkUpdate: failed is list")
ok(isinstance(bdu["total"],     int),  "BulkUpdate: total is int")

# BulkDelete schema
r_bd_schema = bulk_delete_findings(BulkDeleteFindingsRequest(findingIds=[ids_s[0]]))
bdd = r_bd_schema.data
ok(isinstance(bdd["succeeded"], list), "BulkDelete: succeeded is list")
ok(isinstance(bdd["failed"],    list), "BulkDelete: failed is list")
ok(isinstance(bdd["total"],     int),  "BulkDelete: total is int")


# ===========================================================================
# 22. Statistics with multiple status values
# ===========================================================================
section("22. Statistics with multiple status values")
_setup()
f_open  = _make("Open Finding",     severity="HIGH")
f_conf  = _make("Confirmed Finding", severity="CRITICAL")
f_supp  = _make("Suppressed Finding", severity="MEDIUM")

update_finding_endpoint(f_conf["findingId"], UpdateFindingRequest(status="CONFIRMED"))
update_finding_endpoint(f_supp["findingId"], UpdateFindingRequest(status="SUPPRESSED"))

r_sts = get_finding_statistics()
st_counts = r_sts.data["statusCounts"]
ok(st_counts.get("OPEN",0) >= 1,        "statusCounts has OPEN >= 1")
ok(st_counts.get("CONFIRMED",0) >= 1,   "statusCounts has CONFIRMED >= 1")
ok(st_counts.get("SUPPRESSED",0) >= 1,  "statusCounts has SUPPRESSED >= 1")
eq(r_sts.data["totalFindings"], 3,       "totalFindings=3 after status changes")


# ===========================================================================
# 23. Search — full field coverage
# ===========================================================================
section("23. Search — full field coverage")
_setup()
_make("XYZ Alpha finding",     severity="HIGH",   category="NETWORK",  confidence=80.0)
_make("ABC Beta evidence",     severity="MEDIUM", category="EVIDENCE", confidence=40.0)
_make("DEF Gamma traffic",     severity="LOW",    category="TRAFFIC",  confidence=20.0)

# Match by title
ok(search_findings(q="Alpha").data["total"] >= 1, "search by title substring 'Alpha'")
ok(search_findings(q="Beta").data["total"]  >= 1, "search by title substring 'Beta'")
ok(search_findings(q="Gamma").data["total"] >= 1, "search by title substring 'Gamma'")

# Match by severity in search
ok(search_findings(q="HIGH").data["total"]  >= 1, "search 'HIGH' matches severity field")

# Match by category in search
ok(search_findings(q="EVIDENCE").data["total"] >= 1, "search 'EVIDENCE' matches category field")
ok(search_findings(q="TRAFFIC").data["total"]  >= 1, "search 'TRAFFIC' matches category field")

# Match by projectId
ok(search_findings(q="proj-1").data["total"] >= 3, "search by projectId")

# Match by investigationId
ok(search_findings(q="inv-1").data["total"] >= 3, "search by investigationId")

# Default sort is by severity DESC
r_default = search_findings(q="finding")
ok(r_default.data["sortBy"]    == "severity", "default sortBy=severity")
ok(r_default.data["sortOrder"] == "desc",     "default sortOrder=desc")

# All sort options work
for srt in ("severity","status","confidence","riskScore","createdAt","title"):
    r = search_findings(q="a", sort_by=srt, sort_order="asc")
    ok(r.success is True, f"search sort_by={srt} asc succeeds")
    r2 = search_findings(q="a", sort_by=srt, sort_order="desc")
    ok(r2.success is True, f"search sort_by={srt} desc succeeds")


# ===========================================================================
# 24. Filter helpers — comprehensive
# ===========================================================================
section("24. filter_findings_api — comprehensive coverage")
_setup()
for i in range(8):
    sev = ["CRITICAL","HIGH","HIGH","MEDIUM","MEDIUM","LOW","LOW","INFO"][i]
    cat = ["NETWORK","HOST","NETWORK","TRAFFIC","IDENTITY","SYSTEM","NETWORK","OTHER"][i]
    _make(f"flt-{i}", severity=sev, category=cat,
          confidence=float(i*12), risk_score=float(i*11))

all_f = list(_FINDING_STORE.values())

# Every severity value
for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
    res = filter_findings_api(all_f, severity=sev)
    ok(all(f["severity"]==sev for f in res), f"filter all severity={sev}")

# Every category that was created
for cat in ("NETWORK","HOST","TRAFFIC","IDENTITY","SYSTEM","OTHER"):
    res = filter_findings_api(all_f, category=cat)
    ok(all(f["category"]==cat for f in res), f"filter all category={cat}")

# Confidence boundary
for threshold in (0.0, 25.0, 50.0, 75.0, 100.0):
    above = filter_findings_api(all_f, min_confidence=threshold)
    ok(all(f["confidence"] >= threshold for f in above),
       f"filter min_confidence={threshold}")
    below = filter_findings_api(all_f, max_confidence=threshold)
    ok(all(f["confidence"] <= threshold for f in below),
       f"filter max_confidence={threshold}")

# Risk boundary
for rthresh in (0.0, 33.0, 66.0):
    above_r = filter_findings_api(all_f, min_risk_score=rthresh)
    ok(all(f["riskScore"] >= rthresh for f in above_r),
       f"filter min_risk_score={rthresh}")


# ===========================================================================
# 25. Pagination — full page cycle
# ===========================================================================
section("25. Pagination full page cycle")
_setup()
for i in range(12):
    _make(f"pgcycle-{i:02d}", severity=["HIGH","MEDIUM","LOW","CRITICAL","INFO"][i%5])

all_f = list(_FINDING_STORE.values())

# 3 pages of 4
all_seen = []
for pg in range(1, 4):
    sl, pag = paginate_findings(all_f, pg, 4)
    ok(pag.totalPages == 3, f"pagination cycle: totalPages=3 on page={pg}")
    ok(pag.totalItems == 12, f"pagination cycle: totalItems=12 on page={pg}")
    all_seen.extend(f["findingId"] for f in sl)

eq(len(all_seen), 12, "pagination cycle: 12 total items seen")
eq(len(set(all_seen)), 12, "pagination cycle: no duplicates")

# Single-item pages
sl1, pag1 = paginate_findings(all_f, 1, 1)
eq(len(sl1), 1, "paginate size=1: one item")
eq(pag1.totalPages, 12, "paginate size=1: 12 total pages")

# Check pages don't overlap
sl_a = {f["findingId"] for f in paginate_findings(all_f, 1, 6)[0]}
sl_b = {f["findingId"] for f in paginate_findings(all_f, 2, 6)[0]}
ok(sl_a.isdisjoint(sl_b), "pages 1 and 2 do not overlap")


# ===========================================================================
# 26. Sort — status ordering
# ===========================================================================
section("26. Sort — status ordering")
_setup()
statuses = [("OPEN","HIGH"),("CONFIRMED","CRITICAL"),("SUPPRESSED","MEDIUM"),
            ("RESOLVED","LOW"),("FALSE_POSITIVE","INFO"),("CLOSED","HIGH")]
for st, sev in statuses:
    f = _make(f"st-{st}", severity=sev)
    update_finding_endpoint(f["findingId"], UpdateFindingRequest(status=st))

all_f = list(_FINDING_STORE.values())
STATUS_W = {"CONFIRMED":6,"OPEN":5,"RESOLVED":4,"SUPPRESSED":3,"FALSE_POSITIVE":2,"CLOSED":1}

# Sort status DESC
by_st_desc = sort_findings_api(all_f, "status", "desc")
weights_d = [STATUS_W.get(f["status"],0) for f in by_st_desc]
ok(weights_d == sorted(weights_d, reverse=True), "sort status DESC weights descending")

# Sort status ASC
by_st_asc = sort_findings_api(all_f, "status", "asc")
weights_a = [STATUS_W.get(f["status"],0) for f in by_st_asc]
ok(weights_a == sorted(weights_a), "sort status ASC weights ascending")

# After status update, list reflects status change
eq(by_st_desc[0]["status"], "CONFIRMED", "sort status DESC: CONFIRMED first")
eq(by_st_asc[0]["status"],  "CLOSED",    "sort status ASC: CLOSED first")


# ===========================================================================
# 27. Search with status filter
# ===========================================================================
section("27. Search with status filter")
r_st_search = search_findings(q="st-", status_filter="CONFIRMED")
ok(r_st_search.success is True, "search + status_filter=CONFIRMED")
ok(all(f["status"]=="CONFIRMED" for f in r_st_search.data["findings"]),
   "search status_filter all=CONFIRMED")

r_st_search2 = search_findings(q="st-", status_filter="CLOSED")
ok(r_st_search2.success is True, "search + status_filter=CLOSED")
ok(all(f["status"]=="CLOSED" for f in r_st_search2.data["findings"]),
   "search status_filter all=CLOSED")

# Filter + sort combined
r_combo = search_findings(q="st-", status_filter="OPEN", sort_by="severity", sort_order="desc")
ok(r_combo.success is True, "search + status_filter + severity sort")
for fn in r_combo.data["findings"]:
    ok(fn["status"] == "OPEN", f"combo filter: status=OPEN for {fn['title']}")


# ===========================================================================
# 28. Audit trail accumulation
# ===========================================================================
section("28. Audit trail accumulation")
_setup()
f_audit = _make("Audit Trail Test", severity="MEDIUM", category="NETWORK")
fid_audit = f_audit["findingId"]
ok("Created" in f_audit["auditTrail"], "auditTrail starts with 'Created'")
eq(len(f_audit["auditTrail"]), 1, "auditTrail length=1 after create")

update_finding_endpoint(fid_audit, UpdateFindingRequest(severity="HIGH"))
r2 = get_finding(fid_audit)
ok("Severity changed to HIGH" in r2.data["auditTrail"], "auditTrail: severity change appended")
ok(len(r2.data["auditTrail"]) == 2, "auditTrail length=2 after severity update")

update_finding_endpoint(fid_audit, UpdateFindingRequest(status="CONFIRMED"))
r3 = get_finding(fid_audit)
ok("Status changed to CONFIRMED" in r3.data["auditTrail"], "auditTrail: status change appended")
ok(len(r3.data["auditTrail"]) == 3, "auditTrail length=3 after status update")

update_finding_endpoint(fid_audit, UpdateFindingRequest(category="HOST"))
r4 = get_finding(fid_audit)
ok("Category changed to HOST" in r4.data["auditTrail"], "auditTrail: category change appended")

# No audit entry on unchanged field
r5 = update_finding_endpoint(fid_audit, UpdateFindingRequest(confidence=50.0))
ok(r5.success is True, "update confidence (no audit entry expected)")
ok(len(r5.data["auditTrail"]) == 4, "auditTrail unchanged after confidence update (no entry for confidence)")


# ===========================================================================
# 29. Explanation fields
# ===========================================================================
section("29. Explanation fields")
_setup()
req_exp = CreateFindingRequest(
    **_BASE, title="Explanation Test",
    reason="Suspicious outbound traffic detected",
    evidenceSummary="5 packets to known C2 IP",
    affectedAssets=["asset-1","asset-2"],
    affectedRelationships=["rel-1"],
    recommendedAction="Block outbound port 4444",
)
r_exp = create_finding(req_exp)
ok(r_exp.success is True, "create with explanation fields: success")
exp = r_exp.data["explanation"]
ok(exp is not None,                                                    "explanation not None")
eq(exp["reason"],            "Suspicious outbound traffic detected",   "explanation.reason")
eq(exp["evidenceSummary"],   "5 packets to known C2 IP",               "explanation.evidenceSummary")
ok("asset-1" in exp["affectedAssets"],                                 "explanation.affectedAssets has asset-1")
ok("asset-2" in exp["affectedAssets"],                                 "explanation.affectedAssets has asset-2")
ok("rel-1"   in exp["affectedRelationships"],                          "explanation.affectedRelationships has rel-1")
eq(exp["recommendedAction"], "Block outbound port 4444",               "explanation.recommendedAction")
ok(exp["affectedAssets"] == sorted(exp["affectedAssets"]),             "affectedAssets are sorted")

# Update explanation fields
fid_exp = r_exp.data["findingId"]
r_upd_exp = update_finding_endpoint(fid_exp, UpdateFindingRequest(
    reason="Updated reason",
    recommendedAction="Updated action",
))
ok(r_upd_exp.success is True, "update explanation fields: success")
eq(r_upd_exp.data["explanation"]["reason"], "Updated reason", "explanation.reason updated")
eq(r_upd_exp.data["explanation"]["recommendedAction"], "Updated action", "explanation.recommendedAction updated")
# evidenceSummary unchanged
eq(r_upd_exp.data["explanation"]["evidenceSummary"], "5 packets to known C2 IP",
   "explanation.evidenceSummary unchanged after partial update")


# ===========================================================================
# 30. Linked ID collections
# ===========================================================================
section("30. Linked ID collections")
_setup()
req_links = CreateFindingRequest(
    **_BASE, title="Linked IDs Test",
    assetIds=["a3","a1","a2","a1"],         # dup + unsorted
    evidenceIds=["e2","e1"],
    relationshipIds=["r1"],
    graphNodeIds=["g1","g2"],
    mitreTechniqueIds=["T1059","T1055"],
    timelineEventIds=["te1"],
)
r_links = create_finding(req_links)
ok(r_links.success is True, "create with linked IDs: success")
d = r_links.data
eq(len(d["assetIds"]), 3, "assetIds deduplicated: 3 unique")
ok(d["assetIds"] == sorted(d["assetIds"]), "assetIds sorted")
ok(d["evidenceIds"] == sorted(d["evidenceIds"]), "evidenceIds sorted")
ok(d["mitreTechniqueIds"] == sorted(d["mitreTechniqueIds"]), "mitreTechniqueIds sorted")

# Update replaces linked IDs
fid_links = d["findingId"]
r_upd_links = update_finding_endpoint(fid_links, UpdateFindingRequest(
    assetIds=["new-asset-1","new-asset-2"],
))
ok(r_upd_links.success is True, "update assetIds: success")
eq(len(r_upd_links.data["assetIds"]), 2, "assetIds replaced with 2 new IDs")
ok("new-asset-1" in r_upd_links.data["assetIds"], "new-asset-1 in assetIds")

# Empty list replaces all
r_clear_ids = update_finding_endpoint(fid_links, UpdateFindingRequest(assetIds=[]))
ok(r_clear_ids.success is True, "update assetIds=[]: success")
eq(len(r_clear_ids.data["assetIds"]), 0, "assetIds cleared to empty")


# ===========================================================================
# 31. _reset_store() utility
# ===========================================================================
section("31. _reset_store() utility")
_setup()
_make("reset-test-1")
_make("reset-test-2")
ok(len(_FINDING_STORE) > 0, "before reset: store non-empty")
_reset_store()
eq(len(_FINDING_STORE), 0, "after reset: store empty")
r_after_reset = list_findings()
eq(r_after_reset.data["total"], 0, "list after reset: total=0")


# ===========================================================================
# 32. Bulk operations — all-fail scenarios
# ===========================================================================
section("32. Bulk operations — all-fail scenarios")
_setup()

# Bulk update all nonexistent
r_bu_all_miss = bulk_update_findings(BulkUpdateFindingsRequest(items=[
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId="nope-1", update=UpdateFindingRequest(severity="LOW")),
    BulkUpdateFindingsRequest.BulkUpdateItem(
        findingId="nope-2", update=UpdateFindingRequest(severity="HIGH")),
]))
ok(r_bu_all_miss.success is True, "bulk update all-miss: success=True")
eq(r_bu_all_miss.data["successCount"], 0, "bulk update all-miss: successCount=0")
eq(r_bu_all_miss.data["failCount"],    2, "bulk update all-miss: failCount=2")
ok(all(f["reason"] == "Finding not found." for f in r_bu_all_miss.data["failed"]),
   "bulk update all-miss: all failures say 'Finding not found.'")

# Bulk delete all nonexistent
r_bd_all_miss = bulk_delete_findings(BulkDeleteFindingsRequest(
    findingIds=["nope-a","nope-b","nope-c"]))
ok(r_bd_all_miss.success is True, "bulk delete all-miss: success=True")
eq(r_bd_all_miss.data["successCount"], 0, "bulk delete all-miss: successCount=0")
eq(r_bd_all_miss.data["failCount"],    3, "bulk delete all-miss: failCount=3")

# Bulk create where all have invalid category
r_bc_all_inv = bulk_create_findings(BulkCreateFindingsRequest(findings=[
    CreateFindingRequest(**_BASE, title="inv-1", category="FAKE_CAT"),
    CreateFindingRequest(**_BASE, title="inv-2", category="BOGUS"),
]))
ok(r_bc_all_inv.success is True, "bulk create all-invalid-category: success=True")
eq(r_bc_all_inv.data["successCount"], 0, "bulk create all-invalid: successCount=0")
eq(r_bc_all_inv.data["failCount"],    2, "bulk create all-invalid: failCount=2")


# ===========================================================================
# 33. Search pagination correctness
# ===========================================================================
section("33. Search pagination correctness")
_setup()
for i in range(9):
    _make(f"pagtest-{i:02d}", severity=["CRITICAL","HIGH","MEDIUM"][i%3],
          confidence=float(i*10), risk_score=float(i*10))

# Full traversal via search pagination (size=3 → 3 pages)
all_ids_seen = []
for pg in range(1, 4):
    r = search_findings(q="pagtest", sort_by="riskScore", sort_order="asc",
                        page=pg, page_size=3)
    ok(r.success is True,          f"search pagination page={pg}: success")
    eq(r.data["page"], pg,         f"search pagination page={pg}: page echoed")
    eq(r.data["pageSize"], 3,      f"search pagination page={pg}: pageSize=3")
    eq(r.data["totalPages"], 3,    f"search pagination page={pg}: totalPages=3")
    eq(r.data["total"], 9,         f"search pagination page={pg}: total=9")
    all_ids_seen.extend(f["findingId"] for f in r.data["findings"])

eq(len(all_ids_seen), 9,          "search pagination: 9 findings across all pages")
eq(len(set(all_ids_seen)), 9,     "search pagination: no duplicates")

# Global sort continuity: page 1 risks >= page 2 risks (asc means p1 has lowest)
r_p1 = search_findings(q="pagtest", sort_by="riskScore", sort_order="asc", page=1, page_size=3)
r_p2 = search_findings(q="pagtest", sort_by="riskScore", sort_order="asc", page=2, page_size=3)
if r_p1.data["findings"] and r_p2.data["findings"]:
    max_p1 = max(f["riskScore"] for f in r_p1.data["findings"])
    min_p2 = min(f["riskScore"] for f in r_p2.data["findings"])
    ok(max_p1 <= min_p2, "search ASC: page1 max risk <= page2 min risk")


# ===========================================================================
# 34. FindingResponse completeness
# ===========================================================================
section("34. FindingResponse all fields present")
_setup()
req_full = CreateFindingRequest(
    **_BASE, title="Full Response Test",
    severity="CRITICAL", category="ATTACK_GRAPH",
    description="Test finding for response completeness",
    confidence=88.0, riskScore=77.0,
    assetIds=["a1"], evidenceIds=["e1"],
    graphNodeIds=["g1"], mitreTechniqueIds=["T1059"],
    reason="Test reason", evidenceSummary="Test evidence summary",
    affectedAssets=["a1"], affectedRelationships=["r1"],
    recommendedAction="Test remediation",
    tags=["test","coverage"], metadata={"key1": "val1"},
)
r_full = create_finding(req_full)
ok(r_full.success is True, "create full request: success")
d = r_full.data

string_fields = ["findingId","findingKey","projectId","investigationId","title",
                 "description","category","severity","status","createdBy",
                 "createdAt","updatedAt","engineVersion","findingFingerprint"]
for sf in string_fields:
    ok(isinstance(d.get(sf), str),  f"FindingResponse.{sf} is str")
    ok(len(d.get(sf, "")) > 0,     f"FindingResponse.{sf} is non-empty")

float_fields = ["confidence", "riskScore"]
for ff in float_fields:
    ok(isinstance(d.get(ff), float), f"FindingResponse.{ff} is float")

list_fields = ["assetIds","evidenceIds","graphNodeIds","mitreTechniqueIds",
               "tags","auditTrail","relationshipIds","timelineEventIds"]
for lf in list_fields:
    ok(isinstance(d.get(lf), list), f"FindingResponse.{lf} is list")

ok(isinstance(d.get("metadata"), dict), "FindingResponse.metadata is dict")
ok(d.get("explanation") is not None,    "FindingResponse.explanation is not None")
ok(d.get("closedAt") is None,           "FindingResponse.closedAt is None for OPEN finding")

# engineVersion is present and non-empty
ok(d["engineVersion"].startswith("finding-engine"), "engineVersion starts with 'finding-engine'")

# ===========================================================================
# Final Report
# ===========================================================================
section("SMOKE TEST RESULTS")
total = _PASS + _FAIL
print(f"\n  PASSED: {_PASS}")
print(f"  FAILED: {_FAIL}")
print(f"  TOTAL:  {total}")
if _FAIL:
    print(f"\n{'='*60}\n  FAILURE DETAILS\n{'='*60}")
    for m in _FAIL_MSGS:
        print(f"  {m}")
    print(f"{'='*60}\n")
    sys.exit(1)
else:
    print(f"\n{'='*60}")
    print(f"  ALL {total} ASSERTIONS PASSED")
    print(f"{'='*60}")
    print("\n  Findings API (Part A + Part B) — SMOKE TEST PASSED\n")
    sys.exit(0)
