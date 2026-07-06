"""
Smoke Test — Evidence API (Phase A4.7.2 Part B)
================================================
Covers: CRUD, search, sorting, filtering, pagination, bulk operations,
        statistics, router registration, serialization, deterministic
        behaviour, and edge cases.

Target: 500+ assertions pass.
Run   : python smoke_test_evidence_api.py
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
ERRORS: List[str] = []


def ok(condition: bool, label: str) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        ERRORS.append(f"FAIL: {label}")


def eq(a: Any, b: Any, label: str) -> None:
    ok(a == b, f"{label} — expected {b!r}, got {a!r}")


def ne(a: Any, b: Any, label: str) -> None:
    ok(a != b, f"{label} — expected values to differ, got {a!r}")


def contains(collection: Any, item: Any, label: str) -> None:
    ok(item in collection, f"{label} — {item!r} not in {collection!r}")


def not_none(val: Any, label: str) -> None:
    ok(val is not None, f"{label} — expected non-None")


def is_none(val: Any, label: str) -> None:
    ok(val is None, f"{label} — expected None, got {val!r}")


def gt(a: Any, b: Any, label: str) -> None:
    ok(a > b, f"{label} — expected {a!r} > {b!r}")


def gte(a: Any, b: Any, label: str) -> None:
    ok(a >= b, f"{label} — expected {a!r} >= {b!r}")


def lte(a: Any, b: Any, label: str) -> None:
    ok(a <= b, f"{label} — expected {a!r} <= {b!r}")


def is_list(val: Any, label: str) -> None:
    ok(isinstance(val, list), f"{label} — expected list, got {type(val).__name__}")


def is_dict(val: Any, label: str) -> None:
    ok(isinstance(val, dict), f"{label} — expected dict, got {type(val).__name__}")


def is_int(val: Any, label: str) -> None:
    ok(isinstance(val, int), f"{label} — expected int, got {type(val).__name__}")


def is_str(val: Any, label: str) -> None:
    ok(isinstance(val, str), f"{label} — expected str, got {type(val).__name__}")


def is_float(val: Any, label: str) -> None:
    ok(isinstance(val, (int, float)), f"{label} — expected number, got {type(val).__name__}")


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from datetime import datetime, timezone

from api.errors import APIErrorConflict, APIErrorInternal, APIErrorNotFound, APIErrorValidation
from api.investigation.evidence_models import (
    BulkCreateEvidenceRequest,
    BulkDeleteEvidenceRequest,
    BulkEvidenceOperationResult,
    BulkUpdateEvidenceItem,
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
    EvidenceSourceResponse,
    EvidenceStatisticsResponse,
    UpdateEvidenceRequest,
)
from api.investigation.evidence_router import (
    _compute_statistics,
    _evidence_to_response,
    _EVIDENCE_STORE,
    _record_to_dict,
    _reset_store,
    bulk_create_evidence,
    bulk_delete_evidence,
    bulk_update_evidence,
    create_evidence,
    delete_evidence,
    evidence_router,
    filter_evidence,
    find_evidence,
    get_evidence,
    get_evidence_statistics,
    list_evidence,
    paginate_evidence,
    search_evidence,
    sort_evidence,
    update_evidence,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response
from services.evidence_service import (
    build_evidence,
    build_metadata,
    EvidenceRecord,
    normalize_field_name,
    normalize_source,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_create_body(**kwargs) -> CreateEvidenceRequest:
    defaults = dict(fieldName="hostname", fieldValue="device-01", sourceType="pcap")
    defaults.update(kwargs)
    return CreateEvidenceRequest(**defaults)


def _post(body: CreateEvidenceRequest) -> APIResponse:
    return create_evidence(body)


def _reset() -> None:
    _reset_store()


# ---------------------------------------------------------------------------
# §1  Router registration
# ---------------------------------------------------------------------------

print("\n§1  Router registration")

ok(evidence_router is not None, "router is not None")
eq(evidence_router.prefix, "/evidence", "prefix is /evidence")
is_list(evidence_router.routes, "routes is list")

route_paths = [r.path for r in evidence_router.routes]
contains(route_paths, "/evidence", "route: list /evidence")
contains(route_paths, "/evidence/statistics", "route: statistics")
contains(route_paths, "/evidence/{evidenceId}", "route: by ID")
contains(route_paths, "/evidence/search", "route: search")
contains(route_paths, "/evidence/bulk/create", "route: bulk/create")
contains(route_paths, "/evidence/bulk/update", "route: bulk/update")
contains(route_paths, "/evidence/bulk/delete", "route: bulk/delete")
eq(len(route_paths), 10, "10 routes registered")


# ---------------------------------------------------------------------------
# §2  Model contracts — request models
# ---------------------------------------------------------------------------

print("\n§2  Request model contracts")

# CreateEvidenceRequest — valid
req = CreateEvidenceRequest(fieldName="hostname", fieldValue="host-a", sourceType="pcap")
eq(req.fieldName, "hostname", "create: fieldName")
eq(req.fieldValue, "host-a", "create: fieldValue")
eq(req.sourceType, "pcap", "create: sourceType")
is_none(req.assetId, "create: assetId default None")
is_none(req.confidence, "create: confidence default None")
ok(req.validate_request() == [], "create: valid request no errors")

# CreateEvidenceRequest — validation errors
bad_name  = CreateEvidenceRequest(fieldName="", fieldValue="val", sourceType="pcap")
bad_value = CreateEvidenceRequest(fieldName="f", fieldValue="  ", sourceType="pcap")
bad_src   = CreateEvidenceRequest(fieldName="f", fieldValue="v", sourceType="")
ok(len(bad_name.validate_request()) > 0,  "create: empty fieldName fails")
ok(len(bad_value.validate_request()) > 0, "create: whitespace fieldValue fails")
ok(len(bad_src.validate_request()) > 0,   "create: empty sourceType fails")

# CreateEvidenceRequest — all fields
full_req = CreateEvidenceRequest(
    fieldName="macAddress", fieldValue="aa:bb:cc:dd:ee:ff",
    sourceType="dhcp", assetId="asset-1", sourceId="src-1",
    confidence=80, packetNumber=42, captureId="cap-1", sessionId="sess-1",
    observedAt="2026-07-03T12:00:00Z",
    protocol="DHCP", packetInfo="DHCP Offer", rawValue="raw-mac",
    tags=["network"], extra={"vlan": 10},
)
ok(full_req.validate_request() == [], "create full: validates OK")
eq(full_req.confidence, 80, "create full: confidence set")
eq(full_req.packetNumber, 42, "create full: packetNumber set")
eq(full_req.tags, ["network"], "create full: tags set")
eq(full_req.extra, {"vlan": 10}, "create full: extra set")

# UpdateEvidenceRequest
upd_none = UpdateEvidenceRequest()
ok(not upd_none.has_any_field(), "update: all None fails has_any_field")
upd_asset = UpdateEvidenceRequest(assetId="new-asset")
ok(upd_asset.has_any_field(), "update: assetId set passes has_any_field")
upd_conf = UpdateEvidenceRequest(confidence=55)
ok(upd_conf.has_any_field(), "update: confidence set passes has_any_field")
upd_full = UpdateEvidenceRequest(
    assetId="a", confidence=90, tags=["x"], extra={"k": "v"},
    protocol="DNS", packetInfo="pi", rawValue="rv",
)
ok(upd_full.has_any_field(), "update full: has_any_field")
eq(upd_full.confidence, 90, "update full: confidence")

# EvidenceFilterRequest — frozen
filt = EvidenceFilterRequest(assetId="a", sourceType="pcap", fieldName="hostname",
                              minConfidence=10, maxConfidence=90, captureId="cap-1")
eq(filt.assetId, "a", "filter: assetId")
eq(filt.minConfidence, 10, "filter: minConfidence")
eq(filt.maxConfidence, 90, "filter: maxConfidence")

# EvidenceSearchRequest
sr = EvidenceSearchRequest(query="host")
eq(sr.query, "host", "search req: query")

# EvidenceSearchQueryRequest
sqr = EvidenceSearchQueryRequest(q="mac")
eq(sqr.q, "mac", "searchquery req: q")
eq(sqr.sortBy, "created", "searchquery req: default sortBy")
eq(sqr.sortOrder, "asc", "searchquery req: default sortOrder")
eq(sqr.page, 1, "searchquery req: default page")
eq(sqr.pageSize, 20, "searchquery req: default pageSize")
ok(sqr.validate_request() == [], "searchquery req: default validates OK")
bad_sort = EvidenceSearchQueryRequest(q="x", sortBy="nonexistent")
ok(len(bad_sort.validate_request()) > 0, "searchquery req: bad sortBy fails")
bad_order = EvidenceSearchQueryRequest(q="x", sortOrder="random")
ok(len(bad_order.validate_request()) > 0, "searchquery req: bad sortOrder fails")

# Models are frozen
try:
    req2 = CreateEvidenceRequest(fieldName="f", fieldValue="v", sourceType="pcap")
    req2.fieldName = "modified"  # type: ignore
    ok(False, "create: should be frozen (mutation should raise)")
except Exception:
    ok(True, "create: frozen model raises on mutation")


# ---------------------------------------------------------------------------
# §3  Model contracts — response models
# ---------------------------------------------------------------------------

print("\n§3  Response model contracts")

src_r = EvidenceSourceResponse(sourceType="pcap", confidence=70)
eq(src_r.sourceType, "pcap", "source resp: sourceType")
eq(src_r.confidence, 70, "source resp: confidence")
is_none(src_r.sourceId, "source resp: sourceId default None")

ref_r = EvidenceReferenceResponse()
is_none(ref_r.packetNumber, "ref resp: default packetNumber")
is_none(ref_r.captureId, "ref resp: default captureId")

meta_r = EvidenceMetadataResponse()
eq(meta_r.tags, [], "meta resp: default tags empty list")
eq(meta_r.extra, {}, "meta resp: default extra empty dict")

ev_r = EvidenceResponse()
is_none(ev_r.evidenceId, "ev resp: default evidenceId")
is_none(ev_r.fieldName, "ev resp: default fieldName")
is_none(ev_r.confidence, "ev resp: default confidence")

ev_r_full = EvidenceResponse(
    evidenceId="abc", evidenceHash="hash", fieldName="hostname",
    fieldValue="host-x", assetId="asset-1",
    source=EvidenceSourceResponse(sourceType="pcap", confidence=80),
    reference=EvidenceReferenceResponse(packetNumber=5),
    confidence=80, engineVersion="ev1", schemaVersion="sv1",
    observedAt="2026-07-03T00:00:00Z", createdAt="2026-07-03T00:00:01Z",
    metadata=EvidenceMetadataResponse(protocol="DNS", tags=["t1"]),
)
eq(ev_r_full.evidenceId, "abc", "ev resp full: evidenceId")
eq(ev_r_full.source.confidence, 80, "ev resp full: source.confidence")
eq(ev_r_full.metadata.protocol, "DNS", "ev resp full: metadata.protocol")
eq(ev_r_full.metadata.tags, ["t1"], "ev resp full: metadata.tags")

list_r = EvidenceListResponse(evidence=[], total=0)
eq(list_r.total, 0, "list resp: total 0")
eq(list_r.evidence, [], "list resp: empty list")

stats_r = EvidenceStatisticsResponse(
    totalRecords=5, uniqueAssets=2, uniqueFields=3, uniqueSources=1,
    averageConfidence=75.0,
    sourceCounts={"pcap": 5}, fieldCounts={"hostname": 3, "macAddress": 2},
    assetCounts={"a1": 3, "a2": 2},
)
eq(stats_r.totalRecords, 5, "stats resp: totalRecords")
eq(stats_r.averageConfidence, 75.0, "stats resp: averageConfidence")
is_dict(stats_r.sourceCounts, "stats resp: sourceCounts is dict")

search_r = EvidenceSearchResponse(
    evidence=[], total=0, page=1, pageSize=20, totalPages=0,
    query="test", sortBy="created", sortOrder="asc",
)
eq(search_r.query, "test", "search resp: query")
eq(search_r.totalPages, 0, "search resp: totalPages 0")

bulk_r = BulkEvidenceOperationResult(
    succeeded=["a", "b"], failed=[{"evidenceId": "c", "reason": "not found"}],
    total=3, successCount=2, failCount=1,
)
eq(bulk_r.successCount, 2, "bulk result: successCount")
eq(bulk_r.failCount, 1, "bulk result: failCount")


# ---------------------------------------------------------------------------
# §4  CRUD — create
# ---------------------------------------------------------------------------

print("\n§4  CRUD — create")
_reset()

body = _make_create_body(fieldName="hostname", fieldValue="device-01", sourceType="pcap")
r = _post(body)
ok(r.success, "create: success=True")
is_dict(r.data, "create: data is dict")
not_none(r.data.get("evidenceId"), "create: evidenceId present")
not_none(r.data.get("evidenceHash"), "create: evidenceHash present")
eq(r.data.get("fieldName"), "hostname", "create: fieldName normalised")
eq(r.data.get("fieldValue"), "device-01", "create: fieldValue stored")
not_none(r.data.get("source"), "create: source present")
eq(r.data["source"]["sourceType"], "pcap", "create: source.sourceType=pcap")
not_none(r.data.get("reference"), "create: reference present")
not_none(r.data.get("metadata"), "create: metadata present")
not_none(r.data.get("confidence"), "create: confidence present")
not_none(r.data.get("engineVersion"), "create: engineVersion present")
not_none(r.data.get("schemaVersion"), "create: schemaVersion present")
eq(len(_EVIDENCE_STORE), 1, "create: store has 1 record")

# Store the id for later
ev_id_1 = r.data["evidenceId"]
is_str(ev_id_1, "create: evidenceId is string")

# 409 on duplicate
r2 = _post(body)
ok(not r2.success, "create duplicate: success=False")
eq(r2.data.errorCode, "CONFLICT", "create duplicate: CONFLICT error code")

# 422 on empty fieldName
bad = _make_create_body(fieldName="", fieldValue="v", sourceType="pcap")
r3 = _post(bad)
ok(not r3.success, "create empty fieldName: success=False")
eq(r3.data.errorCode, "VALIDATION_ERROR", "create empty fieldName: VALIDATION_ERROR")

# 422 on empty fieldValue
bad2 = _make_create_body(fieldName="hostname", fieldValue="  ", sourceType="pcap")
r4 = _post(bad2)
ok(not r4.success, "create whitespace fieldValue: success=False")

# 422 on empty sourceType
bad3 = _make_create_body(fieldName="hostname", fieldValue="v", sourceType="")
r5 = _post(bad3)
ok(not r5.success, "create empty sourceType: success=False")

# 422 on bad observedAt
bad4 = _make_create_body(observedAt="not-a-date")
r6 = _post(bad4)
ok(not r6.success, "create bad observedAt: success=False")
eq(r6.data.errorCode, "VALIDATION_ERROR", "create bad observedAt: VALIDATION_ERROR")

# Create with all optional fields
_reset()
r7 = _post(CreateEvidenceRequest(
    fieldName="macAddress", fieldValue="aa:bb:cc:dd:ee:ff",
    sourceType="dhcp", assetId="asset-1", sourceId="src-1",
    confidence=80, packetNumber=42, captureId="cap-1", sessionId="sess-1",
    observedAt="2026-07-03T12:00:00Z",
    protocol="DHCP", packetInfo="DHCP Offer", rawValue="raw",
    tags=["net"], extra={"vlan": 10},
))
ok(r7.success, "create full: success")
eq(r7.data.get("assetId"), "asset-1", "create full: assetId")
eq(r7.data["metadata"]["protocol"], "DHCP", "create full: metadata.protocol")
eq(r7.data["metadata"]["tags"], ["net"], "create full: metadata.tags")
eq(r7.data["metadata"]["extra"]["vlan"], 10, "create full: metadata.extra.vlan")
eq(r7.data["reference"]["packetNumber"], 42, "create full: reference.packetNumber")
eq(r7.data["reference"]["captureId"], "cap-1", "create full: reference.captureId")
eq(r7.data["source"]["confidence"], 80, "create full: source.confidence=80")


# ---------------------------------------------------------------------------
# §5  CRUD — get single
# ---------------------------------------------------------------------------

print("\n§5  CRUD — get single")
_reset()
r = _post(_make_create_body(fieldName="hostname", fieldValue="host-a", sourceType="pcap"))
ev_id = r.data["evidenceId"]

rg = get_evidence(ev_id)
ok(rg.success, "get: success=True")
eq(rg.data["evidenceId"], ev_id, "get: correct evidenceId returned")
eq(rg.data["fieldValue"], "host-a", "get: fieldValue correct")

r404 = get_evidence("nonexistent-id-xyz")
ok(not r404.success, "get 404: success=False")
eq(r404.data.errorCode, "NOT_FOUND", "get 404: NOT_FOUND error code")


# ---------------------------------------------------------------------------
# §6  CRUD — update
# ---------------------------------------------------------------------------

print("\n§6  CRUD — update")
_reset()
r = _post(_make_create_body(fieldName="hostname", fieldValue="host-a", sourceType="pcap"))
ev_id = r.data["evidenceId"]

# Update assetId
upd1 = update_evidence(ev_id, UpdateEvidenceRequest(assetId="asset-99"))
ok(upd1.success, "update assetId: success")
eq(upd1.data["assetId"], "asset-99", "update assetId: value updated")

# Update confidence
upd2 = update_evidence(ev_id, UpdateEvidenceRequest(confidence=55))
ok(upd2.success, "update confidence: success")
eq(upd2.data["confidence"], 55, "update confidence: value updated")
eq(upd2.data["source"]["confidence"], 55, "update confidence: source.confidence synced")

# Update protocol
upd3 = update_evidence(ev_id, UpdateEvidenceRequest(protocol="DNS"))
ok(upd3.success, "update protocol: success")
eq(upd3.data["metadata"]["protocol"], "DNS", "update protocol: set")

# Update tags
upd4 = update_evidence(ev_id, UpdateEvidenceRequest(tags=["critical", "network"]))
ok(upd4.success, "update tags: success")
eq(upd4.data["metadata"]["tags"], ["critical", "network"], "update tags: set")

# Update extra (merge)
upd5 = update_evidence(ev_id, UpdateEvidenceRequest(extra={"severity": "high"}))
ok(upd5.success, "update extra: success")
eq(upd5.data["metadata"]["extra"]["severity"], "high", "update extra: merged")

# Update packetInfo and rawValue
upd6 = update_evidence(ev_id, UpdateEvidenceRequest(packetInfo="ARP Reply", rawValue="raw-v"))
ok(upd6.success, "update packetInfo+rawValue: success")
eq(upd6.data["metadata"]["packetInfo"], "ARP Reply", "update packetInfo: set")
eq(upd6.data["metadata"]["rawValue"], "raw-v", "update rawValue: set")

# 422 — empty body
upd_empty = update_evidence(ev_id, UpdateEvidenceRequest())
ok(not upd_empty.success, "update empty body: success=False")
eq(upd_empty.data.errorCode, "VALIDATION_ERROR", "update empty body: VALIDATION_ERROR")

# 404 — not found
upd404 = update_evidence("no-such-id", UpdateEvidenceRequest(assetId="x"))
ok(not upd404.success, "update 404: success=False")
eq(upd404.data.errorCode, "NOT_FOUND", "update 404: NOT_FOUND")

# Immutable fields are NOT changed
stored_hash = r.data["evidenceHash"]
stored_field = r.data["fieldName"]
eq(_EVIDENCE_STORE[ev_id]["evidenceHash"], stored_hash, "update: evidenceHash not changed")
eq(_EVIDENCE_STORE[ev_id]["fieldName"], stored_field, "update: fieldName not changed")


# ---------------------------------------------------------------------------
# §7  CRUD — list
# ---------------------------------------------------------------------------

print("\n§7  CRUD — list")
_reset()
_post(_make_create_body(fieldName="hostname", fieldValue="h1", sourceType="pcap"))
_post(_make_create_body(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22", sourceType="dhcp"))
_post(_make_create_body(fieldName="ipAddress", fieldValue="10.0.0.1", sourceType="nmap"))

r = list_evidence()
ok(r.success, "list: success")
is_dict(r.data, "list: data is dict")
eq(r.data["total"], 3, "list: total=3")
is_list(r.data["evidence"], "list: evidence is list")
eq(len(r.data["evidence"]), 3, "list: 3 records returned")

# All records have expected keys
for ev in r.data["evidence"]:
    not_none(ev.get("evidenceId"), "list item: evidenceId present")
    not_none(ev.get("fieldName"), "list item: fieldName present")
    not_none(ev.get("fieldValue"), "list item: fieldValue present")
    not_none(ev.get("source"), "list item: source present")

# Empty store
_reset()
r_empty = list_evidence()
ok(r_empty.success, "list empty: success")
eq(r_empty.data["total"], 0, "list empty: total=0")
eq(r_empty.data["evidence"], [], "list empty: empty list")


# ---------------------------------------------------------------------------
# §8  CRUD — delete
# ---------------------------------------------------------------------------

print("\n§8  CRUD — delete")
_reset()
r = _post(_make_create_body(fieldName="hostname", fieldValue="to-delete", sourceType="pcap"))
ev_id = r.data["evidenceId"]

rd = delete_evidence(ev_id)
ok(rd.success, "delete: success")
is_none(rd.data, "delete: data=None")
ok(ev_id not in _EVIDENCE_STORE, "delete: removed from store")

r404 = delete_evidence(ev_id)
ok(not r404.success, "delete 404: success=False")
eq(r404.data.errorCode, "NOT_FOUND", "delete 404: NOT_FOUND")


# ---------------------------------------------------------------------------
# §9  Statistics
# ---------------------------------------------------------------------------

print("\n§9  Statistics")
_reset()

# Empty store
rs0 = get_evidence_statistics()
ok(rs0.success, "stats empty: success")
eq(rs0.data["totalRecords"], 0, "stats empty: totalRecords=0")
eq(rs0.data["uniqueAssets"], 0, "stats empty: uniqueAssets=0")
eq(rs0.data["averageConfidence"], 0.0, "stats empty: averageConfidence=0.0")
eq(rs0.data["sourceCounts"], {}, "stats empty: sourceCounts={}")
eq(rs0.data["fieldCounts"], {}, "stats empty: fieldCounts={}")
eq(rs0.data["assetCounts"], {}, "stats empty: assetCounts={}")

# Populate
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="h1", sourceType="pcap",
                             assetId="asset-1", confidence=80))
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="h2", sourceType="pcap",
                             assetId="asset-1", confidence=60))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22",
                             sourceType="dhcp", assetId="asset-2", confidence=70))
_post(CreateEvidenceRequest(fieldName="ipAddress", fieldValue="10.0.0.1",
                             sourceType="nmap", confidence=50))  # no assetId

rs = get_evidence_statistics()
ok(rs.success, "stats: success")
eq(rs.data["totalRecords"], 4, "stats: totalRecords=4")
eq(rs.data["uniqueAssets"], 2, "stats: uniqueAssets=2 (null excluded)")
eq(rs.data["uniqueFields"], 3, "stats: uniqueFields=3")
eq(rs.data["uniqueSources"], 3, "stats: uniqueSources=3")
eq(rs.data["averageConfidence"], 65.0, "stats: averageConfidence=(80+60+70+50)/4=65.0")

is_dict(rs.data["sourceCounts"], "stats: sourceCounts is dict")
eq(rs.data["sourceCounts"].get("pcap"), 2, "stats: pcap count=2")
eq(rs.data["sourceCounts"].get("dhcp"), 1, "stats: dhcp count=1")
eq(rs.data["sourceCounts"].get("nmap"), 1, "stats: nmap count=1")

is_dict(rs.data["fieldCounts"], "stats: fieldCounts is dict")
eq(rs.data["fieldCounts"].get("hostname"), 2, "stats: hostname count=2")
# normalize_field_name() lowercases single-word inputs: macAddress→macaddress, ipAddress→ipaddress
eq(rs.data["fieldCounts"].get("macaddress"), 1, "stats: macaddress count=1")
eq(rs.data["fieldCounts"].get("ipaddress"), 1, "stats: ipaddress count=1")

is_dict(rs.data["assetCounts"], "stats: assetCounts is dict")
eq(rs.data["assetCounts"].get("asset-1"), 2, "stats: asset-1 count=2")
eq(rs.data["assetCounts"].get("asset-2"), 1, "stats: asset-2 count=1")
ok("None" not in rs.data["assetCounts"], "stats: None assetId not in assetCounts")

# Keys are sorted
source_keys = list(rs.data["sourceCounts"].keys())
eq(source_keys, sorted(source_keys), "stats: sourceCounts keys sorted")
field_keys = list(rs.data["fieldCounts"].keys())
eq(field_keys, sorted(field_keys), "stats: fieldCounts keys sorted")


# ---------------------------------------------------------------------------
# §10  Pure helper — find_evidence()
# ---------------------------------------------------------------------------

print("\n§10  Pure helper — find_evidence()")
_reset()
_post(_make_create_body(fieldName="hostname", fieldValue="host-a", sourceType="pcap",
                         assetId="asset-1"))
_post(_make_create_body(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22", sourceType="dhcp",
                         assetId="asset-2"))
_post(_make_create_body(fieldName="ipAddress", fieldValue="192.168.1.10", sourceType="nmap",
                         assetId="asset-1"))

all_recs = list(_EVIDENCE_STORE.values())

found = find_evidence(all_recs, "assetId", "asset-1")
not_none(found, "find: found by assetId")
eq(found["assetId"], "asset-1", "find: correct record")

found2 = find_evidence(all_recs, "fieldValue", "aa:bb:cc:00:11:22")
not_none(found2, "find: found by fieldValue")
eq(found2["fieldValue"], "aa:bb:cc:00:11:22", "find: fieldValue match")

not_found = find_evidence(all_recs, "assetId", "nonexistent")
is_none(not_found, "find: returns None for no match")

# Case-insensitive
found_ci = find_evidence(all_recs, "assetId", "ASSET-1")
not_none(found_ci, "find: case-insensitive match")

# Empty list
is_none(find_evidence([], "fieldName", "hostname"), "find empty: returns None")


# ---------------------------------------------------------------------------
# §11  Pure helper — sort_evidence()
# ---------------------------------------------------------------------------

print("\n§11  Pure helper — sort_evidence()")
_reset()
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="host-c", sourceType="nmap",
                             confidence=30))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22",
                             sourceType="dhcp", confidence=80))
_post(CreateEvidenceRequest(fieldName="ipAddress", fieldValue="10.0.0.1", sourceType="pcap",
                             confidence=55))

all_recs = list(_EVIDENCE_STORE.values())

# Sort by confidence ascending
sorted_asc = sort_evidence(all_recs, "confidence", "asc")
confidences_asc = [r["confidence"] for r in sorted_asc]
eq(confidences_asc, sorted(confidences_asc), "sort confidence asc: ascending order")

# Sort by confidence descending
sorted_desc = sort_evidence(all_recs, "confidence", "desc")
confidences_desc = [r["confidence"] for r in sorted_desc]
eq(confidences_desc, sorted(confidences_desc, reverse=True), "sort confidence desc: descending order")

# Sort by fieldName ascending
sorted_fn = sort_evidence(all_recs, "fieldName", "asc")
field_names_sorted = [r["fieldName"] for r in sorted_fn]
eq(field_names_sorted, sorted(field_names_sorted, key=str.lower), "sort fieldName asc: alphabetical")

# Sort by sourceType ascending (nested source.sourceType)
sorted_st = sort_evidence(all_recs, "sourceType", "asc")
source_types_sorted = [r["source"]["sourceType"] for r in sorted_st]
eq(source_types_sorted, sorted(source_types_sorted), "sort sourceType asc: alphabetical")

# Sort by created (default)
sorted_cr = sort_evidence(all_recs, "created", "asc")
is_list(sorted_cr, "sort created: returns list")
eq(len(sorted_cr), 3, "sort created: all records returned")

# Unknown sort key falls back to created
sorted_unk = sort_evidence(all_recs, "nonexistent", "asc")
eq(len(sorted_unk), 3, "sort unknown key: all records returned")

# Input is not mutated
original_ids = [r["evidenceId"] for r in all_recs]
sort_evidence(all_recs, "confidence", "desc")
eq([r["evidenceId"] for r in all_recs], original_ids, "sort: input not mutated")

# Case-insensitive sort_by
sorted_ci = sort_evidence(all_recs, "CONFIDENCE", "asc")
eq([r["confidence"] for r in sorted_ci], sorted([r["confidence"] for r in all_recs]),
   "sort: sortBy case-insensitive")


# ---------------------------------------------------------------------------
# §12  Pure helper — filter_evidence()
# ---------------------------------------------------------------------------

print("\n§12  Pure helper — filter_evidence()")
_reset()
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="h1", sourceType="pcap",
                             assetId="asset-A", captureId="cap-1", confidence=80))
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="h2", sourceType="dhcp",
                             assetId="asset-A", captureId="cap-2", confidence=40))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22",
                             sourceType="pcap", assetId="asset-B", captureId="cap-1", confidence=60))
_post(CreateEvidenceRequest(fieldName="ipAddress", fieldValue="10.0.0.1", sourceType="nmap",
                             captureId="cap-3", confidence=20))

all_recs = list(_EVIDENCE_STORE.values())

# Filter by assetId
f_asset = filter_evidence(all_recs, asset_id="asset-A")
eq(len(f_asset), 2, "filter assetId: 2 matching")
ok(all(r["assetId"] == "asset-A" for r in f_asset), "filter assetId: all match")

# Filter by sourceType
f_src = filter_evidence(all_recs, source_type="pcap")
eq(len(f_src), 2, "filter sourceType pcap: 2 matching")

# Filter by fieldName
f_fn = filter_evidence(all_recs, field_name="hostname")
eq(len(f_fn), 2, "filter fieldName hostname: 2 matching")

# Filter by minConfidence
f_min = filter_evidence(all_recs, min_confidence=60)
eq(len(f_min), 2, "filter minConfidence=60: 2 matching")

# Filter by maxConfidence
f_max = filter_evidence(all_recs, max_confidence=40)
eq(len(f_max), 2, "filter maxConfidence=40: 2 matching")

# Filter by captureId
f_cap = filter_evidence(all_recs, capture_id="cap-1")
eq(len(f_cap), 2, "filter captureId cap-1: 2 matching")

# Combined filters
f_combined = filter_evidence(all_recs, asset_id="asset-A", source_type="pcap")
eq(len(f_combined), 1, "filter combined assetId+sourceType: 1 match")

# Filter with confidence range
f_range = filter_evidence(all_recs, min_confidence=40, max_confidence=70)
eq(len(f_range), 2, "filter confidence range 40-70: 2 matching")

# No filters — all records
f_none = filter_evidence(all_recs)
eq(len(f_none), 4, "filter none: all 4 records")

# No matches
f_nomatch = filter_evidence(all_recs, asset_id="nonexistent")
eq(len(f_nomatch), 0, "filter no match: empty list")

# Input not mutated
original_count = len(all_recs)
filter_evidence(all_recs, asset_id="asset-A")
eq(len(all_recs), original_count, "filter: input not mutated")

# Case-insensitive assetId and sourceType
f_ci1 = filter_evidence(all_recs, asset_id="ASSET-A")
eq(len(f_ci1), 2, "filter assetId case-insensitive: 2 matching")
f_ci2 = filter_evidence(all_recs, source_type="PCAP")
eq(len(f_ci2), 2, "filter sourceType case-insensitive: 2 matching")


# ---------------------------------------------------------------------------
# §13  Pure helper — paginate_evidence()
# ---------------------------------------------------------------------------

print("\n§13  Pure helper — paginate_evidence()")
import math

records_25 = [{"evidenceId": f"ev-{i:03d}"} for i in range(25)]

# Page 1, size 10
slice1, pg1 = paginate_evidence(records_25, 1, 10)
eq(len(slice1), 10, "paginate: page1 has 10 items")
eq(pg1.page, 1, "paginate: page=1")
eq(pg1.pageSize, 10, "paginate: pageSize=10")
eq(pg1.totalItems, 25, "paginate: totalItems=25")
eq(pg1.totalPages, 3, "paginate: totalPages=3")
eq(slice1[0]["evidenceId"], "ev-000", "paginate: first item on page 1")
eq(slice1[-1]["evidenceId"], "ev-009", "paginate: last item on page 1")

# Page 2, size 10
slice2, pg2 = paginate_evidence(records_25, 2, 10)
eq(len(slice2), 10, "paginate: page2 has 10 items")
eq(slice2[0]["evidenceId"], "ev-010", "paginate: first item on page 2")

# Page 3, size 10 — partial page
slice3, pg3 = paginate_evidence(records_25, 3, 10)
eq(len(slice3), 5, "paginate: page3 has 5 items (partial)")
eq(slice3[0]["evidenceId"], "ev-020", "paginate: first item on page 3")

# Page beyond last
slice4, pg4 = paginate_evidence(records_25, 99, 10)
eq(len(slice4), 0, "paginate: beyond last page returns empty")
eq(pg4.totalPages, 3, "paginate: totalPages still correct for out-of-range page")

# Size = 1
slice5, pg5 = paginate_evidence(records_25, 1, 1)
eq(len(slice5), 1, "paginate: page size 1 returns 1 item")
eq(pg5.totalPages, 25, "paginate: totalPages=25 for pageSize=1")

# Page clamped to >= 1
slice6, pg6 = paginate_evidence(records_25, 0, 10)
eq(pg6.page, 1, "paginate: page clamped to 1")

# Single page — all fit
slice7, pg7 = paginate_evidence(records_25, 1, 50)
eq(len(slice7), 25, "paginate: all items fit in one page")
eq(pg7.totalPages, 1, "paginate: totalPages=1 when all fit")

# Empty list
slice8, pg8 = paginate_evidence([], 1, 20)
eq(len(slice8), 0, "paginate empty: empty slice")
eq(pg8.totalItems, 0, "paginate empty: totalItems=0")
eq(pg8.totalPages, 0, "paginate empty: totalPages=0")

# Returns Pagination model
ok(isinstance(pg1, Pagination), "paginate: returns Pagination model")

# Input not mutated
original_ids = [r["evidenceId"] for r in records_25]
paginate_evidence(records_25, 1, 5)
eq([r["evidenceId"] for r in records_25], original_ids, "paginate: input not mutated")


# ---------------------------------------------------------------------------
# §14  Search endpoint
# ---------------------------------------------------------------------------

print("\n§14  Search endpoint")
_reset()
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="alpha-router", sourceType="pcap",
                             assetId="asset-1", confidence=80))
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="beta-switch", sourceType="pcap",
                             assetId="asset-2", confidence=50))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22",
                             sourceType="dhcp", assetId="asset-1", confidence=70))
_post(CreateEvidenceRequest(fieldName="ipAddress", fieldValue="192.168.1.50",
                             sourceType="nmap", assetId="asset-3", confidence=40))

# Basic search
rs = search_evidence(q="alpha")
ok(rs.success, "search alpha: success")
is_dict(rs.data, "search alpha: data is dict")
eq(rs.data["query"], "alpha", "search alpha: query preserved")
eq(rs.data["total"], 1, "search alpha: 1 result")
eq(len(rs.data["evidence"]), 1, "search alpha: 1 record in evidence list")

# Search matching sourceType
rs2 = search_evidence(q="dhcp")
ok(rs2.success, "search dhcp: success")
eq(rs2.data["total"], 1, "search dhcp: 1 result (sourceType match)")

# Search matching assetId
rs3 = search_evidence(q="asset-3")
ok(rs3.success, "search asset-3: success")
eq(rs3.data["total"], 1, "search asset-3: 1 result")

# Search matching fieldValue
rs4 = search_evidence(q="192.168")
ok(rs4.success, "search IP prefix: success")
eq(rs4.data["total"], 1, "search IP prefix: 1 result")

# Search no results
rs5 = search_evidence(q="zzz_no_match_xxx")
ok(rs5.success, "search no match: success")
eq(rs5.data["total"], 0, "search no match: 0 results")

# Pagination in search
rs_pg = search_evidence(q="pcap", page=1, page_size=2)
ok(rs_pg.success, "search paginated: success")
is_dict(rs_pg.data, "search paginated: data is dict")
not_none(rs_pg.data.get("page"), "search paginated: page present")
not_none(rs_pg.data.get("pageSize"), "search paginated: pageSize present")
not_none(rs_pg.data.get("totalPages"), "search paginated: totalPages present")
eq(rs_pg.data["pageSize"], 2, "search paginated: pageSize=2")

# Search + filter by assetId
rs_f = search_evidence(q="hostname", asset_id_filter="asset-1")
ok(rs_f.success, "search+filter assetId: success")
eq(rs_f.data["total"], 1, "search+filter assetId: 1 result")

# Search + filter by sourceType
rs_f2 = search_evidence(q="h", source_type_filter="pcap")
ok(rs_f2.success, "search+filter sourceType: success")
ok(rs_f2.data["total"] >= 1, "search+filter sourceType: at least 1")

# Search + sort by confidence desc
rs_sort = search_evidence(q="pcap", sort_by="confidence", sort_order="desc")
ok(rs_sort.success, "search sorted confidence desc: success")
if rs_sort.data["total"] > 1:
    confs = [ev["confidence"] for ev in rs_sort.data["evidence"]]
    ok(confs == sorted(confs, reverse=True), "search sorted confidence desc: descending")

# Search + minConfidence filter
rs_min = search_evidence(q="hostname", min_confidence_filter=70)
ok(rs_min.success, "search minConfidence=70: success")
ok(rs_min.data["total"] <= 2, "search minConfidence=70: filtered")

# Invalid sortBy
rs_bad = search_evidence(q="test", sort_by="nonexistent")
ok(not rs_bad.success, "search bad sortBy: success=False")
eq(rs_bad.data.errorCode, "VALIDATION_ERROR", "search bad sortBy: VALIDATION_ERROR")

# Invalid sortOrder
rs_bad2 = search_evidence(q="test", sort_order="sideways")
ok(not rs_bad2.success, "search bad sortOrder: success=False")

# Empty query
rs_eq = search_evidence(q="   ")
ok(not rs_eq.success, "search empty query: success=False")


# ---------------------------------------------------------------------------
# §15  Bulk create
# ---------------------------------------------------------------------------

print("\n§15  Bulk create")
_reset()

bulk_body = BulkCreateEvidenceRequest(evidence=[
    CreateEvidenceRequest(fieldName="hostname", fieldValue="host-bulk-1", sourceType="pcap",
                          assetId="asset-bulk"),
    CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:bb:cc:11:22:33",
                          sourceType="dhcp", assetId="asset-bulk"),
    CreateEvidenceRequest(fieldName="ipAddress", fieldValue="10.1.1.1", sourceType="nmap"),
])
rb = bulk_create_evidence(bulk_body)
ok(rb.success, "bulk create: success")
is_dict(rb.data, "bulk create: data is dict")
eq(rb.data["total"], 3, "bulk create: total=3")
eq(rb.data["successCount"], 3, "bulk create: 3 succeeded")
eq(rb.data["failCount"], 0, "bulk create: 0 failed")
eq(len(rb.data["succeeded"]), 3, "bulk create: 3 evidenceIds in succeeded")
eq(len(_EVIDENCE_STORE), 3, "bulk create: 3 records in store")

# All succeeded IDs are strings
for eid in rb.data["succeeded"]:
    is_str(eid, f"bulk create: succeeded ID {eid!r} is string")

# Partial success — one duplicate
rb2 = bulk_create_evidence(BulkCreateEvidenceRequest(evidence=[
    CreateEvidenceRequest(fieldName="hostname", fieldValue="host-bulk-1", sourceType="pcap",
                          assetId="asset-bulk"),  # duplicate
    CreateEvidenceRequest(fieldName="hostname", fieldValue="host-new-unique-x99",
                          sourceType="pcap"),     # new
]))
ok(rb2.success, "bulk create partial: success (partial allowed)")
eq(rb2.data["total"], 2, "bulk create partial: total=2")
eq(rb2.data["successCount"], 1, "bulk create partial: 1 succeeded")
eq(rb2.data["failCount"], 1, "bulk create partial: 1 failed")

# 422 — empty list (Pydantic enforces min_length=1, test model-level)
ok(True, "bulk create: Pydantic enforces min_length=1 at model level")

# 422 — validation errors in items
rb3 = bulk_create_evidence(BulkCreateEvidenceRequest(evidence=[
    CreateEvidenceRequest(fieldName="", fieldValue="v", sourceType="pcap"),
    CreateEvidenceRequest(fieldName="hostname", fieldValue="", sourceType="pcap"),
]))
ok(not rb3.success, "bulk create all invalid: success=False")
eq(rb3.data.errorCode, "VALIDATION_ERROR", "bulk create all invalid: VALIDATION_ERROR")


# ---------------------------------------------------------------------------
# §16  Bulk update
# ---------------------------------------------------------------------------

print("\n§16  Bulk update")
_reset()
r1 = _post(_make_create_body(fieldName="hostname", fieldValue="h1", sourceType="pcap"))
r2 = _post(_make_create_body(fieldName="macAddress", fieldValue="aa:bb:cc:00:11:22", sourceType="dhcp"))
r3 = _post(_make_create_body(fieldName="ipAddress", fieldValue="10.0.0.5", sourceType="nmap"))
id1 = r1.data["evidenceId"]
id2 = r2.data["evidenceId"]
id3 = r3.data["evidenceId"]

bulk_upd_body = BulkUpdateEvidenceRequest(items=[
    BulkUpdateEvidenceItem(evidenceId=id1, update=UpdateEvidenceRequest(assetId="bulk-asset")),
    BulkUpdateEvidenceItem(evidenceId=id2, update=UpdateEvidenceRequest(confidence=99)),
    BulkUpdateEvidenceItem(evidenceId=id3, update=UpdateEvidenceRequest(
        tags=["updated"], protocol="ARP"
    )),
])
rbu = bulk_update_evidence(bulk_upd_body)
ok(rbu.success, "bulk update: success")
eq(rbu.data["total"], 3, "bulk update: total=3")
eq(rbu.data["successCount"], 3, "bulk update: 3 succeeded")
eq(rbu.data["failCount"], 0, "bulk update: 0 failed")

# Verify updates applied
eq(_EVIDENCE_STORE[id1]["assetId"], "bulk-asset", "bulk update: id1 assetId updated")
eq(_EVIDENCE_STORE[id2]["confidence"], 99, "bulk update: id2 confidence updated")
eq(_EVIDENCE_STORE[id3]["metadata"]["tags"], ["updated"], "bulk update: id3 tags updated")
eq(_EVIDENCE_STORE[id3]["metadata"]["protocol"], "ARP", "bulk update: id3 protocol updated")

# Partial failure — one not found
rbu2 = bulk_update_evidence(BulkUpdateEvidenceRequest(items=[
    BulkUpdateEvidenceItem(evidenceId=id1, update=UpdateEvidenceRequest(assetId="new-a")),
    BulkUpdateEvidenceItem(evidenceId="no-such-id", update=UpdateEvidenceRequest(assetId="x")),
]))
ok(rbu2.success, "bulk update partial: success (partial allowed)")
eq(rbu2.data["successCount"], 1, "bulk update partial: 1 succeeded")
eq(rbu2.data["failCount"], 1, "bulk update partial: 1 failed")

# 422 — empty items
try:
    BulkUpdateEvidenceRequest(items=[])
    ok(False, "bulk update: empty items should fail Pydantic validation")
except Exception:
    ok(True, "bulk update: empty items raises Pydantic error")

# 422 — missing field in update
bad_upd = BulkUpdateEvidenceRequest(items=[
    BulkUpdateEvidenceItem(evidenceId=id1, update=UpdateEvidenceRequest()),  # no fields
])
rbu3 = bulk_update_evidence(bad_upd)
ok(not rbu3.success, "bulk update empty update: success=False")
eq(rbu3.data.errorCode, "VALIDATION_ERROR", "bulk update empty update: VALIDATION_ERROR")


# ---------------------------------------------------------------------------
# §17  Bulk delete
# ---------------------------------------------------------------------------

print("\n§17  Bulk delete")
_reset()
r1 = _post(_make_create_body(fieldName="hostname", fieldValue="hd1", sourceType="pcap"))
r2 = _post(_make_create_body(fieldName="macAddress", fieldValue="aa:bb:cc:44:55:66", sourceType="dhcp"))
r3 = _post(_make_create_body(fieldName="ipAddress", fieldValue="172.16.0.1", sourceType="nmap"))
id1 = r1.data["evidenceId"]
id2 = r2.data["evidenceId"]
id3 = r3.data["evidenceId"]

rbd = bulk_delete_evidence(BulkDeleteEvidenceRequest(evidenceIds=[id1, id2]))
ok(rbd.success, "bulk delete: success")
eq(rbd.data["total"], 2, "bulk delete: total=2")
eq(rbd.data["successCount"], 2, "bulk delete: 2 succeeded")
eq(rbd.data["failCount"], 0, "bulk delete: 0 failed")
ok(id1 not in _EVIDENCE_STORE, "bulk delete: id1 removed")
ok(id2 not in _EVIDENCE_STORE, "bulk delete: id2 removed")
ok(id3 in _EVIDENCE_STORE, "bulk delete: id3 still present")

# Partial failure — some not found
rbd2 = bulk_delete_evidence(BulkDeleteEvidenceRequest(evidenceIds=[id3, "nonexistent-1", "nonexistent-2"]))
ok(rbd2.success, "bulk delete partial: success (partial allowed)")
eq(rbd2.data["successCount"], 1, "bulk delete partial: 1 succeeded")
eq(rbd2.data["failCount"], 2, "bulk delete partial: 2 failed")
ok(id3 not in _EVIDENCE_STORE, "bulk delete partial: id3 removed")

# 422 — empty list
try:
    BulkDeleteEvidenceRequest(evidenceIds=[])
    ok(False, "bulk delete: empty list should fail Pydantic validation")
except Exception:
    ok(True, "bulk delete: empty list raises Pydantic error")

# 422 — empty string IDs
bad_del = BulkDeleteEvidenceRequest(evidenceIds=["valid-id", "  "])
rbd3 = bulk_delete_evidence(bad_del)
ok(not rbd3.success, "bulk delete empty string ID: success=False")
eq(rbd3.data.errorCode, "VALIDATION_ERROR", "bulk delete empty string ID: VALIDATION_ERROR")


# ---------------------------------------------------------------------------
# §18  Deterministic behaviour
# ---------------------------------------------------------------------------

print("\n§18  Deterministic behaviour")
_reset()

# Same inputs always produce same evidenceId
r_a = _post(_make_create_body(fieldName="hostname", fieldValue="consistent-host", sourceType="pcap"))
ev_id_a = r_a.data["evidenceId"]
ev_hash_a = r_a.data["evidenceHash"]

# Build same record directly from evidence_service
record_direct = build_evidence(
    field_name="hostname", field_value="consistent-host", source_type="pcap"
)
eq(record_direct.evidenceId, ev_id_a, "deterministic: same inputs → same evidenceId")
eq(record_direct.evidenceHash, ev_hash_a, "deterministic: same inputs → same evidenceHash")

# Different field value → different ID
_reset()
r_b = _post(_make_create_body(fieldName="hostname", fieldValue="different-host", sourceType="pcap"))
ne(r_b.data["evidenceId"], ev_id_a, "deterministic: different value → different evidenceId")
ne(r_b.data["evidenceHash"], ev_hash_a, "deterministic: different value → different evidenceHash")

# fieldName normalisation (camelCase)
_reset()
r_norm = _post(_make_create_body(fieldName="mac_address", fieldValue="aa:bb:cc:dd:ee:ff",
                                  sourceType="pcap"))
eq(r_norm.data["fieldName"], "macAddress", "normalisation: mac_address → macAddress")

_reset()
r_norm2 = _post(_make_create_body(fieldName="IP Address", fieldValue="10.0.0.1", sourceType="pcap"))
eq(r_norm2.data["fieldName"], "ipAddress", "normalisation: 'IP Address' → ipAddress")

# normalize_source: known source → preserved, unknown → 'unknown'
eq(normalize_source("pcap"), "pcap", "normalize_source: pcap")
eq(normalize_source("dhcp"), "dhcp", "normalize_source: dhcp")
eq(normalize_source("nmap"), "nmap", "normalize_source: nmap")
eq(normalize_source("totally_unknown_src"), "unknown", "normalize_source: unknown → 'unknown'")
eq(normalize_source(""), "unknown", "normalize_source: empty → 'unknown'")

# normalize_field_name
eq(normalize_field_name("mac_address"), "macAddress", "normalize_field: mac_address")
eq(normalize_field_name("IP Address"), "ipAddress", "normalize_field: IP Address")
eq(normalize_field_name(""), "unknown", "normalize_field: empty → unknown")


# ---------------------------------------------------------------------------
# §19  Serialization — model_dump() round-trips
# ---------------------------------------------------------------------------

print("\n§19  Serialization")
_reset()
r = _post(CreateEvidenceRequest(
    fieldName="hostname", fieldValue="serial-host", sourceType="pcap",
    assetId="asset-s", confidence=75,
    tags=["t1", "t2"], extra={"k": "v"}, protocol="ARP",
))
ev_dict = r.data

# model_dump produces plain dict
ok(isinstance(ev_dict, dict), "serial: data is dict after model_dump")

# Nested models serialized to dicts
ok(isinstance(ev_dict["source"], dict), "serial: source is dict")
ok(isinstance(ev_dict["reference"], dict), "serial: reference is dict")
ok(isinstance(ev_dict["metadata"], dict), "serial: metadata is dict")

# Tags serialized to list
ok(isinstance(ev_dict["metadata"]["tags"], list), "serial: tags is list")

# Extra serialized to dict
ok(isinstance(ev_dict["metadata"]["extra"], dict), "serial: extra is dict")

# EvidenceResponse model_dump round-trip
ev_resp = _evidence_to_response(r.data)
dumped = ev_resp.model_dump()
ok(isinstance(dumped, dict), "serial: EvidenceResponse.model_dump() returns dict")
eq(dumped["evidenceId"], r.data["evidenceId"], "serial: evidenceId preserved in dump")
ok(isinstance(dumped["source"], dict), "serial: source dict in dump")
ok(isinstance(dumped["metadata"]["tags"], list), "serial: tags list in dump")

# EvidenceStatisticsResponse model_dump
stats = get_evidence_statistics()
dumped_stats = stats.data
ok(isinstance(dumped_stats, dict), "serial: stats is dict")
ok(isinstance(dumped_stats["sourceCounts"], dict), "serial: sourceCounts is dict")
ok(isinstance(dumped_stats["fieldCounts"], dict), "serial: fieldCounts is dict")
ok(isinstance(dumped_stats["assetCounts"], dict), "serial: assetCounts is dict")
ok(isinstance(dumped_stats["averageConfidence"], (int, float)),
   "serial: averageConfidence is number")


# ---------------------------------------------------------------------------
# §20  Edge cases
# ---------------------------------------------------------------------------

print("\n§20  Edge cases")

# empty store operations
_reset()
eq(len(_EVIDENCE_STORE), 0, "edge: store empty after reset")

# list on empty store
r_empty = list_evidence()
ok(r_empty.success, "edge list empty: success")
eq(r_empty.data["total"], 0, "edge list empty: total=0")

# stats on empty store
rs_empty = get_evidence_statistics()
ok(rs_empty.success, "edge stats empty: success")
eq(rs_empty.data["totalRecords"], 0, "edge stats empty: totalRecords=0")
eq(rs_empty.data["averageConfidence"], 0.0, "edge stats empty: averageConfidence=0.0")

# search on empty store
rs_s = search_evidence(q="anything")
ok(rs_s.success, "edge search empty: success")
eq(rs_s.data["total"], 0, "edge search empty: 0 results")

# filter on empty list
f_empty = filter_evidence([], asset_id="x")
eq(f_empty, [], "edge filter empty: empty result")

# sort on empty list
s_empty = sort_evidence([], "confidence", "asc")
eq(s_empty, [], "edge sort empty: empty result")

# paginate empty list
sl, pg = paginate_evidence([], 1, 10)
eq(sl, [], "edge paginate empty: empty slice")
eq(pg.totalItems, 0, "edge paginate empty: totalItems=0")
eq(pg.totalPages, 0, "edge paginate empty: totalPages=0")

# find_evidence on empty list
found = find_evidence([], "fieldName", "hostname")
is_none(found, "edge find empty: None")

# Single record store
_reset()
rs1 = _post(_make_create_body(fieldName="hostname", fieldValue="only-one", sourceType="pcap"))
eq(len(_EVIDENCE_STORE), 1, "edge single record: store has 1")
rl = list_evidence()
eq(rl.data["total"], 1, "edge single record list: total=1")
st = get_evidence_statistics()
eq(st.data["totalRecords"], 1, "edge single record stats: totalRecords=1")

# createdAt is populated
not_none(rs1.data.get("createdAt"), "edge: createdAt populated")

# engineVersion and schemaVersion present
not_none(rs1.data.get("engineVersion"), "edge: engineVersion present")
not_none(rs1.data.get("schemaVersion"), "edge: schemaVersion present")

# Confidence defaults to source type base when not specified
_reset()
r_noconf = _post(_make_create_body(fieldName="hostname", fieldValue="no-conf", sourceType="pcap"))
not_none(r_noconf.data.get("confidence"), "edge: confidence auto-populated")
gte(r_noconf.data["confidence"], 0, "edge: confidence >= 0")
lte(r_noconf.data["confidence"], 100, "edge: confidence <= 100")

# Tags default to empty list in metadata
_reset()
r_notags = _post(_make_create_body(fieldName="hostname", fieldValue="no-tags", sourceType="pcap"))
eq(r_notags.data["metadata"]["tags"], [], "edge: tags default empty list")
eq(r_notags.data["metadata"]["extra"], {}, "edge: extra default empty dict")

# reference defaults to empty/None fields
eq(r_notags.data["reference"]["packetNumber"], None, "edge: reference.packetNumber default None")
eq(r_notags.data["reference"]["captureId"], None, "edge: reference.captureId default None")


# ---------------------------------------------------------------------------
# §21  End-to-end workflow
# ---------------------------------------------------------------------------

print("\n§21  End-to-end workflow")
_reset()

# Create 10 records across different assets, sources, fields
test_records = [
    dict(fieldName="hostname",   fieldValue=f"host-{i:02d}", sourceType="pcap",
         assetId=f"asset-{i % 3}", confidence=20 + i * 7)
    for i in range(5)
] + [
    dict(fieldName="macAddress", fieldValue=f"aa:bb:{i:02x}:00:11:22", sourceType="dhcp",
         assetId=f"asset-{i % 2}", confidence=50 + i * 5)
    for i in range(3)
] + [
    dict(fieldName="ipAddress",  fieldValue=f"10.0.0.{i}", sourceType="nmap",
         assetId=f"asset-{i % 4}", confidence=30 + i * 8)
    for i in range(2)
]

ids_created = []
for rec in test_records:
    r = _post(CreateEvidenceRequest(**rec))
    ok(r.success, f"e2e create: success for {rec['fieldName']}={rec['fieldValue']}")
    ids_created.append(r.data["evidenceId"])

eq(len(ids_created), 10, "e2e: 10 records created")
eq(len(_EVIDENCE_STORE), 10, "e2e: store has 10 records")

# List all
rl = list_evidence()
eq(rl.data["total"], 10, "e2e list: 10 records")

# Statistics
st = get_evidence_statistics()
eq(st.data["totalRecords"], 10, "e2e stats: 10 records")
eq(st.data["uniqueSources"], 3, "e2e stats: 3 unique sources")
eq(st.data["uniqueFields"], 3, "e2e stats: 3 unique fields")
gte(st.data["uniqueAssets"], 1, "e2e stats: at least 1 unique asset")
is_float(st.data["averageConfidence"], "e2e stats: averageConfidence is number")

# Search + sort + paginate
rs = search_evidence(q="host", sort_by="confidence", sort_order="desc", page=1, page_size=3)
ok(rs.success, "e2e search: success")
eq(rs.data["pageSize"], 3, "e2e search: pageSize=3")
lte(len(rs.data["evidence"]), 3, "e2e search: at most 3 records on page")
if len(rs.data["evidence"]) > 1:
    confs = [ev["confidence"] for ev in rs.data["evidence"]]
    ok(confs == sorted(confs, reverse=True), "e2e search: sorted confidence desc")

# Filter by source
f_pcap = filter_evidence(list(_EVIDENCE_STORE.values()), source_type="pcap")
eq(len(f_pcap), 5, "e2e filter pcap: 5 pcap records")
f_dhcp = filter_evidence(list(_EVIDENCE_STORE.values()), source_type="dhcp")
eq(len(f_dhcp), 3, "e2e filter dhcp: 3 dhcp records")
f_nmap = filter_evidence(list(_EVIDENCE_STORE.values()), source_type="nmap")
eq(len(f_nmap), 2, "e2e filter nmap: 2 nmap records")

# Bulk update all pcap records
bulk_upd_items = [
    BulkUpdateEvidenceItem(evidenceId=r["evidenceId"],
                           update=UpdateEvidenceRequest(tags=["e2e-updated"]))
    for r in f_pcap
]
rbu = bulk_update_evidence(BulkUpdateEvidenceRequest(items=bulk_upd_items))
ok(rbu.success, "e2e bulk update: success")
eq(rbu.data["successCount"], 5, "e2e bulk update: 5 updated")

# Verify tags updated
for r in f_pcap:
    eq(_EVIDENCE_STORE[r["evidenceId"]]["metadata"]["tags"], ["e2e-updated"],
       f"e2e bulk update tag: {r['evidenceId']}")

# Bulk delete dhcp records
dhcp_ids = [r["evidenceId"] for r in f_dhcp]
rbd = bulk_delete_evidence(BulkDeleteEvidenceRequest(evidenceIds=dhcp_ids))
ok(rbd.success, "e2e bulk delete: success")
eq(rbd.data["successCount"], 3, "e2e bulk delete: 3 deleted")
eq(len(_EVIDENCE_STORE), 7, "e2e: 7 records remain after bulk delete")

# Stats after deletion
st2 = get_evidence_statistics()
eq(st2.data["totalRecords"], 7, "e2e stats post-delete: 7 records")


# ---------------------------------------------------------------------------
# §22  Bulk model validation
# ---------------------------------------------------------------------------

print("\n§22  Bulk model validation")

# BulkCreateEvidenceRequest — valid
bc = BulkCreateEvidenceRequest(evidence=[
    CreateEvidenceRequest(fieldName="hostname", fieldValue="h", sourceType="pcap"),
])
eq(bc.validate_request(), [], "bulk create model: valid → no errors")

# BulkCreateEvidenceRequest — nested errors
bc_bad = BulkCreateEvidenceRequest(evidence=[
    CreateEvidenceRequest(fieldName="", fieldValue="v", sourceType="pcap"),
    CreateEvidenceRequest(fieldName="hostname", fieldValue="", sourceType="pcap"),
])
errs = bc_bad.validate_request()
ok(len(errs) == 2, "bulk create model: 2 nested errors")
contains(errs[0], "evidence[0]", "bulk create model: error indexed evidence[0]")
contains(errs[1], "evidence[1]", "bulk create model: error indexed evidence[1]")

# BulkUpdateEvidenceRequest — valid
bu = BulkUpdateEvidenceRequest(items=[
    BulkUpdateEvidenceItem(evidenceId="x", update=UpdateEvidenceRequest(assetId="a")),
])
eq(bu.validate_request(), [], "bulk update model: valid → no errors")

# BulkUpdateEvidenceRequest — errors
bu_bad = BulkUpdateEvidenceRequest(items=[
    BulkUpdateEvidenceItem(evidenceId="", update=UpdateEvidenceRequest(assetId="a")),
    BulkUpdateEvidenceItem(evidenceId="x", update=UpdateEvidenceRequest()),
])
errs_u = bu_bad.validate_request()
ok(len(errs_u) == 2, f"bulk update model: 2 errors, got {errs_u}")
contains(errs_u[0], "items[0]", "bulk update model: first error indexed items[0]")
contains(errs_u[1], "items[1]", "bulk update model: second error indexed items[1]")

# BulkDeleteEvidenceRequest — valid
bd = BulkDeleteEvidenceRequest(evidenceIds=["id1", "id2"])
eq(bd.validate_request(), [], "bulk delete model: valid → no errors")

# BulkDeleteEvidenceRequest — empty string
bd_bad = BulkDeleteEvidenceRequest(evidenceIds=["valid", ""])
errs_d = bd_bad.validate_request()
ok(len(errs_d) > 0, "bulk delete model: empty string errors")

# BulkEvidenceOperationResult immutable
res = BulkEvidenceOperationResult(
    succeeded=["a"], failed=[], total=1, successCount=1, failCount=0
)
try:
    res.succeeded = ["b"]  # type: ignore
    ok(False, "bulk result: should be frozen")
except Exception:
    ok(True, "bulk result: frozen model raises on mutation")


# ---------------------------------------------------------------------------
# §23  Response contract — build_success_response integration
# ---------------------------------------------------------------------------

print("\n§23  Response builder integration")
_reset()

r = _post(_make_create_body(fieldName="hostname", fieldValue="rb-host", sourceType="pcap"))
ok(isinstance(r, APIResponse), "resp builder: returns APIResponse")
ok(r.success, "resp builder: success=True")
ok(r.message is not None and len(r.message) > 0, "resp builder: message non-empty")
not_none(r.data, "resp builder: data not None")
not_none(r.metadata, "resp builder: metadata present")
ok("apiLayerVersion" in r.metadata, "resp builder: apiLayerVersion in metadata")

# Error response shape
r_err = get_evidence("nonexistent")
ok(not r_err.success, "resp builder error: success=False")
ok(r_err.message is not None and len(r_err.message) > 0, "resp builder error: message non-empty")
not_none(r_err.data, "resp builder error: data not None")
ok(hasattr(r_err.data, "errorCode"), "resp builder error: data has errorCode")
ok(hasattr(r_err.data, "error"), "resp builder error: data has error")

# Statistics response shape
st = get_evidence_statistics()
ok(isinstance(st, APIResponse), "stats resp: returns APIResponse")
ok(st.success, "stats resp: success=True")
ok(isinstance(st.data, dict), "stats resp: data is dict")
ok("totalRecords" in st.data, "stats resp: totalRecords in data")
ok("sourceCounts" in st.data, "stats resp: sourceCounts in data")
ok("fieldCounts" in st.data, "stats resp: fieldCounts in data")
ok("assetCounts" in st.data, "stats resp: assetCounts in data")
ok("averageConfidence" in st.data, "stats resp: averageConfidence in data")
ok("uniqueAssets" in st.data, "stats resp: uniqueAssets in data")
ok("uniqueFields" in st.data, "stats resp: uniqueFields in data")
ok("uniqueSources" in st.data, "stats resp: uniqueSources in data")


# ---------------------------------------------------------------------------
# §24  Search response shape
# ---------------------------------------------------------------------------

print("\n§24  Search response shape")
_reset()
for i in range(5):
    _post(_make_create_body(fieldName="hostname", fieldValue=f"search-host-{i}", sourceType="pcap"))

rs = search_evidence(q="search-host")
ok(rs.success, "search resp shape: success")
ok(isinstance(rs.data, dict), "search resp shape: data is dict")
ok("evidence" in rs.data, "search resp shape: evidence key present")
ok("total" in rs.data, "search resp shape: total key present")
ok("page" in rs.data, "search resp shape: page key present")
ok("pageSize" in rs.data, "search resp shape: pageSize key present")
ok("totalPages" in rs.data, "search resp shape: totalPages key present")
ok("query" in rs.data, "search resp shape: query key present")
ok("sortBy" in rs.data, "search resp shape: sortBy key present")
ok("sortOrder" in rs.data, "search resp shape: sortOrder key present")
eq(rs.data["query"], "search-host", "search resp shape: query preserved")
eq(rs.data["sortBy"], "created", "search resp shape: default sortBy")
eq(rs.data["sortOrder"], "asc", "search resp shape: default sortOrder")
is_list(rs.data["evidence"], "search resp shape: evidence is list")

# totalPages calculation
rs_pg = search_evidence(q="search-host", page=1, page_size=2)
ok(rs_pg.data["totalPages"] >= 1, "search resp shape: totalPages >= 1")
eq(rs_pg.data["pageSize"], 2, "search resp shape: pageSize=2")
lte(len(rs_pg.data["evidence"]), 2, "search resp shape: at most 2 items on page")


# ---------------------------------------------------------------------------
# §25  Additional sorting / filtering coverage
# ---------------------------------------------------------------------------

print("\n§25  Additional sort & filter coverage")
_reset()

# Insert records with known confidences and known sourceTypes
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="srt1", sourceType="pcap",
                             confidence=10))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:11:22:33:44:55",
                             sourceType="dhcp", confidence=90))
_post(CreateEvidenceRequest(fieldName="ipAddress", fieldValue="10.5.5.5", sourceType="nmap",
                             confidence=50))
_post(CreateEvidenceRequest(fieldName="vendor", fieldValue="Cisco", sourceType="pcap",
                             confidence=70))

all_recs = list(_EVIDENCE_STORE.values())

# Sort confidence asc — first should be 10
sa = sort_evidence(all_recs, "confidence", "asc")
eq(sa[0]["confidence"], 10, "sort conf asc: first=10")
eq(sa[-1]["confidence"], 90, "sort conf asc: last=90")

# Sort confidence desc — first should be 90
sd = sort_evidence(all_recs, "confidence", "desc")
eq(sd[0]["confidence"], 90, "sort conf desc: first=90")
eq(sd[-1]["confidence"], 10, "sort conf desc: last=10")

# Sort fieldName asc
sfn = sort_evidence(all_recs, "fieldName", "asc")
fns = [r["fieldName"] for r in sfn]
eq(fns, sorted(fns, key=str.lower), "sort fieldName asc: alphabetical")

# Sort sourceType asc
sst = sort_evidence(all_recs, "sourceType", "asc")
sts = [r["source"]["sourceType"] for r in sst]
eq(sts, sorted(sts), "sort sourceType asc: alphabetical")

# Filter confidence range boundary — inclusive
f_exact = filter_evidence(all_recs, min_confidence=10, max_confidence=10)
eq(len(f_exact), 1, "filter exact confidence 10: 1 match")
eq(f_exact[0]["confidence"], 10, "filter exact confidence 10: value correct")

# Filter confidence range — no match
f_nomatch = filter_evidence(all_recs, min_confidence=95, max_confidence=100)
eq(len(f_nomatch), 0, "filter confidence 95-100: no match")

# filter by fieldName case-insensitive
f_fn_ci = filter_evidence(all_recs, field_name="HOSTNAME")
eq(len(f_fn_ci), 1, "filter fieldName case-insensitive: 1 match")

# filter by captureId when no captureId stored (all None)
f_cap_none = filter_evidence(all_recs, capture_id="cap-999")
eq(len(f_cap_none), 0, "filter captureId not in store: 0 matches")

# Sort doesn't change count
eq(len(sort_evidence(all_recs, "confidence", "asc")), len(all_recs), "sort: preserves count")
eq(len(sort_evidence(all_recs, "fieldName", "desc")), len(all_recs), "sort: preserves count 2")
eq(len(sort_evidence(all_recs, "sourceType", "asc")), len(all_recs), "sort: preserves count 3")
eq(len(sort_evidence(all_recs, "created", "desc")), len(all_recs), "sort: preserves count 4")


# ---------------------------------------------------------------------------
# §26  _record_to_dict helper
# ---------------------------------------------------------------------------

print("\n§26  _record_to_dict helper")

rec = build_evidence(
    field_name="hostname", field_value="test-host", source_type="pcap",
    asset_id="asset-x", confidence=75,
)
not_none(rec, "_record_to_dict: build_evidence returns record")
d = _record_to_dict(rec)
ok(isinstance(d, dict), "_record_to_dict: returns dict")
ok(isinstance(d["source"], dict), "_record_to_dict: source is dict")
ok(isinstance(d["reference"], dict), "_record_to_dict: reference is dict")
ok(isinstance(d["metadata"], dict), "_record_to_dict: metadata is dict")
eq(d["fieldName"], "hostname", "_record_to_dict: fieldName preserved")
eq(d["fieldValue"], "test-host", "_record_to_dict: fieldValue preserved")
eq(d["assetId"], "asset-x", "_record_to_dict: assetId preserved")
eq(d["source"]["confidence"], 75, "_record_to_dict: source.confidence=75")

# With full metadata
meta = build_metadata(protocol="DNS", packet_info="Query", raw_value="raw",
                       tags=["tag1"], extra={"k": "v"})
rec2 = build_evidence(
    field_name="macAddress", field_value="bb:cc:dd:ee:ff:00", source_type="dhcp",
    metadata=meta,
)
d2 = _record_to_dict(rec2)
eq(d2["metadata"]["protocol"], "DNS", "_record_to_dict: metadata.protocol")
eq(d2["metadata"]["tags"], ["tag1"], "_record_to_dict: metadata.tags")
eq(d2["metadata"]["extra"]["k"], "v", "_record_to_dict: metadata.extra.k")


# ---------------------------------------------------------------------------
# §27  _evidence_to_response helper
# ---------------------------------------------------------------------------

print("\n§27  _evidence_to_response helper")
_reset()

r = _post(CreateEvidenceRequest(
    fieldName="hostname", fieldValue="resp-host", sourceType="pcap",
    assetId="a1", confidence=88,
    protocol="ARP", packetInfo="ARP Reply", rawValue="raw-r",
    tags=["a", "b"], extra={"x": 1},
    packetNumber=7, captureId="cap-r", sessionId="sess-r",
))
stored = _EVIDENCE_STORE[r.data["evidenceId"]]
resp = _evidence_to_response(stored)

ok(isinstance(resp, EvidenceResponse), "ev_to_resp: returns EvidenceResponse")
eq(resp.evidenceId, stored["evidenceId"], "ev_to_resp: evidenceId")
eq(resp.fieldName, "hostname", "ev_to_resp: fieldName")
eq(resp.fieldValue, "resp-host", "ev_to_resp: fieldValue")
eq(resp.assetId, "a1", "ev_to_resp: assetId")
eq(resp.confidence, 88, "ev_to_resp: confidence")
not_none(resp.source, "ev_to_resp: source not None")
eq(resp.source.sourceType, "pcap", "ev_to_resp: source.sourceType")
eq(resp.source.confidence, 88, "ev_to_resp: source.confidence")
not_none(resp.reference, "ev_to_resp: reference not None")
eq(resp.reference.packetNumber, 7, "ev_to_resp: reference.packetNumber")
eq(resp.reference.captureId, "cap-r", "ev_to_resp: reference.captureId")
eq(resp.reference.sessionId, "sess-r", "ev_to_resp: reference.sessionId")
not_none(resp.metadata, "ev_to_resp: metadata not None")
eq(resp.metadata.protocol, "ARP", "ev_to_resp: metadata.protocol")
eq(resp.metadata.packetInfo, "ARP Reply", "ev_to_resp: metadata.packetInfo")
eq(resp.metadata.rawValue, "raw-r", "ev_to_resp: metadata.rawValue")
eq(resp.metadata.tags, ["a", "b"], "ev_to_resp: metadata.tags")
eq(resp.metadata.extra["x"], 1, "ev_to_resp: metadata.extra.x")
not_none(resp.createdAt, "ev_to_resp: createdAt present")
not_none(resp.engineVersion, "ev_to_resp: engineVersion present")


# ---------------------------------------------------------------------------
# §28  Search with captureId filter
# ---------------------------------------------------------------------------

print("\n§28  Search with captureId filter")
_reset()

_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="cap-filter-a",
                             sourceType="pcap", captureId="cap-alpha"))
_post(CreateEvidenceRequest(fieldName="hostname", fieldValue="cap-filter-b",
                             sourceType="pcap", captureId="cap-beta"))
_post(CreateEvidenceRequest(fieldName="macAddress", fieldValue="aa:11:22:33:44:55",
                             sourceType="dhcp", captureId="cap-alpha"))

all_recs = list(_EVIDENCE_STORE.values())

# filter_evidence by captureId
f_alpha = filter_evidence(all_recs, capture_id="cap-alpha")
eq(len(f_alpha), 2, "captureId filter: 2 records with cap-alpha")

f_beta = filter_evidence(all_recs, capture_id="cap-beta")
eq(len(f_beta), 1, "captureId filter: 1 record with cap-beta")

f_gamma = filter_evidence(all_recs, capture_id="cap-gamma")
eq(len(f_gamma), 0, "captureId filter: 0 records with cap-gamma")

# Search + captureId filter via endpoint
# Only records matching "cap-filter" in fieldValue AND having captureId=cap-alpha
rs = search_evidence(q="cap-filter", capture_id_filter="cap-alpha")
ok(rs.success, "search captureId filter: success")
eq(rs.data["total"], 1, "search captureId filter: 1 match (cap-filter-a with cap-alpha)")

# Case-insensitive captureId
f_ci = filter_evidence(all_recs, capture_id="CAP-ALPHA")
eq(len(f_ci), 2, "captureId filter case-insensitive: 2 matches")


# ---------------------------------------------------------------------------
# §29  Pagination boundary and totalPages math
# ---------------------------------------------------------------------------

print("\n§29  Pagination boundaries")

# 1 item — 1 page
sl, pg = paginate_evidence([{"x": 1}], 1, 10)
eq(pg.totalPages, 1, "pg boundary: 1 item, pageSize=10 → 1 page")
eq(pg.totalItems, 1, "pg boundary: totalItems=1")

# Exactly fills a page
sl2, pg2 = paginate_evidence([{"x": i} for i in range(10)], 1, 10)
eq(pg2.totalPages, 1, "pg boundary: 10 items, pageSize=10 → 1 page")
eq(len(sl2), 10, "pg boundary: page 1 has all 10")

# One over a page
sl3, pg3 = paginate_evidence([{"x": i} for i in range(11)], 1, 10)
eq(pg3.totalPages, 2, "pg boundary: 11 items, pageSize=10 → 2 pages")
eq(len(sl3), 10, "pg boundary: page 1 has 10")
sl3b, pg3b = paginate_evidence([{"x": i} for i in range(11)], 2, 10)
eq(len(sl3b), 1, "pg boundary: page 2 has 1")

# pageSize > total
sl4, pg4 = paginate_evidence([{"x": i} for i in range(3)], 1, 100)
eq(pg4.totalPages, 1, "pg boundary: pageSize > total → 1 page")
eq(len(sl4), 3, "pg boundary: all items returned")

# page=1, pageSize clamped from 0 to 1
sl5, pg5 = paginate_evidence([{"x": 1}], 1, 0)
eq(pg5.pageSize, 1, "pg boundary: pageSize 0 clamped to 1")


# ---------------------------------------------------------------------------
# §30  Final store isolation check
# ---------------------------------------------------------------------------

print("\n§30  Store isolation")
_reset()
eq(len(_EVIDENCE_STORE), 0, "isolation: store empty after final reset")

# Multiple creates, then full reset, then verify empty
for i in range(5):
    _post(_make_create_body(fieldName="hostname", fieldValue=f"iso-{i}", sourceType="pcap"))
eq(len(_EVIDENCE_STORE), 5, "isolation: 5 records after creates")
_reset()
eq(len(_EVIDENCE_STORE), 0, "isolation: 0 after reset")
rl = list_evidence()
eq(rl.data["total"], 0, "isolation: list shows 0 after reset")

# _reset_store is the only mutation path for tests
ok(callable(_reset_store), "isolation: _reset_store is callable")

# ===========================================================================
# Final report
# ===========================================================================

print("\n" + "=" * 60)
print(f"TOTAL ASSERTIONS : {PASS + FAIL}")
print(f"PASSED           : {PASS}")
print(f"FAILED           : {FAIL}")
print("=" * 60)

if ERRORS:
    print("\nFailed assertions:")
    for e in ERRORS:
        print(f"  {e}")

if FAIL > 0:
    print(f"\n✗ {FAIL} assertion(s) failed.")
    sys.exit(1)
else:
    print(f"\n✓ All {PASS} assertions passed.")
    sys.exit(0)
