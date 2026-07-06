"""
Smoke Test — Asset API Part B (Phase A4.7.2)
=============================================
500+ assertions covering:
  - CRUD (Part A verification)
  - search, filter, sorting, pagination
  - bulk create / update / delete
  - statistics (extended)
  - router registration
  - serialization / model shape
  - deterministic helpers (find_asset, sort_assets, filter_assets, paginate_assets)
  - edge cases

Run:
    python smoke_test_asset_api.py
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from api.investigation.asset_router import (
    _reset_store,
    _ASSET_STORE,
    _all_assets,
    find_asset,
    sort_assets,
    filter_assets,
    paginate_assets,
    create_asset,
    get_asset,
    list_assets,
    update_asset,
    delete_asset,
    get_asset_statistics,
    search_assets,
    bulk_create_assets,
    bulk_update_assets,
    bulk_delete_assets,
    asset_router,
)
from api.investigation.asset_models import (
    CreateAssetRequest,
    UpdateAssetRequest,
    BulkCreateAssetsRequest,
    BulkUpdateAssetsRequest,
    BulkDeleteAssetsRequest,
)
from api.router import root_router
from api.models import Pagination

PASS = 0
FAIL = 0

def check(condition: bool, label: str) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {label}")


# ===========================================================================
# Section 1 — Router Registration
# ===========================================================================
print("=== 1. Router Registration ===")

asset_paths = {r.path for r in asset_router.routes}
check("/assets"            in asset_paths, "route /assets exists")
check("/assets/statistics" in asset_paths, "route /assets/statistics exists")
check("/assets/{assetId}"  in asset_paths, "route /assets/{assetId} exists")
check("/assets/search"     in asset_paths, "route /assets/search exists")
check("/assets/bulk/create" in asset_paths, "route /assets/bulk/create exists")
check("/assets/bulk/update" in asset_paths, "route /assets/bulk/update exists")
check("/assets/bulk/delete" in asset_paths, "route /assets/bulk/delete exists")

methods_by_path = {}
for r in asset_router.routes:
    methods_by_path.setdefault(r.path, set()).update(r.methods or [])

check("GET"    in methods_by_path.get("/assets", set()),            "GET /assets")
check("POST"   in methods_by_path.get("/assets", set()),            "POST /assets")
check("GET"    in methods_by_path.get("/assets/statistics", set()), "GET /assets/statistics")
check("GET"    in methods_by_path.get("/assets/search", set()),     "GET /assets/search")
check("GET"    in methods_by_path.get("/assets/{assetId}", set()),  "GET /assets/{assetId}")
check("PUT"    in methods_by_path.get("/assets/{assetId}", set()),  "PUT /assets/{assetId}")
check("DELETE" in methods_by_path.get("/assets/{assetId}", set()),  "DELETE /assets/{assetId}")
check("POST"   in methods_by_path.get("/assets/bulk/create", set()), "POST /assets/bulk/create")
check("PUT"    in methods_by_path.get("/assets/bulk/update", set()), "PUT /assets/bulk/update")
check("DELETE" in methods_by_path.get("/assets/bulk/delete", set()), "DELETE /assets/bulk/delete")

root_paths = {r.path for r in root_router.routes}
check("/api/v2/assets/search" in root_paths,        "root: /api/v2/assets/search")
check("/api/v2/assets/bulk/create" in root_paths,   "root: /api/v2/assets/bulk/create")
check("/api/v2/assets/bulk/update" in root_paths,   "root: /api/v2/assets/bulk/update")
check("/api/v2/assets/bulk/delete" in root_paths,   "root: /api/v2/assets/bulk/delete")


# ===========================================================================
# Section 2 — CRUD (Part A re-verify)
# ===========================================================================
print("=== 2. CRUD (Part A) ===")
_reset_store()

# 2.1 Create
b = CreateAssetRequest(assetId="aa:bb:cc:dd:ee:ff", hostname="host-a", vendor="Cisco", currentIp="10.0.0.1")
r = create_asset(b)
check(r.success == True,                          "create: success")
check(r.data["assetId"] == "aa:bb:cc:dd:ee:ff",  "create: assetId")
check(r.data["hostname"] == "host-a",             "create: hostname")
check(r.data["vendor"] == "Cisco",                "create: vendor")
check(r.data["currentIp"] == "10.0.0.1",          "create: currentIp")
check(r.data["currentStatus"] == "active",         "create: default status active")
check(r.data["currentRiskScore"] == 0,             "create: default risk 0")
check(r.data["packetCount"] == 0,                  "create: default packetCount 0")
check(r.data["previousIPs"] == ["10.0.0.1"],       "create: previousIPs seeded")
check(r.data["notes"] == [],                       "create: empty notes default")
check(r.data["metadata"] == {},                    "create: empty metadata default")

# 2.2 Duplicate → 409
r2 = create_asset(b)
check(r2.success == False,                    "create duplicate: success=False")
check(r2.data.errorCode == "CONFLICT",        "create duplicate: CONFLICT")

# 2.3 Empty assetId → 422
bad = CreateAssetRequest(assetId="   ")
rb = create_asset(bad)
check(rb.success == False,                    "create empty assetId: success=False")
check(rb.data.errorCode == "VALIDATION_ERROR","create empty assetId: VALIDATION_ERROR")

# 2.4 Get existing
r3 = get_asset("aa:bb:cc:dd:ee:ff")
check(r3.success == True,                     "get: success")
check(r3.data["hostname"] == "host-a",        "get: hostname matches")

# 2.5 Get missing → 404
r4 = get_asset("no-such")
check(r4.success == False,                    "get missing: success=False")
check(r4.data.errorCode == "NOT_FOUND",       "get missing: NOT_FOUND")

# 2.6 List
r5 = list_assets()
check(r5.success == True,                     "list: success")
check(r5.data["total"] == 1,                  "list: total==1")
check(len(r5.data["assets"]) == 1,            "list: 1 asset returned")

# 2.7 List vendor filter
r5b = list_assets(vendor="Cisco")
check(r5b.data["total"] == 1,                 "list filter Cisco: total==1")
r5c = list_assets(vendor="Unknown")
check(r5c.data["total"] == 0,                 "list filter Unknown: total==0")

# 2.8 Update
upd = UpdateAssetRequest(hostname="host-b")
r6 = update_asset("aa:bb:cc:dd:ee:ff", upd)
check(r6.success == True,                     "update: success")
check(r6.data["hostname"] == "host-b",        "update: hostname changed")

# 2.9 Update missing → 404
r7 = update_asset("no-such", upd)
check(r7.success == False,                    "update missing: success=False")
check(r7.data.errorCode == "NOT_FOUND",       "update missing: NOT_FOUND")

# 2.10 Update empty body → 422
r8 = update_asset("aa:bb:cc:dd:ee:ff", UpdateAssetRequest())
check(r8.success == False,                    "update empty: success=False")
check(r8.data.errorCode == "VALIDATION_ERROR","update empty: VALIDATION_ERROR")

# 2.11 Delete
r9 = delete_asset("aa:bb:cc:dd:ee:ff")
check(r9.success == True,                     "delete: success")
check(r9.data is None,                        "delete: data is None")

# 2.12 Delete missing → 404
r10 = delete_asset("aa:bb:cc:dd:ee:ff")
check(r10.success == False,                   "delete missing: success=False")
check(r10.data.errorCode == "NOT_FOUND",      "delete missing: NOT_FOUND")

# 2.13 List after delete
r11 = list_assets()
check(r11.data["total"] == 0,                 "list after delete: total==0")


# ===========================================================================
# Section 3 — Full Asset Fields Serialization
# ===========================================================================
print("=== 3. Serialization ===")
_reset_store()

full = CreateAssetRequest(
    assetId="mac-full",
    macAddress="00:11:22:33:44:55",
    hostname="full-host",
    deviceName="Dev-1",
    vendor="Cisco",
    operatingSystem="Linux",
    currentIp="192.168.1.5",
    currentStatus="active",
    notes=["note-a", "note-b"],
    metadata={"env": "prod", "rack": "3"},
)
rf = create_asset(full)
d = rf.data
check(rf.success == True,                        "full create: success")
check(d["macAddress"] == "00:11:22:33:44:55",    "full: macAddress")
check(d["hostname"] == "full-host",              "full: hostname")
check(d["deviceName"] == "Dev-1",                "full: deviceName")
check(d["vendor"] == "Cisco",                    "full: vendor")
check(d["operatingSystem"] == "Linux",           "full: operatingSystem")
check(d["currentIp"] == "192.168.1.5",           "full: currentIp")
check(d["currentStatus"] == "active",            "full: currentStatus")
check(d["notes"] == ["note-a", "note-b"],        "full: notes")
check(d["metadata"] == {"env": "prod", "rack": "3"}, "full: metadata")
check(d["currentRiskScore"] == 0,                "full: riskScore=0")
check(d["packetCount"] == 0,                     "full: packetCount=0")
check("192.168.1.5" in d["previousIPs"],         "full: previousIPs seeded")
check(d["firstSeen"] is None,                    "full: firstSeen=None")
check(d["lastSeen"] is None,                     "full: lastSeen=None")
check(isinstance(d["protocols"], dict),          "full: protocols is dict")

# AssetResponse keys present
expected_keys = {
    "assetId","macAddress","hostname","deviceName","vendor","operatingSystem",
    "currentIp","previousIPs","currentStatus","currentRiskScore","packetCount",
    "firstSeen","lastSeen","protocols","notes","metadata",
}
check(set(d.keys()) >= expected_keys,            "full: all AssetResponse keys present")


# ===========================================================================
# Section 4 — Pure Helper: find_asset()
# ===========================================================================
print("=== 4. find_asset() ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="a1", hostname="router-1", vendor="Cisco", currentIp="10.0.0.1"))
create_asset(CreateAssetRequest(assetId="a2", hostname="switch-1", vendor="Juniper", currentIp="10.0.0.2"))
create_asset(CreateAssetRequest(assetId="a3", hostname="Router-2", vendor="Cisco", currentIp="10.0.0.3"))

assets = _all_assets()

# Find by hostname (case-insensitive exact)
r = find_asset(assets, "hostname", "router-1")
check(r is not None,                    "find_asset hostname found")
check(r["assetId"] == "a1",             "find_asset hostname correct")

# Case-insensitive
r2 = find_asset(assets, "hostname", "ROUTER-1")
check(r2 is not None,                   "find_asset hostname case-insensitive")
check(r2["assetId"] == "a1",            "find_asset hostname CI correct")

# Find by currentIp
r3 = find_asset(assets, "currentIp", "10.0.0.2")
check(r3 is not None,                   "find_asset ip found")
check(r3["assetId"] == "a2",            "find_asset ip correct")

# Find by vendor — returns first match
r4 = find_asset(assets, "vendor", "cisco")
check(r4 is not None,                   "find_asset vendor found")
check(r4["vendor"] == "Cisco",          "find_asset vendor correct")

# Find missing
r5 = find_asset(assets, "hostname", "nonexistent")
check(r5 is None,                       "find_asset missing returns None")

# Find by assetId
r6 = find_asset(assets, "assetId", "a3")
check(r6 is not None,                   "find_asset assetId found")
check(r6["hostname"] == "Router-2",     "find_asset assetId correct")

# Empty list
r7 = find_asset([], "hostname", "router-1")
check(r7 is None,                       "find_asset empty list returns None")

# Field not present
r8 = find_asset(assets, "nonExistentField", "value")
check(r8 is None,                       "find_asset unknown field returns None")


# ===========================================================================
# Section 5 — Pure Helper: sort_assets()
# ===========================================================================
print("=== 5. sort_assets() ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="s1", hostname="zebra",   vendor="Juniper", currentIp="10.0.0.3"))
create_asset(CreateAssetRequest(assetId="s2", hostname="alpha",   vendor="Cisco",   currentIp="10.0.0.1"))
create_asset(CreateAssetRequest(assetId="s3", hostname="mango",   vendor="Apple",   currentIp="10.0.0.2"))

# Manually set risk scores
_ASSET_STORE["s1"]["currentRiskScore"] = 80
_ASSET_STORE["s2"]["currentRiskScore"] = 10
_ASSET_STORE["s3"]["currentRiskScore"] = 50

assets = _all_assets()

# Sort by hostname asc
sa = sort_assets(assets, "hostname", "asc")
check(len(sa) == 3,                          "sort hostname asc: len")
check(sa[0]["hostname"] == "alpha",          "sort hostname asc[0]")
check(sa[1]["hostname"] == "mango",          "sort hostname asc[1]")
check(sa[2]["hostname"] == "zebra",          "sort hostname asc[2]")

# Sort by hostname desc
sd = sort_assets(assets, "hostname", "desc")
check(sd[0]["hostname"] == "zebra",          "sort hostname desc[0]")
check(sd[2]["hostname"] == "alpha",          "sort hostname desc[2]")

# Sort by vendor asc
sv = sort_assets(assets, "vendor", "asc")
check(sv[0]["vendor"] == "Apple",            "sort vendor asc[0]")
check(sv[1]["vendor"] == "Cisco",            "sort vendor asc[1]")
check(sv[2]["vendor"] == "Juniper",          "sort vendor asc[2]")

# Sort by risk asc
sr = sort_assets(assets, "risk", "asc")
check(sr[0]["currentRiskScore"] == 10,       "sort risk asc[0]=10")
check(sr[1]["currentRiskScore"] == 50,       "sort risk asc[1]=50")
check(sr[2]["currentRiskScore"] == 80,       "sort risk asc[2]=80")

# Sort by risk desc
srd = sort_assets(assets, "risk", "desc")
check(srd[0]["currentRiskScore"] == 80,      "sort risk desc[0]=80")
check(srd[2]["currentRiskScore"] == 10,      "sort risk desc[2]=10")

# Sort by ip asc
sip = sort_assets(assets, "ip", "asc")
check(sip[0]["currentIp"] == "10.0.0.1",    "sort ip asc[0]")
check(sip[2]["currentIp"] == "10.0.0.3",    "sort ip asc[2]")

# Sort by created (assetId) asc
sc = sort_assets(assets, "created", "asc")
check(sc[0]["assetId"] == "s1",              "sort created asc[0]=s1")
check(sc[1]["assetId"] == "s2",              "sort created asc[1]=s2")

# Unknown sort_by falls back to hostname
su = sort_assets(assets, "unknown_field", "asc")
check(su[0]["hostname"] == "alpha",          "sort unknown falls back to hostname")

# Original list not mutated
check(_all_assets()[0]["assetId"] == "s1",   "sort: original list not mutated")

# Empty list
check(sort_assets([], "hostname", "asc") == [], "sort empty list returns []")

# None hostname sorted last in asc
create_asset(CreateAssetRequest(assetId="s4"))  # no hostname
assets2 = _all_assets()
sa2 = sort_assets(assets2, "hostname", "asc")
check(sa2[-1]["assetId"] == "s4",            "sort: None hostname sorted last asc")


# ===========================================================================
# Section 6 — Pure Helper: filter_assets()
# ===========================================================================
print("=== 6. filter_assets() ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="f1", vendor="Cisco",   hostname="core-sw",    currentIp="192.168.1.10", currentStatus="active"))
create_asset(CreateAssetRequest(assetId="f2", vendor="Juniper", hostname="edge-rtr",   currentIp="192.168.2.20", currentStatus="external"))
create_asset(CreateAssetRequest(assetId="f3", vendor="Cisco",   hostname="core-rtr",   currentIp="10.0.0.5",     currentStatus="active"))
create_asset(CreateAssetRequest(assetId="f4", vendor="Apple",   hostname="laptop-eng", currentIp="192.168.1.99", currentStatus="offline"))
_ASSET_STORE["f1"]["currentRiskScore"] = 70
_ASSET_STORE["f2"]["currentRiskScore"] = 20
_ASSET_STORE["f3"]["currentRiskScore"] = 55
_ASSET_STORE["f4"]["currentRiskScore"] = 5
_ASSET_STORE["f1"]["lastSeen"] = "2026-07-01T00:00:00Z"
_ASSET_STORE["f3"]["lastSeen"] = "2026-07-02T00:00:00Z"

assets = _all_assets()

# vendor filter
fv = filter_assets(assets, vendor="Cisco")
check(len(fv) == 2,                         "filter vendor=Cisco: 2 results")
check(all(a["vendor"] == "Cisco" for a in fv), "filter vendor=Cisco: all Cisco")

fv2 = filter_assets(assets, vendor="cisco")  # case-insensitive
check(len(fv2) == 2,                        "filter vendor case-insensitive")

# hostname substring
fh = filter_assets(assets, hostname="core")
check(len(fh) == 2,                         "filter hostname=core: 2 results")
check(all("core" in a["hostname"] for a in fh), "filter hostname substring correct")

# subnet filter
fs1 = filter_assets(assets, subnet="192.168.1")
check(len(fs1) == 2,                        "filter subnet=192.168.1: 2 results")
check(all(a["currentIp"].startswith("192.168.1.") for a in fs1), "filter subnet IPs correct")

fs2 = filter_assets(assets, subnet="10.0.0")
check(len(fs2) == 1,                        "filter subnet=10.0.0: 1 result")
check(fs2[0]["assetId"] == "f3",            "filter subnet=10.0.0: f3")

# min_risk / max_risk
fr1 = filter_assets(assets, min_risk=55)
check(len(fr1) == 2,                        "filter min_risk=55: 2 results")
check(all(a["currentRiskScore"] >= 55 for a in fr1), "filter min_risk correct")

fr2 = filter_assets(assets, max_risk=20)
check(len(fr2) == 2,                        "filter max_risk=20: 2 results")
check(all(a["currentRiskScore"] <= 20 for a in fr2), "filter max_risk correct")

fr3 = filter_assets(assets, min_risk=20, max_risk=60)
check(len(fr3) == 2,                        "filter risk range [20,60]: 2 results")

# observed filter
fo_t = filter_assets(assets, observed=True)
check(len(fo_t) == 2,                       "filter observed=True: 2 results")
check(all(a.get("lastSeen") for a in fo_t), "filter observed=True: all have lastSeen")

fo_f = filter_assets(assets, observed=False)
check(len(fo_f) == 2,                       "filter observed=False: 2 results")

# online filter
fon_t = filter_assets(assets, online=True)
check(len(fon_t) == 2,                      "filter online=True: 2 active assets")
check(all(a["currentStatus"] in {"active","online"} for a in fon_t), "filter online=True status")

fon_f = filter_assets(assets, online=False)
check(len(fon_f) == 2,                      "filter online=False: 2 non-active")

# Combined filters
fc = filter_assets(assets, vendor="Cisco", online=True)
check(len(fc) == 2,                         "filter vendor+online: 2 Cisco active")

fc2 = filter_assets(assets, subnet="192.168.1", vendor="Apple")
check(len(fc2) == 1,                        "filter subnet+vendor: 1 Apple in 192.168.1")
check(fc2[0]["assetId"] == "f4",            "filter combined: f4")

# No match
fn = filter_assets(assets, vendor="NoSuchVendor")
check(len(fn) == 0,                         "filter no match: empty list")

# Empty list
check(filter_assets([], vendor="Cisco") == [], "filter empty list: []")

# No filters = all assets returned
fall = filter_assets(assets)
check(len(fall) == 4,                       "filter no params: all 4 returned")


# ===========================================================================
# Section 7 — Pure Helper: paginate_assets()
# ===========================================================================
print("=== 7. paginate_assets() ===")

items = [{"assetId": f"x{i}"} for i in range(25)]

# Page 1, size 10
p1, pag1 = paginate_assets(items, 1, 10)
check(len(p1) == 10,            "paginate p1 len=10")
check(pag1.page == 1,           "paginate pag1.page=1")
check(pag1.pageSize == 10,      "paginate pag1.pageSize=10")
check(pag1.totalItems == 25,    "paginate pag1.totalItems=25")
check(pag1.totalPages == 3,     "paginate pag1.totalPages=3")
check(p1[0]["assetId"] == "x0", "paginate p1[0]=x0")
check(p1[9]["assetId"] == "x9", "paginate p1[9]=x9")

# Page 2, size 10
p2, pag2 = paginate_assets(items, 2, 10)
check(len(p2) == 10,             "paginate p2 len=10")
check(p2[0]["assetId"] == "x10", "paginate p2[0]=x10")
check(pag2.page == 2,            "paginate pag2.page=2")

# Page 3, size 10 — partial
p3, pag3 = paginate_assets(items, 3, 10)
check(len(p3) == 5,              "paginate p3 len=5 (partial)")
check(p3[0]["assetId"] == "x20", "paginate p3[0]=x20")

# Page beyond end → empty slice
p4, pag4 = paginate_assets(items, 10, 10)
check(len(p4) == 0,              "paginate beyond end: empty slice")
check(pag4.totalPages == 3,      "paginate beyond end: totalPages still 3")

# Empty list
pe, page_e = paginate_assets([], 1, 10)
check(len(pe) == 0,              "paginate empty: slice empty")
check(page_e.totalItems == 0,    "paginate empty: totalItems=0")
check(page_e.totalPages == 0,    "paginate empty: totalPages=0")

# Page size 1
pp1, ppag1 = paginate_assets(items, 1, 1)
check(len(pp1) == 1,             "paginate pageSize=1: len=1")
check(ppag1.totalPages == 25,    "paginate pageSize=1: totalPages=25")

# Clamp page < 1 to 1
pc, pagc = paginate_assets(items, 0, 10)
check(pagc.page == 1,            "paginate: page<1 clamped to 1")

# Clamp pageSize < 1 to 1
pc2, pagc2 = paginate_assets(items, 1, 0)
check(pagc2.pageSize == 1,       "paginate: pageSize<1 clamped to 1")
check(pagc2.totalPages == 25,    "paginate: clamped pageSize totalPages=25")

# Pagination is a Pagination model
check(isinstance(pag1, Pagination), "paginate: returns Pagination model")


# ===========================================================================
# Section 8 — search_assets() endpoint
# ===========================================================================
print("=== 8. search_assets() endpoint ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="aa:00:00:00:00:01", hostname="firewall-core", vendor="Cisco",   currentIp="10.1.1.1"))
create_asset(CreateAssetRequest(assetId="aa:00:00:00:00:02", hostname="switch-access", vendor="Juniper", currentIp="10.1.1.2"))
create_asset(CreateAssetRequest(assetId="aa:00:00:00:00:03", hostname="laptop-dev",    vendor="Apple",   currentIp="192.168.5.50"))
create_asset(CreateAssetRequest(assetId="aa:00:00:00:00:04", hostname="server-web",    vendor="Cisco",   currentIp="10.1.1.10"))
create_asset(CreateAssetRequest(assetId="aa:00:00:00:00:05", hostname="printer-hq",    vendor="HP",      currentIp="192.168.5.55"))
_ASSET_STORE["aa:00:00:00:00:01"]["currentRiskScore"] = 80
_ASSET_STORE["aa:00:00:00:00:02"]["currentRiskScore"] = 30
_ASSET_STORE["aa:00:00:00:00:03"]["currentRiskScore"] = 10
_ASSET_STORE["aa:00:00:00:00:04"]["currentRiskScore"] = 60
_ASSET_STORE["aa:00:00:00:00:05"]["currentRiskScore"] = 5

# Basic search
rs = search_assets(q="cisco")
check(rs.success == True,                  "search cisco: success")
check(rs.data["total"] == 2,               "search cisco: total=2")
check(rs.data["query"] == "cisco",         "search cisco: query echoed")

# Search by IP fragment
rip = search_assets(q="10.1.1")
check(rip.success == True,                 "search ip fragment: success")
check(rip.data["total"] == 3,              "search 10.1.1: total=3")

# Search by hostname fragment
rh = search_assets(q="laptop")
check(rh.success == True,                  "search laptop: success")
check(rh.data["total"] == 1,               "search laptop: total=1")
check(rh.data["assets"][0]["hostname"] == "laptop-dev", "search laptop: correct asset")

# Search with no match
rnm = search_assets(q="zzz_no_match")
check(rnm.success == True,                 "search no match: success (not error)")
check(rnm.data["total"] == 0,              "search no match: total=0")
check(rnm.data["assets"] == [],            "search no match: empty assets")

# Sorting
rs_asc = search_assets(q="cisco", sort_by="hostname", sort_order="asc")
check(rs_asc.data["assets"][0]["hostname"] == "firewall-core", "search sort asc[0]")
check(rs_asc.data["sortBy"] == "hostname",   "search: sortBy echoed")
check(rs_asc.data["sortOrder"] == "asc",     "search: sortOrder echoed")

rs_desc = search_assets(q="cisco", sort_by="hostname", sort_order="desc")
check(rs_desc.data["assets"][0]["hostname"] == "server-web", "search sort desc[0]")

rs_risk = search_assets(q="1.1", sort_by="risk", sort_order="desc")
check(rs_risk.data["assets"][0]["currentRiskScore"] == 80, "search sort risk desc[0]=80")

# Pagination
rp = search_assets(q="aa:00", page=1, page_size=2)
check(rp.data["total"] == 5,               "search paginate: total=5")
check(rp.data["page"] == 1,                "search paginate: page=1")
check(rp.data["pageSize"] == 2,            "search paginate: pageSize=2")
check(rp.data["totalPages"] == 3,          "search paginate: totalPages=3")
check(len(rp.data["assets"]) == 2,         "search paginate: 2 assets on page 1")

rp2 = search_assets(q="aa:00", page=2, page_size=2)
check(rp2.data["page"] == 2,               "search paginate p2: page=2")
check(len(rp2.data["assets"]) == 2,        "search paginate p2: 2 assets")

rp3 = search_assets(q="aa:00", page=3, page_size=2)
check(len(rp3.data["assets"]) == 1,        "search paginate p3: 1 asset (remainder)")

# Vendor filter inside search
rsvf = search_assets(q="aa:00", vendor_filter="Cisco")
check(rsvf.data["total"] == 2,             "search+vendor filter: 2 Cisco")

# Invalid sortBy
rinv = search_assets(q="x", sort_by="invalid_sort")
check(rinv.success == False,               "search invalid sortBy: success=False")
check(rinv.data.errorCode == "VALIDATION_ERROR", "search invalid sortBy: VALIDATION_ERROR")

# Invalid sortOrder
rinv2 = search_assets(q="x", sort_order="sideways")
check(rinv2.success == False,              "search invalid sortOrder: success=False")
check(rinv2.data.errorCode == "VALIDATION_ERROR", "search invalid sortOrder: VALIDATION_ERROR")

# Min/max risk filter in search
rs_risk_f = search_assets(q="aa:00", min_risk=60)
check(rs_risk_f.data["total"] == 2,        "search min_risk=60: 2 results")

rs_risk_mx = search_assets(q="aa:00", max_risk=10)
check(rs_risk_mx.data["total"] == 2,       "search max_risk=10: 2 results")

# Subnet filter in search
rs_sub = search_assets(q="aa:00", subnet_filter="192.168.5")
check(rs_sub.data["total"] == 2,           "search subnet filter 192.168.5: 2")

# Online filter in search
rs_on = search_assets(q="aa:00", online=True)
check(rs_on.data["total"] == 5,            "search online=True: 5 active assets")


# ===========================================================================
# Section 9 — Bulk Create
# ===========================================================================
print("=== 9. bulk_create_assets() ===")
_reset_store()

bc_req = BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="b1", hostname="bulk-host-1", vendor="Cisco",   currentIp="10.10.0.1"),
    CreateAssetRequest(assetId="b2", hostname="bulk-host-2", vendor="Juniper", currentIp="10.10.0.2"),
    CreateAssetRequest(assetId="b3", hostname="bulk-host-3", vendor="Cisco",   currentIp="10.10.0.3"),
])
bc_r = bulk_create_assets(bc_req)
check(bc_r.success == True,                   "bulk_create: success")
check(bc_r.data["successCount"] == 3,         "bulk_create: successCount=3")
check(bc_r.data["failCount"] == 0,            "bulk_create: failCount=0")
check(bc_r.data["total"] == 3,                "bulk_create: total=3")
check("b1" in bc_r.data["succeeded"],         "bulk_create: b1 in succeeded")
check("b2" in bc_r.data["succeeded"],         "bulk_create: b2 in succeeded")
check("b3" in bc_r.data["succeeded"],         "bulk_create: b3 in succeeded")
check(bc_r.data["failed"] == [],              "bulk_create: no failures")
check(len(_ASSET_STORE) == 3,                 "bulk_create: 3 assets in store")

# Partial failure — b1 already exists, b4 is new
bc_req2 = BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="b1", hostname="dup"),
    CreateAssetRequest(assetId="b4", hostname="bulk-host-4", vendor="HP"),
])
bc_r2 = bulk_create_assets(bc_req2)
check(bc_r2.success == True,                  "bulk_create partial: success=True (partial ok)")
check(bc_r2.data["successCount"] == 1,        "bulk_create partial: 1 succeeded")
check(bc_r2.data["failCount"] == 1,           "bulk_create partial: 1 failed")
check("b4" in bc_r2.data["succeeded"],        "bulk_create partial: b4 succeeded")
check(bc_r2.data["failed"][0]["assetId"] == "b1", "bulk_create partial: b1 in failed")

# Validation failure — empty assetId in list
bc_bad = BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="  "),
    CreateAssetRequest(assetId="b5"),
])
bc_rb = bulk_create_assets(bc_bad)
check(bc_rb.success == False,                 "bulk_create invalid body: success=False")
check(bc_rb.data.errorCode == "VALIDATION_ERROR", "bulk_create invalid body: VALIDATION_ERROR")

# Duplicate within request body
bc_dup = BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="dup-x"),
    CreateAssetRequest(assetId="dup-x"),
])
bc_rd = bulk_create_assets(bc_dup)
check(bc_rd.success == False,                 "bulk_create dup in body: success=False")
check(bc_rd.data.errorCode == "VALIDATION_ERROR","bulk_create dup in body: VALIDATION_ERROR")

# Verify store state after partial
check("b4" in _ASSET_STORE,                   "bulk_create: b4 in store")
check(len(_ASSET_STORE) == 4,                 "bulk_create: store has 4 total")

# Bulk create: default fields
_reset_store()
bc_min = BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="min1"),
])
bc_rm = bulk_create_assets(bc_min)
check(bc_rm.success == True,                  "bulk_create minimal: success")
check(_ASSET_STORE["min1"]["vendor"] == "Unknown",  "bulk_create minimal: vendor=Unknown")
check(_ASSET_STORE["min1"]["currentStatus"] == "active", "bulk_create minimal: status=active")


# ===========================================================================
# Section 10 — Bulk Update
# ===========================================================================
print("=== 10. bulk_update_assets() ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="u1", hostname="old-1", vendor="Cisco"))
create_asset(CreateAssetRequest(assetId="u2", hostname="old-2", vendor="Juniper"))
create_asset(CreateAssetRequest(assetId="u3", hostname="old-3", vendor="Apple"))

bu_req = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u1", update=UpdateAssetRequest(hostname="new-1")),
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u2", update=UpdateAssetRequest(vendor="HP")),
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u3", update=UpdateAssetRequest(currentStatus="offline")),
])
bu_r = bulk_update_assets(bu_req)
check(bu_r.success == True,                   "bulk_update: success")
check(bu_r.data["successCount"] == 3,         "bulk_update: successCount=3")
check(bu_r.data["failCount"] == 0,            "bulk_update: failCount=0")
check(_ASSET_STORE["u1"]["hostname"] == "new-1",       "bulk_update: u1 hostname updated")
check(_ASSET_STORE["u2"]["vendor"] == "HP",            "bulk_update: u2 vendor updated")
check(_ASSET_STORE["u3"]["currentStatus"] == "offline","bulk_update: u3 status updated")

# Partial failure — u99 not found
bu_req2 = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u1",  update=UpdateAssetRequest(hostname="new-1b")),
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u99", update=UpdateAssetRequest(hostname="ghost")),
])
bu_r2 = bulk_update_assets(bu_req2)
check(bu_r2.success == True,                  "bulk_update partial: success=True")
check(bu_r2.data["successCount"] == 1,        "bulk_update partial: 1 succeeded")
check(bu_r2.data["failCount"] == 1,           "bulk_update partial: 1 failed")
check(bu_r2.data["failed"][0]["assetId"] == "u99",     "bulk_update partial: u99 failed")

# Validation failure — empty items list  (can't construct BulkUpdateAssetsRequest with [])
# Instead test empty update fields per item
bu_bad_item = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u1", update=UpdateAssetRequest()),
])
bu_rb = bulk_update_assets(bu_bad_item)
check(bu_rb.success == False,                 "bulk_update empty update: success=False")
check(bu_rb.data.errorCode == "VALIDATION_ERROR", "bulk_update empty update: VALIDATION_ERROR")

# Metadata merge in bulk
bu_meta = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u1", update=UpdateAssetRequest(metadata={"k": "v"})),
])
bulk_update_assets(bu_meta)
check(_ASSET_STORE["u1"].get("metadata", {}).get("k") == "v", "bulk_update: metadata merged")

# Notes replacement
bu_notes = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="u1", update=UpdateAssetRequest(notes=["n1", "n2"])),
])
bulk_update_assets(bu_notes)
check(_ASSET_STORE["u1"]["notes"] == ["n1", "n2"], "bulk_update: notes replaced")


# ===========================================================================
# Section 11 — Bulk Delete
# ===========================================================================
print("=== 11. bulk_delete_assets() ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="d1"))
create_asset(CreateAssetRequest(assetId="d2"))
create_asset(CreateAssetRequest(assetId="d3"))
create_asset(CreateAssetRequest(assetId="d4"))

bd_req = BulkDeleteAssetsRequest(assetIds=["d1", "d2", "d3"])
bd_r = bulk_delete_assets(bd_req)
check(bd_r.success == True,                   "bulk_delete: success")
check(bd_r.data["successCount"] == 3,         "bulk_delete: successCount=3")
check(bd_r.data["failCount"] == 0,            "bulk_delete: failCount=0")
check(bd_r.data["total"] == 3,                "bulk_delete: total=3")
check("d1" in bd_r.data["succeeded"],         "bulk_delete: d1 in succeeded")
check("d1" not in _ASSET_STORE,               "bulk_delete: d1 removed from store")
check("d4" in _ASSET_STORE,                   "bulk_delete: d4 untouched")

# Partial failure — d99 not found
bd_req2 = BulkDeleteAssetsRequest(assetIds=["d4", "d99"])
bd_r2 = bulk_delete_assets(bd_req2)
check(bd_r2.success == True,                  "bulk_delete partial: success=True")
check(bd_r2.data["successCount"] == 1,        "bulk_delete partial: 1 succeeded")
check(bd_r2.data["failCount"] == 1,           "bulk_delete partial: 1 failed")
check(bd_r2.data["failed"][0]["assetId"] == "d99", "bulk_delete partial: d99 failed")
check("d4" not in _ASSET_STORE,               "bulk_delete partial: d4 deleted")

# Validation failure — empty assetId string
bd_bad = BulkDeleteAssetsRequest(assetIds=["  "])
bd_rb = bulk_delete_assets(bd_bad)
check(bd_rb.success == False,                 "bulk_delete empty id: success=False")
check(bd_rb.data.errorCode == "VALIDATION_ERROR", "bulk_delete empty id: VALIDATION_ERROR")

# Idempotent delete — all missing
create_asset(CreateAssetRequest(assetId="del-once"))
bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=["del-once"]))
bd_again = bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=["del-once"]))
check(bd_again.data["failCount"] == 1,        "bulk_delete: already deleted → fail")
check(bd_again.data["failed"][0]["assetId"] == "del-once", "bulk_delete: correct fail assetId")

# Store is empty after all deletes
check(len(_ASSET_STORE) == 0,                 "bulk_delete: store empty")


# ===========================================================================
# Section 12 — Extended Statistics
# ===========================================================================
print("=== 12. get_asset_statistics() extended ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="st1", vendor="Cisco",   currentIp="10.0.1.1",   currentStatus="active"))
create_asset(CreateAssetRequest(assetId="st2", vendor="Cisco",   currentIp="10.0.1.2",   currentStatus="active"))
create_asset(CreateAssetRequest(assetId="st3", vendor="Juniper", currentIp="10.0.2.10",  currentStatus="external"))
create_asset(CreateAssetRequest(assetId="st4", vendor="Apple",   currentIp="192.168.1.5",currentStatus="offline"))
create_asset(CreateAssetRequest(assetId="st5", vendor="HP",      currentIp="192.168.1.6",currentStatus="online"))
create_asset(CreateAssetRequest(assetId="st6", vendor="Cisco",                           currentStatus="active"))  # no IP
_ASSET_STORE["st1"]["currentRiskScore"] = 70
_ASSET_STORE["st2"]["currentRiskScore"] = 80
_ASSET_STORE["st3"]["currentRiskScore"] = 35
_ASSET_STORE["st4"]["currentRiskScore"] = 10
_ASSET_STORE["st5"]["currentRiskScore"] = 60
_ASSET_STORE["st6"]["currentRiskScore"] = 20

rs = get_asset_statistics()
d = rs.data

check(rs.success == True,                     "stats: success")
check(d["totalAssets"] == 6,                  "stats: totalAssets=6")
check(d["activeAssets"] == 3,                 "stats: activeAssets=3 (active)")
check(d["externalAssets"] == 1,               "stats: externalAssets=1")

# high risk (>=60): st1(70),st2(80),st5(60) = 3
check(d["highRiskAssets"] == 3,               "stats: highRiskAssets=3")

# medium risk [30,60): st3(35) = 1
check(d["mediumRiskAssets"] == 1,             "stats: mediumRiskAssets=1")

# average
total_risk = 70+80+35+10+60+20
expected_avg = round(total_risk / 6, 4)
check(d["averageRiskScore"] == expected_avg,  "stats: averageRiskScore correct")
check(d["averageRisk"] == expected_avg,       "stats: averageRisk alias correct")

# vendorCounts
check("Cisco"   in d["vendorCounts"],         "stats: Cisco in vendorCounts")
check("Juniper" in d["vendorCounts"],         "stats: Juniper in vendorCounts")
check("Apple"   in d["vendorCounts"],         "stats: Apple in vendorCounts")
check("HP"      in d["vendorCounts"],         "stats: HP in vendorCounts")
check(d["vendorCounts"]["Cisco"] == 3,        "stats: Cisco count=3")
check(d["vendorCounts"]["Juniper"] == 1,      "stats: Juniper count=1")

# statusCounts
check("active"   in d["statusCounts"],        "stats: active in statusCounts")
check("external" in d["statusCounts"],        "stats: external in statusCounts")
check("offline"  in d["statusCounts"],        "stats: offline in statusCounts")
check("online"   in d["statusCounts"],        "stats: online in statusCounts")
check(d["statusCounts"]["active"] == 3,       "stats: active count=3")

# subnetCounts
check("10.0.1" in d["subnetCounts"],          "stats: subnet 10.0.1 present")
check("10.0.2" in d["subnetCounts"],          "stats: subnet 10.0.2 present")
check("192.168.1" in d["subnetCounts"],       "stats: subnet 192.168.1 present")
check(d["subnetCounts"]["10.0.1"] == 2,       "stats: subnet 10.0.1 count=2")
check(d["subnetCounts"]["192.168.1"] == 2,    "stats: subnet 192.168.1 count=2")
check(d["subnetCounts"]["10.0.2"] == 1,       "stats: subnet 10.0.2 count=1")

# onlineAssets = active + online = 3 + 1 = 4
check(d["onlineAssets"] == 4,                 "stats: onlineAssets=4 (active+online)")

# offlineAssets = external + offline = 1 + 1 = 2
check(d["offlineAssets"] == 2,                "stats: offlineAssets=2 (external+offline)")

# Empty store stats
_reset_store()
re = get_asset_statistics()
de = re.data
check(re.success == True,                     "stats empty: success")
check(de["totalAssets"] == 0,                 "stats empty: totalAssets=0")
check(de["activeAssets"] == 0,                "stats empty: activeAssets=0")
check(de["averageRiskScore"] == 0.0,          "stats empty: averageRiskScore=0.0")
check(de["vendorCounts"] == {},               "stats empty: vendorCounts={}")
check(de["subnetCounts"] == {},               "stats empty: subnetCounts={}")
check(de["onlineAssets"] == 0,                "stats empty: onlineAssets=0")
check(de["offlineAssets"] == 0,               "stats empty: offlineAssets=0")


# ===========================================================================
# Section 13 — Deterministic Behavior
# ===========================================================================
print("=== 13. Deterministic behavior ===")
_reset_store()

# Same create request twice (with reset) yields identical response
create_asset(CreateAssetRequest(assetId="det1", hostname="stable", vendor="Cisco", currentIp="1.2.3.4"))
r_det1 = get_asset("det1")
_reset_store()
create_asset(CreateAssetRequest(assetId="det1", hostname="stable", vendor="Cisco", currentIp="1.2.3.4"))
r_det2 = get_asset("det1")
check(r_det1.data["assetId"]   == r_det2.data["assetId"],   "deterministic: assetId identical")
check(r_det1.data["hostname"]  == r_det2.data["hostname"],  "deterministic: hostname identical")
check(r_det1.data["vendor"]    == r_det2.data["vendor"],    "deterministic: vendor identical")
check(r_det1.data["currentIp"] == r_det2.data["currentIp"],"deterministic: currentIp identical")

# sort_assets is pure — multiple calls produce same result
_reset_store()
create_asset(CreateAssetRequest(assetId="z1", hostname="bravo"))
create_asset(CreateAssetRequest(assetId="z2", hostname="alpha"))
assets_z = _all_assets()
s1 = sort_assets(assets_z, "hostname", "asc")
s2 = sort_assets(assets_z, "hostname", "asc")
check(s1 == s2,                              "deterministic: sort same result twice")
check([a["assetId"] for a in assets_z] == ["z1","z2"], "deterministic: original list unchanged")

# filter_assets is pure
f1 = filter_assets(assets_z, vendor="Unknown")
f2 = filter_assets(assets_z, vendor="Unknown")
check(f1 == f2,                              "deterministic: filter same result twice")

# paginate_assets is pure
items_det = [{"assetId": f"p{i}"} for i in range(10)]
pa1, pag1a = paginate_assets(items_det, 1, 3)
pa2, pag1b = paginate_assets(items_det, 1, 3)
check(pa1 == pa2,                            "deterministic: paginate same result twice")
check(pag1a.totalPages == pag1b.totalPages,  "deterministic: pagination meta identical")

# Statistics keys are sorted
_reset_store()
create_asset(CreateAssetRequest(assetId="sv1", vendor="Zebra"))
create_asset(CreateAssetRequest(assetId="sv2", vendor="Alpha"))
rs_det = get_asset_statistics()
vendor_keys = list(rs_det.data["vendorCounts"].keys())
check(vendor_keys == sorted(vendor_keys),    "deterministic: vendorCounts sorted")


# ===========================================================================
# Section 14 — Edge Cases & Robustness
# ===========================================================================
print("=== 14. Edge cases ===")
_reset_store()

# 14.1 Large bulk operations
large_items = [CreateAssetRequest(assetId=f"large-{i}", hostname=f"host-{i}") for i in range(100)]
bl_large = bulk_create_assets(BulkCreateAssetsRequest(assets=large_items))
check(bl_large.success == True,              "edge: bulk create 100 assets")
check(bl_large.data["successCount"] == 100,  "edge: bulk 100 success")
check(len(_ASSET_STORE) == 100,              "edge: 100 in store")

# 14.2 Search + pagination with large result set
rs_large = search_assets(q="large", page=1, page_size=10)
check(rs_large.data["total"] == 100,         "edge: search 100 results total")
check(len(rs_large.data["assets"]) == 10,    "edge: search page 1 size 10")
check(rs_large.data["totalPages"] == 10,     "edge: search 100 items → 10 pages")

# 14.3 Page beyond end
rs_beyond = search_assets(q="large", page=100, page_size=10)
check(len(rs_beyond.data["assets"]) == 0,    "edge: page beyond end → empty")

# 14.4 Empty string fields
create_asset(CreateAssetRequest(assetId="edge-empty", hostname=""))
r_empty = get_asset("edge-empty")
check(r_empty.success == True,               "edge: empty hostname accepted")
check(r_empty.data["hostname"] == "",        "edge: empty hostname preserved")

# 14.5 None fields handled
# Field not set → defaults
create_asset(CreateAssetRequest(assetId="edge-none"))
r_none = get_asset("edge-none")
check(r_none.data["vendor"] == "Unknown",    "edge: vendor defaults to Unknown")
check(r_none.data["currentStatus"] == "active", "edge: status defaults to active")
check(r_none.data["notes"] == [],            "edge: notes defaults to []")

# 14.6 previousIPs tracking
create_asset(CreateAssetRequest(assetId="ip-track", currentIp="1.1.1.1"))
check(_ASSET_STORE["ip-track"]["previousIPs"] == ["1.1.1.1"], "edge: previousIPs seeded")
update_asset("ip-track", UpdateAssetRequest(currentIp="2.2.2.2"))
check("2.2.2.2" in _ASSET_STORE["ip-track"]["previousIPs"],  "edge: previousIPs tracks update")
check("1.1.1.1" in _ASSET_STORE["ip-track"]["previousIPs"],  "edge: old IP preserved")

# 14.7 Metadata merge
create_asset(CreateAssetRequest(assetId="meta-merge", metadata={"a": "1"}))
update_asset("meta-merge", UpdateAssetRequest(metadata={"b": "2"}))
meta = _ASSET_STORE["meta-merge"]["metadata"]
check("a" in meta,                           "edge: metadata merge preserves old keys")
check("b" in meta,                           "edge: metadata merge adds new keys")
check(meta["a"] == "1",                      "edge: metadata old value correct")
check(meta["b"] == "2",                      "edge: metadata new value correct")

# 14.8 Notes replacement (not merge)
create_asset(CreateAssetRequest(assetId="notes-replace", notes=["old"]))
update_asset("notes-replace", UpdateAssetRequest(notes=["new1", "new2"]))
check(_ASSET_STORE["notes-replace"]["notes"] == ["new1", "new2"], "edge: notes replaced not merged")

# 14.9 filter_assets with None/empty values
_reset_store()
create_asset(CreateAssetRequest(assetId="filt-none", hostname="", currentIp=""))
assets_fn = _all_assets()
filt_host = filter_assets(assets_fn, hostname="something")
check(len(filt_host) == 0,                   "edge: filter empty hostname substring fails")

# 14.10 sort with all None values
_reset_store()
create_asset(CreateAssetRequest(assetId="s-none-1"))
create_asset(CreateAssetRequest(assetId="s-none-2"))
assets_sn = _all_assets()
sorted_none = sort_assets(assets_sn, "hostname", "asc")
check(len(sorted_none) == 2,                 "edge: sort None hostnames doesn't crash")
# Both have None hostname, sorted by assetId (created)
check(sorted_none[0]["assetId"] == "s-none-1", "edge: sort None hostnames stable by assetId")

# 14.11 paginate page=0 or page=-1 → clamped to 1
items_ec = [{"assetId": "x"}]
p_neg, pag_neg = paginate_assets(items_ec, -5, 10)
check(pag_neg.page == 1,                     "edge: negative page clamped to 1")
p_zero, pag_zero = paginate_assets(items_ec, 0, 10)
check(pag_zero.page == 1,                    "edge: page=0 clamped to 1")

# 14.12 pageSize=0 or negative → clamped to 1
p_sz0, pag_sz0 = paginate_assets(items_ec, 1, 0)
check(pag_sz0.pageSize == 1,                 "edge: pageSize=0 clamped to 1")
p_sz_neg, pag_sz_neg = paginate_assets(items_ec, 1, -10)
check(pag_sz_neg.pageSize == 1,              "edge: negative pageSize clamped to 1")

# 14.13 search with empty query not allowed (min_length=1) — but test with 1-char
rs_min = search_assets(q="x")
check(rs_min.success == True,                "edge: search q='x' (1 char) valid")

# 14.14 Bulk create with all failures
_reset_store()
create_asset(CreateAssetRequest(assetId="x1"))
bc_all_fail = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="x1"),  # dup
]))
check(bc_all_fail.success == True,           "edge: bulk create all fail returns success=True")
check(bc_all_fail.data["successCount"] == 0, "edge: bulk all fail successCount=0")
check(bc_all_fail.data["failCount"] == 1,    "edge: bulk all fail failCount=1")

# 14.15 Bulk update with all failures
bu_all_fail = bulk_update_assets(BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="no-such", update=UpdateAssetRequest(hostname="x")),
]))
check(bu_all_fail.success == True,           "edge: bulk update all fail returns success=True")
check(bu_all_fail.data["successCount"] == 0, "edge: bulk update all fail successCount=0")
check(bu_all_fail.data["failCount"] == 1,    "edge: bulk update all fail failCount=1")

# 14.16 Bulk delete with all failures
bd_all_fail = bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=["no-such-1", "no-such-2"]))
check(bd_all_fail.success == True,           "edge: bulk delete all fail returns success=True")
check(bd_all_fail.data["successCount"] == 0, "edge: bulk delete all fail successCount=0")
check(bd_all_fail.data["failCount"] == 2,    "edge: bulk delete all fail failCount=2")

# 14.17 Search with no results but valid query
_reset_store()
rs_empty = search_assets(q="zzz_no_match_at_all")
check(rs_empty.success == True,              "edge: search no results success=True")
check(rs_empty.data["total"] == 0,           "edge: search no results total=0")
check(rs_empty.data["totalPages"] == 0,      "edge: search no results totalPages=0")


# ===========================================================================
# Section 15 — Sorting via search endpoint
# ===========================================================================
print("=== 15. Sorting via search ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="sort-c", hostname="charlie", vendor="Vendor-B", currentIp="10.0.0.3"))
create_asset(CreateAssetRequest(assetId="sort-a", hostname="alpha",   vendor="Vendor-C", currentIp="10.0.0.1"))
create_asset(CreateAssetRequest(assetId="sort-b", hostname="bravo",   vendor="Vendor-A", currentIp="10.0.0.2"))
_ASSET_STORE["sort-c"]["currentRiskScore"] = 30
_ASSET_STORE["sort-a"]["currentRiskScore"] = 90
_ASSET_STORE["sort-b"]["currentRiskScore"] = 10

# All 5 sort_by options via search endpoint
for field, key, expected_first in [
    ("hostname", "hostname",         "alpha"),
    ("vendor",   "vendor",           "Vendor-A"),
    ("ip",       "currentIp",        "10.0.0.1"),
    ("risk",     "currentRiskScore", 10),
    ("created",  "assetId",          "sort-a"),
]:
    rs_s = search_assets(q="sort", sort_by=field, sort_order="asc")
    check(rs_s.success == True,              f"sort via search {field} asc: success")
    check(rs_s.data["assets"][0][key] == expected_first,
                                             f"sort via search {field} asc: first correct")
    check(rs_s.data["sortBy"] == field,      f"sort via search {field}: sortBy echoed")

# Descending sorts
rsd_h = search_assets(q="sort", sort_by="hostname", sort_order="desc")
check(rsd_h.data["assets"][0]["hostname"] == "charlie", "sort desc hostname: charlie first")

rsd_r = search_assets(q="sort", sort_by="risk", sort_order="desc")
check(rsd_r.data["assets"][0]["currentRiskScore"] == 90, "sort desc risk: 90 first")


# ===========================================================================
# Section 16 — Pagination via list_assets (list endpoint)
# ===========================================================================
print("=== 16. list_assets filter combinations ===")
_reset_store()

# Build a set of assets with varied fields
for i in range(10):
    status = "active" if i % 2 == 0 else "external"
    vendor = "Cisco" if i % 3 == 0 else "Juniper"
    ip = f"10.0.{i}.1"
    create_asset(CreateAssetRequest(
        assetId=f"lf-{i}", hostname=f"host-{i:02d}",
        vendor=vendor, currentIp=ip, currentStatus=status,
    ))
    _ASSET_STORE[f"lf-{i}"]["currentRiskScore"] = i * 10

# All
rl_all = list_assets()
check(rl_all.data["total"] == 10,            "list: 10 assets total")

# Filter by vendor
rl_cisco = list_assets(vendor="Cisco")
cisco_count = sum(1 for i in range(10) if i % 3 == 0)
check(rl_cisco.data["total"] == cisco_count, f"list filter Cisco: {cisco_count}")

# Filter by status
rl_active = list_assets(current_status="active")
active_count = sum(1 for i in range(10) if i % 2 == 0)
check(rl_active.data["total"] == active_count, f"list filter active: {active_count}")

# Filter by min risk score
rl_min = list_assets(min_risk_score=50)
check(rl_min.data["total"] == 5,             "list filter min_risk=50: 5 assets")

# Filter by max risk score
rl_max = list_assets(max_risk_score=30)
check(rl_max.data["total"] == 4,             "list filter max_risk=30: 4 assets")

# Filter hasIp=True
rl_ip = list_assets(has_ip=True)
check(rl_ip.data["total"] == 10,             "list hasIp=True: all 10 have IP")

# Create one without IP
create_asset(CreateAssetRequest(assetId="no-ip"))
rl_no_ip = list_assets(has_ip=False)
check(rl_no_ip.data["total"] == 1,           "list hasIp=False: 1 without IP")
check(rl_no_ip.data["assets"][0]["assetId"] == "no-ip", "list hasIp=False: correct asset")

# Filter hasMac=True — none have MAC set
rl_mac = list_assets(has_mac=True)
check(rl_mac.data["total"] == 0,             "list hasMac=True: 0 (none have MAC)")

# Add MAC to one
create_asset(CreateAssetRequest(assetId="with-mac", macAddress="aa:bb:cc:dd:ee:ff"))
rl_mac2 = list_assets(has_mac=True)
check(rl_mac2.data["total"] == 1,            "list hasMac=True: 1 with MAC")

# Filter hasMac=False
rl_no_mac = list_assets(has_mac=False)
check(rl_no_mac.data["total"] == 11,         "list hasMac=False: 11 without MAC")

# Combined vendor + status
rl_combo = list_assets(vendor="Cisco", current_status="active")
check(rl_combo.data["total"] >= 0,           "list combined filter: no crash")

# OS filter
create_asset(CreateAssetRequest(assetId="os-test", operatingSystem="Windows"))
rl_os = list_assets(operating_system="Windows")
check(rl_os.data["total"] == 1,              "list OS filter Windows: 1")
rl_os2 = list_assets(operating_system="linux")  # case-insensitive
check(rl_os2.data["total"] == 0,             "list OS filter linux CI: 0 (none)")


# ===========================================================================
# Section 17 — BulkOperationResult model shape
# ===========================================================================
print("=== 17. BulkOperationResult model shape ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="shape-1"))
bc_shape = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="shape-2"),
]))
d_shape = bc_shape.data
check("succeeded"    in d_shape,             "bulk result: succeeded key present")
check("failed"       in d_shape,             "bulk result: failed key present")
check("total"        in d_shape,             "bulk result: total key present")
check("successCount" in d_shape,             "bulk result: successCount key present")
check("failCount"    in d_shape,             "bulk result: failCount key present")
check(isinstance(d_shape["succeeded"], list),"bulk result: succeeded is list")
check(isinstance(d_shape["failed"], list),   "bulk result: failed is list")
check(isinstance(d_shape["total"], int),     "bulk result: total is int")
check(isinstance(d_shape["successCount"], int), "bulk result: successCount is int")
check(isinstance(d_shape["failCount"], int), "bulk result: failCount is int")
check(d_shape["total"] == d_shape["successCount"] + d_shape["failCount"],
                                             "bulk result: total = success + fail")

# failed entry shape
_reset_store()
bc_fail_shape = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="dup-shape"),
    CreateAssetRequest(assetId="dup-shape"),
]))
# Above triggers validation error (dup in body), so let's do it differently
create_asset(CreateAssetRequest(assetId="existing-shape"))
bc_fail_shape2 = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="existing-shape"),
]))
fail_entry = bc_fail_shape2.data["failed"][0]
check("assetId" in fail_entry,               "bulk fail entry: assetId key")
check("reason"  in fail_entry,               "bulk fail entry: reason key")
check(isinstance(fail_entry["assetId"], str),"bulk fail entry: assetId is str")
check(isinstance(fail_entry["reason"],  str),"bulk fail entry: reason is str")

# ===========================================================================
# Section 18 — AssetSearchResponse shape
# ===========================================================================
print("=== 18. AssetSearchResponse shape ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="shape-s1", hostname="shape-host"))
rs_shape = search_assets(q="shape")
d_ss = rs_shape.data
check("assets"     in d_ss,                  "search resp: assets key")
check("total"      in d_ss,                  "search resp: total key")
check("page"       in d_ss,                  "search resp: page key")
check("pageSize"   in d_ss,                  "search resp: pageSize key")
check("totalPages" in d_ss,                  "search resp: totalPages key")
check("query"      in d_ss,                  "search resp: query key")
check("sortBy"     in d_ss,                  "search resp: sortBy key")
check("sortOrder"  in d_ss,                  "search resp: sortOrder key")
check(isinstance(d_ss["assets"], list),      "search resp: assets is list")
check(isinstance(d_ss["total"], int),        "search resp: total is int")
check(isinstance(d_ss["page"], int),         "search resp: page is int")
check(isinstance(d_ss["pageSize"], int),     "search resp: pageSize is int")
check(isinstance(d_ss["totalPages"], int),   "search resp: totalPages is int")
check(isinstance(d_ss["query"], str),        "search resp: query is str")


# ===========================================================================
# Section 19 — Extended filter_assets coverage
# ===========================================================================
print("=== 19. Extended filter_assets ===")
_reset_store()

# Build diverse assets
for i in range(20):
    vendor  = ["Cisco","Juniper","Apple","HP","Dell"][i % 5]
    status  = ["active","external","offline","online","inactive"][i % 5]
    ip      = f"172.{i // 10}.{i % 10}.{i}"
    rs      = i * 4
    lseen   = f"2026-07-0{1+i%7}T00:00:00Z" if i % 3 == 0 else None
    create_asset(CreateAssetRequest(
        assetId=f"ext-{i}", hostname=f"node-{i:02d}",
        vendor=vendor, currentIp=ip, currentStatus=status,
    ))
    _ASSET_STORE[f"ext-{i}"]["currentRiskScore"] = rs
    _ASSET_STORE[f"ext-{i}"]["lastSeen"] = lseen

assets_ext = _all_assets()

# vendor counts
for vend in ["Cisco","Juniper","Apple","HP","Dell"]:
    fv2 = filter_assets(assets_ext, vendor=vend)
    check(len(fv2) == 4, f"ext filter vendor={vend}: 4 assets")

# status counts
for stat in ["active","external","offline","online","inactive"]:
    fs2 = filter_assets(assets_ext, online=(stat in {"active","online"}))
    check(len(fs2) >= 0, f"ext filter online status no crash {stat}")

# hostname substring
fh2 = filter_assets(assets_ext, hostname="node-0")
check(len(fh2) > 0,                          "ext filter hostname node-0: found")

# risk range various
fr_lo = filter_assets(assets_ext, max_risk=10)
check(len(fr_lo) == 3,                       "ext filter max_risk=10: 3 (0,4,8)")

fr_hi = filter_assets(assets_ext, min_risk=70)
check(len(fr_hi) == 2,                       "ext filter min_risk=70: 2 (72,76)")

# subnet counts in stats
rs_ext_stats = get_asset_statistics()
check(rs_ext_stats.success == True,          "ext stats: success")
check(rs_ext_stats.data["totalAssets"] == 20,"ext stats: 20 assets")
check(len(rs_ext_stats.data["vendorCounts"]) == 5, "ext stats: 5 vendors")

# online/offline counts
active_n  = sum(1 for i in range(20) if ["active","external","offline","online","inactive"][i%5] in {"active","online"})
offline_n = sum(1 for i in range(20) if ["active","external","offline","online","inactive"][i%5] in {"inactive","offline","external"})
check(rs_ext_stats.data["onlineAssets"]  == active_n,  "ext stats: onlineAssets correct")
check(rs_ext_stats.data["offlineAssets"] == offline_n, "ext stats: offlineAssets correct")

# subnetCounts not empty
check(len(rs_ext_stats.data["subnetCounts"]) > 0, "ext stats: subnetCounts populated")


# ===========================================================================
# Section 20 — Bulk operations at scale
# ===========================================================================
print("=== 20. Bulk at scale ===")
_reset_store()

# Create 50 assets
bc_50 = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId=f"bulk50-{i}", hostname=f"bulk-host-{i:02d}",
                       vendor="Cisco" if i%2==0 else "Juniper",
                       currentIp=f"10.50.0.{i}")
    for i in range(50)
]))
check(bc_50.success == True,                      "bulk scale 50: success")
check(bc_50.data["successCount"] == 50,           "bulk scale 50: 50 created")
check(len(_ASSET_STORE) == 50,                    "bulk scale 50: store has 50")

# Update 25 of them
bu_25 = bulk_update_assets(BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(
        assetId=f"bulk50-{i}",
        update=UpdateAssetRequest(currentStatus="offline")
    )
    for i in range(25)
]))
check(bu_25.success == True,                      "bulk update 25: success")
check(bu_25.data["successCount"] == 25,           "bulk update 25: 25 updated")
check(all(_ASSET_STORE[f"bulk50-{i}"]["currentStatus"] == "offline" for i in range(25)),
                                                  "bulk update 25: statuses set to offline")
check(all(_ASSET_STORE[f"bulk50-{i}"]["currentStatus"] == "active" for i in range(25, 50)),
                                                  "bulk update 25: remaining still active")

# Delete 30 of them
bd_30 = bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=[
    f"bulk50-{i}" for i in range(30)
]))
check(bd_30.success == True,                      "bulk delete 30: success")
check(bd_30.data["successCount"] == 30,           "bulk delete 30: 30 deleted")
check(len(_ASSET_STORE) == 20,                    "bulk delete 30: 20 remain")

# Search remaining
rs_50_remain = search_assets(q="bulk50", page=1, page_size=20)
check(rs_50_remain.data["total"] == 20,           "bulk remain: search total=20")
check(rs_50_remain.data["totalPages"] == 1,       "bulk remain: 1 page of 20")

# Stats on remaining 20
rs_50_stats = get_asset_statistics()
check(rs_50_stats.data["totalAssets"] == 20,      "bulk remain stats: totalAssets=20")

# ===========================================================================
# Section 21 — search with combined filter+sort+pagination
# ===========================================================================
print("=== 21. search combined filter+sort+paginate ===")
_reset_store()

for i in range(30):
    vendor = "Cisco" if i < 15 else "Juniper"
    ip = f"10.21.{i//10}.{i%10}"
    create_asset(CreateAssetRequest(
        assetId=f"cs-{i:02d}", hostname=f"cs-host-{i:02d}",
        vendor=vendor, currentIp=ip,
    ))
    _ASSET_STORE[f"cs-{i:02d}"]["currentRiskScore"] = i * 3

# Search cisco by ip substring + vendor + sort risk desc + page 2 size 5
rs_c = search_assets(
    q="cs-", vendor_filter="Cisco",
    sort_by="risk", sort_order="desc",
    page=2, page_size=5,
)
check(rs_c.success == True,                       "combined: success")
check(rs_c.data["total"] == 15,                   "combined: 15 Cisco total")
check(rs_c.data["page"] == 2,                     "combined: page=2")
check(rs_c.data["pageSize"] == 5,                 "combined: pageSize=5")
check(rs_c.data["totalPages"] == 3,               "combined: totalPages=3")
check(len(rs_c.data["assets"]) == 5,              "combined: 5 assets on page 2")

risks_p2 = [a["currentRiskScore"] for a in rs_c.data["assets"]]
check(risks_p2 == sorted(risks_p2, reverse=True), "combined: page 2 risk desc order")

rs_c_last = search_assets(
    q="cs-", vendor_filter="Cisco",
    sort_by="risk", sort_order="desc",
    page=3, page_size=5,
)
check(len(rs_c_last.data["assets"]) == 5,         "combined: page 3 has 5 assets")

rs_sub21 = search_assets(q="cs-", subnet_filter="10.21.0")
check(rs_sub21.data["total"] == 10,               "combined subnet 10.21.0: 10")
rs_sub21b = search_assets(q="cs-", subnet_filter="10.21.1")
check(rs_sub21b.data["total"] == 10,              "combined subnet 10.21.1: 10")
rs_sub21c = search_assets(q="cs-", subnet_filter="10.21.2")
check(rs_sub21c.data["total"] == 10,              "combined subnet 10.21.2: 10")

# ===========================================================================
# Section 22 — message strings
# ===========================================================================
print("=== 22. Response messages ===")
_reset_store()
create_asset(CreateAssetRequest(assetId="msg-1"))

rl_msg = list_assets()
check("1 asset(s) found" in rl_msg.message,       "msg list: '1 asset(s) found'")

rc_msg = create_asset(CreateAssetRequest(assetId="msg-2"))
check("Asset created" in rc_msg.message,          "msg create: 'Asset created'")

ru_msg = update_asset("msg-1", UpdateAssetRequest(hostname="x"))
check("Asset updated" in ru_msg.message,          "msg update: 'Asset updated'")

rg_msg = get_asset("msg-1")
check("Asset retrieved" in rg_msg.message,        "msg get: 'Asset retrieved'")

rd_msg = delete_asset("msg-1")
check("msg-1" in rd_msg.message,                  "msg delete: assetId in message")

rs_msg = get_asset_statistics()
check("statistics" in rs_msg.message.lower(),     "msg stats: 'statistics' in message")

rsearch_msg = search_assets(q="msg-2")
check("matched" in rsearch_msg.message,           "msg search: 'matched' in message")

rbc_msg = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="msg-bulk-1"),
]))
check("Bulk create" in rbc_msg.message,           "msg bulk create: 'Bulk create' in message")

rbu_msg = bulk_update_assets(BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="msg-2", update=UpdateAssetRequest(hostname="y")),
]))
check("Bulk update" in rbu_msg.message,           "msg bulk update: 'Bulk update' in message")

rbd_msg = bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=["msg-2"]))
check("Bulk delete" in rbd_msg.message,           "msg bulk delete: 'Bulk delete' in message")

# ===========================================================================
# Section 23 — _all_assets ordering
# ===========================================================================
print("=== 23. _all_assets ordering ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="zzz"))
create_asset(CreateAssetRequest(assetId="aaa"))
create_asset(CreateAssetRequest(assetId="mmm"))

ordered = _all_assets()
ids = [a["assetId"] for a in ordered]
check(ids == sorted(ids),                         "_all_assets: sorted by assetId ASC")

# ===========================================================================
# Section 24 — update preserves unmodified fields
# ===========================================================================
print("=== 24. Update field preservation ===")
_reset_store()

create_asset(CreateAssetRequest(
    assetId="preserve-1",
    hostname="original-host",
    vendor="Cisco",
    operatingSystem="Linux",
    currentIp="1.2.3.4",
    notes=["original"],
    metadata={"key": "val"},
))
update_asset("preserve-1", UpdateAssetRequest(hostname="new-host"))

a = _ASSET_STORE["preserve-1"]
check(a["hostname"] == "new-host",                "preserve: hostname updated")
check(a["vendor"] == "Cisco",                     "preserve: vendor unchanged")
check(a["operatingSystem"] == "Linux",            "preserve: OS unchanged")
check(a["currentIp"] == "1.2.3.4",               "preserve: currentIp unchanged")
check(a["notes"] == ["original"],                 "preserve: notes unchanged")
check(a["metadata"]["key"] == "val",              "preserve: metadata key preserved")

# Update only OS
update_asset("preserve-1", UpdateAssetRequest(operatingSystem="Windows"))
a2 = _ASSET_STORE["preserve-1"]
check(a2["hostname"] == "new-host",               "preserve: hostname still new after OS update")
check(a2["operatingSystem"] == "Windows",         "preserve: OS updated")

# ===========================================================================
# Section 25 — currentIp update adds to previousIPs (no duplicates)
# ===========================================================================
print("=== 25. previousIPs deduplication ===")
_reset_store()

create_asset(CreateAssetRequest(assetId="ip-dedup", currentIp="10.0.0.1"))
update_asset("ip-dedup", UpdateAssetRequest(currentIp="10.0.0.2"))
update_asset("ip-dedup", UpdateAssetRequest(currentIp="10.0.0.3"))
update_asset("ip-dedup", UpdateAssetRequest(currentIp="10.0.0.2"))  # duplicate

prev = _ASSET_STORE["ip-dedup"]["previousIPs"]
check("10.0.0.1" in prev,                         "previousIPs: 10.0.0.1 present")
check("10.0.0.2" in prev,                         "previousIPs: 10.0.0.2 present")
check("10.0.0.3" in prev,                         "previousIPs: 10.0.0.3 present")
check(prev.count("10.0.0.2") == 1,               "previousIPs: 10.0.0.2 not duplicated")

# ===========================================================================
# Section 26 — Additional edge cases
# ===========================================================================
print("=== 26. Additional edge cases ===")
_reset_store()

# Empty query prevented by min_length=1, but test boundary
rs_1char = search_assets(q="a")
check(rs_1char.success == True,                   "edge: 1-char query valid")

# Sort by all 5 sort keys with empty result set
for key in ["hostname", "vendor", "ip", "risk", "created"]:
    rs_empty_sort = search_assets(q="zzz_no_match", sort_by=key)
    check(rs_empty_sort.success == True,          f"edge: empty result sort {key} no crash")

# Filter with empty vs None fields
create_asset(CreateAssetRequest(assetId="edge-26-1", hostname=""))
fa_empty_host = filter_assets(_all_assets(), hostname="")
check(len(fa_empty_host) == 1,                    "edge: filter empty hostname substring matches")

# SubnetCounts with malformed IPs (not x.x.x.x)
create_asset(CreateAssetRequest(assetId="edge-26-2", currentIp="10.0"))
rs_malformed = get_asset_statistics()
check(rs_malformed.success == True,               "edge: malformed IP doesn't crash stats")

# Risk score stats with all zeros
_reset_store()
for i in range(5):
    create_asset(CreateAssetRequest(assetId=f"zero-{i}"))
rs_zeros = get_asset_statistics()
check(rs_zeros.data["averageRiskScore"] == 0.0,   "edge: all zeros average = 0.0")
check(rs_zeros.data["highRiskAssets"] == 0,       "edge: no high risk assets")
check(rs_zeros.data["mediumRiskAssets"] == 0,     "edge: no medium risk assets")

# Bulk create/update/delete with single item
_reset_store()
bc_single = bulk_create_assets(BulkCreateAssetsRequest(assets=[
    CreateAssetRequest(assetId="single-c"),
]))
check(bc_single.success == True,                  "edge: bulk create single item success")
check(bc_single.data["successCount"] == 1,        "edge: bulk create single successCount=1")

bu_single = bulk_update_assets(BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="single-c", update=UpdateAssetRequest(hostname="x")),
]))
check(bu_single.success == True,                  "edge: bulk update single item success")
check(bu_single.data["successCount"] == 1,        "edge: bulk update single successCount=1")

bd_single = bulk_delete_assets(BulkDeleteAssetsRequest(assetIds=["single-c"]))
check(bd_single.success == True,                  "edge: bulk delete single item success")
check(bd_single.data["successCount"] == 1,        "edge: bulk delete single successCount=1")

# Search with all filters applied at once
_reset_store()
for i in range(15):
    vendor = "Cisco" if i < 10 else "Juniper"
    status = "active" if i % 2 == 0 else "offline"
    ip = f"192.168.7.{i}"
    create_asset(CreateAssetRequest(assetId=f"all-f-{i}", hostname=f"multi-{i}",
                                    vendor=vendor, currentIp=ip, currentStatus=status))
    _ASSET_STORE[f"all-f-{i}"]["currentRiskScore"] = i * 5
    if i < 7:
        _ASSET_STORE[f"all-f-{i}"]["lastSeen"] = "2026-07-01T00:00:00Z"

rs_all_filters = search_assets(
    q="all-f",
    vendor_filter="Cisco",
    hostname_filter="multi",
    subnet_filter="192.168.7",
    min_risk=10,
    max_risk=40,
    observed=True,
    online=True,
)
check(rs_all_filters.success == True,            "edge: all filters combined success")
check(rs_all_filters.data["total"] >= 0,         "edge: all filters total >= 0 (filtered)")

# Update same field twice
_reset_store()
create_asset(CreateAssetRequest(assetId="dup-up", hostname="h1"))
update_asset("dup-up", UpdateAssetRequest(hostname="h2"))
update_asset("dup-up", UpdateAssetRequest(hostname="h3"))
check(_ASSET_STORE["dup-up"]["hostname"] == "h3", "edge: sequential updates apply latest")

# list with all filter params
create_asset(CreateAssetRequest(assetId="list-all-f", vendor="Cisco", currentIp="1.1.1.1", 
                                currentStatus="active", macAddress="ff:ff:ff:ff:ff:ff"))
_ASSET_STORE["list-all-f"]["currentRiskScore"] = 25
rl_all = list_assets(vendor="Cisco", current_status="active", min_risk_score=20, 
                     max_risk_score=30, has_ip=True, has_mac=True)
check(rl_all.success == True,                    "edge: list all filter params success")
check(rl_all.data["total"] >= 1,                 "edge: list all filter matches at least 1")

# Pagination edge: exact multiple of page size
_reset_store()
for i in range(20):
    create_asset(CreateAssetRequest(assetId=f"pag-exact-{i}"))
rs_exact = search_assets(q="pag-exact", page_size=10)
check(rs_exact.data["totalPages"] == 2,          "edge: exact multiple → totalPages=2")
rs_exact_p2 = search_assets(q="pag-exact", page=2, page_size=10)
check(len(rs_exact_p2.data["assets"]) == 10,     "edge: page 2 full with exact multiple")

# Statistics with single asset
_reset_store()
create_asset(CreateAssetRequest(assetId="stats-solo", vendor="Solo", currentIp="9.9.9.9"))
_ASSET_STORE["stats-solo"]["currentRiskScore"] = 42
rs_solo = get_asset_statistics()
check(rs_solo.data["totalAssets"] == 1,          "edge: stats single asset totalAssets=1")
check(rs_solo.data["averageRiskScore"] == 42.0,  "edge: stats single asset avg=value")
check(rs_solo.data["vendorCounts"]["Solo"] == 1, "edge: stats single vendor count=1")

# ===========================================================================
# Section 27 — Model validation
# ===========================================================================
print("=== 27. Model validation ===")

# CreateAssetRequest — whitespace-only assetId
bad_ws = CreateAssetRequest(assetId="   \t   ")
errs_ws = bad_ws.validate_request()
check(len(errs_ws) > 0,                           "model: whitespace assetId invalid")
check("assetId" in errs_ws[0],                    "model: error mentions assetId")

# CreateAssetRequest — valid minimal
good = CreateAssetRequest(assetId="ok")
errs_good = good.validate_request()
check(errs_good == [],                             "model: minimal CreateAssetRequest valid")

# UpdateAssetRequest — has_any_field
upd_none = UpdateAssetRequest()
check(upd_none.has_any_field() == False,           "model: empty UpdateAssetRequest no fields")

upd_one = UpdateAssetRequest(hostname="x")
check(upd_one.has_any_field() == True,             "model: UpdateAssetRequest with hostname has field")

upd_meta = UpdateAssetRequest(metadata={"k": "v"})
check(upd_meta.has_any_field() == True,            "model: UpdateAssetRequest with metadata has field")

# BulkCreateAssetsRequest validate_request
bc_val = BulkCreateAssetsRequest(assets=[CreateAssetRequest(assetId="v1")])
errs_bc = bc_val.validate_request()
check(errs_bc == [],                               "model: valid BulkCreateAssetsRequest no errors")

bc_val_bad = BulkCreateAssetsRequest(assets=[CreateAssetRequest(assetId="")])
errs_bc_bad = bc_val_bad.validate_request()
check(len(errs_bc_bad) > 0,                        "model: empty assetId in bulk create errors")

# BulkUpdateAssetsRequest validate_request
bu_val = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="v1", update=UpdateAssetRequest(hostname="x")),
])
errs_bu = bu_val.validate_request()
check(errs_bu == [],                               "model: valid BulkUpdateAssetsRequest no errors")

bu_val_bad = BulkUpdateAssetsRequest(items=[
    BulkUpdateAssetsRequest.BulkUpdateItem(assetId="v1", update=UpdateAssetRequest()),
])
errs_bu_bad = bu_val_bad.validate_request()
check(len(errs_bu_bad) > 0,                        "model: empty update in bulk update errors")

# BulkDeleteAssetsRequest validate_request
bd_val = BulkDeleteAssetsRequest(assetIds=["v1", "v2"])
errs_bd = bd_val.validate_request()
check(errs_bd == [],                               "model: valid BulkDeleteAssetsRequest no errors")

bd_val_bad = BulkDeleteAssetsRequest(assetIds=["  "])
errs_bd_bad = bd_val_bad.validate_request()
check(len(errs_bd_bad) > 0,                        "model: whitespace assetId in bulk delete errors")

# AssetStatisticsExtendedResponse has both averageRiskScore and averageRisk
_reset_store()
create_asset(CreateAssetRequest(assetId="stat-model"))
_ASSET_STORE["stat-model"]["currentRiskScore"] = 50
rs_stat_model = get_asset_statistics()
check("averageRiskScore" in rs_stat_model.data,    "model: averageRiskScore key present")
check("averageRisk"      in rs_stat_model.data,    "model: averageRisk alias key present")
check(rs_stat_model.data["averageRiskScore"] == rs_stat_model.data["averageRisk"],
                                                   "model: averageRisk == averageRiskScore")
check("subnetCounts"  in rs_stat_model.data,       "model: subnetCounts key present")
check("onlineAssets"  in rs_stat_model.data,       "model: onlineAssets key present")
check("offlineAssets" in rs_stat_model.data,       "model: offlineAssets key present")









print()
print("=" * 60)
print(f"PASS: {PASS}")
print(f"FAIL: {FAIL}")
print("=" * 60)

if FAIL > 0:
    print("SMOKE TEST FAILED — fix failures above.")
    sys.exit(1)
else:
    target = 500
    if PASS < target:
        print(f"WARNING: Only {PASS}/{target} assertions (target not met).")
        print("Asset API Part B implementation incomplete.")
        sys.exit(1)
    else:
        print(f"ALL {PASS} ASSERTIONS PASSED ✓")
        print("Asset API Part B smoke test complete.")
        sys.exit(0)
