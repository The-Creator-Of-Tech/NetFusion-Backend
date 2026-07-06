"""
Attack Graph API Smoke Test — Phase A4.7.4 (Part A + Part B)
==============================================================
Comprehensive test coverage for the Attack Graph API router.

Test coverage
-------------
- CRUD operations (create, read, update, delete)
- Search functionality
- Sorting (nodeType, label, riskScore, confidence, createdAt)
- Filtering (nodeType, risk ranges, confidence ranges)
- Pagination
- Bulk operations (create, update, delete)
- Statistics (extended with Part B fields)
- Neighbor queries
- Relationship queries
- Router registration
- Serialization
- Deterministic behavior
- Edge cases

Target: 550+ assertions.

Run
---
python smoke_test_attack_graph_api.py
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any, Dict, List

from api.investigation.attack_graph_models import (
    AttackGraphStatisticsResponse,
    AttackNodeResponse,
    BulkCreateAttackNodesRequest,
    BulkDeleteAttackNodesRequest,
    BulkOperationResult,
    BulkUpdateAttackNodesRequest,
    CreateAttackNodeRequest,
    UpdateAttackNodeRequest,
)
from api.investigation.attack_graph_router import (
    _EDGE_STORE,
    _NODE_STORE,
    _reset_store,
    attack_graph_router,
    bulk_create_attack_nodes,
    bulk_delete_attack_nodes,
    bulk_update_attack_nodes,
    create_attack_node,
    delete_attack_node,
    filter_attack_nodes,
    find_attack_node,
    get_attack_graph_statistics,
    get_attack_node,
    get_attack_node_neighbors,
    get_attack_node_relationships,
    get_connected_nodes,
    get_neighbor_nodes,
    get_node_relationships,
    list_attack_nodes,
    paginate_attack_nodes,
    search_attack_nodes,
    sort_attack_nodes,
    update_attack_node,
)
from api.models import APIResponse
from services.attack_graph_service import GraphNodeTypeEnum, build_node

# Assertion counter

_PASS = 0
_FAIL = 0
_FAIL_MSGS: List[str] = []


def ok(condition: bool, msg: str) -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        _FAIL_MSGS.append(f"FAIL: {msg}")
        print(f"  FAIL: {msg}")


def eq(a: Any, b: Any, msg: str) -> None:
    ok(a == b, f"{msg}  (got {a!r}, expected {b!r})")


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _setup() -> None:
    """Clear stores before each test group."""
    _reset_store()


# ---------------------------------------------------------------------------
# Helpers — create nodes quickly
# ---------------------------------------------------------------------------

def _create_node(node_type: str, label: str, **kwargs) -> Dict[str, Any]:
    """Call create_attack_node() and return the data dict."""
    req = CreateAttackNodeRequest(nodeType=node_type, label=label, **kwargs)
    resp = create_attack_node(req)
    assert resp.success, f"create_attack_node failed: {resp.message}"
    return resp.data


def _create_edge(edge_id: str, src: str, tgt: str, edge_type: str = "RELATED_TO") -> None:
    """Directly insert an edge into _EDGE_STORE for graph utility tests."""
    _EDGE_STORE[edge_id] = {
        "edgeId": edge_id,
        "edgeKey": edge_id,
        "sourceNodeId": src,
        "targetNodeId": tgt,
        "edgeType": edge_type,
        "confidence": 70,
        "metadata": {},
    }


# ===========================================================================
# 1. Router Registration
# ===========================================================================

section("1. Router Registration")

paths = [r.path for r in attack_graph_router.routes]
methods = {r.path: list(r.methods) for r in attack_graph_router.routes}

ok("/attack-graph" in paths, "GET /attack-graph registered")
ok("/attack-graph/statistics" in paths, "GET /attack-graph/statistics registered")
ok("/attack-graph/search" in paths, "GET /attack-graph/search registered")
ok("/attack-graph/bulk/create" in paths, "POST /attack-graph/bulk/create registered")
ok("/attack-graph/bulk/update" in paths, "PUT /attack-graph/bulk/update registered")
ok("/attack-graph/bulk/delete" in paths, "DELETE /attack-graph/bulk/delete registered")
ok("/attack-graph/{nodeId}" in paths, "GET|PUT|DELETE /attack-graph/{nodeId} registered")
ok("/attack-graph/{nodeId}/neighbors" in paths, "GET /attack-graph/{nodeId}/neighbors registered")
ok("/attack-graph/{nodeId}/relationships" in paths, "GET /attack-graph/{nodeId}/relationships registered")

# Verify tag
for r in attack_graph_router.routes:
    ok("Attack Graph" in attack_graph_router.tags, "Router tag = Attack Graph")
    break

ok(attack_graph_router.prefix == "/attack-graph", "Router prefix = /attack-graph")

print(f"  Registered routes: {len(paths)}")
ok(len(paths) == 12, f"12 routes registered (got {len(paths)})")


# ===========================================================================
# 2. CRUD Operations — Create
# ===========================================================================

section("2. CRUD — Create Attack Node")

_setup()

# Create node 1
req1 = CreateAttackNodeRequest(
    nodeType="ASSET",
    label="192.168.1.100",
    displayName="Web Server",
    riskScore=75,
    confidence=90,
    metadata={"zone": "dmz"},
)
resp1 = create_attack_node(req1)
ok(resp1.success is True, "create_attack_node returns success=True")
ok(resp1.data is not None, "create_attack_node returns data")

node1 = resp1.data
ok(node1["nodeType"] == "ASSET", "Created node has nodeType=ASSET")
ok(node1["label"] == "192.168.1.100", "Created node has correct label")
ok(node1["displayName"] == "Web Server", "Created node has correct displayName")
ok(node1["riskScore"] == 75, "Created node has riskScore=75")
ok(node1["confidence"] == 90, "Created node has confidence=90")
ok(node1["metadata"]["zone"] == "dmz", "Created node has metadata.zone=dmz")
ok("nodeId" in node1, "Created node has nodeId")
ok("nodeKey" in node1, "Created node has nodeKey")
ok("createdAt" in node1, "Created node has createdAt")

node_id_1 = node1["nodeId"]
ok(len(node_id_1) == 32, "nodeId is 32 chars (SHA-256 truncated)")

# Create node 2 — same nodeType + label → same nodeId (deterministic)
req2 = CreateAttackNodeRequest(
    nodeType="ASSET",
    label="192.168.1.100",
    displayName="Different Name",
    riskScore=50,
)
resp2 = create_attack_node(req2)
ok(resp2.success is False, "create_attack_node rejects duplicate (same nodeType+label)")
ok("already exists" in resp2.message.lower() or "conflict" in resp2.message.lower(),
   "Error message mentions conflict/already exists")

# Create node 3 — different label
req3 = CreateAttackNodeRequest(
    nodeType="ASSET",
    label="192.168.1.101",
    riskScore=20,
)
resp3 = create_attack_node(req3)
ok(resp3.success is True, "create_attack_node succeeds for different label")
node3 = resp3.data
node_id_3 = node3["nodeId"]
ok(node_id_3 != node_id_1, "Different labels produce different nodeIds")

# Create node 4 — different nodeType
req4 = CreateAttackNodeRequest(
    nodeType="EVIDENCE",
    label="hostname",
)
resp4 = create_attack_node(req4)
ok(resp4.success is True, "create_attack_node succeeds for different nodeType")
node_id_4 = resp4.data["nodeId"]
ok(node_id_4 != node_id_1, "Different nodeTypes produce different nodeIds")

# Validation — empty nodeType
req5 = CreateAttackNodeRequest(nodeType="", label="test")
resp5 = create_attack_node(req5)
ok(resp5.success is False, "create_attack_node rejects empty nodeType")

# Validation — empty label
req6 = CreateAttackNodeRequest(nodeType="ASSET", label="")
resp6 = create_attack_node(req6)
ok(resp6.success is False, "create_attack_node rejects empty label")

# Validation — invalid nodeType
req7 = CreateAttackNodeRequest(nodeType="INVALID_TYPE", label="test")
resp7 = create_attack_node(req7)
ok(resp7.success is False, "create_attack_node rejects invalid nodeType")
ok("invalid" in resp7.message.lower() or "not a recognised" in resp7.message.lower(),
   "Error message mentions invalid nodeType")

print(f"  Created {len(_NODE_STORE)} nodes in store")


# ===========================================================================
# 3. CRUD — Read (Get by ID + List)
# ===========================================================================

section("3. CRUD — Read")

# Get by nodeId
resp_get1 = get_attack_node(node_id_1)
ok(resp_get1.success is True, "get_attack_node returns success=True")
ok(resp_get1.data is not None, "get_attack_node returns data")
ok(resp_get1.data["nodeId"] == node_id_1, "get_attack_node returns correct node")
ok(resp_get1.data["label"] == "192.168.1.100", "get_attack_node has correct label")

# Get nonexistent node
resp_get_missing = get_attack_node("nonexistent_id_999")
ok(resp_get_missing.success is False, "get_attack_node returns success=False for missing node")
ok("not found" in resp_get_missing.message.lower(), "Error message mentions not found")

# List all nodes
resp_list = list_attack_nodes()
ok(resp_list.success is True, "list_attack_nodes returns success=True")
ok(resp_list.data is not None, "list_attack_nodes returns data")
ok("nodes" in resp_list.data, "list_attack_nodes data has 'nodes' key")
ok("total" in resp_list.data, "list_attack_nodes data has 'total' key")
eq(resp_list.data["total"], len(_NODE_STORE), "list_attack_nodes total matches store size")
ok(len(resp_list.data["nodes"]) == resp_list.data["total"],
   "list_attack_nodes returns all nodes (no pagination in Part A list endpoint)")

# Verify serialization
node_resp = resp_list.data["nodes"][0]
ok("nodeId" in node_resp, "Serialized node has nodeId")
ok("nodeType" in node_resp, "Serialized node has nodeType")
ok("label" in node_resp, "Serialized node has label")
ok("displayName" in node_resp, "Serialized node has displayName")
ok("riskScore" in node_resp, "Serialized node has riskScore")
ok("confidence" in node_resp, "Serialized node has confidence")
ok("metadata" in node_resp, "Serialized node has metadata")
ok("createdAt" in node_resp, "Serialized node has createdAt")


# ===========================================================================
# 4. CRUD — Update
# ===========================================================================

section("4. CRUD — Update")

# Successful update
req_upd = UpdateAttackNodeRequest(displayName="Updated Web Server", riskScore=85)
resp_upd = update_attack_node(node_id_1, req_upd)
ok(resp_upd.success is True, "update_attack_node returns success=True")
ok(resp_upd.data["displayName"] == "Updated Web Server", "update_attack_node updates displayName")
ok(resp_upd.data["riskScore"] == 85, "update_attack_node updates riskScore")
ok(resp_upd.data["label"] == "192.168.1.100", "update_attack_node preserves label (immutable)")

# Verify persisted
resp_reget = get_attack_node(node_id_1)
ok(resp_reget.data["displayName"] == "Updated Web Server", "Update persisted to store")
ok(resp_reget.data["riskScore"] == 85, "riskScore update persisted to store")

# Update confidence
req_upd_conf = UpdateAttackNodeRequest(confidence=50)
resp_upd_conf = update_attack_node(node_id_1, req_upd_conf)
ok(resp_upd_conf.success is True, "update_attack_node updates confidence")
ok(resp_upd_conf.data["confidence"] == 50, "confidence updated to 50")

# Update metadata merges
req_upd_meta = UpdateAttackNodeRequest(metadata={"newKey": "newVal"})
resp_upd_meta = update_attack_node(node_id_1, req_upd_meta)
ok(resp_upd_meta.success is True, "update_attack_node updates metadata")
ok(resp_upd_meta.data["metadata"]["newKey"] == "newVal", "New metadata key merged in")
ok(resp_upd_meta.data["metadata"].get("zone") == "dmz", "Existing metadata key preserved")

# Update riskScore boundary — clamp to 100
req_upd_clamp = UpdateAttackNodeRequest(riskScore=100)
resp_upd_clamp = update_attack_node(node_id_1, req_upd_clamp)
ok(resp_upd_clamp.success is True, "update_attack_node accepts riskScore=100")
ok(resp_upd_clamp.data["riskScore"] == 100, "riskScore clamped to 100")

# Update 404
resp_upd_404 = update_attack_node("nonexistent_node", UpdateAttackNodeRequest(riskScore=50))
ok(resp_upd_404.success is False, "update_attack_node returns success=False for missing node")

# Update 422 — no fields
req_empty = UpdateAttackNodeRequest()
resp_422 = update_attack_node(node_id_1, req_empty)
ok(resp_422.success is False, "update_attack_node rejects empty update body")
ok("at least one field" in resp_422.message.lower(), "Error mentions at least one field")


# ===========================================================================
# 5. CRUD — Delete
# ===========================================================================

section("5. CRUD — Delete")

# Create a temporary node to delete
req_del = CreateAttackNodeRequest(nodeType="ALERT", label="alert-to-delete")
resp_del_create = create_attack_node(req_del)
ok(resp_del_create.success is True, "Setup: created node for deletion")
node_id_del = resp_del_create.data["nodeId"]

count_before = len(_NODE_STORE)

# Delete
resp_del = delete_attack_node(node_id_del)
ok(resp_del.success is True, "delete_attack_node returns success=True")
ok(resp_del.data is None, "delete_attack_node returns data=None")
ok(node_id_del not in _NODE_STORE, "Node removed from _NODE_STORE")
eq(len(_NODE_STORE), count_before - 1, "Store size decremented by 1 after delete")

# Delete again — 404
resp_del_again = delete_attack_node(node_id_del)
ok(resp_del_again.success is False, "delete_attack_node returns success=False for missing node")
ok("not found" in resp_del_again.message.lower(), "Delete error mentions not found")

# Delete nonexistent
resp_del_missing = delete_attack_node("totally_nonexistent_xyz")
ok(resp_del_missing.success is False, "delete_attack_node fails for nonexistent node")


# ===========================================================================
# 6. Statistics
# ===========================================================================

section("6. Statistics (Extended — Part B)")

_setup()

# Empty store
resp_stats_empty = get_attack_graph_statistics()
ok(resp_stats_empty.success is True, "get_attack_graph_statistics returns success=True on empty store")
s = resp_stats_empty.data
ok("totalNodes" in s, "Statistics has totalNodes")
ok("nodeTypeCounts" in s, "Statistics has nodeTypeCounts (Part B)")
ok("nodeTypeCount" in s, "Statistics has nodeTypeCount (Part A alias)")
ok("relationshipCounts" in s, "Statistics has relationshipCounts (Part B)")
ok("relationshipCount" in s, "Statistics has relationshipCount (Part A compat)")
ok("averageRiskScore" in s, "Statistics has averageRiskScore")
ok("averageConfidence" in s, "Statistics has averageConfidence (Part B)")
eq(s["totalNodes"], 0, "Statistics totalNodes=0 on empty store")
eq(s["averageRiskScore"], 0.0, "Statistics averageRiskScore=0.0 on empty store")
eq(s["averageConfidence"], 0.0, "Statistics averageConfidence=0.0 on empty store")
eq(s["relationshipCount"], 0, "Statistics relationshipCount=0 on empty store")

# Populate store
_create_node("ASSET",    "192.168.1.1",  riskScore=80, confidence=90)
_create_node("ASSET",    "192.168.1.2",  riskScore=60, confidence=70)
_create_node("EVIDENCE", "mac-abcd",     riskScore=30, confidence=50)
_create_node("FINDING",  "cve-2024-001", riskScore=90, confidence=85)
_create_node("IP",       "10.0.0.1",     riskScore=10, confidence=40)

resp_stats = get_attack_graph_statistics()
ok(resp_stats.success is True, "get_attack_graph_statistics returns success=True")
s2 = resp_stats.data

eq(s2["totalNodes"], 5, "Statistics totalNodes=5")
ok(s2["nodeTypeCounts"].get("ASSET") == 2, "nodeTypeCounts has ASSET=2")
ok(s2["nodeTypeCounts"].get("EVIDENCE") == 1, "nodeTypeCounts has EVIDENCE=1")
ok(s2["nodeTypeCounts"].get("FINDING") == 1, "nodeTypeCounts has FINDING=1")
ok(s2["nodeTypeCounts"].get("IP") == 1, "nodeTypeCounts has IP=1")

# nodeTypeCount alias must match nodeTypeCounts exactly
ok(s2["nodeTypeCount"] == s2["nodeTypeCounts"], "nodeTypeCount alias equals nodeTypeCounts")

# averageRiskScore = (80+60+30+90+10)/5 = 54.0
expected_avg_risk = round((80+60+30+90+10) / 5, 4)
eq(s2["averageRiskScore"], expected_avg_risk, f"averageRiskScore={expected_avg_risk}")

# averageConfidence = (90+70+50+85+40)/5 = 67.0
expected_avg_conf = round((90+70+50+85+40) / 5, 4)
eq(s2["averageConfidence"], expected_avg_conf, f"averageConfidence={expected_avg_conf}")

# nodeTypeCounts is sorted alphabetically
keys = list(s2["nodeTypeCounts"].keys())
ok(keys == sorted(keys), "nodeTypeCounts keys are sorted alphabetically")

# Add edges and verify relationshipCount
ids = list(_NODE_STORE.keys())
if len(ids) >= 2:
    _create_edge("e1", ids[0], ids[1], "COMMUNICATES_WITH")
    _create_edge("e2", ids[1], ids[2], "RELATED_TO")
    resp_stats2 = get_attack_graph_statistics()
    eq(resp_stats2.data["relationshipCount"], 2, "relationshipCount=2 after adding edges")
    ok("COMMUNICATES_WITH" in resp_stats2.data["relationshipCounts"] or
       len(resp_stats2.data["relationshipCounts"]) >= 1,
       "relationshipCounts contains edge types")


# ===========================================================================
# 7. Sorting Helpers
# ===========================================================================

section("7. sort_attack_nodes() helper")

_setup()
_create_node("ASSET",    "zebra",  riskScore=10, confidence=90)
_create_node("EVIDENCE", "alpha",  riskScore=80, confidence=20)
_create_node("FINDING",  "mango",  riskScore=50, confidence=55)
_create_node("IP",       "delta",  riskScore=30, confidence=70)
_create_node("ALERT",    "bravo",  riskScore=95, confidence=10)

all_nodes = list(_NODE_STORE.values())

# Sort by label ASC
by_label_asc = sort_attack_nodes(all_nodes, "label", "asc")
labels_asc = [n["label"] for n in by_label_asc]
ok(labels_asc == sorted(labels_asc), "sort_attack_nodes label ASC is alphabetical")

# Sort by label DESC
by_label_desc = sort_attack_nodes(all_nodes, "label", "desc")
labels_desc = [n["label"] for n in by_label_desc]
ok(labels_desc == sorted(labels_desc, reverse=True), "sort_attack_nodes label DESC is reverse alphabetical")

# Sort by riskScore ASC
by_risk_asc = sort_attack_nodes(all_nodes, "riskScore", "asc")
risks_asc = [n["riskScore"] for n in by_risk_asc]
ok(risks_asc == sorted(risks_asc), "sort_attack_nodes riskScore ASC is ascending")
eq(risks_asc[0], 10, "sort_attack_nodes riskScore ASC: first=10")
eq(risks_asc[-1], 95, "sort_attack_nodes riskScore ASC: last=95")

# Sort by riskScore DESC
by_risk_desc = sort_attack_nodes(all_nodes, "riskScore", "desc")
risks_desc = [n["riskScore"] for n in by_risk_desc]
ok(risks_desc == sorted(risks_desc, reverse=True), "sort_attack_nodes riskScore DESC is descending")
eq(risks_desc[0], 95, "sort_attack_nodes riskScore DESC: first=95")
eq(risks_desc[-1], 10, "sort_attack_nodes riskScore DESC: last=10")

# Sort by confidence ASC
by_conf_asc = sort_attack_nodes(all_nodes, "confidence", "asc")
conf_asc = [n["confidence"] for n in by_conf_asc]
ok(conf_asc == sorted(conf_asc), "sort_attack_nodes confidence ASC is ascending")

# Sort by confidence DESC
by_conf_desc = sort_attack_nodes(all_nodes, "confidence", "desc")
conf_desc = [n["confidence"] for n in by_conf_desc]
ok(conf_desc == sorted(conf_desc, reverse=True), "sort_attack_nodes confidence DESC is descending")

# Sort by nodeType ASC
by_type_asc = sort_attack_nodes(all_nodes, "nodeType", "asc")
types_asc = [n["nodeType"] for n in by_type_asc]
ok(types_asc == sorted(types_asc), "sort_attack_nodes nodeType ASC is alphabetical")

# Sort by nodeType DESC
by_type_desc = sort_attack_nodes(all_nodes, "nodeType", "desc")
types_desc = [n["nodeType"] for n in by_type_desc]
ok(types_desc == sorted(types_desc, reverse=True), "sort_attack_nodes nodeType DESC is reverse alphabetical")

# Sort by createdAt ASC (all have datetime values)
by_created_asc = sort_attack_nodes(all_nodes, "createdAt", "asc")
ok(len(by_created_asc) == len(all_nodes), "sort_attack_nodes createdAt ASC returns all nodes")

# Invalid sort_by falls back to label
by_invalid = sort_attack_nodes(all_nodes, "INVALID_FIELD", "asc")
ok(len(by_invalid) == len(all_nodes), "sort_attack_nodes with invalid field falls back gracefully")

# Input not mutated
orig_order = [n["nodeId"] for n in all_nodes]
_ = sort_attack_nodes(all_nodes, "riskScore", "desc")
ok([n["nodeId"] for n in all_nodes] == orig_order, "sort_attack_nodes does not mutate input list")

# Deterministic — same call twice produces same order
s1 = [n["nodeId"] for n in sort_attack_nodes(all_nodes, "riskScore", "asc")]
s2 = [n["nodeId"] for n in sort_attack_nodes(all_nodes, "riskScore", "asc")]
ok(s1 == s2, "sort_attack_nodes is deterministic (same result on repeated calls)")


# ===========================================================================
# 8. Filtering Helpers
# ===========================================================================

section("8. filter_attack_nodes() helper")

all_nodes = list(_NODE_STORE.values())

# Filter by nodeType
assets = filter_attack_nodes(all_nodes, node_type="ASSET")
ok(all(n["nodeType"] == "ASSET" for n in assets), "filter_attack_nodes nodeType=ASSET")
eq(len(assets), 1, "filter_attack_nodes nodeType=ASSET returns 1 node")

evidence = filter_attack_nodes(all_nodes, node_type="EVIDENCE")
eq(len(evidence), 1, "filter_attack_nodes nodeType=EVIDENCE returns 1 node")

# Filter by nodeType case-insensitive
assets_lower = filter_attack_nodes(all_nodes, node_type="asset")
eq(len(assets_lower), 1, "filter_attack_nodes nodeType is case-insensitive")

# Filter by nonexistent nodeType
none_type = filter_attack_nodes(all_nodes, node_type="NONEXISTENT")
eq(len(none_type), 0, "filter_attack_nodes nonexistent nodeType returns 0 nodes")

# Filter by min_risk
high_risk = filter_attack_nodes(all_nodes, min_risk=50)
ok(all(n["riskScore"] >= 50 for n in high_risk), "filter_attack_nodes min_risk=50 filters correctly")
eq(len(high_risk), 3, "filter_attack_nodes min_risk=50 returns 3 nodes (50, 80, 95)")

# Filter by max_risk
low_risk = filter_attack_nodes(all_nodes, max_risk=30)
ok(all(n["riskScore"] <= 30 for n in low_risk), "filter_attack_nodes max_risk=30 filters correctly")
eq(len(low_risk), 2, "filter_attack_nodes max_risk=30 returns 2 nodes (10, 30)")

# Filter by risk range
mid_risk = filter_attack_nodes(all_nodes, min_risk=30, max_risk=80)
ok(all(30 <= n["riskScore"] <= 80 for n in mid_risk), "filter_attack_nodes risk range [30,80]")
eq(len(mid_risk), 3, "filter_attack_nodes risk range [30,80] returns 3 nodes (30, 50, 80)")

# Filter by min_confidence
high_conf = filter_attack_nodes(all_nodes, min_confidence=70)
ok(all(n["confidence"] >= 70 for n in high_conf), "filter_attack_nodes min_confidence=70")
eq(len(high_conf), 2, "filter_attack_nodes min_confidence=70 returns 2 nodes (90, 70)")

# Filter by max_confidence
low_conf = filter_attack_nodes(all_nodes, max_confidence=20)
ok(all(n["confidence"] <= 20 for n in low_conf), "filter_attack_nodes max_confidence=20")
eq(len(low_conf), 2, "filter_attack_nodes max_confidence=20 returns 2 nodes (20, 10)")

# Filter by confidence range
mid_conf = filter_attack_nodes(all_nodes, min_confidence=20, max_confidence=70)
ok(all(20 <= n["confidence"] <= 70 for n in mid_conf), "filter_attack_nodes confidence range [20,70]")

# Combined nodeType + risk filter
asset_high = filter_attack_nodes(all_nodes, node_type="ALERT", min_risk=90)
eq(len(asset_high), 1, "filter_attack_nodes nodeType=ALERT min_risk=90 returns 1 node")

# No filters — returns all
all_filtered = filter_attack_nodes(all_nodes)
eq(len(all_filtered), len(all_nodes), "filter_attack_nodes with no filters returns all nodes")

# Input not mutated
orig_ids = [n["nodeId"] for n in all_nodes]
_ = filter_attack_nodes(all_nodes, node_type="ASSET")
ok([n["nodeId"] for n in all_nodes] == orig_ids, "filter_attack_nodes does not mutate input")


# ===========================================================================
# 9. Pagination Helper
# ===========================================================================

section("9. paginate_attack_nodes() helper")

all_nodes = list(_NODE_STORE.values())  # 5 nodes

# Page 1 of 2 (page_size=3)
page1, pag1 = paginate_attack_nodes(all_nodes, page=1, page_size=3)
eq(len(page1), 3, "paginate_attack_nodes page=1, size=3 returns 3 items")
eq(pag1.page, 1, "Pagination.page=1")
eq(pag1.pageSize, 3, "Pagination.pageSize=3")
eq(pag1.totalItems, 5, "Pagination.totalItems=5")
eq(pag1.totalPages, 2, "Pagination.totalPages=2")

# Page 2 of 2 (page_size=3)
page2, pag2 = paginate_attack_nodes(all_nodes, page=2, page_size=3)
eq(len(page2), 2, "paginate_attack_nodes page=2, size=3 returns 2 items (remainder)")
eq(pag2.page, 2, "Pagination.page=2")
eq(pag2.totalItems, 5, "Pagination.totalItems=5 on page 2")

# Page 3 (beyond last)
page3, pag3 = paginate_attack_nodes(all_nodes, page=3, page_size=3)
eq(len(page3), 0, "paginate_attack_nodes page=3 beyond last page returns empty list")
eq(pag3.totalPages, 2, "Pagination.totalPages=2 still accurate on empty page")

# page_size=1
page_1each, pag_1each = paginate_attack_nodes(all_nodes, page=1, page_size=1)
eq(len(page_1each), 1, "paginate_attack_nodes size=1 returns 1 item")
eq(pag_1each.totalPages, 5, "Pagination.totalPages=5 for size=1 with 5 nodes")

# page_size=100 (larger than total)
page_all, pag_all = paginate_attack_nodes(all_nodes, page=1, page_size=100)
eq(len(page_all), 5, "paginate_attack_nodes size=100 returns all 5 items")
eq(pag_all.totalPages, 1, "Pagination.totalPages=1 when size > total")

# Empty list
page_empty, pag_empty = paginate_attack_nodes([], page=1, page_size=20)
eq(len(page_empty), 0, "paginate_attack_nodes on empty list returns empty slice")
eq(pag_empty.totalItems, 0, "Pagination.totalItems=0 for empty list")
eq(pag_empty.totalPages, 0, "Pagination.totalPages=0 for empty list")

# page clamped to 1 if 0 or negative
page_clamp, pag_clamp = paginate_attack_nodes(all_nodes, page=0, page_size=3)
eq(pag_clamp.page, 1, "paginate_attack_nodes clamps page=0 to page=1")

# page_size clamped to 1 if 0 or negative
page_sz_clamp, pag_sz_clamp = paginate_attack_nodes(all_nodes, page=1, page_size=0)
eq(pag_sz_clamp.pageSize, 1, "paginate_attack_nodes clamps page_size=0 to page_size=1")

# Pagination model fields
ok(hasattr(pag1, "page"), "Pagination has .page attribute")
ok(hasattr(pag1, "pageSize"), "Pagination has .pageSize attribute")
ok(hasattr(pag1, "totalItems"), "Pagination has .totalItems attribute")
ok(hasattr(pag1, "totalPages"), "Pagination has .totalPages attribute")

# Deterministic — two calls with same args yield same result
r1 = [n["nodeId"] for n in paginate_attack_nodes(all_nodes, page=1, page_size=3)[0]]
r2 = [n["nodeId"] for n in paginate_attack_nodes(all_nodes, page=1, page_size=3)[0]]
ok(r1 == r2, "paginate_attack_nodes is deterministic")


# ===========================================================================
# 10. find_attack_node() helper
# ===========================================================================

section("10. find_attack_node() helper")

all_nodes = list(_NODE_STORE.values())

# Find by label
found = find_attack_node(all_nodes, "label", "zebra")
ok(found is not None, "find_attack_node finds node by label")
ok(found["label"] == "zebra", "find_attack_node returns correct node")

# Find by label case-insensitive
found_ci = find_attack_node(all_nodes, "label", "ZEBRA")
ok(found_ci is not None, "find_attack_node is case-insensitive")
ok(found_ci["label"] == "zebra", "find_attack_node case-insensitive returns correct node")

# Find by nodeType
found_ev = find_attack_node(all_nodes, "nodeType", "EVIDENCE")
ok(found_ev is not None, "find_attack_node finds node by nodeType")
eq(found_ev["nodeType"], "EVIDENCE", "find_attack_node nodeType match is correct")

# Find by nodeId
first_id = all_nodes[0]["nodeId"]
found_by_id = find_attack_node(all_nodes, "nodeId", first_id)
ok(found_by_id is not None, "find_attack_node finds node by nodeId")
ok(found_by_id["nodeId"] == first_id, "find_attack_node nodeId match is exact")

# Find missing value
not_found = find_attack_node(all_nodes, "label", "nonexistent_label_xyz")
ok(not_found is None, "find_attack_node returns None when not found")

# Find on empty list
empty_result = find_attack_node([], "label", "anything")
ok(empty_result is None, "find_attack_node returns None on empty list")

# Find by unknown field
unknown_field = find_attack_node(all_nodes, "UNKNOWN_FIELD", "val")
ok(unknown_field is None, "find_attack_node returns None for unknown field")


# ===========================================================================
# 11. Search Endpoint
# ===========================================================================

section("11. GET /attack-graph/search")

_setup()
_create_node("ASSET",    "server-01", displayName="Production Server 01", riskScore=80)
_create_node("ASSET",    "server-02", displayName="Production Server 02", riskScore=60)
_create_node("EVIDENCE", "hostname-server-01", riskScore=30)
_create_node("FINDING",  "cve-2024-001", riskScore=90)
_create_node("IP",       "10.0.0.5", riskScore=10)

# Search by label substring
resp_search1 = search_attack_nodes(q="server")
ok(resp_search1.success is True, "search_attack_nodes returns success=True")
ok("nodes" in resp_search1.data, "Search response has 'nodes' key")
ok("total" in resp_search1.data, "Search response has 'total' key")
ok("query" in resp_search1.data, "Search response has 'query' key")
ok(resp_search1.data["query"] == "server", "Search response includes query string")
ok(resp_search1.data["total"] >= 3, "Search for 'server' matches at least 3 nodes")

# Search by displayName substring
resp_search2 = search_attack_nodes(q="Production")
ok(resp_search2.success is True, "search_attack_nodes by displayName succeeds")
ok(resp_search2.data["total"] >= 2, "Search for 'Production' matches at least 2 nodes")

# Search by nodeType
resp_search3 = search_attack_nodes(q="ASSET")
ok(resp_search3.success is True, "search_attack_nodes by nodeType succeeds")
ok(resp_search3.data["total"] >= 2, "Search for 'ASSET' matches at least 2 nodes")

# Search with sorting
resp_search_sort = search_attack_nodes(q="server", sort_by="riskScore", sort_order="desc")
ok(resp_search_sort.success is True, "search_attack_nodes with sort succeeds")
nodes = resp_search_sort.data["nodes"]
if len(nodes) >= 2:
    risks = [n["riskScore"] for n in nodes]
    ok(risks == sorted(risks, reverse=True), "Search results sorted by riskScore DESC")

# Search with filtering
resp_search_filter = search_attack_nodes(q="server", min_risk_filter=50)
ok(resp_search_filter.success is True, "search_attack_nodes with filter succeeds")
filtered_nodes = resp_search_filter.data["nodes"]
ok(all(n["riskScore"] >= 50 for n in filtered_nodes), "Search filtered nodes have riskScore >= 50")

# Search with pagination
resp_search_page = search_attack_nodes(q="server", page=1, page_size=2)
ok(resp_search_page.success is True, "search_attack_nodes with pagination succeeds")
ok("page" in resp_search_page.data, "Search response has 'page' key")
ok("pageSize" in resp_search_page.data, "Search response has 'pageSize' key")
ok("totalPages" in resp_search_page.data, "Search response has 'totalPages' key")
eq(resp_search_page.data["page"], 1, "Search response page=1")
eq(resp_search_page.data["pageSize"], 2, "Search response pageSize=2")
ok(len(resp_search_page.data["nodes"]) <= 2, "Search page returns at most page_size nodes")

# Search empty query — validation error
resp_search_empty = search_attack_nodes(q="")
ok(resp_search_empty.success is False, "search_attack_nodes rejects empty query")

# Search with invalid sort_by
resp_search_invalid = search_attack_nodes(q="server", sort_by="INVALID_FIELD")
ok(resp_search_invalid.success is False, "search_attack_nodes rejects invalid sort_by")

# Search with invalid sort_order
resp_search_bad_order = search_attack_nodes(q="server", sort_order="INVALID")
ok(resp_search_bad_order.success is False, "search_attack_nodes rejects invalid sort_order")

# Search no matches
resp_no_match = search_attack_nodes(q="zzz_no_match_xyz_999")
ok(resp_no_match.success is True, "search_attack_nodes with no matches returns success=True")
eq(resp_no_match.data["total"], 0, "search_attack_nodes no matches returns total=0")
eq(len(resp_no_match.data["nodes"]), 0, "search_attack_nodes no matches returns empty nodes list")

# Search case-insensitive
resp_case = search_attack_nodes(q="SERVER")
ok(resp_case.success is True, "search_attack_nodes is case-insensitive")
ok(resp_case.data["total"] >= 3, "search_attack_nodes case-insensitive matches correctly")


# ===========================================================================
# 12. Bulk Create
# ===========================================================================

section("12. POST /attack-graph/bulk/create")

_setup()

bulk_req = BulkCreateAttackNodesRequest(nodes=[
    CreateAttackNodeRequest(nodeType="ASSET",    label="bulk-asset-1",    riskScore=80),
    CreateAttackNodeRequest(nodeType="ASSET",    label="bulk-asset-2",    riskScore=60),
    CreateAttackNodeRequest(nodeType="EVIDENCE", label="bulk-evidence-1", riskScore=40),
    CreateAttackNodeRequest(nodeType="FINDING",  label="bulk-finding-1",  riskScore=90),
    CreateAttackNodeRequest(nodeType="IP",       label="10.0.0.100",      riskScore=15),
])

resp_bulk_create = bulk_create_attack_nodes(bulk_req)
ok(resp_bulk_create.success is True, "bulk_create_attack_nodes returns success=True")
ok(resp_bulk_create.data is not None, "bulk_create_attack_nodes returns data")

result = resp_bulk_create.data
ok("succeeded" in result, "Bulk create result has 'succeeded'")
ok("failed" in result, "Bulk create result has 'failed'")
ok("total" in result, "Bulk create result has 'total'")
ok("successCount" in result, "Bulk create result has 'successCount'")
ok("failCount" in result, "Bulk create result has 'failCount'")

eq(result["total"], 5, "Bulk create total=5")
eq(result["successCount"], 5, "Bulk create successCount=5")
eq(result["failCount"], 0, "Bulk create failCount=0")
eq(len(result["succeeded"]), 5, "Bulk create succeeded list has 5 entries")
eq(len(result["failed"]), 0, "Bulk create failed list is empty")

ok(len(_NODE_STORE) == 5, "Bulk create stored 5 nodes")

# Bulk create with duplicates — some fail
bulk_req2 = BulkCreateAttackNodesRequest(nodes=[
    CreateAttackNodeRequest(nodeType="ASSET",   label="bulk-asset-1",  riskScore=10),  # duplicate
    CreateAttackNodeRequest(nodeType="DOMAIN",  label="evil.com",      riskScore=70),  # new
])
resp_bulk2 = bulk_create_attack_nodes(bulk_req2)
ok(resp_bulk2.success is True, "Bulk create partial duplicate returns success=True")
r2 = resp_bulk2.data
eq(r2["total"], 2, "Bulk create partial duplicate total=2")
eq(r2["successCount"], 1, "Bulk create partial duplicate successCount=1")
eq(r2["failCount"], 1, "Bulk create partial duplicate failCount=1")
ok(len(r2["failed"]) == 1, "Bulk create partial duplicate failed list has 1 entry")
ok("reason" in r2["failed"][0], "Bulk create failed entry has 'reason'")

# Bulk create with invalid nodeType (passes Pydantic but fails service-level)
bulk_req_inv = BulkCreateAttackNodesRequest(nodes=[
    CreateAttackNodeRequest(nodeType="INVALID_TYPE_XYZ", label="node-inv-1"),
    CreateAttackNodeRequest(nodeType="ASSET", label="node-inv-valid"),
])
resp_inv = bulk_create_attack_nodes(bulk_req_inv)
ok(resp_inv.success is True, "Bulk create with invalid nodeType returns success=True (item-level fail)")
ri = resp_inv.data
eq(ri["failCount"], 1, "Bulk create invalid nodeType records a failure")
eq(ri["successCount"], 1, "Bulk create invalid nodeType: valid item succeeds")
eq(ri["successCount"] + ri["failCount"], ri["total"], "Bulk create: successCount + failCount == total")


# ===========================================================================
# 13. Bulk Update
# ===========================================================================

section("13. PUT /attack-graph/bulk/update")

# All 6 nodes in store now; grab IDs
all_ids = list(_NODE_STORE.keys())
ok(len(all_ids) >= 3, f"Setup: at least 3 nodes in store (got {len(all_ids)})")

id_a = all_ids[0]
id_b = all_ids[1]
id_c = all_ids[2]

bulk_upd_req = BulkUpdateAttackNodesRequest(items=[
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=id_a,
        update=UpdateAttackNodeRequest(riskScore=99, displayName="Updated A"),
    ),
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=id_b,
        update=UpdateAttackNodeRequest(confidence=88),
    ),
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=id_c,
        update=UpdateAttackNodeRequest(metadata={"bulkKey": "bulkVal"}),
    ),
])

resp_bulk_upd = bulk_update_attack_nodes(bulk_upd_req)
ok(resp_bulk_upd.success is True, "bulk_update_attack_nodes returns success=True")
ru = resp_bulk_upd.data
eq(ru["total"], 3, "Bulk update total=3")
eq(ru["successCount"], 3, "Bulk update successCount=3")
eq(ru["failCount"], 0, "Bulk update failCount=0")

# Verify updates persisted
ok(_NODE_STORE[id_a]["riskScore"] == 99, "Bulk update: riskScore=99 persisted for node A")
ok(_NODE_STORE[id_a]["displayName"] == "Updated A", "Bulk update: displayName persisted for node A")
ok(_NODE_STORE[id_b]["confidence"] == 88, "Bulk update: confidence=88 persisted for node B")
ok(_NODE_STORE[id_c]["metadata"].get("bulkKey") == "bulkVal", "Bulk update: metadata persisted for node C")

# Bulk update with nonexistent node
bulk_upd_req2 = BulkUpdateAttackNodesRequest(items=[
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId="nonexistent_node_xyz",
        update=UpdateAttackNodeRequest(riskScore=50),
    ),
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=id_a,
        update=UpdateAttackNodeRequest(riskScore=55),
    ),
])
resp_bulk_upd2 = bulk_update_attack_nodes(bulk_upd_req2)
ok(resp_bulk_upd2.success is True, "Bulk update partial 404 returns success=True")
ru2 = resp_bulk_upd2.data
eq(ru2["successCount"], 1, "Bulk update partial 404: 1 succeeded")
eq(ru2["failCount"], 1, "Bulk update partial 404: 1 failed")
ok(ru2["failed"][0]["reason"] == "Node not found.", "Bulk update failed reason='Node not found.'")

# Bulk update empty items — Pydantic validation
try:
    bad_upd = BulkUpdateAttackNodesRequest(items=[])
    resp_bad_upd = bulk_update_attack_nodes(bad_upd)
    ok(resp_bad_upd.success is False, "Bulk update empty items fails")
except Exception:
    ok(True, "Bulk update empty items raises Pydantic validation error")


# ===========================================================================
# 14. Bulk Delete
# ===========================================================================

section("14. DELETE /attack-graph/bulk/delete")

count_before = len(_NODE_STORE)
ok(count_before >= 3, f"Setup: at least 3 nodes before bulk delete (got {count_before})")

# Pick 3 node IDs to delete
ids_to_del = all_ids[:3]

bulk_del_req = BulkDeleteAttackNodesRequest(nodeIds=ids_to_del)
resp_bulk_del = bulk_delete_attack_nodes(bulk_del_req)
ok(resp_bulk_del.success is True, "bulk_delete_attack_nodes returns success=True")
rd = resp_bulk_del.data

eq(rd["total"], 3, "Bulk delete total=3")
eq(rd["successCount"], 3, "Bulk delete successCount=3")
eq(rd["failCount"], 0, "Bulk delete failCount=0")
eq(len(rd["succeeded"]), 3, "Bulk delete succeeded list has 3 IDs")

eq(len(_NODE_STORE), count_before - 3, "Bulk delete removed 3 nodes from store")
for nid in ids_to_del:
    ok(nid not in _NODE_STORE, f"Bulk delete removed node {nid}")

# Bulk delete with nonexistent ID
bulk_del_req2 = BulkDeleteAttackNodesRequest(nodeIds=["nonexistent_xyz"])
resp_bulk_del2 = bulk_delete_attack_nodes(bulk_del_req2)
ok(resp_bulk_del2.success is True, "Bulk delete nonexistent node returns success=True")
rd2 = resp_bulk_del2.data
eq(rd2["successCount"], 0, "Bulk delete nonexistent: successCount=0")
eq(rd2["failCount"], 1, "Bulk delete nonexistent: failCount=1")
ok(rd2["failed"][0]["reason"] == "Node not found.", "Bulk delete failed reason='Node not found.'")

# Bulk delete partial success
if len(_NODE_STORE) > 0:
    valid_id = list(_NODE_STORE.keys())[0]
    bulk_del_req3 = BulkDeleteAttackNodesRequest(nodeIds=[valid_id, "nonexistent_abc"])
    resp_bulk_del3 = bulk_delete_attack_nodes(bulk_del_req3)
    ok(resp_bulk_del3.success is True, "Bulk delete partial returns success=True")
    rd3 = resp_bulk_del3.data
    eq(rd3["successCount"], 1, "Bulk delete partial: successCount=1")
    eq(rd3["failCount"], 1, "Bulk delete partial: failCount=1")

# Bulk delete empty list — Pydantic validation
try:
    bad_del = BulkDeleteAttackNodesRequest(nodeIds=[])
    resp_bad_del = bulk_delete_attack_nodes(bad_del)
    ok(resp_bad_del.success is False, "Bulk delete empty nodeIds fails")
except Exception:
    ok(True, "Bulk delete empty nodeIds raises Pydantic validation error")


# ===========================================================================
# 15. Graph Utilities — get_connected_nodes / get_node_relationships /
#                       get_neighbor_nodes
# ===========================================================================

section("15. Graph Utilities — helpers")

_setup()

# Build a small graph
node_a = _create_node("ASSET",    "node-a", riskScore=70)
node_b = _create_node("ASSET",    "node-b", riskScore=50)
node_c = _create_node("EVIDENCE", "node-c", riskScore=30)
node_d = _create_node("IP",       "node-d", riskScore=20)

id_a = node_a["nodeId"]
id_b = node_b["nodeId"]
id_c = node_c["nodeId"]
id_d = node_d["nodeId"]

# Edges: a→b, a→c, d→a
_create_edge("edge-ab", id_a, id_b, "COMMUNICATES_WITH")
_create_edge("edge-ac", id_a, id_c, "GENERATES")
_create_edge("edge-da", id_d, id_a, "OBSERVED_IN")

# --- get_connected_nodes() ---
connected_a = get_connected_nodes(id_a)
connected_ids_a = {n["nodeId"] for n in connected_a}
ok(id_b in connected_ids_a, "get_connected_nodes(a): includes b (outbound)")
ok(id_c in connected_ids_a, "get_connected_nodes(a): includes c (outbound)")
ok(id_d in connected_ids_a, "get_connected_nodes(a): includes d (inbound)")
ok(id_a not in connected_ids_a, "get_connected_nodes(a): does not include a itself")
eq(len(connected_a), 3, "get_connected_nodes(a): 3 connected nodes")

connected_b = get_connected_nodes(id_b)
connected_ids_b = {n["nodeId"] for n in connected_b}
ok(id_a in connected_ids_b, "get_connected_nodes(b): includes a")
eq(len(connected_b), 1, "get_connected_nodes(b): only 1 connected node")

# Isolated node (d has edge to a but get_connected checks both directions)
connected_d = get_connected_nodes(id_d)
ok(id_a in {n["nodeId"] for n in connected_d}, "get_connected_nodes(d): includes a (outbound from d)")

# Non-existent node returns empty
connected_none = get_connected_nodes("nonexistent_xyz")
eq(len(connected_none), 0, "get_connected_nodes nonexistent node returns empty list")

# Returns are sorted by nodeId
ok(connected_a == sorted(connected_a, key=lambda n: n.get("nodeId", "")),
   "get_connected_nodes returns nodes sorted by nodeId")

# --- get_node_relationships() ---
rels_a = get_node_relationships(id_a)
eq(len(rels_a), 3, "get_node_relationships(a): 3 edges involve node a")

rels_b = get_node_relationships(id_b)
eq(len(rels_b), 1, "get_node_relationships(b): 1 edge involves node b")

rels_none = get_node_relationships("nonexistent_xyz")
eq(len(rels_none), 0, "get_node_relationships nonexistent returns empty list")

# Edge dicts have expected keys
if rels_a:
    e = rels_a[0]
    ok("edgeId" in e, "Relationship edge has edgeId")
    ok("sourceNodeId" in e, "Relationship edge has sourceNodeId")
    ok("targetNodeId" in e, "Relationship edge has targetNodeId")
    ok("edgeType" in e, "Relationship edge has edgeType")

# Sorted by edgeId
ok(rels_a == sorted(rels_a, key=lambda e: e.get("edgeId", "")),
   "get_node_relationships returns edges sorted by edgeId")

# --- get_neighbor_nodes() ---
neighbors_a = get_neighbor_nodes(id_a)
ok("inbound" in neighbors_a, "get_neighbor_nodes returns 'inbound' key")
ok("outbound" in neighbors_a, "get_neighbor_nodes returns 'outbound' key")

outbound_ids = {n["nodeId"] for n in neighbors_a["outbound"]}
inbound_ids  = {n["nodeId"] for n in neighbors_a["inbound"]}

ok(id_b in outbound_ids, "get_neighbor_nodes(a) outbound includes b")
ok(id_c in outbound_ids, "get_neighbor_nodes(a) outbound includes c")
ok(id_d in inbound_ids,  "get_neighbor_nodes(a) inbound includes d")
ok(id_a not in outbound_ids, "get_neighbor_nodes(a) outbound does not include a")
ok(id_a not in inbound_ids,  "get_neighbor_nodes(a) inbound does not include a")

eq(len(neighbors_a["outbound"]), 2, "get_neighbor_nodes(a) outbound count=2")
eq(len(neighbors_a["inbound"]),  1, "get_neighbor_nodes(a) inbound count=1")

neighbors_b = get_neighbor_nodes(id_b)
eq(len(neighbors_b["inbound"]), 1,  "get_neighbor_nodes(b) inbound count=1 (from a)")
eq(len(neighbors_b["outbound"]), 0, "get_neighbor_nodes(b) outbound count=0 (no out-edges)")

neighbors_none = get_neighbor_nodes("nonexistent_xyz")
eq(len(neighbors_none["inbound"]), 0,  "get_neighbor_nodes nonexistent inbound is empty")
eq(len(neighbors_none["outbound"]), 0, "get_neighbor_nodes nonexistent outbound is empty")


# ===========================================================================
# 16. Graph Utilities — /neighbors and /relationships endpoints
# ===========================================================================

section("16. GET /attack-graph/{nodeId}/neighbors and /relationships")

# GET /neighbors
resp_neighbors = get_attack_node_neighbors(id_a)
ok(resp_neighbors.success is True, "get_attack_node_neighbors returns success=True")
ok("inbound" in resp_neighbors.data, "/neighbors response has 'inbound'")
ok("outbound" in resp_neighbors.data, "/neighbors response has 'outbound'")
ok("inboundCount" in resp_neighbors.data, "/neighbors response has 'inboundCount'")
ok("outboundCount" in resp_neighbors.data, "/neighbors response has 'outboundCount'")
ok("nodeId" in resp_neighbors.data, "/neighbors response has 'nodeId'")

eq(resp_neighbors.data["nodeId"], id_a, "/neighbors nodeId matches requested")
eq(resp_neighbors.data["inboundCount"], 1, "/neighbors inboundCount=1 for node a")
eq(resp_neighbors.data["outboundCount"], 2, "/neighbors outboundCount=2 for node a")

# GET /neighbors 404
resp_neighbors_404 = get_attack_node_neighbors("nonexistent_node")
ok(resp_neighbors_404.success is False, "/neighbors nonexistent node returns success=False")
ok("not found" in resp_neighbors_404.message.lower(), "/neighbors 404 message mentions not found")

# GET /relationships
resp_rels = get_attack_node_relationships(id_a)
ok(resp_rels.success is True, "get_attack_node_relationships returns success=True")
ok("relationships" in resp_rels.data, "/relationships response has 'relationships'")
ok("count" in resp_rels.data, "/relationships response has 'count'")
ok("nodeId" in resp_rels.data, "/relationships response has 'nodeId'")

eq(resp_rels.data["nodeId"], id_a, "/relationships nodeId matches requested")
eq(resp_rels.data["count"], 3, "/relationships count=3 for node a")
eq(len(resp_rels.data["relationships"]), 3, "/relationships returns 3 edge dicts")

# GET /relationships 404
resp_rels_404 = get_attack_node_relationships("nonexistent_node")
ok(resp_rels_404.success is False, "/relationships nonexistent node returns success=False")
ok("not found" in resp_rels_404.message.lower(), "/relationships 404 message mentions not found")


# ===========================================================================
# 17. Determinism & Stability
# ===========================================================================

section("17. Determinism & Stability")

_setup()

# Same nodeType + label → same nodeId deterministically
req_det_1 = CreateAttackNodeRequest(nodeType="ASSET", label="deterministic-test", riskScore=50)
resp_det_1 = create_attack_node(req_det_1)
ok(resp_det_1.success is True, "Determinism setup: first create succeeds")
node_id_det_1 = resp_det_1.data["nodeId"]

# Delete and recreate
delete_attack_node(node_id_det_1)
req_det_2 = CreateAttackNodeRequest(nodeType="ASSET", label="deterministic-test", riskScore=75)
resp_det_2 = create_attack_node(req_det_2)
ok(resp_det_2.success is True, "Determinism setup: recreate succeeds")
node_id_det_2 = resp_det_2.data["nodeId"]

eq(node_id_det_1, node_id_det_2, "Determinism: same nodeType+label produces same nodeId")

# Different namespace → different nodeId
req_ns_1 = CreateAttackNodeRequest(nodeType="ASSET", label="ns-test", namespace="project-a")
resp_ns_1 = create_attack_node(req_ns_1)
req_ns_2 = CreateAttackNodeRequest(nodeType="ASSET", label="ns-test", namespace="project-b")
resp_ns_2 = create_attack_node(req_ns_2)
ok(resp_ns_1.success and resp_ns_2.success, "Determinism: namespace creates succeed")
ok(resp_ns_1.data["nodeId"] != resp_ns_2.data["nodeId"],
   "Determinism: different namespaces produce different nodeIds")

# nodeId length is always 32 chars (SHA-256 truncated)
for _ in range(5):
    req_r = CreateAttackNodeRequest(nodeType="IP", label=f"random-{_}", riskScore=10)
    resp_r = create_attack_node(req_r)
    if resp_r.success:
        ok(len(resp_r.data["nodeId"]) == 32, f"nodeId is 32 chars for node {_}")

# nodeKey == nodeId always
all_current = list(_NODE_STORE.values())
for n in all_current:
    ok(n.get("nodeKey") == n.get("nodeId"), "nodeKey == nodeId for all nodes")

# Sort order is stable
nodes_1 = sort_attack_nodes(all_current, "riskScore", "asc")
nodes_2 = sort_attack_nodes(all_current, "riskScore", "asc")
ids_1 = [n["nodeId"] for n in nodes_1]
ids_2 = [n["nodeId"] for n in nodes_2]
ok(ids_1 == ids_2, "sort_attack_nodes produces stable order on repeated calls")

# Filter output order is stable (insertion-order preserved)
filtered_1 = filter_attack_nodes(all_current, min_risk=10)
filtered_2 = filter_attack_nodes(all_current, min_risk=10)
fids_1 = [n["nodeId"] for n in filtered_1]
fids_2 = [n["nodeId"] for n in filtered_2]
ok(fids_1 == fids_2, "filter_attack_nodes produces stable order on repeated calls")


# ===========================================================================
# 18. Model Validation & Serialization
# ===========================================================================

section("18. Model Validation & Serialization")

# CreateAttackNodeRequest — riskScore bounds
req_score_ok = CreateAttackNodeRequest(nodeType="ASSET", label="score-test", riskScore=0)
eq(req_score_ok.riskScore, 0, "CreateAttackNodeRequest riskScore=0 accepted")

req_score_max = CreateAttackNodeRequest(nodeType="ASSET", label="score-max", riskScore=100)
eq(req_score_max.riskScore, 100, "CreateAttackNodeRequest riskScore=100 accepted")

# riskScore > 100 or < 0 should raise Pydantic validation error
try:
    bad_score = CreateAttackNodeRequest(nodeType="ASSET", label="bad", riskScore=101)
    ok(False, "CreateAttackNodeRequest riskScore=101 should raise ValidationError")
except Exception:
    ok(True, "CreateAttackNodeRequest riskScore=101 raises ValidationError")

try:
    bad_score2 = CreateAttackNodeRequest(nodeType="ASSET", label="bad2", riskScore=-1)
    ok(False, "CreateAttackNodeRequest riskScore=-1 should raise ValidationError")
except Exception:
    ok(True, "CreateAttackNodeRequest riskScore=-1 raises ValidationError")

# UpdateAttackNodeRequest.has_any_field()
upd_empty = UpdateAttackNodeRequest()
ok(upd_empty.has_any_field() is False, "UpdateAttackNodeRequest.has_any_field() False when all None")

upd_one = UpdateAttackNodeRequest(riskScore=50)
ok(upd_one.has_any_field() is True, "UpdateAttackNodeRequest.has_any_field() True with riskScore")

upd_display = UpdateAttackNodeRequest(displayName="Test")
ok(upd_display.has_any_field() is True, "UpdateAttackNodeRequest.has_any_field() True with displayName")

# AttackNodeResponse model fields
_setup()
n = _create_node("ASSET", "serial-test", riskScore=42, confidence=88, metadata={"k": "v"})
ok(isinstance(n["nodeId"], str), "AttackNodeResponse nodeId is str")
ok(isinstance(n["nodeKey"], str), "AttackNodeResponse nodeKey is str")
ok(isinstance(n["nodeType"], str), "AttackNodeResponse nodeType is str")
ok(isinstance(n["label"], str), "AttackNodeResponse label is str")
ok(isinstance(n["displayName"], str), "AttackNodeResponse displayName is str")
ok(isinstance(n["riskScore"], int), "AttackNodeResponse riskScore is int")
ok(isinstance(n["confidence"], int), "AttackNodeResponse confidence is int")
ok(isinstance(n["metadata"], dict), "AttackNodeResponse metadata is dict")
ok(isinstance(n["createdAt"], str), "AttackNodeResponse createdAt is str")

# nodeType is a plain string in response (not enum)
ok(n["nodeType"] == "ASSET", "AttackNodeResponse nodeType is plain string 'ASSET'")

# metadata roundtrip
ok(n["metadata"]["k"] == "v", "AttackNodeResponse metadata roundtrip preserves keys")

# AttackGraphStatisticsResponse fields
stats = get_attack_graph_statistics().data
ok(isinstance(stats["totalNodes"], int), "Statistics totalNodes is int")
ok(isinstance(stats["nodeTypeCounts"], dict), "Statistics nodeTypeCounts is dict")
ok(isinstance(stats["nodeTypeCount"], dict), "Statistics nodeTypeCount is dict")
ok(isinstance(stats["relationshipCounts"], dict), "Statistics relationshipCounts is dict")
ok(isinstance(stats["relationshipCount"], int), "Statistics relationshipCount is int")
ok(isinstance(stats["averageRiskScore"], float), "Statistics averageRiskScore is float")
ok(isinstance(stats["averageConfidence"], float), "Statistics averageConfidence is float")


# ===========================================================================
# 19. Edge Cases
# ===========================================================================

section("19. Edge Cases")

_setup()

# Empty store list
resp_empty = list_attack_nodes()
ok(resp_empty.success is True, "list_attack_nodes on empty store returns success=True")
eq(resp_empty.data["total"], 0, "list_attack_nodes on empty store has total=0")
eq(len(resp_empty.data["nodes"]), 0, "list_attack_nodes on empty store returns empty nodes list")

# Empty store statistics
resp_stats_empty = get_attack_graph_statistics()
ok(resp_stats_empty.success is True, "get_attack_graph_statistics on empty store succeeds")
eq(resp_stats_empty.data["totalNodes"], 0, "Statistics on empty store: totalNodes=0")
eq(resp_stats_empty.data["averageRiskScore"], 0.0, "Statistics on empty store: averageRiskScore=0.0")
eq(resp_stats_empty.data["averageConfidence"], 0.0, "Statistics on empty store: averageConfidence=0.0")

# Search on empty store
resp_search_empty = search_attack_nodes(q="anything")
ok(resp_search_empty.success is True, "search_attack_nodes on empty store succeeds")
eq(resp_search_empty.data["total"], 0, "search_attack_nodes on empty store: total=0")

# Create node with minimal fields (only required)
req_minimal = CreateAttackNodeRequest(nodeType="IP", label="10.0.0.1")
resp_minimal = create_attack_node(req_minimal)
ok(resp_minimal.success is True, "create_attack_node with minimal fields succeeds")
ok(resp_minimal.data["riskScore"] == 0, "Minimal node has riskScore=0 default")
ok(resp_minimal.data["confidence"] == 0, "Minimal node has confidence=0 default")
ok(resp_minimal.data["displayName"] == "10.0.0.1", "Minimal node displayName defaults to label")

# Create node with all optional fields
req_maximal = CreateAttackNodeRequest(
    nodeType="ASSET",
    label="maximal-test",
    displayName="Maximal Test Node",
    riskScore=85,
    confidence=95,
    metadata={"key1": "val1", "key2": 42},
    namespace="test-ns",
)
resp_maximal = create_attack_node(req_maximal)
ok(resp_maximal.success is True, "create_attack_node with all fields succeeds")
ok(resp_maximal.data["displayName"] == "Maximal Test Node", "Maximal node displayName set")
ok(resp_maximal.data["metadata"]["key1"] == "val1", "Maximal node metadata key1")
ok(resp_maximal.data["metadata"]["key2"] == 42, "Maximal node metadata key2")

# Update single field
node_id_single = resp_maximal.data["nodeId"]
req_upd_single = UpdateAttackNodeRequest(riskScore=10)
resp_upd_single = update_attack_node(node_id_single, req_upd_single)
ok(resp_upd_single.success is True, "update_attack_node single field succeeds")
ok(resp_upd_single.data["riskScore"] == 10, "Update single field changes riskScore")
ok(resp_upd_single.data["displayName"] == "Maximal Test Node", "Update single field preserves displayName")
ok(resp_upd_single.data["confidence"] == 95, "Update single field preserves confidence")

# Whitespace-only nodeType
req_ws_type = CreateAttackNodeRequest(nodeType="   ", label="test")
resp_ws_type = create_attack_node(req_ws_type)
ok(resp_ws_type.success is False, "create_attack_node rejects whitespace-only nodeType")

# Whitespace-only label
req_ws_label = CreateAttackNodeRequest(nodeType="ASSET", label="   ")
resp_ws_label = create_attack_node(req_ws_label)
ok(resp_ws_label.success is False, "create_attack_node rejects whitespace-only label")

# Empty metadata dict
req_empty_meta = CreateAttackNodeRequest(nodeType="IP", label="10.0.0.2", metadata={})
resp_empty_meta = create_attack_node(req_empty_meta)
ok(resp_empty_meta.success is True, "create_attack_node accepts empty metadata dict")
ok(resp_empty_meta.data["metadata"] == {}, "Empty metadata dict serialized correctly")

# Sorting empty list
sorted_empty = sort_attack_nodes([], "riskScore", "asc")
eq(len(sorted_empty), 0, "sort_attack_nodes on empty list returns empty")

# Filtering empty list
filtered_empty = filter_attack_nodes([], node_type="ASSET")
eq(len(filtered_empty), 0, "filter_attack_nodes on empty list returns empty")

# Pagination empty list
page_empty, pag_empty = paginate_attack_nodes([], 1, 20)
eq(len(page_empty), 0, "paginate_attack_nodes on empty list returns empty slice")
eq(pag_empty.totalPages, 0, "paginate_attack_nodes on empty list: totalPages=0")

# Special characters in label
req_special = CreateAttackNodeRequest(nodeType="DOMAIN", label="evil.com/?param=value&x=y")
resp_special = create_attack_node(req_special)
ok(resp_special.success is True, "create_attack_node accepts special chars in label")
ok(resp_special.data["label"] == "evil.com/?param=value&x=y", "Special chars preserved in label")

# Unicode in label
req_unicode = CreateAttackNodeRequest(nodeType="USER", label="user-名前")
resp_unicode = create_attack_node(req_unicode)
ok(resp_unicode.success is True, "create_attack_node accepts Unicode in label")
ok(resp_unicode.data["label"] == "user-名前", "Unicode preserved in label")


# ===========================================================================
# 20. All GraphNodeTypeEnum Values Accepted
# ===========================================================================

section("20. All GraphNodeTypeEnum Values Accepted")

_setup()

valid_types = [
    "ASSET", "EVIDENCE", "FINDING", "ALERT", "MITRE",
    "DOMAIN", "IP", "URL", "HASH", "EMAIL",
    "USER", "PROCESS", "SERVICE", "PORT", "EXTERNAL_HOST", "UNKNOWN",
]

for i, nt in enumerate(valid_types):
    req = CreateAttackNodeRequest(nodeType=nt, label=f"type-test-{i}-{nt.lower()}")
    resp = create_attack_node(req)
    ok(resp.success is True, f"create_attack_node accepts nodeType={nt}")
    ok(resp.data["nodeType"] == nt, f"Response nodeType == {nt}")

ok(len(_NODE_STORE) == len(valid_types), f"All {len(valid_types)} node types created successfully")

# Statistics reflects all node types
resp_stats_all = get_attack_graph_statistics()
s = resp_stats_all.data
eq(s["totalNodes"], len(valid_types), f"Statistics totalNodes={len(valid_types)}")
for nt in valid_types:
    ok(nt in s["nodeTypeCounts"], f"nodeTypeCounts includes {nt}")
    eq(s["nodeTypeCounts"][nt], 1, f"nodeTypeCounts[{nt}]=1")


# ===========================================================================
# 21. Integrated Search + Sort + Filter + Pagination
# ===========================================================================

section("21. Integrated Search + Sort + Filter + Pagination")

_setup()

# Create 10 nodes for integration test
for i in range(10):
    node_type = ["ASSET", "EVIDENCE", "FINDING", "IP", "ALERT"][i % 5]
    _create_node(
        node_type,
        f"target-node-{i:02d}",
        displayName=f"Target {node_type} Node {i:02d}",
        riskScore=i * 10,
        confidence=100 - (i * 9),
    )

# Full pipeline: search 'target' → filter risk >= 30 → sort riskScore DESC → page 1 size 3
resp_int = search_attack_nodes(
    q="target",
    sort_by="riskScore",
    sort_order="desc",
    page=1,
    page_size=3,
    min_risk_filter=30,
)
ok(resp_int.success is True, "Integrated search+filter+sort+paginate succeeds")
d = resp_int.data

ok(d["total"] >= 7, "Integrated: at least 7 nodes match risk >= 30")
eq(len(d["nodes"]), 3, "Integrated: page_size=3 returns 3 nodes")
if len(d["nodes"]) >= 2:
    risks = [n["riskScore"] for n in d["nodes"]]
    ok(risks == sorted(risks, reverse=True), "Integrated: nodes sorted by riskScore DESC")

ok(all(n["riskScore"] >= 30 for n in d["nodes"]), "Integrated: all returned nodes have risk >= 30")
eq(d["page"], 1, "Integrated: page=1")
eq(d["pageSize"], 3, "Integrated: pageSize=3")
ok(d["totalPages"] >= 3, "Integrated: totalPages >= 3 for 7+ nodes at page_size=3")

# Second page
resp_int_p2 = search_attack_nodes(
    q="target",
    sort_by="riskScore",
    sort_order="desc",
    page=2,
    page_size=3,
    min_risk_filter=30,
)
ok(resp_int_p2.success is True, "Integrated page 2 succeeds")
eq(resp_int_p2.data["page"], 2, "Integrated: page=2 in response")
if len(resp_int_p2.data["nodes"]) >= 1:
    # Page 2 should have lower risks than page 1 (sorted DESC)
    max_risk_p2 = max(n["riskScore"] for n in resp_int_p2.data["nodes"])
    min_risk_p1 = min(n["riskScore"] for n in d["nodes"])
    ok(max_risk_p2 <= min_risk_p1, "Integrated: page 2 has lower or equal risks than page 1 (sorted DESC)")

# Filter by nodeType within search
resp_int_type = search_attack_nodes(
    q="target",
    sort_by="riskScore",
    sort_order="asc",
    page=1,
    page_size=10,
    node_type_filter="ASSET",
)
ok(resp_int_type.success is True, "Integrated search + nodeType filter succeeds")
ok(all(n["nodeType"] == "ASSET" for n in resp_int_type.data["nodes"]),
   "Integrated: all returned nodes are ASSET type")


# ===========================================================================
# 22. Additional Bulk Operation Edge Cases
# ===========================================================================

section("22. Additional Bulk Operation Edge Cases")

_setup()

# Bulk create: mix of valid and invalid
bulk_mix = BulkCreateAttackNodesRequest(nodes=[
    CreateAttackNodeRequest(nodeType="ASSET", label="valid-1", riskScore=50),
    CreateAttackNodeRequest(nodeType="IP", label="valid-2", riskScore=30),
])

resp_mix = bulk_create_attack_nodes(bulk_mix)
ok(resp_mix.success is True, "Bulk create valid nodes succeeds")
rm = resp_mix.data
ok(rm["successCount"] == 2, "Bulk create valid: 2 succeeded")
eq(rm["total"], 2, "Bulk create valid: total=2")

# Bulk update with empty update — should fail validation
id_any = list(_NODE_STORE.keys())[0] if _NODE_STORE else "dummy"
bulk_upd_empty = BulkUpdateAttackNodesRequest(items=[
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=id_any,
        update=UpdateAttackNodeRequest(),  # all None
    ),
])
resp_upd_empty = bulk_update_attack_nodes(bulk_upd_empty)
ok(resp_upd_empty.success is False or resp_upd_empty.data["failCount"] == 1,
   "Bulk update with empty update body fails or records failure")

# Bulk delete: all nonexistent
bulk_del_none = BulkDeleteAttackNodesRequest(nodeIds=[
    "nonexistent-1", "nonexistent-2", "nonexistent-3"
])
resp_del_none = bulk_delete_attack_nodes(bulk_del_none)
ok(resp_del_none.success is True, "Bulk delete all nonexistent returns success=True")
eq(resp_del_none.data["successCount"], 0, "Bulk delete all nonexistent: successCount=0")
eq(resp_del_none.data["failCount"], 3, "Bulk delete all nonexistent: failCount=3")


# ===========================================================================
# 23. More Sorting Variants
# ===========================================================================

section("23. More Sorting Variants")

_setup()
for i in range(6):
    _create_node("ASSET", f"sort-node-{i}", riskScore=i * 15, confidence=100 - i * 10)

all_n = list(_NODE_STORE.values())

# Sort by confidence ASC
by_conf_asc = sort_attack_nodes(all_n, "confidence", "asc")
conf_vals = [n["confidence"] for n in by_conf_asc]
ok(conf_vals == sorted(conf_vals), "sort confidence ASC is ascending")

# Sort by confidence DESC
by_conf_desc = sort_attack_nodes(all_n, "confidence", "desc")
conf_vals_desc = [n["confidence"] for n in by_conf_desc]
ok(conf_vals_desc == sorted(conf_vals_desc, reverse=True), "sort confidence DESC is descending")

# Sort by label case-insensitive
_create_node("IP", "Zebra", riskScore=10)
_create_node("IP", "alpha", riskScore=20)
_create_node("IP", "Beta", riskScore=30)
all_n2 = list(_NODE_STORE.values())
by_label = sort_attack_nodes(all_n2, "label", "asc")
labels = [n["label"].lower() for n in by_label]
ok(labels == sorted(labels), "sort by label is case-insensitive")

# Sort by createdAt DESC
by_created_desc = sort_attack_nodes(all_n2, "createdAt", "desc")
ok(len(by_created_desc) == len(all_n2), "sort by createdAt DESC returns all nodes")

# Sort by unknown field falls back to label
by_unknown = sort_attack_nodes(all_n, "unknown_field_xyz", "asc")
ok(len(by_unknown) == len(all_n), "sort by unknown field returns all nodes (fallback)")


# ===========================================================================
# 24. More Filtering Variants
# ===========================================================================

section("24. More Filtering Variants")

all_n = list(_NODE_STORE.values())

# Filter by exact risk score
risk_20 = filter_attack_nodes(all_n, min_risk=20, max_risk=20)
ok(all(n["riskScore"] == 20 for n in risk_20), "filter exact risk=20")

# Filter by exact confidence
conf_50 = filter_attack_nodes(all_n, min_confidence=50, max_confidence=50)
ok(all(n["confidence"] == 50 for n in conf_50), "filter exact confidence=50")

# Filter combined: type + risk + confidence
combined = filter_attack_nodes(all_n, node_type="ASSET", min_risk=10, max_risk=80, min_confidence=20)
ok(all(n["nodeType"] == "ASSET" for n in combined), "filter combined: all ASSET")
ok(all(10 <= n["riskScore"] <= 80 for n in combined), "filter combined: risk in [10,80]")
ok(all(n["confidence"] >= 20 for n in combined), "filter combined: confidence >= 20")

# Filter no matching nodes
no_match = filter_attack_nodes(all_n, node_type="NONEXISTENT_TYPE_XYZ")
eq(len(no_match), 0, "filter no matching nodes returns empty list")

# Filter with nodeType case variations
assets_upper = filter_attack_nodes(all_n, node_type="ASSET")
assets_lower = filter_attack_nodes(all_n, node_type="asset")
assets_mixed = filter_attack_nodes(all_n, node_type="AsSeT")
ok(len(assets_upper) == len(assets_lower) == len(assets_mixed),
   "filter nodeType is case-insensitive (same count)")


# ===========================================================================
# 25. APIResponse Metadata & Message Consistency
# ===========================================================================

section("25. APIResponse Metadata & Message Consistency")

_setup()
_create_node("ASSET", "api-test-1", riskScore=75)

# All success responses have success=True
resp_list = list_attack_nodes()
ok(resp_list.success is True, "list_attack_nodes success=True")
ok(isinstance(resp_list.message, str), "list_attack_nodes message is str")

resp_stats = get_attack_graph_statistics()
ok(resp_stats.success is True, "get_attack_graph_statistics success=True")
ok(isinstance(resp_stats.message, str), "get_attack_graph_statistics message is str")

# Error responses have success=False
resp_404 = get_attack_node("nonexistent")
ok(resp_404.success is False, "get_attack_node 404 success=False")
ok(isinstance(resp_404.message, str), "get_attack_node 404 message is str")
ok(len(resp_404.message) > 0, "get_attack_node 404 message is non-empty")

# Message describes the operation
ok("not found" in resp_404.message.lower(), "404 message mentions 'not found'")

# Successful create message
req_c = CreateAttackNodeRequest(nodeType="IP", label="10.0.0.1")
resp_c = create_attack_node(req_c)
ok("created" in resp_c.message.lower(), "create message mentions 'created'")

# Successful update message
nid = resp_c.data["nodeId"]
resp_u = update_attack_node(nid, UpdateAttackNodeRequest(riskScore=50))
ok("updated" in resp_u.message.lower(), "update message mentions 'updated'")

# Successful delete message
resp_d = delete_attack_node(nid)
ok("deleted" in resp_d.message.lower(), "delete message mentions 'deleted'")


# ===========================================================================
# 26. _reset_store() Test Utility
# ===========================================================================

section("26. _reset_store() Test Utility")

_setup()
_create_node("ASSET", "reset-test-1")
_create_node("IP", "reset-test-2")
_create_edge("e-reset", list(_NODE_STORE.keys())[0], list(_NODE_STORE.keys())[1])

ok(len(_NODE_STORE) > 0, "Before reset: nodes present")
ok(len(_EDGE_STORE) > 0, "Before reset: edges present")

_reset_store()

eq(len(_NODE_STORE), 0, "After reset: _NODE_STORE is empty")
eq(len(_EDGE_STORE), 0, "After reset: _EDGE_STORE is empty")


# ===========================================================================
# 27. Response Structure Contract
# ===========================================================================

section("27. Response Structure Contract — APIResponse fields")

_setup()
_create_node("ASSET", "contract-node-1", riskScore=42, confidence=88)

# Every endpoint returns APIResponse with required fields
def _check_api_response(resp: APIResponse, label: str) -> None:
    ok(hasattr(resp, "success"),   f"{label}: has .success")
    ok(hasattr(resp, "message"),   f"{label}: has .message")
    ok(hasattr(resp, "data"),      f"{label}: has .data")
    ok(isinstance(resp.success, bool), f"{label}: .success is bool")
    ok(isinstance(resp.message, str),  f"{label}: .message is str")

nid = list(_NODE_STORE.keys())[0]

_check_api_response(list_attack_nodes(),                                           "list_attack_nodes")
_check_api_response(get_attack_graph_statistics(),                                 "get_statistics")
_check_api_response(get_attack_node(nid),                                          "get_attack_node OK")
_check_api_response(get_attack_node("no-id"),                                      "get_attack_node 404")
_check_api_response(create_attack_node(CreateAttackNodeRequest(nodeType="IP", label="c-1")), "create OK")
_check_api_response(create_attack_node(CreateAttackNodeRequest(nodeType="IP", label="c-1")), "create 409")
_check_api_response(update_attack_node(nid, UpdateAttackNodeRequest(riskScore=50)),  "update OK")
_check_api_response(update_attack_node("no-id", UpdateAttackNodeRequest(riskScore=50)), "update 404")
_check_api_response(update_attack_node(nid, UpdateAttackNodeRequest()),            "update 422")
_check_api_response(search_attack_nodes(q="contract"),                             "search OK")
_check_api_response(search_attack_nodes(q=""),                                     "search 422")
_check_api_response(get_attack_node_neighbors(nid),                                "neighbors OK")
_check_api_response(get_attack_node_neighbors("no-id"),                            "neighbors 404")
_check_api_response(get_attack_node_relationships(nid),                            "relationships OK")
_check_api_response(get_attack_node_relationships("no-id"),                        "relationships 404")

nid2 = list(_NODE_STORE.keys())[0]
_check_api_response(delete_attack_node(nid2),                                      "delete OK")
_check_api_response(delete_attack_node(nid2),                                      "delete 404 (already gone)")


# ===========================================================================
# 28. BulkOperationResult Schema
# ===========================================================================

section("28. BulkOperationResult Schema Completeness")

_setup()

# Bulk create 4 nodes
bulk_schema_req = BulkCreateAttackNodesRequest(nodes=[
    CreateAttackNodeRequest(nodeType="ASSET",    label="schema-a"),
    CreateAttackNodeRequest(nodeType="EVIDENCE", label="schema-b"),
    CreateAttackNodeRequest(nodeType="FINDING",  label="schema-c"),
    CreateAttackNodeRequest(nodeType="IP",       label="schema-d"),
])
resp_schema = bulk_create_attack_nodes(bulk_schema_req)
bdata = resp_schema.data

# All required keys present
ok("succeeded" in bdata,    "BulkResult: 'succeeded' key present")
ok("failed" in bdata,       "BulkResult: 'failed' key present")
ok("total" in bdata,        "BulkResult: 'total' key present")
ok("successCount" in bdata, "BulkResult: 'successCount' key present")
ok("failCount" in bdata,    "BulkResult: 'failCount' key present")

# Types
ok(isinstance(bdata["succeeded"], list),    "BulkResult: succeeded is list")
ok(isinstance(bdata["failed"], list),       "BulkResult: failed is list")
ok(isinstance(bdata["total"], int),         "BulkResult: total is int")
ok(isinstance(bdata["successCount"], int),  "BulkResult: successCount is int")
ok(isinstance(bdata["failCount"], int),     "BulkResult: failCount is int")

# succeeded contains nodeId strings
for sid in bdata["succeeded"]:
    ok(isinstance(sid, str), f"BulkResult: succeeded entry {sid!r} is str")
    ok(len(sid) == 32, f"BulkResult: succeeded entry {sid!r} is 32-char nodeId")

# Arithmetic consistency
eq(bdata["successCount"], len(bdata["succeeded"]), "BulkResult: successCount == len(succeeded)")
eq(bdata["failCount"], len(bdata["failed"]), "BulkResult: failCount == len(failed)")
eq(bdata["total"], bdata["successCount"] + bdata["failCount"], "BulkResult: total = success + fail")

# Bulk update schema
all_ids = list(_NODE_STORE.keys())
bulk_upd_schema = BulkUpdateAttackNodesRequest(items=[
    BulkUpdateAttackNodesRequest.BulkUpdateItem(
        nodeId=all_ids[0], update=UpdateAttackNodeRequest(riskScore=55)
    ),
])
upd_schema_resp = bulk_update_attack_nodes(bulk_upd_schema)
ud = upd_schema_resp.data
ok(isinstance(ud["succeeded"], list), "BulkUpdate: succeeded is list")
ok(isinstance(ud["failed"], list),    "BulkUpdate: failed is list")
ok(isinstance(ud["total"], int),      "BulkUpdate: total is int")

# Bulk delete schema
bulk_del_schema = BulkDeleteAttackNodesRequest(nodeIds=[all_ids[0]])
del_schema_resp = bulk_delete_attack_nodes(bulk_del_schema)
dd = del_schema_resp.data
ok(isinstance(dd["succeeded"], list), "BulkDelete: succeeded is list")
ok(isinstance(dd["failed"], list),    "BulkDelete: failed is list")
ok(isinstance(dd["total"], int),      "BulkDelete: total is int")


# ===========================================================================
# 29. Search Pagination — full page cycle
# ===========================================================================

section("29. Search Pagination — full page cycle")

_setup()
for i in range(12):
    _create_node("ASSET", f"page-cycle-{i:02d}", riskScore=i*5)

# Page through all results: 3 pages of 4
total_seen = []
for pg in range(1, 4):
    r = search_attack_nodes(q="page-cycle", sort_by="label", sort_order="asc", page=pg, page_size=4)
    ok(r.success is True, f"Search page {pg} succeeds")
    eq(r.data["page"], pg, f"Search page {pg} in response")
    eq(r.data["pageSize"], 4, f"Search pageSize=4 on page {pg}")
    eq(r.data["totalPages"], 3, f"Search totalPages=3 on page {pg}")
    eq(r.data["total"], 12, f"Search total=12 on page {pg}")
    total_seen.extend(n["nodeId"] for n in r.data["nodes"])

eq(len(total_seen), 12, "All 12 nodes returned across 3 pages")
eq(len(set(total_seen)), 12, "No duplicate nodes across pages")

# sortOrder=asc across pages: labels should be globally ascending
resp_all_asc = search_attack_nodes(q="page-cycle", sort_by="label", sort_order="asc", page=1, page_size=50)
all_labels = [n["label"] for n in resp_all_asc.data["nodes"]]
ok(all_labels == sorted(all_labels), "Search ASC sort is globally consistent")

# sortOrder=desc across pages
resp_p1_desc = search_attack_nodes(q="page-cycle", sort_by="label", sort_order="desc", page=1, page_size=6)
resp_p2_desc = search_attack_nodes(q="page-cycle", sort_by="label", sort_order="desc", page=2, page_size=6)
labels_p1 = [n["label"] for n in resp_p1_desc.data["nodes"]]
labels_p2 = [n["label"] for n in resp_p2_desc.data["nodes"]]
if labels_p1 and labels_p2:
    ok(labels_p1[-1].lower() >= labels_p2[0].lower(),
       "Search DESC: last on page 1 >= first on page 2")


# ===========================================================================
# Final Report
# ===========================================================================

section("SMOKE TEST RESULTS")

total_tests = _PASS + _FAIL
print(f"\n  PASSED: {_PASS}")
print(f"  FAILED: {_FAIL}")
print(f"  TOTAL:  {total_tests}")

if _FAIL > 0:
    print(f"\n{'='*60}")
    print("  FAILURE DETAILS")
    print(f"{'='*60}")
    for msg in _FAIL_MSGS:
        print(f"  {msg}")
    print(f"{'='*60}\n")
    sys.exit(1)
else:
    print(f"\n{'='*60}")
    print(f"  ALL {total_tests} ASSERTIONS PASSED")
    print(f"{'='*60}")
    print("\n  Attack Graph API (Part A + Part B) — SMOKE TEST PASSED\n")
    sys.exit(0)
