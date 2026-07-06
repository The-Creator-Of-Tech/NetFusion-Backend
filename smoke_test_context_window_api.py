"""
Smoke Test — Context Window API (Phase A4.8.4 - Part B)
======================================================
Target: 850+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.context_window_router import (
    context_window_router,
    _reset_store,
    _CONTEXT_STORE,
    create_context_window,
    get_context_window,
    list_context_windows,
    delete_context_window,
    update_context_window,
    get_context_statistics,
    append_context_item_route,
    list_context_items,
    search_context_windows_endpoint,
    bulk_create_context_windows,
    bulk_update_context_windows,
    bulk_delete_context_windows,
    update_context_window_entry,
    delete_context_window_entry,
    get_context_window_summary,
    # Helpers
    find_context_window,
    sort_context_windows,
    filter_context_windows,
    paginate_context_windows,
    append_context_entry,
    update_context_entry,
    delete_context_entry,
    find_context_entry,
    search_context_entries,
    build_context_summary,
)
from api.ai.context_window_models import (
    CreateContextWindowRequest,
    UpdateContextWindowRequest,
    ContextWindowEntryRequest,
    ContextWindowEntryResponse,
    ContextWindowResponse,
    ContextWindowListResponse,
    ContextWindowStatisticsResponse,
    ContextWindowSearchResponse,
    BulkCreateContextWindowsRequest,
    BulkUpdateContextWindowsRequest,
    BulkDeleteContextWindowsRequest,
    BulkOperationResult,
    UpdateContextWindowEntryRequest,
)
from services.context_window_service import (
    build_context_item as service_build_item,
    build_context_window as service_build_window,
    ContextSourceEnum,
    ContextPriorityEnum,
)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0

def _eq(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a == b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: {a!r} != {b!r}")

def _ne(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a != b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected not-equal but got {a!r}")

def _is(obj, typ, label: str) -> None:
    global _PASS, _FAIL
    if isinstance(obj, typ):
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {typ.__name__}, got {type(obj).__name__}")

def _true(v, label: str) -> None:
    global _PASS, _FAIL
    if v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected True")

def _false(v, label: str) -> None:
    global _PASS, _FAIL
    if not v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected False")

# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    global _PASS, _FAIL
    print("Starting AI Context Window API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in context_window_router.routes}
    expected_paths = {
        "/context", "/context/statistics", "/context/search",
        "/context/bulk/create", "/context/bulk/update", "/context/bulk/delete",
        "/context/{contextId}", "/context/{contextId}/entries",
        "/context/{contextId}/entries/{entryId}", "/context/{contextId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (80 items -> 800 assertions)
    # =======================================================================
    windows = []
    for i in range(80):
        items = []
        for m_idx in range(i % 5 + 1):
            entry = service_build_item(
                source           = ContextSourceEnum.CONVERSATION if m_idx % 2 == 0 else ContextSourceEnum.MEMORY,
                priority         = ContextPriorityEnum.NORMAL if m_idx % 2 == 0 else ContextPriorityEnum.HIGH,
                title            = f"Context Title {i:03d} - {m_idx}",
                content          = f"content {i} entry {m_idx}",
                created_at       = f"2026-07-03T12:00:{m_idx:02d}Z",
            )
            items.append(entry)
            
        win = service_build_window(
            created_at       = f"2026-07-03T12:{i:02d}:00Z",
            investigation_id = f"inv-{(i % 4):02d}",
            conversation_id  = f"conv-{i:03d}",
            items            = items,
        )
        
        session_dict = {
            "window"      : win,
            "projectId"   : f"proj-{(i % 5)}",
            "userId"      : f"user-{(i % 3)}",
            "status"      : "ACTIVE" if i % 2 == 0 else "ARCHIVED",
            "contextSize" : i * 150,
            "windowName"  : f"Window Name {i:03d}",
        }
        windows.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "windowName", "entryCount", "tokenCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_context_windows(windows, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 80, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(79):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["window"]
                c2 = s2["window"]
                
                if field == "tokenCount":
                    v1 = c1.totalTokenEstimate
                    v2 = c2.totalTokenEstimate
                elif field == "entryCount":
                    v1 = len(c1.items)
                    v2 = len(c2.items)
                elif field == "windowName":
                    v1 = s1.get("windowName").lower()
                    v2 = s2.get("windowName").lower()
                elif field == "createdAt":
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                elif field == "updatedAt":
                    # window has no updatedAt, uses createdAt fallback
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                
                if reverse:
                    _true(v1 >= v2, f"Sort order verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort order verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification (15 runs)
    # =======================================================================
    filters = [
        ({"status": "ACTIVE"}, 40),
        ({"status": "ARCHIVED"}, 40),
        ({"userId": "user-0"}, 27),
        ({"userId": "user-1"}, 27),
        ({"userId": "user-2"}, 26),
        ({"projectId": "proj-0"}, 16),
        ({"projectId": "proj-3"}, 16),
        ({"minimumEntries": 3}, 48),
        ({"maximumEntries": 2}, 32),
        ({"minimumEntries": 2, "maximumEntries": 4}, 48),
        ({"minimumTokens": 10}, 64),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 59),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "ACTIVE", "userId": "user-0"}, 14),
    ]
    for filt, expected_count in filters:
        filtered = filter_context_windows(
            windows,
            status=filt.get("status"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            investigationId=filt.get("investigationId"),
            minimumEntries=filt.get("minimumEntries"),
            maximumEntries=filt.get("maximumEntries"),
            minimumTokens=filt.get("minimumTokens"),
            maximumTokens=filt.get("maximumTokens"),
            createdAfter=filt.get("createdAfter"),
            createdBefore=filt.get("createdBefore"),
        )
        _eq(len(filtered), expected_count, f"Filter count: {filt}")

    # =======================================================================
    # 4. Pagination Helper Verification
    # =======================================================================
    for page in [1, 2, 3]:
        for page_size in [5, 10]:
            slice_res, pag = paginate_context_windows(windows, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 80, "TotalItems meta")
            _eq(pag.totalPages, 80 // page_size, "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & entry actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_context_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalContexts"], 0, "Empty totalContexts")
    _eq(stats_resp.data["averageContextSize"], 0.0, "Empty averageContextSize")

    # Create Context Window
    body1 = CreateContextWindowRequest(
        createdAt="2026-07-03T12:00:00Z", investigationId="inv-sec", conversationId="conv-sec",
        projectId="proj-sec", userId="analyst-9", status="ACTIVE", contextSize=4000, windowName="Sec Window"
    )
    resp1 = create_context_window(body1)
    _eq(resp1.success, True, "Create context window")
    wid1 = resp1.data["windowId"]
    _true(wid1 is not None, "Valid windowId returned")

    # Get context window
    get1 = get_context_window(wid1)
    _eq(get1.data["projectId"], "proj-sec", "projectId metadata")
    _eq(get1.data["contextSize"], 4000, "contextSize metadata")

    # Append entry
    entry_body1 = ContextWindowEntryRequest(
        source="CONVERSATION", priority="HIGH", title="IP Scan alert", content="Port scan alert from 10.0.0.5.",
        createdAt="2026-07-03T12:01:00Z", referenceId="alert-abc", importanceScore=0.8, confidence=0.9
    )
    entry_resp1 = append_context_item_route(wid1, entry_body1)
    _eq(entry_resp1.success, True, "Entry appended")
    eid1 = entry_resp1.data["contextItemId"]

    # Append second entry
    entry_body2 = ContextWindowEntryRequest(
        source="MEMORY", priority="CRITICAL", title="Domain lookup", content="External lookup mapped to dynamic DNS.",
        createdAt="2026-07-03T12:02:00Z", referenceId="alert-xyz", importanceScore=0.75, confidence=0.85
    )
    entry_resp2 = append_context_item_route(wid1, entry_body2)
    _eq(entry_resp2.success, True, "Second entry appended")
    eid2 = entry_resp2.data["contextItemId"]

    # Verify entries listing
    list_entries = list_context_items(wid1)
    _eq(len(list_entries.data), 2, "Context window has 2 entries")

    # Update entry content
    upd_entry_body = UpdateContextWindowEntryRequest(content="External lookup mapped to dynamic DNS (resolved to 8.8.8.8).")
    upd_entry_resp = update_context_window_entry(wid1, eid2, upd_entry_body)
    _eq(upd_entry_resp.success, True, "Entry updated")
    _eq(upd_entry_resp.data["content"], "External lookup mapped to dynamic DNS (resolved to 8.8.8.8).", "Updated content value")

    # Verify summary endpoint
    sum_resp = get_context_window_summary(wid1)
    _eq(sum_resp.success, True, "Summary retrieved")
    _true("Port scan" in sum_resp.data["summary"], "Summary lists first text")

    # Delete entry
    del_entry_resp = delete_context_window_entry(wid1, eid1)
    _eq(del_entry_resp.success, True, "Entry deleted")

    # Verify entry list size after deletion
    list_entries_after = list_context_items(wid1)
    _eq(len(list_entries_after.data), 1, "Only 1 entry remaining")

    # Update context window status
    upd1 = UpdateContextWindowRequest(status="ARCHIVED", windowName="Archived Sec Window")
    upd_resp1 = update_context_window(wid1, upd1)
    _eq(upd_resp1.success, True, "Update context window")
    _eq(upd_resp1.data["status"], "ARCHIVED", "Updated status")
    _eq(upd_resp1.data["windowName"], "Archived Sec Window", "Updated name")

    # Statistics check
    stats_resp2 = get_context_statistics()
    _eq(stats_resp2.data["totalContexts"], 1, "Stats totalContexts = 1")
    _eq(stats_resp2.data["archivedContexts"], 1, "Contexts archived = 1")
    _eq(stats_resp2.data["averageContextSize"], 4000.0, "Stats averageContextSize = 4000")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_windows = []
    for j in range(5):
        bulk_windows.append(CreateContextWindowRequest(
            createdAt=f"2026-07-03T13:{j:02d}:00Z", investigationId="inv-bulk", conversationId=f"conv-{j}",
            projectId=f"proj-{j}", userId=f"analyst-{j}", status="ACTIVE", contextSize=100*j, windowName=f"Bulk window {j}"
        ))
    bulk_req = BulkCreateContextWindowsRequest(windows=bulk_windows)
    bulk_resp = bulk_create_context_windows(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create context windows")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search windows
    search_resp = search_context_windows_endpoint(q="Bulk window", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk window'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["memories"]), 3, "Page slice size")

    # Bulk Update
    wids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for wid in wids_to_update:
        update_items.append({
            "windowId": wid,
            "update": UpdateContextWindowRequest(status="ARCHIVED")
        })
    bulk_upd_req = BulkUpdateContextWindowsRequest(items=update_items)
    bulk_upd_resp = bulk_update_context_windows(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for wid in wids_to_update:
        c_get = get_context_window(wid)
        _eq(c_get.data["status"], "ARCHIVED", "Bulk status updated")

    # Bulk Delete
    wids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteContextWindowsRequest(windowIds=wids_to_delete)
    bulk_del_resp = bulk_delete_context_windows(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
