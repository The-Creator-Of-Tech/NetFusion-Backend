"""
Smoke Test — Session Memory API (Phase A4.8.3 - Part B)
======================================================
Target: 800+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.session_memory_router import (
    session_memory_router,
    _reset_store,
    _MEMORY_STORE,
    create_memory_session,
    get_memory_session,
    list_memory_sessions,
    delete_memory_session,
    update_memory_session,
    get_memory_statistics,
    append_memory_entry_route,
    list_memory_entries,
    search_memory_sessions_endpoint,
    bulk_create_memory,
    bulk_update_memory,
    bulk_delete_memory,
    update_session_memory_entry,
    delete_session_memory_entry,
    get_memory_session_summary,
    # Helpers
    find_memory,
    sort_memory,
    filter_memory,
    paginate_memory,
    append_memory_entry,
    update_memory_entry,
    delete_memory_entry,
    find_memory_entry,
    search_memory_entries,
    build_memory_summary,
)
from api.ai.session_memory_models import (
    CreateMemoryRequest,
    UpdateMemoryRequest,
    MemoryEntryRequest,
    MemoryEntryResponse,
    MemoryResponse,
    MemoryListResponse,
    MemoryStatisticsResponse,
    MemorySearchResponse,
    BulkCreateMemoryRequest,
    BulkUpdateMemoryRequest,
    BulkDeleteMemoryRequest,
    BulkOperationResult,
    UpdateMemoryEntryRequest,
)
from services.session_memory_service import (
    build_memory_entry as service_build_entry,
    build_session_memory as service_build_session,
    MemoryTypeEnum,
    MemoryStateEnum,
    _estimate_tokens,
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
    print("Starting AI Session Memory API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in session_memory_router.routes}
    expected_paths = {
        "/memory", "/memory/statistics", "/memory/search",
        "/memory/bulk/create", "/memory/bulk/update", "/memory/bulk/delete",
        "/memory/{memoryId}", "/memory/{memoryId}/entries",
        "/memory/{memoryId}/entries/{entryId}", "/memory/{memoryId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (75 items -> 750 assertions)
    # =======================================================================
    sessions = []
    for i in range(75):
        entries = []
        for m_idx in range(i % 5 + 1):
            entry = service_build_entry(
                conversation_id = f"conv-{i:03d}",
                memory_type      = MemoryTypeEnum.SHORT_TERM if m_idx % 2 == 0 else MemoryTypeEnum.LONG_TERM,
                title            = f"Memory Title {i:03d} - {m_idx}",
                content          = f"content {i} entry {m_idx}",
                created_at       = f"2026-07-03T12:00:{m_idx:02d}Z",
            )
            entries.append(entry)
            
        sess = service_build_session(
            conversation_id   = f"conv-{i:03d}",
            created_at        = f"2026-07-03T12:{i:02d}:00Z",
            updated_at        = f"2026-07-03T12:{i:02d}:00Z",
            investigation_id  = f"inv-{(i % 4):02d}",
            memories          = entries,
            summaries         = [],
        )
        
        session_dict = {
            "session"     : sess,
            "projectId"   : f"proj-{(i % 5)}",
            "userId"      : f"user-{(i % 3)}",
            "status"      : "ACTIVE" if i % 2 == 0 else "ARCHIVED",
            "contextSize" : i * 150,
            "sessionName" : f"Session Name {i:03d}",
        }
        sessions.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "sessionName", "entryCount", "tokenCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_memory(sessions, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 75, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(74):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["session"]
                c2 = s2["session"]
                
                if field == "tokenCount":
                    v1 = sum(_estimate_tokens(e.content) for e in c1.memories)
                    v2 = sum(_estimate_tokens(e.content) for e in c2.memories)
                elif field == "entryCount":
                    v1 = len(c1.memories)
                    v2 = len(c2.memories)
                elif field == "sessionName":
                    v1 = s1.get("sessionName").lower()
                    v2 = s2.get("sessionName").lower()
                elif field == "createdAt":
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                elif field == "updatedAt":
                    v1 = c1.updatedAt
                    v2 = c2.updatedAt
                
                if reverse:
                    _true(v1 >= v2, f"Sort order verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort order verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification (15 runs)
    # =======================================================================
    filters = [
        ({"status": "ACTIVE"}, 38),
        ({"status": "ARCHIVED"}, 37),
        ({"userId": "user-0"}, 25),
        ({"userId": "user-1"}, 25),
        ({"userId": "user-2"}, 25),
        ({"projectId": "proj-0"}, 15),
        ({"projectId": "proj-3"}, 15),
        ({"minimumEntries": 3}, 45),
        ({"maximumEntries": 2}, 30),
        ({"minimumEntries": 2, "maximumEntries": 4}, 45),
        ({"minimumTokens": 10}, 60),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 54),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "ACTIVE", "userId": "user-0"}, 13),
    ]
    for filt, expected_count in filters:
        filtered = filter_memory(
            sessions,
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
            slice_res, pag = paginate_memory(sessions, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 75, "TotalItems meta")
            _eq(pag.totalPages, math.ceil(75 / page_size), "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & entry actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_memory_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalMemories"], 0, "Empty totalMemories")
    _eq(stats_resp.data["averageContextSize"], 0.0, "Empty averageContextSize")

    # Create Session Memory
    body1 = CreateMemoryRequest(
        conversationId="conv-999", investigationId="inv-cyber", createdAt="2026-07-03T12:00:00Z",
        projectId="proj-sec", userId="analyst-9", status="ACTIVE", contextSize=5000, sessionName="Cyber Memory"
    )
    resp1 = create_memory_session(body1)
    _eq(resp1.success, True, "Create session memory")
    mid1 = resp1.data["sessionId"]
    _true(mid1 is not None, "Valid sessionId returned")

    # Get session memory
    get1 = get_memory_session(mid1)
    _eq(get1.data["projectId"], "proj-sec", "projectId metadata")
    _eq(get1.data["contextSize"], 5000, "contextSize metadata")

    # Append entry
    entry_body1 = MemoryEntryRequest(
        memoryType="SHORT_TERM", state="ACTIVE", title="IP Scan alert", content="Port scan alert from 10.0.0.5.",
        importanceScore=0.8, confidence=0.9,
        createdAt="2026-07-03T12:01:00Z", sourceId="alert-abc", tags=["scan", "internal"]
    )
    entry_resp1 = append_memory_entry_route(mid1, entry_body1)
    _eq(entry_resp1.success, True, "Entry appended")
    eid1 = entry_resp1.data["memoryId"]

    # Append second entry
    entry_body2 = MemoryEntryRequest(
        memoryType="LONG_TERM", state="ACTIVE", title="Domain lookup", content="External lookup mapped to dynamic DNS.",
        importanceScore=0.7, confidence=0.85,
        createdAt="2026-07-03T12:02:00Z", sourceId="alert-xyz", tags=["domain", "dns"]
    )
    entry_resp2 = append_memory_entry_route(mid1, entry_body2)
    _eq(entry_resp2.success, True, "Second entry appended")
    eid2 = entry_resp2.data["memoryId"]

    # Verify entries listing
    list_entries = list_memory_entries(mid1)
    _eq(len(list_entries.data), 2, "Session memory has 2 entries")

    # Update entry content
    upd_entry_body = UpdateMemoryEntryRequest(content="External lookup mapped to dynamic DNS (resolved to 8.8.8.8).")
    upd_entry_resp = update_session_memory_entry(mid1, eid2, upd_entry_body)
    _eq(upd_entry_resp.success, True, "Entry updated")
    _eq(upd_entry_resp.data["content"], "External lookup mapped to dynamic DNS (resolved to 8.8.8.8).", "Updated content value")

    # Verify summary endpoint
    sum_resp = get_memory_session_summary(mid1)
    _eq(sum_resp.success, True, "Summary retrieved")
    _true("Port scan" in sum_resp.data["summary"], "Summary lists first text")

    # Delete entry
    del_entry_resp = delete_session_memory_entry(mid1, eid1)
    _eq(del_entry_resp.success, True, "Entry deleted")

    # Verify entry sequence after deletion
    list_entries_after = list_memory_entries(mid1)
    _eq(len(list_entries_after.data), 1, "Only 1 entry remaining")

    # Update session memory status
    upd1 = UpdateMemoryRequest(status="ARCHIVED", sessionName="Archived Cyber Memory")
    upd_resp1 = update_memory_session(mid1, upd1)
    _eq(upd_resp1.success, True, "Update session memory")
    _eq(upd_resp1.data["status"], "ARCHIVED", "Updated status")
    _eq(upd_resp1.data["sessionName"], "Archived Cyber Memory", "Updated name")

    # Statistics check
    stats_resp2 = get_memory_statistics()
    _eq(stats_resp2.data["totalMemories"], 1, "Stats totalMemories = 1")
    _eq(stats_resp2.data["archivedMemories"], 0, "Entries archived = 0 (only session is archived)")
    _eq(stats_resp2.data["averageContextSize"], 5000.0, "Stats averageContextSize = 5000")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_sessions = []
    for j in range(5):
        bulk_sessions.append(CreateMemoryRequest(
            conversationId=f"conv-{j}", investigationId="inv-bulk", createdAt=f"2026-07-03T13:{j:02d}:00Z",
            projectId=f"proj-{j}", userId=f"analyst-{j}", status="ACTIVE", contextSize=100*j, sessionName=f"Bulk session {j}"
        ))
    bulk_req = BulkCreateMemoryRequest(sessions=bulk_sessions)
    bulk_resp = bulk_create_memory(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create memory sessions")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search sessions
    search_resp = search_memory_sessions_endpoint(q="Bulk session", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk session'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["memories"]), 3, "Page slice size")

    # Bulk Update
    mids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for mid in mids_to_update:
        update_items.append({
            "memoryId": mid,
            "update": UpdateMemoryRequest(status="ARCHIVED")
        })
    bulk_upd_req = BulkUpdateMemoryRequest(items=update_items)
    bulk_upd_resp = bulk_update_memory(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for mid in mids_to_update:
        c_get = get_memory_session(mid)
        _eq(c_get.data["status"], "ARCHIVED", "Bulk status updated")

    # Bulk Delete
    mids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteMemoryRequest(memoryIds=mids_to_delete)
    bulk_del_resp = bulk_delete_memory(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
