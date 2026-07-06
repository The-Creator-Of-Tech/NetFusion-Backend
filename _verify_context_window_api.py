"""
Verification Script — Context Window API (Phase A4.8.4 - Part A)
================================================================
"""

from __future__ import annotations

import json
from api.ai.context_window_router import (
    context_window_router,
    _reset_store,
    _CONTEXT_STORE,
    list_context_windows,
    get_context_statistics,
    get_context_window,
    create_context_window,
    update_context_window,
    delete_context_window,
    append_context_item_route,
    list_context_items,
)
from api.ai.context_window_models import (
    CreateContextWindowRequest,
    UpdateContextWindowRequest,
    ContextWindowEntryRequest,
)

def run_verification() -> None:
    print("=== Context Window router routes ===")
    for r in context_window_router.routes:
        print(f"  {list(r.methods)} {r.path}")

    # Check routes
    paths = {r.path for r in context_window_router.routes}
    expected_paths = {
        "/context",
        "/context/statistics",
        "/context/{contextId}",
        "/context/{contextId}/entries",
    }
    assert expected_paths.issubset(paths), f"Missing paths: {expected_paths - paths}"
    print("All expected paths present: OK")

    # 1. Statistics on empty store
    _reset_store()
    resp_stats = get_context_statistics()
    assert resp_stats.success == True
    assert resp_stats.data["totalContexts"] == 0
    assert resp_stats.data["activeContexts"] == 0
    assert resp_stats.data["averageEntries"] == 0.0
    assert resp_stats.data["averageTokens"] == 0.0
    print("get_context_statistics (empty): OK")

    # 2. Create Window
    body_create = CreateContextWindowRequest(
        createdAt="2026-07-03T12:00:00Z",
        investigationId="inv-123",
        conversationId="conv-456",
    )
    resp_create = create_context_window(body_create)
    assert resp_create.success == True
    wid = resp_create.data["windowId"]
    assert wid is not None
    print("create_context_window: OK")

    # 3. Create Duplicate Window (Conflict)
    resp_dup = create_context_window(body_create)
    assert resp_dup.success == False
    assert resp_dup.data.errorCode == "CONFLICT"
    print("create_context_window duplicate: OK (CONFLICT)")

    # 4. Request Validation Failure
    body_invalid = CreateContextWindowRequest(
        createdAt="",
    )
    resp_invalid = create_context_window(body_invalid)
    assert resp_invalid.success == False
    assert resp_invalid.data.errorCode == "VALIDATION_ERROR"
    print("create_context_window validation failure: OK (VALIDATION_ERROR)")

    # 5. Get Window
    resp_get = get_context_window(wid)
    assert resp_get.success == True
    assert resp_get.data["conversationId"] == "conv-456"
    assert resp_get.data["investigationId"] == "inv-123"
    print("get_context_window: OK")

    # 6. Get Missing Window (Not Found)
    resp_missing = get_context_window("nonexistent-id")
    assert resp_missing.success == False
    assert resp_missing.data.errorCode == "NOT_FOUND"
    print("get_context_window missing: OK (NOT_FOUND)")

    # 7. Append Entry
    body_entry = ContextWindowEntryRequest(
        source="CONVERSATION",
        priority="NORMAL",
        title="Host discovery",
        content="Analyzed network packets showing new host active.",
        referenceId="alert-999",
        importanceScore=0.75,
        confidence=0.9,
        createdAt="2026-07-03T12:05:00Z",
    )
    resp_entry = append_context_item_route(wid, body_entry)
    assert resp_entry.success == True
    eid = resp_entry.data["contextItemId"]
    assert eid is not None
    print("append_context_item_route: OK")

    # 8. List Entries
    resp_entries = list_context_items(wid)
    assert resp_entries.success == True
    assert len(resp_entries.data) == 1
    assert resp_entries.data[0]["title"] == "Host discovery"
    print("list_context_items: OK")

    # 9. Update Window
    body_update = UpdateContextWindowRequest(
        investigationId="inv-updated",
        status="ARCHIVED",
    )
    resp_upd = update_context_window(wid, body_update)
    assert resp_upd.success == True
    assert resp_upd.data["investigationId"] == "inv-updated"
    assert resp_upd.data["status"] == "ARCHIVED"
    print("update_context_window: OK")

    # 10. Statistics with Window and Item
    resp_stats2 = get_context_statistics()
    assert resp_stats2.success == True
    assert resp_stats2.data["totalContexts"] == 1
    assert resp_stats2.data["activeContexts"] == 0 # status changed to ARCHIVED
    assert resp_stats2.data["archivedContexts"] == 1
    assert resp_stats2.data["averageEntries"] == 1.0
    assert resp_stats2.data["averageTokens"] == 13.0 # ceiling(49 chars / 4) = 13
    print("get_context_statistics (with items): OK")

    # 11. List Windows
    resp_list = list_context_windows()
    assert resp_list.success == True
    assert resp_list.data["total"] == 1
    print("list_context_windows: OK")

    # 12. Delete Window
    resp_del = delete_context_window(wid)
    assert resp_del.success == True
    print("delete_context_window: OK")

    # 13. Delete Missing Window
    resp_del_missing = delete_context_window(wid)
    assert resp_del_missing.success == False
    assert resp_del_missing.data.errorCode == "NOT_FOUND"
    print("delete_context_window missing: OK (NOT_FOUND)")

    print("\nALL CONTEXT WINDOW PART A CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_verification()
