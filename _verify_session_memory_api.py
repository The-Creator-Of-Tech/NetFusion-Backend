"""
Verification Script — Session Memory API (Phase A4.8.3 - Part A)
===============================================================
"""

from __future__ import annotations

import json
from api.ai.session_memory_router import (
    session_memory_router,
    _reset_store,
    _MEMORY_STORE,
    list_memory_sessions,
    get_memory_statistics,
    get_memory_session,
    create_memory_session,
    update_memory_session,
    delete_memory_session,
    append_memory_entry,
    list_memory_entries,
)
from api.ai.session_memory_models import (
    CreateMemoryRequest,
    UpdateMemoryRequest,
    MemoryEntryRequest,
)

def run_verification() -> None:
    print("=== Session Memory router routes ===")
    for r in session_memory_router.routes:
        print(f"  {list(r.methods)} {r.path}")

    # Check routes
    paths = {r.path for r in session_memory_router.routes}
    expected_paths = {
        "/memory",
        "/memory/statistics",
        "/memory/{memoryId}",
        "/memory/{memoryId}/entries",
    }
    assert expected_paths.issubset(paths), f"Missing paths: {expected_paths - paths}"
    print("All expected paths present: OK")

    # 1. Statistics on empty store
    _reset_store()
    resp_stats = get_memory_statistics()
    assert resp_stats.success == True
    assert resp_stats.data["totalMemories"] == 0
    assert resp_stats.data["activeMemories"] == 0
    assert resp_stats.data["averageEntries"] == 0.0
    assert resp_stats.data["averageTokens"] == 0.0
    print("get_memory_statistics (empty): OK")

    # 2. Create Session
    body_create = CreateMemoryRequest(
        conversationId="conv-1",
        investigationId="inv-123",
        createdAt="2026-07-03T12:00:00Z",
    )
    resp_create = create_memory_session(body_create)
    assert resp_create.success == True
    mid = resp_create.data["sessionId"]
    assert mid is not None
    print("create_memory_session: OK")

    # 3. Create Duplicate Session (Conflict)
    resp_dup = create_memory_session(body_create)
    assert resp_dup.success == False
    assert resp_dup.data.errorCode == "CONFLICT"
    print("create_memory_session duplicate: OK (CONFLICT)")

    # 4. Request Validation Failure
    body_invalid = CreateMemoryRequest(
        conversationId="",
        createdAt="",
    )
    resp_invalid = create_memory_session(body_invalid)
    assert resp_invalid.success == False
    assert resp_invalid.data.errorCode == "VALIDATION_ERROR"
    print("create_memory_session validation failure: OK (VALIDATION_ERROR)")

    # 5. Get Session
    resp_get = get_memory_session(mid)
    assert resp_get.success == True
    assert resp_get.data["conversationId"] == "conv-1"
    assert resp_get.data["investigationId"] == "inv-123"
    print("get_memory_session: OK")

    # 6. Get Missing Session (Not Found)
    resp_missing = get_memory_session("nonexistent-id")
    assert resp_missing.success == False
    assert resp_missing.data.errorCode == "NOT_FOUND"
    print("get_memory_session missing: OK (NOT_FOUND)")

    # 7. Append Entry
    body_entry = MemoryEntryRequest(
        memoryType="SHORT_TERM",
        state="ACTIVE",
        title="First discovery",
        content="Detected malicious shell code execution.",
        importanceScore=0.8,
        confidence=0.9,
        createdAt="2026-07-03T12:05:00Z",
        sourceId="msg-111",
        tags=["malware", "shellcode"],
    )
    resp_entry = append_memory_entry(mid, body_entry)
    assert resp_entry.success == True
    eid = resp_entry.data["memoryId"]
    assert eid is not None
    print("append_memory_entry: OK")

    # 8. List Entries
    resp_entries = list_memory_entries(mid)
    assert resp_entries.success == True
    assert len(resp_entries.data) == 1
    assert resp_entries.data[0]["title"] == "First discovery"
    print("list_memory_entries: OK")

    # 9. Update Session
    body_update = UpdateMemoryRequest(
        investigationId="inv-updated",
        updatedAt="2026-07-03T12:10:00Z",
    )
    resp_upd = update_memory_session(mid, body_update)
    assert resp_upd.success == True
    assert resp_upd.data["investigationId"] == "inv-updated"
    assert resp_upd.data["updatedAt"] == "2026-07-03T12:10:00Z"
    print("update_memory_session: OK")

    # 10. Statistics with Session and Entry
    resp_stats2 = get_memory_statistics()
    assert resp_stats2.success == True
    assert resp_stats2.data["totalMemories"] == 1
    assert resp_stats2.data["activeMemories"] == 1
    assert resp_stats2.data["averageEntries"] == 1.0
    assert resp_stats2.data["averageTokens"] == 10.0 # ceiling(40 chars / 4) = 10
    print("get_memory_statistics (with items): OK")

    # 11. List Sessions
    resp_list = list_memory_sessions()
    assert resp_list.success == True
    assert resp_list.data["total"] == 1
    print("list_memory_sessions: OK")

    # 12. Delete Session
    resp_del = delete_memory_session(mid)
    assert resp_del.success == True
    print("delete_memory_session: OK")

    # 13. Delete Missing Session
    resp_del_missing = delete_memory_session(mid)
    assert resp_del_missing.success == False
    assert resp_del_missing.data.errorCode == "NOT_FOUND"
    print("delete_memory_session missing: OK (NOT_FOUND)")

    print("\nALL SESSION MEMORY PART A CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_verification()
