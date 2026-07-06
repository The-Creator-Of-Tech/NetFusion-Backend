"""
Smoke Test — AI Copilot API (Phase A4.8.1 - Part B)
===================================================
Target: 700+ assertions, 0 failures.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from api.ai.copilot_router import (
    copilot_router,
    _reset_store,
    _COPILOT_STORE,
    create_copilot_session,
    get_copilot_session,
    list_copilot_sessions,
    delete_copilot_session,
    update_copilot_session,
    get_copilot_statistics,
    copilot_chat,
    search_copilot_sessions,
    bulk_create_sessions,
    bulk_update_sessions,
    bulk_delete_sessions,
    get_session_history,
    clear_session_history,
    get_session_summary,
    # Helpers
    find_session,
    sort_sessions,
    filter_sessions,
    paginate_sessions,
    append_chat_message,
    get_chat_history,
    clear_chat_history,
    build_chat_summary,
)
from api.ai.copilot_models import (
    CreateCopilotSessionRequest,
    UpdateCopilotSessionRequest,
    CopilotChatRequest,
    CopilotChatResponse,
    CopilotSessionResponse,
    CopilotSessionListResponse,
    CopilotStatisticsResponse,
    CopilotSearchResponse,
    BulkCreateCopilotSessionsRequest,
    BulkUpdateCopilotSessionsRequest,
    BulkDeleteCopilotSessionsRequest,
    BulkOperationResult,
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

def _raises(exc_type, fn, label: str) -> None:
    global _PASS, _FAIL
    try:
        fn()
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {exc_type.__name__}, got no exception")
    except exc_type:
        _PASS += 1
    except Exception as e:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {exc_type.__name__}, got {type(e).__name__}: {e}")

# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    global _PASS, _FAIL
    print("Starting AI Copilot API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in copilot_router.routes}
    expected_paths = {"/copilot", "/copilot/statistics", "/copilot/{sessionId}", "/copilot/chat", "/copilot/search", "/copilot/bulk/create", "/copilot/bulk/update", "/copilot/bulk/delete", "/copilot/{sessionId}/history", "/copilot/{sessionId}/summary"}
    for p in expected_paths:
        _true(p in paths, f"Path {p} in router routes")

    # =======================================================================
    # 2. Programmatic Sort Testing (50 items -> 6 fields * 2 orders * 49 pairs = 588 assertions)
    # =======================================================================
    sessions: List[Dict[str, Any]] = []
    for i in range(50):
        # Create a mock metadata object with prompt and response token estimates
        class MockMeta:
            def __init__(self, p_tok, r_tok):
                self.promptTokenEstimate = p_tok
                self.responseTokenEstimate = r_tok

        sessions.append({
            "sessionId"  : f"sess-{i:03d}",
            "sessionKey" : f"key-{i:03d}",
            "request"    : type("Req", (object,), {"investigationId": f"inv-{(i % 5):02d}", "systemPrompt": f"sys {i}", "userPrompt": f"user {i}"})(),
            "response"   : type("Resp", (object,), {"content": f"content {i}"})(),
            "metadata"   : MockMeta(i * 10, i * 5),
            "createdAt"  : f"2026-07-03T12:{i:02d}:00Z",
            "updatedAt"  : f"2026-07-03T13:{i:02d}:00Z",
            "status"     : "active" if i % 2 == 0 else "completed",
            "turns"      : i + 1,
            "userId"     : f"user-{(i % 3)}",
            "projectId"  : f"proj-{(i % 4)}",
            "sessionName": f"Session Name {i:03d}",
            "contextSize": i * 100,
        })

    sort_fields = ["createdAt", "updatedAt", "sessionName", "status", "totalTurns", "totalTokens"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_sessions(sessions, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 50, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(49):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                if field == "totalTokens":
                    v1 = s1["metadata"].promptTokenEstimate + s1["metadata"].responseTokenEstimate
                    v2 = s2["metadata"].promptTokenEstimate + s2["metadata"].responseTokenEstimate
                elif field == "totalTurns":
                    v1 = s1["turns"]
                    v2 = s2["turns"]
                elif field == "sessionName":
                    v1 = s1["sessionName"]
                    v2 = s2["sessionName"]
                elif field == "status":
                    v1 = s1["status"]
                    v2 = s2["status"]
                elif field == "createdAt":
                    v1 = s1["createdAt"]
                    v2 = s2["createdAt"]
                elif field == "updatedAt":
                    v1 = s1["updatedAt"]
                    v2 = s2["updatedAt"]
                
                if reverse:
                    _true(v1 >= v2, f"Sort order verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort order verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification (15 test combinations)
    # =======================================================================
    filters = [
        ({"status": "active"}, 25),
        ({"status": "completed"}, 25),
        ({"userId": "user-0"}, 17),
        ({"userId": "user-1"}, 17),
        ({"userId": "user-2"}, 16),
        ({"projectId": "proj-0"}, 13),
        ({"projectId": "proj-3"}, 12),
        ({"minimumTurns": 25}, 26),
        ({"maximumTurns": 10}, 10),
        ({"minimumTurns": 10, "maximumTurns": 20}, 11),
        ({"minimumTokens": 450}, 20), # i*15 >= 450 -> i >= 30. range 30..49 (20 items)
        ({"maximumTokens": 150}, 11), # i*15 <= 150 -> i <= 10. range 0..10 (11 items)
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 29),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "active", "userId": "user-0"}, 9),
    ]
    for filt, expected_count in filters:
        filtered = filter_sessions(
            sessions,
            status=filt.get("status"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            investigationId=filt.get("investigationId"),
            minimumTurns=filt.get("minimumTurns"),
            maximumTurns=filt.get("maximumTurns"),
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
            slice_res, pag = paginate_sessions(sessions, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 50, "TotalItems meta")
            _eq(pag.totalPages, 50 // page_size, "TotalPages meta")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. Validation Rules on Create Request
    # =======================================================================
    fields_to_test = [
        "contextId", "reasoningId", "promptPackageId", "narrativeId",
        "investigationId", "provider", "model", "systemPrompt",
        "userPrompt", "createdAt", "responseContent", "responseCreatedAt"
    ]
    for field in fields_to_test:
        valid_dict = {
            "contextId": "ctx", "reasoningId": "reas", "promptPackageId": "pkg",
            "narrativeId": "narr", "investigationId": "inv", "provider": "prov",
            "model": "mod", "systemPrompt": "sys", "userPrompt": "usr",
            "createdAt": "ts", "responseContent": "resp", "responseCreatedAt": "ts_resp"
        }
        valid_dict[field] = ""
        req = CreateCopilotSessionRequest(**valid_dict)
        errs = req.validate_request()
        _true(len(errs) > 0, f"Error should trigger for empty {field}")
        _true(any(field in e for e in errs), f"Error message lists field name: {field}")

    # =======================================================================
    # 6. REST Endpoint Orchestrations & CRUD Tests
    # =======================================================================
    _reset_store()

    # Empty store stats
    stats_resp = get_copilot_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalSessions"], 0, "Empty totalSessions")
    _eq(stats_resp.data["activeSessions"], 0, "Empty activeSessions")
    _eq(stats_resp.data["completedSessions"], 0, "Empty completedSessions")
    _eq(stats_resp.data["averageTurns"], 0.0, "Empty averageTurns")
    _eq(stats_resp.data["averageTokens"], 0.0, "Empty averageTokens")
    _eq(stats_resp.data["averageContextSize"], 0.0, "Empty averageContextSize")
    _eq(stats_resp.data["statusCounts"], {}, "Empty statusCounts")

    # Create Session
    body1 = CreateCopilotSessionRequest(
        contextId="ctx-111", reasoningId="reas-111", promptPackageId="pkg-111",
        narrativeId="narr-111", investigationId="inv-111", provider="groq",
        model="llama-3", systemPrompt="You are a subnet parser.", userPrompt="Analyze the subnet",
        createdAt="2026-07-03T12:00:00Z", responseContent="Subnet details: 10.0.0.0/24",
        responseCreatedAt="2026-07-03T12:00:05Z", confidence=88.5, status="active",
        turns=1, userId="user-alpha", projectId="proj-alpha", sessionName="Analysis Session",
        contextSize=500
    )
    resp1 = create_copilot_session(body1)
    _eq(resp1.success, True, "Create session 1")
    sid1 = resp1.data["sessionId"]
    _true(sid1 is not None, "Valid sessionId returned")

    # Get Session
    get1 = get_copilot_session(sid1)
    _eq(get1.success, True, "Get session 1")
    _eq(get1.data["userId"], "user-alpha", "userId validation")
    _eq(get1.data["projectId"], "proj-alpha", "projectId validation")
    _eq(get1.data["sessionName"], "Analysis Session", "sessionName validation")
    _eq(get1.data["contextSize"], 500, "contextSize validation")

    # Update Session
    upd1 = UpdateCopilotSessionRequest(
        status="completed", turns=3, sessionName="Updated Analysis Session"
    )
    upd_resp1 = update_copilot_session(sid1, upd1)
    _eq(upd_resp1.success, True, "Update session 1")
    _eq(upd_resp1.data["status"], "completed", "Updated status")
    _eq(upd_resp1.data["turns"], 3, "Updated turns")
    _eq(upd_resp1.data["sessionName"], "Updated Analysis Session", "Updated sessionName")

    # Statistics after 1 completed session
    stats_resp2 = get_copilot_statistics()
    _eq(stats_resp2.data["totalSessions"], 1, "Stats totalSessions = 1")
    _eq(stats_resp2.data["activeSessions"], 0, "Stats activeSessions = 0")
    _eq(stats_resp2.data["completedSessions"], 1, "Stats completedSessions = 1")
    _eq(stats_resp2.data["averageTurns"], 3.0, "Stats averageTurns = 3")
    _eq(stats_resp2.data["averageContextSize"], 500.0, "Stats averageContextSize = 500")
    _eq(stats_resp2.data["statusCounts"], {"completed": 1}, "Stats statusCounts = completed")

    # =======================================================================
    # 7. Chat History & Summarization
    # =======================================================================
    # Check history initially empty
    hist_resp1 = get_session_history(sid1)
    _eq(hist_resp1.success, True, "Get history")
    _eq(len(hist_resp1.data), 0, "Empty history array")

    # New chat turn (initializes conversation)
    chat_body1 = CopilotChatRequest(
        conversationId="conv-chat", userPrompt="First user message.", provider="groq",
        model="llama-3", createdAt="2026-07-03T12:10:00Z", userId="user-alpha",
        projectId="proj-alpha", sessionName="Chat Session"
    )
    chat_resp1 = copilot_chat(chat_body1)
    _eq(chat_resp1.success, True, "Chat initialization")
    chat_sid = chat_resp1.data["session"]["sessionId"]

    # History after 1 turn (should have USER and ASSISTANT messages)
    hist_resp2 = get_session_history(chat_sid)
    _eq(len(hist_resp2.data), 2, "History has 2 messages")
    _eq(hist_resp2.data[0]["role"], "USER", "First message role")
    _eq(hist_resp2.data[1]["role"], "ASSISTANT", "Second message role")

    # Summary of chat turn
    sum_resp = get_session_summary(chat_sid)
    _eq(sum_resp.success, True, "Get chat summary")
    _true("First user message" in sum_resp.data["summary"], "Summary contains user message content")

    # Clear history
    clear_resp = clear_session_history(chat_sid)
    _eq(clear_resp.success, True, "Clear history success")
    hist_resp3 = get_session_history(chat_sid)
    _eq(len(hist_resp3.data), 0, "History cleared")

    # =======================================================================
    # 8. Search Endpoint
    # =======================================================================
    # Let's populate the store with bulk creation first!
    bulk_sessions = []
    for j in range(10):
        bulk_sessions.append(CreateCopilotSessionRequest(
            contextId=f"ctx-{j}", reasoningId=f"reas-{j}", promptPackageId=f"pkg-{j}",
            narrativeId=f"narr-{j}", investigationId="inv-bulk", provider="groq",
            model="llama-3", systemPrompt=f"Bulk System Prompt {j}", userPrompt=f"Bulk User Prompt {j}",
            createdAt=f"2026-07-03T13:{j:02d}:00Z", responseContent=f"Bulk Response Content {j}",
            responseCreatedAt=f"2026-07-03T13:{j:02d}:10Z", status="active" if j % 2 == 0 else "completed",
            turns=j+1, userId=f"user-{j%2}", projectId=f"proj-{j%3}",
            sessionName=f"Bulk Session Name {j}", contextSize=100 * j
        ))
    bulk_req = BulkCreateCopilotSessionsRequest(sessions=bulk_sessions)
    bulk_resp = bulk_create_sessions(bulk_req)
    _eq(bulk_resp.success, True, "Bulk creation of 10 sessions")
    _eq(bulk_resp.data["successCount"], 10, "Bulk create successCount")

    # Search with q="Bulk"
    search_resp = search_copilot_sessions(q="Bulk", page=1, pageSize=5)
    _eq(search_resp.success, True, "Search for 'Bulk'")
    _eq(search_resp.data["total"], 10, "Search total matching items")
    _eq(len(search_resp.data["sessions"]), 5, "Search page slice length")

    # Search with status="completed" filter
    search_resp_completed = search_copilot_sessions(q="Bulk", status="completed")
    _eq(search_resp_completed.data["total"], 5, "Filtered search status='completed'")

    # Search sorting by totalTurns desc
    search_sort_desc = search_copilot_sessions(q="Bulk", sortBy="totalTurns", sortOrder="desc", pageSize=10)
    _eq(search_sort_desc.data["sessions"][0]["turns"], 10, "First sorted element turns (desc)")
    _eq(search_sort_desc.data["sessions"][-1]["turns"], 1, "Last sorted element turns (desc)")

    # =======================================================================
    # 9. Bulk Operations (Update and Delete)
    # =======================================================================
    # Bulk Update status to completed for two sessions
    sids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for sid in sids_to_update:
        update_items.append({
            "sessionId": sid,
            "update": UpdateCopilotSessionRequest(status="completed", turns=5)
        })
    bulk_upd_req = BulkUpdateCopilotSessionsRequest(items=update_items)
    bulk_upd_resp = bulk_update_sessions(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify updated status
    for sid in sids_to_update:
        sess_get = get_copilot_session(sid)
        _eq(sess_get.data["status"], "completed", "Status updated successfully")
        _eq(sess_get.data["turns"], 5, "Turns updated successfully")

    # Bulk Delete
    sids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteCopilotSessionsRequest(sessionIds=sids_to_delete)
    bulk_del_resp = bulk_delete_sessions(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 10, "Bulk delete successCount")

    # Verify deletion
    list_after = list_copilot_sessions()
    # The two sessions created outside bulk (sid1, chat_sid) should remain
    _eq(list_after.data["total"], 2, "Remaining session count")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
