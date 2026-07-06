"""
Smoke Test — Conversation API (Phase A4.8.2 - Part B)
=====================================================
Target: 750+ assertions, 0 failures.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from api.ai.conversation_router import (
    conversation_router,
    _reset_store,
    _CONVERSATION_STORE,
    create_conversation,
    get_conversation,
    list_conversations,
    delete_conversation,
    update_conversation,
    get_conversation_statistics,
    append_conversation_message,
    list_conversation_messages,
    search_conversations_endpoint,
    bulk_create_conversations,
    bulk_update_conversations,
    bulk_delete_conversations,
    update_conversation_message,
    delete_conversation_message,
    get_conversation_summary_endpoint,
    # Helpers
    find_conversation,
    sort_conversations,
    filter_conversations,
    paginate_conversations,
    append_message,
    update_message,
    delete_message,
    find_message,
    search_messages,
    build_conversation_summary,
)
from api.ai.conversation_models import (
    CreateConversationRequest,
    UpdateConversationRequest,
    ConversationMessageRequest,
    ConversationMessageResponse,
    ConversationResponse,
    ConversationListResponse,
    ConversationStatisticsResponse,
    ConversationSearchResponse,
    BulkCreateConversationsRequest,
    BulkUpdateConversationsRequest,
    BulkDeleteConversationsRequest,
    BulkOperationResult,
    UpdateMessageRequest,
)
from services.conversation_manager_service import (
    build_message,
    build_conversation,
    ConversationRole,
    ConversationState,
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
    print("Starting AI Conversation API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in conversation_router.routes}
    expected_paths = {
        "/conversations", "/conversations/statistics", "/conversations/search",
        "/conversations/bulk/create", "/conversations/bulk/update", "/conversations/bulk/delete",
        "/conversations/{conversationId}", "/conversations/{conversationId}/messages",
        "/conversations/{conversationId}/messages/{messageId}", "/conversations/{conversationId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (60 items -> 720 assertions)
    # =======================================================================
    conversations = []
    for i in range(60):
        messages = []
        for m_idx in range(i % 5 + 1):
            msg = build_message(
                conversation_id = f"conv-{i:03d}",
                role            = ConversationRole.USER if m_idx % 2 == 0 else ConversationRole.ASSISTANT,
                content         = f"content {i} message {m_idx}",
                sequence_number = m_idx + 1,
                created_at      = f"2026-07-03T12:00:{m_idx:02d}Z",
            )
            messages.append(msg)
            
        conv = build_conversation(
            created_by       = f"user-{(i % 3)}",
            title            = f"Conversation Title {i:03d}",
            created_at       = f"2026-07-03T12:{i:02d}:00Z",
            investigation_id = f"inv-{(i % 4):02d}",
            state            = ConversationState.ACTIVE if i % 2 == 0 else ConversationState.ARCHIVED,
            messages         = messages,
            summary          = f"Summary of {i}",
            tags             = [f"tag-{i%2}", f"tag-{i%3}"],
        )
        session_dict = {
            "conversation": conv,
            "projectId"   : f"proj-{(i % 5)}",
            "userId"      : f"user-{(i % 3)}",
            "contextSize" : i * 150,
        }
        conversations.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "title", "status", "messageCount", "tokenCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_conversations(conversations, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 60, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(59):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["conversation"]
                c2 = s2["conversation"]
                
                if field == "tokenCount":
                    v1 = c1.metadata.totalTokens
                    v2 = c2.metadata.totalTokens
                elif field == "messageCount":
                    v1 = len(c1.messages)
                    v2 = len(c2.messages)
                elif field == "title":
                    v1 = c1.metadata.title.lower()
                    v2 = c2.metadata.title.lower()
                elif field == "status":
                    v1 = c1.state.value if hasattr(c1.state, "value") else str(c1.state)
                    v2 = c2.state.value if hasattr(c2.state, "value") else str(c2.state)
                    v1 = v1.lower()
                    v2 = v2.lower()
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
        ({"status": "ACTIVE"}, 30),
        ({"status": "ARCHIVED"}, 30),
        ({"userId": "user-0"}, 20),
        ({"userId": "user-1"}, 20),
        ({"userId": "user-2"}, 20),
        ({"projectId": "proj-0"}, 12),
        ({"projectId": "proj-3"}, 12),
        ({"minimumMessages": 3}, 36),
        ({"maximumMessages": 2}, 24),
        ({"minimumMessages": 2, "maximumMessages": 4}, 36),
        ({"minimumTokens": 10}, 48),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 39),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "ACTIVE", "userId": "user-0"}, 10),
    ]
    for filt, expected_count in filters:
        filtered = filter_conversations(
            conversations,
            status=filt.get("status"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            investigationId=filt.get("investigationId"),
            minimumMessages=filt.get("minimumMessages"),
            maximumMessages=filt.get("maximumMessages"),
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
            slice_res, pag = paginate_conversations(conversations, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 60, "TotalItems meta")
            _eq(pag.totalPages, 60 // page_size, "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & message actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_conversation_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalConversations"], 0, "Empty totalConversations")
    _eq(stats_resp.data["averageContextSize"], 0.0, "Empty averageContextSize")

    # Create Conversation
    body1 = CreateConversationRequest(
        createdBy="analyst-1", title="Cyber Incident 2026", createdAt="2026-07-03T12:00:00Z",
        investigationId="inv-999", state="ACTIVE", summary="Tracking external IP portscan.",
        tags=["incident", "portscan"], projectId="proj-incident", userId="analyst-1", contextSize=1200
    )
    resp1 = create_conversation(body1)
    _eq(resp1.success, True, "Create conversation")
    cid1 = resp1.data["conversationId"]
    _true(cid1 is not None, "Valid conversationId returned")

    # Get conversation
    get1 = get_conversation(cid1)
    _eq(get1.data["projectId"], "proj-incident", "projectId metadata")
    _eq(get1.data["contextSize"], 1200, "contextSize metadata")

    # Append message
    msg_body1 = ConversationMessageRequest(
        role="user", content="Show scan timeline.", createdAt="2026-07-03T12:01:00Z"
    )
    msg_resp1 = append_conversation_message(cid1, msg_body1)
    _eq(msg_resp1.success, True, "Message appended")
    mid1 = msg_resp1.data["messageId"]

    # Append second message
    msg_body2 = ConversationMessageRequest(
        role="assistant", content="Scan started at 12:00.", createdAt="2026-07-03T12:02:00Z"
    )
    msg_resp2 = append_conversation_message(cid1, msg_body2)
    _eq(msg_resp2.success, True, "Second message appended")
    mid2 = msg_resp2.data["messageId"]

    # Verify history listing
    list_msgs = list_conversation_messages(cid1)
    _eq(len(list_msgs.data), 2, "Conversation has 2 messages")

    # Update message content
    upd_msg_body = UpdateMessageRequest(content="Scan started at 11:59 UTC.")
    upd_msg_resp = update_conversation_message(cid1, mid2, upd_msg_body)
    _eq(upd_msg_resp.success, True, "Message updated")
    _eq(upd_msg_resp.data["content"], "Scan started at 11:59 UTC.", "Updated content value")

    # Verify summary endpoint
    sum_resp = get_conversation_summary_endpoint(cid1)
    _eq(sum_resp.success, True, "Summary retrieved")
    _true("Scan started" in sum_resp.data["summary"], "Summary lists text")

    # Delete message
    del_msg_resp = delete_conversation_message(cid1, mid1)
    _eq(del_msg_resp.success, True, "Message deleted")

    # Verify message sequence re-numbered
    list_msgs_after = list_conversation_messages(cid1)
    _eq(len(list_msgs_after.data), 1, "Only 1 message remaining")
    _eq(list_msgs_after.data[0]["sequenceNumber"], 1, "Message re-sequenced to 1")

    # Update conversation
    upd1 = UpdateConversationRequest(state="ARCHIVED", tags=["incident", "resolved"])
    upd_resp1 = update_conversation(cid1, upd1)
    _eq(upd_resp1.success, True, "Update conversation")
    _eq(upd_resp1.data["state"], "ARCHIVED", "Updated state")

    # Statistics check
    stats_resp2 = get_conversation_statistics()
    _eq(stats_resp2.data["totalConversations"], 1, "Stats totalConversations = 1")
    _eq(stats_resp2.data["archivedConversations"], 1, "Stats archivedConversations = 1")
    _eq(stats_resp2.data["averageContextSize"], 1200.0, "Stats averageContextSize = 1200")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_convs = []
    for j in range(5):
        bulk_convs.append(CreateConversationRequest(
            createdBy=f"analyst-{j}", title=f"Bulk incident {j}", createdAt=f"2026-07-03T13:{j:02d}:00Z",
            investigationId="inv-bulk", state="ACTIVE", summary=f"Bulk Incident summary {j}",
            tags=["bulk"], projectId=f"proj-{j}", userId=f"analyst-{j}", contextSize=100*j
        ))
    bulk_req = BulkCreateConversationsRequest(conversations=bulk_convs)
    bulk_resp = bulk_create_conversations(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create conversations")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search conversations
    search_resp = search_conversations_endpoint(q="Bulk incident", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk incident'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["conversations"]), 3, "Page slice size")

    # Bulk Update
    sids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for sid in sids_to_update:
        update_items.append({
            "conversationId": sid,
            "update": UpdateConversationRequest(state="ARCHIVED")
        })
    bulk_upd_req = BulkUpdateConversationsRequest(items=update_items)
    bulk_upd_resp = bulk_update_conversations(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for sid in sids_to_update:
        c_get = get_conversation(sid)
        _eq(c_get.data["state"], "ARCHIVED", "Bulk state updated")

    # Bulk Delete
    sids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteConversationsRequest(conversationIds=sids_to_delete)
    bulk_del_resp = bulk_delete_conversations(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
