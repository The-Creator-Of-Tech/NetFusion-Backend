"""
Verification script for Conversation API endpoints.
"""

from __future__ import annotations

import api
from api.ai.conversation_router import conversation_router, _reset_store
from api.ai.conversation_router import (
    create_conversation, get_conversation, list_conversations,
    delete_conversation, update_conversation, get_conversation_statistics,
    append_conversation_message, list_conversation_messages,
)
from api.ai.conversation_models import (
    CreateConversationRequest,
    UpdateConversationRequest,
    ConversationMessageRequest,
)

print("=== Conversation router routes ===")
for r in conversation_router.routes:
    print(f"  {sorted(r.methods)} {r.path}")

print()

# Verify paths
paths = {r.path for r in conversation_router.routes}
expected = {"/conversations", "/conversations/statistics", "/conversations/{conversationId}", "/conversations/{conversationId}/messages"}
for p in expected:
    assert p in paths, f"Missing path: {p}"
print("All expected paths present: OK")

_reset_store()

# Test 1: Empty stats
stats_empty = get_conversation_statistics()
assert stats_empty.success == True
assert stats_empty.data["totalConversations"] == 0
assert stats_empty.data["activeConversations"] == 0
assert stats_empty.data["archivedConversations"] == 0
assert stats_empty.data["averageMessages"] == 0.0
assert stats_empty.data["averageTokens"] == 0.0
print("get_conversation_statistics (empty): OK")

# Test 2: Create conversation
body = CreateConversationRequest(
    createdBy="analyst-1",
    title="Investigation conversation",
    createdAt="2026-07-03T12:00:00Z",
    investigationId="inv-123",
    state="active",
    summary="A test conversation.",
    tags=["netfusion", "test"],
)
resp_create = create_conversation(body)
assert resp_create.success == True
conversationId = resp_create.data["conversationId"]
assert conversationId is not None
print("create_conversation: OK")

# Test 3: Duplicate create -> CONFLICT
resp_dup = create_conversation(body)
assert resp_dup.success == False
assert resp_dup.data.errorCode == "CONFLICT"
print("create_conversation duplicate: OK (CONFLICT)")

# Test 4: Validation error (empty createdBy) -> VALIDATION_ERROR
bad_body = CreateConversationRequest(
    createdBy="",
    title="Investigation conversation",
    createdAt="2026-07-03T12:00:00Z",
)
resp_bad = create_conversation(bad_body)
assert resp_bad.success == False
assert resp_bad.data.errorCode == "VALIDATION_ERROR"
print("create_conversation validation failure: OK (VALIDATION_ERROR)")

# Test 5: Get conversation
resp_get = get_conversation(conversationId)
assert resp_get.success == True
assert resp_get.data["conversationId"] == conversationId
assert resp_get.data["metadata"]["title"] == "Investigation conversation"
print("get_conversation: OK")

# Test 6: Get missing conversation -> NOT_FOUND
resp_get_missing = get_conversation("missing-id")
assert resp_get_missing.success == False
assert resp_get_missing.data.errorCode == "NOT_FOUND"
print("get_conversation missing: OK (NOT_FOUND)")

# Test 7: Append message
msg_body = ConversationMessageRequest(
    role="user",
    content="Hello NetFusion Analyst!",
    createdAt="2026-07-03T12:01:00Z",
)
resp_msg = append_conversation_message(conversationId, msg_body)
assert resp_msg.success == True
messageId = resp_msg.data["messageId"]
assert messageId is not None
print("append_conversation_message: OK")

# Test 8: List messages
resp_msgs = list_conversation_messages(conversationId)
assert resp_msgs.success == True
assert len(resp_msgs.data) == 1
assert resp_msgs.data[0]["messageId"] == messageId
assert resp_msgs.data[0]["content"] == "Hello NetFusion Analyst!"
print("list_conversation_messages: OK")

# Test 9: Update conversation state and tags
upd = UpdateConversationRequest(
    state="archived",
    tags=["netfusion", "test", "archived"],
)
resp_upd = update_conversation(conversationId, upd)
assert resp_upd.success == True
assert resp_upd.data["state"] == "ARCHIVED"
assert "archived" in resp_upd.data["metadata"]["tags"]
print("update_conversation: OK")

# Test 10: Stats with 1 archived conversation
stats_resp = get_conversation_statistics()
assert stats_resp.success == True
assert stats_resp.data["totalConversations"] == 1
assert stats_resp.data["activeConversations"] == 0
assert stats_resp.data["archivedConversations"] == 1
assert stats_resp.data["averageMessages"] == 1.0
assert stats_resp.data["averageTokens"] > 0
print("get_conversation_statistics (with items): OK")

# Test 11: List conversations
resp_list = list_conversations()
assert resp_list.success == True
assert resp_list.data["total"] == 1
assert resp_list.data["conversations"][0]["conversationId"] == conversationId
print("list_conversations: OK")

# Test 12: Delete conversation
resp_del = delete_conversation(conversationId)
assert resp_del.success == True
print("delete_conversation: OK")

# Test 13: Delete missing -> NOT_FOUND
resp_del_missing = delete_conversation(conversationId)
assert resp_del_missing.success == False
assert resp_del_missing.data.errorCode == "NOT_FOUND"
print("delete_conversation missing: OK (NOT_FOUND)")

print("\nALL CONVERSATION API CHECKS PASSED SUCCESSFULLY!")
