"""
Verification script for AI Copilot API endpoints and logic.
"""

from __future__ import annotations

import api
from api.ai.copilot_router import copilot_router, _reset_store
from api.ai.copilot_router import (
    create_copilot_session, get_copilot_session, list_copilot_sessions,
    delete_copilot_session, update_copilot_session, get_copilot_statistics,
    copilot_chat,
)
from api.ai.copilot_models import (
    CreateCopilotSessionRequest,
    UpdateCopilotSessionRequest,
    CopilotChatRequest,
)

# Check all routes registered on copilot_router
print("=== Copilot router routes ===")
for r in copilot_router.routes:
    print(f"  {sorted(r.methods)} {r.path}")

print()

# Verify paths
paths = {r.path for r in copilot_router.routes}
expected = {"/copilot", "/copilot/statistics", "/copilot/{sessionId}", "/copilot/chat"}
for p in expected:
    assert p in paths, f"Missing path: {p}"
print("All expected paths present: OK")

_reset_store()

# Test 1: Create Copilot Session
body = CreateCopilotSessionRequest(
    contextId="ctx-123",
    reasoningId="reas-123",
    promptPackageId="pkg-123",
    narrativeId="narr-123",
    investigationId="inv-123",
    provider="groq",
    model="llama-3",
    systemPrompt="You are a helper.",
    userPrompt="Hello",
    createdAt="2026-07-03T12:00:00Z",
    responseContent="Hi user",
    responseCreatedAt="2026-07-03T12:00:01Z",
    confidence=95.0,
    status="active",
    turns=1,
)

resp = create_copilot_session(body)
assert resp.success == True, f"Create failed: {resp}"
sessionId = resp.data["sessionId"]
assert sessionId is not None
print("create_copilot_session: OK")

# Test 2: Duplicate Create -> 409
resp_dup = create_copilot_session(body)
assert resp_dup.success == False
assert resp_dup.data.errorCode == "CONFLICT"
print("create_copilot_session duplicate: OK (CONFLICT)")

# Test 3: Validation failure -> 422
bad_body = CreateCopilotSessionRequest(
    contextId="",
    reasoningId="reas-123",
    promptPackageId="pkg-123",
    narrativeId="narr-123",
    investigationId="inv-123",
    provider="groq",
    model="llama-3",
    systemPrompt="You are a helper.",
    userPrompt="Hello",
    createdAt="2026-07-03T12:00:00Z",
    responseContent="Hi user",
    responseCreatedAt="2026-07-03T12:00:01Z",
)
resp_bad = create_copilot_session(bad_body)
assert resp_bad.success == False
assert resp_bad.data.errorCode == "VALIDATION_ERROR"
print("create_copilot_session empty contextId: OK (VALIDATION_ERROR)")

# Test 4: Get existing session
resp_get = get_copilot_session(sessionId)
assert resp_get.success == True
assert resp_get.data["sessionId"] == sessionId
assert resp_get.data["status"] == "active"
print("get_copilot_session existing: OK")

# Test 5: Get missing session -> 404
resp_get_missing = get_copilot_session("nonexistent-id")
assert resp_get_missing.success == False
assert resp_get_missing.data.errorCode == "NOT_FOUND"
print("get_copilot_session missing: OK (NOT_FOUND)")

# Test 6: List sessions
resp_list = list_copilot_sessions()
assert resp_list.success == True
assert resp_list.data["total"] == 1
assert resp_list.data["sessions"][0]["sessionId"] == sessionId
print("list_copilot_sessions: OK")

# Test 7: Get statistics
resp_stats = get_copilot_statistics()
assert resp_stats.success == True
assert resp_stats.data["totalSessions"] == 1
assert resp_stats.data["activeSessions"] == 1
assert resp_stats.data["completedSessions"] == 0
assert resp_stats.data["averageTurns"] == 1.0
assert resp_stats.data["averageTokens"] > 0
print("get_copilot_statistics: OK")

# Test 8: Update session
upd = UpdateCopilotSessionRequest(
    status="completed",
    turns=2,
    responseContent="Updated reply text",
)
resp_upd = update_copilot_session(sessionId, upd)
assert resp_upd.success == True
assert resp_upd.data["status"] == "completed"
assert resp_upd.data["turns"] == 2
assert resp_upd.data["response"]["content"] == "Updated reply text"
print("update_copilot_session: OK")

# Test 9: Update session missing -> 404
resp_upd_missing = update_copilot_session("nonexistent-id", upd)
assert resp_upd_missing.success == False
assert resp_upd_missing.data.errorCode == "NOT_FOUND"
print("update_copilot_session missing: OK (NOT_FOUND)")

# Test 10: Update session empty -> 422
resp_upd_empty = update_copilot_session(sessionId, UpdateCopilotSessionRequest())
assert resp_upd_empty.success == False
assert resp_upd_empty.data.errorCode == "VALIDATION_ERROR"
print("update_copilot_session empty body: OK (VALIDATION_ERROR)")

# Test 11: Chat Route
chat_body = CopilotChatRequest(
    conversationId="conv-999",
    userPrompt="Describe the subnet.",
    provider="groq",
    model="llama-3",
    createdAt="2026-07-03T12:10:00Z",
)
resp_chat = copilot_chat(chat_body)
assert resp_chat.success == True
chat_sess = resp_chat.data["session"]
assert chat_sess["sessionId"] is not None
assert chat_sess["turns"] == 1
assert "Mock response content" in chat_sess["response"]["content"]
print("copilot_chat (new session): OK")

# Test 12: Chat Route (continue existing)
chat_body_cont = CopilotChatRequest(
    conversationId="conv-999",
    userPrompt="What else?",
    provider="groq",
    model="llama-3",
    createdAt="2026-07-03T12:11:00Z",
    sessionId=chat_sess["sessionId"],
)
resp_chat_cont = copilot_chat(chat_body_cont)
assert resp_chat_cont.success == True
chat_sess_cont = resp_chat_cont.data["session"]
assert chat_sess_cont["sessionId"] != chat_sess["sessionId"]
assert chat_sess_cont["turns"] == 2
print("copilot_chat (continue session): OK")

# Test 13: Delete Session
resp_del = delete_copilot_session(sessionId)
assert resp_del.success == True
print("delete_copilot_session: OK")

# Test 14: Delete missing session -> 404
resp_del_missing = delete_copilot_session(sessionId)
assert resp_del_missing.success == False
assert resp_del_missing.data.errorCode == "NOT_FOUND"
print("delete_copilot_session missing: OK (NOT_FOUND)")

# Test 15: List after delete
resp_list_after = list_copilot_sessions()
# We created two sessions via chat (new and continue), so total should be 2
assert resp_list_after.data["total"] == 2
print("list_copilot_sessions after delete: OK")

print("\nALL CHECKS PASSED SUCCESSFULLY!")
