"""
Smoke Test — Conversation Manager Engine
==========================================
Phase A4.4.0 — Verifies every model, builder, validator, serialisation path,
integration helper, fingerprint, lifecycle operation, thread operation,
utility function, and statistics in
services/conversation_manager_service.py.

Run:
    python smoke_test_conversation_manager_engine.py
Expected: 350+/350 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. Pure model / builder / validator tests.
- Same inputs -> same outputs (fully deterministic).
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: List[str] = []


def _assert(cond: bool, msg: str) -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
    else:
        _FAIL += 1
        frame = traceback.extract_stack()[-2]
        _ERRORS.append(f"FAIL [line {frame.lineno}]: {msg}")


def _eq(a, b, msg):  _assert(a == b,  f"{msg} — expected {b!r}, got {a!r}")
def _ne(a, b, msg):  _assert(a != b,  f"{msg} — both are {a!r}")
def _in(x, c, msg):  _assert(x in c,  f"{msg} — {x!r} not in collection")
def _ni(x, c, msg):  _assert(x not in c, f"{msg} — {x!r} unexpectedly in collection")
def _gt(a, b, msg):  _assert(a > b,   f"{msg} — {a!r} not > {b!r}")
def _ge(a, b, msg):  _assert(a >= b,  f"{msg} — {a!r} not >= {b!r}")
def _lt(a, b, msg):  _assert(a < b,   f"{msg} — {a!r} not < {b!r}")
def _is(a, t, msg):  _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
def _true(v, msg):   _assert(bool(v), f"{msg}")
def _false(v, msg):  _assert(not bool(v), f"{msg}")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.conversation_manager_service import (
    # Enumerations
    ConversationRole, ConversationState,
    # Exceptions
    ConversationManagerError, InvalidMessageError,
    InvalidThreadError, InvalidConversationError,
    # Models
    ConversationMessage, ConversationThread,
    ConversationMetadata, Conversation, ConversationStatistics,
    # Builders
    build_message, build_thread, build_metadata,
    build_conversation, build_statistics,
    # Validators
    validate_message, validate_thread, validate_conversation,
    # ID helpers
    _sha256_32, _sha256_64, _uuid5,
    _compute_message_key, _compute_thread_key,
    _compute_conversation_key, _compute_conversation_fingerprint,
    # Integration helpers
    messages_to_execution_prompts,
    conversation_to_prompt_sections,
    conversation_to_copilot_context,
    # Lifecycle operations
    add_message, edit_message, delete_message, move_message,
    archive_conversation, pause_conversation,
    resume_conversation, complete_conversation,
    # Thread operations
    create_thread, merge_threads, split_thread, find_thread,
    # Message utilities
    sort_messages, filter_messages, group_messages, find_message,
    # Conversation utilities
    sort_conversations, filter_conversations,
    group_conversations, find_conversation,
    # Engine version (re-exported from service module import)
    CONVERSATION_MANAGER_ENGINE_VERSION,
)
from core.constants import CONVERSATION_MANAGER_ENGINE_VERSION as CONST_CMV

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS   = "2026-07-01T12:00:00Z"
_TS2  = "2026-07-01T13:00:00Z"
_TS3  = "2026-07-01T14:00:00Z"
_CONV_ID = "conv-test-001"
_INV_ID  = "inv-abc-123"
_USER    = "analyst-01"
_TITLE   = "Incident Analysis Session"


# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version ...")
_eq(CONVERSATION_MANAGER_ENGINE_VERSION, "conversation-manager-v1", "version value")
_eq(CONST_CMV, CONVERSATION_MANAGER_ENGINE_VERSION, "core.constants matches service")
_is(CONVERSATION_MANAGER_ENGINE_VERSION, str, "version is str")
_in("conversation-manager", CONVERSATION_MANAGER_ENGINE_VERSION, "version contains 'conversation-manager'")

# ===========================================================================
# §2  ConversationRole enum
# ===========================================================================
print("§2  ConversationRole ...")
_eq(ConversationRole.SYSTEM.value,    "SYSTEM",    "SYSTEM value")
_eq(ConversationRole.USER.value,      "USER",      "USER value")
_eq(ConversationRole.ASSISTANT.value, "ASSISTANT", "ASSISTANT value")
_eq(ConversationRole.TOOL.value,      "TOOL",      "TOOL value")
_eq(len(ConversationRole), 4, "exactly 4 roles")
# All roles are distinct
roles = [r.value for r in ConversationRole]
_eq(len(roles), len(set(roles)), "all role values are distinct")
# ConversationRole is a str subclass
_is(ConversationRole.USER, str, "ConversationRole is str subclass")

# ===========================================================================
# §3  ConversationState enum
# ===========================================================================
print("§3  ConversationState ...")
_eq(ConversationState.ACTIVE.value,    "ACTIVE",    "ACTIVE value")
_eq(ConversationState.PAUSED.value,    "PAUSED",    "PAUSED value")
_eq(ConversationState.COMPLETED.value, "COMPLETED", "COMPLETED value")
_eq(ConversationState.ARCHIVED.value,  "ARCHIVED",  "ARCHIVED value")
_eq(len(ConversationState), 4, "exactly 4 states")
states = [s.value for s in ConversationState]
_eq(len(states), len(set(states)), "all state values are distinct")
_is(ConversationState.ACTIVE, str, "ConversationState is str subclass")

# ===========================================================================
# §4  Deterministic ID helpers
# ===========================================================================
print("§4  ID helpers ...")

# _sha256_32
h1 = _sha256_32("alpha", "beta")
h2 = _sha256_32("alpha", "beta")
_eq(h1, h2,   "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 returns 32 chars")
_true(all(c in "0123456789abcdef" for c in h1), "_sha256_32 is hex")
h3 = _sha256_32("beta", "alpha")
_ne(h1, h3,   "different order -> different hash")
h4 = _sha256_32("alpha", "beta", "gamma")
_ne(h1, h4,   "extra part -> different hash")

# _sha256_64
f1 = _sha256_64("alpha", "beta")
_eq(len(f1), 64, "_sha256_64 returns 64 chars")
_true(f1.startswith(h1), "_sha256_64 starts with _sha256_32 result")

# _uuid5
u1 = _uuid5("test-key-abc")
u2 = _uuid5("test-key-abc")
_eq(u1, u2,   "_uuid5 deterministic")
_eq(len(u1), 36, "_uuid5 returns 36-char UUID")
_eq(u1[14],  "5", "_uuid5 is version 5")
u3 = _uuid5("other-key-xyz")
_ne(u1, u3,   "different key -> different UUID")

# _compute_message_key
mk1 = _compute_message_key(_CONV_ID, "USER", "Hello world", 1)
mk2 = _compute_message_key(_CONV_ID, "USER", "Hello world", 1)
_eq(mk1, mk2,   "_compute_message_key deterministic")
_eq(len(mk1), 32, "_compute_message_key 32 chars")
mk3 = _compute_message_key(_CONV_ID, "ASSISTANT", "Hello world", 1)
_ne(mk1, mk3,   "different role -> different message key")
mk4 = _compute_message_key(_CONV_ID, "USER", "Hello world", 2)
_ne(mk1, mk4,   "different seq -> different message key")

# _compute_thread_key
msg_ids = ("msg-1", "msg-2", "msg-3")
tk1 = _compute_thread_key(_CONV_ID, "msg-1", msg_ids)
tk2 = _compute_thread_key(_CONV_ID, "msg-1", msg_ids)
_eq(tk1, tk2,   "_compute_thread_key deterministic")
_eq(len(tk1), 32, "_compute_thread_key 32 chars")
tk3 = _compute_thread_key(_CONV_ID, "msg-2", msg_ids)
_ne(tk1, tk3,   "different root -> different thread key")

# _compute_conversation_key
ck1 = _compute_conversation_key(_INV_ID, _USER, _TITLE)
ck2 = _compute_conversation_key(_INV_ID, _USER, _TITLE)
_eq(ck1, ck2,   "_compute_conversation_key deterministic")
_eq(len(ck1), 32, "_compute_conversation_key 32 chars")
ck3 = _compute_conversation_key(_INV_ID, "other-analyst", _TITLE)
_ne(ck1, ck3,   "different user -> different conversation key")

# _compute_conversation_fingerprint
cfp1 = _compute_conversation_fingerprint(ck1, ("mk1", "mk2"), ("tk1",))
cfp2 = _compute_conversation_fingerprint(ck1, ("mk1", "mk2"), ("tk1",))
_eq(cfp1, cfp2, "_compute_conversation_fingerprint deterministic")
_eq(len(cfp1), 32, "fingerprint is 32 chars")
cfp3 = _compute_conversation_fingerprint(ck1, ("mk2", "mk1"), ("tk1",))
_eq(cfp1, cfp3, "fingerprint is order-independent for messageKeys")
cfp4 = _compute_conversation_fingerprint(ck1, ("mk1", "mk2"), ("tk2",))
_ne(cfp1, cfp4, "different thread key -> different fingerprint")

# ===========================================================================
# §5  validate_message()
# ===========================================================================
print("§5  validate_message() ...")

# Valid call — no exception
try:
    validate_message(_CONV_ID, ConversationRole.USER, "Hello", 1, _TS)
    _assert(True, "valid message -> no exception")
except InvalidMessageError:
    _assert(False, "valid message should not raise")

# Empty conversation_id raises
try:
    validate_message("", ConversationRole.USER, "Hello", 1, _TS)
    _assert(False, "empty conversationId should raise")
except InvalidMessageError as e:
    _assert(True, "empty conversationId raises InvalidMessageError")
    _in("conversationId", str(e), "error mentions conversationId")

# None content raises
try:
    validate_message(_CONV_ID, ConversationRole.USER, None, 1, _TS)  # type: ignore
    _assert(False, "None content should raise")
except InvalidMessageError as e:
    _assert(True, "None content raises InvalidMessageError")
    _in("content", str(e), "error mentions content")

# sequenceNumber = 0 raises
try:
    validate_message(_CONV_ID, ConversationRole.USER, "Hi", 0, _TS)
    _assert(False, "sequenceNumber=0 should raise")
except InvalidMessageError as e:
    _assert(True, "sequenceNumber=0 raises InvalidMessageError")
    _in("sequenceNumber", str(e), "error mentions sequenceNumber")

# Negative sequenceNumber raises
try:
    validate_message(_CONV_ID, ConversationRole.USER, "Hi", -1, _TS)
    _assert(False, "negative sequenceNumber should raise")
except InvalidMessageError:
    _assert(True, "negative sequenceNumber raises InvalidMessageError")

# Empty createdAt raises
try:
    validate_message(_CONV_ID, ConversationRole.USER, "Hi", 1, "")
    _assert(False, "empty createdAt should raise")
except InvalidMessageError as e:
    _assert(True, "empty createdAt raises InvalidMessageError")
    _in("createdAt", str(e), "error mentions createdAt")

# Invalid role type raises
try:
    validate_message(_CONV_ID, "USER", "Hi", 1, _TS)  # type: ignore
    _assert(False, "string role should raise")
except InvalidMessageError as e:
    _assert(True, "string role raises InvalidMessageError")
    _in("role", str(e), "error mentions role")

# Empty content is allowed (tool placeholder)
try:
    validate_message(_CONV_ID, ConversationRole.TOOL, "", 1, _TS)
    _assert(True, "empty content allowed for TOOL role")
except InvalidMessageError:
    _assert(False, "empty content should be allowed")

# ===========================================================================
# §6  validate_thread()
# ===========================================================================
print("§6  validate_thread() ...")

_ids = ("msg-a", "msg-b", "msg-c")

# Valid call
try:
    validate_thread(_CONV_ID, "msg-a", _ids, 0, _TS)
    _assert(True, "valid thread -> no exception")
except InvalidThreadError:
    _assert(False, "valid thread should not raise")

# Empty conversationId raises
try:
    validate_thread("", "msg-a", _ids, 0, _TS)
    _assert(False, "empty conversationId should raise")
except InvalidThreadError as e:
    _assert(True, "empty conversationId raises InvalidThreadError")
    _in("conversationId", str(e), "error mentions conversationId")

# Empty rootMessageId raises
try:
    validate_thread(_CONV_ID, "", _ids, 0, _TS)
    _assert(False, "empty rootMessageId should raise")
except InvalidThreadError as e:
    _assert(True, "empty rootMessageId raises InvalidThreadError")
    _in("rootMessageId", str(e), "error mentions rootMessageId")

# Empty messageIds raises
try:
    validate_thread(_CONV_ID, "msg-a", (), 0, _TS)
    _assert(False, "empty messageIds should raise")
except InvalidThreadError as e:
    _assert(True, "empty messageIds raises InvalidThreadError")
    _in("messageIds", str(e), "error mentions messageIds")

# rootMessageId not in messageIds raises
try:
    validate_thread(_CONV_ID, "msg-z", _ids, 0, _TS)
    _assert(False, "rootMessageId not in messageIds should raise")
except InvalidThreadError as e:
    _assert(True, "rootMessageId not in messageIds raises InvalidThreadError")
    _in("rootMessageId", str(e), "error mentions rootMessageId")

# Negative depth raises
try:
    validate_thread(_CONV_ID, "msg-a", _ids, -1, _TS)
    _assert(False, "negative depth should raise")
except InvalidThreadError as e:
    _assert(True, "negative depth raises InvalidThreadError")
    _in("depth", str(e), "error mentions depth")

# Empty createdAt raises
try:
    validate_thread(_CONV_ID, "msg-a", _ids, 0, "")
    _assert(False, "empty createdAt should raise")
except InvalidThreadError as e:
    _assert(True, "empty createdAt raises InvalidThreadError")

# ===========================================================================
# §7  validate_conversation()
# ===========================================================================
print("§7  validate_conversation() ...")

# Valid call
try:
    validate_conversation(_INV_ID, _USER, _TITLE, _TS, ConversationState.ACTIVE)
    _assert(True, "valid conversation -> no exception")
except InvalidConversationError:
    _assert(False, "valid conversation should not raise")

# Empty investigation_id is allowed
try:
    validate_conversation("", _USER, _TITLE, _TS, ConversationState.ACTIVE)
    _assert(True, "empty investigationId is allowed")
except InvalidConversationError:
    _assert(False, "empty investigationId should be allowed")

# Empty createdBy raises
try:
    validate_conversation(_INV_ID, "", _TITLE, _TS, ConversationState.ACTIVE)
    _assert(False, "empty createdBy should raise")
except InvalidConversationError as e:
    _assert(True, "empty createdBy raises InvalidConversationError")
    _in("createdBy", str(e), "error mentions createdBy")

# Empty title raises
try:
    validate_conversation(_INV_ID, _USER, "", _TS, ConversationState.ACTIVE)
    _assert(False, "empty title should raise")
except InvalidConversationError as e:
    _assert(True, "empty title raises InvalidConversationError")
    _in("title", str(e), "error mentions title")

# Empty createdAt raises
try:
    validate_conversation(_INV_ID, _USER, _TITLE, "", ConversationState.ACTIVE)
    _assert(False, "empty createdAt should raise")
except InvalidConversationError as e:
    _assert(True, "empty createdAt raises InvalidConversationError")
    _in("createdAt", str(e), "error mentions createdAt")

# Invalid state type raises
try:
    validate_conversation(_INV_ID, _USER, _TITLE, _TS, "ACTIVE")  # type: ignore
    _assert(False, "string state should raise")
except InvalidConversationError as e:
    _assert(True, "string state raises InvalidConversationError")
    _in("state", str(e), "error mentions state")

# ===========================================================================
# §8  build_message()
# ===========================================================================
print("§8  build_message() ...")

conv = build_conversation(
    created_by       = _USER,
    title            = _TITLE,
    created_at       = _TS,
    investigation_id = _INV_ID,
)

msg1 = build_message(
    conversation_id   = conv.conversationId,
    role              = ConversationRole.SYSTEM,
    content           = "You are a security analyst assistant.",
    sequence_number   = 1,
    created_at        = _TS,
)
_is(msg1, ConversationMessage, "returns ConversationMessage")
_eq(len(msg1.messageId),  36, "messageId is 36-char UUID")
_eq(msg1.messageId[14],   "5", "messageId is UUIDv5")
_eq(len(msg1.messageKey), 32, "messageKey is 32 chars")
_eq(msg1.conversationId,  conv.conversationId, "conversationId stored")
_eq(msg1.parentMessageId, "", "default parentMessageId is empty string")
_eq(msg1.role,            ConversationRole.SYSTEM, "role stored")
_eq(msg1.content,         "You are a security analyst assistant.", "content stored")
_eq(msg1.sequenceNumber,  1, "sequenceNumber stored")
_gt(msg1.tokenEstimate,   0, "tokenEstimate > 0 for non-empty content")
_eq(msg1.createdAt,       _TS, "createdAt stored")
_is(msg1.metadata,        dict, "metadata is dict")

# Determinism
msg1b = build_message(
    conversation_id = conv.conversationId,
    role            = ConversationRole.SYSTEM,
    content         = "You are a security analyst assistant.",
    sequence_number = 1,
    created_at      = _TS,
)
_eq(msg1.messageId,  msg1b.messageId,  "same inputs -> same messageId")
_eq(msg1.messageKey, msg1b.messageKey, "same inputs -> same messageKey")

# Different role -> different IDs
msg1_user = build_message(conv.conversationId, ConversationRole.USER,
                          "You are a security analyst assistant.", 1, _TS)
_ne(msg1.messageId, msg1_user.messageId, "different role -> different messageId")

# Different sequence -> different IDs
msg1_s2 = build_message(conv.conversationId, ConversationRole.SYSTEM,
                        "You are a security analyst assistant.", 2, _TS)
_ne(msg1.messageId, msg1_s2.messageId, "different seq -> different messageId")

# Parent message ID stored
msg_with_parent = build_message(
    conv.conversationId, ConversationRole.USER, "Follow-up", 2, _TS,
    parent_message_id=msg1.messageId,
)
_eq(msg_with_parent.parentMessageId, msg1.messageId, "parentMessageId stored")

# Metadata stored
msg_meta = build_message(
    conv.conversationId, ConversationRole.TOOL, "tool result", 3, _TS,
    metadata={"toolName": "search_assets", "callId": "tc-001"},
)
_eq(msg_meta.metadata["toolName"], "search_assets", "metadata dict stored")
_eq(msg_meta.metadata["callId"],   "tc-001",        "metadata callId stored")

# Empty content allowed (tool placeholder)
msg_empty = build_message(conv.conversationId, ConversationRole.TOOL, "", 1, _TS,
                          validate=False)
_eq(msg_empty.content,       "", "empty content stored")
_eq(msg_empty.tokenEstimate,  0, "empty content -> tokenEstimate=0")

# Immutability
try:
    msg1.content = "changed"  # type: ignore
    _assert(False, "ConversationMessage should be frozen")
except Exception:
    _assert(True, "ConversationMessage is immutable")

# Validation disabled
msg_novalidate = build_message(
    conv.conversationId, ConversationRole.USER, "text", 1, _TS, validate=False
)
_is(msg_novalidate, ConversationMessage, "validate=False still builds message")

# Invalid sequence raises when validate=True
try:
    build_message(conv.conversationId, ConversationRole.USER, "text", 0, _TS)
    _assert(False, "seq=0 should raise InvalidMessageError")
except InvalidMessageError:
    _assert(True, "seq=0 raises InvalidMessageError")

# Token estimate accuracy — test for length-based ceiling
long_content = "A" * 100  # 100 chars / 4 = 25 tokens
msg_long = build_message(conv.conversationId, ConversationRole.USER, long_content, 1, _TS)
_eq(msg_long.tokenEstimate, 25, "tokenEstimate = ceil(100/4) = 25")

# All four roles can be used
for role in ConversationRole:
    m = build_message(conv.conversationId, role, f"Test {role.value}", 1, _TS)
    _eq(m.role, role, f"role {role.value} stored correctly")

# ===========================================================================
# §9  build_thread()
# ===========================================================================
print("§9  build_thread() ...")

# Build three messages to use as thread members
m_a = build_message(conv.conversationId, ConversationRole.USER,      "First",  1, _TS)
m_b = build_message(conv.conversationId, ConversationRole.ASSISTANT, "Second", 2, _TS)
m_c = build_message(conv.conversationId, ConversationRole.USER,      "Third",  3, _TS2)

thread1 = build_thread(
    conversation_id = conv.conversationId,
    root_message_id = m_a.messageId,
    message_ids     = [m_a.messageId, m_b.messageId, m_c.messageId],
    created_at      = _TS,
    depth           = 0,
)
_is(thread1, ConversationThread, "returns ConversationThread")
_eq(len(thread1.threadId),  36, "threadId is 36-char UUID")
_eq(thread1.threadId[14],   "5", "threadId is UUIDv5")
_eq(len(thread1.threadKey), 32, "threadKey is 32 chars")
_eq(thread1.rootMessageId,  m_a.messageId, "rootMessageId stored")
_in(m_a.messageId, thread1.messageIds, "m_a in messageIds")
_in(m_b.messageId, thread1.messageIds, "m_b in messageIds")
_in(m_c.messageId, thread1.messageIds, "m_c in messageIds")
_eq(thread1.depth,    0, "depth=0 stored")
_eq(thread1.createdAt, _TS, "createdAt stored")

# Determinism — same inputs -> same IDs
thread1b = build_thread(
    conv.conversationId, m_a.messageId,
    [m_a.messageId, m_b.messageId, m_c.messageId], _TS, 0,
)
_eq(thread1.threadId,  thread1b.threadId,  "same inputs -> same threadId")
_eq(thread1.threadKey, thread1b.threadKey, "same inputs -> same threadKey")

# messageIds are sorted regardless of input order
thread1c = build_thread(
    conv.conversationId, m_a.messageId,
    [m_c.messageId, m_a.messageId, m_b.messageId], _TS, 0,
)
_eq(thread1.threadId, thread1c.threadId, "input order doesn't affect threadId")

# Different root -> different thread ID
thread2 = build_thread(
    conv.conversationId, m_b.messageId,
    [m_a.messageId, m_b.messageId, m_c.messageId], _TS, 0,
)
_ne(thread1.threadId, thread2.threadId, "different root -> different threadId")

# Depth stored and clamped to 0 minimum
thread_deep = build_thread(
    conv.conversationId, m_a.messageId,
    [m_a.messageId], _TS, depth=3,
)
_eq(thread_deep.depth, 3, "depth=3 stored")

thread_neg_depth = build_thread(
    conv.conversationId, m_a.messageId,
    [m_a.messageId], _TS, depth=-5, validate=False,
)
_eq(thread_neg_depth.depth, 0, "negative depth clamped to 0")

# Single-message thread allowed
thread_single = build_thread(
    conv.conversationId, m_a.messageId, [m_a.messageId], _TS,
)
_eq(len(thread_single.messageIds), 1, "single-message thread allowed")

# Duplicate IDs are deduplicated
thread_dup = build_thread(
    conv.conversationId, m_a.messageId,
    [m_a.messageId, m_a.messageId, m_b.messageId], _TS,
)
_eq(len(thread_dup.messageIds), 2, "duplicate messageIds deduplicated")

# Immutability
try:
    thread1.depth = 99  # type: ignore
    _assert(False, "ConversationThread should be frozen")
except Exception:
    _assert(True, "ConversationThread is immutable")

# Validation: rootMessageId not in messageIds raises
try:
    build_thread(conv.conversationId, "non-existent-id", [m_a.messageId], _TS)
    _assert(False, "rootMessageId not in messageIds should raise")
except InvalidThreadError:
    _assert(True, "rootMessageId not in messageIds raises InvalidThreadError")

# ===========================================================================
# §10  build_metadata()
# ===========================================================================
print("§10  build_metadata() ...")

# Build some messages for metadata testing
meta_msgs = (
    build_message(conv.conversationId, ConversationRole.SYSTEM,    "Sys",      1, _TS),
    build_message(conv.conversationId, ConversationRole.USER,      "Query",    2, _TS),
    build_message(conv.conversationId, ConversationRole.ASSISTANT, "Response", 3, _TS2),
)
meta1 = build_metadata(
    title      = _TITLE,
    created_by = _USER,
    messages   = meta_msgs,
    created_at = _TS,
    summary    = "A test summary.",
    tags       = ["security", "network", "security"],  # duplicate
)
_is(meta1, ConversationMetadata, "returns ConversationMetadata")
_eq(meta1.title,         _TITLE,    "title stored")
_eq(meta1.summary,       "A test summary.", "summary stored")
_eq(meta1.totalMessages, 3, "totalMessages = 3")
_gt(meta1.totalTokens,   0, "totalTokens > 0")
_eq(meta1.lastMessageAt, _TS2, "lastMessageAt = most recent message's createdAt")
_eq(meta1.createdBy,     _USER, "createdBy stored")
_eq(meta1.tags,          ("network", "security"), "tags deduped and sorted")
_eq(meta1.engineVersion, CONVERSATION_MANAGER_ENGINE_VERSION, "engineVersion set")

# Empty messages -> sensible defaults
meta_empty = build_metadata(
    title      = "Empty",
    created_by = _USER,
    messages   = (),
    created_at = _TS,
)
_eq(meta_empty.totalMessages, 0,   "empty -> totalMessages=0")
_eq(meta_empty.totalTokens,   0,   "empty -> totalTokens=0")
_eq(meta_empty.lastMessageAt, _TS, "empty -> lastMessageAt=created_at fallback")
_eq(meta_empty.tags,          (),  "no tags -> empty tuple")

# Token count matches sum of individual messages
total_est = sum(m.tokenEstimate for m in meta_msgs)
_eq(meta1.totalTokens, total_est, "totalTokens matches sum of message tokenEstimates")

# Tags are lowercased and deduplicated
meta_tags = build_metadata("T", _USER, (), _TS, tags=["Alpha", "BETA", "alpha"])
_eq(meta_tags.tags, ("alpha", "beta"), "tags lowercased and deduplicated")

# Immutability
try:
    meta1.title = "changed"  # type: ignore
    _assert(False, "ConversationMetadata should be frozen")
except Exception:
    _assert(True, "ConversationMetadata is immutable")

# ===========================================================================
# §11  build_conversation()
# ===========================================================================
print("§11  build_conversation() ...")

# Minimal conversation (no messages, no threads)
c1 = build_conversation(
    created_by       = _USER,
    title            = _TITLE,
    created_at       = _TS,
    investigation_id = _INV_ID,
)
_is(c1, Conversation, "returns Conversation")
_eq(len(c1.conversationId),  36, "conversationId is 36-char UUID")
_eq(c1.conversationId[14],   "5", "conversationId is UUIDv5")
_eq(len(c1.conversationKey), 32, "conversationKey is 32 chars")
_eq(len(c1.conversationFingerprint), 32, "conversationFingerprint is 32 chars")
_eq(c1.investigationId, _INV_ID, "investigationId stored")
_eq(c1.state,   ConversationState.ACTIVE, "default state is ACTIVE")
_eq(c1.messages, (), "no messages -> empty tuple")
_eq(c1.threads,  (), "no threads -> empty tuple")
_is(c1.metadata, ConversationMetadata, "metadata is ConversationMetadata")
_eq(c1.createdAt, _TS, "createdAt stored")
_eq(c1.updatedAt, _TS, "updatedAt stored")

# Determinism
c1b = build_conversation(_USER, _TITLE, _TS, _INV_ID)
_eq(c1.conversationId,          c1b.conversationId,          "same inputs -> same conversationId")
_eq(c1.conversationKey,         c1b.conversationKey,         "same inputs -> same conversationKey")
_eq(c1.conversationFingerprint, c1b.conversationFingerprint, "same inputs -> same fingerprint")

# Different title -> different ID
c_other = build_conversation(_USER, "Other Title", _TS, _INV_ID)
_ne(c1.conversationId, c_other.conversationId, "different title -> different conversationId")

# Different investigationId -> different ID
c_other2 = build_conversation(_USER, _TITLE, _TS, "other-inv-999")
_ne(c1.conversationId, c_other2.conversationId, "different investigationId -> different conversationId")

# Messages are sorted by sequenceNumber
m1 = build_message(c1.conversationId, ConversationRole.USER,      "First",  1, _TS)
m2 = build_message(c1.conversationId, ConversationRole.ASSISTANT, "Second", 2, _TS)
m3 = build_message(c1.conversationId, ConversationRole.USER,      "Third",  3, _TS2)

c_with_msgs = build_conversation(
    created_by = _USER, title = _TITLE, created_at = _TS,
    investigation_id = _INV_ID,
    messages = [m3, m1, m2],  # deliberately out of order
)
_eq(c_with_msgs.messages[0].sequenceNumber, 1, "messages sorted: first is seq=1")
_eq(c_with_msgs.messages[1].sequenceNumber, 2, "messages sorted: second is seq=2")
_eq(c_with_msgs.messages[2].sequenceNumber, 3, "messages sorted: third is seq=3")

# metadata.totalMessages reflects message count
_eq(c_with_msgs.metadata.totalMessages, 3, "metadata.totalMessages=3")

# State stored
c_paused = build_conversation(_USER, _TITLE, _TS, state=ConversationState.PAUSED)
_eq(c_paused.state, ConversationState.PAUSED, "PAUSED state stored")

# All states can be used
for state in ConversationState:
    cx = build_conversation(_USER, _TITLE, _TS, state=state)
    _eq(cx.state, state, f"state {state.value} stored correctly")

# Fingerprint changes when messages change
c_no_msg = build_conversation(_USER, _TITLE, _TS, _INV_ID)
c_with_m = build_conversation(_USER, _TITLE, _TS, _INV_ID, messages=[m1])
_ne(c_no_msg.conversationFingerprint, c_with_m.conversationFingerprint,
    "adding message changes fingerprint")

# investigationId may be empty
c_no_inv = build_conversation(_USER, _TITLE, _TS, investigation_id="")
_eq(c_no_inv.investigationId, "", "empty investigationId allowed")

# Immutability
try:
    c1.state = ConversationState.ARCHIVED  # type: ignore
    _assert(False, "Conversation should be frozen")
except Exception:
    _assert(True, "Conversation is immutable")

# Validation: empty title raises
try:
    build_conversation(_USER, "", _TS)
    _assert(False, "empty title should raise")
except InvalidConversationError:
    _assert(True, "empty title raises InvalidConversationError")

# Validation disabled
c_novalidate = build_conversation(_USER, _TITLE, _TS, validate=False)
_is(c_novalidate, Conversation, "validate=False still builds conversation")

# ===========================================================================
# §12  Conversation with threads
# ===========================================================================
print("§12  Conversation with threads ...")

cx = build_conversation(
    created_by       = _USER,
    title            = "Thread Test",
    created_at       = _TS,
    investigation_id = _INV_ID,
)
mx1 = build_message(cx.conversationId, ConversationRole.USER,      "Start",   1, _TS)
mx2 = build_message(cx.conversationId, ConversationRole.ASSISTANT, "Reply",   2, _TS)
mx3 = build_message(cx.conversationId, ConversationRole.USER,      "Follow",  3, _TS2)

t1 = build_thread(cx.conversationId, mx1.messageId, [mx1.messageId, mx2.messageId], _TS, depth=0)
t2 = build_thread(cx.conversationId, mx2.messageId, [mx2.messageId, mx3.messageId], _TS, depth=1)

c_threads = build_conversation(
    created_by       = _USER,
    title            = "Thread Test",
    created_at       = _TS,
    investigation_id = _INV_ID,
    messages         = [mx1, mx2, mx3],
    threads          = [t2, t1],  # reversed order on purpose
)
_eq(len(c_threads.threads), 2, "two threads stored")
# threads are sorted by threadId ASC
_eq(
    c_threads.threads,
    tuple(sorted([t1, t2], key=lambda t: t.threadId)),
    "threads sorted by threadId ASC",
)
# fingerprint includes thread keys
c_no_t = build_conversation(_USER, "Thread Test", _TS, _INV_ID, messages=[mx1, mx2, mx3])
_ne(
    c_threads.conversationFingerprint,
    c_no_t.conversationFingerprint,
    "threads change the fingerprint",
)

# ===========================================================================
# §13  build_statistics()
# ===========================================================================
print("§13  build_statistics() ...")

# Empty list
stats_empty = build_statistics([])
_is(stats_empty, ConversationStatistics, "returns ConversationStatistics for empty list")
_eq(stats_empty.totalConversations,    0,   "empty: totalConversations=0")
_eq(stats_empty.activeConversations,   0,   "empty: activeConversations=0")
_eq(stats_empty.archivedConversations, 0,   "empty: archivedConversations=0")
_eq(stats_empty.averageMessages,       0.0, "empty: averageMessages=0.0")
_eq(stats_empty.averageTokens,         0.0, "empty: averageTokens=0.0")
_eq(stats_empty.longestConversation,   0,   "empty: longestConversation=0")
_eq(stats_empty.totalThreads,          0,   "empty: totalThreads=0")

# Build a set of conversations
ca1 = build_conversation(_USER, "Conv A", _TS, state=ConversationState.ACTIVE,
                          messages=[m1, m2])
ca2 = build_conversation(_USER, "Conv B", _TS, state=ConversationState.ACTIVE,
                          messages=[m1])
ca3 = build_conversation(_USER, "Conv C", _TS, state=ConversationState.ARCHIVED,
                          messages=[m1, m2, m3])
ca4 = build_conversation(_USER, "Conv D", _TS, state=ConversationState.COMPLETED,
                          messages=[])
ca5 = build_conversation(_USER, "Conv E", _TS, state=ConversationState.PAUSED,
                          messages=[m1, m2, m3],
                          threads=[t1])

stats = build_statistics([ca1, ca2, ca3, ca4, ca5])
_is(stats, ConversationStatistics, "returns ConversationStatistics")
_eq(stats.totalConversations,    5, "totalConversations=5")
_eq(stats.activeConversations,   2, "activeConversations=2 (ACTIVE only)")
_eq(stats.archivedConversations, 1, "archivedConversations=1")
_eq(stats.longestConversation,   3, "longestConversation=3 (max messages)")
_eq(stats.totalThreads,          1, "totalThreads=1 (from ca5)")
_gt(stats.averageMessages,       0.0, "averageMessages > 0")
_ge(stats.averageTokens,         0.0, "averageTokens >= 0")

# Determinism — same list -> same stats
stats2 = build_statistics([ca5, ca4, ca3, ca2, ca1])  # different order
_eq(stats.totalConversations,    stats2.totalConversations,    "stats deterministic: total")
_eq(stats.activeConversations,   stats2.activeConversations,   "stats deterministic: active")
_eq(stats.averageMessages,       stats2.averageMessages,       "stats deterministic: avg msgs")
_eq(stats.averageTokens,         stats2.averageTokens,         "stats deterministic: avg tokens")

# Immutability
try:
    stats.totalConversations = 99  # type: ignore
    _assert(False, "ConversationStatistics should be frozen")
except Exception:
    _assert(True, "ConversationStatistics is immutable")

# ===========================================================================
# §14  Serialisation — model_dump() / JSON round-trip
# ===========================================================================
print("§14  Serialisation ...")

import json

# ConversationMessage serialises cleanly
msg_ser = build_message(c1.conversationId, ConversationRole.USER, "Serialise me", 1, _TS)
d_msg = msg_ser.model_dump()
_is(d_msg,                  dict,  "model_dump() returns dict")
_in("messageId",            d_msg, "messageId in dump")
_in("messageKey",           d_msg, "messageKey in dump")
_in("conversationId",       d_msg, "conversationId in dump")
_in("role",                 d_msg, "role in dump")
_in("content",              d_msg, "content in dump")
_in("sequenceNumber",       d_msg, "sequenceNumber in dump")
_in("tokenEstimate",        d_msg, "tokenEstimate in dump")
_in("createdAt",            d_msg, "createdAt in dump")

# JSON serialisation
json_str = json.dumps(d_msg)
_is(json_str, str, "model_dump is JSON-serialisable")
restored = json.loads(json_str)
_eq(restored["messageId"],  msg_ser.messageId,  "messageId survives JSON round-trip")
_eq(restored["content"],    "Serialise me",     "content survives JSON round-trip")

# ConversationThread serialises cleanly
t_ser = build_thread(c1.conversationId, msg_ser.messageId, [msg_ser.messageId], _TS)
d_t = t_ser.model_dump()
_in("threadId",      d_t, "threadId in thread dump")
_in("threadKey",     d_t, "threadKey in thread dump")
_in("rootMessageId", d_t, "rootMessageId in thread dump")
_in("messageIds",    d_t, "messageIds in thread dump")
_in("depth",         d_t, "depth in thread dump")

# Conversation serialises cleanly
d_conv = c_with_msgs.model_dump()
_in("conversationId",          d_conv, "conversationId in conv dump")
_in("conversationKey",         d_conv, "conversationKey in conv dump")
_in("conversationFingerprint", d_conv, "conversationFingerprint in conv dump")
_in("investigationId",         d_conv, "investigationId in conv dump")
_in("state",                   d_conv, "state in conv dump")
_in("messages",                d_conv, "messages in conv dump")
_in("threads",                 d_conv, "threads in conv dump")
_in("metadata",                d_conv, "metadata in conv dump")
_in("messages",                d_conv, "messages key present in conv dump")

# ConversationStatistics serialises cleanly
d_stats = stats.model_dump()
_in("totalConversations",    d_stats, "totalConversations in stats dump")
_in("activeConversations",   d_stats, "activeConversations in stats dump")
_in("archivedConversations", d_stats, "archivedConversations in stats dump")
_in("averageMessages",       d_stats, "averageMessages in stats dump")
_in("averageTokens",         d_stats, "averageTokens in stats dump")
_in("longestConversation",   d_stats, "longestConversation in stats dump")
_in("totalThreads",          d_stats, "totalThreads in stats dump")

# Full JSON round-trip on Conversation
conv_json = json.dumps(d_conv, default=str)
_is(conv_json, str, "Conversation serialises to JSON string")
conv_restored = json.loads(conv_json)
_eq(conv_restored["conversationId"], c_with_msgs.conversationId,
    "conversationId survives JSON round-trip")
_eq(conv_restored["conversationFingerprint"], c_with_msgs.conversationFingerprint,
    "fingerprint survives JSON round-trip")

# ===========================================================================
# §15  Fingerprint stability
# ===========================================================================
print("§15  Fingerprint stability ...")

# Building identical conversations twice produces identical fingerprints
fp_base = build_conversation(_USER, "FP Test", _TS, _INV_ID,
                              messages=[m1, m2, m3]).conversationFingerprint
fp_copy = build_conversation(_USER, "FP Test", _TS, _INV_ID,
                              messages=[m3, m1, m2]).conversationFingerprint  # different list order
_eq(fp_base, fp_copy, "fingerprint is order-independent over messages")

# Adding a message changes the fingerprint
fp_less = build_conversation(_USER, "FP Test", _TS, _INV_ID,
                              messages=[m1, m2]).conversationFingerprint
_ne(fp_base, fp_less, "removing a message changes the fingerprint")

# Adding a thread changes the fingerprint
fp_no_thread  = build_conversation(_USER, "FP Test", _TS, _INV_ID, messages=[m1]).conversationFingerprint
fp_with_thread = build_conversation(_USER, "FP Test", _TS, _INV_ID, messages=[m1],
                                    threads=[t1]).conversationFingerprint
_ne(fp_no_thread, fp_with_thread, "adding thread changes fingerprint")

# conversationKey only depends on investigationId + createdBy + title
# (changing timestamps does not change the key)
key_ts1 = _compute_conversation_key(_INV_ID, _USER, _TITLE)
key_ts2 = _compute_conversation_key(_INV_ID, _USER, _TITLE)
_eq(key_ts1, key_ts2, "conversationKey is stable (same inputs)")

# messageKey content boundary — only first 64 chars of content used
content_long  = "X" * 200
content_short = "X" * 64
mk_long  = _compute_message_key(_CONV_ID, "USER", content_long,  1)
mk_short = _compute_message_key(_CONV_ID, "USER", content_short, 1)
_eq(mk_long, mk_short, "messageKey uses only content[:64] (boundary test)")

content_diff = "X" * 63 + "Y"
mk_diff = _compute_message_key(_CONV_ID, "USER", content_diff, 1)
_ne(mk_long, mk_diff, "content difference within 64 chars produces different key")

# ===========================================================================
# §16  Zero randomness verification
# ===========================================================================
print("§16  Zero randomness ...")

# Build 10 identical conversations in a loop — all IDs must match
base_id = build_conversation(_USER, "Dup Test", _TS, _INV_ID).conversationId
for i in range(10):
    cid = build_conversation(_USER, "Dup Test", _TS, _INV_ID).conversationId
    _eq(cid, base_id, f"iteration {i}: conversationId is identical (zero randomness)")

# Build 10 identical messages — all keys must match
base_mkey = build_message(c1.conversationId, ConversationRole.USER, "Dup", 1, _TS).messageKey
for i in range(10):
    mkey = build_message(c1.conversationId, ConversationRole.USER, "Dup", 1, _TS).messageKey
    _eq(mkey, base_mkey, f"message iteration {i}: messageKey is identical (zero randomness)")

# ===========================================================================
# §17  Integration: messages_to_execution_prompts()
# ===========================================================================
print("§17  messages_to_execution_prompts() ...")

sys_msg  = build_message(c1.conversationId, ConversationRole.SYSTEM,    "You are a detective.", 1, _TS)
user_msg = build_message(c1.conversationId, ConversationRole.USER,      "What happened?",       2, _TS)
asst_msg = build_message(c1.conversationId, ConversationRole.ASSISTANT, "I found clues.",       3, _TS)
tool_msg = build_message(c1.conversationId, ConversationRole.TOOL,      "Tool output here.",    4, _TS)

sys_prompt, user_prompt = messages_to_execution_prompts(
    (sys_msg, user_msg, asst_msg, tool_msg)
)

_is(sys_prompt,  str, "system_prompt is str")
_is(user_prompt, str, "user_prompt is str")
_in("You are a detective.", sys_prompt,  "SYSTEM content in system_prompt")
_ni("What happened",        sys_prompt,  "USER content not in system_prompt")
_in("USER: What happened?", user_prompt, "USER prefixed in user_prompt")
_in("ASSISTANT: I found",   user_prompt, "ASSISTANT prefixed in user_prompt")
_in("TOOL: Tool output",    user_prompt, "TOOL prefixed in user_prompt")
_ni("You are a detective",  user_prompt, "SYSTEM content not in user_prompt")

# Empty messages returns ("", "")
sp_empty, up_empty = messages_to_execution_prompts(())
_eq(sp_empty, "", "empty -> empty system_prompt")
_eq(up_empty, "", "empty -> empty user_prompt")

# Multiple SYSTEM messages joined
sys2 = build_message(c1.conversationId, ConversationRole.SYSTEM, "Extra system note.", 5, _TS)
sp2, _ = messages_to_execution_prompts((sys_msg, sys2))
_in("You are a detective.", sp2, "first SYSTEM in joined system_prompt")
_in("Extra system note.",   sp2, "second SYSTEM in joined system_prompt")

# Messages processed in sequenceNumber order (not insertion order)
reversed_order = (tool_msg, asst_msg, user_msg, sys_msg)
sp_r, up_r = messages_to_execution_prompts(reversed_order)
_in("You are a detective.", sp_r, "reversed input: SYSTEM still in system_prompt")
# USER appears before ASSISTANT in dialogue (seq 2 before 3)
u_idx = up_r.find("USER:")
a_idx = up_r.find("ASSISTANT:")
_lt(u_idx, a_idx, "USER appears before ASSISTANT in dialogue (sequence order)")

# ===========================================================================
# §18  Integration: conversation_to_prompt_sections()
# ===========================================================================
print("§18  conversation_to_prompt_sections() ...")

c_sections = build_conversation(
    created_by       = _USER,
    title            = "Section Test",
    created_at       = _TS,
    investigation_id = _INV_ID,
    messages         = [sys_msg, user_msg, asst_msg, tool_msg],
)
sections = conversation_to_prompt_sections(c_sections)
_is(sections, list, "returns list")
_eq(len(sections), 4, "one section per message")

# Check section structure
for sec in sections:
    _is(sec,             dict, "each section is a dict")
    _in("title",         sec,  "section has title")
    _in("content",       sec,  "section has content")
    _in("priority",      sec,  "section has priority")
    _is(sec["title"],    str,  "title is str")
    _is(sec["content"],  str,  "content is str")
    _is(sec["priority"], int,  "priority is int")

# Priority mapping: SYSTEM=90, USER=70, ASSISTANT=50, TOOL=30
priority_map = {s["title"].split()[0]: s["priority"] for s in sections}
_eq(priority_map["SYSTEM"],    90, "SYSTEM priority=90")
_eq(priority_map["USER"],      70, "USER priority=70")
_eq(priority_map["ASSISTANT"], 50, "ASSISTANT priority=50")
_eq(priority_map["TOOL"],      30, "TOOL priority=30")

# Title contains role and sequence number
_in("SYSTEM Message 1",    sections[0]["title"], "title includes role and seq 1")
_in("USER Message 2",      sections[1]["title"], "title includes role and seq 2")
_in("ASSISTANT Message 3", sections[2]["title"], "title includes role and seq 3")
_in("TOOL Message 4",      sections[3]["title"], "title includes role and seq 4")

# Content preserved
_eq(sections[0]["content"], "You are a detective.", "SYSTEM content preserved")
_eq(sections[1]["content"], "What happened?",       "USER content preserved")

# Empty conversation returns empty list
sections_empty = conversation_to_prompt_sections(c1)
_eq(sections_empty, [], "empty conversation -> empty sections list")

# ===========================================================================
# §19  Integration: conversation_to_copilot_context()
# ===========================================================================
print("§19  conversation_to_copilot_context() ...")

ctx = conversation_to_copilot_context(c_with_msgs)
_is(ctx, dict, "returns dict")
_eq(ctx["conversationId"],          c_with_msgs.conversationId,          "conversationId in ctx")
_eq(ctx["investigationId"],         c_with_msgs.investigationId,         "investigationId in ctx")
_eq(ctx["state"],                   c_with_msgs.state.value,             "state as string value")
_eq(ctx["totalMessages"],           c_with_msgs.metadata.totalMessages,  "totalMessages in ctx")
_eq(ctx["totalTokens"],             c_with_msgs.metadata.totalTokens,    "totalTokens in ctx")
_eq(ctx["lastMessageAt"],           c_with_msgs.metadata.lastMessageAt,  "lastMessageAt in ctx")
_eq(ctx["engineVersion"],           CONVERSATION_MANAGER_ENGINE_VERSION, "engineVersion in ctx")
_eq(ctx["conversationFingerprint"], c_with_msgs.conversationFingerprint, "fingerprint in ctx")
_eq(ctx["title"],                   c_with_msgs.metadata.title,          "title in ctx")
_eq(ctx["summary"],                 c_with_msgs.metadata.summary,        "summary in ctx")

# All values are JSON-serialisable
import json as _json
ctx_json = _json.dumps(ctx)
_is(ctx_json, str, "copilot context is JSON-serialisable")

# State is a string (not an enum object)
_is(ctx["state"], str, "state in context is plain str, not enum")

# Determinism
ctx2 = conversation_to_copilot_context(c_with_msgs)
_eq(ctx["conversationId"], ctx2["conversationId"], "context is deterministic")

# ===========================================================================
# §20  Exception hierarchy
# ===========================================================================
print("§20  Exception hierarchy ...")
_true(issubclass(InvalidMessageError,      ConversationManagerError), "InvalidMessageError inherits ConversationManagerError")
_true(issubclass(InvalidThreadError,       ConversationManagerError), "InvalidThreadError inherits ConversationManagerError")
_true(issubclass(InvalidConversationError, ConversationManagerError), "InvalidConversationError inherits ConversationManagerError")
_true(issubclass(ConversationManagerError, Exception), "ConversationManagerError inherits Exception")

# Exceptions carry meaningful messages
try:
    build_message("", ConversationRole.USER, "text", 1, _TS)
except InvalidMessageError as e:
    _true(len(str(e)) > 0, "InvalidMessageError has non-empty message")

try:
    build_thread("", "root", ("root",), _TS)
except InvalidThreadError as e:
    _true(len(str(e)) > 0, "InvalidThreadError has non-empty message")

try:
    build_conversation("", "", _TS)
except InvalidConversationError as e:
    _true(len(str(e)) > 0, "InvalidConversationError has non-empty message")

# ===========================================================================
# §21  Edge cases & boundary conditions
# ===========================================================================
print("§21  Edge cases ...")

# Very long content — token estimate scales correctly
content_1000 = "B" * 1000  # 1000 / 4 = 250 tokens
msg_big = build_message(c1.conversationId, ConversationRole.USER, content_1000, 1, _TS)
_eq(msg_big.tokenEstimate, 250, "1000-char content -> 250 token estimate")

# Single-character content — at least 1 token
msg_one = build_message(c1.conversationId, ConversationRole.USER, "X", 1, _TS)
_eq(msg_one.tokenEstimate, 1, "single char -> tokenEstimate=1")

# Very large sequence number
msg_highseq = build_message(c1.conversationId, ConversationRole.USER, "Hi", 99999, _TS)
_eq(msg_highseq.sequenceNumber, 99999, "large sequenceNumber stored")

# Conversation with 0 threads and multiple messages
c_many = build_conversation(
    _USER, "Many Messages", _TS, _INV_ID,
    messages=[
        build_message(c1.conversationId, ConversationRole.USER, f"msg {i}", i, _TS)
        for i in range(1, 11)
    ],
)
_eq(c_many.metadata.totalMessages, 10, "10 messages: totalMessages=10")
_eq(len(c_many.messages), 10, "10 messages in tuple")
_eq(c_many.messages[0].sequenceNumber, 1,  "first message is seq 1")
_eq(c_many.messages[9].sequenceNumber, 10, "last message is seq 10")

# Conversation title with special characters
c_special = build_conversation(_USER, "Test: <Alert!> & 'Quotes'", _TS)
_is(c_special.conversationId, str, "special chars in title: still valid UUID")

# Unicode content in message
msg_unicode = build_message(
    c1.conversationId, ConversationRole.USER, "Análisis de seguridad 🔒", 1, _TS
)
_eq(msg_unicode.content, "Análisis de seguridad 🔒", "unicode content preserved")
_gt(msg_unicode.tokenEstimate, 0, "unicode content: tokenEstimate > 0")

# metadata dict is copied (not a shared reference)
orig_meta = {"key": "value"}
msg_meta2 = build_message(c1.conversationId, ConversationRole.USER, "test", 1, _TS,
                           metadata=orig_meta)
orig_meta["key"] = "mutated"
_eq(msg_meta2.metadata["key"], "value", "metadata is copied (not shared reference)")

# ConversationThread messageIds are a tuple (not a list)
_is(thread1.messageIds, tuple, "thread messageIds is a tuple")

# Conversation messages is a tuple (not a list)
_is(c_with_msgs.messages, tuple, "conversation messages is a tuple")

# Conversation threads is a tuple (not a list)
_is(c_threads.threads, tuple, "conversation threads is a tuple")

# ConversationMetadata tags is a tuple
_is(meta1.tags, tuple, "metadata tags is a tuple")

# ===========================================================================
# §22  All-states statistics coverage
# ===========================================================================
print("§22  All-states statistics ...")

all_state_convs = [
    build_conversation(_USER, f"State {s.value}", _TS, state=s)
    for s in ConversationState
]
all_stats = build_statistics(all_state_convs)
_eq(all_stats.totalConversations, 4, "totalConversations=4 (one per state)")
_eq(all_stats.activeConversations,   1, "activeConversations=1")
_eq(all_stats.archivedConversations, 1, "archivedConversations=1")
# PAUSED and COMPLETED are not counted in either active or archived
non_active_archived = all_stats.totalConversations - all_stats.activeConversations - all_stats.archivedConversations
_eq(non_active_archived, 2, "PAUSED + COMPLETED = 2 (neither active nor archived)")


# ===========================================================================
# §23  Lifecycle: add_message()
# ===========================================================================
print("§23  add_message() ...")

_base = build_conversation(
    created_by       = _USER,
    title            = "Lifecycle Test",
    created_at       = _TS,
    investigation_id = _INV_ID,
)

# Add first message
_lc1 = add_message(_base, ConversationRole.USER, "Hello", _TS)
_eq(len(_lc1.messages), 1, "add_message: 1 message after first add")
_eq(_lc1.messages[0].sequenceNumber, 1, "first message seq=1")
_eq(_lc1.messages[0].role, ConversationRole.USER, "role USER stored")
_eq(_lc1.messages[0].content, "Hello", "content stored")
_eq(_lc1.updatedAt, _TS, "updatedAt set on add_message")
_eq(_lc1.conversationId, _base.conversationId, "conversationId unchanged")

# Add second message
_lc2 = add_message(_lc1, ConversationRole.ASSISTANT, "World", _TS2)
_eq(len(_lc2.messages), 2, "add_message: 2 messages after second add")
_eq(_lc2.messages[1].sequenceNumber, 2, "second message seq=2")
_eq(_lc2.updatedAt, _TS2, "updatedAt updated on second add")

# Fingerprint changes after add
_ne(_base.conversationFingerprint, _lc1.conversationFingerprint,
    "fingerprint changes after add_message")

# Original is unmodified (immutability)
_eq(len(_base.messages), 0, "original conversation unmodified after add_message")

# Add with parent
_lc_parent = add_message(_lc2, ConversationRole.USER, "Follow up", _TS3,
                         parent_message_id=_lc2.messages[0].messageId)
_eq(_lc_parent.messages[2].parentMessageId, _lc2.messages[0].messageId,
    "parentMessageId stored in added message")

# Determinism: same add produces same messageId
_lc1a = add_message(_base, ConversationRole.USER, "Hello", _TS)
_lc1b = add_message(_base, ConversationRole.USER, "Hello", _TS)
_eq(_lc1a.messages[0].messageId, _lc1b.messages[0].messageId,
    "add_message deterministic: same messageId")

# ===========================================================================
# §24  Lifecycle: edit_message() / delete_message()
# ===========================================================================
print("§24  edit_message() / delete_message() ...")

_ed_base = add_message(
    add_message(_base, ConversationRole.USER, "Original", _TS),
    ConversationRole.ASSISTANT, "Reply", _TS2,
)
_target_id = _ed_base.messages[0].messageId

# edit_message — content replaced
_edited = edit_message(_ed_base, _target_id, "Edited content", _TS3)
_eq(len(_edited.messages), 2, "edit: same message count")
_eq(_edited.messages[0].content, "Edited content", "edit: content replaced")
_eq(_edited.messages[0].sequenceNumber, 1, "edit: sequenceNumber preserved")
_eq(_edited.messages[0].role, ConversationRole.USER, "edit: role preserved")
_ne(_edited.messages[0].messageId, _target_id, "edit: new messageId after content change")
_ne(_edited.conversationFingerprint, _ed_base.conversationFingerprint,
    "edit: fingerprint changes")
_eq(_edited.updatedAt, _TS3, "edit: updatedAt set")

# edit not found raises
try:
    edit_message(_ed_base, "nonexistent-id", "x", _TS)
    _assert(False, "edit_message: not-found should raise")
except InvalidMessageError:
    _assert(True, "edit_message: not-found raises InvalidMessageError")

# delete_message
_deleted = delete_message(_ed_base, _target_id, _TS3)
_eq(len(_deleted.messages), 1, "delete: 1 message remains")
_eq(_deleted.messages[0].sequenceNumber, 2, "delete: remaining message seq=2 unchanged")
_ne(_deleted.conversationFingerprint, _ed_base.conversationFingerprint,
    "delete: fingerprint changes")
_eq(_deleted.updatedAt, _TS3, "delete: updatedAt set")

# delete not found raises
try:
    delete_message(_ed_base, "nonexistent-id", _TS)
    _assert(False, "delete_message: not-found should raise")
except InvalidMessageError:
    _assert(True, "delete_message: not-found raises InvalidMessageError")

# Original unmodified
_eq(len(_ed_base.messages), 2, "delete: original unchanged")


# ===========================================================================
# §25  Lifecycle: move_message()
# ===========================================================================
print("§25  move_message() ...")

_mv_base = add_message(
    add_message(_base, ConversationRole.USER, "First", _TS),
    ConversationRole.ASSISTANT, "Second", _TS2,
)
_mv_id = _mv_base.messages[0].messageId

# Move first message to seq 5
_moved = move_message(_mv_base, _mv_id, 5, _TS3)
moved_msg = next(m for m in _moved.messages if m.messageId != _mv_id
                 or True and m.sequenceNumber == 5)
# Find the moved message by matching new seq
found_moved = next(m for m in _moved.messages if m.sequenceNumber == 5)
_eq(found_moved.content, "First", "move: content preserved")
_eq(found_moved.role, ConversationRole.USER, "move: role preserved")
_ne(found_moved.messageId, _mv_id, "move: new messageId after seq change")
_eq(_moved.updatedAt, _TS3, "move: updatedAt set")
_eq(len(_moved.messages), 2, "move: message count unchanged")

# Move not found raises
try:
    move_message(_mv_base, "nonexistent", 3, _TS)
    _assert(False, "move_message: not-found should raise")
except InvalidMessageError:
    _assert(True, "move_message: not-found raises InvalidMessageError")

# Invalid seq raises
try:
    move_message(_mv_base, _mv_id, 0, _TS)
    _assert(False, "move_message: seq=0 should raise")
except InvalidMessageError:
    _assert(True, "move_message: seq=0 raises InvalidMessageError")


# ===========================================================================
# §26  Lifecycle: archive / pause / resume / complete
# ===========================================================================
print("§26  archive / pause / resume / complete ...")

_lc_active = build_conversation(_USER, "State Machine", _TS, _INV_ID)
_eq(_lc_active.state, ConversationState.ACTIVE, "initial state is ACTIVE")

# archive
_arch = archive_conversation(_lc_active, _TS2)
_eq(_arch.state, ConversationState.ARCHIVED, "archive: state is ARCHIVED")
_eq(_arch.updatedAt, _TS2, "archive: updatedAt set")
_eq(_arch.conversationId, _lc_active.conversationId, "archive: conversationId unchanged")
_eq(_lc_active.state, ConversationState.ACTIVE, "archive: original unchanged")

# pause
_paused = pause_conversation(_lc_active, _TS2)
_eq(_paused.state, ConversationState.PAUSED, "pause: state is PAUSED")
_eq(_paused.updatedAt, _TS2, "pause: updatedAt set")

# resume
_resumed = resume_conversation(_paused, _TS3)
_eq(_resumed.state, ConversationState.ACTIVE, "resume: state is ACTIVE")
_eq(_resumed.updatedAt, _TS3, "resume: updatedAt set")

# complete
_completed = complete_conversation(_lc_active, _TS3)
_eq(_completed.state, ConversationState.COMPLETED, "complete: state is COMPLETED")
_eq(_completed.updatedAt, _TS3, "complete: updatedAt set")

# Determinism: same transition produces same conversationFingerprint
_arch2 = archive_conversation(_lc_active, _TS2)
_eq(_arch.conversationFingerprint, _arch2.conversationFingerprint,
    "archive: deterministic fingerprint")

# State transitions don't change conversationId or conversationKey
_eq(_arch.conversationId,  _lc_active.conversationId,  "archive: same conversationId")
_eq(_arch.conversationKey, _lc_active.conversationKey, "archive: same conversationKey")

# build_statistics reflects lifecycle states
_stats_lc = build_statistics([_lc_active, _paused, _arch, _completed])
_eq(_stats_lc.totalConversations,    4, "stats: 4 total after lifecycle ops")
_eq(_stats_lc.activeConversations,   1, "stats: only _lc_active is ACTIVE")
_eq(_stats_lc.archivedConversations, 1, "stats: 1 archived")

# ===========================================================================
# §27  Thread: create_thread()
# ===========================================================================
print("§27  create_thread() ...")

# Build a conversation with 3 messages
_tc_conv = build_conversation(_USER, "Thread Ops", _TS, _INV_ID)
_tc_m1 = build_message(_tc_conv.conversationId, ConversationRole.USER,      "Msg1", 1, _TS)
_tc_m2 = build_message(_tc_conv.conversationId, ConversationRole.ASSISTANT, "Msg2", 2, _TS)
_tc_m3 = build_message(_tc_conv.conversationId, ConversationRole.USER,      "Msg3", 3, _TS2)
_tc_conv = build_conversation(
    _USER, "Thread Ops", _TS, _INV_ID,
    messages=[_tc_m1, _tc_m2, _tc_m3],
)

# create_thread adds one thread
_tc_with_t = create_thread(
    _tc_conv,
    root_message_id = _tc_m1.messageId,
    message_ids     = [_tc_m1.messageId, _tc_m2.messageId],
    created_at      = _TS,
    updated_at      = _TS2,
    depth           = 0,
)
_eq(len(_tc_with_t.threads), 1, "create_thread: 1 thread added")
_eq(_tc_with_t.threads[0].rootMessageId, _tc_m1.messageId, "create_thread: rootMessageId set")
_eq(_tc_with_t.updatedAt, _TS2, "create_thread: updatedAt set")
_ne(_tc_with_t.conversationFingerprint, _tc_conv.conversationFingerprint,
    "create_thread: fingerprint changes")

# Original unmodified
_eq(len(_tc_conv.threads), 0, "create_thread: original has no threads")

# Create second thread
_tc_with_t2 = create_thread(
    _tc_with_t,
    root_message_id = _tc_m3.messageId,
    message_ids     = [_tc_m3.messageId],
    created_at      = _TS2,
    updated_at      = _TS3,
    depth           = 1,
)
_eq(len(_tc_with_t2.threads), 2, "create_thread: 2 threads after second add")

# Determinism: same create produces same threadId
_tc_det_a = create_thread(_tc_conv, _tc_m1.messageId,
                           [_tc_m1.messageId, _tc_m2.messageId], _TS, _TS2)
_tc_det_b = create_thread(_tc_conv, _tc_m1.messageId,
                           [_tc_m1.messageId, _tc_m2.messageId], _TS, _TS2)
_eq(_tc_det_a.threads[0].threadId, _tc_det_b.threads[0].threadId,
    "create_thread: deterministic threadId")

# ===========================================================================
# §28  Thread: merge_threads()
# ===========================================================================
print("§28  merge_threads() ...")

_mt_tid_a = _tc_with_t2.threads[0].threadId
_mt_tid_b = _tc_with_t2.threads[1].threadId

_merged_conv = merge_threads(_tc_with_t2, _mt_tid_a, _mt_tid_b, _TS3)
_eq(len(_merged_conv.threads), 1, "merge_threads: 2 threads collapse to 1")
_merged_t = _merged_conv.threads[0]
# All message IDs from both source threads are present
_src_a_ids = set(_tc_with_t2.threads[0].messageIds)
_src_b_ids = set(_tc_with_t2.threads[1].messageIds)
_merged_ids = set(_merged_t.messageIds)
_true(_src_a_ids.issubset(_merged_ids), "merge: all thread-A messageIds present")
_true(_src_b_ids.issubset(_merged_ids), "merge: all thread-B messageIds present")
# rootMessageId comes from thread_a
_eq(_merged_t.rootMessageId, _tc_with_t2.threads[0].rootMessageId,
    "merge: rootMessageId from thread_a")
_eq(_merged_conv.updatedAt, _TS3, "merge: updatedAt set")
_ne(_merged_conv.conversationFingerprint, _tc_with_t2.conversationFingerprint,
    "merge: fingerprint changes")

# Not-found raises
try:
    merge_threads(_tc_with_t2, "bad-id-a", _mt_tid_b, _TS)
    _assert(False, "merge: bad thread_id_a should raise")
except InvalidThreadError:
    _assert(True, "merge: bad thread_id_a raises InvalidThreadError")

try:
    merge_threads(_tc_with_t2, _mt_tid_a, "bad-id-b", _TS)
    _assert(False, "merge: bad thread_id_b should raise")
except InvalidThreadError:
    _assert(True, "merge: bad thread_id_b raises InvalidThreadError")

# Determinism
_merged2 = merge_threads(_tc_with_t2, _mt_tid_a, _mt_tid_b, _TS3)
_eq(_merged_conv.threads[0].threadId, _merged2.threads[0].threadId,
    "merge_threads: deterministic threadId")

# ===========================================================================
# §29  Thread: split_thread()
# ===========================================================================
print("§29  split_thread() ...")

# Use the merged thread as the source to split
_split_tid  = _merged_conv.threads[0].threadId
_split_root = _tc_m3.messageId
_split_ids  = [_tc_m3.messageId]

_split_conv = split_thread(
    _merged_conv,
    thread_id    = _split_tid,
    new_root_id  = _split_root,
    split_ids    = _split_ids,
    created_at   = _TS2,
    updated_at   = _TS3,
)
_eq(len(_split_conv.threads), 2, "split_thread: 1 thread becomes 2")
# new thread has split_ids
_new_thread = next(
    t for t in _split_conv.threads
    if _tc_m3.messageId in t.messageIds and t.rootMessageId == _split_root
)
_eq(_new_thread.rootMessageId, _split_root, "split: new thread rootMessageId correct")
_in(_tc_m3.messageId, _new_thread.messageIds, "split: split message in new thread")
# original thread no longer contains the split id
_orig_thread = next(t for t in _split_conv.threads if t.threadId != _new_thread.threadId)
_ni(_tc_m3.messageId, _orig_thread.messageIds, "split: split message removed from original")
_eq(_split_conv.updatedAt, _TS3, "split: updatedAt set")
_ne(_split_conv.conversationFingerprint, _merged_conv.conversationFingerprint,
    "split: fingerprint changes")

# Not-found raises
try:
    split_thread(_merged_conv, "bad-id", _split_root, _split_ids, _TS, _TS)
    _assert(False, "split: bad threadId should raise")
except InvalidThreadError:
    _assert(True, "split: bad threadId raises InvalidThreadError")

# Splitting all messages out raises
try:
    all_ids = list(_merged_conv.threads[0].messageIds)
    split_thread(_merged_conv, _split_tid, all_ids[0], all_ids, _TS, _TS)
    _assert(False, "split: removing all messages should raise")
except InvalidThreadError:
    _assert(True, "split: removing all messages raises InvalidThreadError")

# ===========================================================================
# §30  Thread: find_thread()
# ===========================================================================
print("§30  find_thread() ...")

# find by threadId
_ft = find_thread(_tc_with_t2, thread_id=_tc_with_t2.threads[0].threadId)
_assert(_ft is not None, "find_thread: found by threadId")
_eq(_ft.threadId, _tc_with_t2.threads[0].threadId, "find_thread: correct thread by id")

# find by rootMessageId
_ft2 = find_thread(_tc_with_t2, root_message_id=_tc_m3.messageId)
_assert(_ft2 is not None, "find_thread: found by rootMessageId")
_eq(_ft2.rootMessageId, _tc_m3.messageId, "find_thread: correct thread by root")

# not found returns None
_assert(find_thread(_tc_with_t2, thread_id="nonexistent") is None,
        "find_thread: not-found returns None")
_assert(find_thread(_tc_with_t2, root_message_id="nonexistent") is None,
        "find_thread: not-found by root returns None")

# no criterion returns None
_assert(find_thread(_tc_with_t2) is None,
        "find_thread: no criterion returns None")

# threadId priority over rootMessageId
_ft_prio = find_thread(
    _tc_with_t2,
    thread_id       = _tc_with_t2.threads[0].threadId,
    root_message_id = _tc_m3.messageId,
)
_eq(_ft_prio.threadId, _tc_with_t2.threads[0].threadId,
    "find_thread: threadId takes priority over rootMessageId")

# empty conversation
_eq(find_thread(_tc_conv, thread_id="x"), None, "find_thread: empty conv returns None")

# ===========================================================================
# §31  sort_messages()
# ===========================================================================
print("§31  sort_messages() ...")

_sm_msgs = [
    build_message(_tc_conv.conversationId, ConversationRole.USER,      "C", 3, _TS),
    build_message(_tc_conv.conversationId, ConversationRole.ASSISTANT, "A", 1, _TS),
    build_message(_tc_conv.conversationId, ConversationRole.TOOL,      "B", 2, _TS),
]
_sorted_asc  = sort_messages(_sm_msgs, ascending=True)
_sorted_desc = sort_messages(_sm_msgs, ascending=False)

_eq(_sorted_asc[0].sequenceNumber,  1, "sort ASC: first seq=1")
_eq(_sorted_asc[1].sequenceNumber,  2, "sort ASC: second seq=2")
_eq(_sorted_asc[2].sequenceNumber,  3, "sort ASC: third seq=3")
_eq(_sorted_desc[0].sequenceNumber, 3, "sort DESC: first seq=3")
_eq(_sorted_desc[2].sequenceNumber, 1, "sort DESC: last seq=1")

# Input not mutated
_eq(_sm_msgs[0].sequenceNumber, 3, "sort_messages: input not mutated")

# Empty list
_eq(sort_messages([]), [], "sort_messages: empty returns empty")

# Determinism
_eq(sort_messages(_sm_msgs), sort_messages(_sm_msgs), "sort_messages: deterministic")

# Result is a list
_is(sort_messages(_sm_msgs), list, "sort_messages: returns list")

# Default ascending
_sorted_default = sort_messages(_sm_msgs)
_eq(_sorted_default[0].sequenceNumber, 1, "sort_messages: default ascending")

# ===========================================================================
# §32  filter_messages()
# ===========================================================================
print("§32  filter_messages() ...")

_conv_a_id = _tc_conv.conversationId
_conv_b_id = build_conversation(_USER, "Other Conv", _TS).conversationId

_fm_msgs = [
    build_message(_conv_a_id, ConversationRole.USER,      "Short",          1, _TS),
    build_message(_conv_a_id, ConversationRole.ASSISTANT, "A" * 200,        2, _TS),
    build_message(_conv_a_id, ConversationRole.USER,      "Another user",   3, _TS2),
    build_message(_conv_b_id, ConversationRole.TOOL,      "Tool result",    1, _TS),
]

# filter by role
_by_user = filter_messages(_fm_msgs, role=ConversationRole.USER)
_eq(len(_by_user), 2, "filter by USER role → 2")
_true(all(m.role == ConversationRole.USER for m in _by_user),
      "filter: all results are USER")

_by_tool = filter_messages(_fm_msgs, role=ConversationRole.TOOL)
_eq(len(_by_tool), 1, "filter by TOOL role → 1")

# filter by min_tokens
_big = filter_messages(_fm_msgs, min_tokens=40)
_eq(len(_big), 1, "filter min_tokens=40 → 1 (200-char message)")

# filter by max_tokens — "Short"=2t, "Another user"=3t, "Tool result"=3t, "A"*200=50t
# max_tokens=5 returns all except the 200-char message (50 tokens)
_small = filter_messages(_fm_msgs, max_tokens=5)
_eq(len(_small), 3, "filter max_tokens=5 → 3 (all except 200-char message)")

# filter by max_tokens strict — only the very short message
_very_small = filter_messages(_fm_msgs, max_tokens=2)
_eq(len(_very_small), 1, "filter max_tokens=2 → only 'Short' (2 tokens)")

# filter by conversation_id
_conv_a_only = filter_messages(_fm_msgs, conversation_id=_conv_a_id)
_eq(len(_conv_a_only), 3, "filter by conv_a_id → 3")
_conv_b_only = filter_messages(_fm_msgs, conversation_id=_conv_b_id)
_eq(len(_conv_b_only), 1, "filter by conv_b_id → 1")

# combined filter — USER role + max_tokens=2 → only "Short" (2 tokens)
_combo = filter_messages(_fm_msgs, role=ConversationRole.USER, max_tokens=2)
_eq(len(_combo), 1, "filter USER + max_tokens=2 → 1")

# no filter → all
_eq(len(filter_messages(_fm_msgs)), 4, "no filter → all 4 returned")

# empty
_eq(len(filter_messages([])), 0, "empty input → empty output")

# input not mutated
_eq(len(_fm_msgs), 4, "filter_messages: input not mutated")

# ===========================================================================
# §33  group_messages()
# ===========================================================================
print("§33  group_messages() ...")

_gm_msgs = [
    build_message(_conv_a_id, ConversationRole.USER,      "u1", 1, _TS),
    build_message(_conv_a_id, ConversationRole.ASSISTANT, "a1", 2, _TS),
    build_message(_conv_a_id, ConversationRole.USER,      "u2", 3, _TS2),
    build_message(_conv_b_id, ConversationRole.SYSTEM,    "s1", 1, _TS),
]

# group by role
_by_role = group_messages(_gm_msgs, group_by="role")
_in("USER",      _by_role, "group by role: USER key present")
_in("ASSISTANT", _by_role, "group by role: ASSISTANT key present")
_in("SYSTEM",    _by_role, "group by role: SYSTEM key present")
_eq(len(_by_role["USER"]), 2, "group by role: 2 USER messages")
_eq(len(_by_role["ASSISTANT"]), 1, "group by role: 1 ASSISTANT message")

# groups are sorted by sequenceNumber ASC within each group
_user_grp = _by_role["USER"]
_eq(_user_grp[0].sequenceNumber, 1, "group USER sorted: first seq=1")
_eq(_user_grp[1].sequenceNumber, 3, "group USER sorted: second seq=3")

# group by conversationId
_by_conv = group_messages(_gm_msgs, group_by="conversationId")
_eq(len(_by_conv), 2, "group by conversationId: 2 groups")
_in(_conv_a_id, _by_conv, "group by conv: conv_a group present")
_in(_conv_b_id, _by_conv, "group by conv: conv_b group present")
_eq(len(_by_conv[_conv_a_id]), 3, "group by conv: 3 messages in conv_a")

# invalid key raises ValueError
try:
    group_messages(_gm_msgs, group_by="invalid_key")
    _assert(False, "group_messages: invalid key should raise")
except ValueError:
    _assert(True, "group_messages: invalid key raises ValueError")

# empty
_eq(len(group_messages([])), 0, "group_messages: empty → empty dict")

# determinism
_eq(
    {k: [m.messageId for m in v] for k, v in group_messages(_gm_msgs).items()},
    {k: [m.messageId for m in v] for k, v in group_messages(_gm_msgs).items()},
    "group_messages: deterministic",
)

# ===========================================================================
# §34  find_message()
# ===========================================================================
print("§34  find_message() ...")

_find_msgs = [_tc_m1, _tc_m2, _tc_m3]

# find by messageId
_found_mid = find_message(_find_msgs, message_id=_tc_m2.messageId)
_assert(_found_mid is not None, "find_message: found by messageId")
_eq(_found_mid.messageId, _tc_m2.messageId, "find_message: correct message by id")

# find by messageKey
_found_key = find_message(_find_msgs, message_key=_tc_m1.messageKey)
_assert(_found_key is not None, "find_message: found by messageKey")
_eq(_found_key.messageKey, _tc_m1.messageKey, "find_message: correct message by key")

# not found returns None
_assert(find_message(_find_msgs, message_id="nonexistent") is None,
        "find_message: not-found returns None")
_assert(find_message(_find_msgs, message_key="nonexistent") is None,
        "find_message: not-found by key returns None")

# no criterion returns None
_assert(find_message(_find_msgs) is None, "find_message: no criterion returns None")

# messageId priority over messageKey
_found_prio = find_message(
    _find_msgs, message_id=_tc_m3.messageId, message_key=_tc_m1.messageKey
)
_eq(_found_prio.messageId, _tc_m3.messageId,
    "find_message: messageId takes priority over messageKey")

# empty list
_assert(find_message([], message_id="x") is None,
        "find_message: empty list returns None")

# determinism
_eq(find_message(_find_msgs, message_id=_tc_m1.messageId),
    find_message(_find_msgs, message_id=_tc_m1.messageId),
    "find_message: deterministic")

# ===========================================================================
# §35  sort_conversations()
# ===========================================================================
print("§35  sort_conversations() ...")

_sc_msgs_2 = [
    build_message(_tc_conv.conversationId, ConversationRole.USER, "x", i, _TS)
    for i in range(1, 3)
]
_sc_msgs_4 = [
    build_message(_tc_conv.conversationId, ConversationRole.USER, "x", i, _TS)
    for i in range(1, 5)
]

_sc_a = build_conversation(_USER, "Alpha", _TS,  _INV_ID, messages=_sc_msgs_2)
_sc_b = build_conversation(_USER, "Beta",  _TS2, _INV_ID, messages=_sc_msgs_4)
_sc_c = build_conversation(_USER, "Gamma", _TS3, _INV_ID)

_sc_list = [_sc_b, _sc_c, _sc_a]

# sort by conversationId ASC (default)
_sorted_id = sort_conversations(_sc_list)
_eq(len(_sorted_id), 3, "sort_conversations: returns 3")
_true(_sorted_id[0].conversationId <= _sorted_id[1].conversationId,
      "sort by conversationId ASC: order correct 0→1")
_true(_sorted_id[1].conversationId <= _sorted_id[2].conversationId,
      "sort by conversationId ASC: order correct 1→2")

# sort by conversationId DESC
_sorted_id_desc = sort_conversations(_sc_list, key="conversationId", ascending=False)
_true(_sorted_id_desc[0].conversationId >= _sorted_id_desc[1].conversationId,
      "sort by conversationId DESC: order correct")

# sort by totalMessages ASC
_sorted_msgs = sort_conversations(_sc_list, key="totalMessages", ascending=True)
_eq(_sorted_msgs[0].metadata.totalMessages, 0, "sort by totalMessages ASC: 0 first")
_eq(_sorted_msgs[2].metadata.totalMessages, 4, "sort by totalMessages ASC: 4 last")

# sort by totalMessages DESC
_sorted_msgs_d = sort_conversations(_sc_list, key="totalMessages", ascending=False)
_eq(_sorted_msgs_d[0].metadata.totalMessages, 4, "sort by totalMessages DESC: 4 first")

# sort by createdAt ASC
_sorted_ts = sort_conversations(_sc_list, key="createdAt", ascending=True)
_eq(_sorted_ts[0].createdAt, _TS, "sort by createdAt ASC: earliest first")

# sort by updatedAt
_sorted_upd = sort_conversations(_sc_list, key="updatedAt")
_is(sort_conversations(_sc_list, key="updatedAt"), list, "sort by updatedAt returns list")

# invalid key raises
try:
    sort_conversations(_sc_list, key="nonexistent")
    _assert(False, "sort_conversations: invalid key should raise")
except ValueError:
    _assert(True, "sort_conversations: invalid key raises ValueError")

# empty
_eq(sort_conversations([]), [], "sort_conversations: empty → empty")

# input not mutated
_eq(_sc_list[0].conversationId, _sc_b.conversationId,
    "sort_conversations: input not mutated")

# determinism
_eq(
    [c.conversationId for c in sort_conversations(_sc_list)],
    [c.conversationId for c in sort_conversations(_sc_list)],
    "sort_conversations: deterministic",
)

# ===========================================================================
# §36  filter_conversations()
# ===========================================================================
print("§36  filter_conversations() ...")

_fc_m1 = build_message(_sc_a.conversationId, ConversationRole.USER, "hi", 1, _TS)

_fc_active   = build_conversation(_USER, "FC Active",   _TS,  "inv-X",
                                   state=ConversationState.ACTIVE,
                                   messages=[_fc_m1])
_fc_paused   = build_conversation(_USER, "FC Paused",   _TS,  "inv-X",
                                   state=ConversationState.PAUSED)
_fc_archived = build_conversation(_USER, "FC Archived", _TS,  "inv-Y",
                                   state=ConversationState.ARCHIVED)
_fc_complete = build_conversation(_USER, "FC Complete", _TS2, "inv-Y",
                                   state=ConversationState.COMPLETED,
                                   messages=[_fc_m1],
                                   tags=["incident", "network"])

# Build a thread for _fc_active
_fc_thread   = build_thread(
    _fc_active.conversationId, _fc_m1.messageId, [_fc_m1.messageId], _TS
)
_fc_active_with_t = build_conversation(
    _USER, "FC Active", _TS, "inv-X",
    state=ConversationState.ACTIVE,
    messages=[_fc_m1],
    threads=[_fc_thread],
)

_fc_all = [_fc_active_with_t, _fc_paused, _fc_archived, _fc_complete]

# filter by state
_fc_actives = filter_conversations(_fc_all, state=ConversationState.ACTIVE)
_eq(len(_fc_actives), 1, "filter by ACTIVE → 1")

_fc_paus = filter_conversations(_fc_all, state=ConversationState.PAUSED)
_eq(len(_fc_paus), 1, "filter by PAUSED → 1")

# filter by investigation_id
_fc_inv_x = filter_conversations(_fc_all, investigation_id="inv-X")
_eq(len(_fc_inv_x), 2, "filter inv-X → 2")
_fc_inv_y = filter_conversations(_fc_all, investigation_id="inv-Y")
_eq(len(_fc_inv_y), 2, "filter inv-Y → 2")

# filter has_messages
_fc_has_msg = filter_conversations(_fc_all, has_messages=True)
_eq(len(_fc_has_msg), 2, "filter has_messages=True → 2")
_fc_no_msg = filter_conversations(_fc_all, has_messages=False)
_eq(len(_fc_no_msg), 2, "filter has_messages=False → 2")

# filter has_threads
_fc_has_t = filter_conversations(_fc_all, has_threads=True)
_eq(len(_fc_has_t), 1, "filter has_threads=True → 1")
_fc_no_t = filter_conversations(_fc_all, has_threads=False)
_eq(len(_fc_no_t), 3, "filter has_threads=False → 3")

# filter min_messages / max_messages
_fc_min = filter_conversations(_fc_all, min_messages=1)
_eq(len(_fc_min), 2, "filter min_messages=1 → 2")
_fc_max = filter_conversations(_fc_all, max_messages=0)
_eq(len(_fc_max), 2, "filter max_messages=0 → 2")

# filter by tag (case-insensitive)
_fc_tagged = filter_conversations(_fc_all, tag="incident")
_eq(len(_fc_tagged), 1, "filter tag=incident → 1")
_fc_tagged_upper = filter_conversations(_fc_all, tag="NETWORK")
_eq(len(_fc_tagged_upper), 1, "filter tag=NETWORK (case-insensitive) → 1")

# no filter → all
_eq(len(filter_conversations(_fc_all)), 4, "no filter → all 4")

# combined filter
_fc_combo = filter_conversations(_fc_all, state=ConversationState.ACTIVE, has_threads=True)
_eq(len(_fc_combo), 1, "combined filter ACTIVE + has_threads → 1")

# empty
_eq(len(filter_conversations([])), 0, "filter_conversations: empty → empty")

# input not mutated
_eq(len(_fc_all), 4, "filter_conversations: input not mutated")

# ===========================================================================
# §37  group_conversations()
# ===========================================================================
print("§37  group_conversations() ...")

_gc_list = [_fc_active_with_t, _fc_paused, _fc_archived, _fc_complete]

# group by state
_gc_by_state = group_conversations(_gc_list, group_by="state")
_in("ACTIVE",    _gc_by_state, "group by state: ACTIVE key present")
_in("PAUSED",    _gc_by_state, "group by state: PAUSED key present")
_in("ARCHIVED",  _gc_by_state, "group by state: ARCHIVED key present")
_in("COMPLETED", _gc_by_state, "group by state: COMPLETED key present")
_eq(len(_gc_by_state["ACTIVE"]),    1, "group by state: 1 ACTIVE")
_eq(len(_gc_by_state["PAUSED"]),    1, "group by state: 1 PAUSED")

# groups sorted by conversationId ASC
_active_grp = _gc_by_state["ACTIVE"]
_is(_active_grp, list, "group by state: value is list")

# group by investigationId
_gc_by_inv = group_conversations(_gc_list, group_by="investigationId")
_eq(len(_gc_by_inv), 2, "group by investigationId: 2 groups")
_in("inv-X", _gc_by_inv, "group by inv: inv-X present")
_in("inv-Y", _gc_by_inv, "group by inv: inv-Y present")
_eq(len(_gc_by_inv["inv-X"]), 2, "group by inv: 2 conversations in inv-X")
_eq(len(_gc_by_inv["inv-Y"]), 2, "group by inv: 2 conversations in inv-Y")

# invalid key raises ValueError
try:
    group_conversations(_gc_list, group_by="badkey")
    _assert(False, "group_conversations: invalid key should raise")
except ValueError:
    _assert(True, "group_conversations: invalid key raises ValueError")

# empty
_eq(len(group_conversations([])), 0, "group_conversations: empty → empty dict")

# default group_by is "state"
_gc_default = group_conversations(_gc_list)
_in("ACTIVE", _gc_default, "group_conversations: default group_by='state'")

# determinism
_eq(
    {k: [c.conversationId for c in v] for k, v in group_conversations(_gc_list).items()},
    {k: [c.conversationId for c in v] for k, v in group_conversations(_gc_list).items()},
    "group_conversations: deterministic",
)

# ===========================================================================
# §38  find_conversation()
# ===========================================================================
print("§38  find_conversation() ...")

_find_list = [_sc_a, _sc_b, _sc_c]

# find by conversationId
_found_cid = find_conversation(_find_list, conversation_id=_sc_b.conversationId)
_assert(_found_cid is not None, "find_conversation: found by conversationId")
_eq(_found_cid.conversationId, _sc_b.conversationId,
    "find_conversation: correct conversation by id")

# find by conversationKey
_found_ck = find_conversation(_find_list, conversation_key=_sc_a.conversationKey)
_assert(_found_ck is not None, "find_conversation: found by conversationKey")
_eq(_found_ck.conversationKey, _sc_a.conversationKey,
    "find_conversation: correct conversation by key")

# not found → None
_assert(find_conversation(_find_list, conversation_id="nonexistent") is None,
        "find_conversation: not-found returns None")
_assert(find_conversation(_find_list, conversation_key="nonexistent") is None,
        "find_conversation: not-found by key returns None")

# no criterion → None
_assert(find_conversation(_find_list) is None,
        "find_conversation: no criterion returns None")

# conversationId priority over conversationKey
_found_prio = find_conversation(
    _find_list,
    conversation_id  = _sc_c.conversationId,
    conversation_key = _sc_a.conversationKey,
)
_eq(_found_prio.conversationId, _sc_c.conversationId,
    "find_conversation: conversationId takes priority")

# empty list
_assert(find_conversation([], conversation_id="x") is None,
        "find_conversation: empty list returns None")

# determinism
_eq(
    find_conversation(_find_list, conversation_id=_sc_a.conversationId),
    find_conversation(_find_list, conversation_id=_sc_a.conversationId),
    "find_conversation: deterministic",
)

# ===========================================================================
# §39  build_statistics() using lifecycle operations
# ===========================================================================
print("§39  build_statistics() via lifecycle ...")

# Build conversations through lifecycle transitions and verify stats
_sl_base = build_conversation(_USER, "Stats LC", _TS, "inv-stats")

# Add messages via lifecycle
_sl_c1 = add_message(
    add_message(_sl_base, ConversationRole.USER, "q1", _TS),
    ConversationRole.ASSISTANT, "a1", _TS2,
)
# Archive one, keep others active
_sl_c2 = archive_conversation(
    add_message(_sl_base, ConversationRole.USER, "q2", _TS),
    _TS2,
)
_sl_c3 = complete_conversation(
    add_message(
        add_message(_sl_base, ConversationRole.USER, "q3", _TS),
        ConversationRole.ASSISTANT, "a3", _TS2,
    ),
    _TS3,
)
_sl_c4 = pause_conversation(_sl_base, _TS2)

# Add threads via create_thread
_sl_m = _sl_c1.messages[0]
_sl_c1_with_t = create_thread(
    _sl_c1, _sl_m.messageId, [_sl_m.messageId], _TS, _TS2
)

_sl_convs = [_sl_c1_with_t, _sl_c2, _sl_c3, _sl_c4]
_sl_stats = build_statistics(_sl_convs)

_eq(_sl_stats.totalConversations,    4, "lc stats: totalConversations=4")
_eq(_sl_stats.activeConversations,   1, "lc stats: 1 ACTIVE (sl_c1_with_t)")
_eq(_sl_stats.archivedConversations, 1, "lc stats: 1 ARCHIVED (sl_c2)")
_eq(_sl_stats.totalThreads,          1, "lc stats: 1 thread (from sl_c1_with_t)")
_gt(_sl_stats.averageMessages,       0.0, "lc stats: averageMessages > 0")
_eq(_sl_stats.longestConversation,   2,   "lc stats: longest=2 (sl_c1 or sl_c3)")

# Order-independence
_sl_stats_rev = build_statistics(list(reversed(_sl_convs)))
_eq(_sl_stats.totalConversations,    _sl_stats_rev.totalConversations,
    "lc stats: order-independent totalConversations")
_eq(_sl_stats.activeConversations,   _sl_stats_rev.activeConversations,
    "lc stats: order-independent activeConversations")
_eq(_sl_stats.averageMessages,       _sl_stats_rev.averageMessages,
    "lc stats: order-independent averageMessages")
_eq(_sl_stats.averageTokens,         _sl_stats_rev.averageTokens,
    "lc stats: order-independent averageTokens")

# Immutability of stats result
try:
    _sl_stats.totalConversations = 99  # type: ignore
    _assert(False, "lc stats: ConversationStatistics should be frozen")
except Exception:
    _assert(True, "lc stats: ConversationStatistics is immutable")

# ===========================================================================
# §40  Deterministic updates — edit/delete round-trips
# ===========================================================================
print("§40  Deterministic updates (edit/delete round-trips) ...")

_rt_base = build_conversation(_USER, "RT Test", _TS, _INV_ID)
_rt_base = add_message(_rt_base, ConversationRole.USER,      "original content", _TS)
_rt_base = add_message(_rt_base, ConversationRole.ASSISTANT, "assistant reply",  _TS2)

_rt_mid = _rt_base.messages[0].messageId

# Edit and re-edit back to the same content → same fingerprint
_rt_edited   = edit_message(_rt_base, _rt_mid, "changed content", _TS3)
_rt_restored = edit_message(
    _rt_edited,
    _rt_edited.messages[0].messageId,
    "original content",
    _TS3,
)
# Fingerprint after restoring original content matches original
# (updatedAt differs so only the message fingerprint matters here)
_eq(
    _rt_restored.messages[0].messageKey,
    _rt_base.messages[0].messageKey,
    "round-trip edit: restored messageKey matches original",
)

# Delete then re-add produces same message id (deterministic)
_rt_deleted = delete_message(_rt_base, _rt_mid, _TS3)
_rt_readded = add_message(
    _rt_deleted, ConversationRole.USER, "original content", _TS
)
# seq number is 3 now (2 remaining + 1 added), so messageKey differs
# but same role+content → same key if we rebuild at seq=1
_rt_rebuilt_msg = build_message(
    _rt_base.conversationId,
    ConversationRole.USER,
    "original content",
    1,
    _TS,
)
_eq(_rt_rebuilt_msg.messageKey, _rt_base.messages[0].messageKey,
    "deterministic: rebuild at seq=1 → same messageKey as original")

# After deleting all messages, the conversation is valid with empty messages
_rt_empty = delete_message(
    delete_message(_rt_base,
                   _rt_base.messages[0].messageId, _TS3),
    _rt_base.messages[1].messageId,
    _TS3,
)
_eq(len(_rt_empty.messages), 0, "delete all: 0 messages remain")
_is(_rt_empty, Conversation, "delete all: still a valid Conversation")

# ===========================================================================
# §41  Structured logging events (validation failures)
# ===========================================================================
print("§41  Validation failure logging ...")

# validate_message logs / raises for each failure type
_vf_errors = []
for bad_args, label in [
    (("",  ConversationRole.USER, "t", 1, _TS), "empty conversationId"),
    (("c", "NOT_A_ROLE",          "t", 1, _TS), "invalid role"),
    (("c", ConversationRole.USER,  None, 1, _TS), "None content"),
    (("c", ConversationRole.USER,  "t", 0, _TS), "seq=0"),
    (("c", ConversationRole.USER,  "t", 1, ""),  "empty createdAt"),
]:
    try:
        validate_message(*bad_args)  # type: ignore
        _vf_errors.append(f"MISSING RAISE for {label}")
        _assert(False, f"validate_message should raise for {label}")
    except InvalidMessageError:
        _assert(True, f"validate_message raises for {label}")

# validate_thread raises for each failure type
for bad_args, label in [
    (("", "r", ("r",), 0, _TS), "empty conversationId"),
    (("c", "", ("r",), 0, _TS), "empty rootMessageId"),
    (("c", "r", (),    0, _TS), "empty messageIds"),
    (("c", "z", ("r",), 0, _TS), "rootId not in ids"),
    (("c", "r", ("r",), -1, _TS), "negative depth"),
]:
    try:
        validate_thread(*bad_args)
        _assert(False, f"validate_thread should raise for {label}")
    except InvalidThreadError:
        _assert(True, f"validate_thread raises for {label}")

# validate_conversation raises for each failure type
for bad_args, label in [
    ((_INV_ID, "",     _TITLE, _TS, ConversationState.ACTIVE), "empty createdBy"),
    ((_INV_ID, _USER,  "",     _TS, ConversationState.ACTIVE), "empty title"),
    ((_INV_ID, _USER,  _TITLE, "", ConversationState.ACTIVE),  "empty createdAt"),
    ((_INV_ID, _USER,  _TITLE, _TS, "ACTIVE"),                 "string state"),
]:
    try:
        validate_conversation(*bad_args)  # type: ignore
        _assert(False, f"validate_conversation should raise for {label}")
    except InvalidConversationError:
        _assert(True, f"validate_conversation raises for {label}")

# ===========================================================================
# Final report
# ===========================================================================
print()
print("=" * 60)
print(f"Conversation Manager Engine Smoke Test: {_PASS} passed, {_FAIL} failed")
print("=" * 60)
if _ERRORS:
    print()
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

if _FAIL > 0:
    sys.exit(1)
else:
    print("ALL ASSERTIONS PASSED")
    sys.exit(0)
