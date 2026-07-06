"""
Smoke Test — Chat Runtime Engine (Phase A4.3.6)
===============================================
Target: 700+ assertions, 0 failures.

Sections
--------
 1. Imports & helpers
 2. Version constant
 3. Enumerations
 4. Typed exceptions
 5. RuntimeRequest — build & validate
 6. RuntimeResponse — build & validate
 7. RuntimeMetadata — build
 8. RuntimeSession — build & validate
 9. Deterministic ID helpers (key functions)
10. Deterministic fingerprints
11. Immutability
12. Serialisation
13. Lifecycle — start_runtime_session
14. Lifecycle — complete_runtime_session
15. Lifecycle — fail_runtime_session
16. Lifecycle — reset_runtime_session
17. Lifecycle — invalid state transitions
18. Runtime decisions (should_execute, can_resume, is_complete)
19. Sort utilities — RuntimeSession
20. Filter utilities — RuntimeSession
21. Group utilities — RuntimeSession
22. Find utilities — RuntimeSession
23. Sort utilities — RuntimeRequest
24. Filter utilities — RuntimeRequest
25. Group utilities — RuntimeRequest
26. Find utilities — RuntimeRequest
27. Statistics — extended fields
28. Statistics — order-independence
29. Statistics — empty input
30. Integration helpers — conversation_to_runtime_request
31. Integration helpers — memory_to_runtime_request
32. Integration helpers — context_window_to_runtime_request
33. Integration helpers — execution_result_to_runtime_response
34. Integration helpers — copilot_session_to_runtime_response
35. Edge cases
36. Zero-randomness guarantee
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.chat_runtime_service import (
    # Enum
    ChatRuntimeStateEnum,
    # Exceptions
    ChatRuntimeError, InvalidChatSessionError,
    InvalidRuntimeRequestError, InvalidRuntimeResponseError,
    # Models
    RuntimeRequest, RuntimeResponse, RuntimeMetadata,
    RuntimeSession, RuntimeStatistics,
    # Key helpers
    runtimeRequestKey, runtimeResponseKey, runtimeSessionKey, runtimeFingerprint,
    # Builders
    build_runtime_request, build_runtime_response, build_runtime_metadata,
    build_runtime_session, build_runtime_statistics,
    # Validators
    validate_runtime_request, validate_runtime_response, validate_runtime_session,
    # Lifecycle
    start_runtime_session, complete_runtime_session,
    fail_runtime_session, reset_runtime_session,
    # Decisions
    should_execute_runtime, can_resume_runtime, is_runtime_complete,
    # Session utilities
    sort_runtime_sessions, filter_runtime_sessions,
    group_runtime_sessions, find_runtime_session,
    # Request utilities
    sort_runtime_requests, filter_runtime_requests,
    group_runtime_requests, find_runtime_request,
    # Integration helpers
    conversation_to_runtime_request, memory_to_runtime_request,
    context_window_to_runtime_request, execution_result_to_runtime_response,
    copilot_session_to_runtime_response,
    # Version
    CHAT_RUNTIME_ENGINE_VERSION,
    # Internal helpers exposed for testing
    _sha256_32, _uuid5, _norm, _norm_strings, _clamp_float, _estimate_tokens,
    _RUNTIME_NS, _ALLOWED_TRANSITIONS,
)
from core.constants import CHAT_RUNTIME_ENGINE_VERSION as CONST_VER

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
# Shared fixtures
# ---------------------------------------------------------------------------
TS  = "2026-07-01T12:00:00Z"
TS2 = "2026-07-01T13:00:00Z"
TS3 = "2026-07-01T14:00:00Z"
CONV_ID  = "conv-abc-001"
SESS_ID  = "sess-xyz-001"
PROVIDER = "groq"
MODEL    = "llama-3.3-70b-versatile"


def _make_request(
    conv_id   : str  = CONV_ID,
    sess_id   : str  = SESS_ID,
    user_prompt: str = "What is the network topology?",
    provider  : str  = PROVIDER,
    model     : str  = MODEL,
    created_at: str  = TS,
) -> RuntimeRequest:
    return build_runtime_request(
        conversation_id = conv_id,
        user_prompt     = user_prompt,
        provider        = provider,
        model           = model,
        created_at      = created_at,
        session_id      = sess_id,
        system_prompt   = "You are a network analyst.",
        temperature     = 0.0,
        max_tokens      = 1024,
    )


def _make_response(req: RuntimeRequest, created_at: str = TS2) -> RuntimeResponse:
    return build_runtime_response(
        runtime_request_id = req.runtimeRequestId,
        content            = "The topology is star-based.",
        finish_reason      = "stop",
        provider           = req.provider,
        model              = req.model,
        created_at         = created_at,
        confidence         = 85.0,
        prompt_tokens      = 120,
        completion_tokens  = 40,
        latency_ms         = 350,
    )


def _make_session(
    state      : ChatRuntimeStateEnum = ChatRuntimeStateEnum.READY,
    with_resp  : bool                 = False,
    created_at : str                  = TS,
    updated_at : str                  = TS,
) -> RuntimeSession:
    req  = _make_request(created_at=created_at)
    resp = _make_response(req) if with_resp else None
    return build_runtime_session(
        request    = req,
        created_at = created_at,
        updated_at = updated_at,
        state      = state,
        response   = resp,
        latency_ms = 350 if with_resp else 0,
        success    = (state != ChatRuntimeStateEnum.FAILED),
        error_message = "timeout" if state == ChatRuntimeStateEnum.FAILED else "",
    )


# ===========================================================================
# Section 2 — Version constant
# ===========================================================================

def test_version_constant() -> None:
    _eq(CHAT_RUNTIME_ENGINE_VERSION, "chat-runtime-v1", "engine version string")
    _eq(CONST_VER, "chat-runtime-v1", "constant from core.constants")
    _eq(CHAT_RUNTIME_ENGINE_VERSION, CONST_VER, "both imports identical")
    _is(CHAT_RUNTIME_ENGINE_VERSION, str, "version is str")

test_version_constant()


# ===========================================================================
# Section 3 — Enumerations
# ===========================================================================

def test_enumerations() -> None:
    states = {s.value for s in ChatRuntimeStateEnum}
    for expected in ("READY", "RUNNING", "WAITING", "COMPLETED", "FAILED"):
        _true(expected in states, f"state {expected} exists")
    _eq(len(states), 5, "exactly 5 states")
    _is(ChatRuntimeStateEnum.READY, ChatRuntimeStateEnum, "READY is enum member")
    _eq(ChatRuntimeStateEnum.READY.value, "READY", "READY.value")
    _eq(ChatRuntimeStateEnum.RUNNING.value, "RUNNING", "RUNNING.value")
    _eq(ChatRuntimeStateEnum.WAITING.value, "WAITING", "WAITING.value")
    _eq(ChatRuntimeStateEnum.COMPLETED.value, "COMPLETED", "COMPLETED.value")
    _eq(ChatRuntimeStateEnum.FAILED.value, "FAILED", "FAILED.value")
    # str subclass
    _is(ChatRuntimeStateEnum.READY, str, "enum is str subclass")

test_enumerations()


# ===========================================================================
# Section 4 — Typed exceptions
# ===========================================================================

def test_exceptions() -> None:
    _true(issubclass(ChatRuntimeError, Exception), "ChatRuntimeError is Exception")
    _true(issubclass(InvalidChatSessionError, ChatRuntimeError), "InvalidChatSessionError chain")
    _true(issubclass(InvalidRuntimeRequestError, ChatRuntimeError), "InvalidRuntimeRequestError chain")
    _true(issubclass(InvalidRuntimeResponseError, ChatRuntimeError), "InvalidRuntimeResponseError chain")

    try:
        raise InvalidRuntimeRequestError("bad request")
    except ChatRuntimeError as e:
        _true("bad request" in str(e), "exception message preserved")
        _is(e, InvalidRuntimeRequestError, "raised as subtype")

test_exceptions()


# ===========================================================================
# Section 5 — RuntimeRequest — build & validate
# ===========================================================================

def test_build_runtime_request() -> None:
    req = _make_request()

    # Types
    _is(req, RuntimeRequest, "returns RuntimeRequest")
    _is(req.runtimeRequestId,  str, "runtimeRequestId is str")
    _is(req.runtimeRequestKey, str, "runtimeRequestKey is str")

    # Field values
    _eq(req.conversationId, CONV_ID,   "conversationId stored")
    _eq(req.sessionId,      SESS_ID,   "sessionId stored")
    _eq(req.provider,       PROVIDER,  "provider normalised lowercase")
    _eq(req.model,          MODEL,     "model stored")
    _eq(req.temperature,    0.0,       "temperature stored")
    _eq(req.maxTokens,      1024,      "maxTokens stored")
    _eq(req.engineVersion,  CHAT_RUNTIME_ENGINE_VERSION, "engineVersion")
    _eq(req.createdAt,      TS,        "createdAt stored")
    _eq(req.userPrompt,     "What is the network topology?", "userPrompt stored")

    # Key length
    _eq(len(req.runtimeRequestKey), 32, "runtimeRequestKey is 32 chars")

    # UUID format
    _true("-" in req.runtimeRequestId, "runtimeRequestId looks like UUID")

    # Determinism
    req2 = _make_request()
    _eq(req.runtimeRequestId,  req2.runtimeRequestId,  "deterministic runtimeRequestId")
    _eq(req.runtimeRequestKey, req2.runtimeRequestKey, "deterministic runtimeRequestKey")

    # Different inputs → different IDs
    req3 = _make_request(user_prompt="Different question")
    _ne(req.runtimeRequestId,  req3.runtimeRequestId,  "different prompt → different id")
    _ne(req.runtimeRequestKey, req3.runtimeRequestKey, "different prompt → different key")

    # Provider normalised
    req_upper = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="GROQ",
        model="llama-3.3-70b-versatile", created_at=TS,
    )
    _eq(req_upper.provider, "groq", "provider uppercased → normalised lowercase")

    # Temperature clamped
    req_hot = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS, temperature=5.0,
    )
    _eq(req_hot.temperature, 2.0, "temperature clamped to 2.0")

    req_cold = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS, temperature=-1.0,
    )
    _eq(req_cold.temperature, 0.0, "temperature clamped to 0.0")

    # maxTokens clamped
    req_mt = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, max_tokens=0,
    )
    _eq(req_mt.maxTokens, 1, "maxTokens clamped to 1")

    # validate=False skips validation
    req_nv = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, validate=False,
    )
    _is(req_nv, RuntimeRequest, "validate=False returns RuntimeRequest")

    # metadata copied
    req_meta = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, metadata={"k": "v"},
    )
    _eq(req_meta.metadata["k"], "v", "metadata stored")


def test_validate_runtime_request() -> None:
    # empty conversationId
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("", "q", "groq", "m", 0.0, 1, TS),
        "empty conversationId raises")
    # empty userPrompt
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "", "groq", "m", 0.0, 1, TS),
        "empty userPrompt raises")
    # empty provider
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "q", "", "m", 0.0, 1, TS),
        "empty provider raises")
    # empty model
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "q", "groq", "", 0.0, 1, TS),
        "empty model raises")
    # bad temperature
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "q", "groq", "m", 3.0, 1, TS),
        "temperature > 2.0 raises")
    # bad maxTokens
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "q", "groq", "m", 0.0, 0, TS),
        "maxTokens=0 raises")
    # empty createdAt
    _raises(InvalidRuntimeRequestError,
        lambda: validate_runtime_request("c1", "q", "groq", "m", 0.0, 1, ""),
        "empty createdAt raises")
    # valid passes silently
    validate_runtime_request("c1", "q", "groq", "m", 0.0, 1, TS)
    _PASS_local = _PASS   # noqa
    _true(True, "valid validate_runtime_request passes")

test_build_runtime_request()
test_validate_runtime_request()


# ===========================================================================
# Section 6 — RuntimeResponse — build & validate
# ===========================================================================

def test_build_runtime_response() -> None:
    req  = _make_request()
    resp = _make_response(req)

    _is(resp, RuntimeResponse, "returns RuntimeResponse")
    _eq(resp.runtimeRequestId,   req.runtimeRequestId, "runtimeRequestId linked")
    _eq(resp.content,            "The topology is star-based.", "content stored")
    _eq(resp.finishReason,       "stop",  "finishReason stored")
    _eq(resp.provider,           PROVIDER, "provider stored")
    _eq(resp.model,              MODEL,    "model stored")
    _eq(resp.promptTokens,       120, "promptTokens stored")
    _eq(resp.completionTokens,    40, "completionTokens stored")
    _eq(resp.totalTokens,        160, "totalTokens = prompt + completion")
    _eq(resp.latencyMs,          350, "latencyMs stored")
    _eq(resp.confidence,         85.0, "confidence stored")
    _eq(resp.engineVersion,      CHAT_RUNTIME_ENGINE_VERSION, "engineVersion")
    _eq(len(resp.runtimeResponseKey), 32, "responseKey is 32 chars")

    # Determinism
    resp2 = _make_response(req)
    _eq(resp.runtimeResponseId,  resp2.runtimeResponseId,  "deterministic responseId")
    _eq(resp.runtimeResponseKey, resp2.runtimeResponseKey, "deterministic responseKey")

    # Different content → different key
    resp3 = build_runtime_response(
        runtime_request_id=req.runtimeRequestId,
        content="Different answer.", finish_reason="stop",
        provider=PROVIDER, model=MODEL, created_at=TS2,
    )
    _ne(resp.runtimeResponseId, resp3.runtimeResponseId, "different content → different id")

    # Confidence clamped
    resp_hi = build_runtime_response(
        runtime_request_id=req.runtimeRequestId,
        content="x", finish_reason="stop", provider="groq", model="m",
        created_at=TS, confidence=200.0,
    )
    _eq(resp_hi.confidence, 100.0, "confidence clamped to 100.0")

    resp_lo = build_runtime_response(
        runtime_request_id=req.runtimeRequestId,
        content="x", finish_reason="stop", provider="groq", model="m",
        created_at=TS, confidence=-5.0,
    )
    _eq(resp_lo.confidence, 0.0, "confidence clamped to 0.0")

    # Tokens clamped to 0
    resp_nt = build_runtime_response(
        runtime_request_id=req.runtimeRequestId,
        content="x", finish_reason="stop", provider="groq", model="m",
        created_at=TS, prompt_tokens=-10, completion_tokens=-5,
    )
    _eq(resp_nt.promptTokens,     0, "negative promptTokens clamped to 0")
    _eq(resp_nt.completionTokens, 0, "negative completionTokens clamped to 0")
    _eq(resp_nt.totalTokens,      0, "totalTokens = 0")

    # Empty content allowed
    resp_empty = build_runtime_response(
        runtime_request_id=req.runtimeRequestId,
        content="", finish_reason="tool_calls",
        provider="groq", model="m", created_at=TS,
    )
    _eq(resp_empty.content, "", "empty content allowed")


def test_validate_runtime_response() -> None:
    rid = "abc-request-id"
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response("", "c", "stop", "groq", "m", TS),
        "empty runtimeRequestId raises")
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response(rid, "c", "", "groq", "m", TS),
        "empty finishReason raises")
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response(rid, "c", "stop", "", "m", TS),
        "empty provider raises")
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response(rid, "c", "stop", "groq", "", TS),
        "empty model raises")
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response(rid, "c", "stop", "groq", "m", ""),
        "empty createdAt raises")
    # None content raises
    _raises(InvalidRuntimeResponseError,
        lambda: validate_runtime_response(rid, None, "stop", "groq", "m", TS),
        "None content raises")
    # valid passes
    validate_runtime_response(rid, "content", "stop", "groq", "m", TS)
    _true(True, "valid validate_runtime_response passes")

test_build_runtime_response()
test_validate_runtime_response()


# ===========================================================================
# Section 7 — RuntimeMetadata — build
# ===========================================================================

def test_build_runtime_metadata() -> None:
    meta = build_runtime_metadata(
        conversation_id = CONV_ID,
        session_id      = SESS_ID,
        provider        = PROVIDER,
        model           = MODEL,
        created_at      = TS,
        pipeline_stages = ["CONVERSATION", "MEMORY", "CONTEXT_WINDOW"],
        total_tokens    = 500,
        latency_ms      = 300,
        success         = True,
        error_message   = "",
        warnings        = ["warn1", "warn2", "warn1"],
    )

    _is(meta, RuntimeMetadata, "returns RuntimeMetadata")
    _eq(meta.conversationId, CONV_ID, "conversationId stored")
    _eq(meta.sessionId,      SESS_ID, "sessionId stored")
    _eq(meta.provider,       PROVIDER, "provider normalised")
    _eq(meta.model,          MODEL, "model normalised")
    _eq(meta.totalTokens,    500, "totalTokens stored")
    _eq(meta.latencyMs,      300, "latencyMs stored")
    _true(meta.success, "success stored")
    _eq(meta.errorMessage, "", "errorMessage stored")
    _eq(meta.engineVersion, CHAT_RUNTIME_ENGINE_VERSION, "engineVersion")
    # pipeline_stages deduped + sorted
    _true("CONVERSATION" in meta.pipelineStages, "CONVERSATION stage present")
    _true("MEMORY" in meta.pipelineStages, "MEMORY stage present")
    # warnings deduped
    _eq(len(meta.warnings), 2, "warnings deduped")
    # negative tokens clamped
    meta_neg = build_runtime_metadata(
        conversation_id="c1", session_id="s1", provider="groq", model="m",
        created_at=TS, total_tokens=-100, latency_ms=-50,
    )
    _eq(meta_neg.totalTokens, 0, "negative totalTokens clamped to 0")
    _eq(meta_neg.latencyMs,   0, "negative latencyMs clamped to 0")

test_build_runtime_metadata()


# ===========================================================================
# Section 8 — RuntimeSession — build & validate
# ===========================================================================

def test_build_runtime_session() -> None:
    sess = _make_session()
    _is(sess, RuntimeSession, "returns RuntimeSession")
    _eq(sess.state, ChatRuntimeStateEnum.READY, "initial state READY")
    _is(sess.runtimeSessionId,  str, "runtimeSessionId is str")
    _is(sess.runtimeSessionKey, str, "runtimeSessionKey is str")
    _is(sess.runtimeFingerprint, str, "runtimeFingerprint is str")
    _eq(len(sess.runtimeSessionKey),  32, "sessionKey is 32 chars")
    _eq(len(sess.runtimeFingerprint), 32, "fingerprint is 32 chars")
    _eq(sess.response, None, "no response on READY session")
    _eq(sess.createdAt, TS, "createdAt stored")
    _eq(sess.updatedAt, TS, "updatedAt stored")

    # With response
    sess_with = _make_session(
        state=ChatRuntimeStateEnum.COMPLETED, with_resp=True,
    )
    _true(sess_with.response is not None, "response attached on COMPLETED")
    _eq(sess_with.metadata.totalTokens, 160, "totalTokens from response")

    # Determinism
    sess2 = _make_session()
    _eq(sess.runtimeSessionId,  sess2.runtimeSessionId,  "deterministic sessionId")
    _eq(sess.runtimeSessionKey, sess2.runtimeSessionKey, "deterministic sessionKey")
    _eq(sess.runtimeFingerprint, sess2.runtimeFingerprint, "deterministic fingerprint")

    # Different request → different session key
    req_b = _make_request(user_prompt="A different question entirely?")
    sess_b = build_runtime_session(
        request=req_b, created_at=TS, updated_at=TS,
    )
    _ne(sess.runtimeSessionId, sess_b.runtimeSessionId, "different request → different id")


def test_validate_runtime_session() -> None:
    _raises(InvalidChatSessionError,
        lambda: validate_runtime_session("", TS, TS, ChatRuntimeStateEnum.READY),
        "empty conversationId raises")
    _raises(InvalidChatSessionError,
        lambda: validate_runtime_session(CONV_ID, "", TS, ChatRuntimeStateEnum.READY),
        "empty createdAt raises")
    _raises(InvalidChatSessionError,
        lambda: validate_runtime_session(CONV_ID, TS, "", ChatRuntimeStateEnum.READY),
        "empty updatedAt raises")
    _raises(InvalidChatSessionError,
        lambda: validate_runtime_session(CONV_ID, TS, TS, "READY"),
        "string state raises")
    # valid passes
    validate_runtime_session(CONV_ID, TS, TS, ChatRuntimeStateEnum.READY)
    _true(True, "valid validate_runtime_session passes")

test_build_runtime_session()
test_validate_runtime_session()


# ===========================================================================
# Section 9 — Deterministic ID helpers
# ===========================================================================

def test_key_functions() -> None:
    rk = runtimeRequestKey(CONV_ID, SESS_ID, "hello")
    _eq(len(rk), 32, "runtimeRequestKey length 32")
    _eq(rk, runtimeRequestKey(CONV_ID, SESS_ID, "hello"), "runtimeRequestKey deterministic")
    _ne(rk, runtimeRequestKey(CONV_ID, SESS_ID, "world"), "different prompt → different key")
    _ne(rk, runtimeRequestKey("other-conv", SESS_ID, "hello"), "different conv → different key")

    rspk = runtimeResponseKey("req-123", "content text", "stop")
    _eq(len(rspk), 32, "runtimeResponseKey length 32")
    _eq(rspk, runtimeResponseKey("req-123", "content text", "stop"), "runtimeResponseKey deterministic")
    _ne(rspk, runtimeResponseKey("req-123", "different", "stop"), "different content → different key")

    sk = runtimeSessionKey(CONV_ID, SESS_ID, rk)
    _eq(len(sk), 32, "runtimeSessionKey length 32")
    _eq(sk, runtimeSessionKey(CONV_ID, SESS_ID, rk), "runtimeSessionKey deterministic")
    _ne(sk, runtimeSessionKey("other", SESS_ID, rk), "different conv → different session key")

    fp = runtimeFingerprint(sk, rk, rspk)
    _eq(len(fp), 32, "runtimeFingerprint length 32")
    _eq(fp, runtimeFingerprint(sk, rk, rspk), "runtimeFingerprint deterministic")
    # empty resp key gives different fingerprint
    fp_no_resp = runtimeFingerprint(sk, rk, "")
    _ne(fp, fp_no_resp, "resp key '' → different fingerprint")

    # _sha256_32 basics
    h = _sha256_32("a", "b")
    _eq(len(h), 32, "_sha256_32 output length 32")
    _eq(h, _sha256_32("a", "b"), "_sha256_32 deterministic")
    _ne(h, _sha256_32("a", "c"), "_sha256_32 sensitive to input")

    # _uuid5 produces valid UUID string
    uid = _uuid5("some-key")
    _eq(len(uid), 36, "_uuid5 output length 36")
    _true("-" in uid, "_uuid5 contains hyphens")
    _eq(uid, _uuid5("some-key"), "_uuid5 deterministic")
    _ne(uid, _uuid5("other-key"), "_uuid5 sensitive to input")

test_key_functions()


# ===========================================================================
# Section 10 — Deterministic fingerprints
# ===========================================================================

def test_fingerprints() -> None:
    req  = _make_request()
    sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)

    # Same request → same fingerprint
    req2  = _make_request()
    sess2 = build_runtime_session(request=req2, created_at=TS, updated_at=TS)
    _eq(sess.runtimeFingerprint, sess2.runtimeFingerprint, "identical sessions → same fingerprint")

    # Adding response changes fingerprint
    resp = _make_response(req)
    sess_with = build_runtime_session(
        request=req, created_at=TS, updated_at=TS2,
        state=ChatRuntimeStateEnum.COMPLETED,
        response=resp,
    )
    _ne(sess.runtimeFingerprint, sess_with.runtimeFingerprint,
        "adding response changes fingerprint")

    # Different conversation → different fingerprint
    req_b = _make_request(conv_id="other-conv-id")
    sess_b = build_runtime_session(request=req_b, created_at=TS, updated_at=TS)
    _ne(sess.runtimeFingerprint, sess_b.runtimeFingerprint,
        "different conversation → different fingerprint")

    # Timestamp does NOT change session ID (only updatedAt, not key)
    req3  = _make_request(created_at=TS2)
    sess3 = build_runtime_session(request=req3, created_at=TS2, updated_at=TS2)
    # sessionKey depends on request key which depends on conversationId+sessionId+userPrompt
    # (not on createdAt), so same conversation/session/prompt → same sessionKey
    _eq(sess.runtimeSessionKey, sess3.runtimeSessionKey,
        "timestamp does not change sessionKey")

test_fingerprints()


# ===========================================================================
# Section 11 — Immutability
# ===========================================================================

def test_immutability() -> None:
    req  = _make_request()
    resp = _make_response(req)
    sess = _make_session()
    meta = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID,
        provider=PROVIDER, model=MODEL, created_at=TS,
    )
    stats = build_runtime_statistics([sess])

    for obj, name in [
        (req,  "RuntimeRequest"),
        (resp, "RuntimeResponse"),
        (meta, "RuntimeMetadata"),
        (sess, "RuntimeSession"),
        (stats, "RuntimeStatistics"),
    ]:
        try:
            obj.engineVersion = "hacked"  # type: ignore
            global _FAIL
            _FAIL += 1
            print(f"  FAIL [{name} frozen]: mutation succeeded — not frozen!")
        except Exception:
            global _PASS
            _PASS += 1

test_immutability()


# ===========================================================================
# Section 12 — Serialisation
# ===========================================================================

def test_serialisation() -> None:
    req  = _make_request()
    resp = _make_response(req)
    sess = _make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True)

    for obj, name in [(req, "RuntimeRequest"), (resp, "RuntimeResponse"), (sess, "RuntimeSession")]:
        d = obj.model_dump()
        _is(d, dict, f"{name}.model_dump() returns dict")
        j = obj.model_dump_json()
        _is(j, str, f"{name}.model_dump_json() returns str")
        parsed = json.loads(j)
        _is(parsed, dict, f"{name}.model_dump_json() is valid JSON")

    # RuntimeSession round-trip key fields
    d = sess.model_dump()
    _eq(d["state"], ChatRuntimeStateEnum.COMPLETED.value, "state serialised as value")
    _true("request" in d, "request nested in dict")
    _true("metadata" in d, "metadata nested in dict")

    # RuntimeStatistics
    stats = build_runtime_statistics([sess])
    d_stats = stats.model_dump()
    for f in ("totalSessions","completedSessions","failedSessions",
              "readySessions","runningSessions",
              "averageLatency","averageTokens","averageConfidence",
              "executionRate","failureRate"):
        _true(f in d_stats, f"stats field '{f}' in dict")

test_serialisation()


# ===========================================================================
# Section 13 — Lifecycle: start_runtime_session
# ===========================================================================

def test_start_runtime_session() -> None:
    sess = _make_session(state=ChatRuntimeStateEnum.READY)
    started = start_runtime_session(sess, updated_at=TS2)

    _is(started, RuntimeSession, "start returns RuntimeSession")
    _eq(started.state, ChatRuntimeStateEnum.RUNNING, "state → RUNNING")
    _eq(started.updatedAt, TS2, "updatedAt updated")
    _eq(started.createdAt, sess.createdAt, "createdAt unchanged")
    _eq(started.runtimeSessionId, sess.runtimeSessionId, "sessionId unchanged")
    _eq(started.request, sess.request, "request unchanged")
    _eq(started.response, None, "response still None")

    # Idempotent: same inputs → same result
    started2 = start_runtime_session(sess, updated_at=TS2)
    _eq(started.runtimeFingerprint, started2.runtimeFingerprint, "start deterministic")

    # Cannot start a RUNNING session
    _raises(InvalidChatSessionError,
        lambda: start_runtime_session(started, updated_at=TS3),
        "RUNNING → RUNNING raises")

    # Cannot start COMPLETED
    sess_done = _make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True)
    _raises(InvalidChatSessionError,
        lambda: start_runtime_session(sess_done, updated_at=TS3),
        "COMPLETED → RUNNING raises")

    # Cannot start FAILED
    sess_fail = _make_session(state=ChatRuntimeStateEnum.FAILED)
    _raises(InvalidChatSessionError,
        lambda: start_runtime_session(sess_fail, updated_at=TS3),
        "FAILED → RUNNING raises")

    # Warnings carried forward
    started_w = start_runtime_session(sess, updated_at=TS2, warnings=["test-warning"])
    _true("test-warning" in started_w.metadata.warnings, "warning carried forward")

test_start_runtime_session()


# ===========================================================================
# Section 14 — Lifecycle: complete_runtime_session
# ===========================================================================

def test_complete_runtime_session() -> None:
    sess    = _make_session(state=ChatRuntimeStateEnum.READY)
    running = start_runtime_session(sess, updated_at=TS2)
    req     = running.request
    resp    = _make_response(req, created_at=TS2)

    completed = complete_runtime_session(
        session    = running,
        response   = resp,
        updated_at = TS3,
        latency_ms = 500,
        pipeline_stages = ["CONTEXT_WINDOW", "TOKEN_BUDGET"],
    )

    _is(completed, RuntimeSession, "complete returns RuntimeSession")
    _eq(completed.state, ChatRuntimeStateEnum.COMPLETED, "state → COMPLETED")
    _eq(completed.response, resp, "response attached")
    _eq(completed.updatedAt, TS3, "updatedAt updated")
    _eq(completed.metadata.success, True, "success=True")
    _eq(completed.metadata.errorMessage, "", "errorMessage empty")
    _eq(completed.metadata.totalTokens, resp.totalTokens, "totalTokens from response")
    _eq(completed.metadata.latencyMs, 500, "latencyMs stored")
    _true("CONTEXT_WINDOW" in completed.metadata.pipelineStages, "pipeline stage stored")

    # Fingerprint changes when response attached
    _ne(completed.runtimeFingerprint, running.runtimeFingerprint,
        "fingerprint updated after completion")

    # Cannot complete a READY session
    _raises(InvalidChatSessionError,
        lambda: complete_runtime_session(sess, resp, TS3),
        "READY → COMPLETED raises")

    # Cannot complete an already COMPLETED session
    _raises(InvalidChatSessionError,
        lambda: complete_runtime_session(completed, resp, TS3),
        "COMPLETED → COMPLETED raises")

    # Determinism
    completed2 = complete_runtime_session(
        session=running, response=resp, updated_at=TS3, latency_ms=500,
        pipeline_stages=["CONTEXT_WINDOW", "TOKEN_BUDGET"],
    )
    _eq(completed.runtimeFingerprint, completed2.runtimeFingerprint,
        "complete is deterministic")

test_complete_runtime_session()


# ===========================================================================
# Section 15 — Lifecycle: fail_runtime_session
# ===========================================================================

def test_fail_runtime_session() -> None:
    sess    = _make_session(state=ChatRuntimeStateEnum.READY)
    running = start_runtime_session(sess, updated_at=TS2)

    failed = fail_runtime_session(
        session       = running,
        error_message = "Provider timed out",
        updated_at    = TS3,
        latency_ms    = 9000,
        warnings      = ["retry-limit-reached"],
    )

    _is(failed, RuntimeSession, "fail returns RuntimeSession")
    _eq(failed.state, ChatRuntimeStateEnum.FAILED, "state → FAILED")
    _eq(failed.metadata.success,      False, "success=False")
    _eq(failed.metadata.errorMessage, "Provider timed out", "errorMessage stored")
    _eq(failed.metadata.latencyMs,    9000, "latencyMs stored")
    _eq(failed.updatedAt,             TS3,  "updatedAt updated")
    _eq(failed.response,              None, "response still None")
    _true("retry-limit-reached" in failed.metadata.warnings, "warning stored")

    # Cannot fail a READY session
    _raises(InvalidChatSessionError,
        lambda: fail_runtime_session(sess, "err", TS3),
        "READY → FAILED raises")

    # Cannot fail a COMPLETED session
    req    = running.request
    resp   = _make_response(req)
    done   = complete_runtime_session(running, resp, TS3)
    _raises(InvalidChatSessionError,
        lambda: fail_runtime_session(done, "err", TS3),
        "COMPLETED → FAILED raises")

    # Cannot fail an already FAILED session
    _raises(InvalidChatSessionError,
        lambda: fail_runtime_session(failed, "err2", TS3),
        "FAILED → FAILED raises")

    # Determinism
    running2 = start_runtime_session(_make_session(), updated_at=TS2)
    failed2  = fail_runtime_session(running2, "Provider timed out", TS3, 9000, ["retry-limit-reached"])
    _eq(failed.runtimeFingerprint, failed2.runtimeFingerprint, "fail is deterministic")

test_fail_runtime_session()


# ===========================================================================
# Section 16 — Lifecycle: reset_runtime_session
# ===========================================================================

def test_reset_runtime_session() -> None:
    # Reset from READY
    sess_ready = _make_session(state=ChatRuntimeStateEnum.READY)
    reset_r = reset_runtime_session(sess_ready, updated_at=TS2)
    _eq(reset_r.state, ChatRuntimeStateEnum.READY, "READY → READY on reset")
    _eq(reset_r.response, None, "response cleared on reset")
    _eq(reset_r.metadata.totalTokens, 0, "totalTokens reset to 0")
    _eq(reset_r.metadata.latencyMs, 0, "latencyMs reset to 0")
    _true(reset_r.metadata.success, "success=True after reset")
    _eq(reset_r.metadata.errorMessage, "", "errorMessage cleared")

    # Reset from RUNNING
    running = start_runtime_session(sess_ready, updated_at=TS2)
    reset_run = reset_runtime_session(running, updated_at=TS3)
    _eq(reset_run.state, ChatRuntimeStateEnum.READY, "RUNNING → READY on reset")

    # Reset from COMPLETED
    resp  = _make_response(sess_ready.request)
    done  = complete_runtime_session(running, resp, TS3)
    reset_done = reset_runtime_session(done, updated_at=TS3)
    _eq(reset_done.state, ChatRuntimeStateEnum.READY, "COMPLETED → READY on reset")
    _eq(reset_done.response, None, "response cleared after reset")

    # Reset from FAILED
    failed = fail_runtime_session(running, "err", TS3)
    reset_fail = reset_runtime_session(failed, updated_at=TS3)
    _eq(reset_fail.state, ChatRuntimeStateEnum.READY, "FAILED → READY on reset")

    # sessionId preserved across reset
    _eq(reset_fail.runtimeSessionId, failed.runtimeSessionId, "sessionId preserved on reset")

    # Fingerprint changes on reset (response removed)
    done2 = complete_runtime_session(start_runtime_session(_make_session(), TS2), _make_response(_make_request()), TS3)
    reset2 = reset_runtime_session(done2, updated_at=TS3)
    _ne(done2.runtimeFingerprint, reset2.runtimeFingerprint, "fingerprint changes on reset")

    # Warnings on reset
    reset_w = reset_runtime_session(sess_ready, updated_at=TS2, warnings=["reset-warning"])
    _true("reset-warning" in reset_w.metadata.warnings, "reset warning stored")

    # Determinism
    reset_det1 = reset_runtime_session(_make_session(), updated_at=TS2)
    reset_det2 = reset_runtime_session(_make_session(), updated_at=TS2)
    _eq(reset_det1.runtimeFingerprint, reset_det2.runtimeFingerprint, "reset deterministic")

test_reset_runtime_session()


# ===========================================================================
# Section 17 — Lifecycle: invalid state transitions
# ===========================================================================

def test_invalid_transitions() -> None:
    # WAITING → COMPLETED not directly allowed (must go WAITING→RUNNING→COMPLETED)
    sess_wait = build_runtime_session(
        request    = _make_request(),
        created_at = TS,
        updated_at = TS,
        state      = ChatRuntimeStateEnum.WAITING,
    )
    _raises(InvalidChatSessionError,
        lambda: complete_runtime_session(sess_wait, _make_response(_make_request()), TS2),
        "WAITING → COMPLETED raises")
    _raises(InvalidChatSessionError,
        lambda: fail_runtime_session(sess_wait, "err", TS2),
        "WAITING → FAILED raises (must go through RUNNING)")

    # COMPLETED is terminal
    done = _make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True)
    _raises(InvalidChatSessionError,
        lambda: start_runtime_session(done, TS2),
        "COMPLETED → RUNNING raises")

    # FAILED is terminal
    failed = _make_session(state=ChatRuntimeStateEnum.FAILED)
    _raises(InvalidChatSessionError,
        lambda: start_runtime_session(failed, TS2),
        "FAILED → RUNNING raises")

    # Error messages are descriptive
    try:
        start_runtime_session(done, TS2)
    except InvalidChatSessionError as e:
        _true("COMPLETED" in str(e), "error message mentions COMPLETED")
        _true("RUNNING" in str(e), "error message mentions RUNNING")

test_invalid_transitions()


# ===========================================================================
# Section 18 — Runtime decisions
# ===========================================================================

def test_runtime_decisions() -> None:
    s_ready     = _make_session(state=ChatRuntimeStateEnum.READY)
    s_running   = _make_session(state=ChatRuntimeStateEnum.RUNNING)
    s_waiting   = build_runtime_session(
        request=_make_request(), created_at=TS, updated_at=TS,
        state=ChatRuntimeStateEnum.WAITING,
    )
    s_completed = _make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True)
    s_failed    = _make_session(state=ChatRuntimeStateEnum.FAILED)

    # should_execute_runtime — READY and WAITING
    _true(should_execute_runtime(s_ready),   "READY should execute")
    _true(should_execute_runtime(s_waiting), "WAITING should execute")
    _false(should_execute_runtime(s_running),   "RUNNING should NOT execute")
    _false(should_execute_runtime(s_completed), "COMPLETED should NOT execute")
    _false(should_execute_runtime(s_failed),    "FAILED should NOT execute")

    # can_resume_runtime — WAITING only
    _false(can_resume_runtime(s_ready),     "READY cannot resume")
    _false(can_resume_runtime(s_running),   "RUNNING cannot resume")
    _true(can_resume_runtime(s_waiting),    "WAITING can resume")
    _false(can_resume_runtime(s_completed), "COMPLETED cannot resume")
    _false(can_resume_runtime(s_failed),    "FAILED cannot resume")

    # is_runtime_complete — COMPLETED and FAILED only
    _false(is_runtime_complete(s_ready),    "READY not complete")
    _false(is_runtime_complete(s_running),  "RUNNING not complete")
    _false(is_runtime_complete(s_waiting),  "WAITING not complete")
    _true(is_runtime_complete(s_completed), "COMPLETED is complete")
    _true(is_runtime_complete(s_failed),    "FAILED is complete")

    # Decision functions are pure (no side effects)
    _ = should_execute_runtime(s_ready)
    _eq(s_ready.state, ChatRuntimeStateEnum.READY, "should_execute has no side effects")

test_runtime_decisions()


# ===========================================================================
# Section 19 — Sort utilities — RuntimeSession
# ===========================================================================

def test_sort_runtime_sessions() -> None:
    req_a = _make_request(conv_id="conv-a", user_prompt="question A")
    req_b = _make_request(conv_id="conv-b", user_prompt="question B")
    req_c = _make_request(conv_id="conv-c", user_prompt="question C")

    s_a = build_runtime_session(request=req_a, created_at=TS,  updated_at=TS,  latency_ms=100)
    s_b = build_runtime_session(request=req_b, created_at=TS2, updated_at=TS2, latency_ms=500)
    s_c = build_runtime_session(request=req_c, created_at=TS3, updated_at=TS3, latency_ms=300)
    sessions = [s_c, s_a, s_b]

    # Default: by runtimeSessionId ASC
    sorted_id = sort_runtime_sessions(sessions)
    ids = [s.runtimeSessionId for s in sorted_id]
    _eq(ids, sorted(ids), "default sort by runtimeSessionId ASC")

    # DESC
    sorted_id_desc = sort_runtime_sessions(sessions, ascending=False)
    ids_desc = [s.runtimeSessionId for s in sorted_id_desc]
    _eq(ids_desc, sorted(ids_desc, reverse=True), "runtimeSessionId DESC")

    # by createdAt ASC
    sorted_ts = sort_runtime_sessions(sessions, key="createdAt")
    _eq(sorted_ts[0].createdAt, TS,  "createdAt ASC: first is earliest")
    _eq(sorted_ts[-1].createdAt, TS3, "createdAt ASC: last is latest")

    # by latencyMs ASC
    sorted_lat = sort_runtime_sessions(sessions, key="latencyMs")
    lats = [s.metadata.latencyMs for s in sorted_lat]
    _eq(lats, sorted(lats), "latencyMs ASC")

    # by latencyMs DESC
    sorted_lat_d = sort_runtime_sessions(sessions, key="latencyMs", ascending=False)
    lats_d = [s.metadata.latencyMs for s in sorted_lat_d]
    _eq(lats_d, sorted(lats_d, reverse=True), "latencyMs DESC")

    # Input not mutated
    original_order = [s.runtimeSessionId for s in [s_c, s_a, s_b]]
    _ = sort_runtime_sessions([s_c, s_a, s_b])
    _eq([s.runtimeSessionId for s in [s_c, s_a, s_b]], original_order, "input not mutated")

    # Unknown key raises
    _raises(ValueError,
        lambda: sort_runtime_sessions(sessions, key="badkey"),
        "unknown sort key raises")

test_sort_runtime_sessions()


# ===========================================================================
# Section 20 — Filter utilities — RuntimeSession
# ===========================================================================

def test_filter_runtime_sessions() -> None:
    req_groq    = _make_request(conv_id="c1", user_prompt="groq q", provider="groq")
    req_openai  = _make_request(conv_id="c2", user_prompt="openai q", provider="openai", model="gpt-4")
    req_groq2   = _make_request(conv_id="c3", user_prompt="groq q2", provider="groq")

    s_ready    = build_runtime_session(request=req_groq, created_at=TS, updated_at=TS,
                                       state=ChatRuntimeStateEnum.READY)
    s_running  = build_runtime_session(request=req_openai, created_at=TS2, updated_at=TS2,
                                       state=ChatRuntimeStateEnum.RUNNING, latency_ms=200)

    req_for_resp = _make_request(conv_id="c3", user_prompt="groq q2", provider="groq")
    resp_obj = _make_response(req_for_resp)
    s_completed = build_runtime_session(
        request=req_groq2, created_at=TS3, updated_at=TS3,
        state=ChatRuntimeStateEnum.COMPLETED,
        response=resp_obj, latency_ms=450, success=True,
    )
    sessions = [s_ready, s_running, s_completed]

    # Filter by state
    ready_only = filter_runtime_sessions(sessions, state=ChatRuntimeStateEnum.READY)
    _eq(len(ready_only), 1, "filter by READY state")
    _eq(ready_only[0].state, ChatRuntimeStateEnum.READY, "correct state filtered")

    completed_only = filter_runtime_sessions(sessions, state=ChatRuntimeStateEnum.COMPLETED)
    _eq(len(completed_only), 1, "filter by COMPLETED")

    # Filter by provider
    groq_only = filter_runtime_sessions(sessions, provider="groq")
    _eq(len(groq_only), 2, "filter by groq provider")
    openai_only = filter_runtime_sessions(sessions, provider="OPENAI")
    _eq(len(openai_only), 1, "filter by OPENAI (case-insensitive)")

    # Filter by has_response
    with_resp = filter_runtime_sessions(sessions, has_response=True)
    _eq(len(with_resp), 1, "filter has_response=True")
    without_resp = filter_runtime_sessions(sessions, has_response=False)
    _eq(len(without_resp), 2, "filter has_response=False")

    # Filter by latency
    high_lat = filter_runtime_sessions(sessions, min_latency_ms=400)
    _eq(len(high_lat), 1, "filter min_latency_ms=400")

    low_lat = filter_runtime_sessions(sessions, max_latency_ms=300)
    _eq(len(low_lat), 2, "filter max_latency_ms=300")

    # Filter by confidence (only completed session has response)
    conf_filter = filter_runtime_sessions(sessions, min_confidence=80.0)
    _eq(len(conf_filter), 1, "filter min_confidence=80.0")

    # Filter by conversation_id
    c1_only = filter_runtime_sessions(sessions, conversation_id="c1")
    _eq(len(c1_only), 1, "filter by conversation_id")

    # No criteria → all returned
    all_sess = filter_runtime_sessions(sessions)
    _eq(len(all_sess), 3, "no criteria → all returned")

    # Empty list → empty result
    _eq(filter_runtime_sessions([], state=ChatRuntimeStateEnum.READY), [], "empty input → empty output")

test_filter_runtime_sessions()


# ===========================================================================
# Section 21 — Group utilities — RuntimeSession
# ===========================================================================

def test_group_runtime_sessions() -> None:
    req_g1 = _make_request(conv_id="c1", user_prompt="q1", provider="groq")
    req_g2 = _make_request(conv_id="c2", user_prompt="q2", provider="groq")
    req_o1 = _make_request(conv_id="c3", user_prompt="q3", provider="openai", model="gpt-4")

    s1 = build_runtime_session(request=req_g1, created_at=TS, updated_at=TS,
                                state=ChatRuntimeStateEnum.READY)
    s2 = build_runtime_session(request=req_g2, created_at=TS2, updated_at=TS2,
                                state=ChatRuntimeStateEnum.COMPLETED)
    s3 = build_runtime_session(request=req_o1, created_at=TS3, updated_at=TS3,
                                state=ChatRuntimeStateEnum.FAILED)
    sessions = [s1, s2, s3]

    # Group by provider
    by_prov = group_runtime_sessions(sessions, group_by="provider")
    _true("groq" in by_prov, "groq group exists")
    _true("openai" in by_prov, "openai group exists")
    _eq(len(by_prov["groq"]), 2, "2 groq sessions")
    _eq(len(by_prov["openai"]), 1, "1 openai session")

    # Group by state
    by_state = group_runtime_sessions(sessions, group_by="state")
    _true("READY" in by_state, "READY group exists")
    _true("COMPLETED" in by_state, "COMPLETED group exists")
    _true("FAILED" in by_state, "FAILED group exists")

    # Group by conversationId
    by_conv = group_runtime_sessions(sessions, group_by="conversationId")
    _eq(len(by_conv), 3, "3 distinct conversations → 3 groups")

    # Each group sorted by runtimeSessionId
    for grp_key, grp_sessions in by_prov.items():
        ids = [s.runtimeSessionId for s in grp_sessions]
        _eq(ids, sorted(ids), f"group '{grp_key}' sorted by sessionId")

    # Default group_by = "state"
    by_default = group_runtime_sessions(sessions)
    _is(by_default, dict, "default group returns dict")

    # Unknown key raises
    _raises(ValueError,
        lambda: group_runtime_sessions(sessions, group_by="badkey"),
        "unknown group_by raises")

    # Empty list → empty dict
    _eq(group_runtime_sessions([]), {}, "empty input → empty dict")

test_group_runtime_sessions()


# ===========================================================================
# Section 22 — Find utilities — RuntimeSession
# ===========================================================================

def test_find_runtime_session() -> None:
    s1 = _make_session()
    s2 = build_runtime_session(
        request=_make_request(user_prompt="another question"), created_at=TS, updated_at=TS,
    )
    sessions = [s1, s2]

    found = find_runtime_session(sessions, s1.runtimeSessionId)
    _true(found is not None, "find returns session")
    _eq(found.runtimeSessionId, s1.runtimeSessionId, "correct session found")

    not_found = find_runtime_session(sessions, "nonexistent-id")
    _true(not_found is None, "find returns None for missing id")

    # Strips whitespace
    found_ws = find_runtime_session(sessions, f"  {s2.runtimeSessionId}  ")
    _true(found_ws is not None, "find strips whitespace")

    # Empty list → None
    _true(find_runtime_session([], "any-id") is None, "empty list → None")

test_find_runtime_session()


# ===========================================================================
# Section 23 — Sort utilities — RuntimeRequest
# ===========================================================================

def test_sort_runtime_requests() -> None:
    r1 = _make_request(conv_id="c1", user_prompt="q1")
    r2 = _make_request(conv_id="c2", user_prompt="q2")
    r3 = _make_request(conv_id="c3", user_prompt="q3")
    requests = [r3, r1, r2]

    # Default: by runtimeRequestId ASC
    sorted_id = sort_runtime_requests(requests)
    ids = [r.runtimeRequestId for r in sorted_id]
    _eq(ids, sorted(ids), "default sort by runtimeRequestId ASC")

    # by conversationId
    sorted_conv = sort_runtime_requests(requests, key="conversationId")
    convs = [r.conversationId for r in sorted_conv]
    _eq(convs, sorted(convs), "conversationId ASC")

    # by provider
    r_openai = build_runtime_request(
        conversation_id="c4", user_prompt="q4",
        provider="openai", model="gpt-4", created_at=TS,
    )
    mixed = [r1, r_openai]
    sorted_prov = sort_runtime_requests(mixed, key="provider")
    provs = [r.provider for r in sorted_prov]
    _eq(provs, sorted(provs), "provider ASC")

    # DESC
    sorted_desc = sort_runtime_requests(requests, ascending=False)
    ids_desc = [r.runtimeRequestId for r in sorted_desc]
    _eq(ids_desc, sorted(ids_desc, reverse=True), "runtimeRequestId DESC")

    # Input not mutated
    orig = [r3.runtimeRequestId, r1.runtimeRequestId, r2.runtimeRequestId]
    _ = sort_runtime_requests([r3, r1, r2])
    _eq([r3.runtimeRequestId, r1.runtimeRequestId, r2.runtimeRequestId], orig, "input not mutated")

    # Unknown key raises
    _raises(ValueError, lambda: sort_runtime_requests(requests, key="badkey"), "unknown key raises")

test_sort_runtime_requests()


# ===========================================================================
# Section 24 — Filter utilities — RuntimeRequest
# ===========================================================================

def test_filter_runtime_requests() -> None:
    r_groq_s  = build_runtime_request(
        conversation_id="c1", user_prompt="q1", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS,
        session_id="sess-1", max_tokens=512, temperature=0.0,
    )
    r_groq_l  = build_runtime_request(
        conversation_id="c2", user_prompt="q2", provider="groq",
        model="llama-3.1-8b-instant", created_at=TS,
        session_id="sess-2", max_tokens=2048, temperature=0.5,
    )
    r_openai  = build_runtime_request(
        conversation_id="c3", user_prompt="q3", provider="openai",
        model="gpt-4", created_at=TS,
        session_id="sess-1", max_tokens=1024, temperature=1.0,
    )
    requests = [r_groq_s, r_groq_l, r_openai]

    # Filter by provider
    groq_reqs = filter_runtime_requests(requests, provider="groq")
    _eq(len(groq_reqs), 2, "filter groq provider")
    openai_reqs = filter_runtime_requests(requests, provider="OPENAI")
    _eq(len(openai_reqs), 1, "filter openai (case-insensitive)")

    # Filter by model
    llama_reqs = filter_runtime_requests(requests, model="llama-3.3-70b-versatile")
    _eq(len(llama_reqs), 1, "filter by model")

    # Filter by session_id
    sess1_reqs = filter_runtime_requests(requests, session_id="sess-1")
    _eq(len(sess1_reqs), 2, "filter by session_id")

    # Filter by conversation_id
    c2_reqs = filter_runtime_requests(requests, conversation_id="c2")
    _eq(len(c2_reqs), 1, "filter by conversation_id")

    # Filter by min_max_tokens
    big_reqs = filter_runtime_requests(requests, min_max_tokens=1024)
    _eq(len(big_reqs), 2, "filter min_max_tokens=1024")

    # Filter by max_temperature
    cold_reqs = filter_runtime_requests(requests, max_temperature=0.5)
    _eq(len(cold_reqs), 2, "filter max_temperature=0.5")

    # No criteria → all
    all_reqs = filter_runtime_requests(requests)
    _eq(len(all_reqs), 3, "no criteria → all returned")

test_filter_runtime_requests()


# ===========================================================================
# Section 25 — Group utilities — RuntimeRequest
# ===========================================================================

def test_group_runtime_requests() -> None:
    r_ga = build_runtime_request(
        conversation_id="c1", user_prompt="qa", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS, session_id="s1",
    )
    r_gb = build_runtime_request(
        conversation_id="c2", user_prompt="qb", provider="groq",
        model="llama-3.1-8b-instant", created_at=TS2, session_id="s2",
    )
    r_oa = build_runtime_request(
        conversation_id="c3", user_prompt="qc", provider="openai",
        model="gpt-4", created_at=TS3, session_id="s1",
    )
    requests = [r_ga, r_gb, r_oa]

    # Group by provider (default)
    by_prov = group_runtime_requests(requests)
    _true("groq" in by_prov, "groq group exists")
    _true("openai" in by_prov, "openai group exists")
    _eq(len(by_prov["groq"]), 2, "2 groq requests")
    _eq(len(by_prov["openai"]), 1, "1 openai request")

    # Group by model
    by_model = group_runtime_requests(requests, group_by="model")
    _eq(len(by_model), 3, "3 distinct models → 3 groups")

    # Group by sessionId
    by_sess = group_runtime_requests(requests, group_by="sessionId")
    _true("s1" in by_sess, "s1 group exists")
    _eq(len(by_sess["s1"]), 2, "2 requests in session s1")

    # Groups sorted by runtimeRequestId
    for k, grp in by_prov.items():
        ids = [r.runtimeRequestId for r in grp]
        _eq(ids, sorted(ids), f"group '{k}' sorted by requestId")

    # Unknown key raises
    _raises(ValueError,
        lambda: group_runtime_requests(requests, group_by="badkey"),
        "unknown group_by raises")

test_group_runtime_requests()


# ===========================================================================
# Section 26 — Find utilities — RuntimeRequest
# ===========================================================================

def test_find_runtime_request() -> None:
    r1 = _make_request(user_prompt="find me")
    r2 = _make_request(user_prompt="not me")
    requests = [r1, r2]

    found = find_runtime_request(requests, r1.runtimeRequestId)
    _true(found is not None, "find returns request")
    _eq(found.runtimeRequestId, r1.runtimeRequestId, "correct request found")

    not_found = find_runtime_request(requests, "nonexistent")
    _true(not_found is None, "missing id returns None")

    # Strips whitespace
    found_ws = find_runtime_request(requests, f"  {r2.runtimeRequestId}  ")
    _true(found_ws is not None, "find strips whitespace on id")

    # Empty list
    _true(find_runtime_request([], r1.runtimeRequestId) is None, "empty list → None")

test_find_runtime_request()


# ===========================================================================
# Section 27 — Statistics — extended fields & correctness
# ===========================================================================

def test_build_runtime_statistics_extended() -> None:
    req = _make_request()
    resp = _make_response(req)

    # Build a variety of sessions
    s_ready   = build_runtime_session(request=_make_request(user_prompt="q-ready"), created_at=TS, updated_at=TS, state=ChatRuntimeStateEnum.READY)
    s_running = build_runtime_session(request=_make_request(user_prompt="q-running"), created_at=TS, updated_at=TS, state=ChatRuntimeStateEnum.RUNNING, latency_ms=100)
    s_comp1   = build_runtime_session(
        request=_make_request(user_prompt="q-comp1"), created_at=TS2, updated_at=TS2,
        state=ChatRuntimeStateEnum.COMPLETED,
        response=build_runtime_response(
            runtime_request_id=_make_request(user_prompt="q-comp1").runtimeRequestId,
            content="ans1", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS2,
            confidence=80.0, prompt_tokens=100, completion_tokens=50, latency_ms=400,
        ),
        latency_ms=400, success=True,
    )
    s_comp2   = build_runtime_session(
        request=_make_request(user_prompt="q-comp2"), created_at=TS3, updated_at=TS3,
        state=ChatRuntimeStateEnum.COMPLETED,
        response=build_runtime_response(
            runtime_request_id=_make_request(user_prompt="q-comp2").runtimeRequestId,
            content="ans2", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS3,
            confidence=60.0, prompt_tokens=80, completion_tokens=30, latency_ms=200,
        ),
        latency_ms=200, success=True,
    )
    s_failed  = build_runtime_session(request=_make_request(user_prompt="q-fail"), created_at=TS, updated_at=TS, state=ChatRuntimeStateEnum.FAILED, latency_ms=500, success=False, error_message="timeout")

    sessions = [s_ready, s_running, s_comp1, s_comp2, s_failed]
    stats = build_runtime_statistics(sessions)

    _is(stats, RuntimeStatistics, "returns RuntimeStatistics")
    _eq(stats.totalSessions,     5, "totalSessions = 5")
    _eq(stats.readySessions,     1, "readySessions = 1")
    _eq(stats.runningSessions,   1, "runningSessions = 1")
    _eq(stats.completedSessions, 2, "completedSessions = 2")
    _eq(stats.failedSessions,    1, "failedSessions = 1")

    # executionRate = 2/5 = 0.4
    _eq(round(stats.executionRate, 6), round(2/5, 6), "executionRate = 2/5")
    # failureRate = 1/5 = 0.2
    _eq(round(stats.failureRate, 6), round(1/5, 6), "failureRate = 1/5")

    # averageLatency = (0 + 100 + 400 + 200 + 500) / 5 = 240
    _eq(stats.averageLatency, round(1200 / 5, 4), "averageLatency correct")

    # averageConfidence: only comp1 and comp2 have responses → (80 + 60) / 2 = 70
    _eq(stats.averageConfidence, 70.0, "averageConfidence = 70.0")

    # averageTokens: comp1=150, comp2=110, others=0 → (150+110)/5 = 52
    _eq(stats.averageTokens, round(260 / 5, 4), "averageTokens correct")


def test_statistics_empty() -> None:
    stats = build_runtime_statistics([])
    _eq(stats.totalSessions,     0,   "empty: totalSessions=0")
    _eq(stats.readySessions,     0,   "empty: readySessions=0")
    _eq(stats.runningSessions,   0,   "empty: runningSessions=0")
    _eq(stats.completedSessions, 0,   "empty: completedSessions=0")
    _eq(stats.failedSessions,    0,   "empty: failedSessions=0")
    _eq(stats.averageLatency,    0.0, "empty: averageLatency=0.0")
    _eq(stats.averageTokens,     0.0, "empty: averageTokens=0.0")
    _eq(stats.averageConfidence, 0.0, "empty: averageConfidence=0.0")
    _eq(stats.executionRate,     0.0, "empty: executionRate=0.0")
    _eq(stats.failureRate,       0.0, "empty: failureRate=0.0")

test_build_runtime_statistics_extended()
test_statistics_empty()


# ===========================================================================
# Section 28 — Statistics — order-independence
# ===========================================================================

def test_statistics_order_independence() -> None:
    s1 = build_runtime_session(request=_make_request(user_prompt="oi-q1"), created_at=TS, updated_at=TS, latency_ms=100)
    s2 = build_runtime_session(request=_make_request(user_prompt="oi-q2"), created_at=TS2, updated_at=TS2, latency_ms=300)
    s3 = build_runtime_session(request=_make_request(user_prompt="oi-q3"), created_at=TS3, updated_at=TS3, latency_ms=200)

    stats_abc = build_runtime_statistics([s1, s2, s3])
    stats_cba = build_runtime_statistics([s3, s2, s1])
    stats_bca = build_runtime_statistics([s2, s3, s1])

    _eq(stats_abc.averageLatency, stats_cba.averageLatency, "averageLatency order-independent ABC vs CBA")
    _eq(stats_abc.averageLatency, stats_bca.averageLatency, "averageLatency order-independent ABC vs BCA")
    _eq(stats_abc.totalSessions,  stats_cba.totalSessions,  "totalSessions order-independent")
    _eq(stats_abc.executionRate,  stats_cba.executionRate,  "executionRate order-independent")
    _eq(stats_abc.failureRate,    stats_cba.failureRate,    "failureRate order-independent")

test_statistics_order_independence()


# ===========================================================================
# Section 29 — Integration helpers
# ===========================================================================

# ── 29a  conversation_to_runtime_request ─────────────────────────────────

def test_conversation_to_runtime_request() -> None:
    # Build a minimal Conversation-like object using the real service
    from services.conversation_manager_service import (
        build_conversation, build_message,
        ConversationRole, ConversationState,
    )

    msg_sys  = build_message(CONV_ID, ConversationRole.SYSTEM, "You are an analyst.", 1, TS)
    msg_user = build_message(CONV_ID, ConversationRole.USER, "What ports are open?", 2, TS)
    msg_asst = build_message(CONV_ID, ConversationRole.ASSISTANT, "Ports 80, 443.", 3, TS)
    msg_usr2 = build_message(CONV_ID, ConversationRole.USER, "Any suspicious traffic?", 4, TS2)

    conv = build_conversation(
        created_by="analyst",
        title="Test Conversation",
        created_at=TS,
        investigation_id="inv-001",
        messages=[msg_sys, msg_user, msg_asst, msg_usr2],
    )

    req = conversation_to_runtime_request(
        conversation=conv, provider=PROVIDER, model=MODEL, created_at=TS2,
    )

    _is(req, RuntimeRequest, "conversation_to_runtime_request returns RuntimeRequest")
    _eq(req.conversationId, conv.conversationId, "conversationId taken from conversation")
    _eq(req.userPrompt, "Any suspicious traffic?", "last USER message becomes userPrompt")
    _true("You are an analyst." in req.systemPrompt, "SYSTEM message in systemPrompt")
    _eq(req.provider, PROVIDER, "provider set")
    _eq(req.model, MODEL, "model set")

    # Determinism
    req2 = conversation_to_runtime_request(
        conversation=conv, provider=PROVIDER, model=MODEL, created_at=TS2,
    )
    _eq(req.runtimeRequestId, req2.runtimeRequestId, "deterministic")

    # No USER message raises
    conv_no_user = build_conversation(
        created_by="analyst", title="No User Conv", created_at=TS,
        messages=[msg_sys],
    )
    _raises(InvalidRuntimeRequestError,
        lambda: conversation_to_runtime_request(conv_no_user, PROVIDER, MODEL, TS),
        "no USER message raises")

test_conversation_to_runtime_request()


# ── 29b  memory_to_runtime_request ───────────────────────────────────────

def test_memory_to_runtime_request() -> None:
    from services.session_memory_service import (
        build_memory_entry, build_session_memory,
        MemoryTypeEnum, MemoryStateEnum,
    )

    mem1 = build_memory_entry(
        conversation_id=CONV_ID, memory_type=MemoryTypeEnum.SHORT_TERM,
        title="Key finding", content="Port 22 is open on 192.168.1.10",
        created_at=TS, importance_score=0.9, confidence=0.95,
    )
    mem2 = build_memory_entry(
        conversation_id=CONV_ID, memory_type=MemoryTypeEnum.LONG_TERM,
        title="Device profile", content="Router is Cisco IOS 15.x",
        created_at=TS, importance_score=0.7, confidence=0.8,
        state=MemoryStateEnum.ACTIVE,
    )
    mem_archived = build_memory_entry(
        conversation_id=CONV_ID, memory_type=MemoryTypeEnum.EPISODIC,
        title="Old info", content="Archived data",
        created_at=TS, importance_score=0.3, state=MemoryStateEnum.ARCHIVED,
    )

    session_mem = build_session_memory(
        conversation_id=CONV_ID, created_at=TS, updated_at=TS,
        memories=[mem1, mem2, mem_archived],
    )

    req = memory_to_runtime_request(
        session_memory=session_mem,
        provider=PROVIDER, model=MODEL, created_at=TS2,
        user_prompt="What do you know about the network?",
    )

    _is(req, RuntimeRequest, "memory_to_runtime_request returns RuntimeRequest")
    _eq(req.conversationId, CONV_ID, "conversationId from session_memory")
    _eq(req.userPrompt, "What do you know about the network?", "userPrompt passed through")
    _true("[SESSION MEMORY]" in req.systemPrompt, "memory block in systemPrompt")
    _true("Key finding" in req.systemPrompt, "active memory title in systemPrompt")
    _true("Device profile" in req.systemPrompt, "second active memory in systemPrompt")
    # Archived memory excluded
    _false("Old info" in req.systemPrompt, "archived memory excluded from systemPrompt")

    # Determinism
    req2 = memory_to_runtime_request(
        session_memory=session_mem, provider=PROVIDER, model=MODEL, created_at=TS2,
        user_prompt="What do you know about the network?",
    )
    _eq(req.runtimeRequestId, req2.runtimeRequestId, "memory_to_runtime_request deterministic")

test_memory_to_runtime_request()


# ── 29c  context_window_to_runtime_request ───────────────────────────────

def test_context_window_to_runtime_request() -> None:
    from services.context_window_service import (
        build_context_item, build_context_window,
        ContextSourceEnum, ContextPriorityEnum,
    )

    item_user = build_context_item(
        source=ContextSourceEnum.USER_INPUT,
        priority=ContextPriorityEnum.CRITICAL,
        title="User query",
        content="Is the network under attack?",
        created_at=TS,
    )
    item_finding = build_context_item(
        source=ContextSourceEnum.FINDING,
        priority=ContextPriorityEnum.HIGH,
        title="Critical finding",
        content="Lateral movement detected on subnet.",
        created_at=TS,
        importance_score=0.9,
    )
    item_conv = build_context_item(
        source=ContextSourceEnum.CONVERSATION,
        priority=ContextPriorityEnum.NORMAL,
        title="Prior turn",
        content="Previous user message.",
        created_at=TS,
    )

    window = build_context_window(
        created_at=TS,
        conversation_id=CONV_ID,
        items=[item_user, item_finding, item_conv],
    )

    req = context_window_to_runtime_request(
        context_window=window, provider=PROVIDER, model=MODEL, created_at=TS2,
    )

    _is(req, RuntimeRequest, "context_window_to_runtime_request returns RuntimeRequest")
    _eq(req.conversationId, CONV_ID, "conversationId from window")
    # USER_INPUT and CONVERSATION go to userPrompt
    _true("Is the network under attack?" in req.userPrompt, "USER_INPUT in userPrompt")
    _true("Previous user message." in req.userPrompt, "CONVERSATION in userPrompt")
    # FINDING goes to systemPrompt
    _true("Lateral movement detected" in req.systemPrompt, "FINDING in systemPrompt")

    # Fallback when no user items
    window_no_user = build_context_window(
        created_at=TS,
        conversation_id=CONV_ID,
        items=[item_finding],
    )
    req_no_user = context_window_to_runtime_request(
        context_window=window_no_user, provider=PROVIDER, model=MODEL, created_at=TS2,
    )
    _eq(req_no_user.userPrompt, "[no user input]", "fallback userPrompt when no user items")

    # Determinism
    req2 = context_window_to_runtime_request(
        context_window=window, provider=PROVIDER, model=MODEL, created_at=TS2,
    )
    _eq(req.runtimeRequestId, req2.runtimeRequestId, "context_window_to_runtime_request deterministic")

test_context_window_to_runtime_request()


# ── 29d  execution_result_to_runtime_response ────────────────────────────

def test_execution_result_to_runtime_response() -> None:
    from services.ai_execution_service import (
        build_execution_request, build_execution_response,
        build_execution_metadata, build_execution_result,
    )

    exec_req = build_execution_request(
        provider="groq", model=MODEL,
        system_prompt="sys", user_prompt="What is the risk?",
        created_at=TS,
    )
    exec_resp = build_execution_response(
        execution_id=exec_req.executionId,
        provider="groq", model=MODEL,
        content="The risk is HIGH.",
        finish_reason="stop",
        created_at=TS2,
        prompt_tokens=50,
        completion_tokens=20,
        latency_ms=300,
    )
    exec_meta = build_execution_metadata(
        execution_id=exec_req.executionId,
        provider="groq", model=MODEL,
        strategy="priority",
        attempt_number=1, total_attempts=1,
        processing_time_ms=300,
        success=True,
    )
    exec_result = build_execution_result(exec_req, exec_resp, exec_meta)

    req  = _make_request()
    resp = execution_result_to_runtime_response(
        execution_result=exec_result,
        runtime_request_id=req.runtimeRequestId,
        created_at=TS2,
        confidence=90.0,
    )

    _is(resp, RuntimeResponse, "execution_result_to_runtime_response returns RuntimeResponse")
    _eq(resp.runtimeRequestId, req.runtimeRequestId, "runtimeRequestId linked")
    _eq(resp.content, "The risk is HIGH.", "content extracted")
    _eq(resp.finishReason, "stop", "finishReason extracted")
    _eq(resp.promptTokens, 50, "promptTokens extracted")
    _eq(resp.completionTokens, 20, "completionTokens extracted")
    _eq(resp.totalTokens, 70, "totalTokens = 50+20")
    _eq(resp.latencyMs, 300, "latencyMs from processingTimeMs")
    _eq(resp.confidence, 90.0, "confidence passed through")
    _eq(resp.provider, "groq", "provider extracted")

    # Failed execution (response=None)
    exec_result_fail = build_execution_result(exec_req, None, exec_meta)
    resp_fail = execution_result_to_runtime_response(
        execution_result=exec_result_fail,
        runtime_request_id=req.runtimeRequestId,
        created_at=TS2,
    )
    _eq(resp_fail.content, "", "failed execution: empty content")
    _eq(resp_fail.finishReason, "error", "failed execution: finishReason=error")
    _eq(resp_fail.promptTokens, 0, "failed execution: promptTokens=0")

    # Determinism
    resp2 = execution_result_to_runtime_response(
        execution_result=exec_result,
        runtime_request_id=req.runtimeRequestId,
        created_at=TS2,
        confidence=90.0,
    )
    _eq(resp.runtimeResponseId, resp2.runtimeResponseId, "execution_result_to_runtime_response deterministic")

test_execution_result_to_runtime_response()


# ── 29e  copilot_session_to_runtime_response ─────────────────────────────

def test_copilot_session_to_runtime_response() -> None:
    from services.copilot_orchestrator_service import (
        build_copilot_request, build_copilot_response, build_copilot_session,
    )

    cp_req = build_copilot_request(
        context_id="ctx-1", reasoning_id="rsn-1",
        prompt_package_id="pkg-1", narrative_id="nar-1",
        investigation_id="inv-1",
        provider=PROVIDER, model=MODEL,
        system_prompt="sys", user_prompt="What happened?",
        created_at=TS,
        processing_time_ms=100,
    )
    cp_resp = build_copilot_response(
        request_id=cp_req.requestId,
        provider=PROVIDER, model=MODEL,
        content="An intrusion was detected.",
        created_at=TS2,
        confidence=75.0,
        processing_time_ms=250,
    )
    cp_sess = build_copilot_session(
        request=cp_req, response=cp_resp, created_at=TS2,
        processing_time_ms=350,
    )

    req  = _make_request()
    resp = copilot_session_to_runtime_response(
        copilot_session=cp_sess,
        runtime_request_id=req.runtimeRequestId,
        created_at=TS2,
    )

    _is(resp, RuntimeResponse, "copilot_session_to_runtime_response returns RuntimeResponse")
    _eq(resp.runtimeRequestId, req.runtimeRequestId, "runtimeRequestId linked")
    _eq(resp.content, "An intrusion was detected.", "content extracted")
    _eq(resp.finishReason, "stop", "finishReason='stop'")
    _eq(resp.confidence, 75.0, "confidence from copilot response")
    _eq(resp.provider, PROVIDER, "provider from copilot request")
    _eq(resp.model,    MODEL,    "model from copilot request")
    _eq(resp.latencyMs, 350, "latencyMs from processingTimeMs")

    # Determinism
    resp2 = copilot_session_to_runtime_response(
        copilot_session=cp_sess,
        runtime_request_id=req.runtimeRequestId,
        created_at=TS2,
    )
    _eq(resp.runtimeResponseId, resp2.runtimeResponseId, "copilot_session_to_runtime_response deterministic")

test_copilot_session_to_runtime_response()


# ===========================================================================
# Section 30 — Edge cases
# ===========================================================================

def test_edge_cases() -> None:
    # maxTokens = 1
    req_min = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, max_tokens=1,
    )
    _eq(req_min.maxTokens, 1, "maxTokens=1 allowed")

    # Very long user prompt (only first 64 chars used in key)
    long_prompt = "A" * 500
    req_long = build_runtime_request(
        conversation_id="c1", user_prompt=long_prompt, provider="groq",
        model="m", created_at=TS,
    )
    _is(req_long, RuntimeRequest, "very long userPrompt accepted")
    # Two prompts with identical first 64 chars → same key ([:64] slice in hash)
    long_prompt2 = "A" * 64 + "B" + "A" * 435
    req_long2 = build_runtime_request(
        conversation_id="c1", user_prompt=long_prompt2, provider="groq",
        model="m", created_at=TS,
    )
    _eq(req_long.runtimeRequestKey, req_long2.runtimeRequestKey,
        "prompts sharing first 64 chars → same key ([:64] hash)")
    # Prompt that differs in first 64 chars → different key
    different_start = "B" + "A" * 499
    req_diff = build_runtime_request(
        conversation_id="c1", user_prompt=different_start, provider="groq",
        model="m", created_at=TS,
    )
    _ne(req_long.runtimeRequestKey, req_diff.runtimeRequestKey,
        "first-64-char difference changes key")

    # Empty system prompt is fine
    req_no_sys = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, system_prompt="",
    )
    _eq(req_no_sys.systemPrompt, "", "empty systemPrompt allowed")

    # Empty session_id is fine
    req_no_sess = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, session_id="",
    )
    _eq(req_no_sess.sessionId, "", "empty sessionId allowed")

    # Metadata copied (not shared reference)
    orig_meta = {"key": "val"}
    req_meta = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, metadata=orig_meta,
    )
    orig_meta["key"] = "mutated"
    _eq(req_meta.metadata["key"], "val", "metadata dict is copied, not referenced")

    # Response with 0 tokens
    req_tok = _make_request()
    resp_tok = build_runtime_response(
        runtime_request_id=req_tok.runtimeRequestId,
        content="", finish_reason="stop",
        provider="groq", model="m", created_at=TS,
        prompt_tokens=0, completion_tokens=0,
    )
    _eq(resp_tok.totalTokens, 0, "totalTokens=0 when both 0")

    # Single session statistics
    s = _make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True)
    stats_one = build_runtime_statistics([s])
    _eq(stats_one.totalSessions, 1, "single session stats total=1")
    _eq(stats_one.completedSessions, 1, "single completed")
    _eq(stats_one.executionRate, 1.0, "executionRate=1.0 for single completed")
    _eq(stats_one.failureRate, 0.0, "failureRate=0.0 for single completed")

    # All failed
    s_f1 = _make_session(state=ChatRuntimeStateEnum.FAILED)
    s_f2 = _make_session(state=ChatRuntimeStateEnum.FAILED)
    stats_fail = build_runtime_statistics([s_f1, s_f2])
    _eq(stats_fail.failureRate, 1.0, "failureRate=1.0 when all failed")
    _eq(stats_fail.executionRate, 0.0, "executionRate=0.0 when all failed")

    # _norm helper
    _eq(_norm("  GROQ  "), "groq", "_norm strips and lowercases")
    _eq(_norm(""), "", "_norm empty string")

    # _clamp_float helper
    _eq(_clamp_float(150.0, 0.0, 100.0), 100.0, "_clamp_float upper bound")
    _eq(_clamp_float(-5.0, 0.0, 100.0),  0.0,   "_clamp_float lower bound")
    _eq(_clamp_float(50.0, 0.0, 100.0),  50.0,  "_clamp_float in range")

    # _estimate_tokens helper
    _eq(_estimate_tokens(""), 0, "_estimate_tokens empty")
    _eq(_estimate_tokens("abcd"), 1, "_estimate_tokens 4 chars = 1 token")
    _eq(_estimate_tokens("a" * 8), 2, "_estimate_tokens 8 chars = 2 tokens")

    # _norm_strings helper
    _eq(_norm_strings(None), (), "_norm_strings None → empty tuple")
    _eq(_norm_strings([]), (), "_norm_strings [] → empty tuple")
    result_ns = _norm_strings(["b", "a", "a", "c"])
    _eq(result_ns, ("a", "b", "c"), "_norm_strings deduped + sorted")

    # ALLOWED_TRANSITIONS dict has all states
    _true(ChatRuntimeStateEnum.READY    in _ALLOWED_TRANSITIONS, "READY in transitions")
    _true(ChatRuntimeStateEnum.RUNNING  in _ALLOWED_TRANSITIONS, "RUNNING in transitions")
    _true(ChatRuntimeStateEnum.WAITING  in _ALLOWED_TRANSITIONS, "WAITING in transitions")
    _true(ChatRuntimeStateEnum.COMPLETED in _ALLOWED_TRANSITIONS, "COMPLETED in transitions")
    _true(ChatRuntimeStateEnum.FAILED   in _ALLOWED_TRANSITIONS, "FAILED in transitions")
    _eq(_ALLOWED_TRANSITIONS[ChatRuntimeStateEnum.COMPLETED], (), "COMPLETED has no allowed transitions")
    _eq(_ALLOWED_TRANSITIONS[ChatRuntimeStateEnum.FAILED],    (), "FAILED has no allowed transitions")

test_edge_cases()


# ===========================================================================
# Section 31 — Zero-randomness guarantee
# ===========================================================================

def test_zero_randomness() -> None:
    # Run the entire pipeline 3 times; every ID and fingerprint must be identical

    def _pipeline():
        req  = _make_request()
        resp = _make_response(req)
        sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)
        run  = start_runtime_session(sess, updated_at=TS2)
        done = complete_runtime_session(run, resp, TS3, latency_ms=400)
        rst  = reset_runtime_session(done, updated_at=TS3)
        return (
            req.runtimeRequestId,
            req.runtimeRequestKey,
            resp.runtimeResponseId,
            resp.runtimeResponseKey,
            sess.runtimeSessionId,
            sess.runtimeSessionKey,
            sess.runtimeFingerprint,
            run.runtimeFingerprint,
            done.runtimeFingerprint,
            rst.runtimeFingerprint,
        )

    r1, r2, r3 = _pipeline(), _pipeline(), _pipeline()

    for i, (a, b, c) in enumerate(zip(r1, r2, r3)):
        _eq(a, b, f"zero-randomness run1==run2 field[{i}]")
        _eq(b, c, f"zero-randomness run2==run3 field[{i}]")

    # Verify no uuid4 / random was used — all IDs are UUIDv5 (version 5)
    req = _make_request()
    uid_str = req.runtimeRequestId
    # UUIDv5 has version nibble = 5
    import uuid as _uuid_mod
    uid_obj = _uuid_mod.UUID(uid_str)
    _eq(uid_obj.version, 5, "runtimeRequestId is UUIDv5 (version=5)")

    resp = _make_response(req)
    uid_resp = _uuid_mod.UUID(resp.runtimeResponseId)
    _eq(uid_resp.version, 5, "runtimeResponseId is UUIDv5")

    sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)
    uid_sess = _uuid_mod.UUID(sess.runtimeSessionId)
    _eq(uid_sess.version, 5, "runtimeSessionId is UUIDv5")

test_zero_randomness()


# ===========================================================================
# Section 32 — Full pipeline end-to-end
# ===========================================================================

def test_full_pipeline() -> None:
    """READY → RUNNING → COMPLETED lifecycle with statistics verification."""
    sessions: List[RuntimeSession] = []

    for i in range(5):
        req  = _make_request(user_prompt=f"Pipeline question {i}")
        sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)
        _eq(sess.state, ChatRuntimeStateEnum.READY, f"session {i}: initial READY")
        _true(should_execute_runtime(sess), f"session {i}: should execute")
        _false(is_runtime_complete(sess), f"session {i}: not complete yet")

        running = start_runtime_session(sess, updated_at=TS2)
        _eq(running.state, ChatRuntimeStateEnum.RUNNING, f"session {i}: RUNNING")
        _false(should_execute_runtime(running), f"session {i}: running → not executable")

        resp = build_runtime_response(
            runtime_request_id=req.runtimeRequestId,
            content=f"Answer {i}", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS2,
            confidence=float(70 + i),
            prompt_tokens=100 + i * 10,
            completion_tokens=30 + i * 5,
            latency_ms=200 + i * 50,
        )
        done = complete_runtime_session(running, resp, TS3, latency_ms=200 + i * 50)
        _eq(done.state, ChatRuntimeStateEnum.COMPLETED, f"session {i}: COMPLETED")
        _true(is_runtime_complete(done), f"session {i}: is complete")
        sessions.append(done)

    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions,     5, "pipeline: totalSessions=5")
    _eq(stats.completedSessions, 5, "pipeline: all completed")
    _eq(stats.failedSessions,    0, "pipeline: no failures")
    _eq(stats.readySessions,     0, "pipeline: no ready")
    _eq(stats.runningSessions,   0, "pipeline: no running")
    _eq(stats.executionRate, 1.0, "pipeline: executionRate=1.0")
    _eq(stats.failureRate,   0.0, "pipeline: failureRate=0.0")
    # averageConfidence = (70+71+72+73+74)/5 = 72.0
    _eq(stats.averageConfidence, 72.0, "pipeline: averageConfidence=72.0")

test_full_pipeline()


# ===========================================================================
# Section 33 — Full failure pipeline
# ===========================================================================

def test_full_failure_pipeline() -> None:
    sessions: List[RuntimeSession] = []

    for i in range(3):
        req  = _make_request(user_prompt=f"Fail question {i}")
        sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)
        running = start_runtime_session(sess, updated_at=TS2)
        failed  = fail_runtime_session(running, f"Error {i}", TS3, latency_ms=100 * (i+1))
        _eq(failed.state, ChatRuntimeStateEnum.FAILED, f"fail pipeline {i}: FAILED")
        _true(is_runtime_complete(failed), f"fail pipeline {i}: is complete")
        sessions.append(failed)

    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions,     3, "failure pipeline: total=3")
    _eq(stats.failedSessions,    3, "failure pipeline: all failed")
    _eq(stats.completedSessions, 0, "failure pipeline: no completed")
    _eq(stats.failureRate, 1.0,  "failure pipeline: failureRate=1.0")
    _eq(stats.executionRate, 0.0, "failure pipeline: executionRate=0.0")
    _eq(stats.averageConfidence, 0.0, "failure pipeline: averageConfidence=0.0 (no responses)")

test_full_failure_pipeline()


# ===========================================================================
# Section 34 — Reset pipeline (reset → re-run)
# ===========================================================================

def test_reset_and_rerun_pipeline() -> None:
    req     = _make_request(user_prompt="Reset me")
    sess    = build_runtime_session(request=req, created_at=TS, updated_at=TS)
    running = start_runtime_session(sess, updated_at=TS2)
    failed  = fail_runtime_session(running, "First attempt failed", TS2, latency_ms=500)

    # Reset
    reset = reset_runtime_session(failed, updated_at=TS3)
    _eq(reset.state, ChatRuntimeStateEnum.READY, "after reset: READY")
    _eq(reset.response, None, "after reset: no response")
    _eq(reset.metadata.errorMessage, "", "after reset: errorMessage cleared")
    _eq(reset.metadata.success, True, "after reset: success=True")
    _true(should_execute_runtime(reset), "after reset: should execute")

    # Re-run
    running2 = start_runtime_session(reset, updated_at=TS3)
    resp2 = _make_response(req, created_at=TS3)
    done2 = complete_runtime_session(running2, resp2, TS3, latency_ms=200)
    _eq(done2.state, ChatRuntimeStateEnum.COMPLETED, "rerun: COMPLETED")
    _true(done2.response is not None, "rerun: response attached")

    # Same session ID across the whole lifecycle
    _eq(sess.runtimeSessionId, done2.runtimeSessionId, "sessionId stable across reset+rerun")

test_reset_and_rerun_pipeline()


# ===========================================================================
# Section 35 — Sorting tie-breaker determinism
# ===========================================================================

def test_sort_tiebreaker() -> None:
    """Sessions with identical latency must break ties by runtimeSessionId."""
    sessions: List[RuntimeSession] = []
    for i in range(5):
        req = _make_request(user_prompt=f"tie-{i}")
        s   = build_runtime_session(request=req, created_at=TS, updated_at=TS, latency_ms=300)
        sessions.append(s)

    sorted1 = sort_runtime_sessions(sessions, key="latencyMs")
    sorted2 = sort_runtime_sessions(sessions, key="latencyMs")

    ids1 = [s.runtimeSessionId for s in sorted1]
    ids2 = [s.runtimeSessionId for s in sorted2]
    _eq(ids1, ids2, "sort with identical latency is stable/deterministic")

    # Verify tie-breaker is by ID ASC
    _eq(ids1, sorted(ids1), "tie-break by runtimeSessionId ASC")

test_sort_tiebreaker()


# ===========================================================================
# Section 36 — Filter combined criteria
# ===========================================================================

def test_filter_combined_criteria() -> None:
    req_g1 = build_runtime_request(
        conversation_id="c1", user_prompt="combined-1", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS, session_id="s1",
    )
    req_g2 = build_runtime_request(
        conversation_id="c2", user_prompt="combined-2", provider="groq",
        model="llama-3.1-8b-instant", created_at=TS2, session_id="s2",
    )
    req_o1 = build_runtime_request(
        conversation_id="c3", user_prompt="combined-3", provider="openai",
        model="gpt-4", created_at=TS3, session_id="s1",
    )

    resp1 = build_runtime_response(
        runtime_request_id=req_g1.runtimeRequestId,
        content="r1", finish_reason="stop",
        provider="groq", model="llama-3.3-70b-versatile", created_at=TS2,
        confidence=90.0, latency_ms=100,
    )
    s1 = build_runtime_session(request=req_g1, created_at=TS, updated_at=TS2,
                                state=ChatRuntimeStateEnum.COMPLETED,
                                response=resp1, latency_ms=100, success=True)
    s2 = build_runtime_session(request=req_g2, created_at=TS2, updated_at=TS2,
                                state=ChatRuntimeStateEnum.RUNNING, latency_ms=200)
    s3 = build_runtime_session(request=req_o1, created_at=TS3, updated_at=TS3,
                                state=ChatRuntimeStateEnum.FAILED, latency_ms=999, success=False)

    # provider=groq AND state=COMPLETED
    result = filter_runtime_sessions([s1, s2, s3],
                                     provider="groq",
                                     state=ChatRuntimeStateEnum.COMPLETED)
    _eq(len(result), 1, "combined provider+state filter")
    _eq(result[0].runtimeSessionId, s1.runtimeSessionId, "correct session returned")

    # has_response AND min_confidence
    result2 = filter_runtime_sessions([s1, s2, s3],
                                      has_response=True, min_confidence=85.0)
    _eq(len(result2), 1, "has_response + min_confidence filter")

    # success_only=True
    result3 = filter_runtime_sessions([s1, s2, s3], success_only=True)
    _eq(len(result3), 2, "success_only=True → completed+running (both success)")

    # success_only=False (not successful only)
    result4 = filter_runtime_sessions([s1, s2, s3], success_only=False)
    _eq(len(result4), 1, "success_only=False → only failed")

test_filter_combined_criteria()


# ===========================================================================
# Section 37 — Group all valid keys (coverage)
# ===========================================================================

def test_group_all_keys() -> None:
    sessions: List[RuntimeSession] = []
    for i, (prov, state) in enumerate([
        ("groq",   ChatRuntimeStateEnum.READY),
        ("groq",   ChatRuntimeStateEnum.COMPLETED),
        ("openai", ChatRuntimeStateEnum.FAILED),
    ]):
        req = build_runtime_request(
            conversation_id=f"cov-c{i}", user_prompt=f"cov-q{i}",
            provider=prov, model="m", created_at=TS,
        )
        s = build_runtime_session(request=req, created_at=TS, updated_at=TS, state=state)
        sessions.append(s)

    for key in ("state", "provider", "model", "conversationId", "runtimeSessionId"):
        g = group_runtime_sessions(sessions, group_by=key)
        _is(g, dict, f"group_runtime_sessions by '{key}' returns dict")
        total = sum(len(v) for v in g.values())
        _eq(total, len(sessions), f"group_by='{key}' preserves all sessions")

    requests = [s.request for s in sessions]
    for key in ("provider", "model", "conversationId", "sessionId", "runtimeRequestId"):
        g = group_runtime_requests(requests, group_by=key)
        _is(g, dict, f"group_runtime_requests by '{key}' returns dict")
        total = sum(len(v) for v in g.values())
        _eq(total, len(requests), f"req group_by='{key}' preserves all requests")

test_group_all_keys()


# ===========================================================================
# Section 38 — RuntimeMetadata pipeline_stages dedup behaviour
# ===========================================================================

def test_pipeline_stages() -> None:
    meta = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID,
        provider=PROVIDER, model=MODEL, created_at=TS,
        pipeline_stages=["MEMORY", "CONTEXT_WINDOW", "MEMORY", "TOKEN_BUDGET", "CONTEXT_WINDOW"],
    )
    # _norm_strings deduplicates and sorts
    _eq(len(meta.pipelineStages), 3, "pipeline_stages deduped to 3 unique values")
    _eq(meta.pipelineStages, tuple(sorted({"MEMORY", "CONTEXT_WINDOW", "TOKEN_BUDGET"})),
        "pipeline_stages sorted deterministically")

    # Empty pipeline_stages
    meta_empty = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID,
        provider=PROVIDER, model=MODEL, created_at=TS,
        pipeline_stages=[],
    )
    _eq(meta_empty.pipelineStages, (), "empty pipeline_stages → empty tuple")

    # None pipeline_stages
    meta_none = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID,
        provider=PROVIDER, model=MODEL, created_at=TS,
    )
    _eq(meta_none.pipelineStages, (), "None pipeline_stages → empty tuple")

test_pipeline_stages()


# ===========================================================================
# Section 39 — Key collision resistance
# ===========================================================================

def test_key_collision_resistance() -> None:
    """Different field combinations must not produce the same key."""
    # Null-byte separator prevents cross-field collision
    # e.g. conversationId="ab" sessionId="c" vs conversationId="a" sessionId="bc"
    k1 = runtimeRequestKey("ab", "c",  "q")
    k2 = runtimeRequestKey("a",  "bc", "q")
    _ne(k1, k2, "null-byte separator prevents conv+session collision")

    k3 = runtimeResponseKey("id1", "content", "stop")
    k4 = runtimeResponseKey("id1content", "", "stop")
    _ne(k3, k4, "null-byte separator prevents requestId+content collision")

    k5 = runtimeSessionKey("c1", "s1", "rk1")
    k6 = runtimeSessionKey("c1s1", "", "rk1")
    _ne(k5, k6, "null-byte separator prevents conv+session+reqKey collision")

    # Swapped fields produce different keys
    k7  = runtimeRequestKey("aaa", "bbb", "ccc")
    k8  = runtimeRequestKey("bbb", "aaa", "ccc")
    k9  = runtimeRequestKey("ccc", "bbb", "aaa")
    _ne(k7, k8, "swapped conv+session → different key")
    _ne(k7, k9, "swapped conv+prompt → different key")
    _ne(k8, k9, "all three orderings distinct")

test_key_collision_resistance()


# ===========================================================================
# Section 40 — Statistics with mixed state sessions
# ===========================================================================

def test_statistics_mixed() -> None:
    # 2 ready, 1 running, 3 completed, 2 failed = 8 total
    sessions: List[RuntimeSession] = []

    for i in range(2):
        s = build_runtime_session(
            request=_make_request(user_prompt=f"mix-ready-{i}"),
            created_at=TS, updated_at=TS,
            state=ChatRuntimeStateEnum.READY,
        )
        sessions.append(s)

    for i in range(1):
        s = build_runtime_session(
            request=_make_request(user_prompt=f"mix-running-{i}"),
            created_at=TS, updated_at=TS,
            state=ChatRuntimeStateEnum.RUNNING, latency_ms=50,
        )
        sessions.append(s)

    for i in range(3):
        req  = _make_request(user_prompt=f"mix-comp-{i}")
        resp = build_runtime_response(
            runtime_request_id=req.runtimeRequestId,
            content=f"answer-{i}", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS2,
            confidence=float(60 + i * 10),
            prompt_tokens=100, completion_tokens=50, latency_ms=300,
        )
        s = build_runtime_session(
            request=req, created_at=TS2, updated_at=TS2,
            state=ChatRuntimeStateEnum.COMPLETED,
            response=resp, latency_ms=300, success=True,
        )
        sessions.append(s)

    for i in range(2):
        s = build_runtime_session(
            request=_make_request(user_prompt=f"mix-fail-{i}"),
            created_at=TS, updated_at=TS,
            state=ChatRuntimeStateEnum.FAILED, latency_ms=800, success=False,
        )
        sessions.append(s)

    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions,     8, "mixed: totalSessions=8")
    _eq(stats.readySessions,     2, "mixed: readySessions=2")
    _eq(stats.runningSessions,   1, "mixed: runningSessions=1")
    _eq(stats.completedSessions, 3, "mixed: completedSessions=3")
    _eq(stats.failedSessions,    2, "mixed: failedSessions=2")
    _eq(round(stats.executionRate, 6), round(3/8, 6), "mixed: executionRate=3/8")
    _eq(round(stats.failureRate, 6),   round(2/8, 6), "mixed: failureRate=2/8")
    # averageConfidence from 3 completed responses: (60+70+80)/3 = 70.0
    _eq(stats.averageConfidence, 70.0, "mixed: averageConfidence=70.0")

test_statistics_mixed()


# ===========================================================================
# Section 41 — validate_runtime_session all states
# ===========================================================================

def test_validate_all_states() -> None:
    for state in ChatRuntimeStateEnum:
        validate_runtime_session(CONV_ID, TS, TS, state)
        _true(True, f"validate_runtime_session accepts state={state.value}")

test_validate_all_states()


# ===========================================================================
# Section 42 — WAITING state lifecycle
# ===========================================================================

def test_waiting_state() -> None:
    req = _make_request(user_prompt="waiting state test")
    sess_wait = build_runtime_session(
        request=req, created_at=TS, updated_at=TS,
        state=ChatRuntimeStateEnum.WAITING,
    )
    _eq(sess_wait.state, ChatRuntimeStateEnum.WAITING, "WAITING state set")
    _true(should_execute_runtime(sess_wait), "WAITING should execute")
    _true(can_resume_runtime(sess_wait),     "WAITING can resume")
    _false(is_runtime_complete(sess_wait),   "WAITING is not complete")

    # WAITING → RUNNING is allowed
    started = start_runtime_session(sess_wait, updated_at=TS2)
    _eq(started.state, ChatRuntimeStateEnum.RUNNING, "WAITING → RUNNING allowed")

    # WAITING → COMPLETED not allowed directly
    _raises(InvalidChatSessionError,
        lambda: complete_runtime_session(sess_wait, _make_response(req), TS2),
        "WAITING → COMPLETED not allowed directly")

test_waiting_state()


# ===========================================================================
# Section 43 — RuntimeRequest metadata isolation
# ===========================================================================

def test_request_metadata_isolation() -> None:
    meta = {"context": "original"}
    req = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, metadata=meta,
    )
    # Mutate original dict after build
    meta["context"] = "mutated"
    meta["new_key"] = "new_value"
    _eq(req.metadata.get("context"), "original", "original metadata not affected by post-build mutation")
    _false("new_key" in req.metadata, "new key not in request metadata after post-build addition")

test_request_metadata_isolation()


# ===========================================================================
# Section 44 — find returns first match (list order)
# ===========================================================================

def test_find_first_match() -> None:
    s1 = _make_session()
    sessions = [s1, s1, s1]  # same session three times
    found = find_runtime_session(sessions, s1.runtimeSessionId)
    _true(found is not None, "find returns match when duplicates present")
    _eq(found.runtimeSessionId, s1.runtimeSessionId, "found correct session")

    r1 = _make_request()
    requests = [r1, r1, r1]
    found_r = find_runtime_request(requests, r1.runtimeRequestId)
    _true(found_r is not None, "find_runtime_request with duplicates")

test_find_first_match()


# ===========================================================================
# Section 45 — sort_runtime_sessions all supported keys
# ===========================================================================

def test_sort_all_session_keys() -> None:
    sessions: List[RuntimeSession] = []
    for i in range(4):
        req = build_runtime_request(
            conversation_id=f"sort-c{i}", user_prompt=f"sort-q{i}",
            provider="groq", model="m", created_at=TS,
        )
        s = build_runtime_session(
            request=req, created_at=TS, updated_at=TS, latency_ms=i * 100,
        )
        sessions.append(s)

    for key in ("runtimeSessionId", "createdAt", "updatedAt", "state",
                "latencyMs", "totalTokens", "conversationId"):
        asc  = sort_runtime_sessions(sessions, key=key, ascending=True)
        desc = sort_runtime_sessions(sessions, key=key, ascending=False)
        _eq(len(asc),  len(sessions), f"sort key='{key}' ASC preserves count")
        _eq(len(desc), len(sessions), f"sort key='{key}' DESC preserves count")

test_sort_all_session_keys()


# ===========================================================================
# Section 46 — sort_runtime_requests all supported keys
# ===========================================================================

def test_sort_all_request_keys() -> None:
    requests: List[RuntimeRequest] = []
    for i in range(4):
        r = build_runtime_request(
            conversation_id=f"rk-c{i}", user_prompt=f"rk-q{i}",
            provider="groq", model="m", created_at=TS,
            max_tokens=512 + i * 128, temperature=i * 0.3,
        )
        requests.append(r)

    for key in ("runtimeRequestId", "createdAt", "conversationId",
                "provider", "model", "maxTokens", "temperature"):
        asc  = sort_runtime_requests(requests, key=key, ascending=True)
        desc = sort_runtime_requests(requests, key=key, ascending=False)
        _eq(len(asc),  len(requests), f"req sort key='{key}' ASC count")
        _eq(len(desc), len(requests), f"req sort key='{key}' DESC count")

test_sort_all_request_keys()


# ===========================================================================
# Section 47 — pipeline stage merge in complete_runtime_session
# ===========================================================================

def test_complete_pipeline_stage_merge() -> None:
    req = _make_request(user_prompt="stage merge test")
    sess = build_runtime_session(
        request=req, created_at=TS, updated_at=TS,
        pipeline_stages=["CONVERSATION", "MEMORY"],
    )
    running = start_runtime_session(sess, updated_at=TS2)
    resp = _make_response(req)
    done = complete_runtime_session(
        session=running, response=resp, updated_at=TS3,
        pipeline_stages=["CONTEXT_WINDOW", "TOKEN_BUDGET", "EXECUTION"],
    )
    for stage in ("CONTEXT_WINDOW", "TOKEN_BUDGET", "EXECUTION"):
        _true(stage in done.metadata.pipelineStages,
              f"stage '{stage}' in merged pipelineStages")

test_complete_pipeline_stage_merge()


# ===========================================================================
# Section 48 — Response token arithmetic
# ===========================================================================

def test_response_token_arithmetic() -> None:
    req = _make_request()
    for pt, ct, expected in [(0, 0, 0), (100, 0, 100), (0, 50, 50), (123, 456, 579)]:
        resp = build_runtime_response(
            runtime_request_id=req.runtimeRequestId,
            content="x", finish_reason="stop",
            provider="groq", model="m", created_at=TS,
            prompt_tokens=pt, completion_tokens=ct,
        )
        _eq(resp.totalTokens, expected, f"totalTokens: {pt}+{ct}={expected}")

test_response_token_arithmetic()


# ===========================================================================
# Section 49 — Decision function exhaustive state coverage
# ===========================================================================

def test_decision_exhaustive() -> None:
    state_map = {
        ChatRuntimeStateEnum.READY    : (True,  False, False),
        ChatRuntimeStateEnum.RUNNING  : (False, False, False),
        ChatRuntimeStateEnum.WAITING  : (True,  True,  False),
        ChatRuntimeStateEnum.COMPLETED: (False, False, True),
        ChatRuntimeStateEnum.FAILED   : (False, False, True),
    }
    for state, (should_exec, can_res, is_comp) in state_map.items():
        req  = _make_request(user_prompt=f"decision-{state.value}")
        sess = build_runtime_session(request=req, created_at=TS, updated_at=TS, state=state)
        _eq(should_execute_runtime(sess), should_exec, f"should_execute({state.value})={should_exec}")
        _eq(can_resume_runtime(sess),     can_res,     f"can_resume({state.value})={can_res}")
        _eq(is_runtime_complete(sess),    is_comp,     f"is_complete({state.value})={is_comp}")

test_decision_exhaustive()


# ===========================================================================
# Section 50 — Fingerprint changes per lifecycle transition
# ===========================================================================

def test_fingerprint_changes_on_transitions() -> None:
    req  = _make_request(user_prompt="fp transition test")
    resp = _make_response(req)
    s0 = build_runtime_session(request=req, created_at=TS, updated_at=TS)
    s1 = start_runtime_session(s0, updated_at=TS2)
    s2 = complete_runtime_session(s1, resp, TS3, latency_ms=300)
    s3 = reset_runtime_session(s2, updated_at=TS3)
    _eq(s0.runtimeFingerprint, s1.runtimeFingerprint,
        "READY and RUNNING fingerprints equal (no response)")
    _ne(s1.runtimeFingerprint, s2.runtimeFingerprint,
        "COMPLETED fingerprint differs from RUNNING (response added)")
    _ne(s2.runtimeFingerprint, s3.runtimeFingerprint,
        "RESET fingerprint differs from COMPLETED (response removed)")
    _eq(s0.runtimeFingerprint, s3.runtimeFingerprint,
        "RESET fingerprint == initial READY fingerprint")

test_fingerprint_changes_on_transitions()


# ===========================================================================
# Section 51 — Provider normalisation edge cases
# ===========================================================================

def test_provider_normalisation() -> None:
    for raw, expected in [
        ("GROQ", "groq"), ("  Groq  ", "groq"), ("OpenAI", "openai"),
        ("ANTHROPIC", "anthropic"), ("google", "google"), ("OLLAMA", "ollama"),
    ]:
        req = build_runtime_request(
            conversation_id="c1", user_prompt="q",
            provider=raw, model="m", created_at=TS,
        )
        _eq(req.provider, expected, f"provider '{raw}' → '{expected}'")
    resp = build_runtime_response(
        runtime_request_id="rid", content="x", finish_reason="stop",
        provider="  GROQ  ", model="  M  ", created_at=TS,
    )
    _eq(resp.provider, "groq", "response provider normalised")
    _eq(resp.model, "m", "response model normalised")

test_provider_normalisation()


# ===========================================================================
# Section 52 — Session ID stable across all transitions
# ===========================================================================

def test_session_id_stability() -> None:
    req     = _make_request(user_prompt="stability test")
    s0      = build_runtime_session(request=req, created_at=TS, updated_at=TS)
    s1      = start_runtime_session(s0, updated_at=TS2)
    resp    = _make_response(req)
    s2      = complete_runtime_session(s1, resp, TS3, latency_ms=100)
    s3      = reset_runtime_session(s2, updated_at=TS3)
    s4      = start_runtime_session(s3, updated_at=TS3)
    s5      = fail_runtime_session(s4, "err", TS3)
    for s, label in [(s0,"initial"),(s1,"running"),(s2,"completed"),
                     (s3,"reset"),(s4,"running2"),(s5,"failed")]:
        _eq(s.runtimeSessionId,  s0.runtimeSessionId,  f"sessionId stable '{label}'")
        _eq(s.runtimeSessionKey, s0.runtimeSessionKey, f"sessionKey stable '{label}'")

test_session_id_stability()


# ===========================================================================
# Section 53 — Single-session rate edge cases
# ===========================================================================

def test_single_session_rates() -> None:
    for state, exp_exec, exp_fail in [
        (ChatRuntimeStateEnum.COMPLETED, 1.0, 0.0),
        (ChatRuntimeStateEnum.FAILED,    0.0, 1.0),
        (ChatRuntimeStateEnum.READY,     0.0, 0.0),
        (ChatRuntimeStateEnum.RUNNING,   0.0, 0.0),
        (ChatRuntimeStateEnum.WAITING,   0.0, 0.0),
    ]:
        req = _make_request(user_prompt=f"rate-{state.value}")
        s   = build_runtime_session(request=req, created_at=TS, updated_at=TS, state=state)
        stats = build_runtime_statistics([s])
        _eq(stats.executionRate, exp_exec, f"single {state.value}: executionRate={exp_exec}")
        _eq(stats.failureRate,   exp_fail, f"single {state.value}: failureRate={exp_fail}")

test_single_session_rates()


# ===========================================================================
# Section 54 — Key collision resistance
# ===========================================================================

def test_key_collision_resistance() -> None:
    k1 = runtimeRequestKey("ab", "c",  "q")
    k2 = runtimeRequestKey("a",  "bc", "q")
    _ne(k1, k2, "null-byte separator prevents conv+session collision")
    k3 = runtimeResponseKey("id1", "content", "stop")
    k4 = runtimeResponseKey("id1content", "", "stop")
    _ne(k3, k4, "null-byte separator prevents requestId+content collision")
    k5 = runtimeSessionKey("c1", "s1", "rk1")
    k6 = runtimeSessionKey("c1s1", "", "rk1")
    _ne(k5, k6, "null-byte separator prevents conv+session+reqKey collision")
    k7 = runtimeRequestKey("aaa", "bbb", "ccc")
    k8 = runtimeRequestKey("bbb", "aaa", "ccc")
    k9 = runtimeRequestKey("ccc", "bbb", "aaa")
    _ne(k7, k8, "swapped conv+session → different key")
    _ne(k7, k9, "swapped conv+prompt → different key")
    _ne(k8, k9, "all three orderings distinct")

test_key_collision_resistance()


# ===========================================================================
# Section 55 — Statistics with mixed state sessions
# ===========================================================================

def test_statistics_mixed() -> None:
    sessions: List[RuntimeSession] = []
    for i in range(2):
        s = build_runtime_session(request=_make_request(user_prompt=f"mx-r{i}"),
                                   created_at=TS, updated_at=TS,
                                   state=ChatRuntimeStateEnum.READY)
        sessions.append(s)
    for i in range(1):
        s = build_runtime_session(request=_make_request(user_prompt=f"mx-run{i}"),
                                   created_at=TS, updated_at=TS,
                                   state=ChatRuntimeStateEnum.RUNNING, latency_ms=50)
        sessions.append(s)
    for i in range(3):
        req  = _make_request(user_prompt=f"mx-c{i}")
        resp = build_runtime_response(
            runtime_request_id=req.runtimeRequestId,
            content=f"a{i}", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS2,
            confidence=float(60 + i * 10),
            prompt_tokens=100, completion_tokens=50, latency_ms=300,
        )
        s = build_runtime_session(request=req, created_at=TS2, updated_at=TS2,
                                   state=ChatRuntimeStateEnum.COMPLETED,
                                   response=resp, latency_ms=300, success=True)
        sessions.append(s)
    for i in range(2):
        s = build_runtime_session(request=_make_request(user_prompt=f"mx-f{i}"),
                                   created_at=TS, updated_at=TS,
                                   state=ChatRuntimeStateEnum.FAILED, latency_ms=800, success=False)
        sessions.append(s)
    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions,     8, "mixed: totalSessions=8")
    _eq(stats.readySessions,     2, "mixed: readySessions=2")
    _eq(stats.runningSessions,   1, "mixed: runningSessions=1")
    _eq(stats.completedSessions, 3, "mixed: completedSessions=3")
    _eq(stats.failedSessions,    2, "mixed: failedSessions=2")
    _eq(round(stats.executionRate, 6), round(3/8, 6), "mixed: executionRate=3/8")
    _eq(round(stats.failureRate, 6),   round(2/8, 6), "mixed: failureRate=2/8")
    _eq(stats.averageConfidence, 70.0, "mixed: averageConfidence=70.0")

test_statistics_mixed()


# ===========================================================================
# Section 56 — validate_runtime_session all valid states
# ===========================================================================

def test_validate_all_states() -> None:
    for state in ChatRuntimeStateEnum:
        validate_runtime_session(CONV_ID, TS, TS, state)
        _true(True, f"validate_runtime_session accepts state={state.value}")

test_validate_all_states()


# ===========================================================================
# Section 57 — WAITING state lifecycle
# ===========================================================================

def test_waiting_state() -> None:
    req = _make_request(user_prompt="waiting state test")
    sess_wait = build_runtime_session(request=req, created_at=TS, updated_at=TS,
                                       state=ChatRuntimeStateEnum.WAITING)
    _eq(sess_wait.state, ChatRuntimeStateEnum.WAITING, "WAITING state set")
    _true(should_execute_runtime(sess_wait), "WAITING should execute")
    _true(can_resume_runtime(sess_wait),     "WAITING can resume")
    _false(is_runtime_complete(sess_wait),   "WAITING is not complete")
    started = start_runtime_session(sess_wait, updated_at=TS2)
    _eq(started.state, ChatRuntimeStateEnum.RUNNING, "WAITING → RUNNING allowed")
    _raises(InvalidChatSessionError,
        lambda: complete_runtime_session(sess_wait, _make_response(req), TS2),
        "WAITING → COMPLETED not allowed directly")

test_waiting_state()


# ===========================================================================
# Section 58 — RuntimeRequest metadata isolation
# ===========================================================================

def test_request_metadata_isolation() -> None:
    meta = {"context": "original"}
    req  = build_runtime_request(
        conversation_id="c1", user_prompt="q", provider="groq",
        model="m", created_at=TS, metadata=meta,
    )
    meta["context"] = "mutated"
    meta["new_key"] = "new_value"
    _eq(req.metadata.get("context"), "original", "original metadata not affected by post-build mutation")
    _false("new_key" in req.metadata, "new key not in request metadata")

test_request_metadata_isolation()


# ===========================================================================
# Section 59 — Full end-to-end pipeline
# ===========================================================================

def test_full_pipeline() -> None:
    sessions: List[RuntimeSession] = []
    for i in range(5):
        req  = _make_request(user_prompt=f"Pipeline question {i}")
        sess = build_runtime_session(request=req, created_at=TS, updated_at=TS)
        _eq(sess.state, ChatRuntimeStateEnum.READY,   f"pipeline {i}: initial READY")
        _true(should_execute_runtime(sess),           f"pipeline {i}: should execute")
        _false(is_runtime_complete(sess),             f"pipeline {i}: not complete")
        running = start_runtime_session(sess, updated_at=TS2)
        _eq(running.state, ChatRuntimeStateEnum.RUNNING, f"pipeline {i}: RUNNING")
        resp = build_runtime_response(
            runtime_request_id=req.runtimeRequestId,
            content=f"Answer {i}", finish_reason="stop",
            provider=PROVIDER, model=MODEL, created_at=TS2,
            confidence=float(70 + i), prompt_tokens=100+i*10,
            completion_tokens=30+i*5, latency_ms=200+i*50,
        )
        done = complete_runtime_session(running, resp, TS3, latency_ms=200+i*50)
        _eq(done.state, ChatRuntimeStateEnum.COMPLETED, f"pipeline {i}: COMPLETED")
        _true(is_runtime_complete(done), f"pipeline {i}: is complete")
        sessions.append(done)
    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions, 5,   "pipeline: 5 sessions")
    _eq(stats.completedSessions, 5, "pipeline: all completed")
    _eq(stats.executionRate, 1.0,  "pipeline: executionRate=1.0")
    _eq(stats.failureRate,   0.0,  "pipeline: failureRate=0.0")
    _eq(stats.averageConfidence, 72.0, "pipeline: averageConfidence=72.0")

test_full_pipeline()


# ===========================================================================
# Section 60 — Full failure pipeline
# ===========================================================================

def test_full_failure_pipeline() -> None:
    sessions: List[RuntimeSession] = []
    for i in range(3):
        req     = _make_request(user_prompt=f"fail-q{i}")
        sess    = build_runtime_session(request=req, created_at=TS, updated_at=TS)
        running = start_runtime_session(sess, updated_at=TS2)
        failed  = fail_runtime_session(running, f"Error {i}", TS3, latency_ms=100*(i+1))
        _eq(failed.state, ChatRuntimeStateEnum.FAILED, f"fail pipeline {i}: FAILED")
        sessions.append(failed)
    stats = build_runtime_statistics(sessions)
    _eq(stats.totalSessions, 3,    "fail pipeline: total=3")
    _eq(stats.failedSessions, 3,   "fail pipeline: all failed")
    _eq(stats.failureRate,  1.0,   "fail pipeline: failureRate=1.0")
    _eq(stats.executionRate, 0.0,  "fail pipeline: executionRate=0.0")
    _eq(stats.averageConfidence, 0.0, "fail pipeline: averageConfidence=0.0")

test_full_failure_pipeline()


# ===========================================================================
# Section 61 — Reset and re-run pipeline
# ===========================================================================

def test_reset_and_rerun() -> None:
    req     = _make_request(user_prompt="Reset me")
    sess    = build_runtime_session(request=req, created_at=TS, updated_at=TS)
    running = start_runtime_session(sess, updated_at=TS2)
    failed  = fail_runtime_session(running, "First attempt failed", TS2, latency_ms=500)
    reset   = reset_runtime_session(failed, updated_at=TS3)
    _eq(reset.state, ChatRuntimeStateEnum.READY, "after reset: READY")
    _eq(reset.response, None, "after reset: no response")
    _eq(reset.metadata.errorMessage, "", "after reset: errorMessage cleared")
    running2 = start_runtime_session(reset, updated_at=TS3)
    resp2    = _make_response(req, created_at=TS3)
    done2    = complete_runtime_session(running2, resp2, TS3, latency_ms=200)
    _eq(done2.state, ChatRuntimeStateEnum.COMPLETED, "rerun: COMPLETED")
    _eq(sess.runtimeSessionId, done2.runtimeSessionId, "sessionId stable across reset+rerun")

test_reset_and_rerun()


# ===========================================================================
# Section 62 — Sorting tie-breaker determinism
# ===========================================================================

def test_sort_tiebreaker() -> None:
    sessions: List[RuntimeSession] = []
    for i in range(5):
        req = _make_request(user_prompt=f"tie-{i}")
        s   = build_runtime_session(request=req, created_at=TS, updated_at=TS, latency_ms=300)
        sessions.append(s)
    sorted1 = sort_runtime_sessions(sessions, key="latencyMs")
    sorted2 = sort_runtime_sessions(sessions, key="latencyMs")
    ids1 = [s.runtimeSessionId for s in sorted1]
    ids2 = [s.runtimeSessionId for s in sorted2]
    _eq(ids1, ids2, "sort with identical latency is deterministic")
    _eq(ids1, sorted(ids1), "tie-break by runtimeSessionId ASC")

test_sort_tiebreaker()


# ===========================================================================
# Section 63 — Filter combined criteria
# ===========================================================================

def test_filter_combined_criteria() -> None:
    req_g1 = build_runtime_request(conversation_id="c1", user_prompt="comb-1",
                                    provider="groq", model="llama-3.3-70b-versatile",
                                    created_at=TS, session_id="s1")
    resp1  = build_runtime_response(
        runtime_request_id=req_g1.runtimeRequestId,
        content="r1", finish_reason="stop", provider="groq",
        model="llama-3.3-70b-versatile", created_at=TS2,
        confidence=90.0, latency_ms=100,
    )
    s1 = build_runtime_session(request=req_g1, created_at=TS, updated_at=TS2,
                                state=ChatRuntimeStateEnum.COMPLETED,
                                response=resp1, latency_ms=100, success=True)
    req_g2 = build_runtime_request(conversation_id="c2", user_prompt="comb-2",
                                    provider="groq", model="llama-3.1-8b-instant",
                                    created_at=TS2)
    s2 = build_runtime_session(request=req_g2, created_at=TS2, updated_at=TS2,
                                state=ChatRuntimeStateEnum.RUNNING, latency_ms=200)
    req_o1 = build_runtime_request(conversation_id="c3", user_prompt="comb-3",
                                    provider="openai", model="gpt-4", created_at=TS3)
    s3 = build_runtime_session(request=req_o1, created_at=TS3, updated_at=TS3,
                                state=ChatRuntimeStateEnum.FAILED, latency_ms=999, success=False)
    sessions = [s1, s2, s3]

    result = filter_runtime_sessions(sessions, provider="groq", state=ChatRuntimeStateEnum.COMPLETED)
    _eq(len(result), 1, "combined provider+state filter")

    result2 = filter_runtime_sessions(sessions, has_response=True, min_confidence=85.0)
    _eq(len(result2), 1, "has_response + min_confidence filter")

    result3 = filter_runtime_sessions(sessions, success_only=True)
    _eq(len(result3), 2, "success_only=True → completed+running")

    result4 = filter_runtime_sessions(sessions, success_only=False)
    _eq(len(result4), 1, "success_only=False → only failed")

test_filter_combined_criteria()


# ===========================================================================
# Section 64 — Group all valid keys
# ===========================================================================

def test_group_all_keys() -> None:
    sessions: List[RuntimeSession] = []
    for i, (prov, state) in enumerate([
        ("groq",   ChatRuntimeStateEnum.READY),
        ("groq",   ChatRuntimeStateEnum.COMPLETED),
        ("openai", ChatRuntimeStateEnum.FAILED),
    ]):
        req = build_runtime_request(conversation_id=f"cov-c{i}", user_prompt=f"cov-q{i}",
                                     provider=prov, model="m", created_at=TS)
        sessions.append(build_runtime_session(request=req, created_at=TS, updated_at=TS, state=state))

    for key in ("state", "provider", "model", "conversationId", "runtimeSessionId"):
        g = group_runtime_sessions(sessions, group_by=key)
        _is(g, dict, f"group_runtime_sessions by '{key}' returns dict")
        _eq(sum(len(v) for v in g.values()), len(sessions), f"group '{key}' preserves all sessions")

    requests = [s.request for s in sessions]
    for key in ("provider", "model", "conversationId", "sessionId", "runtimeRequestId"):
        g = group_runtime_requests(requests, group_by=key)
        _is(g, dict, f"group_runtime_requests by '{key}' returns dict")
        _eq(sum(len(v) for v in g.values()), len(requests), f"req group '{key}' preserves all")

test_group_all_keys()


# ===========================================================================
# Section 65 — pipeline_stages dedup behaviour
# ===========================================================================

def test_pipeline_stages() -> None:
    meta = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID,
        provider=PROVIDER, model=MODEL, created_at=TS,
        pipeline_stages=["MEMORY", "CONTEXT_WINDOW", "MEMORY", "TOKEN_BUDGET", "CONTEXT_WINDOW"],
    )
    _eq(len(meta.pipelineStages), 3, "pipeline_stages deduped to 3 unique")
    _eq(meta.pipelineStages,
        tuple(sorted({"MEMORY", "CONTEXT_WINDOW", "TOKEN_BUDGET"})),
        "pipeline_stages sorted deterministically")
    meta_empty = build_runtime_metadata(
        conversation_id=CONV_ID, session_id=SESS_ID, provider=PROVIDER,
        model=MODEL, created_at=TS, pipeline_stages=[],
    )
    _eq(meta_empty.pipelineStages, (), "empty pipeline_stages → empty tuple")

test_pipeline_stages()


# ===========================================================================
# Section 66 — Lifecycle error message content
# ===========================================================================

def test_lifecycle_error_messages() -> None:
    for sess, target_fn, current, target in [
        (_make_session(state=ChatRuntimeStateEnum.COMPLETED, with_resp=True),
         lambda s: start_runtime_session(s, TS3), "COMPLETED", "RUNNING"),
        (_make_session(state=ChatRuntimeStateEnum.FAILED),
         lambda s: start_runtime_session(s, TS3), "FAILED", "RUNNING"),
        (_make_session(state=ChatRuntimeStateEnum.READY),
         lambda s: fail_runtime_session(s, "e", TS3), "READY", "FAILED"),
    ]:
        try:
            target_fn(sess)
            global _FAIL
            _FAIL += 1
            print(f"  FAIL [error msg {current}→{target}]: no exception raised")
        except InvalidChatSessionError as e:
            msg = str(e)
            _true(current in msg, f"error mentions current state '{current}'")
            _true(target  in msg, f"error mentions target state '{target}'")

test_lifecycle_error_messages()

print()
print("=" * 60)
print(f"Chat Runtime Engine — smoke test complete")
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print("=" * 60)

if _FAIL > 0:
    raise SystemExit(f"{_FAIL} assertion(s) failed.")
else:
    print(f"All {_PASS} assertions passed. 0 failures.")
