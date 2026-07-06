"""
Smoke Test — Groq Streaming Engine
=====================================
Phase A4.2.2 — Verifies every model, builder, parser, metric calculator,
and error handler in services/groq_streaming_service.py.

Run:
    python smoke_test_groq_streaming_engine.py
Expected: 350+/350 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. All streaming is simulated via raw SSE line lists.
- Same inputs → same outputs (fully deterministic).
- Chunk ordering: chunks assembled in sequenceNumber ASC regardless of input order.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

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

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.groq_streaming_service import (
    # Exceptions
    GroqStreamError, MalformedChunkError, DuplicateChunkError,
    InvalidSequenceError, InvalidFinishReasonError, StreamInterruptedError,
    StreamTimeoutError, MissingDeltaError,
    # Models
    GroqStreamChunk, GroqStreamState, GroqStreamingMetadata, GroqStreamingResult,
    # Builders
    build_stream_chunk, build_stream_state,
    build_streaming_metadata, build_streaming_result,
    # Streaming functions
    parse_stream_chunk, append_chunk, finalize_stream, reset_stream,
    stream_to_response,
    # Constants
    GROQ_STREAMING_ENGINE_VERSION,
    # Internals
    _sha256_32, _uuid5_stream, _normalise_finish_reason,
)
from services.groq_provider_service import (
    build_message, build_request as build_groq_request,
    GroqRequest, GroqResponse,
)
from core.constants import GROQ_STREAMING_ENGINE_VERSION as CONST_STREAM_VERSION

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS  = "2026-06-30T12:00:00Z"
_M70 = "llama-3.3-70b-versatile"
_M8  = "llama-3.1-8b-instant"

_MSGS = [
    build_message("system", "You are a forensic analyst."),
    build_message("user",   "Summarise the attack chain."),
]
_REQ = build_groq_request(_M70, _MSGS, _TS, temperature=0.0, top_p=1.0, max_tokens=512)
_SID = "test-stream-001"


# ===========================================================================
# §1  Engine version
# ===========================================================================
print("§1  Engine version ...")
_eq(GROQ_STREAMING_ENGINE_VERSION, "groq-streaming-v1", "engine version value")
_eq(CONST_STREAM_VERSION, GROQ_STREAMING_ENGINE_VERSION, "core.constants matches service")
_is(GROQ_STREAMING_ENGINE_VERSION, str, "engine version is str")
_in("groq-streaming", GROQ_STREAMING_ENGINE_VERSION, "engine version contains groq-streaming")

# ===========================================================================
# §2  _sha256_32 and _uuid5_stream helpers
# ===========================================================================
print("§2  ID helpers ...")
h1 = _sha256_32("abc", "def")
h2 = _sha256_32("abc", "def")
_eq(h1, h2, "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 returns 32 chars")
h3 = _sha256_32("abc", "xyz")
_ne(h1, h3, "different inputs → different sha256_32")
h4 = _sha256_32("def", "abc")
_ne(h1, h4, "different arg order → different sha256_32")

uid1 = _uuid5_stream("key-abc")
uid2 = _uuid5_stream("key-abc")
_eq(uid1, uid2, "_uuid5_stream deterministic")
_eq(len(uid1), 36, "_uuid5_stream returns 36-char UUID")
_in("-", uid1, "_uuid5_stream UUID contains hyphens")
uid3 = _uuid5_stream("key-xyz")
_ne(uid1, uid3, "different keys → different UUIDs")

# ===========================================================================
# §3  _normalise_finish_reason
# ===========================================================================
print("§3  _normalise_finish_reason ...")
_assert(_normalise_finish_reason(None) is None, "None → None")
_assert(_normalise_finish_reason("") is None, "empty string → None")
_assert(_normalise_finish_reason("  ") is None, "whitespace → None")
_assert(_normalise_finish_reason("null") is None, "'null' string → None")
_assert(_normalise_finish_reason("NULL") is None, "'NULL' string → None")
_eq(_normalise_finish_reason("stop"),           "stop",           "'stop' preserved")
_eq(_normalise_finish_reason("length"),         "length",         "'length' preserved")
_eq(_normalise_finish_reason("  stop  "),       "stop",           "whitespace trimmed from finish_reason")
_eq(_normalise_finish_reason("content_filter"), "content_filter", "'content_filter' preserved")

# ===========================================================================
# §4  build_stream_chunk() — basic construction
# ===========================================================================
print("§4  build_stream_chunk() ...")
chunk = build_stream_chunk(_SID, 0, "Hello", finish_reason=None)
_is(chunk, GroqStreamChunk, "returns GroqStreamChunk")
_eq(chunk.sequenceNumber, 0,       "sequenceNumber=0")
_eq(chunk.content,        "Hello", "content set")
_assert(chunk.finishReason is None, "finishReason=None for intermediate chunk")
_eq(len(chunk.chunkId),   36,      "chunkId is UUID (36 chars)")
_in("-", chunk.chunkId,            "chunkId contains hyphens")
_gt(chunk.receivedAt,     0,       "receivedAt is positive monotonic ms")

# With finish_reason
chunk_fr = build_stream_chunk(_SID, 5, "", finish_reason="stop")
_eq(chunk_fr.finishReason, "stop", "finishReason='stop' stored")
_eq(chunk_fr.content, "",          "empty content allowed")

# Deterministic chunkId — same inputs → same chunkId
c1 = build_stream_chunk(_SID, 0, "Hello")
c2 = build_stream_chunk(_SID, 0, "Hello")
_eq(c1.chunkId, c2.chunkId, "same inputs → same chunkId")

# Different seq → different chunkId
c3 = build_stream_chunk(_SID, 1, "Hello")
_ne(c1.chunkId, c3.chunkId, "different seq → different chunkId")

# Different content → different chunkId
c4 = build_stream_chunk(_SID, 0, "World")
_ne(c1.chunkId, c4.chunkId, "different content → different chunkId")

# Different stream_id → different chunkId
c5 = build_stream_chunk("other-stream", 0, "Hello")
_ne(c1.chunkId, c5.chunkId, "different stream_id → different chunkId")

# Immutability
try:
    chunk.content = "changed"   # type: ignore
    _assert(False, "GroqStreamChunk should be frozen")
except Exception:
    _assert(True, "GroqStreamChunk is immutable")

# Negative sequenceNumber raises
try:
    build_stream_chunk(_SID, -1, "x")
    _assert(False, "negative sequenceNumber should raise")
except InvalidSequenceError:
    _assert(True, "negative sequenceNumber raises InvalidSequenceError")

# Zero sequenceNumber is valid
c_zero = build_stream_chunk(_SID, 0, "x")
_eq(c_zero.sequenceNumber, 0, "sequenceNumber=0 is valid")

# Invalid finish_reason raises
try:
    build_stream_chunk(_SID, 0, "x", finish_reason="invalid_reason_xyz")
    _assert(False, "invalid finish_reason should raise")
except InvalidFinishReasonError:
    _assert(True, "invalid finish_reason raises InvalidFinishReasonError")

# All valid finish reasons accepted
for fr in ("stop", "length", "content_filter", "tool_calls"):
    c_fr = build_stream_chunk(_SID, 0, "", finish_reason=fr)
    _eq(c_fr.finishReason, fr, f"finish_reason='{fr}' accepted")

# ===========================================================================
# §5  build_stream_state() — construction and ordering
# ===========================================================================
print("§5  build_stream_state() ...")
chunks_ordered = [
    build_stream_chunk(_SID, 0, "The "),
    build_stream_chunk(_SID, 1, "attacker "),
    build_stream_chunk(_SID, 2, "used DNS."),
]
state = build_stream_state(
    request_id    = _REQ.requestId,
    chunks        = chunks_ordered,
    completed     = True,
    finish_reason = "stop",
    started_at    = 1000,
    completed_at  = 2500,
)
_is(state, GroqStreamState, "returns GroqStreamState")
_eq(len(state.chunkId) if hasattr(state, 'chunkId') else 36, 36, "state has UUID-like streamId")
_eq(len(state.streamId), 36, "streamId is UUID (36 chars)")
_in("-", state.streamId, "streamId contains hyphens")
_eq(state.requestId, _REQ.requestId, "requestId linked")
_eq(state.totalChunks, 3, "totalChunks=3")
_eq(state.accumulatedContent, "The attacker used DNS.", "content accumulated correctly")
_assert(state.completed, "completed=True")
_eq(state.finishReason, "stop", "finishReason='stop'")
_eq(state.startedAt, 1000, "startedAt preserved")
_eq(state.completedAt, 2500, "completedAt preserved")
_eq(state.engineVersion, GROQ_STREAMING_ENGINE_VERSION, "engineVersion set")
_eq(len(state.chunks), 3, "chunks tuple has 3 elements")
_eq(state.chunks[0].sequenceNumber, 0, "chunks[0] is seq=0")
_eq(state.chunks[1].sequenceNumber, 1, "chunks[1] is seq=1")
_eq(state.chunks[2].sequenceNumber, 2, "chunks[2] is seq=2")

# Out-of-order chunks — must be reassembled ASC
chunks_ooo = [
    build_stream_chunk(_SID, 2, "used DNS."),
    build_stream_chunk(_SID, 0, "The "),
    build_stream_chunk(_SID, 1, "attacker "),
]
state_ooo = build_stream_state(
    request_id = _REQ.requestId,
    chunks     = chunks_ooo,
)
_eq(state_ooo.chunks[0].sequenceNumber, 0, "out-of-order: chunks[0] seq=0 after sorting")
_eq(state_ooo.chunks[1].sequenceNumber, 1, "out-of-order: chunks[1] seq=1 after sorting")
_eq(state_ooo.chunks[2].sequenceNumber, 2, "out-of-order: chunks[2] seq=2 after sorting")
_eq(state_ooo.accumulatedContent, "The attacker used DNS.", "out-of-order: content assembled correctly")

# Deterministic streamId — same requestId always yields same streamId
state_a = build_stream_state(_REQ.requestId, [])
state_b = build_stream_state(_REQ.requestId, [])
_eq(state_a.streamId, state_b.streamId, "same requestId → same streamId")

# Different requestId → different streamId
from services.groq_provider_service import build_request as build_groq_req2
_REQ2 = build_groq_req2(_M8, _MSGS, _TS)
state_c = build_stream_state(_REQ2.requestId, [])
_ne(state_a.streamId, state_c.streamId, "different requestId → different streamId")

# Empty chunks
state_empty = build_stream_state(_REQ.requestId, [])
_eq(state_empty.totalChunks, 0, "empty: totalChunks=0")
_eq(state_empty.accumulatedContent, "", "empty: accumulatedContent is empty string")
_assert(not state_empty.completed, "empty: not completed by default")
_assert(state_empty.finishReason is None, "empty: finishReason is None")

# Immutability
try:
    state.accumulatedContent = "changed"  # type: ignore
    _assert(False, "GroqStreamState should be frozen")
except Exception:
    _assert(True, "GroqStreamState is immutable")

# Negative startedAt / completedAt clamped to 0
state_neg = build_stream_state(_REQ.requestId, [], started_at=-100, completed_at=-200)
_eq(state_neg.startedAt, 0, "negative startedAt clamped to 0")
_eq(state_neg.completedAt, 0, "negative completedAt clamped to 0")

# ===========================================================================
# §6  build_streaming_metadata()
# ===========================================================================
print("§6  build_streaming_metadata() ...")

# Build a state with known timing
import time as _time
_t0 = 1_000_000   # fake startedAt ms

chunks_timed = [
    build_stream_chunk(_SID, 0, "Hello "),   # 6 chars
    build_stream_chunk(_SID, 1, "world"),    # 5 chars
]
# Patch receivedAt on fake chunks by rebuilding with fixed IDs
# (we test metric calculations using the actual builder)
state_timed = build_stream_state(
    request_id   = _REQ.requestId,
    chunks       = chunks_timed,
    completed    = True,
    finish_reason= "stop",
    started_at   = _t0,
    completed_at = _t0 + 800,
)
meta = build_streaming_metadata(state_timed)
_is(meta, GroqStreamingMetadata, "returns GroqStreamingMetadata")
_eq(meta.chunkCount, 2, "chunkCount=2 (both have content)")
_eq(meta.totalLatencyMs, 800, "totalLatencyMs=800")
_ge(meta.firstTokenLatencyMs, 0, "firstTokenLatencyMs >= 0")
_gt(meta.averageChunkSize, 0.0, "averageChunkSize > 0")
_eq(round(meta.averageChunkSize, 4), round((6 + 5) / 2, 4), "averageChunkSize = (6+5)/2 = 5.5")
_assert(not meta.interrupted, "not interrupted")
_eq(meta.warnings, (), "no warnings by default")

# Immutability
try:
    meta.chunkCount = 99  # type: ignore
    _assert(False, "GroqStreamingMetadata should be frozen")
except Exception:
    _assert(True, "GroqStreamingMetadata is immutable")

# tokensPerSecond > 0 when latency > 0 and content exists
_gt(meta.tokensPerSecond, 0.0, "tokensPerSecond > 0 with content and latency")

# State with no content chunks
state_no_content = build_stream_state(_REQ.requestId, [], completed=True, started_at=_t0, completed_at=_t0+100)
meta_nc = build_streaming_metadata(state_no_content)
_eq(meta_nc.chunkCount, 0, "no content: chunkCount=0")
_eq(meta_nc.averageChunkSize, 0.0, "no content: averageChunkSize=0.0")
_eq(meta_nc.tokensPerSecond, 0.0, "no content: tokensPerSecond=0.0")
_eq(meta_nc.firstTokenLatencyMs, 0, "no content: firstTokenLatencyMs=0")

# interrupted stream
meta_int = build_streaming_metadata(state_timed, interrupted=True, warnings=["Premature EOF"])
_assert(meta_int.interrupted, "interrupted=True stored")
_eq(meta_int.warnings, ("Premature EOF",), "warning stored")

# Warnings deduplication + sort
meta_warn = build_streaming_metadata(
    state_no_content,
    warnings=["B warning", "A warning", "B warning", "  "],
)
_eq(meta_warn.warnings, ("A warning", "B warning"), "warnings deduped and sorted")

# Zero latency — no division error
state_zero_lat = build_stream_state(_REQ.requestId, chunks_timed, completed=True, started_at=0, completed_at=0)
meta_zero = build_streaming_metadata(state_zero_lat)
_eq(meta_zero.tokensPerSecond, 0.0, "zero latency → tokensPerSecond=0.0 (no div/0)")

# ===========================================================================
# §7  build_streaming_result()
# ===========================================================================
print("§7  build_streaming_result() ...")

# Build a minimal GroqResponse to use as fixture
from services.groq_provider_service import build_response as build_groq_resp
_RESP = build_groq_resp(
    request_id        = _REQ.requestId,
    model             = _M70,
    content           = "The attacker used DNS.",
    finish_reason     = "stop",
    created_at        = _TS,
    prompt_tokens     = 20,
    completion_tokens = 6,
    latency_ms        = 800,
)

_state_for_result = build_stream_state(
    request_id    = _REQ.requestId,
    chunks        = chunks_ordered,
    completed     = True,
    finish_reason = "stop",
    started_at    = _t0,
    completed_at  = _t0 + 800,
)
_meta_for_result = build_streaming_metadata(_state_for_result)
result = build_streaming_result(_state_for_result, _RESP, _meta_for_result)

_is(result, GroqStreamingResult, "returns GroqStreamingResult")
_eq(result.state,    _state_for_result, "state preserved")
_eq(result.response, _RESP,            "response preserved")
_eq(result.metadata, _meta_for_result, "metadata preserved")

# Immutability
try:
    result.state = _state_for_result  # type: ignore
    _assert(False, "GroqStreamingResult should be frozen")
except Exception:
    _assert(True, "GroqStreamingResult is immutable")

# Same inputs → same result
result2 = build_streaming_result(_state_for_result, _RESP, _meta_for_result)
_eq(result, result2, "same inputs → same GroqStreamingResult")

# ===========================================================================
# §8  parse_stream_chunk() — SSE parsing
# ===========================================================================
print("§8  parse_stream_chunk() ...")

import json as _json

def _make_sse(content: str, finish_reason=None) -> str:
    data = {"choices": [{"delta": {"content": content}, "finish_reason": finish_reason}]}
    return f"data: {_json.dumps(data)}"

def _make_sse_fr(finish_reason: str) -> str:
    data = {"choices": [{"delta": {}, "finish_reason": finish_reason}]}
    return f"data: {_json.dumps(data)}"

def _make_sse_role() -> str:
    """First chunk from Groq is typically role-only, no content."""
    data = {"choices": [{"delta": {"role": "assistant"}, "finish_reason": None}]}
    return f"data: {_json.dumps(data)}"

# Normal content chunk
sse_hello = _make_sse("Hello")
c_parsed = parse_stream_chunk(sse_hello, _SID, 0)
_is(c_parsed, GroqStreamChunk, "returns GroqStreamChunk for content chunk")
_eq(c_parsed.content, "Hello", "content extracted")
_assert(c_parsed.finishReason is None, "finishReason None for intermediate")
_eq(c_parsed.sequenceNumber, 0, "sequenceNumber=0 set")

# Finish chunk
sse_stop = _make_sse_fr("stop")
c_stop = parse_stream_chunk(sse_stop, _SID, 5)
_is(c_stop, GroqStreamChunk, "returns GroqStreamChunk for finish chunk")
_eq(c_stop.finishReason, "stop", "finishReason='stop' extracted")
_eq(c_stop.sequenceNumber, 5, "sequenceNumber=5 set")

# [DONE] sentinel returns None
c_done = parse_stream_chunk("data: [DONE]", _SID, 10)
_assert(c_done is None, "[DONE] sentinel returns None")

# Blank line returns None
c_blank = parse_stream_chunk("", _SID, 0)
_assert(c_blank is None, "blank line returns None")

# Comment line returns None
c_comment = parse_stream_chunk(": keep-alive", _SID, 0)
_assert(c_comment is None, "SSE comment line returns None")

# Non-data line returns None
c_event = parse_stream_chunk("event: chat", _SID, 0)
_assert(c_event is None, "non-data SSE line returns None")

# Whitespace around [DONE]
c_done_ws = parse_stream_chunk("data: [DONE]  ", _SID, 0)
_assert(c_done_ws is None, "[DONE] with trailing whitespace returns None")

# Role-only chunk (first chunk from Groq) — no content, no crash
c_role = parse_stream_chunk(_make_sse_role(), _SID, 0)
_is(c_role, GroqStreamChunk, "role-only chunk returns GroqStreamChunk")
_eq(c_role.content, "", "role-only chunk has empty content")

# Empty choices list — returns chunk with empty content (some providers)
sse_empty_choices = 'data: {"choices": []}'
c_empty = parse_stream_chunk(sse_empty_choices, _SID, 0)
_is(c_empty, GroqStreamChunk, "empty choices → GroqStreamChunk with empty content")
_eq(c_empty.content, "", "empty choices chunk has empty content")

# Malformed JSON raises MalformedChunkError
try:
    parse_stream_chunk("data: {not valid json}", _SID, 0)
    _assert(False, "malformed JSON should raise")
except MalformedChunkError:
    _assert(True, "malformed JSON raises MalformedChunkError")

# Non-dict JSON raises MalformedChunkError
try:
    parse_stream_chunk('data: ["an", "array"]', _SID, 0)
    _assert(False, "non-dict JSON should raise")
except MalformedChunkError:
    _assert(True, "non-dict JSON raises MalformedChunkError")

# Missing choices key raises MissingDeltaError
try:
    parse_stream_chunk('data: {"model": "llama"}', _SID, 0)
    _assert(False, "missing choices should raise")
except MissingDeltaError:
    _assert(True, "missing choices raises MissingDeltaError")

# Deterministic chunkId from parse — same line + same seq → same chunk
c_det1 = parse_stream_chunk(sse_hello, _SID, 7)
c_det2 = parse_stream_chunk(sse_hello, _SID, 7)
_eq(c_det1.chunkId, c_det2.chunkId, "same SSE line + seq → same chunkId (deterministic)")

# Different seq → different chunkId
c_det3 = parse_stream_chunk(sse_hello, _SID, 8)
_ne(c_det1.chunkId, c_det3.chunkId, "different seq → different chunkId")

# ===========================================================================
# §9  append_chunk() — duplicate detection
# ===========================================================================
print("§9  append_chunk() ...")

base_chunks = [
    build_stream_chunk(_SID, 0, "A"),
    build_stream_chunk(_SID, 1, "B"),
]
new_chunk = build_stream_chunk(_SID, 2, "C")
extended  = append_chunk(base_chunks, new_chunk, _SID)
_eq(len(extended), 3, "append_chunk: length increased to 3")
_eq(extended[2].sequenceNumber, 2, "new chunk appended at end")
_eq(len(base_chunks), 2, "original list not mutated by append_chunk")

# Duplicate raises DuplicateChunkError
dup_chunk = build_stream_chunk(_SID, 1, "duplicate")
try:
    append_chunk(base_chunks, dup_chunk, _SID)
    _assert(False, "duplicate chunk should raise")
except DuplicateChunkError as exc:
    _assert(True, "duplicate chunk raises DuplicateChunkError")
    _in("1", str(exc), "error message mentions sequenceNumber")
    _eq(exc.stream_id, _SID, "exception carries stream_id")

# Append to empty list
first = append_chunk([], build_stream_chunk(_SID, 0, "first"), _SID)
_eq(len(first), 1, "append to empty list → length=1")

# Appending seq=0 after gap is allowed (only seq duplicates rejected)
chunks_gap = [build_stream_chunk(_SID, 0, "x"), build_stream_chunk(_SID, 2, "z")]
ok = append_chunk(chunks_gap, build_stream_chunk(_SID, 1, "y"), _SID)
_eq(len(ok), 3, "gap-fill: append seq=1 between seq=0 and seq=2 works")

# ===========================================================================
# §10  finalize_stream()
# ===========================================================================
print("§10  finalize_stream() ...")
chunks_final = [
    build_stream_chunk(_SID, 0, "DNS "),
    build_stream_chunk(_SID, 1, "tunnelling "),
    build_stream_chunk(_SID, 2, "detected."),
]
state_f, meta_f = finalize_stream(
    chunks        = chunks_final,
    request_id    = _REQ.requestId,
    finish_reason = "stop",
    started_at    = 5000,
    interrupted   = False,
    warnings      = None,
)
_is(state_f, GroqStreamState, "finalize_stream returns GroqStreamState")
_is(meta_f, GroqStreamingMetadata, "finalize_stream returns GroqStreamingMetadata")
_assert(state_f.completed, "finalized state is completed")
_eq(state_f.finishReason, "stop", "finishReason='stop' in finalized state")
_eq(state_f.accumulatedContent, "DNS tunnelling detected.", "content assembled")
_eq(meta_f.chunkCount, 3, "metadata chunkCount=3")
_assert(not meta_f.interrupted, "not interrupted")

# Interrupted stream
state_i, meta_i = finalize_stream(
    chunks        = chunks_final[:2],
    request_id    = _REQ.requestId,
    finish_reason = None,
    started_at    = 5000,
    interrupted   = True,
    warnings      = ["Premature EOF"],
)
_assert(not state_i.completed, "interrupted: completed=False")
_assert(meta_i.interrupted, "interrupted: metadata.interrupted=True")
_in("Premature EOF", meta_i.warnings, "interrupted: warning preserved")

# ===========================================================================
# §11  reset_stream()
# ===========================================================================
print("§11  reset_stream() ...")
empty_list, t0 = reset_stream(_REQ.requestId)
_eq(empty_list, [], "reset_stream returns empty list")
_gt(t0, 0, "reset_stream returns positive startedAt")
_is(empty_list, list, "reset_stream returns list type")

# Two reset calls produce different timestamps (monotonic clock advances)
import time as _time_mod
_time_mod.sleep(0.001)
_, t1 = reset_stream(_REQ.requestId)
_ge(t1, t0, "second reset has equal or later timestamp")

# ===========================================================================
# §12  stream_to_response() — integration with GroqResponse builder
# ===========================================================================
print("§12  stream_to_response() ...")

chunks_resp = [
    build_stream_chunk(_SID, 0, "Attacker "),
    build_stream_chunk(_SID, 1, "pivoted "),
    build_stream_chunk(_SID, 2, "via DNS."),
]
state_resp = build_stream_state(
    request_id    = _REQ.requestId,
    chunks        = chunks_resp,
    completed     = True,
    finish_reason = "stop",
    started_at    = 1000,
    completed_at  = 1500,
)
groq_resp = stream_to_response(state_resp, _REQ, _TS)

_is(groq_resp, GroqResponse, "stream_to_response returns GroqResponse")
_eq(groq_resp.content, "Attacker pivoted via DNS.", "content = accumulated chunks")
_eq(groq_resp.finishReason, "stop", "finishReason='stop' from state")
_eq(groq_resp.requestId, _REQ.requestId, "requestId linked to request")
_eq(groq_resp.createdAt, _TS, "createdAt preserved")
_eq(len(groq_resp.responseId), 36, "responseId is UUID (36 chars)")
_eq(len(groq_resp.responseKey), 32, "responseKey is 32 chars")
_eq(len(groq_resp.responseFingerprint), 32, "responseFingerprint is 32 chars")
_ge(groq_resp.usage.completionTokens, 0, "completionTokens >= 0")
_ge(groq_resp.usage.promptTokens,     0, "promptTokens >= 0")
_eq(groq_resp.usage.latencyMs, 500, "latencyMs = completedAt - startedAt = 500ms")

# Determinism — same state + request → same GroqResponse
groq_resp2 = stream_to_response(state_resp, _REQ, _TS)
_eq(groq_resp.responseId,          groq_resp2.responseId,          "same inputs → same responseId")
_eq(groq_resp.responseKey,         groq_resp2.responseKey,         "same inputs → same responseKey")
_eq(groq_resp.responseFingerprint, groq_resp2.responseFingerprint, "same inputs → same fingerprint")
_eq(groq_resp, groq_resp2, "same inputs → identical GroqResponse")

# Different content → different responseId
chunks_alt = [build_stream_chunk(_SID, 0, "Completely different.")]
state_alt  = build_stream_state(_REQ.requestId, chunks_alt, completed=True, finish_reason="stop", started_at=1000, completed_at=1500)
groq_resp_alt = stream_to_response(state_alt, _REQ, _TS)
_ne(groq_resp.responseId, groq_resp_alt.responseId, "different content → different responseId")

# Default finish_reason when state has None — falls back to "stop"
state_no_fr = build_stream_state(_REQ.requestId, chunks_resp, completed=True, finish_reason=None, started_at=1000, completed_at=1500)
groq_resp_nfr = stream_to_response(state_no_fr, _REQ, _TS)
_eq(groq_resp_nfr.finishReason, "stop", "None finishReason defaults to 'stop'")

# Empty content state
state_empty_c = build_stream_state(_REQ.requestId, [], completed=True, finish_reason="stop", started_at=1000, completed_at=1100)
groq_resp_empty = stream_to_response(state_empty_c, _REQ, _TS)
_eq(groq_resp_empty.content, "", "empty state → empty content in response")
_eq(groq_resp_empty.usage.completionTokens, 0, "empty content → completionTokens=0")

# ===========================================================================
# §13  Out-of-order chunk reassembly — deep verification
# ===========================================================================
print("§13  Out-of-order chunk reassembly ...")

tokens = ["The ", "attacker ", "pivoted ", "via ", "DNS ", "tunnelling."]
# Build chunks in shuffled order
shuffled = [5, 2, 0, 4, 1, 3]
ooo_chunks = [build_stream_chunk(_SID, i, tokens[i]) for i in shuffled]

# Assemble via build_stream_state (sorts internally)
state_ooo2 = build_stream_state(
    request_id = _REQ.requestId,
    chunks     = ooo_chunks,
    completed  = True,
    finish_reason = "stop",
    started_at    = 0,
    completed_at  = 600,
)
expected_content = "".join(tokens)
_eq(state_ooo2.accumulatedContent, expected_content, "out-of-order: content correct after sorting")
for i, chunk in enumerate(state_ooo2.chunks):
    _eq(chunk.sequenceNumber, i, f"out-of-order: chunks[{i}].sequenceNumber={i} after sorting")

# Verify via stream_to_response too
groq_ooo = stream_to_response(state_ooo2, _REQ, _TS)
_eq(groq_ooo.content, expected_content, "out-of-order: stream_to_response produces correct content")

# Deterministic: same shuffled input always → same output
state_ooo3 = build_stream_state(_REQ.requestId, ooo_chunks, completed=True, finish_reason="stop", started_at=0, completed_at=600)
_eq(state_ooo2.accumulatedContent, state_ooo3.accumulatedContent, "out-of-order: deterministic assembly")

# ===========================================================================
# §14  Duplicate chunk handling
# ===========================================================================
print("§14  Duplicate chunk handling ...")

dup_base = [
    build_stream_chunk(_SID, 0, "First."),
    build_stream_chunk(_SID, 1, "Second."),
]
# Attempt to append duplicate seq=0
dup_incoming = build_stream_chunk(_SID, 0, "First again (dup)")
try:
    append_chunk(dup_base, dup_incoming, _SID)
    _assert(False, "duplicate seq=0 should raise DuplicateChunkError")
except DuplicateChunkError as e:
    _assert(True, "duplicate seq=0 raises DuplicateChunkError")
    _eq(e.stream_id, _SID, "DuplicateChunkError carries stream_id")

# Attempt to append duplicate seq=1
dup1 = build_stream_chunk(_SID, 1, "dup")
try:
    append_chunk(dup_base, dup1, _SID)
    _assert(False, "duplicate seq=1 should raise DuplicateChunkError")
except DuplicateChunkError:
    _assert(True, "duplicate seq=1 raises DuplicateChunkError")

# Non-duplicate seq=2 succeeds
ok_chunk = build_stream_chunk(_SID, 2, "Third.")
ok_list  = append_chunk(dup_base, ok_chunk, _SID)
_eq(len(ok_list), 3, "non-duplicate append succeeds → length=3")
_eq(ok_list[2].content, "Third.", "non-duplicate chunk content correct")

# Original list unchanged
_eq(len(dup_base), 2, "original chunk list not mutated after failed duplicate append")

# ===========================================================================
# §15  Malformed chunk rejection
# ===========================================================================
print("§15  Malformed chunk rejection ...")

bad_lines = [
    "data: {invalid",
    "data: not-json-at-all",
    "data: {\"key\": true, \"choices\": ",
    'data: [1, 2, 3]',
]
for bad in bad_lines:
    try:
        parse_stream_chunk(bad, _SID, 0)
        _assert(False, f"malformed line should raise: {bad[:50]!r}")
    except (MalformedChunkError, MissingDeltaError):
        _assert(True, f"malformed line raises appropriate error: {bad[:40]!r}")

# Missing 'choices' key
try:
    parse_stream_chunk('data: {"id": "abc", "model": "llama"}', _SID, 0)
    _assert(False, "missing choices key should raise MissingDeltaError")
except MissingDeltaError:
    _assert(True, "missing choices key raises MissingDeltaError")

# Non-list choices raises MissingDeltaError
try:
    parse_stream_chunk('data: {"choices": "not a list"}', _SID, 0)
    _assert(False, "non-list choices should raise MissingDeltaError")
except MissingDeltaError:
    _assert(True, "non-list choices raises MissingDeltaError")

# ===========================================================================
# §16  Finish reason handling
# ===========================================================================
print("§16  Finish reason handling ...")

# All valid finish reasons pass through correctly
valid_reasons = ["stop", "length", "content_filter", "tool_calls"]
for fr in valid_reasons:
    c = build_stream_chunk(_SID, 0, "", finish_reason=fr)
    _eq(c.finishReason, fr, f"finish_reason='{fr}' round-trips correctly")

# "null" string normalised to None
c_null = build_stream_chunk(_SID, 0, "", finish_reason="null")
_assert(c_null.finishReason is None, "'null' string finish_reason → None")

# Empty finish_reason normalised to None
c_empty_fr = build_stream_chunk(_SID, 0, "", finish_reason="")
_assert(c_empty_fr.finishReason is None, "empty finish_reason → None")

# None finish_reason stays None
c_none_fr = build_stream_chunk(_SID, 0, "", finish_reason=None)
_assert(c_none_fr.finishReason is None, "None finish_reason → None")

# Whitespace-only finish_reason → None
c_ws_fr = build_stream_chunk(_SID, 0, "", finish_reason="   ")
_assert(c_ws_fr.finishReason is None, "whitespace finish_reason → None")

# Invalid finish_reason raises InvalidFinishReasonError
bad_reasons = ["STOP", "halt", "error", "terminate", "finished"]
for bad_fr in bad_reasons:
    try:
        build_stream_chunk(_SID, 0, "", finish_reason=bad_fr)
        _assert(False, f"invalid finish_reason '{bad_fr}' should raise")
    except InvalidFinishReasonError:
        _assert(True, f"invalid finish_reason '{bad_fr}' raises InvalidFinishReasonError")

# Finish reason propagated through finalize_stream → state → response
chunks_fr_test = [build_stream_chunk(_SID, 0, "content"), build_stream_chunk(_SID, 1, "", finish_reason="length")]
state_fr, _ = finalize_stream(
    chunks        = chunks_fr_test,
    request_id    = _REQ.requestId,
    finish_reason = "length",
    started_at    = 0,
)
_eq(state_fr.finishReason, "length", "finish_reason='length' propagated to state")
resp_fr = stream_to_response(state_fr, _REQ, _TS)
_eq(resp_fr.finishReason, "length", "finish_reason='length' propagated to GroqResponse")

# ===========================================================================
# §17  Latency metrics
# ===========================================================================
print("§17  Latency metrics ...")

# Known timing — startedAt=1000, completedAt=2200 → total=1200ms
state_lat = build_stream_state(
    request_id    = _REQ.requestId,
    chunks        = chunks_ordered,
    completed     = True,
    finish_reason = "stop",
    started_at    = 1000,
    completed_at  = 2200,
)
meta_lat = build_streaming_metadata(state_lat)
_eq(meta_lat.totalLatencyMs, 1200, "totalLatencyMs = 2200 - 1000 = 1200ms")

# firstTokenLatencyMs: time from startedAt to first chunk.receivedAt
# (chunks have receivedAt = actual monotonic, so we just verify >= 0)
_ge(meta_lat.firstTokenLatencyMs, 0, "firstTokenLatencyMs >= 0")

# chunkCount counts only content-bearing chunks
chunks_mixed = [
    build_stream_chunk(_SID, 0, ""),        # role chunk, no content
    build_stream_chunk(_SID, 1, "Hello "),  # content
    build_stream_chunk(_SID, 2, "world"),   # content
    build_stream_chunk(_SID, 3, ""),        # finish chunk, no content
]
state_mixed = build_stream_state(_REQ.requestId, chunks_mixed, completed=True, started_at=0, completed_at=300)
meta_mixed  = build_streaming_metadata(state_mixed)
_eq(meta_mixed.chunkCount, 2, "chunkCount=2 (only content-bearing chunks counted)")
_eq(round(meta_mixed.averageChunkSize, 1), 5.5, "averageChunkSize = (6+5)/2 = 5.5")

# tokensPerSecond calculation
# total_chars=11, estimated_tokens=ceiling(11/4)=3, total_seconds=300/1000=0.3
# expected = 3 / 0.3 = 10.0
_gt(meta_mixed.tokensPerSecond, 0.0, "tokensPerSecond > 0 for content with known latency")

# ===========================================================================
# §18  Throughput calculation
# ===========================================================================
print("§18  Throughput calculation ...")

# 400 chars over 1000ms → estimated_tokens = ceiling(400/4) = 100
# throughput = 100 tokens / 1.0 second = 100.0 t/s
big_content = "x" * 400
chunks_big = [build_stream_chunk(_SID, 0, big_content)]
state_big  = build_stream_state(_REQ.requestId, chunks_big, completed=True, started_at=0, completed_at=1000)
meta_big   = build_streaming_metadata(state_big)
_eq(meta_big.chunkCount, 1, "big chunk: chunkCount=1")
_eq(meta_big.averageChunkSize, 400.0, "big chunk: averageChunkSize=400.0")
# estimated_tokens = ceiling(400/4) = 100; 100 / 1.0s = 100.0
_eq(meta_big.tokensPerSecond, 100.0, "throughput: 400 chars / 1.0s = 100.0 t/s")

# 4 chars over 2000ms → tokens=1, throughput=0.5 t/s
chunks_small = [build_stream_chunk(_SID, 0, "abcd")]
state_small  = build_stream_state(_REQ.requestId, chunks_small, completed=True, started_at=0, completed_at=2000)
meta_small   = build_streaming_metadata(state_small)
_eq(meta_small.tokensPerSecond, 0.5, "throughput: 4 chars / 2.0s = 0.5 t/s")

# ===========================================================================
# §19  Serialisation
# ===========================================================================
print("§19  Serialisation ...")

chunk_dict = chunk.model_dump()
_is(chunk_dict, dict, "GroqStreamChunk.model_dump() returns dict")
_in("chunkId",        chunk_dict, "dict has chunkId")
_in("sequenceNumber", chunk_dict, "dict has sequenceNumber")
_in("content",        chunk_dict, "dict has content")
_in("finishReason",   chunk_dict, "dict has finishReason")
_in("receivedAt",     chunk_dict, "dict has receivedAt")

state_dict = state_resp.model_dump()
_is(state_dict, dict, "GroqStreamState.model_dump() returns dict")
_in("streamId",           state_dict, "dict has streamId")
_in("requestId",          state_dict, "dict has requestId")
_in("accumulatedContent", state_dict, "dict has accumulatedContent")
_in("totalChunks",        state_dict, "dict has totalChunks")
_in("completed",          state_dict, "dict has completed")
_in("engineVersion",      state_dict, "dict has engineVersion")
_in("chunks",             state_dict, "dict has chunks")

meta_dict = meta.model_dump()
_is(meta_dict, dict, "GroqStreamingMetadata.model_dump() returns dict")
_in("firstTokenLatencyMs", meta_dict, "dict has firstTokenLatencyMs")
_in("totalLatencyMs",      meta_dict, "dict has totalLatencyMs")
_in("chunkCount",          meta_dict, "dict has chunkCount")
_in("averageChunkSize",    meta_dict, "dict has averageChunkSize")
_in("tokensPerSecond",     meta_dict, "dict has tokensPerSecond")
_in("interrupted",         meta_dict, "dict has interrupted")
_in("warnings",            meta_dict, "dict has warnings")

result_dict = result.model_dump()
_is(result_dict, dict, "GroqStreamingResult.model_dump() returns dict")
_in("state",    result_dict, "dict has state")
_in("response", result_dict, "dict has response")
_in("metadata", result_dict, "dict has metadata")

# JSON serialisable
import json as _json2
try:
    _json2.dumps(chunk_dict)
    _assert(True, "GroqStreamChunk is JSON serialisable")
except Exception:
    _assert(False, "GroqStreamChunk should be JSON serialisable")

try:
    _json2.dumps(meta_dict)
    _assert(True, "GroqStreamingMetadata is JSON serialisable")
except Exception:
    _assert(False, "GroqStreamingMetadata should be JSON serialisable")

# ===========================================================================
# §20  Zero randomness — 5 builds always identical
# ===========================================================================
print("§20  Zero randomness ...")

chunk_ids  = set()
state_sids = set()
resp_ids   = set()

for _ in range(5):
    c = build_stream_chunk(_SID, 3, "test content")
    chunk_ids.add(c.chunkId)

_eq(len(chunk_ids), 1, "zero randomness: 5 chunk builds → identical chunkId")

for _ in range(5):
    s = build_stream_state(_REQ.requestId, [])
    state_sids.add(s.streamId)

_eq(len(state_sids), 1, "zero randomness: 5 state builds → identical streamId")

for _ in range(5):
    s_r = build_stream_state(
        _REQ.requestId,
        [build_stream_chunk(_SID, 0, "text"), build_stream_chunk(_SID, 1, "more")],
        completed=True, finish_reason="stop", started_at=100, completed_at=600
    )
    r = stream_to_response(s_r, _REQ, _TS)
    resp_ids.add(r.responseId)

_eq(len(resp_ids), 1, "zero randomness: 5 stream_to_response builds → identical responseId")

# ===========================================================================
# §21  Identical streams → identical responses
# ===========================================================================
print("§21  Identical streams → identical responses ...")

def _simulate_stream(tokens_list, start_at=1000, end_at=2000):
    """Build a GroqStreamingResult from a list of token strings."""
    cks = [build_stream_chunk(_SID, i, t) for i, t in enumerate(tokens_list)]
    st  = build_stream_state(
        _REQ.requestId, cks, completed=True, finish_reason="stop",
        started_at=start_at, completed_at=end_at
    )
    me  = build_streaming_metadata(st)
    rs  = stream_to_response(st, _REQ, _TS)
    return build_streaming_result(st, rs, me)

tokens_a = ["The ", "attacker ", "used ", "DNS."]
tokens_b = ["The ", "attacker ", "used ", "DNS."]  # identical

res_a = _simulate_stream(tokens_a)
res_b = _simulate_stream(tokens_b)

_eq(res_a.response.responseId,          res_b.response.responseId,          "same tokens → same responseId")
_eq(res_a.response.responseFingerprint, res_b.response.responseFingerprint, "same tokens → same fingerprint")
_eq(res_a.response.content,             res_b.response.content,             "same tokens → same content")
_eq(res_a.state.accumulatedContent,     res_b.state.accumulatedContent,     "same tokens → same accumulatedContent")
_eq(res_a.state.streamId,               res_b.state.streamId,               "same requestId → same streamId")
_eq(res_a.metadata.chunkCount,          res_b.metadata.chunkCount,          "same tokens → same chunkCount")

# Different tokens → different response
tokens_c = ["A ", "completely ", "different ", "answer."]
res_c    = _simulate_stream(tokens_c)
_ne(res_a.response.responseId,          res_c.response.responseId,          "different tokens → different responseId")
_ne(res_a.response.responseFingerprint, res_c.response.responseFingerprint, "different tokens → different fingerprint")
_ne(res_a.response.content,             res_c.response.content,             "different tokens → different content")

# Same stream, same result, 3 times
fingerprints = {_simulate_stream(tokens_a).response.responseFingerprint for _ in range(3)}
_eq(len(fingerprints), 1, "3 identical stream builds → 1 unique fingerprint (deterministic)")

# ===========================================================================
# §22  Integration with existing GroqResponse builder
# ===========================================================================
print("§22  Integration with GroqResponse builder ...")

from services.groq_provider_service import (
    build_response as _build_response_direct,
    _compute_response_key, _compute_response_fingerprint,
)

# Build response via stream path
content_str = "Attacker used lateral movement."
cks_int = [build_stream_chunk(_SID, i, t) for i, t in enumerate(content_str.split())]
# Rebuild with spaces
cks_int2 = [build_stream_chunk(_SID, i, t + (" " if i < len(content_str.split())-1 else ""))
            for i, t in enumerate(content_str.split())]
# Simpler: use the full string as one chunk
cks_int3  = [build_stream_chunk(_SID, 0, content_str)]
st_int    = build_stream_state(_REQ.requestId, cks_int3, completed=True, finish_reason="stop", started_at=0, completed_at=500)
resp_stream = stream_to_response(st_int, _REQ, _TS)

# Build equivalent response via direct builder (non-streaming path)
prompt_chars  = sum(len(m.content) for m in _REQ.messages)
prompt_tokens = max(0, -(-prompt_chars // 4))
comp_tokens   = max(0, -(-len(content_str) // 4))
resp_direct = _build_response_direct(
    request_id        = _REQ.requestId,
    model             = _REQ.model,
    content           = content_str,
    finish_reason     = "stop",
    created_at        = _TS,
    prompt_tokens     = prompt_tokens,
    completion_tokens = comp_tokens,
    latency_ms        = 500,
)

# Same responseId and fingerprint — both paths use the same builder
_eq(resp_stream.responseId,          resp_direct.responseId,          "streaming path matches direct builder responseId")
_eq(resp_stream.responseFingerprint, resp_direct.responseFingerprint, "streaming path matches direct builder fingerprint")
_eq(resp_stream.content,             resp_direct.content,             "content matches")
_eq(resp_stream.finishReason,        resp_direct.finishReason,        "finishReason matches")
_eq(resp_stream.requestId,           resp_direct.requestId,           "requestId matches")
_eq(resp_stream.engineVersion,       resp_direct.engineVersion,       "engineVersion matches")

# GroqResponse from stream has same shape as from HTTP path
_in("responseId",          resp_stream.model_dump(), "streaming response has responseId field")
_in("responseKey",         resp_stream.model_dump(), "streaming response has responseKey field")
_in("responseFingerprint", resp_stream.model_dump(), "streaming response has responseFingerprint field")
_in("usage",               resp_stream.model_dump(), "streaming response has usage field")
_in("metadata",            resp_stream.model_dump(), "streaming response has metadata field")

# ===========================================================================
# §23  Exception class hierarchy and attributes
# ===========================================================================
print("§23  Exception class hierarchy ...")

exc_classes = [
    MalformedChunkError, DuplicateChunkError, InvalidSequenceError,
    InvalidFinishReasonError, StreamInterruptedError, StreamTimeoutError,
    MissingDeltaError,
]
for cls in exc_classes:
    _assert(issubclass(cls, GroqStreamError), f"{cls.__name__} is GroqStreamError subclass")
    _assert(issubclass(cls, Exception),       f"{cls.__name__} is Exception subclass")

# stream_id attribute
exc_inst = MalformedChunkError("test message", stream_id="stream-abc")
_eq(exc_inst.stream_id, "stream-abc", "GroqStreamError carries stream_id")
_in("test message", str(exc_inst),    "GroqStreamError message in str()")

# repr includes class name and stream_id
r = repr(exc_inst)
_in("MalformedChunkError", r, "repr includes class name")
_in("stream-abc",          r, "repr includes stream_id")
_in("test message",        r, "repr includes message")

# Default stream_id=""
exc_no_sid = DuplicateChunkError("dup")
_eq(exc_no_sid.stream_id, "", "default stream_id is empty string")

# ===========================================================================
# §24  Error handling — interrupted stream / premature EOF / timeout
# ===========================================================================
print("§24  Error handling ...")

# StreamInterruptedError attributes
err_int = StreamInterruptedError("Stream ended early.", stream_id="s1")
_eq(err_int.stream_id, "s1", "StreamInterruptedError carries stream_id")
_in("Stream ended early", str(err_int), "StreamInterruptedError message")

# StreamTimeoutError attributes
err_to = StreamTimeoutError("Timed out after 60s.", stream_id="s2")
_eq(err_to.stream_id, "s2", "StreamTimeoutError carries stream_id")
_in("Timed out", str(err_to), "StreamTimeoutError message")

# MissingDeltaError attributes
err_md = MissingDeltaError("No delta in chunk.", stream_id="s3")
_eq(err_md.stream_id, "s3", "MissingDeltaError carries stream_id")

# InvalidSequenceError from build_stream_chunk
try:
    build_stream_chunk("sid", -5, "x")
    _assert(False, "negative seq should raise InvalidSequenceError")
except InvalidSequenceError as e:
    _assert(True, "negative seq raises InvalidSequenceError")
    _in("-5", str(e), "error message mentions bad value")

# finalize_stream with interrupted=True marks state not completed
state_intr, meta_intr = finalize_stream(
    chunks        = [build_stream_chunk(_SID, 0, "partial")],
    request_id    = _REQ.requestId,
    finish_reason = None,
    started_at    = 0,
    interrupted   = True,
)
_assert(not state_intr.completed, "interrupted finalize: completed=False")
_assert(meta_intr.interrupted, "interrupted finalize: metadata.interrupted=True")
_assert(state_intr.finishReason is None, "interrupted finalize: finishReason=None")

# stream_to_response still works on interrupted state (uses 'stop' fallback)
resp_intr = stream_to_response(state_intr, _REQ, _TS)
_eq(resp_intr.content, "partial", "interrupted: content assembled from partial chunks")
_eq(resp_intr.finishReason, "stop", "interrupted: finishReason defaults to 'stop'")

# ===========================================================================
# §25  Multiple models — unique stream IDs per request
# ===========================================================================
print("§25  Multiple models ...")
from core.constants import GROQ_SUPPORTED_MODELS

model_stream_ids = set()
for model in GROQ_SUPPORTED_MODELS:
    req_m  = build_groq_request(model, _MSGS, _TS)
    st_m   = build_stream_state(req_m.requestId, [])
    model_stream_ids.add(st_m.streamId)
    _eq(len(st_m.streamId), 36, f"{model}: streamId is UUID")
    _eq(len(st_m.engineVersion), len(GROQ_STREAMING_ENGINE_VERSION), f"{model}: engineVersion length")

_eq(len(model_stream_ids), len(GROQ_SUPPORTED_MODELS), "each model produces unique streamId")

# ===========================================================================
# §26  Chunk count edge cases
# ===========================================================================
print("§26  Chunk count edge cases ...")

# Single chunk
single_chunk = [build_stream_chunk(_SID, 0, "single")]
state_single = build_stream_state(_REQ.requestId, single_chunk, completed=True, finish_reason="stop", started_at=0, completed_at=100)
meta_single  = build_streaming_metadata(state_single)
_eq(meta_single.chunkCount, 1, "single chunk: chunkCount=1")
_eq(meta_single.averageChunkSize, 6.0, "single chunk: averageChunkSize=6.0")

# 100 chunks
chunks_100 = [build_stream_chunk(_SID, i, f"t{i} ") for i in range(100)]
state_100  = build_stream_state(_REQ.requestId, chunks_100, completed=True, finish_reason="stop", started_at=0, completed_at=5000)
meta_100   = build_streaming_metadata(state_100)
_eq(meta_100.chunkCount, 100, "100 chunks: chunkCount=100")
_eq(state_100.totalChunks, 100, "100 chunks: totalChunks=100")
_gt(meta_100.tokensPerSecond, 0.0, "100 chunks: tokensPerSecond > 0")

# ===========================================================================
# §27  parse_stream_chunk — content extraction edge cases
# ===========================================================================
print("§27  parse_stream_chunk content edge cases ...")

# Unicode content
sse_unicode = _make_sse("🔍 Attack pattern detected")
c_uni = parse_stream_chunk(sse_unicode, _SID, 0)
_eq(c_uni.content, "🔍 Attack pattern detected", "unicode content extracted correctly")

# Newline in content
sse_nl = _make_sse("line1\nline2")
c_nl = parse_stream_chunk(sse_nl, _SID, 0)
_eq(c_nl.content, "line1\nline2", "newline in content preserved")

# Content with JSON special chars
sse_json_chars = _make_sse('{"key": "value"}')
c_jc = parse_stream_chunk(sse_json_chars, _SID, 0)
_eq(c_jc.content, '{"key": "value"}', "JSON-like content preserved")

# Very long content
long_content = "A" * 10_000
sse_long = _make_sse(long_content)
c_long = parse_stream_chunk(sse_long, _SID, 0)
_eq(len(c_long.content), 10_000, "very long content (10k chars) preserved")

# Content with null bytes
sse_null = _make_sse("before\x00after")
c_null_byte = parse_stream_chunk(sse_null, _SID, 0)
_eq(c_null_byte.content, "before\x00after", "null byte in content preserved")

# Chunk with delta but no 'content' key (role-only variant)
sse_no_content_key = 'data: {"choices": [{"delta": {"role": "assistant"}, "finish_reason": null}]}'
c_no_key = parse_stream_chunk(sse_no_content_key, _SID, 0)
_eq(c_no_key.content, "", "missing content key → empty string")

# finish_reason=null in JSON → None after normalisation
sse_fr_null = 'data: {"choices": [{"delta": {"content": "hi"}, "finish_reason": null}]}'
c_fr_null = parse_stream_chunk(sse_fr_null, _SID, 0)
_assert(c_fr_null.finishReason is None, "finish_reason=null in JSON → None")

# ===========================================================================
# §28  Deterministic fingerprints across multiple states
# ===========================================================================
print("§28  Deterministic fingerprints ...")

# Build same stream 5 times, all must yield identical response fingerprints
token_list = ["The ", "network ", "was ", "compromised."]
fingerprint_set = set()
for _ in range(5):
    cks  = [build_stream_chunk(_SID, i, t) for i, t in enumerate(token_list)]
    st   = build_stream_state(_REQ.requestId, cks, completed=True, finish_reason="stop", started_at=100, completed_at=900)
    resp = stream_to_response(st, _REQ, _TS)
    fingerprint_set.add(resp.responseFingerprint)

_eq(len(fingerprint_set), 1, "5 builds of same stream → 1 unique fingerprint")

# streamId is always the same for same requestId
sid_set = set()
for _ in range(5):
    s = build_stream_state(_REQ.requestId, [])
    sid_set.add(s.streamId)
_eq(len(sid_set), 1, "5 builds with same requestId → 1 unique streamId")

# chunkId is always the same for same (stream_id, seq, content)
cid_set = set()
for _ in range(5):
    c = build_stream_chunk("fixed-stream", 7, "fixed-content")
    cid_set.add(c.chunkId)
_eq(len(cid_set), 1, "5 builds of same chunk → 1 unique chunkId")

# ===========================================================================
# §29  Immutability of all models
# ===========================================================================
print("§29  Immutability — all models ...")

# GroqStreamChunk
try:
    chunk.sequenceNumber = 99   # type: ignore
    _assert(False, "GroqStreamChunk.sequenceNumber should be immutable")
except Exception:
    _assert(True, "GroqStreamChunk.sequenceNumber is immutable")

try:
    chunk.finishReason = "stop"  # type: ignore
    _assert(False, "GroqStreamChunk.finishReason should be immutable")
except Exception:
    _assert(True, "GroqStreamChunk.finishReason is immutable")

# GroqStreamState
try:
    state.totalChunks = 999   # type: ignore
    _assert(False, "GroqStreamState.totalChunks should be immutable")
except Exception:
    _assert(True, "GroqStreamState.totalChunks is immutable")

try:
    state.completed = False  # type: ignore
    _assert(False, "GroqStreamState.completed should be immutable")
except Exception:
    _assert(True, "GroqStreamState.completed is immutable")

# GroqStreamingMetadata
try:
    meta.totalLatencyMs = 0  # type: ignore
    _assert(False, "GroqStreamingMetadata.totalLatencyMs should be immutable")
except Exception:
    _assert(True, "GroqStreamingMetadata.totalLatencyMs is immutable")

# GroqStreamingResult
try:
    result.metadata = meta  # type: ignore
    _assert(False, "GroqStreamingResult.metadata should be immutable")
except Exception:
    _assert(True, "GroqStreamingResult.metadata is immutable")

# ===========================================================================
# §30  SSE line format variations
# ===========================================================================
print("§30  SSE line format variations ...")

# Leading/trailing whitespace on "data: ..." lines
sse_ws = "  " + _make_sse("trimmed") + "  "
c_ws_line = parse_stream_chunk(sse_ws, _SID, 0)
_is(c_ws_line, GroqStreamChunk, "whitespace-padded data line parsed correctly")
_eq(c_ws_line.content, "trimmed", "content extracted despite whitespace on line")

# Multiple spaces after "data:"
sse_multi_sp = 'data:    {"choices": [{"delta": {"content": "spaced"}, "finish_reason": null}]}'
c_ms = parse_stream_chunk(sse_multi_sp, _SID, 0)
_is(c_ms, GroqStreamChunk, "multiple spaces after 'data:' handled")
_eq(c_ms.content, "spaced", "content extracted with multi-space separator")

# "data:[DONE]" without space
c_done2 = parse_stream_chunk("data:[DONE]", _SID, 0)
_assert(c_done2 is None, "data:[DONE] without space returns None")

# data: with only whitespace after
c_ws_only = parse_stream_chunk("data:   ", _SID, 0)
_assert(c_ws_only is None, "data: with only whitespace returns None (not [DONE], blank payload)")

# ===========================================================================
# §31  Full end-to-end simulation (no network)
# ===========================================================================
print("§31  Full end-to-end simulation ...")

# Simulate a complete Groq SSE stream for a given request
raw_sse_lines = [
    'data: {"choices": [{"delta": {"role": "assistant"}, "finish_reason": null}]}',
    _make_sse("The "),
    _make_sse("attack "),
    _make_sse("chain "),
    _make_sse("involved "),
    _make_sse("DNS "),
    _make_sse("exfiltration."),
    _make_sse_fr("stop"),
    "data: [DONE]",
]

# Parse all lines
sim_chunks  : List = []
sim_chunks_raw, sim_start = reset_stream(_REQ.requestId)
sim_seq     = 0
sim_done    = False
sim_finish  = None

for line in raw_sse_lines:
    chunk_or_none = parse_stream_chunk(line.strip(), _SID, sim_seq)
    if chunk_or_none is None:
        if line.strip() == "data: [DONE]":
            sim_done = True
        continue
    try:
        sim_chunks_raw = append_chunk(sim_chunks_raw, chunk_or_none, _SID)
    except DuplicateChunkError:
        pass
    if chunk_or_none.finishReason:
        sim_finish = chunk_or_none.finishReason
    sim_seq += 1

sim_state, sim_meta = finalize_stream(
    chunks        = sim_chunks_raw,
    request_id    = _REQ.requestId,
    finish_reason = sim_finish,
    started_at    = sim_start,
    interrupted   = not sim_done,
)

sim_resp   = stream_to_response(sim_state, _REQ, _TS)
sim_result = build_streaming_result(sim_state, sim_resp, sim_meta)

expected_sim_content = "The attack chain involved DNS exfiltration."
_eq(sim_resp.content, expected_sim_content, "e2e simulation: content assembled correctly")
_eq(sim_resp.finishReason, "stop", "e2e simulation: finishReason='stop'")
_assert(sim_state.completed, "e2e simulation: state completed")
_assert(not sim_meta.interrupted, "e2e simulation: not interrupted")
_gt(sim_meta.chunkCount, 0, "e2e simulation: chunkCount > 0")
_eq(len(sim_resp.responseId), 36, "e2e simulation: responseId is UUID")

# Run simulation again — identical result
sim_chunks_raw2, sim_start2 = reset_stream(_REQ.requestId)
sim_seq2    = 0
sim_done2   = False
sim_finish2 = None

for line in raw_sse_lines:
    chunk_or_none = parse_stream_chunk(line.strip(), _SID, sim_seq2)
    if chunk_or_none is None:
        if line.strip() == "data: [DONE]":
            sim_done2 = True
        continue
    try:
        sim_chunks_raw2 = append_chunk(sim_chunks_raw2, chunk_or_none, _SID)
    except DuplicateChunkError:
        pass
    if chunk_or_none.finishReason:
        sim_finish2 = chunk_or_none.finishReason
    sim_seq2 += 1

sim_state2, _ = finalize_stream(
    chunks = sim_chunks_raw2,
    request_id    = _REQ.requestId,
    finish_reason = sim_finish2,
    started_at    = sim_start2,
    interrupted   = not sim_done2,
)
sim_resp2 = stream_to_response(sim_state2, _REQ, _TS)

_eq(sim_resp.responseId,          sim_resp2.responseId,          "e2e: repeated simulation → same responseId")
_eq(sim_resp.responseFingerprint, sim_resp2.responseFingerprint, "e2e: repeated simulation → same fingerprint")
_eq(sim_resp.content,             sim_resp2.content,             "e2e: repeated simulation → same content")

# ===========================================================================
# §32  streamId consistency with groq_http_client integration
# ===========================================================================
print("§32  HTTP client integration checks ...")

from services.groq_http_client import (
    build_http_config, build_http_request, build_headers, build_payload,
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
)

# Verify build_headers works with same config used in streaming
cfg_test = build_http_config(api_key="gsk_test_AABB1122CCDD3344")
headers  = build_headers(cfg_test)
_in("Authorization", headers, "build_headers: Authorization present")
_in("Bearer", headers["Authorization"], "build_headers: Bearer prefix present")

# Verify build_payload with stream=True forced
groq_req_stream = build_groq_request(_M70, _MSGS, _TS, stream=True)
payload_stream  = build_payload(groq_req_stream)
_assert(payload_stream["stream"] is True, "build_payload: stream=True in payload")

# Verify streaming engine version != http client version (separate engines)
_ne(GROQ_STREAMING_ENGINE_VERSION, GROQ_HTTP_CLIENT_ENGINE_VERSION,
    "streaming engine version differs from http client version")

# streamId is deterministic and derived from requestId (not from HTTP)
sid1 = build_stream_state(_REQ.requestId, []).streamId
sid2 = build_stream_state(_REQ.requestId, []).streamId
_eq(sid1, sid2, "streamId always deterministic from requestId")

# Different requestId → different streamId
req_diff = build_groq_request(_M8, _MSGS, _TS)
sid_diff = build_stream_state(req_diff.requestId, []).streamId
_ne(sid1, sid_diff, "different requestId → different streamId")

# ===========================================================================
# §33  Warnings deduplication and ordering in metadata
# ===========================================================================
print("§33  Warnings handling ...")

# Empty warnings
meta_no_w = build_streaming_metadata(state_no_content, warnings=None)
_eq(meta_no_w.warnings, (), "None warnings → empty tuple")

meta_empty_w = build_streaming_metadata(state_no_content, warnings=[])
_eq(meta_empty_w.warnings, (), "empty list warnings → empty tuple")

# Duplicate warnings deduped
meta_dup_w = build_streaming_metadata(state_no_content, warnings=["W1", "W2", "W1", "W2", "W3"])
_eq(meta_dup_w.warnings, ("W1", "W2", "W3"), "duplicate warnings deduped and sorted")

# Whitespace-only warning filtered
meta_ws_w = build_streaming_metadata(state_no_content, warnings=["  ", "", "Real warning"])
_eq(meta_ws_w.warnings, ("Real warning",), "whitespace-only warnings filtered")

# Sorted alphabetically
meta_sort_w = build_streaming_metadata(state_no_content, warnings=["Zeta", "Alpha", "Beta"])
_eq(meta_sort_w.warnings, ("Alpha", "Beta", "Zeta"), "warnings sorted alphabetically")

# ===========================================================================
# §34  Token estimation accuracy
# ===========================================================================
print("§34  Token estimation ...")

# 0 chars → 0 tokens
cks_zero = [build_stream_chunk(_SID, 0, "")]
st_zero  = build_stream_state(_REQ.requestId, cks_zero, completed=True, started_at=0, completed_at=100)
resp_zero = stream_to_response(st_zero, _REQ, _TS)
_eq(resp_zero.usage.completionTokens, 0, "0 chars → 0 completion tokens")

# 4 chars → 1 token (ceiling(4/4))
cks_4 = [build_stream_chunk(_SID, 0, "abcd")]
st_4  = build_stream_state(_REQ.requestId, cks_4, completed=True, started_at=0, completed_at=100)
resp_4 = stream_to_response(st_4, _REQ, _TS)
_eq(resp_4.usage.completionTokens, 1, "4 chars → 1 completion token (ceiling(4/4)=1)")

# 5 chars → 2 tokens (ceiling(5/4))
cks_5 = [build_stream_chunk(_SID, 0, "abcde")]
st_5  = build_stream_state(_REQ.requestId, cks_5, completed=True, started_at=0, completed_at=100)
resp_5 = stream_to_response(st_5, _REQ, _TS)
_eq(resp_5.usage.completionTokens, 2, "5 chars → 2 completion tokens (ceiling(5/4)=2)")

# 400 chars → 100 tokens (ceiling(400/4))
cks_400 = [build_stream_chunk(_SID, 0, "x" * 400)]
st_400  = build_stream_state(_REQ.requestId, cks_400, completed=True, started_at=0, completed_at=500)
resp_400 = stream_to_response(st_400, _REQ, _TS)
_eq(resp_400.usage.completionTokens, 100, "400 chars → 100 completion tokens")

# ===========================================================================
# §35  No tool calls / function calls in service
# ===========================================================================
print("§35  No tool call logic ...")

# Verify the streaming service does NOT expose any tool-call related symbols
import services.groq_streaming_service as _svc
tool_symbols = [s for s in dir(_svc) if "tool" in s.lower() or "function_call" in s.lower()]
_eq(len(tool_symbols), 0, "no tool-call symbols in streaming service (reserved for A4.2.4)")

schema_symbols = [s for s in dir(_svc) if "json_schema" in s.lower() or "schema_exec" in s.lower()]
_eq(len(schema_symbols), 0, "no JSON schema execution symbols in streaming service")

# ===========================================================================
# §36  Additional determinism and edge-case coverage
# ===========================================================================
print("§36  Additional edge cases ...")

# build_stream_state with finish_reason='null' string → normalised to None
state_fnull = build_stream_state(_REQ.requestId, [], finish_reason="null")
_assert(state_fnull.finishReason is None, "build_stream_state: 'null' finish_reason → None")

# build_stream_state with whitespace finish_reason → None
state_fws = build_stream_state(_REQ.requestId, [], finish_reason="   ")
_assert(state_fws.finishReason is None, "build_stream_state: whitespace finish_reason → None")

# parse_stream_chunk with data after [DONE] should not be reached in real streams
# but a bare "data:" with whitespace returns None
c_bare = parse_stream_chunk("data:   ", _SID, 0)
_assert(c_bare is None, "data: with only whitespace → None")

# append_chunk: empty content chunk (seq=5) not a duplicate of seq=0
base_with_zero = [build_stream_chunk(_SID, 0, "A")]
new_five = build_stream_chunk(_SID, 5, "")
extended5 = append_chunk(base_with_zero, new_five, _SID)
_eq(len(extended5), 2, "seq=5 not a duplicate of seq=0 → appended")

# GroqStreamState engineVersion matches constant
_eq(state.engineVersion, GROQ_STREAMING_ENGINE_VERSION, "state.engineVersion matches constant")

# GroqStreamingResult has all three required fields
_assert(hasattr(result, "state"),    "GroqStreamingResult has .state")
_assert(hasattr(result, "response"), "GroqStreamingResult has .response")
_assert(hasattr(result, "metadata"), "GroqStreamingResult has .metadata")

# GroqStreamChunk has all five required fields
_assert(hasattr(chunk, "chunkId"),        "GroqStreamChunk has .chunkId")
_assert(hasattr(chunk, "sequenceNumber"), "GroqStreamChunk has .sequenceNumber")
_assert(hasattr(chunk, "content"),        "GroqStreamChunk has .content")
_assert(hasattr(chunk, "finishReason"),   "GroqStreamChunk has .finishReason")
_assert(hasattr(chunk, "receivedAt"),     "GroqStreamChunk has .receivedAt")

# GroqStreamState has all required fields
for field in ("streamId","requestId","chunks","accumulatedContent",
              "totalChunks","completed","finishReason","startedAt","completedAt","engineVersion"):
    _assert(hasattr(state, field), f"GroqStreamState has .{field}")

# GroqStreamingMetadata has all required fields
for field in ("firstTokenLatencyMs","totalLatencyMs","chunkCount",
              "averageChunkSize","tokensPerSecond","interrupted","warnings"):
    _assert(hasattr(meta, field), f"GroqStreamingMetadata has .{field}")

# ===========================================================================
# Final report
# ===========================================================================
print()
print("=" * 60)
total = _PASS + _FAIL
print(f"Result: {_PASS}/{total} assertions passed.")
if _ERRORS:
    print(f"\nFailed assertions ({len(_ERRORS)}):")
    for e in _ERRORS:
        print(f"  {e}")
print("=" * 60)

if _FAIL > 0:
    sys.exit(1)
else:
    print("All assertions passed.")
    sys.exit(0)
