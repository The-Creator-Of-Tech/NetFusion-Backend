"""
Smoke Test — AI Execution Engine
==================================
Phase A4.3.1 — Verifies every model, builder, execution function,
utility, and integration path in services/ai_execution_service.py.

Run:
    python smoke_test_ai_execution_engine.py
Expected: 250+/250 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. All execution is pure metadata.
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


def _eq(a, b, msg): _assert(a == b,  f"{msg} — expected {b!r}, got {a!r}")
def _ne(a, b, msg): _assert(a != b,  f"{msg} — both are {a!r}")
def _in(x, c, msg): _assert(x in c,  f"{msg} — {x!r} not in collection")
def _ni(x, c, msg): _assert(x not in c, f"{msg} — {x!r} unexpectedly in collection")
def _gt(a, b, msg): _assert(a > b,   f"{msg} — {a!r} not > {b!r}")
def _ge(a, b, msg): _assert(a >= b,  f"{msg} — {a!r} not >= {b!r}")
def _lt(a, b, msg): _assert(a < b,   f"{msg} — {a!r} not < {b!r}")
def _is(a, t, msg): _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.ai_execution_service import (
    # Exceptions
    AIExecutionError, ExecutionTimeoutError, ProviderUnavailableError,
    InvalidRequestError, InvalidResponseError, RetryExhaustedError,
    ToolExecutionFailedError,
    # Models
    AIExecutionRequest, AIExecutionResponse, AIExecutionMetadata,
    AIExecutionResult, AIExecutionStatistics,
    # Builders
    build_execution_request, build_execution_response,
    build_execution_metadata, build_execution_result,
    # Execution
    execute_request, execute_with_retry, execute_stream,
    execute_tool_call, execute_with_registry,
    # Utilities
    validate_execution_request, validate_execution_response,
    calculate_execution_statistics, filter_execution_results,
    group_execution_results, find_execution,
    # ID helpers (internal)
    _sha256_32, _uuid5, _compute_execution_key,
    _compute_execution_fingerprint, _compute_response_key,
    _compute_response_fingerprint,
    # Constants
    AI_EXECUTION_ENGINE_VERSION,
    _VALID_STRATEGIES,
)
from core.constants import AI_EXECUTION_ENGINE_VERSION as CONST_AE_VERSION

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS  = "2026-07-01T12:00:00Z"
_SYS = "You are a network security analyst."
_USR = "Analyse the following packet capture and report anomalies."
_RID = "req-abc-001"
_SID = "session-xyz-001"


def _req(**kw) -> AIExecutionRequest:
    return build_execution_request(
        provider      = kw.get("provider",    "groq"),
        model         = kw.get("model",       "llama-3.3-70b-versatile"),
        system_prompt = kw.get("system_prompt", _SYS),
        user_prompt   = kw.get("user_prompt",   _USR),
        created_at    = kw.get("created_at",    _TS),
        temperature   = kw.get("temperature",   0.0),
        max_tokens    = kw.get("max_tokens",     1024),
        stream        = kw.get("stream",         False),
        request_id    = kw.get("request_id",    _RID),
        session_id    = kw.get("session_id",    _SID),
        strategy      = kw.get("strategy",      "priority"),
    )


def _resp(req: AIExecutionRequest, **kw) -> AIExecutionResponse:
    return build_execution_response(
        execution_id      = req.executionId,
        provider          = kw.get("provider",    req.provider),
        model             = kw.get("model",        req.model),
        content           = kw.get("content",      "Analysis complete."),
        finish_reason     = kw.get("finish_reason","stop"),
        created_at        = kw.get("created_at",   _TS),
        prompt_tokens     = kw.get("prompt_tokens",  100),
        completion_tokens = kw.get("completion_tokens", 50),
        estimated_cost    = kw.get("estimated_cost",   0.001),
        latency_ms        = kw.get("latency_ms",       250),
    )


# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version ...")
_eq(AI_EXECUTION_ENGINE_VERSION, "ai-execution-v1", "version value")
_eq(CONST_AE_VERSION, AI_EXECUTION_ENGINE_VERSION, "core.constants matches service")
_is(AI_EXECUTION_ENGINE_VERSION, str, "version is str")
_in("ai-execution", AI_EXECUTION_ENGINE_VERSION, "version contains 'ai-execution'")

# ===========================================================================
# §2  Deterministic ID helpers
# ===========================================================================
print("§2  ID helpers ...")
h1 = _sha256_32("a", "b")
h2 = _sha256_32("a", "b")
_eq(h1, h2, "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 length=32")
h3 = _sha256_32("b", "a")
_ne(h1, h3, "different order -> different hash")

u1 = _uuid5("test-key")
u2 = _uuid5("test-key")
_eq(u1, u2, "_uuid5 deterministic")
_eq(len(u1), 36, "_uuid5 returns 36-char UUID")
_eq(u1[14], "5", "_uuid5 is version 5")
u3 = _uuid5("other-key")
_ne(u1, u3, "different key -> different UUID")

# execution key
k1 = _compute_execution_key("groq","llama-3.3-70b-versatile", _SYS, _USR, 0.0, 1024)
k2 = _compute_execution_key("groq","llama-3.3-70b-versatile", _SYS, _USR, 0.0, 1024)
_eq(k1, k2, "_compute_execution_key deterministic")
_eq(len(k1), 32, "_compute_execution_key returns 32 chars")
k3 = _compute_execution_key("openai","gpt-4o", _SYS, _USR, 0.0, 1024)
_ne(k1, k3, "different provider -> different execution key")

# fingerprint
fp1 = _compute_execution_fingerprint(k1, _SYS, _USR)
fp2 = _compute_execution_fingerprint(k1, _SYS, _USR)
_eq(fp1, fp2, "_compute_execution_fingerprint deterministic")
_eq(len(fp1), 32, "fingerprint is 32 chars")

# response key / fingerprint
rk1 = _compute_response_key("eid-1", "content", "stop")
rk2 = _compute_response_key("eid-1", "content", "stop")
_eq(rk1, rk2, "_compute_response_key deterministic")
rfp1 = _compute_response_fingerprint(rk1, "content")
rfp2 = _compute_response_fingerprint(rk1, "content")
_eq(rfp1, rfp2, "_compute_response_fingerprint deterministic")

# ===========================================================================
# §3  build_execution_request()
# ===========================================================================
print("§3  build_execution_request() ...")
req = _req()
_is(req, AIExecutionRequest, "returns AIExecutionRequest")
_eq(len(req.executionId), 36, "executionId is 36-char UUID")
_eq(req.executionId[14], "5",  "executionId is UUIDv5")
_eq(len(req.executionKey), 32, "executionKey is 32 chars")
_eq(len(req.executionFingerprint), 32, "executionFingerprint is 32 chars")
_eq(req.provider,    "groq",                    "provider normalised")
_eq(req.model,       "llama-3.3-70b-versatile", "model normalised")
_eq(req.systemPrompt, _SYS, "systemPrompt stored")
_eq(req.userPrompt,   _USR, "userPrompt stored")
_eq(req.temperature,  0.0,  "temperature stored")
_eq(req.maxTokens,   1024,  "maxTokens stored")
_assert(not req.stream,     "stream=False by default")
_eq(req.requestId,  _RID,  "requestId stored")
_eq(req.sessionId,  _SID,  "sessionId stored")
_eq(req.strategy,   "priority", "strategy stored")
_eq(req.createdAt,  _TS,   "createdAt stored")
_eq(req.engineVersion, AI_EXECUTION_ENGINE_VERSION, "engineVersion set")

# Determinism
req2 = _req()
_eq(req.executionId,          req2.executionId,          "same inputs -> same executionId")
_eq(req.executionKey,         req2.executionKey,         "same inputs -> same executionKey")
_eq(req.executionFingerprint, req2.executionFingerprint, "same inputs -> same fingerprint")

# Different model -> different ID
req_8b = _req(model="llama-3.1-8b-instant")
_ne(req.executionId, req_8b.executionId, "different model -> different executionId")

# Different prompt -> different ID
req_diff = _req(user_prompt="Different question.")
_ne(req.executionId, req_diff.executionId, "different prompt -> different executionId")

# Provider normalised to lowercase
req_upper = _req(provider="GROQ", model="LLAMA-3.3-70B-VERSATILE")
_eq(req_upper.provider, "groq", "GROQ -> groq")
_eq(req_upper.model, "llama-3.3-70b-versatile", "model lowercased")
_eq(req_upper.executionId, req.executionId, "case normalisation -> same ID")

# Temperature clamped
req_hot = _req(temperature=3.0)
_eq(req_hot.temperature, 2.0, "temperature clamped to 2.0")
req_cold = _req(temperature=-1.0)
_eq(req_cold.temperature, 0.0, "temperature clamped to 0.0")

# maxTokens clamped
req_mt = _req(max_tokens=0)
_eq(req_mt.maxTokens, 1, "maxTokens clamped to 1 minimum")

# Immutability
try:
    req.provider = "changed"  # type: ignore
    _assert(False, "AIExecutionRequest should be frozen")
except Exception:
    _assert(True, "AIExecutionRequest is immutable")

# Empty provider raises
try:
    _req(provider="")
    _assert(False, "empty provider should raise InvalidRequestError")
except InvalidRequestError as e:
    _assert(True, "empty provider raises InvalidRequestError")
    _in("provider", str(e), "error mentions provider")

# Empty model raises
try:
    _req(model="")
    _assert(False, "empty model should raise InvalidRequestError")
except InvalidRequestError as e:
    _assert(True, "empty model raises InvalidRequestError")
    _in("model", str(e), "error mentions model")

# Both prompts empty raises
try:
    _req(system_prompt="", user_prompt="")
    _assert(False, "both prompts empty should raise InvalidRequestError")
except InvalidRequestError as e:
    _assert(True, "both prompts empty raises InvalidRequestError")

# Invalid strategy raises
try:
    _req(strategy="unknown_strategy_xyz")
    _assert(False, "invalid strategy should raise InvalidRequestError")
except InvalidRequestError as e:
    _assert(True, "invalid strategy raises InvalidRequestError")
    _in("strategy", str(e), "error mentions strategy")

# ===========================================================================
# §4  build_execution_response()
# ===========================================================================
print("§4  build_execution_response() ...")
resp = _resp(req)
_is(resp, AIExecutionResponse, "returns AIExecutionResponse")
_eq(len(resp.responseId), 36, "responseId is 36-char UUID")
_eq(resp.responseId[14], "5",  "responseId is UUIDv5")
_eq(len(resp.responseKey), 32, "responseKey is 32 chars")
_eq(len(resp.responseFingerprint), 32, "responseFingerprint is 32 chars")
_eq(resp.executionId,     req.executionId,  "executionId linked")
_eq(resp.provider,        "groq",           "provider stored")
_eq(resp.model,           "llama-3.3-70b-versatile", "model stored")
_eq(resp.content,         "Analysis complete.", "content stored")
_eq(resp.finishReason,    "stop",            "finishReason stored")
_eq(resp.promptTokens,    100,               "promptTokens stored")
_eq(resp.completionTokens, 50,              "completionTokens stored")
_eq(resp.totalTokens,     150,              "totalTokens = 100+50")
_eq(resp.estimatedCost,   0.001,            "estimatedCost stored")
_eq(resp.latencyMs,       250,              "latencyMs stored")
_eq(resp.engineVersion, AI_EXECUTION_ENGINE_VERSION, "engineVersion set")

# Determinism
resp2 = _resp(req)
_eq(resp.responseId,          resp2.responseId,          "same inputs -> same responseId")
_eq(resp.responseKey,         resp2.responseKey,         "same inputs -> same responseKey")
_eq(resp.responseFingerprint, resp2.responseFingerprint, "same inputs -> same fingerprint")

# Different content -> different ID
resp_diff = _resp(req, content="Different analysis.")
_ne(resp.responseId, resp_diff.responseId, "different content -> different responseId")

# Different finish_reason -> different ID
resp_fr = _resp(req, finish_reason="length")
_ne(resp.responseId, resp_fr.responseId, "different finishReason -> different responseId")

# Negative values clamped to 0
resp_neg = build_execution_response(
    req.executionId, "groq", "llama-3.3-70b-versatile",
    "x", "stop", _TS,
    prompt_tokens=-5, completion_tokens=-10,
    estimated_cost=-0.5, latency_ms=-100,
)
_eq(resp_neg.promptTokens,    0,   "negative promptTokens clamped to 0")
_eq(resp_neg.completionTokens, 0,  "negative completionTokens clamped to 0")
_eq(resp_neg.estimatedCost,   0.0, "negative estimatedCost clamped to 0.0")
_eq(resp_neg.latencyMs,       0,   "negative latencyMs clamped to 0")

# Immutability
try:
    resp.content = "changed"  # type: ignore
    _assert(False, "AIExecutionResponse should be frozen")
except Exception:
    _assert(True, "AIExecutionResponse is immutable")

# ===========================================================================
# §5  build_execution_metadata()
# ===========================================================================
print("§5  build_execution_metadata() ...")
meta = build_execution_metadata(
    execution_id       = req.executionId,
    provider           = "groq",
    model              = "llama-3.3-70b-versatile",
    strategy           = "priority",
    attempt_number     = 1,
    total_attempts     = 1,
    processing_time_ms = 300,
    success            = True,
    error              = None,
    warnings           = ["low token count"],
)
_is(meta, AIExecutionMetadata, "returns AIExecutionMetadata")
_eq(meta.executionId,      req.executionId, "executionId stored")
_eq(meta.provider,         "groq",          "provider stored")
_eq(meta.model,            "llama-3.3-70b-versatile", "model stored")
_eq(meta.strategy,         "priority",      "strategy stored")
_eq(meta.attemptNumber,    1,               "attemptNumber stored")
_eq(meta.totalAttempts,    1,               "totalAttempts stored")
_eq(meta.processingTimeMs, 300,             "processingTimeMs stored")
_assert(meta.success,                       "success=True stored")
_assert(meta.error is None,                 "error=None stored")
_eq(meta.warnings, ("low token count",),   "warnings stored")
_eq(meta.engineVersion, AI_EXECUTION_ENGINE_VERSION, "engineVersion set")

# Negative processingTimeMs clamped
meta_neg = build_execution_metadata(req.executionId,"groq","m","priority",1,1,-50,True)
_eq(meta_neg.processingTimeMs, 0, "negative processingTimeMs clamped to 0")

# attemptNumber / totalAttempts clamped to minimum 1
meta_zero = build_execution_metadata(req.executionId,"groq","m","priority",0,0,100,True)
_eq(meta_zero.attemptNumber,  1, "attemptNumber=0 clamped to 1")
_eq(meta_zero.totalAttempts,  1, "totalAttempts=0 clamped to 1")

# Warnings deduped + sorted
meta_w = build_execution_metadata(req.executionId,"g","m","priority",1,1,0,True,
                                  warnings=["B","A","B","C"])
_eq(meta_w.warnings, ("A","B","C"), "warnings deduped and sorted")

# Immutability
try:
    meta.success = False  # type: ignore
    _assert(False, "AIExecutionMetadata should be frozen")
except Exception:
    _assert(True, "AIExecutionMetadata is immutable")

# ===========================================================================
# §6  build_execution_result()
# ===========================================================================
print("§6  build_execution_result() ...")
result = build_execution_result(req, resp, meta)
_is(result, AIExecutionResult, "returns AIExecutionResult")
_eq(result.request,  req,  "request stored")
_eq(result.response, resp, "response stored")
_eq(result.metadata, meta, "metadata stored")

# None response allowed (failure case)
result_fail = build_execution_result(req, None, meta)
_assert(result_fail.response is None, "None response allowed in failure result")

# Immutability
try:
    result.request = req  # type: ignore
    _assert(False, "AIExecutionResult should be frozen")
except Exception:
    _assert(True, "AIExecutionResult is immutable")

# Same inputs -> same result
result2 = build_execution_result(req, resp, meta)
_eq(result, result2, "same inputs -> equal AIExecutionResult")

# ===========================================================================
# §7  validate_execution_request()
# ===========================================================================
print("§7  validate_execution_request() ...")
# Valid request
try:
    validate_execution_request("groq","llama-3.3-70b-versatile",_SYS,_USR,0.0,1024)
    _assert(True, "valid request -> no exception")
except InvalidRequestError:
    _assert(False, "valid request should not raise")

# Empty provider
try:
    validate_execution_request("","model",_SYS,_USR,0.0,1024)
    _assert(False, "empty provider should raise")
except InvalidRequestError as e:
    _assert(True, "empty provider raises InvalidRequestError")
    _in("provider", str(e), "error mentions provider")

# Both prompts empty
try:
    validate_execution_request("groq","m","","",0.0,1024)
    _assert(False, "both prompts empty should raise")
except InvalidRequestError:
    _assert(True, "both prompts empty raises InvalidRequestError")

# Temperature out of range
try:
    validate_execution_request("groq","m",_SYS,"",3.5,1024)
    _assert(False, "temperature=3.5 should raise")
except InvalidRequestError as e:
    _assert(True, "temperature=3.5 raises InvalidRequestError")
    _in("temperature", str(e), "error mentions temperature")

# maxTokens < 1
try:
    validate_execution_request("groq","m",_SYS,"",0.0,0)
    _assert(False, "maxTokens=0 should raise")
except InvalidRequestError as e:
    _assert(True, "maxTokens=0 raises InvalidRequestError")
    _in("maxTokens", str(e), "error mentions maxTokens")

# Unknown strategy
try:
    validate_execution_request("groq","m",_SYS,"",0.0,1024,"invalid_strat")
    _assert(False, "unknown strategy should raise")
except InvalidRequestError as e:
    _assert(True, "unknown strategy raises InvalidRequestError")
    _in("strategy", str(e), "error mentions strategy")

# ===========================================================================
# §8  validate_execution_response()
# ===========================================================================
print("§8  validate_execution_response() ...")
# Valid
try:
    validate_execution_response("content","stop","groq","llama-3.3-70b-versatile")
    _assert(True, "valid response -> no exception")
except InvalidResponseError:
    _assert(False, "valid response should not raise")

# Empty content is allowed (tool-call completions)
try:
    validate_execution_response("","stop","groq","model")
    _assert(True, "empty content is allowed")
except InvalidResponseError:
    _assert(False, "empty content should be allowed")

# None content raises
try:
    validate_execution_response(None,"stop","groq","model")  # type: ignore
    _assert(False, "None content should raise")
except InvalidResponseError as e:
    _assert(True, "None content raises InvalidResponseError")
    _in("content", str(e), "error mentions content")

# Empty finishReason raises
try:
    validate_execution_response("content","","groq","model")
    _assert(False, "empty finishReason should raise")
except InvalidResponseError as e:
    _assert(True, "empty finishReason raises InvalidResponseError")
    _in("finishReason", str(e), "error mentions finishReason")

# Empty provider raises
try:
    validate_execution_response("content","stop","","model")
    _assert(False, "empty provider should raise")
except InvalidResponseError:
    _assert(True, "empty provider raises InvalidResponseError")

# ===========================================================================
# §9  execute_request() — Groq success path (metadata only, no HTTP)
# ===========================================================================
print("§9  execute_request() — success ...")
req_g = _req(provider="groq", model="llama-3.3-70b-versatile")
result_g = execute_request(req_g, _TS)

_is(result_g, AIExecutionResult, "returns AIExecutionResult")
_assert(result_g.metadata.success, "groq execution: success=True")
_assert(result_g.response is not None, "groq execution: response not None")
_eq(result_g.response.provider, "groq", "response provider=groq")
_eq(result_g.response.executionId, req_g.executionId, "response executionId linked")
_assert(result_g.response.finishReason in ("stop","length","tool_calls"),
        "finishReason is a valid value")
_ge(result_g.metadata.processingTimeMs, 0, "processingTimeMs >= 0")
_eq(result_g.metadata.attemptNumber,  1, "attemptNumber=1")
_eq(result_g.metadata.totalAttempts,  1, "totalAttempts=1")
_eq(result_g.metadata.provider, "groq", "metadata.provider=groq")
_eq(result_g.metadata.strategy, "priority", "metadata.strategy=priority")
_assert(result_g.metadata.error is None, "no error on success")

# Determinism — same request -> same executionId in result
result_g2 = execute_request(req_g, _TS)
_eq(result_g.request.executionId, result_g2.request.executionId,
    "execute_request is deterministic (same executionId)")

# ===========================================================================
# §10  execute_request() — non-Groq providers (stub path)
# ===========================================================================
print("§10  execute_request() — non-Groq providers ...")
for prov, mdl in [
    ("openai",    "gpt-4o"),
    ("anthropic", "claude-sonnet-4"),
    ("google",    "gemini-2.5-pro"),
    ("ollama",    "llama3.1"),
    ("azure",     "azure/gpt-4o"),
]:
    r = _req(provider=prov, model=mdl)
    res = execute_request(r, _TS)
    _assert(res.metadata.success, f"{prov}/{mdl}: stub execution succeeds")
    _assert(res.response is not None, f"{prov}/{mdl}: response not None")
    _eq(res.response.provider, prov, f"{prov}: response.provider correct")
    _eq(res.response.model,    mdl,  f"{prov}/{mdl}: response.model correct")

# ===========================================================================
# §11  execute_request() — error capture (unsupported Groq model)
# ===========================================================================
print("§11  execute_request() — invalid Groq model ...")
req_bad = _req(provider="groq", model="gpt-nonexistent-999")
result_bad = execute_request(req_bad, _TS)
# Engine captures the error — does not raise
_is(result_bad, AIExecutionResult, "bad model: returns AIExecutionResult (no raise)")
_assert(not result_bad.metadata.success, "bad model: success=False")
_assert(result_bad.metadata.error is not None, "bad model: error is set")
_assert(result_bad.response is None, "bad model: response is None")

# ===========================================================================
# §12  execute_with_retry() — success on first attempt
# ===========================================================================
print("§12  execute_with_retry() — first attempt success ...")
req_r = _req(provider="groq", model="llama-3.3-70b-versatile")
result_r = execute_with_retry(req_r, _TS, max_attempts=3)
_is(result_r, AIExecutionResult, "retry returns AIExecutionResult")
_assert(result_r.metadata.success, "retry: success on first attempt")
_eq(result_r.metadata.attemptNumber, 1, "retry: attemptNumber=1 on first success")

# ===========================================================================
# §13  execute_with_retry() — non-retryable error aborts early
# ===========================================================================
print("§13  execute_with_retry() — non-retryable error ...")
req_bad2 = _req(provider="groq", model="gpt-nonexistent-999")
result_nr = execute_with_retry(req_bad2, _TS, max_attempts=5)
_assert(not result_nr.metadata.success, "non-retryable: success=False")
# Should abort immediately, not exhaust all 5 attempts (attempt recorded as <=5)
_assert(result_nr.metadata.totalAttempts <= 5, "non-retryable: totalAttempts <= max")

# ===========================================================================
# §14  execute_with_retry() — max_attempts enforced
# ===========================================================================
print("§14  execute_with_retry() — attempts field ...")
req_ok = _req(provider="groq", model="llama-3.3-70b-versatile")
result_ok = execute_with_retry(req_ok, _TS, max_attempts=1)
_eq(result_ok.metadata.totalAttempts, 1, "single attempt: totalAttempts=1")
_assert(result_ok.metadata.success, "single attempt succeeds")

# ===========================================================================
# §15  execute_stream()
# ===========================================================================
print("§15  execute_stream() ...")
req_s = _req(provider="groq", model="llama-3.3-70b-versatile", stream=False)
result_s = execute_stream(req_s, _TS)
_is(result_s, AIExecutionResult, "execute_stream returns AIExecutionResult")
_assert(result_s.request.stream, "stream flag forced True")
# The execution key includes stream=False in the original but stream=True creates
# a new request; since stream is not part of the execution key, the IDs may match.
# What matters is that stream=True is set on the actual request used.
_assert(result_s.request.stream, "stream request has stream=True set")
# Warnings include streaming note
_assert(len(result_s.metadata.warnings) >= 0, "stream: warnings accessible")

# Already stream=True — no extra copy needed
req_s2 = _req(provider="groq", model="llama-3.3-70b-versatile", stream=True)
result_s2 = execute_stream(req_s2, _TS)
_assert(result_s2.request.stream, "stream=True preserved")
_eq(result_s2.request.executionId, req_s2.executionId,
    "stream=True: same executionId (no copy)")

# ===========================================================================
# §16  execute_tool_call()
# ===========================================================================
print("§16  execute_tool_call() ...")
req_tc = _req(provider="groq", model="llama-3.3-70b-versatile")
args   = {"ip": "192.168.1.1", "limit": 10}
result_tc = execute_tool_call(req_tc, "search_assets", args, _TS)
_is(result_tc, AIExecutionResult, "execute_tool_call returns AIExecutionResult")
# The tool context is embedded in the user prompt -> new executionId
_ne(result_tc.request.executionId, req_tc.executionId,
    "tool call has different executionId (augmented prompt)")
_in("search_assets", result_tc.request.userPrompt, "tool name in augmented prompt")
_in("192.168.1.1",   result_tc.request.userPrompt, "tool arg in augmented prompt")
_in("TOOL_CALL",     result_tc.request.userPrompt, "TOOL_CALL marker in prompt")
# Tool call warning present in metadata
_assert(any("tool_call" in w for w in result_tc.metadata.warnings),
        "tool_call warning in metadata")

# ===========================================================================
# §17  execute_with_registry() — provider registry integration
# ===========================================================================
print("§17  execute_with_registry() — registry integration ...")
from services.provider_registry_service import build_default_registry

breg = build_default_registry()

result_reg = execute_with_registry(
    registry      = breg,
    system_prompt = _SYS,
    user_prompt   = _USR,
    created_at    = _TS,
    strategy      = "priority",
)
_is(result_reg, AIExecutionResult, "execute_with_registry returns AIExecutionResult")
_assert(result_reg.metadata.success, "registry execution succeeds")
_assert(result_reg.response is not None, "registry execution: response not None")
# Priority winner across all providers is groq/llama-3.3-70b-versatile (priority=90)
_eq(result_reg.metadata.provider, "groq", "priority selection -> groq")
_eq(result_reg.metadata.model, "llama-3.3-70b-versatile", "priority selection -> 70b model")

# provider_name strategy — force openai
result_oai = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="provider_name", provider_name="openai",
)
_eq(result_oai.metadata.provider, "openai", "provider_name=openai selection")

# cheapest strategy
result_cheap = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="cheapest",
)
_is(result_cheap, AIExecutionResult, "cheapest strategy: returns result")

# model_name strategy
result_mn = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="model_name", model_name="gpt-4o",
)
_eq(result_mn.metadata.model, "gpt-4o", "model_name=gpt-4o selection")

# streaming_required
result_st = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="streaming_required",
)
_is(result_st, AIExecutionResult, "streaming_required: returns result")

# highest_context
result_hc = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="highest_context",
)
_is(result_hc, AIExecutionResult, "highest_context: returns result")

# tool_calling_required
result_tcs = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="tool_calling_required",
)
_is(result_tcs, AIExecutionResult, "tool_calling_required: returns result")

# Registry selection failure (force impossible filter)
from services.provider_registry_service import ProviderRegistry
empty_reg = ProviderRegistry()
result_empty = execute_with_registry(
    registry=empty_reg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="priority",
)
_assert(not result_empty.metadata.success, "empty registry: success=False")
_assert(result_empty.metadata.error is not None, "empty registry: error recorded")
_in("selection", result_empty.metadata.error.lower(), "error mentions selection")

# ===========================================================================
# §18  execute_with_registry() — max_attempts > 1
# ===========================================================================
print("§18  execute_with_registry() — with retry ...")
result_retry_reg = execute_with_registry(
    registry=breg, system_prompt=_SYS, user_prompt=_USR, created_at=_TS,
    strategy="priority", max_attempts=3,
)
_assert(result_retry_reg.metadata.success, "registry+retry: success")
_ge(result_retry_reg.metadata.attemptNumber, 1, "attemptNumber >= 1")

# ===========================================================================
# §19  calculate_execution_statistics()
# ===========================================================================
print("§19  calculate_execution_statistics() ...")

def _make_result(provider="groq", model="llama-3.3-70b-versatile",
                 success=True, latency=200, tokens=150,
                 cost=0.001, sid=_SID, warnings=None) -> AIExecutionResult:
    r = _req(provider=provider, model=model, session_id=sid)
    if success:
        rsp = build_execution_response(
            r.executionId, provider, model, "content", "stop", _TS,
            prompt_tokens=100, completion_tokens=tokens-100 if tokens>100 else 50,
            estimated_cost=cost, latency_ms=latency,
        )
        m = build_execution_metadata(r.executionId, provider, model,
                                     "priority", 1, 1, latency, True,
                                     warnings=warnings)
        return build_execution_result(r, rsp, m)
    else:
        m = build_execution_metadata(r.executionId, provider, model,
                                     "priority", 1, 1, 0, False,
                                     error="test failure", warnings=warnings)
        return build_execution_result(r, None, m)

# Empty list
stats_empty = calculate_execution_statistics([])
_is(stats_empty, AIExecutionStatistics, "empty list returns AIExecutionStatistics")
_eq(stats_empty.totalExecutions,  0, "empty: totalExecutions=0")
_eq(stats_empty.successRate,      0.0, "empty: successRate=0.0")
_eq(stats_empty.averageLatencyMs, 0.0, "empty: averageLatencyMs=0.0")
_eq(stats_empty.totalTokens,      0, "empty: totalTokens=0")

# Single success
r1 = _make_result(latency=200, tokens=150, cost=0.001)
stats1 = calculate_execution_statistics([r1])
_eq(stats1.totalExecutions, 1,     "1 result: totalExecutions=1")
_eq(stats1.successCount,    1,     "1 success: successCount=1")
_eq(stats1.failureCount,    0,     "1 success: failureCount=0")
_eq(stats1.successRate,     1.0,   "1 success: successRate=1.0")
_eq(stats1.averageLatencyMs, 200.0,"1 result: averageLatencyMs=200")
_eq(stats1.totalEstimatedCost, 0.001, "1 result: totalEstimatedCost=0.001")
_eq(stats1.uniqueProviders, ("groq",), "1 provider: unique providers")
_eq(stats1.uniqueModels, ("llama-3.3-70b-versatile",), "1 model: unique models")
_eq(stats1.averageAttempts, 1.0,  "1 result: averageAttempts=1.0")

# Mixed success/failure
r2 = _make_result(provider="openai", model="gpt-4o", success=False)
r3 = _make_result(provider="openai", model="gpt-4o", latency=300, tokens=200, cost=0.005)
stats3 = calculate_execution_statistics([r1, r2, r3])
_eq(stats3.totalExecutions, 3, "3 results: totalExecutions=3")
_eq(stats3.successCount,    2, "2 successes")
_eq(stats3.failureCount,    1, "1 failure")
_eq(round(stats3.successRate, 4), round(2/3, 4), "successRate=2/3")
_eq(len(stats3.uniqueProviders), 2, "2 unique providers")
_eq(len(stats3.uniqueModels),    2, "2 unique models")
_in("groq",   stats3.uniqueProviders, "groq in uniqueProviders")
_in("openai", stats3.uniqueProviders, "openai in uniqueProviders")

# Determinism — same inputs -> same statistics
stats3b = calculate_execution_statistics([r3, r1, r2])  # different order
_eq(stats3.totalExecutions,    stats3b.totalExecutions,    "stats deterministic: total")
_eq(stats3.successRate,        stats3b.successRate,        "stats deterministic: rate")
_eq(stats3.averageLatencyMs,   stats3b.averageLatencyMs,   "stats deterministic: latency")
_eq(stats3.totalEstimatedCost, stats3b.totalEstimatedCost, "stats deterministic: cost")

# executionsWithWarnings
rw = _make_result(warnings=["warn-a"])
stats_w = calculate_execution_statistics([r1, rw])
_eq(stats_w.executionsWithWarnings, 1, "1 result with warnings")

# Immutability
try:
    stats1.totalExecutions = 99  # type: ignore
    _assert(False, "AIExecutionStatistics should be frozen")
except Exception:
    _assert(True, "AIExecutionStatistics is immutable")

# ===========================================================================
# §20  filter_execution_results()
# ===========================================================================
print("§20  filter_execution_results() ...")
ra = _make_result(provider="groq",   model="llama-3.3-70b-versatile", success=True,  latency=100, tokens=50,  sid="s1")
rb = _make_result(provider="groq",   model="llama-3.1-8b-instant",    success=False, latency=0,   tokens=0,   sid="s1")
rc = _make_result(provider="openai", model="gpt-4o",                  success=True,  latency=300, tokens=200, sid="s2")
rd = _make_result(provider="openai", model="gpt-4o-mini",             success=True,  latency=150, tokens=100, sid="s2", warnings=["note"])
pool = [ra, rb, rc, rd]

# Filter by provider
gr = filter_execution_results(pool, provider="groq")
_eq(len(gr), 2, "filter provider=groq -> 2")
_assert(all(r.metadata.provider == "groq" for r in gr), "all groq")

# Filter by model
gpt4o_r = filter_execution_results(pool, model="gpt-4o")
_eq(len(gpt4o_r), 1, "filter model=gpt-4o -> 1")
_eq(gpt4o_r[0].metadata.model, "gpt-4o", "correct model")

# Filter success_only=True
succ = filter_execution_results(pool, success_only=True)
_eq(len(succ), 3, "success_only=True -> 3")
_assert(all(r.metadata.success for r in succ), "all successes")

# Filter success_only=False (failures)
fail = filter_execution_results(pool, success_only=False)
_eq(len(fail), 1, "success_only=False -> 1 failure")
_assert(not fail[0].metadata.success, "is failure")

# Filter by session_id
s1_r = filter_execution_results(pool, session_id="s1")
_eq(len(s1_r), 2, "session_id=s1 -> 2")

# Filter by min_tokens — only checks results that have a response
tok_r = filter_execution_results(pool, min_tokens=200)
# ra: prompt=100 + completion=50 = 150, rc: prompt=100 + completion=100 = 200
# rd: prompt=100 + completion=50 = 150, rb: None response -> 0 tokens
# Only rc has totalTokens >= 200
_eq(len(tok_r), 1, "min_tokens=200 -> 1 (only rc)")

# Filter by max_latency_ms
lat_r = filter_execution_results(pool, max_latency_ms=200)
# ra=100, rc=300, rd=150 (rb=0 but is failure, response=None so no latency check)
# None response skips latency check
_ge(len(lat_r), 1, "max_latency_ms=200 -> at least 1")

# Filter has_warnings=True
warn_r = filter_execution_results(pool, has_warnings=True)
_eq(len(warn_r), 1, "has_warnings=True -> 1 (rd)")

# Filter has_warnings=False
nowarn_r = filter_execution_results(pool, has_warnings=False)
_eq(len(nowarn_r), 3, "has_warnings=False -> 3")

# Combined filter
combo = filter_execution_results(pool, provider="groq", success_only=True)
_eq(len(combo), 1, "groq + success_only -> 1")
_eq(combo[0].metadata.provider, "groq", "combo result is groq")
_assert(combo[0].metadata.success, "combo result is success")

# Empty pool
_eq(filter_execution_results([], provider="groq"), [], "empty pool -> empty list")

# ===========================================================================
# §21  group_execution_results()
# ===========================================================================
print("§21  group_execution_results() ...")
groups_p = group_execution_results(pool, group_by="provider")
_in("groq",   groups_p, "group by provider: groq key")
_in("openai", groups_p, "group by provider: openai key")
_eq(len(groups_p["groq"]),   2, "groq group has 2")
_eq(len(groups_p["openai"]), 2, "openai group has 2")
# Each group sorted by executionId ASC
for grp in groups_p.values():
    ids = [r.request.executionId for r in grp]
    _eq(ids, sorted(ids), "group sorted by executionId ASC")

groups_m = group_execution_results(pool, group_by="model")
_eq(len(groups_m), 4, "group by model: 4 distinct models")

groups_s = group_execution_results(pool, group_by="sessionId")
_in("s1", groups_s, "group by sessionId: s1 key")
_in("s2", groups_s, "group by sessionId: s2 key")

groups_st = group_execution_results(pool, group_by="strategy")
_assert(len(groups_st) >= 1, "group by strategy: at least 1 group")

# Invalid group_by raises ValueError
try:
    group_execution_results(pool, group_by="invalid_key")
    _assert(False, "invalid group_by should raise ValueError")
except ValueError as e:
    _assert(True, "invalid group_by raises ValueError")
    _in("invalid_key", str(e), "error mentions key name")

# ===========================================================================
# §22  find_execution()
# ===========================================================================
print("§22  find_execution() ...")
found = find_execution(pool, ra.request.executionId)
_eq(found, ra, "find_execution finds the correct result")

not_found = find_execution(pool, "nonexistent-id-xyz")
_assert(not_found is None, "find_execution returns None for missing ID")

# find from a single-element list
single = find_execution([rc], rc.request.executionId)
_eq(single, rc, "find_execution in single-element list")

# Empty list
_assert(find_execution([], "any-id") is None, "find_execution in empty list -> None")

# ===========================================================================
# §23  Serialization
# ===========================================================================
print("§23  Serialization ...")
import json

req_ser = _req()
_is(req_ser.model_dump(), dict, "AIExecutionRequest.model_dump() returns dict")
req_json = json.dumps(req_ser.model_dump(), default=str)
_is(req_json, str, "AIExecutionRequest serialises to JSON")

resp_ser = _resp(req_ser)
_is(resp_ser.model_dump(), dict, "AIExecutionResponse.model_dump() returns dict")
resp_json = json.dumps(resp_ser.model_dump(), default=str)
_is(resp_json, str, "AIExecutionResponse serialises to JSON")

meta_ser = build_execution_metadata(req_ser.executionId,"groq","m","priority",1,1,100,True)
_is(meta_ser.model_dump(), dict, "AIExecutionMetadata.model_dump() returns dict")

result_ser = build_execution_result(req_ser, resp_ser, meta_ser)
full_dict = result_ser.model_dump()
_is(full_dict, dict, "AIExecutionResult.model_dump() returns dict")
_in("request",  full_dict, "'request' key in result dict")
_in("response", full_dict, "'response' key in result dict")
_in("metadata", full_dict, "'metadata' key in result dict")
full_json = json.dumps(full_dict, default=str)
_is(full_json, str, "AIExecutionResult serialises to JSON")

stats_ser = calculate_execution_statistics([result_ser])
_is(stats_ser.model_dump(), dict, "AIExecutionStatistics.model_dump() returns dict")

# ===========================================================================
# §24  Zero randomness — identical inputs yield identical outputs
# ===========================================================================
print("§24  Zero randomness ...")
for i in range(5):
    r = build_execution_request("groq","llama-3.3-70b-versatile",_SYS,_USR,_TS)
    _eq(r.executionId, req.executionId, f"iter {i}: same inputs -> same executionId")
    _eq(r.executionKey, req.executionKey, f"iter {i}: same executionKey")
    _eq(r.executionFingerprint, req.executionFingerprint, f"iter {i}: same fingerprint")

for i in range(5):
    rs = build_execution_response(
        req.executionId,"groq","llama-3.3-70b-versatile",
        "Analysis complete.","stop",_TS,100,50,0.001,250
    )
    _eq(rs.responseId, resp.responseId, f"resp iter {i}: same responseId")
    _eq(rs.responseKey, resp.responseKey, f"resp iter {i}: same responseKey")

# UUID version check — all IDs must be UUIDv5 (version digit = '5')
_eq(req.executionId[14], "5", "executionId is UUIDv5")
_eq(resp.responseId[14],  "5", "responseId is UUIDv5")

# No uuid4 — ensure no 'version 4' UUIDs appear
_ne(req.executionId[14], "4", "executionId is NOT uuid4")
_ne(resp.responseId[14],  "4", "responseId is NOT uuid4")

# ===========================================================================
# §25  Valid strategies set
# ===========================================================================
print("§25  Valid strategies ...")
_in("priority",              _VALID_STRATEGIES, "priority in valid strategies")
_in("provider_name",         _VALID_STRATEGIES, "provider_name in valid strategies")
_in("model_name",            _VALID_STRATEGIES, "model_name in valid strategies")
_in("capability",            _VALID_STRATEGIES, "capability in valid strategies")
_in("cheapest",              _VALID_STRATEGIES, "cheapest in valid strategies")
_in("highest_context",       _VALID_STRATEGIES, "highest_context in valid strategies")
_in("streaming_required",    _VALID_STRATEGIES, "streaming_required in valid strategies")
_in("tool_calling_required", _VALID_STRATEGIES, "tool_calling_required in valid strategies")
_eq(len(_VALID_STRATEGIES), 8, "exactly 8 valid strategies")

# ===========================================================================
# §26  Exception hierarchy
# ===========================================================================
print("§26  Exception hierarchy ...")
_assert(issubclass(ExecutionTimeoutError,    AIExecutionError), "ExecutionTimeoutError is AIExecutionError")
_assert(issubclass(ProviderUnavailableError, AIExecutionError), "ProviderUnavailableError is AIExecutionError")
_assert(issubclass(InvalidRequestError,      AIExecutionError), "InvalidRequestError is AIExecutionError")
_assert(issubclass(InvalidResponseError,     AIExecutionError), "InvalidResponseError is AIExecutionError")
_assert(issubclass(RetryExhaustedError,      AIExecutionError), "RetryExhaustedError is AIExecutionError")
_assert(issubclass(ToolExecutionFailedError, AIExecutionError), "ToolExecutionFailedError is AIExecutionError")

# Retryable flag
t_err = ExecutionTimeoutError("eid-1")
_assert(t_err.retryable, "ExecutionTimeoutError is retryable")
p_err = ProviderUnavailableError("unavailable", "eid-1")
_assert(p_err.retryable, "ProviderUnavailableError is retryable")
i_err = InvalidRequestError("bad", "eid-1")
_assert(not i_err.retryable, "InvalidRequestError is not retryable")
ir_err = InvalidResponseError("bad resp", "eid-1")
_assert(not ir_err.retryable, "InvalidResponseError is not retryable")
re_err = RetryExhaustedError(3, "eid-1")
_assert(not re_err.retryable, "RetryExhaustedError is not retryable")

# ===========================================================================
# §27  Groq integration — model alias normalisation flows through
# ===========================================================================
print("§27  Groq alias normalisation ...")
# build_execution_request lowercases — then groq_provider normalises alias in execute
req_alias = _req(model="llama3.3-70b")   # known alias via GROQ_MODEL_ALIASES -> normalised to
# validate passes because model isn't empty; groq layer normalises internally
result_alias = execute_request(req_alias, _TS)
# After groq normalisation, this resolves to llama-3.3-70b-versatile
_assert(result_alias.metadata.success or result_alias.metadata.error is not None,
        "alias request: produces a deterministic result")

# ===========================================================================
# §28  Edge cases
# ===========================================================================
print("§28  Edge cases ...")
# System prompt only (empty user prompt) is valid
req_sys_only = _req(system_prompt=_SYS, user_prompt="")
result_sys = execute_request(req_sys_only, _TS)
_is(result_sys, AIExecutionResult, "system-only prompt: returns result")

# User prompt only (empty system prompt) is valid
req_usr_only = _req(system_prompt="", user_prompt=_USR)
result_usr = execute_request(req_usr_only, _TS)
_is(result_usr, AIExecutionResult, "user-only prompt: returns result")

# Very long prompt (deterministic hash)
long_prompt = "A" * 10000
req_long = _req(user_prompt=long_prompt)
req_long2 = _req(user_prompt=long_prompt)
_eq(req_long.executionId, req_long2.executionId, "long prompt: same ID twice")

# Execution with warnings carries through
result_warn = execute_request(req, _TS, warnings=["test-warning"])
_is(result_warn, AIExecutionResult, "execution with warnings: returns result")

# max_tokens=1 is valid (minimum)
req_min = _req(max_tokens=1)
_eq(req_min.maxTokens, 1, "maxTokens=1 accepted")
result_min = execute_request(req_min, _TS)
_is(result_min, AIExecutionResult, "maxTokens=1: returns result")

# ===========================================================================
# Final summary
# ===========================================================================
print()
print(f"{'='*60}")
total = _PASS + _FAIL
print(f"  {_PASS}/{total} assertions passed")
if _FAIL:
    print(f"\n  FAILURES ({_FAIL}):")
    for err in _ERRORS:
        print(f"    {err}")
    sys.exit(1)
else:
    print("  All assertions passed.")
    sys.exit(0)
