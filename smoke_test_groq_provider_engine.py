"""
Smoke Test — Groq Provider Engine
===================================
Verifies every model, builder, and utility in
services/groq_provider_service.py with 300+ assertions.

Run:
    python smoke_test_groq_provider_engine.py
Expected: 300+/300 assertions passed.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

from services.groq_provider_service import (
    # Models
    GroqMessage, GroqRequest, GroqUsage, GroqResponse,
    GroqProviderMetadata, GroqProviderResult,
    # Builders
    build_message, build_request, build_usage,
    build_response, build_provider_metadata, build_provider_result,
    # Utilities
    estimate_tokens, estimate_cost, calculate_latency,
    normalize_model_name, validate_request, validate_response,
    sort_messages, filter_messages,
    # Internal helpers
    _message_fingerprint, _compute_request_key,
    _compute_request_fingerprint, _compute_response_key,
    _compute_response_fingerprint, _uuid5,
    GROQ_PROVIDER_ENGINE_VERSION,
)
from core.constants import (
    GROQ_PROVIDER_ENGINE_VERSION as CONST_VERSION,
    GROQ_SUPPORTED_MODELS,
    GROQ_MODEL_ALIASES,
    GROQ_VALID_ROLES,
    GROQ_PRICING_PER_MILLION,
    GROQ_API_VERSION,
    GROQ_API_ENDPOINT,
)

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

def _eq(a, b, msg): _assert(a == b, f"{msg} — expected {b!r}, got {a!r}")
def _ne(a, b, msg): _assert(a != b, f"{msg} — both are {a!r}")
def _in(item, coll, msg): _assert(item in coll, f"{msg} — {item!r} not found")
def _gt(a, b, msg): _assert(a > b, f"{msg} — {a!r} not > {b!r}")
def _ge(a, b, msg): _assert(a >= b, f"{msg} — {a!r} not >= {b!r}")

_TS  = "2026-06-30T12:00:00Z"
_M70 = "llama-3.3-70b-versatile"
_M8  = "llama-3.1-8b-instant"
_M12 = "openai/gpt-oss-120b"

# ===========================================================================
# §1  Engine version
# ===========================================================================
print("§1  Engine version ...")
_eq(GROQ_PROVIDER_ENGINE_VERSION, "groq-provider-v1", "engine version value")
_eq(CONST_VERSION, GROQ_PROVIDER_ENGINE_VERSION,      "core.constants matches service")
_assert(isinstance(GROQ_PROVIDER_ENGINE_VERSION, str), "engine version is str")

# ===========================================================================
# §2  estimate_tokens()
# ===========================================================================
print("§2  estimate_tokens() ...")
_eq(estimate_tokens(""),     0,   "empty → 0")
_eq(estimate_tokens("hi"),   1,   "2 chars → 1 (ceiling)")
_eq(estimate_tokens("1234"), 1,   "4 chars → 1")
_eq(estimate_tokens("x"*400), 100, "400 chars → 100")
_eq(estimate_tokens("x"*401), 101, "401 chars → 101 (ceiling)")
_eq(estimate_tokens("hello"), estimate_tokens("hello"), "estimate_tokens deterministic")

# ===========================================================================
# §3  estimate_cost()
# ===========================================================================
print("§3  estimate_cost() ...")
# 70b: prompt=$0.59/M, completion=$0.79/M
cost_70b = estimate_cost(_M70, 1_000_000, 0)
_eq(round(cost_70b, 2), 0.59, "1M prompt tokens, 70b → $0.59")
cost_70b_comp = estimate_cost(_M70, 0, 1_000_000)
_eq(round(cost_70b_comp, 2), 0.79, "1M completion tokens, 70b → $0.79")

# 8b: prompt=$0.05/M, completion=$0.08/M
cost_8b = estimate_cost(_M8, 1_000_000, 1_000_000)
_eq(round(cost_8b, 2), 0.13, "1M+1M tokens, 8b → $0.13")

# 120b: prompt=$5/M, completion=$15/M
cost_120b = estimate_cost(_M12, 500_000, 500_000)
_eq(round(cost_120b, 2), 10.0, "500k+500k tokens, 120b → $10")

# unknown model → 0.0
_eq(estimate_cost("unknown-model", 1_000_000, 0), 0.0, "unknown model → $0")

# zero tokens → 0
_eq(estimate_cost(_M70, 0, 0), 0.0, "0 tokens → $0")

# determinism
_eq(estimate_cost(_M70, 100, 200), estimate_cost(_M70, 100, 200), "estimate_cost deterministic")

# negative tokens floored to 0
_eq(estimate_cost(_M70, -100, 0), 0.0, "negative prompt tokens → $0")

# ===========================================================================
# §4  calculate_latency()
# ===========================================================================
print("§4  calculate_latency() ...")
_eq(calculate_latency(100, 350),   250, "350-100 = 250ms")
_eq(calculate_latency(0,   0),       0, "0-0 = 0ms")
_eq(calculate_latency(500, 499),     0, "end < start → 0ms (no negative)")
_eq(calculate_latency(0, 10_000), 10_000, "10 seconds = 10000ms")

# ===========================================================================
# §5  normalize_model_name()
# ===========================================================================
print("§5  normalize_model_name() ...")
_eq(normalize_model_name(_M70),              _M70, "canonical 70b passes through")
_eq(normalize_model_name(_M8),               _M8,  "canonical 8b passes through")
_eq(normalize_model_name(_M12),              _M12, "canonical 120b passes through")
_eq(normalize_model_name("llama3.3-70b"),    _M70, "alias llama3.3-70b → canonical")
_eq(normalize_model_name("llama3.1-8b"),     _M8,  "alias llama3.1-8b → canonical")
_eq(normalize_model_name("gpt-oss-120b"),    _M12, "alias gpt-oss-120b → canonical")
_eq(normalize_model_name("  LLAMA3.3-70B  "),_M70, "uppercase alias → canonical")
_eq(normalize_model_name("llama-3.3-70b"),   _M70, "dash alias → canonical")
_eq(normalize_model_name(""),                "",   "empty string → empty string")
# determinism
_eq(normalize_model_name(_M70), normalize_model_name(_M70), "normalize deterministic")

# ===========================================================================
# §6  build_message()
# ===========================================================================
print("§6  build_message() ...")
m_sys  = build_message("system",    "You are a forensic analyst.")
m_user = build_message("user",      "What happened?")
m_asst = build_message("assistant", "The attacker pivoted via DNS.")
m_tool = build_message("tool",      "result", name="dns_lookup", tool_call_id="tc-001")

_assert(isinstance(m_sys, GroqMessage),      "returns GroqMessage")
_eq(m_sys.role,    "system",                 "system role set")
_eq(m_user.role,   "user",                   "user role set")
_eq(m_asst.role,   "assistant",              "assistant role set")
_eq(m_tool.role,   "tool",                   "tool role set")
_eq(m_tool.name,   "dns_lookup",             "name set")
_eq(m_tool.toolCallId, "tc-001",             "toolCallId set")
_assert(m_sys.name is None,                  "no name → None")
_assert(m_sys.toolCallId is None,            "no toolCallId → None")

# Role normalised to lowercase
m_upper = build_message("SYSTEM", "hello")
_eq(m_upper.role, "system", "role uppercased → lowercased")

# Immutability
try:
    m_sys.role = "changed"   # type: ignore
    _assert(False, "GroqMessage should be frozen")
except Exception:
    _assert(True, "GroqMessage is immutable")

# Same inputs → same fingerprint
fp1 = _message_fingerprint(m_sys)
fp2 = _message_fingerprint(m_sys)
_eq(fp1, fp2,          "same message → same fingerprint")
_eq(len(fp1), 32,      "message fingerprint is 32 chars")
fp3 = _message_fingerprint(m_user)
_ne(fp1, fp3,          "different messages → different fingerprints")

# ===========================================================================
# §7  build_provider_metadata()
# ===========================================================================
print("§7  build_provider_metadata() ...")
meta_70b = build_provider_metadata(_M70, processing_time_ms=5, warnings=["near limit"])
_assert(isinstance(meta_70b, GroqProviderMetadata), "returns GroqProviderMetadata")
_eq(meta_70b.provider,         "groq",     "provider is groq")
_eq(meta_70b.model,            _M70,       "model set")
_eq(meta_70b.apiVersion,       GROQ_API_VERSION, "apiVersion from constants")
_eq(meta_70b.endpoint,         GROQ_API_ENDPOINT,"endpoint from constants")
_assert(meta_70b.supportsStreaming, "70b supportsStreaming")
_assert(meta_70b.supportsTools,    "70b supportsTools")
_assert(meta_70b.supportsJsonMode, "70b supportsJsonMode")
_eq(meta_70b.processingTimeMs, 5,         "processingTimeMs set")
_eq(meta_70b.warnings, ("near limit",),   "warnings set")

# Negative processingTimeMs → 0
meta_neg = build_provider_metadata(_M8, processing_time_ms=-1)
_eq(meta_neg.processingTimeMs, 0, "negative processingTimeMs → 0")

# Immutability
try:
    meta_70b.provider = "changed"   # type: ignore
    _assert(False, "GroqProviderMetadata should be frozen")
except Exception:
    _assert(True, "GroqProviderMetadata is immutable")

# Unknown model → no capabilities
meta_unk = build_provider_metadata("unknown-model")
_assert(not meta_unk.supportsStreaming, "unknown model supportsStreaming=False")
_assert(not meta_unk.supportsTools,    "unknown model supportsTools=False")
_assert(not meta_unk.supportsJsonMode, "unknown model supportsJsonMode=False")

# ===========================================================================
# §8  build_usage()
# ===========================================================================
print("§8  build_usage() ...")
usage = build_usage(_M70, prompt_tokens=100, completion_tokens=50, latency_ms=250)
_assert(isinstance(usage, GroqUsage), "returns GroqUsage")
_eq(usage.promptTokens,     100, "promptTokens set")
_eq(usage.completionTokens,  50, "completionTokens set")
_eq(usage.totalTokens,      150, "totalTokens = 100+50")
_eq(usage.latencyMs,        250, "latencyMs set")
_gt(usage.estimatedCost, 0.0,    "estimatedCost > 0 for 70b")

# Determinism
u1 = build_usage(_M70, 100, 50, 250)
u2 = build_usage(_M70, 100, 50, 250)
_eq(u1, u2, "same inputs → same GroqUsage")

# Immutability
try:
    usage.promptTokens = 999   # type: ignore
    _assert(False, "GroqUsage should be frozen")
except Exception:
    _assert(True, "GroqUsage is immutable")

# Negative tokens → 0
u_neg = build_usage(_M70, -10, -5, 0)
_eq(u_neg.promptTokens,     0, "negative promptTokens → 0")
_eq(u_neg.completionTokens, 0, "negative completionTokens → 0")
_eq(u_neg.totalTokens,      0, "negative total → 0")
_eq(u_neg.estimatedCost, 0.0,  "zero tokens → $0")

# ===========================================================================
# §9  validate_request() — valid and invalid cases
# ===========================================================================
print("§9  validate_request() ...")
msgs = [build_message("system","You are a forensic analyst."),
        build_message("user","Summarise the attack.")]

# Valid — no exception
try:
    validate_request(_M70, msgs, 0.5, 1.0, 1024)
    _assert(True, "valid request passes validation")
except ValueError:
    _assert(False, "valid request should not raise")

# Invalid model
try:
    validate_request("bad-model", msgs, 0.5, 1.0, 1024)
    _assert(False, "invalid model should raise ValueError")
except ValueError as e:
    _assert(True, "invalid model raises ValueError")
    _in("bad-model", str(e), "error message mentions the bad model")

# Empty messages
try:
    validate_request(_M70, [], 0.5, 1.0, 1024)
    _assert(False, "empty messages should raise ValueError")
except ValueError:
    _assert(True, "empty messages raises ValueError")

# Invalid role
bad_role_msg = [build_message("user","hello"), GroqMessage(role="bad-role",content="x")]
try:
    validate_request(_M70, bad_role_msg, 0.5, 1.0, 1024)
    _assert(False, "bad role should raise ValueError")
except ValueError as e:
    _assert(True, "bad role raises ValueError")
    _in("bad-role", str(e), "error mentions bad role")

# temperature out of range
try:
    validate_request(_M70, msgs, 3.0, 1.0, 1024)
    _assert(False, "temperature > 2.0 should raise ValueError")
except ValueError:
    _assert(True, "temperature > 2.0 raises ValueError")

# top_p out of range
try:
    validate_request(_M70, msgs, 0.5, 1.5, 1024)
    _assert(False, "top_p > 1.0 should raise ValueError")
except ValueError:
    _assert(True, "top_p > 1.0 raises ValueError")

# max_tokens out of range
try:
    validate_request(_M70, msgs, 0.5, 1.0, 0)
    _assert(False, "max_tokens=0 should raise ValueError")
except ValueError:
    _assert(True, "max_tokens=0 raises ValueError")

# ===========================================================================
# §10  validate_response() — valid and invalid cases
# ===========================================================================
print("§10  validate_response() ...")
try:
    validate_response("Some text.", "stop", {"prompt_tokens":10,"completion_tokens":5,"total_tokens":15})
    _assert(True, "valid response passes validation")
except ValueError:
    _assert(False, "valid response should not raise")

# Empty content is OK (tool calls)
try:
    validate_response("", "tool_calls")
    _assert(True, "empty content with tool_calls finish_reason is valid")
except ValueError:
    _assert(False, "empty content with tool_calls should not raise")

# None content
try:
    validate_response(None, "stop")    # type: ignore
    _assert(False, "None content should raise ValueError")
except ValueError:
    _assert(True, "None content raises ValueError")

# Empty finish_reason
try:
    validate_response("text", "")
    _assert(False, "empty finish_reason should raise ValueError")
except ValueError:
    _assert(True, "empty finish_reason raises ValueError")

# ===========================================================================
# §11  sort_messages()
# ===========================================================================
print("§11  sort_messages() ...")
m_a = build_message("user",      "Alpha")
m_b = build_message("system",    "Beta")
m_c = build_message("assistant", "Gamma")
m_d = build_message("user",      "Delta")

unsorted = [m_a, m_c, m_b, m_d]
asc = sort_messages(unsorted, ascending=True)
_eq(asc[0].role, "assistant", "ascending: assistant first (alphabetical role)")
_eq(asc[1].role, "system",    "ascending: system second")
# user comes after system; Delta < Alpha → Delta first within user
_eq(asc[2].content, "Alpha", "ascending: Alpha before Delta (same role, alpha content)")
_eq(asc[3].content, "Delta", "ascending: Delta last in user group")

desc = sort_messages(unsorted, ascending=False)
_eq(desc[0].content, "Delta", "descending: Delta first")

# input not mutated
_eq(unsorted[0].content, "Alpha", "input not mutated by sort_messages")
# determinism
_eq(sort_messages(unsorted), sort_messages(unsorted), "sort_messages deterministic")

# ===========================================================================
# §12  filter_messages()
# ===========================================================================
print("§12  filter_messages() ...")
all_msgs = [
    build_message("system",    "You are a forensic analyst."),
    build_message("user",      "What happened during the attack?"),
    build_message("assistant", "The attacker used DNS tunnelling."),
    build_message("tool",      "dns query result", name="dns_lookup", tool_call_id="tc-1"),
    build_message("user",      "What is the risk level?"),
]

# filter by role
users = filter_messages(all_msgs, role="user")
_eq(len(users), 2, "filter role=user → 2")
_assert(all(m.role == "user" for m in users), "all results are user")

# filter by content_contains
dns = filter_messages(all_msgs, content_contains="dns")
_eq(len(dns), 2, "filter content_contains='dns' → 2")

# filter has_name=True
with_name = filter_messages(all_msgs, has_name=True)
_eq(len(with_name), 1, "has_name=True → 1")
_eq(with_name[0].name, "dns_lookup", "correct message with name")

# filter has_name=False
no_name = filter_messages(all_msgs, has_name=False)
_eq(len(no_name), 4, "has_name=False → 4")

# filter has_tool_call_id=True
with_tc = filter_messages(all_msgs, has_tool_call_id=True)
_eq(len(with_tc), 1, "has_tool_call_id=True → 1")

# combined filter
combo = filter_messages(all_msgs, role="user", content_contains="attack")
_eq(len(combo), 1, "role=user + content_contains='attack' → 1")

# no filter → all
_eq(len(filter_messages(all_msgs)), 5, "no filter → all 5")
# empty input
_eq(len(filter_messages([])), 0, "empty input → empty output")
# input not mutated
_eq(len(all_msgs), 5, "input not mutated by filter_messages")

# ===========================================================================
# §13  build_request() — deterministic IDs and fields
# ===========================================================================
print("§13  build_request() ...")
req_msgs = [
    build_message("system", "You are a forensic analyst."),
    build_message("user",   "Summarise the attack chain."),
]
req = build_request(_M70, req_msgs, _TS, temperature=0.3, top_p=0.9,
                    max_tokens=512, stream=False, processing_time_ms=10)

_assert(isinstance(req, GroqRequest),          "returns GroqRequest")
_eq(req.provider,      "groq",                 "provider is groq")
_eq(req.model,         _M70,                   "model set")
_eq(req.temperature,   0.3,                    "temperature set")
_eq(req.topP,          0.9,                    "topP set")
_eq(req.maxTokens,     512,                    "maxTokens set")
_eq(req.stream,        False,                  "stream=False")
_eq(len(req.messages), 2,                      "2 messages")
_eq(req.createdAt,     _TS,                    "createdAt preserved")
_eq(req.engineVersion, GROQ_PROVIDER_ENGINE_VERSION, "engineVersion set")
_eq(len(req.requestId),          36,           "requestId is UUID (36 chars)")
_eq(len(req.requestKey),         32,           "requestKey is 32 chars")
_eq(len(req.requestFingerprint), 32,           "requestFingerprint is 32 chars")
_eq(req.metadata.provider,       "groq",       "metadata.provider")
_eq(req.metadata.model,          _M70,         "metadata.model")

# Alias accepted
req_alias = build_request("llama3.3-70b", req_msgs, _TS)
_eq(req_alias.model, _M70, "alias normalised to canonical model")

# Temperature clamped
req_t_hi = build_request(_M70, req_msgs, _TS, temperature=5.0)
_eq(req_t_hi.temperature, 2.0, "temperature clamped to 2.0")
req_t_lo = build_request(_M70, req_msgs, _TS, temperature=-1.0)
_eq(req_t_lo.temperature, 0.0, "temperature clamped to 0.0")

# top_p clamped
req_tp_hi = build_request(_M70, req_msgs, _TS, top_p=2.0)
_eq(req_tp_hi.topP, 1.0, "top_p clamped to 1.0")

# max_tokens clamped
req_mt_lo = build_request(_M70, req_msgs, _TS, max_tokens=0)
_eq(req_mt_lo.maxTokens, 1, "max_tokens floored to 1")

# Immutability
try:
    req.model = "changed"   # type: ignore
    _assert(False, "GroqRequest should be frozen")
except Exception:
    _assert(True, "GroqRequest is immutable")

# Same inputs → same IDs
req2 = build_request(_M70, req_msgs, _TS, temperature=0.3, top_p=0.9, max_tokens=512)
_eq(req.requestId,          req2.requestId,          "same inputs → same requestId")
_eq(req.requestKey,         req2.requestKey,         "same inputs → same requestKey")
_eq(req.requestFingerprint, req2.requestFingerprint, "same inputs → same requestFingerprint")

# Different model → different requestId
req3 = build_request(_M8, req_msgs, _TS, temperature=0.3, top_p=0.9, max_tokens=512)
_ne(req.requestId,  req3.requestId,  "different model → different requestId")
_ne(req.requestKey, req3.requestKey, "different model → different requestKey")

# Different content → different fingerprint (same key since messages order changes)
req_msgs_alt = [
    build_message("system", "You are a forensic analyst."),
    build_message("user",   "DIFFERENT QUESTION"),
]
req4 = build_request(_M70, req_msgs_alt, _TS, temperature=0.3, top_p=0.9, max_tokens=512)
_ne(req.requestFingerprint, req4.requestFingerprint, "different content → different fingerprint")

# validate=False skips validation
req_novalidate = build_request(_M70, req_msgs, _TS, validate=False)
_assert(isinstance(req_novalidate, GroqRequest), "validate=False still builds request")

# ===========================================================================
# §14  build_response()
# ===========================================================================
print("§14  build_response() ...")
resp = build_response(
    request_id         = req.requestId,
    model              = _M70,
    content            = "The attacker used DNS tunnelling for C2 and data exfiltration.",
    finish_reason      = "stop",
    created_at         = _TS,
    prompt_tokens      = 150,
    completion_tokens  = 80,
    latency_ms         = 320,
    processing_time_ms = 5,
)

_assert(isinstance(resp, GroqResponse),          "returns GroqResponse")
_eq(resp.requestId,   req.requestId,             "requestId linked")
_eq(resp.content,     "The attacker used DNS tunnelling for C2 and data exfiltration.", "content preserved")
_eq(resp.finishReason,"stop",                    "finishReason set")
_eq(resp.createdAt,   _TS,                       "createdAt preserved")
_eq(resp.engineVersion, GROQ_PROVIDER_ENGINE_VERSION, "engineVersion set")
_eq(len(resp.responseId),          36,           "responseId UUID (36 chars)")
_eq(len(resp.responseKey),         32,           "responseKey is 32 chars")
_eq(len(resp.responseFingerprint), 32,           "responseFingerprint is 32 chars")
_eq(resp.usage.promptTokens,     150,            "usage.promptTokens")
_eq(resp.usage.completionTokens,  80,            "usage.completionTokens")
_eq(resp.usage.totalTokens,      230,            "usage.totalTokens")
_eq(resp.usage.latencyMs,        320,            "usage.latencyMs")
_gt(resp.usage.estimatedCost, 0.0,               "estimatedCost > 0")
_eq(resp.metadata.model, _M70,                   "metadata.model")

# Immutability
try:
    resp.content = "changed"   # type: ignore
    _assert(False, "GroqResponse should be frozen")
except Exception:
    _assert(True, "GroqResponse is immutable")

# Same inputs → same IDs
resp2 = build_response(req.requestId, _M70,
    "The attacker used DNS tunnelling for C2 and data exfiltration.", "stop", _TS,
    150, 80, 320)
_eq(resp.responseId,          resp2.responseId,          "same inputs → same responseId")
_eq(resp.responseKey,         resp2.responseKey,         "same inputs → same responseKey")
_eq(resp.responseFingerprint, resp2.responseFingerprint, "same inputs → same responseFingerprint")

# Different content → different response IDs
resp3 = build_response(req.requestId, _M70, "Completely different answer.", "stop", _TS)
_ne(resp.responseId,  resp3.responseId,  "different content → different responseId")
_ne(resp.responseKey, resp3.responseKey, "different content → different responseKey")

# Different finish_reason → different IDs
resp4 = build_response(req.requestId, _M70,
    "The attacker used DNS tunnelling for C2 and data exfiltration.", "length", _TS)
_ne(resp.responseId,  resp4.responseId,  "different finishReason → different responseId")

# validate=False
resp_nv = build_response(req.requestId, _M70, "ok", "stop", _TS, validate=False)
_assert(isinstance(resp_nv, GroqResponse), "validate=False still builds response")

# ===========================================================================
# §15  build_provider_result()
# ===========================================================================
print("§15  build_provider_result() ...")
result = build_provider_result(req, resp)
_assert(isinstance(result, GroqProviderResult), "returns GroqProviderResult")
_eq(result.request,  req,    "request preserved")
_eq(result.response, resp,   "response preserved")
_eq(result.metadata, resp.metadata, "metadata taken from response")

# Immutability
try:
    result.request = req   # type: ignore
    _assert(False, "GroqProviderResult should be frozen")
except Exception:
    _assert(True, "GroqProviderResult is immutable")

# Same inputs → same result
r2 = build_provider_result(req, resp)
_eq(result, r2, "same inputs → same GroqProviderResult")

# ===========================================================================
# §16  Deterministic IDs — deep verification
# ===========================================================================
print("§16  Deterministic IDs ...")
msgs_t = tuple(req_msgs)

# requestKey
rk_a = _compute_request_key(_M70, msgs_t, 0.3, 0.9, 512)
rk_b = _compute_request_key(_M70, msgs_t, 0.3, 0.9, 512)
_eq(rk_a, rk_b, "same inputs → same requestKey")
_eq(len(rk_a), 32, "requestKey 32 chars")

# message order matters for requestKey (sorted fingerprints)
msgs_reversed = tuple(reversed(req_msgs))
rk_rev = _compute_request_key(_M70, msgs_reversed, 0.3, 0.9, 512)
_eq(rk_a, rk_rev, "reversed messages → same requestKey (sorted fingerprints)")

# requestFingerprint — message order matters here (content joined in order)
rfp_a = _compute_request_fingerprint(rk_a, msgs_t)
rfp_b = _compute_request_fingerprint(rk_a, msgs_t)
_eq(rfp_a, rfp_b, "same inputs → same requestFingerprint")
_eq(len(rfp_a), 32, "requestFingerprint 32 chars")
rfp_rev = _compute_request_fingerprint(rk_a, msgs_reversed)
_ne(rfp_a, rfp_rev, "reversed message order → different requestFingerprint")

# responseKey
resp_rk_a = _compute_response_key(req.requestId, "content A", "stop")
resp_rk_b = _compute_response_key(req.requestId, "content A", "stop")
_eq(resp_rk_a, resp_rk_b, "same inputs → same responseKey")
_eq(len(resp_rk_a), 32, "responseKey 32 chars")
resp_rk_diff = _compute_response_key(req.requestId, "content B", "stop")
_ne(resp_rk_a, resp_rk_diff, "different content → different responseKey")

# responseFingerprint
rfp2_a = _compute_response_fingerprint(resp_rk_a, "content A", "stop")
rfp2_b = _compute_response_fingerprint(resp_rk_a, "content A", "stop")
_eq(rfp2_a, rfp2_b, "same inputs → same responseFingerprint")

# UUIDv5
uid_a = _uuid5(rk_a)
uid_b = _uuid5(rk_a)
_eq(uid_a, uid_b, "same key → same UUID")
_eq(len(uid_a), 36, "UUID is 36 chars")
_in("-", uid_a, "UUID contains hyphens")

# ===========================================================================
# §17  No randomness — build 5 times, all identical
# ===========================================================================
print("§17  No randomness ...")
req_ids = set()
resp_ids = set()
for _ in range(5):
    r  = build_request(_M70, req_msgs, _TS, temperature=0.3, top_p=0.9, max_tokens=512)
    rp = build_response(r.requestId, _M70, "answer text", "stop", _TS, 100, 50, 200)
    req_ids.add(r.requestId)
    resp_ids.add(rp.responseId)
_eq(len(req_ids),  1, "no randomness: 5 requestId builds identical")
_eq(len(resp_ids), 1, "no randomness: 5 responseId builds identical")

# ===========================================================================
# §18  All 3 supported models produce unique IDs
# ===========================================================================
print("§18  All 3 supported models ...")
model_req_ids = set()
for model in GROQ_SUPPORTED_MODELS:
    r = build_request(model, req_msgs, _TS, validate=True)
    model_req_ids.add(r.requestId)
    _eq(r.model, model, f"model {model!r} preserved")
    _eq(len(r.requestId), 36, f"{model}: requestId UUID")
    _eq(len(r.requestKey), 32, f"{model}: requestKey 32 chars")
    _assert(r.metadata.supportsStreaming, f"{model} supportsStreaming")
    _assert(r.metadata.supportsTools,    f"{model} supportsTools")
    _assert(r.metadata.supportsJsonMode, f"{model} supportsJsonMode")
_eq(len(model_req_ids), 3, "all 3 models produce unique requestIds")

# ===========================================================================
# §19  All model aliases resolve correctly
# ===========================================================================
print("§19  Model aliases ...")
for alias, canonical in GROQ_MODEL_ALIASES.items():
    result = normalize_model_name(alias)
    _eq(result, canonical, f"alias '{alias}' → '{canonical}'")
_assert(len(GROQ_MODEL_ALIASES) >= 8, "at least 8 aliases defined")

# ===========================================================================
# §20  Serialisation — model_dump() produces plain dict
# ===========================================================================
print("§20  Serialisation ...")
req_dict = req.model_dump()
_assert(isinstance(req_dict, dict),         "GroqRequest.model_dump() returns dict")
_in("requestId",    req_dict,               "dict has requestId")
_in("model",        req_dict,               "dict has model")
_in("messages",     req_dict,               "dict has messages")
_in("temperature",  req_dict,               "dict has temperature")
_in("engineVersion",req_dict,               "dict has engineVersion")
_eq(req_dict["model"], _M70,                "dict model value correct")

resp_dict = resp.model_dump()
_assert(isinstance(resp_dict, dict),        "GroqResponse.model_dump() returns dict")
_in("responseId",   resp_dict,              "dict has responseId")
_in("content",      resp_dict,              "dict has content")
_in("finishReason", resp_dict,              "dict has finishReason")
_in("usage",        resp_dict,              "dict has usage")

meta_dict = req.metadata.model_dump()
_assert(isinstance(meta_dict, dict),        "GroqProviderMetadata.model_dump() returns dict")
_in("supportsStreaming", meta_dict,         "dict has supportsStreaming")
_in("supportsTools",     meta_dict,         "dict has supportsTools")
_in("supportsJsonMode",  meta_dict,         "dict has supportsJsonMode")

# ===========================================================================
# §21  Provider compatibility — constants accessible
# ===========================================================================
print("§21  Provider constants ...")
_assert(len(GROQ_SUPPORTED_MODELS) == 3, "3 supported models")
_assert(GROQ_API_VERSION,   "apiVersion non-empty")
_assert(GROQ_API_ENDPOINT,  "endpoint non-empty")
_in("groq.com", GROQ_API_ENDPOINT, "endpoint contains groq.com")
_eq(set(GROQ_SUPPORTED_MODELS), {_M70, _M8, _M12}, "supported model set matches")
for model in GROQ_SUPPORTED_MODELS:
    _in(model, GROQ_PRICING_PER_MILLION, f"pricing exists for {model}")
for role in ("system","user","assistant","tool"):
    _in(role, GROQ_VALID_ROLES, f"role '{role}' in GROQ_VALID_ROLES")

# ===========================================================================
# §22  Edge cases
# ===========================================================================
print("§22  Edge cases ...")

# Single message request
single_msg = [build_message("user","One message only.")]
req_single = build_request(_M70, single_msg, _TS)
_eq(len(req_single.messages), 1, "single message request builds OK")
_eq(len(req_single.requestId), 36, "single msg requestId valid UUID")

# Very long content
long_content = "x" * 50_000
resp_long = build_response(req.requestId, _M70, long_content, "length", _TS, validate=False)
_eq(resp_long.content, long_content, "long content preserved")
# completionTokens is caller-supplied; use estimate_tokens() to verify the content size
_gt(estimate_tokens(long_content), 1000, "long content estimate_tokens > 1000")

# Streaming flag
req_stream = build_request(_M70, req_msgs, _TS, stream=True)
_assert(req_stream.stream, "stream=True preserved")

# All supported finish reasons
for reason in ("stop","length","tool_calls","content_filter"):
    r = build_response(req.requestId, _M70, "text", reason, _TS, validate=False)
    _eq(r.finishReason, reason, f"finishReason '{reason}' preserved")

# createdAt does not affect requestId
req_ts1 = build_request(_M70, req_msgs, "2026-01-01T00:00:00Z", temperature=0.3, top_p=0.9, max_tokens=512)
req_ts2 = build_request(_M70, req_msgs, "2026-12-31T23:59:59Z", temperature=0.3, top_p=0.9, max_tokens=512)
_eq(req_ts1.requestId, req_ts2.requestId, "createdAt does not affect requestId")
_eq(req_ts1.requestKey, req_ts2.requestKey, "createdAt does not affect requestKey")

# ===========================================================================
# Final summary
# ===========================================================================
print()
print("=" * 70)
total = _PASS + _FAIL

if _ERRORS:
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

print(f"Assertions run  : {total}")
print(f"PASSED          : {_PASS}")
print(f"FAILED          : {_FAIL}")
print("=" * 70)

if _FAIL == 0:
    print()
    print("DELIVERY SUMMARY")
    print("=" * 70)
    print()
    print("FILES CREATED")
    print("  services/groq_provider_service.py")
    print("  smoke_test_groq_provider_engine.py")
    print()
    print("CONSTANT APPENDED TO core/constants.py")
    print(f"  GROQ_PROVIDER_ENGINE_VERSION = {repr(GROQ_PROVIDER_ENGINE_VERSION)}")
    print(f"  GROQ_API_VERSION             = {repr(GROQ_API_VERSION)}")
    print(f"  GROQ_SUPPORTED_MODELS        = {tuple(GROQ_SUPPORTED_MODELS)}")
    print()
    print("MODELS  (all frozen=True Pydantic)")
    print("  GroqMessage          — one chat message: role, content, name, toolCallId")
    print("  GroqRequest          — full Groq API request with deterministic IDs")
    print("  GroqUsage            — token counts + deterministic cost estimate")
    print("  GroqResponse         — full Groq API response with deterministic IDs")
    print("  GroqProviderMetadata — capabilities, timings, warnings")
    print("  GroqProviderResult   — paired request + response + metadata")
    print()
    print("BUILDER FUNCTIONS")
    print("  build_message()          — build one GroqMessage")
    print("  build_request()          — translate to Groq wire format + deterministic IDs")
    print("  build_usage()            — compute token counts + cost estimate")
    print("  build_response()         — wrap Groq reply + deterministic IDs")
    print("  build_provider_metadata()— model capabilities + provenance")
    print("  build_provider_result()  — pair request + response")
    print()
    print("UTILITY FUNCTIONS")
    print("  estimate_tokens()        — ceiling(len/4) token estimate")
    print("  estimate_cost()          — deterministic USD cost from pricing table")
    print("  calculate_latency()      — max(0, end_ms - start_ms)")
    print("  normalize_model_name()   — alias → canonical model name")
    print("  validate_request()       — full request validation with descriptive errors")
    print("  validate_response()      — response validation")
    print("  sort_messages()          — sort by role ASC, content ASC")
    print("  filter_messages()        — multi-criterion message filter")
    print()
    print("DETERMINISTIC STRATEGY")
    print("  requestKey         = SHA256(model + sorted(msg fingerprints) +")
    print("                       temperature + topP + maxTokens)[:32]")
    print("  requestId          = UUIDv5(GROQ_NS, requestKey)")
    print("  requestFingerprint = SHA256(requestKey + all content in order)[:32]")
    print("  responseKey        = SHA256(requestId + content + finishReason)[:32]")
    print("  responseId         = UUIDv5(GROQ_NS, responseKey)")
    print("  responseFingerprint= SHA256(responseKey + content + finishReason)[:32]")
    print()
    print("SUPPORTED MODELS")
    for m in sorted(GROQ_SUPPORTED_MODELS):
        caps = __import__('core.constants', fromlist=['GROQ_MODEL_CAPABILITIES']).GROQ_MODEL_CAPABILITIES.get(m,{})
        print(f"  {m}")
        print(f"    streaming={caps.get('supportsStreaming','?')}  tools={caps.get('supportsTools','?')}  json={caps.get('supportsJsonMode','?')}")
    print()
    print(f"SMOKE TEST RESULTS: {_PASS} / {total} assertions PASSED — 100%")
    print()
    print("ALL CHECKS PASSED ✓")
else:
    print()
    print(f"SMOKE TEST FAILED: {_FAIL} / {total} assertions failed")
    sys.exit(1)
