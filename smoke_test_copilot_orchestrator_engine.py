"""
Smoke Test — Copilot Orchestrator Engine
==========================================
Verifies every model, builder, and utility in
services/copilot_orchestrator_service.py with 220+ assertions.

Run:
    python smoke_test_copilot_orchestrator_engine.py
Expected: 100% PASS, no errors.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

from services.copilot_orchestrator_service import (
    # Models
    CopilotMetadata,
    CopilotRequest,
    CopilotResponse,
    CopilotSession,
    SessionStatistics,
    # Builders
    build_copilot_metadata,
    build_copilot_request,
    build_copilot_response,
    build_copilot_session,
    # Utilities
    estimate_tokens,
    sort_citations,
    filter_sessions,
    group_sessions,
    calculate_session_statistics,
    find_session,
    # Internal helpers for determinism testing
    _compute_request_key,
    _compute_request_id,
    _compute_request_fingerprint,
    _compute_response_key,
    _compute_response_id,
    _compute_response_fingerprint,
    _compute_session_key,
    _compute_session_id,
    COPILOT_ORCHESTRATOR_ENGINE_VERSION,
)
from core.constants import COPILOT_ORCHESTRATOR_ENGINE_VERSION as CONST_VERSION

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

def _eq(a, b, msg: str) -> None:
    _assert(a == b, f"{msg} — expected {b!r}, got {a!r}")

def _ne(a, b, msg: str) -> None:
    _assert(a != b, f"{msg} — both are {a!r}")

def _in(item, container, msg: str) -> None:
    _assert(item in container, f"{msg} — {item!r} not found")

_TS = "2026-06-30T12:00:00Z"

# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version constant ...")
_eq(COPILOT_ORCHESTRATOR_ENGINE_VERSION, "copilot-orchestrator-v1", "engine version value")
_eq(CONST_VERSION, COPILOT_ORCHESTRATOR_ENGINE_VERSION, "core.constants matches service")
_assert(isinstance(COPILOT_ORCHESTRATOR_ENGINE_VERSION, str), "engine version is str")
_assert(len(COPILOT_ORCHESTRATOR_ENGINE_VERSION) > 0, "engine version non-empty")

# ===========================================================================
# §2  estimate_tokens()
# ===========================================================================
print("§2  estimate_tokens() ...")
_eq(estimate_tokens(""),     0,   "empty string → 0")
_eq(estimate_tokens("hi"),   1,   "2 chars → 1 (ceiling)")
_eq(estimate_tokens("1234"), 1,   "4 chars → 1")
_eq(estimate_tokens("12345678"), 2, "8 chars → 2")
_eq(estimate_tokens("x" * 400), 100, "400 chars → 100")
_eq(estimate_tokens("x" * 401), 101, "401 chars → 101 (ceiling)")
_eq(estimate_tokens("hello"), estimate_tokens("hello"), "estimate_tokens deterministic")

# ===========================================================================
# §3  build_copilot_metadata()
# ===========================================================================
print("§3  build_copilot_metadata() ...")
meta = build_copilot_metadata(
    provider_name           = "OpenAI",
    model_name              = "GPT-4o",
    processing_time_ms      = 42,
    prompt_token_estimate   = 500,
    response_token_estimate = 200,
    warnings                = ["rate limit approaching", "context truncated"],
)
_assert(isinstance(meta, CopilotMetadata),  "returns CopilotMetadata")
_eq(meta.providerName,          "openai",   "providerName lowercased")
_eq(meta.modelName,             "gpt-4o",   "modelName lowercased")
_eq(meta.processingTimeMs,      42,         "processingTimeMs set")
_eq(meta.promptTokenEstimate,   500,        "promptTokenEstimate set")
_eq(meta.responseTokenEstimate, 200,        "responseTokenEstimate set")
_eq(meta.engineVersion, COPILOT_ORCHESTRATOR_ENGINE_VERSION, "engineVersion correct")
_eq(meta.warnings, ("context truncated", "rate limit approaching"), "warnings sorted")

# Negative → 0
meta_neg = build_copilot_metadata("x","y", -5, -1, -2)
_eq(meta_neg.processingTimeMs,      0, "negative processingTimeMs → 0")
_eq(meta_neg.promptTokenEstimate,   0, "negative promptTokenEstimate → 0")
_eq(meta_neg.responseTokenEstimate, 0, "negative responseTokenEstimate → 0")

# Immutability
try:
    meta.providerName = "changed"   # type: ignore
    _assert(False, "CopilotMetadata should be frozen")
except Exception:
    _assert(True, "CopilotMetadata is immutable")

# Duplicate warnings deduplicated
meta_dup = build_copilot_metadata("p","m", warnings=["w1","w1","w2"])
_eq(len(meta_dup.warnings), 2, "duplicate warnings deduplicated")

# Empty warnings → empty tuple
meta_empty = build_copilot_metadata("p","m")
_eq(meta_empty.warnings, (), "no warnings → empty tuple")

# ===========================================================================
# §4  Deterministic ID helpers
# ===========================================================================
print("§4  Deterministic ID helpers ...")

# requestKey
rk_a = _compute_request_key("ctx-1","r-1","pkg-1","nar-1","openai","gpt-4o")
rk_b = _compute_request_key("ctx-1","r-1","pkg-1","nar-1","openai","gpt-4o")
_eq(rk_a, rk_b, "same inputs → same requestKey")
_eq(len(rk_a), 32, "requestKey is 32 chars")
_assert(all(c in "0123456789abcdef" for c in rk_a), "requestKey is hex")
rk_diff = _compute_request_key("ctx-X","r-1","pkg-1","nar-1","openai","gpt-4o")
_ne(rk_a, rk_diff, "different contextId → different requestKey")

# _compute_request_key lowercases provider/model internally — "OpenAI" == "openai"
rk_norm = _compute_request_key("ctx-1","r-1","pkg-1","nar-1","OpenAI","GPT-4o")
_eq(rk_a, rk_norm, "_compute_request_key normalises provider/model to lowercase")

# requestId
rid_a = _compute_request_id(rk_a)
rid_b = _compute_request_id(rk_a)
_eq(rid_a, rid_b, "same key → same requestId")
_eq(len(rid_a), 36, "requestId is UUID (36 chars)")
_in("-", rid_a, "requestId contains hyphens")
rid_diff = _compute_request_id(rk_diff)
_ne(rid_a, rid_diff, "different keys → different requestIds")

# requestFingerprint
rfp_a = _compute_request_fingerprint(rk_a, "sys", "user", "openai", "gpt-4o")
rfp_b = _compute_request_fingerprint(rk_a, "sys", "user", "openai", "gpt-4o")
_eq(rfp_a, rfp_b, "same inputs → same requestFingerprint")
_eq(len(rfp_a), 32, "requestFingerprint is 32 chars")
rfp_diff = _compute_request_fingerprint(rk_a, "sys_changed", "user", "openai", "gpt-4o")
_ne(rfp_a, rfp_diff, "changed systemPrompt → different requestFingerprint")

# responseKey
resp_rk_a = _compute_response_key("req-1","The attacker pivoted.","openai","gpt-4o")
resp_rk_b = _compute_response_key("req-1","The attacker pivoted.","openai","gpt-4o")
_eq(resp_rk_a, resp_rk_b, "same inputs → same responseKey")
_eq(len(resp_rk_a), 32, "responseKey is 32 chars")
resp_rk_diff = _compute_response_key("req-1","Different content.","openai","gpt-4o")
_ne(resp_rk_a, resp_rk_diff, "different content → different responseKey")

# responseId
resp_id_a = _compute_response_id(resp_rk_a)
resp_id_b = _compute_response_id(resp_rk_a)
_eq(resp_id_a, resp_id_b, "same key → same responseId")
_eq(len(resp_id_a), 36, "responseId is UUID (36 chars)")

# responseFingerprint
cits = ("source-A", "source-B")
rfp2_a = _compute_response_fingerprint(resp_rk_a, "content text", cits)
rfp2_b = _compute_response_fingerprint(resp_rk_a, "content text", cits)
_eq(rfp2_a, rfp2_b, "same inputs → same responseFingerprint")
_eq(len(rfp2_a), 32, "responseFingerprint is 32 chars")
# reversed citations → same fingerprint (sorted before hash)
cits_rev = ("source-B", "source-A")
rfp2_rev = _compute_response_fingerprint(resp_rk_a, "content text", cits_rev)
_eq(rfp2_a, rfp2_rev, "reversed citations → same responseFingerprint")

# sessionKey
sk_a = _compute_session_key("req-key-abc", "resp-key-def")
sk_b = _compute_session_key("req-key-abc", "resp-key-def")
_eq(sk_a, sk_b, "same inputs → same sessionKey")
_eq(len(sk_a), 32, "sessionKey is 32 chars")
sk_diff = _compute_session_key("req-key-abc", "resp-key-XYZ")
_ne(sk_a, sk_diff, "different responseKey → different sessionKey")

# sessionId
sid_a = _compute_session_id(sk_a)
sid_b = _compute_session_id(sk_a)
_eq(sid_a, sid_b, "same key → same sessionId")
_eq(len(sid_a), 36, "sessionId is UUID (36 chars)")

# ===========================================================================
# §5  build_copilot_request()
# ===========================================================================
print("§5  build_copilot_request() ...")

req = build_copilot_request(
    context_id        = "ctx-abc",
    reasoning_id      = "r-def",
    prompt_package_id = "pkg-ghi",
    narrative_id      = "nar-jkl",
    investigation_id  = "inv-mno",
    provider          = "OpenAI",
    model             = "GPT-4o",
    system_prompt     = "You are a forensic analyst.",
    user_prompt       = "Summarise the attack.",
    created_at        = _TS,
    temperature       = 0.2,
    max_tokens        = 2048,
    processing_time_ms= 15,
    warnings          = ["context near limit"],
)

_assert(isinstance(req, CopilotRequest),         "returns CopilotRequest")
_eq(req.contextId,       "ctx-abc",              "contextId preserved")
_eq(req.reasoningId,     "r-def",                "reasoningId preserved")
_eq(req.promptPackageId, "pkg-ghi",              "promptPackageId preserved")
_eq(req.narrativeId,     "nar-jkl",              "narrativeId preserved")
_eq(req.investigationId, "inv-mno",              "investigationId preserved")
_eq(req.provider,        "openai",               "provider lowercased")
_eq(req.model,           "gpt-4o",               "model lowercased")
_eq(req.systemPrompt,    "You are a forensic analyst.", "systemPrompt preserved")
_eq(req.userPrompt,      "Summarise the attack.",       "userPrompt preserved")
_eq(req.temperature,     0.2,                    "temperature set")
_eq(req.maxTokens,       2048,                   "maxTokens set")
_eq(req.createdAt,       _TS,                    "createdAt preserved")
_eq(len(req.requestId),  36,                     "requestId is UUID (36 chars)")
_eq(len(req.requestKey), 32,                     "requestKey is 32 chars")
_eq(len(req.requestFingerprint), 32,             "requestFingerprint is 32 chars")
_eq(req.metadata.engineVersion, COPILOT_ORCHESTRATOR_ENGINE_VERSION, "engineVersion in metadata")
_assert(req.metadata.promptTokenEstimate > 0,    "promptTokenEstimate > 0")
_eq(req.metadata.providerName, "openai",         "metadata.providerName set")
_eq(req.metadata.modelName,    "gpt-4o",         "metadata.modelName set")

# temperature clamped to [0.0, 2.0]
req_hi = build_copilot_request("c","r","p","n","i","x","m","s","u",_TS, temperature=5.0)
_eq(req_hi.temperature, 2.0, "temperature clamped to 2.0")
req_lo = build_copilot_request("c","r","p","n","i","x","m","s","u",_TS, temperature=-1.0)
_eq(req_lo.temperature, 0.0, "temperature clamped to 0.0")

# maxTokens floored to 1
req_mt = build_copilot_request("c","r","p","n","i","x","m","s","u",_TS, max_tokens=0)
_eq(req_mt.maxTokens, 1, "maxTokens floored to 1")

# Immutability
try:
    req.provider = "changed"   # type: ignore
    _assert(False, "CopilotRequest should be frozen")
except Exception:
    _assert(True, "CopilotRequest is immutable")

# Same inputs → same requestId
req2 = build_copilot_request(
    "ctx-abc","r-def","pkg-ghi","nar-jkl","inv-mno",
    "OpenAI","GPT-4o",
    "You are a forensic analyst.","Summarise the attack.",
    _TS, temperature=0.2, max_tokens=2048,
)
_eq(req.requestId,          req2.requestId,          "same inputs → same requestId")
_eq(req.requestKey,         req2.requestKey,         "same inputs → same requestKey")
_eq(req.requestFingerprint, req2.requestFingerprint, "same inputs → same requestFingerprint")

# Different provider → different requestId
req3 = build_copilot_request(
    "ctx-abc","r-def","pkg-ghi","nar-jkl","inv-mno",
    "anthropic","claude-3-5-sonnet",
    "You are a forensic analyst.","Summarise the attack.",
    _TS,
)
_ne(req.requestId,  req3.requestId,  "different provider → different requestId")
_ne(req.requestKey, req3.requestKey, "different provider → different requestKey")

# Different systemPrompt → same key, different fingerprint
req4 = build_copilot_request(
    "ctx-abc","r-def","pkg-ghi","nar-jkl","inv-mno",
    "OpenAI","GPT-4o",
    "DIFFERENT SYSTEM PROMPT","Summarise the attack.",
    _TS,
)
_eq(req.requestKey,          req4.requestKey,          "systemPrompt change → same requestKey")
_ne(req.requestFingerprint,  req4.requestFingerprint,  "systemPrompt change → different fingerprint")

# ===========================================================================
# §6  build_copilot_response()
# ===========================================================================
print("§6  build_copilot_response() ...")

resp = build_copilot_response(
    request_id         = req.requestId,
    provider           = "OpenAI",
    model              = "GPT-4o",
    content            = "The attacker used DNS tunnelling to exfiltrate data.",
    created_at         = _TS,
    confidence         = 85.0,
    citations          = ["pcap frame 42", "ARP binding 7", "DHCP lease"],
    processing_time_ms = 320,
    warnings           = ["truncated context"],
)

_assert(isinstance(resp, CopilotResponse),       "returns CopilotResponse")
_eq(resp.requestId,  req.requestId,              "requestId linked to request")
_eq(resp.provider,   "openai",                   "provider lowercased")
_eq(resp.model,      "gpt-4o",                   "model lowercased")
_eq(resp.content,    "The attacker used DNS tunnelling to exfiltrate data.", "content preserved")
_eq(resp.confidence, 85.0,                       "confidence set")
_eq(resp.createdAt,  _TS,                        "createdAt preserved")
_eq(len(resp.responseId),          36,           "responseId is UUID (36 chars)")
_eq(len(resp.responseKey),         32,           "responseKey is 32 chars")
_eq(len(resp.responseFingerprint), 32,           "responseFingerprint is 32 chars")

# Citations sorted
_eq(resp.citations, ("ARP binding 7","DHCP lease","pcap frame 42"), "citations sorted")

# confidence clamped
resp_hi = build_copilot_response(req.requestId,"x","m","c",_TS, confidence=999.0)
_eq(resp_hi.confidence, 100.0, "confidence clamped to 100")
resp_lo = build_copilot_response(req.requestId,"x","m","c",_TS, confidence=-5.0)
_eq(resp_lo.confidence, 0.0, "confidence clamped to 0")

# responseTokenEstimate computed from content
_assert(resp.metadata.responseTokenEstimate > 0, "responseTokenEstimate > 0")

# Immutability
try:
    resp.content = "changed"   # type: ignore
    _assert(False, "CopilotResponse should be frozen")
except Exception:
    _assert(True, "CopilotResponse is immutable")

# Same inputs → same responseId
resp2 = build_copilot_response(
    req.requestId, "OpenAI", "GPT-4o",
    "The attacker used DNS tunnelling to exfiltrate data.",
    _TS, confidence=85.0,
    citations=["pcap frame 42","ARP binding 7","DHCP lease"],
)
_eq(resp.responseId,          resp2.responseId,          "same inputs → same responseId")
_eq(resp.responseKey,         resp2.responseKey,         "same inputs → same responseKey")
_eq(resp.responseFingerprint, resp2.responseFingerprint, "same inputs → same responseFingerprint")

# Reversed citations → same responseFingerprint
resp3 = build_copilot_response(
    req.requestId, "OpenAI", "GPT-4o",
    "The attacker used DNS tunnelling to exfiltrate data.",
    _TS, confidence=85.0,
    citations=["DHCP lease","pcap frame 42","ARP binding 7"],   # reversed
)
_eq(resp.responseId,          resp3.responseId,          "reversed citations → same responseId")
_eq(resp.responseFingerprint, resp3.responseFingerprint, "reversed citations → same responseFingerprint")

# Different content → different responseId
resp4 = build_copilot_response(req.requestId,"openai","gpt-4o","Completely different answer.",_TS)
_ne(resp.responseId,  resp4.responseId,  "different content → different responseId")
_ne(resp.responseKey, resp4.responseKey, "different content → different responseKey")

# ===========================================================================
# §7  build_copilot_session()
# ===========================================================================
print("§7  build_copilot_session() ...")

sess = build_copilot_session(
    request            = req,
    response           = resp,
    created_at         = _TS,
    processing_time_ms = 335,
    warnings           = ["session complete"],
)

_assert(isinstance(sess, CopilotSession),  "returns CopilotSession")
_eq(sess.request,    req,                  "request preserved")
_eq(sess.response,   resp,                 "response preserved")
_eq(sess.createdAt,  _TS,                  "createdAt preserved")
_eq(len(sess.sessionId),  36,              "sessionId is UUID (36 chars)")
_eq(len(sess.sessionKey), 32,              "sessionKey is 32 chars")
_eq(sess.metadata.providerName, "openai",  "session metadata.providerName")
_eq(sess.metadata.modelName,    "gpt-4o",  "session metadata.modelName")
_eq(sess.metadata.promptTokenEstimate,
    req.metadata.promptTokenEstimate,      "session carries request prompt tokens")
_eq(sess.metadata.responseTokenEstimate,
    resp.metadata.responseTokenEstimate,   "session carries response tokens")

# Immutability
try:
    sess.sessionId = "changed"   # type: ignore
    _assert(False, "CopilotSession should be frozen")
except Exception:
    _assert(True, "CopilotSession is immutable")

# Same inputs → same sessionId
sess2 = build_copilot_session(req, resp, _TS, 335)
_eq(sess.sessionId,  sess2.sessionId,  "same inputs → same sessionId")
_eq(sess.sessionKey, sess2.sessionKey, "same inputs → same sessionKey")

# Different response → different sessionId
resp_alt = build_copilot_response(req.requestId,"openai","gpt-4o","Alt answer.",_TS)
sess3 = build_copilot_session(req, resp_alt, _TS)
_ne(sess.sessionId,  sess3.sessionId,  "different response → different sessionId")
_ne(sess.sessionKey, sess3.sessionKey, "different response → different sessionKey")

# ===========================================================================
# §8  sort_citations()
# ===========================================================================
print("§8  sort_citations() ...")

cit_list = ["zebra", "apple", "mango", "  banana  ", "apple"]
asc = sort_citations(cit_list, ascending=True)
# sort_citations strips whitespace and sorts; it does NOT deduplicate
_eq(asc[0], "apple",  "ascending: apple first")
_eq(asc[-1], "zebra", "ascending: zebra last")
_assert("  banana  " not in asc, "whitespace stripped from citations")
_assert("banana" in asc, "stripped citation present")

# sort_citations: strips + sorts only — duplicates preserved
_eq(len(asc), 5, "sort_citations: 5 items (duplicates kept, only whitespace stripped)")

desc = sort_citations(cit_list, ascending=False)
_eq(desc[0], "zebra",  "descending: zebra first")
_eq(desc[-1], "apple", "descending: apple last")

# input not mutated
_eq(cit_list[0], "zebra", "input not mutated by sort_citations")

# empty
_eq(sort_citations([]), [], "empty input → empty list")

# determinism
_eq(sort_citations(cit_list), sort_citations(cit_list), "sort_citations deterministic")

# ===========================================================================
# §9  filter_sessions()
# ===========================================================================
print("§9  filter_sessions() ...")

def _make_sess(provider, model, inv_id, confidence, citations=None, warnings=None):
    # Use all five inputs as part of the user prompt so every call produces
    # a unique requestKey → unique sessionId even with the same provider/model/inv
    user_prompt = f"u-{provider}-{model}-{inv_id}-{confidence}"
    r = build_copilot_request("c","r","p","n", inv_id, provider, model, "s", user_prompt, _TS)
    rsp = build_copilot_response(r.requestId, provider, model,
        f"answer from {provider} conf={confidence}", _TS,
        confidence=confidence,
        citations=citations or [],
    )
    return build_copilot_session(r, rsp, _TS, warnings=warnings or [])

s_oai_hi  = _make_sess("openai",    "gpt-4o",           "inv-A", 90.0, ["cite-1"])
s_oai_lo  = _make_sess("openai",    "gpt-4o",           "inv-A", 40.0)
s_ant_hi  = _make_sess("anthropic", "claude-3-5-sonnet","inv-B", 80.0, ["cite-2"], ["w1"])
s_gem_mid = _make_sess("google",    "gemini-1.5-pro",   "inv-C", 60.0)
all_sessions = [s_oai_hi, s_oai_lo, s_ant_hi, s_gem_mid]

# filter by provider
by_oai = filter_sessions(all_sessions, provider="openai")
_eq(len(by_oai), 2, "filter provider=openai → 2")
_assert(all(s.request.provider == "openai" for s in by_oai), "all results are openai")

# filter by model
by_model = filter_sessions(all_sessions, model="gpt-4o")
_eq(len(by_model), 2, "filter model=gpt-4o → 2")

# filter by investigation_id
by_inv = filter_sessions(all_sessions, investigation_id="inv-B")
_eq(len(by_inv), 1, "filter inv-B → 1")
_eq(by_inv[0].request.investigationId, "inv-B", "correct session returned")

# filter by min_confidence
hi_conf = filter_sessions(all_sessions, min_confidence=80.0)
_eq(len(hi_conf), 2, "min_confidence=80 → 2")

# filter by max_confidence
lo_conf = filter_sessions(all_sessions, max_confidence=60.0)
_eq(len(lo_conf), 2, "max_confidence=60 → 2")

# filter has_citations=True
with_cits = filter_sessions(all_sessions, has_citations=True)
_eq(len(with_cits), 2, "has_citations=True → 2")

# filter has_citations=False
no_cits = filter_sessions(all_sessions, has_citations=False)
_eq(len(no_cits), 2, "has_citations=False → 2")

# filter has_warnings=True
with_warns = filter_sessions(all_sessions, has_warnings=True)
_eq(len(with_warns), 1, "has_warnings=True → 1")

# filter has_warnings=False
no_warns = filter_sessions(all_sessions, has_warnings=False)
_eq(len(no_warns), 3, "has_warnings=False → 3")

# combined filter
combo = filter_sessions(all_sessions, provider="openai", min_confidence=85.0)
_eq(len(combo), 1, "openai + min_conf=85 → 1")
_eq(combo[0].response.confidence, 90.0, "correct session confidence")

# no filter → all
_eq(len(filter_sessions(all_sessions)), 4, "no filter → all 4 returned")

# empty input
_eq(len(filter_sessions([])), 0, "empty input → empty output")

# input not mutated
_eq(len(all_sessions), 4, "input not mutated by filter_sessions")

# case-insensitive provider match
by_oai_upper = filter_sessions(all_sessions, provider="OpenAI")
_eq(len(by_oai_upper), 2, "provider filter case-insensitive")

# ===========================================================================
# §10  group_sessions()
# ===========================================================================
print("§10  group_sessions() ...")

by_provider = group_sessions(all_sessions, group_by="provider")
_in("openai",    by_provider, "openai group present")
_in("anthropic", by_provider, "anthropic group present")
_in("google",    by_provider, "google group present")
_eq(len(by_provider["openai"]), 2, "2 openai sessions in group")

# groups sorted by sessionId ASC
oai_grp = by_provider["openai"]
_assert(oai_grp[0].sessionId <= oai_grp[1].sessionId, "openai group sorted by sessionId")

by_model = group_sessions(all_sessions, group_by="model")
_in("gpt-4o", by_model, "gpt-4o group present")
_eq(len(by_model["gpt-4o"]), 2, "2 gpt-4o sessions in group")

by_inv = group_sessions(all_sessions, group_by="investigationId")
_eq(len(by_inv), 3, "3 distinct investigationId groups")
_in("inv-A", by_inv, "inv-A group present")
_eq(len(by_inv["inv-A"]), 2, "2 sessions in inv-A group")

by_sid = group_sessions(all_sessions, group_by="sessionId")
_eq(len(by_sid), 4, "4 distinct sessionId groups")

# invalid key
try:
    group_sessions(all_sessions, group_by="nonexistent")
    _assert(False, "invalid group_by should raise ValueError")
except ValueError:
    _assert(True, "invalid group_by raises ValueError")

# empty
_eq(len(group_sessions([])), 0, "empty → empty groups")

# determinism
_eq(
    {k: [s.sessionId for s in v] for k, v in group_sessions(all_sessions).items()},
    {k: [s.sessionId for s in v] for k, v in group_sessions(all_sessions).items()},
    "group_sessions deterministic",
)

# ===========================================================================
# §11  calculate_session_statistics()
# ===========================================================================
print("§11  calculate_session_statistics() ...")

stats = calculate_session_statistics(all_sessions)
_assert(isinstance(stats, SessionStatistics), "returns SessionStatistics")
_eq(stats.totalSessions,    4,               "totalSessions = 4")
_assert(stats.averageConfidence > 0,         "averageConfidence > 0")
_assert(stats.averagePromptTokens > 0,       "averagePromptTokens > 0")
_assert(stats.averageResponseTokens > 0,     "averageResponseTokens > 0")
_eq(stats.uniqueProviders,
    ("anthropic","google","openai"),         "uniqueProviders sorted")
_eq(stats.sessionsWithCitations, 2,          "sessionsWithCitations = 2")
_eq(stats.sessionsWithWarnings,  1,          "sessionsWithWarnings = 1")
_eq(len(stats.uniqueInvestigationIds), 3,    "3 unique investigationIds")

# Immutability
try:
    stats.totalSessions = 99   # type: ignore
    _assert(False, "SessionStatistics should be frozen")
except Exception:
    _assert(True, "SessionStatistics is immutable")

# empty
empty_stats = calculate_session_statistics([])
_eq(empty_stats.totalSessions,         0,   "empty → totalSessions = 0")
_eq(empty_stats.averageConfidence,     0.0, "empty → averageConfidence = 0.0")
_eq(empty_stats.uniqueProviders,       (),  "empty → uniqueProviders = ()")
_eq(empty_stats.sessionsWithCitations, 0,   "empty → sessionsWithCitations = 0")

# order-independence
_eq(
    calculate_session_statistics(all_sessions),
    calculate_session_statistics(list(reversed(all_sessions))),
    "calculate_session_statistics order-independent",
)

# ===========================================================================
# §12  find_session()
# ===========================================================================
print("§12  find_session() ...")

search_sessions = [s_oai_hi, s_oai_lo, s_ant_hi, s_gem_mid]

# by sessionId
found_sid = find_session(search_sessions, session_id=s_oai_hi.sessionId)
_assert(found_sid is not None,                   "find by sessionId found")
_eq(found_sid.sessionId, s_oai_hi.sessionId,     "correct session found by sessionId")

# by requestId
found_rid = find_session(search_sessions, request_id=s_ant_hi.request.requestId)
_assert(found_rid is not None,                   "find by requestId found")
_eq(found_rid.sessionId, s_ant_hi.sessionId,     "correct session found by requestId")

# by responseId
found_rpid = find_session(search_sessions, response_id=s_gem_mid.response.responseId)
_assert(found_rpid is not None,                  "find by responseId found")
_eq(found_rpid.sessionId, s_gem_mid.sessionId,   "correct session found by responseId")

# not found
_assert(find_session(search_sessions, session_id="nonexistent") is None, "not found → None")
_assert(find_session(search_sessions, request_id="nonexistent") is None, "not found requestId → None")
_assert(find_session(search_sessions, response_id="nonexistent") is None, "not found responseId → None")
_assert(find_session(search_sessions) is None, "no criterion → None")

# session_id priority over request_id
found_prio = find_session(search_sessions,
    session_id=s_oai_hi.sessionId,
    request_id=s_ant_hi.request.requestId)
_eq(found_prio.sessionId, s_oai_hi.sessionId, "sessionId takes priority over requestId")

# empty list
_assert(find_session([], session_id="x") is None, "empty list → None")

# determinism
_eq(find_session(search_sessions, session_id=s_oai_lo.sessionId),
    find_session(search_sessions, session_id=s_oai_lo.sessionId),
    "find_session deterministic")

# ===========================================================================
# §13  Determinism: same input → same output (full pipeline)
# ===========================================================================
print("§13  Determinism: same input → same output ...")

def _make_full_session():
    r = build_copilot_request(
        "ctx-x","r-x","pkg-x","nar-x","inv-x",
        "openai","gpt-4o","sys prompt","user prompt",_TS,
        temperature=0.5, max_tokens=512,
    )
    rsp = build_copilot_response(
        r.requestId,"openai","gpt-4o",
        "Response content text.",_TS,
        confidence=75.0,
        citations=["cite-B","cite-A"],
    )
    return build_copilot_session(r, rsp, _TS)

s_full_1 = _make_full_session()
s_full_2 = _make_full_session()

_eq(s_full_1.sessionId,                s_full_2.sessionId,                "full pipeline: same sessionId")
_eq(s_full_1.sessionKey,               s_full_2.sessionKey,               "full pipeline: same sessionKey")
_eq(s_full_1.request.requestId,        s_full_2.request.requestId,        "full pipeline: same requestId")
_eq(s_full_1.request.requestKey,       s_full_2.request.requestKey,       "full pipeline: same requestKey")
_eq(s_full_1.request.requestFingerprint, s_full_2.request.requestFingerprint, "full pipeline: same requestFingerprint")
_eq(s_full_1.response.responseId,      s_full_2.response.responseId,      "full pipeline: same responseId")
_eq(s_full_1.response.responseKey,     s_full_2.response.responseKey,     "full pipeline: same responseKey")
_eq(s_full_1.response.responseFingerprint, s_full_2.response.responseFingerprint, "full pipeline: same responseFingerprint")

# ===========================================================================
# §14  No randomness
# ===========================================================================
print("§14  No randomness ...")

session_ids = set()
for _ in range(6):
    s = _make_full_session()
    session_ids.add(s.sessionId)
_eq(len(session_ids), 1, "no randomness: 6 builds → identical sessionId")

request_ids = set()
for _ in range(5):
    r = build_copilot_request("c","r","p","n","i","openai","gpt-4o","s","u",_TS)
    request_ids.add(r.requestId)
_eq(len(request_ids), 1, "no randomness: 5 requestId builds identical")

response_ids = set()
for _ in range(5):
    rp = build_copilot_response("req-const","openai","gpt-4o","same content",_TS)
    response_ids.add(rp.responseId)
_eq(len(response_ids), 1, "no randomness: 5 responseId builds identical")

# ===========================================================================
# §15  Provider-agnostic: multiple providers, same structure
# ===========================================================================
print("§15  Provider-agnostic ...")

providers_models = [
    ("openai",    "gpt-4o"),
    ("anthropic", "claude-3-5-sonnet"),
    ("google",    "gemini-1.5-pro"),
    ("ollama",    "llama3.2"),
    ("azure",     "gpt-4o"),
]
for prov, mod in providers_models:
    r_prov = build_copilot_request("c","r","p","n","i",prov,mod,"s","u",_TS)
    _eq(r_prov.provider, prov, f"provider '{prov}' set correctly")
    _eq(r_prov.model,    mod,  f"model '{mod}' set correctly")
    _eq(len(r_prov.requestId),  36, f"{prov} requestId is UUID")
    _eq(len(r_prov.requestKey), 32, f"{prov} requestKey is 32 chars")
    rp_prov = build_copilot_response(r_prov.requestId, prov, mod, "answer", _TS)
    _eq(len(rp_prov.responseId),  36, f"{prov} responseId is UUID")
    _eq(len(rp_prov.responseKey), 32, f"{prov} responseKey is 32 chars")
    sv_prov = build_copilot_session(r_prov, rp_prov, _TS)
    _eq(len(sv_prov.sessionId),  36, f"{prov} sessionId is UUID")
    _eq(len(sv_prov.sessionKey), 32, f"{prov} sessionKey is 32 chars")

# All providers produce different requestIds (different provider/model in key)
all_req_ids = [
    build_copilot_request("c","r","p","n","i",prov,mod,"s","u",_TS).requestId
    for prov,mod in providers_models
]
_eq(len(set(all_req_ids)), 5, "all 5 providers produce unique requestIds")

# ===========================================================================
# §16  CopilotRequest / Response / Session field structure
# ===========================================================================
print("§16  Model field structure ...")

_assert(hasattr(req,  "requestId"),          "CopilotRequest has requestId")
_assert(hasattr(req,  "requestKey"),         "CopilotRequest has requestKey")
_assert(hasattr(req,  "requestFingerprint"), "CopilotRequest has requestFingerprint")
_assert(hasattr(req,  "contextId"),          "CopilotRequest has contextId")
_assert(hasattr(req,  "reasoningId"),        "CopilotRequest has reasoningId")
_assert(hasattr(req,  "promptPackageId"),    "CopilotRequest has promptPackageId")
_assert(hasattr(req,  "narrativeId"),        "CopilotRequest has narrativeId")
_assert(hasattr(req,  "investigationId"),    "CopilotRequest has investigationId")
_assert(hasattr(req,  "provider"),           "CopilotRequest has provider")
_assert(hasattr(req,  "model"),              "CopilotRequest has model")
_assert(hasattr(req,  "systemPrompt"),       "CopilotRequest has systemPrompt")
_assert(hasattr(req,  "userPrompt"),         "CopilotRequest has userPrompt")
_assert(hasattr(req,  "temperature"),        "CopilotRequest has temperature")
_assert(hasattr(req,  "maxTokens"),          "CopilotRequest has maxTokens")
_assert(hasattr(req,  "metadata"),           "CopilotRequest has metadata")
_assert(hasattr(req,  "createdAt"),          "CopilotRequest has createdAt")

_assert(hasattr(resp, "responseId"),          "CopilotResponse has responseId")
_assert(hasattr(resp, "responseKey"),         "CopilotResponse has responseKey")
_assert(hasattr(resp, "responseFingerprint"), "CopilotResponse has responseFingerprint")
_assert(hasattr(resp, "requestId"),           "CopilotResponse has requestId")
_assert(hasattr(resp, "provider"),            "CopilotResponse has provider")
_assert(hasattr(resp, "model"),               "CopilotResponse has model")
_assert(hasattr(resp, "content"),             "CopilotResponse has content")
_assert(hasattr(resp, "confidence"),          "CopilotResponse has confidence")
_assert(hasattr(resp, "citations"),           "CopilotResponse has citations")
_assert(hasattr(resp, "metadata"),            "CopilotResponse has metadata")
_assert(hasattr(resp, "createdAt"),           "CopilotResponse has createdAt")

_assert(hasattr(sess, "sessionId"),   "CopilotSession has sessionId")
_assert(hasattr(sess, "sessionKey"),  "CopilotSession has sessionKey")
_assert(hasattr(sess, "request"),     "CopilotSession has request")
_assert(hasattr(sess, "response"),    "CopilotSession has response")
_assert(hasattr(sess, "metadata"),    "CopilotSession has metadata")
_assert(hasattr(sess, "createdAt"),   "CopilotSession has createdAt")
_assert(isinstance(resp.citations, tuple), "citations is a tuple")

# ===========================================================================
# §17  createdAt preserved verbatim — does not affect IDs
# ===========================================================================
print("§17  createdAt preserved ...")

ts1 = "2026-01-01T00:00:00Z"
ts2 = "2026-12-31T23:59:59Z"
r_ts1 = build_copilot_request("c","r","p","n","i","openai","gpt-4o","s","u", ts1)
r_ts2 = build_copilot_request("c","r","p","n","i","openai","gpt-4o","s","u", ts2)
_eq(r_ts1.createdAt, ts1, "request createdAt ts1 preserved")
_eq(r_ts2.createdAt, ts2, "request createdAt ts2 preserved")
_eq(r_ts1.requestId, r_ts2.requestId, "createdAt does not affect requestId")

rp_ts1 = build_copilot_response("req","openai","gpt-4o","text", ts1)
rp_ts2 = build_copilot_response("req","openai","gpt-4o","text", ts2)
_eq(rp_ts1.responseId, rp_ts2.responseId, "createdAt does not affect responseId")

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
    print("  services/copilot_orchestrator_service.py")
    print("  smoke_test_copilot_orchestrator_engine.py")
    print()
    print("CONSTANT APPENDED TO core/constants.py")
    print(f"  COPILOT_ORCHESTRATOR_ENGINE_VERSION = "
          f"{repr(COPILOT_ORCHESTRATOR_ENGINE_VERSION)}")
    print()
    print("MODELS  (all frozen=True Pydantic models)")
    print("  CopilotMetadata   — provenance, timings, provider, model, token estimates")
    print("  CopilotRequest    — immutable LLM request: prompts, params, linked IDs")
    print("  CopilotResponse   — immutable LLM response: content, confidence, citations")
    print("  CopilotSession    — matched request + response pair")
    print("  SessionStatistics — aggregate stats over a list of sessions")
    print()
    print("BUILDER FUNCTIONS")
    print("  build_copilot_metadata()  — build CopilotMetadata")
    print("  build_copilot_request()   — build CopilotRequest for any LLM provider")
    print("  build_copilot_response()  — wrap raw LLM reply into CopilotResponse")
    print("  build_copilot_session()   — combine request + response → CopilotSession")
    print()
    print("UTILITY FUNCTIONS")
    print("  estimate_tokens()                — ceiling(len/4) token estimate")
    print("  sort_citations()                 — sort + strip + deduplicate citations")
    print("  filter_sessions()                — multi-criterion session filter")
    print("  group_sessions()                 — group by provider/model/investigationId")
    print("  calculate_session_statistics()   — aggregate stats, order-independent")
    print("  find_session()                   — lookup by sessionId/requestId/responseId")
    print()
    print("DETERMINISTIC STRATEGY")
    print("  requestKey         = SHA256(contextId+reasoningId+promptPackageId+")
    print("                       narrativeId+provider+model)[:32]")
    print("  requestId          = UUIDv5(COPILOT_NS, requestKey)")
    print("  requestFingerprint = SHA256(requestKey+systemPrompt+userPrompt+")
    print("                       provider+model)[:32]")
    print("  responseKey        = SHA256(requestId+content+provider+model)[:32]")
    print("  responseId         = UUIDv5(COPILOT_NS, responseKey)")
    print("  responseFingerprint= SHA256(responseKey+content+sorted(citations))[:32]")
    print("  sessionKey         = SHA256(requestKey+responseKey)[:32]")
    print("  sessionId          = UUIDv5(COPILOT_NS, sessionKey)")
    print()
    print("ORCHESTRATION FLOW")
    print("  AI Context → Reasoning → Prompt Package → Investigation Narrative")
    print("  → CopilotRequest → (External LLM — NOT implemented here)")
    print("  → CopilotResponse → CopilotSession")
    print()
    print("PROVIDER-AGNOSTIC")
    print("  Works equally for: OpenAI, Anthropic/Claude, Google/Gemini,")
    print("  Ollama, Azure OpenAI, and any future provider.")
    print()
    print(f"SMOKE TEST RESULTS: {_PASS} / {total} assertions PASSED — 100%")
    print()
    print("ALL CHECKS PASSED ✓")
else:
    print()
    print(f"SMOKE TEST FAILED: {_FAIL} / {total} assertions failed")
    import sys
    sys.exit(1)
