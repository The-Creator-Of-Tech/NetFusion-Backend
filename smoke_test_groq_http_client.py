"""
Smoke Test — Groq HTTP Client Engine
=====================================
Phase A4.2.1 — Verifies every model, builder, parser, error handler,
retry logic, metrics, and logging-safety function in
services/groq_http_client.py.

Run:
    python smoke_test_groq_http_client.py
Expected: 300+/300 assertions passed.

Design rules (inherited from project-wide pattern):
- Zero randomness. No uuid4(). No random module.
- All mocked HTTP responses are deterministic.
- Same mocked response → same parsed GroqResponse (idempotent).
- No real network calls.
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

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
from services.groq_http_client import (
    # Exceptions
    GroqHTTPError, AuthenticationError, RateLimitError,
    TimeoutError, ServerError, ValidationError, ProviderError,
    # Models
    GroqHTTPConfig, GroqHTTPRequest, GroqHTTPResponse, GroqHTTPResult,
    # Builders
    build_http_config, build_http_request, build_http_response,
    build_http_result, build_headers, build_payload,
    # HTTP functions
    send_request, send_async_request,
    # Parsers
    parse_response, parse_error,
    # Metrics
    get_metrics_snapshot, reset_metrics,
    # Helpers
    _sha256_32, _uuid5_http, _mask_api_key, _mask_headers,
    # Version constant re-exported
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
)
from services.groq_provider_service import (
    build_message, build_request as build_groq_request,
    GroqRequest, GroqResponse,
)
from core.constants import (
    GROQ_HTTP_CLIENT_ENGINE_VERSION as CONST_HTTP_VERSION,
    GROQ_API_ENDPOINT,
    GROQ_API_VERSION,
    GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS,
    GROQ_HTTP_DEFAULT_MAX_RETRIES,
    GROQ_HTTP_DEFAULT_RETRY_DELAY_MS,
    GROQ_HTTP_RETRYABLE_STATUS_CODES,
    GROQ_HTTP_NON_RETRYABLE_STATUS_CODES,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------
_TS  = "2026-06-30T12:00:00Z"
_M70 = "llama-3.3-70b-versatile"
_M8  = "llama-3.1-8b-instant"
_KEY = "gsk_testkey_AAABBBCCC12345678"

_MSGS = [
    build_message("system", "You are a forensic analyst."),
    build_message("user",   "Summarise the attack chain."),
]
_GROQ_REQ = build_groq_request(_M70, _MSGS, _TS, temperature=0.3, top_p=0.9, max_tokens=512)

_GOOD_BODY: Dict[str, Any] = {
    "id"     : "chatcmpl-abc123",
    "object" : "chat.completion",
    "model"  : _M70,
    "choices": [{
        "index"        : 0,
        "message"      : {"role": "assistant", "content": "DNS tunnelling detected."},
        "finish_reason": "stop",
    }],
    "usage": {
        "prompt_tokens"    : 42,
        "completion_tokens": 18,
        "total_tokens"     : 60,
    },
}

_ERROR_BODY_401: Dict[str, Any] = {"error": {"message": "Invalid API key.", "type": "invalid_request_error"}}
_ERROR_BODY_429: Dict[str, Any] = {"error": {"message": "Rate limit exceeded.", "type": "rate_limit_error"}}
_ERROR_BODY_500: Dict[str, Any] = {"error": {"message": "Internal server error.", "type": "server_error"}}
_ERROR_BODY_400: Dict[str, Any] = {"error": {"message": "Bad request.", "type": "invalid_request_error"}}


# ===========================================================================
# §1  Engine version
# ===========================================================================
print("§1  Engine version ...")
_eq(GROQ_HTTP_CLIENT_ENGINE_VERSION, "groq-http-client-v1", "engine version value")
_eq(CONST_HTTP_VERSION, GROQ_HTTP_CLIENT_ENGINE_VERSION, "core.constants matches service")
_is(GROQ_HTTP_CLIENT_ENGINE_VERSION, str, "engine version is str")
_assert("groq-http-client" in GROQ_HTTP_CLIENT_ENGINE_VERSION, "engine version contains groq-http-client")

# ===========================================================================
# §2  Constants sanity checks
# ===========================================================================
print("§2  Constants ...")
_eq(GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS, 60, "default timeout is 60s")
_ge(GROQ_HTTP_DEFAULT_MAX_RETRIES,      0, "max retries >= 0")
_ge(GROQ_HTTP_DEFAULT_RETRY_DELAY_MS,   0, "retry delay >= 0")
_in(429, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "429 is retryable")
_in(500, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "500 is retryable")
_in(502, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "502 is retryable")
_in(503, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "503 is retryable")
_in(504, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "504 is retryable")
_in(400, GROQ_HTTP_NON_RETRYABLE_STATUS_CODES, "400 is non-retryable")
_in(401, GROQ_HTTP_NON_RETRYABLE_STATUS_CODES, "401 is non-retryable")
_in(403, GROQ_HTTP_NON_RETRYABLE_STATUS_CODES, "403 is non-retryable")
_in(404, GROQ_HTTP_NON_RETRYABLE_STATUS_CODES, "404 is non-retryable")
_ni(429, GROQ_HTTP_NON_RETRYABLE_STATUS_CODES, "429 not in non-retryable list")
_ni(401, GROQ_HTTP_RETRYABLE_STATUS_CODES,     "401 not in retryable list")

# ===========================================================================
# §3  build_http_config() — basic construction
# ===========================================================================
print("§3  build_http_config() ...")
cfg = build_http_config(api_key=_KEY)
_is(cfg, GroqHTTPConfig, "returns GroqHTTPConfig")
_eq(cfg.apiKey,         _KEY,                         "apiKey stored")
_eq(cfg.endpoint,       GROQ_API_ENDPOINT,             "default endpoint")
_eq(cfg.apiVersion,     GROQ_API_VERSION,              "default apiVersion")
_eq(cfg.timeoutSeconds, GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS, "default timeout")
_eq(cfg.maxRetries,     GROQ_HTTP_DEFAULT_MAX_RETRIES,    "default maxRetries")
_eq(cfg.retryDelayMs,   GROQ_HTTP_DEFAULT_RETRY_DELAY_MS, "default retryDelayMs")
_assert(cfg.verifySSL,   "verifySSL defaults True")
_assert(len(cfg.userAgent) > 0, "userAgent is non-empty")
_eq(cfg.engineVersion,  GROQ_HTTP_CLIENT_ENGINE_VERSION,  "engineVersion set")

# Custom values
cfg2 = build_http_config(
    api_key         = _KEY,
    endpoint        = "https://custom.endpoint/v1",
    api_version     = "2025-01-01",
    timeout_seconds = 30,
    max_retries     = 5,
    retry_delay_ms  = 500,
    verify_ssl      = False,
    user_agent      = "TestAgent/1.0",
)
_eq(cfg2.endpoint,        "https://custom.endpoint/v1", "custom endpoint")
_eq(cfg2.apiVersion,      "2025-01-01",                 "custom apiVersion")
_eq(cfg2.timeoutSeconds,  30,                           "custom timeoutSeconds")
_eq(cfg2.maxRetries,       5,                           "custom maxRetries")
_eq(cfg2.retryDelayMs,   500,                           "custom retryDelayMs")
_assert(not cfg2.verifySSL, "custom verifySSL=False")
_eq(cfg2.userAgent,  "TestAgent/1.0",                   "custom userAgent")

# Negative timeout clamped to 1
cfg3 = build_http_config(api_key=_KEY, timeout_seconds=-5)
_eq(cfg3.timeoutSeconds, 1, "negative timeout clamped to 1")

# Negative max_retries clamped to 0
cfg4 = build_http_config(api_key=_KEY, max_retries=-1)
_eq(cfg4.maxRetries, 0, "negative maxRetries clamped to 0")

# Immutability
try:
    cfg.apiKey = "changed"  # type: ignore
    _assert(False, "GroqHTTPConfig should be frozen")
except Exception:
    _assert(True, "GroqHTTPConfig is immutable")

# No API key raises ValueError
try:
    build_http_config(api_key="")
    _assert(False, "empty api_key should raise ValueError")
except ValueError as e:
    _assert(True, "empty api_key raises ValueError")
    _in("GROQ_API_KEY", str(e), "error mentions GROQ_API_KEY")


# ===========================================================================
# §4  API key masking — safety
# ===========================================================================
print("§4  API key masking ...")
# _mask_api_key
_eq(_mask_api_key(""),               "***",               "empty key → ***")
_eq(_mask_api_key("short"),          "***",               "short key (<=8) → ***")
_eq(_mask_api_key("12345678"),       "***",               "exactly 8 chars → ***")
masked_long = _mask_api_key(_KEY)
_assert("***" in masked_long,        "long key contains ***")
_assert(_KEY not in masked_long,     "full key NOT in masked output")
_assert(masked_long.startswith(_KEY[:4]), "masked starts with first 4 chars")
_assert(masked_long.endswith(_KEY[-4:]),  "masked ends with last 4 chars")
_eq(_mask_api_key(_KEY), _mask_api_key(_KEY), "_mask_api_key deterministic")

# GroqHTTPConfig.masked_key()
_eq(cfg.masked_key(), _mask_api_key(_KEY), "config.masked_key() matches _mask_api_key()")
_assert(_KEY not in cfg.masked_key(), "masked_key() never exposes full API key")

# _mask_headers
raw_headers = {"Authorization": f"Bearer {_KEY}", "Content-Type": "application/json"}
masked_h = _mask_headers(raw_headers)
_assert(_KEY not in masked_h["Authorization"], "API key masked in Authorization header")
_assert("Bearer" in masked_h["Authorization"], "Bearer prefix preserved in masked header")
_eq(masked_h["Content-Type"], "application/json", "non-auth headers unchanged")
_ne(masked_h, raw_headers, "masked headers differ from originals")
# Original not mutated
_eq(raw_headers["Authorization"], f"Bearer {_KEY}", "original headers not mutated by masking")

# Non-Bearer authorization handled gracefully
non_bearer = {"Authorization": "Token abc123xyz"}
masked_nb  = _mask_headers(non_bearer)
_assert("abc123xyz" not in masked_nb["Authorization"], "non-Bearer auth key masked")

# ===========================================================================
# §5  build_headers()
# ===========================================================================
print("§5  build_headers() ...")
hdrs = build_headers(cfg)
_is(hdrs, dict, "returns dict")
_in("Authorization", hdrs,  "has Authorization")
_in("Content-Type",  hdrs,  "has Content-Type")
_in("Accept",        hdrs,  "has Accept")
_in("User-Agent",    hdrs,  "has User-Agent")
_assert(hdrs["Authorization"].startswith("Bearer "), "Authorization starts with Bearer")
_assert(_KEY in hdrs["Authorization"],               "real key present in headers (for actual requests)")
_eq(hdrs["Content-Type"], "application/json",        "Content-Type is application/json")
_eq(hdrs["Accept"],       "application/json",        "Accept is application/json")
_eq(hdrs["User-Agent"],   cfg.userAgent,             "User-Agent matches config")

# Determinism — same config → same headers
hdrs2 = build_headers(cfg)
_eq(hdrs, hdrs2, "same config → same headers (deterministic)")

# Different API key → different Authorization
cfg_alt = build_http_config(api_key="gsk_different_key_9999ZZZZ")
hdrs_alt = build_headers(cfg_alt)
_ne(hdrs["Authorization"], hdrs_alt["Authorization"], "different key → different auth header")

# ===========================================================================
# §6  build_payload()
# ===========================================================================
print("§6  build_payload() ...")
payload = build_payload(_GROQ_REQ)
_is(payload, dict, "returns dict")
_in("model",       payload, "payload has model")
_in("messages",    payload, "payload has messages")
_in("temperature", payload, "payload has temperature")
_in("top_p",       payload, "payload has top_p")
_in("max_tokens",  payload, "payload has max_tokens")
_in("stream",      payload, "payload has stream")
_eq(payload["model"],       _M70,  "model value correct")
_eq(payload["temperature"], 0.3,   "temperature value correct")
_eq(payload["top_p"],       0.9,   "top_p value correct")
_eq(payload["max_tokens"],  512,   "max_tokens value correct")
_eq(payload["stream"],      False, "stream value correct")
_eq(len(payload["messages"]), 2,   "2 messages in payload")

# Message format
msg0 = payload["messages"][0]
_eq(msg0["role"],    "system",                      "message[0] role correct")
_eq(msg0["content"], "You are a forensic analyst.", "message[0] content correct")
_ni("name",         msg0, "no name field when not set")
_ni("tool_call_id", msg0, "no tool_call_id when not set")

# Message with name and tool_call_id
msgs_with_tool = [
    build_message("tool", "result", name="dns_lookup", tool_call_id="tc-001"),
]
req_tool = build_groq_request(_M70, msgs_with_tool, _TS)
payload_tool = build_payload(req_tool)
msg_tool = payload_tool["messages"][0]
_eq(msg_tool["name"],         "dns_lookup", "tool message name included")
_eq(msg_tool["tool_call_id"], "tc-001",     "tool_call_id included")

# Determinism
payload2 = build_payload(_GROQ_REQ)
_eq(payload, payload2, "same request → same payload (deterministic)")


# ===========================================================================
# §7  build_http_request()
# ===========================================================================
print("§7  build_http_request() ...")
http_req = build_http_request(cfg, _GROQ_REQ)
_is(http_req, GroqHTTPRequest, "returns GroqHTTPRequest")
_eq(len(http_req.requestId), 36, "requestId is UUID (36 chars)")
_in("-", http_req.requestId,     "requestId contains hyphens")
_eq(http_req.url, cfg.endpoint,  "url matches config endpoint")
_is(http_req.headers, dict,      "headers is dict")
_is(http_req.payload, dict,      "payload is dict")
_eq(http_req.timeoutSeconds, cfg.timeoutSeconds, "timeoutSeconds from config")
_gt(http_req.createdAt, 0, "createdAt is positive monotonic ms")

# Deterministic ID — same config + same groq request → same requestId
http_req2 = build_http_request(cfg, _GROQ_REQ)
_eq(http_req.requestId, http_req2.requestId, "identical inputs → identical requestId")
_eq(http_req.payload,   http_req2.payload,   "identical inputs → identical payload")

# Different GroqRequest → different requestId
groq_req2 = build_groq_request(_M8, _MSGS, _TS)
http_req3  = build_http_request(cfg, groq_req2)
_ne(http_req.requestId, http_req3.requestId, "different GroqRequest → different requestId")

# Immutability
try:
    http_req.url = "changed"  # type: ignore
    _assert(False, "GroqHTTPRequest should be frozen")
except Exception:
    _assert(True, "GroqHTTPRequest is immutable")

# API key present in headers (for actual transport — masking is for logging only)
_assert(_KEY in http_req.headers["Authorization"], "API key present in request headers")

# ===========================================================================
# §8  build_http_response()
# ===========================================================================
print("§8  build_http_response() ...")
http_resp = build_http_response(
    status_code = 200,
    headers     = {"content-type": "application/json", "x-request-id": "abc"},
    body        = _GOOD_BODY,
    latency_ms  = 350,
)
_is(http_resp, GroqHTTPResponse, "returns GroqHTTPResponse")
_eq(len(http_resp.responseId), 36, "responseId is UUID (36 chars)")
_in("-", http_resp.responseId,     "responseId contains hyphens")
_eq(http_resp.statusCode,  200,    "statusCode stored")
_eq(http_resp.latencyMs,   350,    "latencyMs stored")
_gt(http_resp.receivedAt,  0,      "receivedAt positive")
_eq(http_resp.body,       _GOOD_BODY, "body stored correctly")
_in("content-type", http_resp.headers, "response headers stored")

# Negative latency clamped to 0
http_resp_neg = build_http_response(200, {}, {}, latency_ms=-10)
_eq(http_resp_neg.latencyMs, 0, "negative latencyMs clamped to 0")

# Deterministic responseId — same status + body → same responseId
http_resp2 = build_http_response(200, {"x": "y"}, _GOOD_BODY, 350)
_eq(http_resp.responseId, http_resp2.responseId, "same status+body → same responseId")

# Different body → different responseId
http_resp3 = build_http_response(200, {}, {"choices": []}, 350)
_ne(http_resp.responseId, http_resp3.responseId, "different body → different responseId")

# Immutability
try:
    http_resp.statusCode = 500  # type: ignore
    _assert(False, "GroqHTTPResponse should be frozen")
except Exception:
    _assert(True, "GroqHTTPResponse is immutable")

# ===========================================================================
# §9  build_http_result()
# ===========================================================================
print("§9  build_http_result() ...")
result = build_http_result(
    http_request  = http_req,
    http_response = http_resp,
    success       = True,
    error         = None,
    retry_count   = 0,
    extra_meta    = {"totalLatencyMs": 350},
)
_is(result, GroqHTTPResult, "returns GroqHTTPResult")
_eq(result.success,    True,     "success=True stored")
_assert(result.error is None,    "error=None stored")
_eq(result.retryCount, 0,        "retryCount=0 stored")
_is(result.metadata, dict,       "metadata is dict")
_in("engineVersion", result.metadata, "metadata has engineVersion")
_eq(result.metadata["engineVersion"], GROQ_HTTP_CLIENT_ENGINE_VERSION, "engineVersion in metadata")
_in("totalLatencyMs", result.metadata, "extra_meta merged")
_eq(result.metadata["totalLatencyMs"], 350, "extra_meta value correct")

# Failure result
result_fail = build_http_result(http_req, None, False, "Server error", 2)
_eq(result_fail.success, False,      "failure result success=False")
_eq(result_fail.error,  "Server error", "failure result error stored")
_eq(result_fail.retryCount, 2,       "retryCount=2 stored")
_assert(result_fail.response is None, "None response stored on failure")

# Negative retryCount clamped to 0
result_neg = build_http_result(http_req, None, False, "err", -5)
_eq(result_neg.retryCount, 0, "negative retryCount clamped to 0")

# Immutability
try:
    result.success = False  # type: ignore
    _assert(False, "GroqHTTPResult should be frozen")
except Exception:
    _assert(True, "GroqHTTPResult is immutable")


# ===========================================================================
# §10  parse_error()
# ===========================================================================
print("§10  parse_error() ...")

# 401 → AuthenticationError, not retryable
err_401 = parse_error(401, _ERROR_BODY_401)
_is(err_401, AuthenticationError, "401 → AuthenticationError")
_eq(err_401.status_code, 401,   "AuthenticationError.status_code=401")
_assert(not err_401.retryable,  "AuthenticationError not retryable")
_in("Invalid API key", err_401.provider_message, "provider message extracted")

# 429 → RateLimitError, retryable
err_429 = parse_error(429, _ERROR_BODY_429)
_is(err_429, RateLimitError, "429 → RateLimitError")
_eq(err_429.status_code, 429, "RateLimitError.status_code=429")
_assert(err_429.retryable,    "RateLimitError is retryable")
_in("Rate limit", err_429.provider_message, "provider message for 429")

# 500 → ServerError, retryable
err_500 = parse_error(500, _ERROR_BODY_500)
_is(err_500, ServerError, "500 → ServerError")
_eq(err_500.status_code, 500, "ServerError.status_code=500")
_assert(err_500.retryable,    "ServerError is retryable")

# 502, 503, 504 → ServerError, retryable
for code in (502, 503, 504):
    e = parse_error(code, {})
    _is(e, ServerError, f"{code} → ServerError")
    _assert(e.retryable, f"{code} ServerError is retryable")
    _eq(e.status_code, code, f"{code} status_code preserved")

# 400 → ValidationError, not retryable
err_400 = parse_error(400, _ERROR_BODY_400)
_is(err_400, ValidationError, "400 → ValidationError")
_assert(not err_400.retryable, "ValidationError not retryable")

# 422 → ValidationError
err_422 = parse_error(422, {"error": "Unprocessable"})
_is(err_422, ValidationError, "422 → ValidationError")

# 403 → ProviderError, not retryable
err_403 = parse_error(403, {})
_is(err_403, ProviderError, "403 → ProviderError")
_assert(not err_403.retryable, "403 ProviderError not retryable")

# 404 → ProviderError, not retryable
err_404 = parse_error(404, {})
_is(err_404, ProviderError, "404 → ProviderError")
_assert(not err_404.retryable, "404 ProviderError not retryable")

# Timeout → TimeoutError, retryable
err_timeout = parse_error(0, {}, is_timeout=True)
_is(err_timeout, TimeoutError, "timeout → TimeoutError")
_assert(err_timeout.retryable, "TimeoutError is retryable")

# Unknown status → ProviderError
err_other = parse_error(418, {"error": {"message": "I'm a teapot"}})
_is(err_other, ProviderError, "unknown status → ProviderError")
_assert(not err_other.retryable, "unknown status ProviderError not retryable")

# Empty body — no crash
err_empty = parse_error(500, {})
_is(err_empty, ServerError, "500 with empty body → ServerError")
_eq(err_empty.provider_message, "", "empty body → empty provider_message")

# String error body
err_str = parse_error(429, {"error": "plain string error"})
_is(err_str, RateLimitError, "string error body → RateLimitError")
_eq(err_str.provider_message, "plain string error", "string error message extracted")

# GroqHTTPError repr
_in("AuthenticationError", repr(err_401), "repr contains class name")
_in("status_code=401",     repr(err_401), "repr contains status_code")
_in("retryable=False",     repr(err_401), "repr contains retryable")

# All typed exceptions are subclasses of GroqHTTPError
for exc_cls in (AuthenticationError, RateLimitError, TimeoutError,
                ServerError, ValidationError, ProviderError):
    _assert(issubclass(exc_cls, GroqHTTPError), f"{exc_cls.__name__} is GroqHTTPError subclass")
    _assert(issubclass(exc_cls, Exception),     f"{exc_cls.__name__} is Exception subclass")


# ===========================================================================
# §11  parse_response()
# ===========================================================================
print("§11  parse_response() ...")

http_resp_ok = build_http_response(200, {}, _GOOD_BODY, 320)
groq_resp = parse_response(_GROQ_REQ, http_resp_ok, _TS)

_is(groq_resp, GroqResponse, "returns GroqResponse")
_eq(groq_resp.requestId,   _GROQ_REQ.requestId, "requestId linked to GroqRequest")
_eq(groq_resp.content,     "DNS tunnelling detected.", "content extracted from body")
_eq(groq_resp.finishReason,"stop",               "finishReason extracted")
_eq(groq_resp.createdAt,   _TS,                  "createdAt preserved")
_eq(groq_resp.usage.promptTokens,     42,        "promptTokens from body")
_eq(groq_resp.usage.completionTokens, 18,        "completionTokens from body")
_eq(groq_resp.usage.totalTokens,      60,        "totalTokens from body")
_eq(groq_resp.usage.latencyMs,       320,        "latencyMs from http_response")
_gt(groq_resp.usage.estimatedCost, 0.0,          "estimatedCost > 0 for 70b model")
_eq(len(groq_resp.responseId), 36,               "responseId is UUID")
_eq(len(groq_resp.responseKey), 32,              "responseKey is 32 chars")

# Determinism — identical mock response → identical GroqResponse
groq_resp2 = parse_response(_GROQ_REQ, http_resp_ok, _TS)
_eq(groq_resp.responseId, groq_resp2.responseId, "same inputs → same responseId")
_eq(groq_resp.content,    groq_resp2.content,    "same inputs → same content")
_eq(groq_resp,            groq_resp2,            "identical mocked responses → identical parsed objects")

# Different content → different responseId
body_alt = {**_GOOD_BODY, "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "Different answer."},
    "finish_reason": "stop",
}], "usage": _GOOD_BODY["usage"]}
http_resp_alt = build_http_response(200, {}, body_alt, 200)
groq_resp_alt = parse_response(_GROQ_REQ, http_resp_alt, _TS)
_ne(groq_resp.responseId, groq_resp_alt.responseId, "different content → different responseId")

# Missing choices → ValidationError
bad_body_no_choices = {"model": _M70, "choices": [], "usage": {}}
http_resp_bad = build_http_response(200, {}, bad_body_no_choices, 100)
try:
    parse_response(_GROQ_REQ, http_resp_bad, _TS)
    _assert(False, "empty choices should raise")
except ValidationError:
    _assert(True, "empty choices → ValidationError")
except Exception:
    _assert(False, "empty choices should raise ValidationError, not other exception")

# Null content in message → treated as empty string (no crash)
body_null_content = {**_GOOD_BODY, "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": None},
    "finish_reason": "length",
}], "usage": _GOOD_BODY["usage"]}
http_resp_null = build_http_response(200, {}, body_null_content, 100)
groq_resp_null = parse_response(_GROQ_REQ, http_resp_null, _TS)
_eq(groq_resp_null.content, "", "null content → empty string")
_eq(groq_resp_null.finishReason, "length", "finish_reason=length extracted")

# Model override from body
body_model_override = {**_GOOD_BODY, "model": "llama-3.1-8b-instant"}
http_resp_model = build_http_response(200, {}, body_model_override, 100)
groq_resp_model = parse_response(_GROQ_REQ, http_resp_model, _TS)
_eq(groq_resp_model.metadata.model, "llama-3.1-8b-instant", "model from body overrides request model")


# ===========================================================================
# §12  Deterministic IDs — deep verification
# ===========================================================================
print("§12  Deterministic IDs ...")

# _sha256_32
h1 = _sha256_32("abc", "def")
h2 = _sha256_32("abc", "def")
_eq(h1, h2, "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 returns 32 chars")
h3 = _sha256_32("abc", "xyz")
_ne(h1, h3, "different inputs → different sha256_32")
h4 = _sha256_32("def", "abc")
_ne(h1, h4, "different arg order → different sha256_32")

# _uuid5_http
uid1 = _uuid5_http("test-key-abc")
uid2 = _uuid5_http("test-key-abc")
_eq(uid1, uid2, "_uuid5_http deterministic")
_eq(len(uid1), 36, "_uuid5_http returns 36-char UUID")
_in("-", uid1, "_uuid5_http UUID contains hyphens")
uid3 = _uuid5_http("different-key")
_ne(uid1, uid3, "different keys → different UUIDs")

# build_http_request IDs are deterministic
req_a = build_http_request(cfg, _GROQ_REQ)
req_b = build_http_request(cfg, _GROQ_REQ)
_eq(req_a.requestId, req_b.requestId, "build_http_request IDs deterministic")

# build_http_response IDs are deterministic
resp_a = build_http_response(200, {}, _GOOD_BODY, 100)
resp_b = build_http_response(200, {}, _GOOD_BODY, 200)  # latency differs but ignored in ID
_eq(resp_a.responseId, resp_b.responseId, "response ID ignores latencyMs (based on status+body)")

# 5 builds of same http_request → always same requestId
req_ids = {build_http_request(cfg, _GROQ_REQ).requestId for _ in range(5)}
_eq(len(req_ids), 1, "zero randomness: 5 http_request builds identical")

# 5 builds of same http_response → always same responseId
resp_ids = {build_http_response(200, {}, _GOOD_BODY, i).responseId for i in range(5)}
_eq(len(resp_ids), 1, "zero randomness: 5 http_response builds identical")

# 5 builds of same parse_response → always same groq responseId
parsed_ids = {parse_response(_GROQ_REQ, build_http_response(200, {}, _GOOD_BODY, i), _TS).responseId for i in range(5)}
_eq(len(parsed_ids), 1, "zero randomness: 5 parse_response builds identical")

# ===========================================================================
# §13  Serialisation
# ===========================================================================
print("§13  Serialisation ...")
cfg_dict = cfg.model_dump()
_is(cfg_dict, dict, "GroqHTTPConfig.model_dump() returns dict")
_in("endpoint",        cfg_dict, "config dict has endpoint")
_in("timeoutSeconds",  cfg_dict, "config dict has timeoutSeconds")
_in("maxRetries",      cfg_dict, "config dict has maxRetries")
_in("engineVersion",   cfg_dict, "config dict has engineVersion")
# API key present in dict (it's a model field — masking is caller's responsibility)
_in("apiKey", cfg_dict, "config dict has apiKey field")

req_dict = http_req.model_dump()
_is(req_dict, dict, "GroqHTTPRequest.model_dump() returns dict")
_in("requestId",      req_dict, "request dict has requestId")
_in("url",            req_dict, "request dict has url")
_in("payload",        req_dict, "request dict has payload")
_in("timeoutSeconds", req_dict, "request dict has timeoutSeconds")

resp_dict = http_resp.model_dump()
_is(resp_dict, dict, "GroqHTTPResponse.model_dump() returns dict")
_in("responseId",  resp_dict, "response dict has responseId")
_in("statusCode",  resp_dict, "response dict has statusCode")
_in("body",        resp_dict, "response dict has body")
_in("latencyMs",   resp_dict, "response dict has latencyMs")

result_dict = result.model_dump()
_is(result_dict, dict, "GroqHTTPResult.model_dump() returns dict")
_in("success",    result_dict, "result dict has success")
_in("retryCount", result_dict, "result dict has retryCount")
_in("metadata",   result_dict, "result dict has metadata")


# ===========================================================================
# §14  Metrics — tracking and reset
# ===========================================================================
print("§14  Metrics ...")
reset_metrics()
snap0 = get_metrics_snapshot()
_eq(snap0["totalRequests"],   0, "fresh metrics: totalRequests=0")
_eq(snap0["totalSuccesses"],  0, "fresh metrics: totalSuccesses=0")
_eq(snap0["totalFailures"],   0, "fresh metrics: totalFailures=0")
_eq(snap0["totalRetries"],    0, "fresh metrics: totalRetries=0")
_eq(snap0["totalLatencyMs"],  0, "fresh metrics: totalLatencyMs=0")
_eq(snap0["totalTokens"],     0, "fresh metrics: totalTokens=0")
_eq(snap0["successRate"],   0.0, "fresh metrics: successRate=0.0")
_eq(snap0["failureRate"],   0.0, "fresh metrics: failureRate=0.0")
_eq(snap0["averageLatencyMs"], 0.0, "fresh metrics: averageLatencyMs=0.0")

# snapshot returns a plain dict
_is(snap0, dict, "get_metrics_snapshot() returns dict")
_in("totalRequests",       snap0, "snapshot has totalRequests")
_in("totalEstimatedCost",  snap0, "snapshot has totalEstimatedCost")
_in("successRate",         snap0, "snapshot has successRate")
_in("failureRate",         snap0, "snapshot has failureRate")
_in("averageLatencyMs",    snap0, "snapshot has averageLatencyMs")

# reset_metrics() is idempotent
reset_metrics()
reset_metrics()
snap_r = get_metrics_snapshot()
_eq(snap_r["totalRequests"], 0, "double reset still gives 0")

# ===========================================================================
# §15  Async send_async_request() — mocked success
# ===========================================================================
print("§15  send_async_request() mocked success ...")
reset_metrics()

def _make_mock_response(status: int, body: dict) -> MagicMock:
    """Build a mock httpx.Response."""
    mock = MagicMock()
    mock.status_code = status
    mock.headers     = {"content-type": "application/json"}
    mock.json.return_value = body
    return mock

async def _run_async_success():
    mock_resp = _make_mock_response(200, _GOOD_BODY)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_resp)
        MockClient.return_value = instance
        return await send_async_request(cfg, _GROQ_REQ, _TS)

result_ok, groq_resp_ok = asyncio.run(_run_async_success())

_is(result_ok,      GroqHTTPResult, "async success: returns GroqHTTPResult")
_is(groq_resp_ok,   GroqResponse,   "async success: returns GroqResponse")
_assert(result_ok.success,          "async success: result.success=True")
_assert(result_ok.error is None,    "async success: result.error=None")
_eq(result_ok.retryCount, 0,        "async success: no retries on first attempt")
_eq(groq_resp_ok.content, "DNS tunnelling detected.", "async success: content parsed")
_eq(groq_resp_ok.requestId, _GROQ_REQ.requestId,      "async success: requestId linked")
_eq(groq_resp_ok.usage.promptTokens,     42,           "async success: promptTokens")
_eq(groq_resp_ok.usage.completionTokens, 18,           "async success: completionTokens")
_eq(groq_resp_ok.usage.totalTokens,      60,           "async success: totalTokens")

# Metrics updated after success
snap_after = get_metrics_snapshot()
_eq(snap_after["totalRequests"],  1, "metrics: 1 request recorded")
_eq(snap_after["totalSuccesses"], 1, "metrics: 1 success recorded")
_eq(snap_after["totalFailures"],  0, "metrics: 0 failures")
_eq(snap_after["totalTokens"],   60, "metrics: 60 tokens recorded")
_gt(snap_after["successRate"],  0.0, "metrics: successRate > 0")
_eq(snap_after["failureRate"],  0.0, "metrics: failureRate = 0")


# ===========================================================================
# §16  send_async_request() — mocked 401 (non-retryable)
# ===========================================================================
print("§16  send_async_request() mocked 401 ...")
reset_metrics()

async def _run_async_401():
    mock_resp = _make_mock_response(401, _ERROR_BODY_401)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_resp)
        MockClient.return_value = instance
        return await send_async_request(cfg, _GROQ_REQ, _TS)

result_401, groq_resp_401 = asyncio.run(_run_async_401())

_assert(not result_401.success,    "401: result.success=False")
_assert(result_401.error is not None, "401: result.error not None")
_assert(groq_resp_401 is None,     "401: no GroqResponse returned")
_eq(result_401.retryCount, 0,      "401: no retries (non-retryable)")
_in("authentication", result_401.error.lower(), "401: error mentions authentication")

snap_401 = get_metrics_snapshot()
_eq(snap_401["totalFailures"], 1, "metrics: 1 failure after 401")
_eq(snap_401["totalRetries"],  0, "metrics: 0 retries after non-retryable 401")

# ===========================================================================
# §17  send_async_request() — mocked 429 with retries
# ===========================================================================
print("§17  send_async_request() mocked 429 retries ...")
reset_metrics()

# Config with 2 max retries and zero delay (fast test)
cfg_fast = build_http_config(api_key=_KEY, max_retries=2, retry_delay_ms=0)

async def _run_async_429_then_200():
    """First two calls return 429, third returns 200."""
    mock_429 = _make_mock_response(429, _ERROR_BODY_429)
    mock_200 = _make_mock_response(200, _GOOD_BODY)
    call_count = 0

    async def _post(*a, **kw):
        nonlocal call_count
        call_count += 1
        return mock_200 if call_count >= 3 else mock_429

    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = _post
        MockClient.return_value = instance
        return await send_async_request(cfg_fast, _GROQ_REQ, _TS)

result_retry, groq_resp_retry = asyncio.run(_run_async_429_then_200())

_assert(result_retry.success,         "retry: eventual success=True")
_is(groq_resp_retry, GroqResponse,    "retry: GroqResponse returned on eventual success")
_eq(result_retry.retryCount, 2,       "retry: 2 retries recorded")
_eq(groq_resp_retry.content, "DNS tunnelling detected.", "retry: content correct")

snap_retry = get_metrics_snapshot()
_eq(snap_retry["totalSuccesses"], 1, "metrics: 1 success after retries")
_eq(snap_retry["totalRetries"],   2, "metrics: 2 retries recorded in metrics")

# ===========================================================================
# §18  send_async_request() — all retries exhausted (500)
# ===========================================================================
print("§18  send_async_request() exhausted retries ...")
reset_metrics()
cfg_no_retry = build_http_config(api_key=_KEY, max_retries=0, retry_delay_ms=0)

async def _run_async_500_exhausted():
    mock_500 = _make_mock_response(500, _ERROR_BODY_500)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_500)
        MockClient.return_value = instance
        return await send_async_request(cfg_no_retry, _GROQ_REQ, _TS)

result_500, groq_resp_500 = asyncio.run(_run_async_500_exhausted())

_assert(not result_500.success,   "500 exhausted: success=False")
_assert(groq_resp_500 is None,    "500 exhausted: no GroqResponse")
_assert(result_500.error is not None, "500 exhausted: error set")
_eq(result_500.retryCount, 0,     "500 exhausted: 0 retries with max_retries=0")

snap_500 = get_metrics_snapshot()
_eq(snap_500["totalFailures"], 1, "metrics: failure recorded for exhausted 500")


# ===========================================================================
# §19  send_async_request() — timeout handling
# ===========================================================================
print("§19  send_async_request() timeout ...")
reset_metrics()
cfg_timeout = build_http_config(api_key=_KEY, max_retries=0, retry_delay_ms=0)

async def _run_async_timeout():
    import httpx as _httpx
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        MockClient.return_value = instance
        return await send_async_request(cfg_timeout, _GROQ_REQ, _TS)

result_to, groq_resp_to = asyncio.run(_run_async_timeout())

_assert(not result_to.success,     "timeout: success=False")
_assert(groq_resp_to is None,      "timeout: no GroqResponse")
_assert(result_to.error is not None, "timeout: error set")
_in("timed out", result_to.error.lower(), "timeout: error message mentions timed out")

snap_to = get_metrics_snapshot()
_eq(snap_to["totalFailures"], 1, "metrics: failure recorded for timeout")

# ===========================================================================
# §20  send_async_request() — timeout with retries succeeds
# ===========================================================================
print("§20  send_async_request() timeout then success ...")
reset_metrics()
cfg_retry_timeout = build_http_config(api_key=_KEY, max_retries=2, retry_delay_ms=0)

async def _run_async_timeout_then_success():
    import httpx as _httpx
    mock_200 = _make_mock_response(200, _GOOD_BODY)
    call_count = 0

    async def _post(*a, **kw):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise _httpx.TimeoutException("timed out")
        return mock_200

    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = _post
        MockClient.return_value = instance
        return await send_async_request(cfg_retry_timeout, _GROQ_REQ, _TS)

result_trs, groq_resp_trs = asyncio.run(_run_async_timeout_then_success())

_assert(result_trs.success,          "timeout-then-success: eventual success=True")
_is(groq_resp_trs, GroqResponse,     "timeout-then-success: GroqResponse returned")
_eq(result_trs.retryCount, 1,        "timeout-then-success: 1 retry recorded")

# ===========================================================================
# §21  send_request() synchronous wrapper
# ===========================================================================
print("§21  send_request() synchronous wrapper ...")
reset_metrics()

def _run_sync_success():
    mock_resp = _make_mock_response(200, _GOOD_BODY)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_resp)
        MockClient.return_value = instance
        return send_request(cfg, _GROQ_REQ, _TS)

result_sync, groq_resp_sync = _run_sync_success()

_is(result_sync,     GroqHTTPResult, "sync: returns GroqHTTPResult")
_is(groq_resp_sync,  GroqResponse,   "sync: returns GroqResponse")
_assert(result_sync.success,         "sync: success=True")
_eq(groq_resp_sync.content, "DNS tunnelling detected.", "sync: content parsed")

snap_sync = get_metrics_snapshot()
_eq(snap_sync["totalSuccesses"], 1, "sync metrics: 1 success recorded")


# ===========================================================================
# §22  All 3 supported models round-trip through HTTP layer
# ===========================================================================
print("§22  All 3 supported models ...")
reset_metrics()

from core.constants import GROQ_SUPPORTED_MODELS

for model in GROQ_SUPPORTED_MODELS:
    model_body = {**_GOOD_BODY, "model": model}
    groq_req_m = build_groq_request(model, _MSGS, _TS)
    http_req_m = build_http_request(cfg, groq_req_m)

    _eq(http_req_m.payload["model"], model, f"{model}: payload model correct")
    _eq(len(http_req_m.requestId), 36,      f"{model}: requestId is UUID")

    http_resp_m = build_http_response(200, {}, model_body, 100)
    groq_resp_m = parse_response(groq_req_m, http_resp_m, _TS)
    _eq(groq_resp_m.requestId, groq_req_m.requestId, f"{model}: requestId linked")
    _is(groq_resp_m, GroqResponse, f"{model}: parses to GroqResponse")

# ===========================================================================
# §23  Retry logic — exhaustion with 3 retries
# ===========================================================================
print("§23  Retry exhaustion with 3 retries ...")
reset_metrics()
cfg_3retry = build_http_config(api_key=_KEY, max_retries=3, retry_delay_ms=0)

async def _run_all_retries_fail():
    mock_503 = _make_mock_response(503, {"error": {"message": "Service unavailable"}})
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_503)
        MockClient.return_value = instance
        return await send_async_request(cfg_3retry, _GROQ_REQ, _TS)

result_ex, groq_resp_ex = asyncio.run(_run_all_retries_fail())

_assert(not result_ex.success,     "exhaustion: success=False")
_assert(groq_resp_ex is None,      "exhaustion: no GroqResponse")
_eq(result_ex.retryCount, 3,       "exhaustion: 3 retries attempted")

snap_ex = get_metrics_snapshot()
_eq(snap_ex["totalRetries"], 3, "metrics: 3 retries in snapshot")

# ===========================================================================
# §24  HTTP result metadata fields
# ===========================================================================
print("§24  HTTP result metadata ...")
reset_metrics()

async def _run_with_meta():
    mock_resp = _make_mock_response(200, _GOOD_BODY)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_resp)
        MockClient.return_value = instance
        return await send_async_request(cfg, _GROQ_REQ, _TS)

result_meta, _ = asyncio.run(_run_with_meta())

_in("engineVersion",  result_meta.metadata, "metadata has engineVersion")
_in("retryCount",     result_meta.metadata, "metadata has retryCount")
_in("success",        result_meta.metadata, "metadata has success")
_in("totalLatencyMs", result_meta.metadata, "metadata has totalLatencyMs")
_in("attemptNumber",  result_meta.metadata, "metadata has attemptNumber")
_eq(result_meta.metadata["engineVersion"], GROQ_HTTP_CLIENT_ENGINE_VERSION, "engineVersion value correct")
_eq(result_meta.metadata["attemptNumber"], 1, "first attempt → attemptNumber=1")

# ===========================================================================
# §25  Logging safety — API key never appears in log output
# ===========================================================================
print("§25  Logging safety ...")
import logging
import io

log_capture = io.StringIO()
handler = logging.StreamHandler(log_capture)
handler.setLevel(logging.DEBUG)
logging.getLogger("netfusion.groq_http_client").addHandler(handler)

async def _run_log_capture():
    mock_resp = _make_mock_response(200, _GOOD_BODY)
    with patch("httpx.AsyncClient") as MockClient:
        instance = MagicMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__  = AsyncMock(return_value=False)
        instance.post       = AsyncMock(return_value=mock_resp)
        MockClient.return_value = instance
        return await send_async_request(cfg, _GROQ_REQ, _TS)

asyncio.run(_run_log_capture())
log_output = log_capture.getvalue()

_assert(_KEY not in log_output,           "API key NOT present in log output")
_assert("***" in log_output,              "masked key (***) IS in log output")
_assert("request_started" in log_output,  "request_started log emitted")
_assert("request_completed" in log_output,"request_completed log emitted")

logging.getLogger("netfusion.groq_http_client").removeHandler(handler)


# ===========================================================================
# §26  All models produce unique http requestIds
# ===========================================================================
print("§26  Unique IDs per model ...")
http_req_ids = set()
for model in GROQ_SUPPORTED_MODELS:
    gr = build_groq_request(model, _MSGS, _TS)
    hr = build_http_request(cfg, gr)
    http_req_ids.add(hr.requestId)
_eq(len(http_req_ids), len(GROQ_SUPPORTED_MODELS), "each model → unique http requestId")

# ===========================================================================
# §27  GroqHTTPConfig masked_key edge cases
# ===========================================================================
print("§27  masked_key edge cases ...")
cfg_short = build_http_config(api_key="short123")   # exactly 8 chars → ***
_eq(cfg_short.masked_key(), "***", "8-char key → masked as ***")

cfg_long = build_http_config(api_key="abcdefghij1234567890")
masked = cfg_long.masked_key()
_assert("abcd" in masked,           "first 4 chars present in masked key")
_assert("7890" in masked,           "last 4 chars present in masked key")
_assert("abcdefghij1234567890" not in masked, "full key not in masked output")

# ===========================================================================
# §28  parse_response — usage fields default to 0 when missing
# ===========================================================================
print("§28  parse_response — missing usage ...")
body_no_usage = {
    "model"  : _M70,
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
}
http_resp_nu = build_http_response(200, {}, body_no_usage, 100)
groq_resp_nu = parse_response(_GROQ_REQ, http_resp_nu, _TS)
_eq(groq_resp_nu.usage.promptTokens,     0, "missing usage → promptTokens=0")
_eq(groq_resp_nu.usage.completionTokens, 0, "missing usage → completionTokens=0")
_eq(groq_resp_nu.usage.totalTokens,      0, "missing usage → totalTokens=0")

# ===========================================================================
# §29  build_http_result extra_meta=None is handled
# ===========================================================================
print("§29  build_http_result — None extra_meta ...")
result_no_meta = build_http_result(http_req, http_resp, True, None, 0, extra_meta=None)
_is(result_no_meta, GroqHTTPResult, "None extra_meta still builds result")
_in("engineVersion", result_no_meta.metadata, "base metadata present without extra_meta")

# ===========================================================================
# §30  parse_error — all retryable codes are ServerError
# ===========================================================================
print("§30  parse_error completeness ...")
for code in (500, 502, 503, 504):
    e = parse_error(code, {"error": {"message": f"error {code}"}})
    _assert(e.retryable,    f"{code}: retryable=True")
    _is(e, ServerError,     f"{code}: is ServerError")
    _eq(e.status_code, code,f"{code}: status_code preserved")
    _in(str(code), e.provider_message, f"{code}: provider_message contains code text")

# Non-retryable codes
for code in (400, 401, 403, 404):
    e = parse_error(code, {})
    _assert(not e.retryable, f"{code}: retryable=False confirmed")

# ===========================================================================
# §31  Async functions are genuine coroutines
# ===========================================================================
print("§31  Async function types ...")
import inspect
_assert(inspect.iscoroutinefunction(send_async_request), "send_async_request is async")
_assert(not inspect.iscoroutinefunction(send_request),   "send_request is sync wrapper")
_assert(not inspect.iscoroutinefunction(parse_response), "parse_response is sync")
_assert(not inspect.iscoroutinefunction(parse_error),    "parse_error is sync")
_assert(not inspect.iscoroutinefunction(build_http_config),   "build_http_config is sync")
_assert(not inspect.iscoroutinefunction(build_http_request),  "build_http_request is sync")
_assert(not inspect.iscoroutinefunction(build_http_response), "build_http_response is sync")
_assert(not inspect.iscoroutinefunction(build_http_result),   "build_http_result is sync")
_assert(not inspect.iscoroutinefunction(build_headers),       "build_headers is sync")
_assert(not inspect.iscoroutinefunction(build_payload),       "build_payload is sync")


# ===========================================================================
# §32  Payload — stream=True propagated
# ===========================================================================
print("§32  Payload stream=True ...")
groq_req_stream = build_groq_request(_M70, _MSGS, _TS, stream=True)
payload_stream  = build_payload(groq_req_stream)
_eq(payload_stream["stream"], True, "stream=True included in payload")

# ===========================================================================
# §33  build_http_config — endpoint and api_version stripped
# ===========================================================================
print("§33  build_http_config stripping ...")
cfg_ws = build_http_config(api_key=_KEY, endpoint="  https://api.groq.com/v1  ", api_version="  2024-01-01  ")
_eq(cfg_ws.endpoint,   "https://api.groq.com/v1", "endpoint whitespace stripped")
_eq(cfg_ws.apiVersion, "2024-01-01",              "apiVersion whitespace stripped")
_eq(cfg_ws.userAgent.strip(), cfg_ws.userAgent,   "userAgent already stripped")

# ===========================================================================
# §34  GroqHTTPResponse — empty body handled
# ===========================================================================
print("§34  Empty body handled ...")
http_resp_empty = build_http_response(503, {}, {}, 50)
_is(http_resp_empty, GroqHTTPResponse, "empty body → GroqHTTPResponse built")
_eq(http_resp_empty.body, {}, "empty body stored as empty dict")

# ===========================================================================
# §35  build_http_request — timeout comes from config
# ===========================================================================
print("§35  build_http_request timeout from config ...")
cfg_t30 = build_http_config(api_key=_KEY, timeout_seconds=30)
hr_t30  = build_http_request(cfg_t30, _GROQ_REQ)
_eq(hr_t30.timeoutSeconds, 30, "timeout 30s from config")

cfg_t90 = build_http_config(api_key=_KEY, timeout_seconds=90)
hr_t90  = build_http_request(cfg_t90, _GROQ_REQ)
_eq(hr_t90.timeoutSeconds, 90, "timeout 90s from config")

# Different timeouts → different GroqHTTPRequest objects (createdAt differs) but same requestId
# (requestId is based on payload+requestId, not config timeout)
_eq(hr_t30.requestId, hr_t90.requestId, "requestId independent of timeout value")

# ===========================================================================
# §36  Metrics success rate and failure rate calculations
# ===========================================================================
print("§36  Metrics rate calculations ...")
reset_metrics()
from services.groq_http_client import _metrics as _m

_m.record_success(latency_ms=100, retry_count=0, total_tokens=50, estimated_cost=0.001)
_m.record_success(latency_ms=200, retry_count=1, total_tokens=80, estimated_cost=0.002)
_m.record_failure(latency_ms=300, retry_count=2)

snap_rates = get_metrics_snapshot()
_eq(snap_rates["totalRequests"],  3, "3 total requests")
_eq(snap_rates["totalSuccesses"], 2, "2 successes")
_eq(snap_rates["totalFailures"],  1, "1 failure")
_eq(snap_rates["totalRetries"],   3, "3 total retries (0+1+2)")
_eq(round(snap_rates["successRate"], 4), round(2/3, 4), "successRate = 2/3")
_eq(round(snap_rates["failureRate"],  4), round(1/3, 4), "failureRate = 1/3")
_eq(snap_rates["totalTokens"],  130, "totalTokens = 50+80")
_gt(snap_rates["averageLatencyMs"], 0, "averageLatencyMs > 0")
_eq(round(snap_rates["averageLatencyMs"], 2), round((100+200+300)/3, 2), "averageLatencyMs = 200")

# totalEstimatedCost
_eq(round(snap_rates["totalEstimatedCost"], 8), round(0.001+0.002, 8), "totalEstimatedCost accurate")

# ===========================================================================
# §37  Zero randomness — build 10 times, always identical
# ===========================================================================
print("§37  Zero randomness — 10 builds ...")
req_id_set  = {build_http_request(cfg, _GROQ_REQ).requestId for _ in range(10)}
resp_id_set = {build_http_response(200, {}, _GOOD_BODY, i).responseId for i in range(10)}
_eq(len(req_id_set),  1, "zero randomness: 10 http_request builds identical")
_eq(len(resp_id_set), 1, "zero randomness: 10 http_response builds identical")

# ===========================================================================
# §38  __all__ exports are all importable
# ===========================================================================
print("§38  __all__ exports ...")
from services.groq_http_client import __all__ as _all_exports
_assert(len(_all_exports) >= 20, "__all__ has at least 20 exports")
_in("GroqHTTPConfig",    _all_exports, "__all__ includes GroqHTTPConfig")
_in("GroqHTTPResult",    _all_exports, "__all__ includes GroqHTTPResult")
_in("send_request",      _all_exports, "__all__ includes send_request")
_in("send_async_request",_all_exports, "__all__ includes send_async_request")
_in("parse_response",    _all_exports, "__all__ includes parse_response")
_in("parse_error",       _all_exports, "__all__ includes parse_error")
_in("build_http_config", _all_exports, "__all__ includes build_http_config")
_in("AuthenticationError",_all_exports,"__all__ includes AuthenticationError")
_in("RateLimitError",    _all_exports, "__all__ includes RateLimitError")
_in("TimeoutError",      _all_exports, "__all__ includes TimeoutError")
_in("ServerError",       _all_exports, "__all__ includes ServerError")
_in("ValidationError",   _all_exports, "__all__ includes ValidationError")
_in("ProviderError",     _all_exports, "__all__ includes ProviderError")
_in("get_metrics_snapshot",_all_exports,"__all__ includes get_metrics_snapshot")
_in("reset_metrics",     _all_exports, "__all__ includes reset_metrics")

# ===========================================================================
# §39  Identical mocked responses → identical parsed GroqResponse objects
# ===========================================================================
print("§39  Idempotent mocked response parsing ...")
parsed_set = set()
for _ in range(5):
    resp_i = build_http_response(200, {}, _GOOD_BODY, 100)
    gr_i   = parse_response(_GROQ_REQ, resp_i, _TS)
    parsed_set.add((gr_i.responseId, gr_i.content, gr_i.finishReason,
                    gr_i.usage.totalTokens, gr_i.usage.estimatedCost))
_eq(len(parsed_set), 1, "5 identical mocked responses → 1 unique parsed object")

# ===========================================================================
# Final report
# ===========================================================================
print()
print("=" * 60)
print(f"  {_PASS + _FAIL} assertions run")
print(f"  {_PASS} passed")
print(f"  {_FAIL} failed")
print("=" * 60)

if _ERRORS:
    print("\nFAILURES:")
    for e in _ERRORS:
        print(" ", e)

if _FAIL > 0:
    sys.exit(1)
else:
    print(f"\n✓ {_PASS}/{_PASS} assertions passed")
