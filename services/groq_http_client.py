"""
Groq HTTP Client
================
Phase A4.2.1 — Deterministic HTTP communication layer between
NetFusion and the Groq REST API.

Responsibilities
----------------
- Send a GroqRequest to the Groq Chat Completions API over HTTPS.
- Return a parsed GroqResponse (using builders from groq_provider_service).
- Implement configurable retry logic for transient errors.
- Implement configurable timeouts.
- Produce structured logs (never log API keys).
- Track latency, retry count, success/failure metrics.

This service is a PURE HTTP TRANSPORT LAYER.
It contains NO AI reasoning, NO prompt generation, NO investigation logic,
NO attack graph logic, NO timeline logic, NO evidence logic.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs.
- No uuid4(). No random module.
- HTTP library: httpx.AsyncClient only.
- API key loaded from environment/config — never hardcoded.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from core.config import GROQ_API_KEY
from core.constants import (
    GROQ_API_ENDPOINT,
    GROQ_HTTP_ACCEPT,
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
    GROQ_HTTP_CONTENT_TYPE,
    GROQ_HTTP_DEFAULT_MAX_RETRIES,
    GROQ_HTTP_DEFAULT_RETRY_DELAY_MS,
    GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS,
    GROQ_HTTP_DEFAULT_USER_AGENT,
    GROQ_HTTP_NON_RETRYABLE_STATUS_CODES,
    GROQ_HTTP_RETRYABLE_STATUS_CODES,
    GROQ_API_VERSION,
)
from core.logging import get_logger
from services.groq_provider_service import (
    GroqRequest,
    GroqResponse,
    build_response,
    normalize_model_name,
)

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("groq_http_client")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; same as groq_provider_service
# ---------------------------------------------------------------------------
_HTTP_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class GroqHTTPError(Exception):
    """Base class for all Groq HTTP Client errors."""
    def __init__(
        self,
        message: str,
        status_code: int = 0,
        provider_message: str = "",
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code      = status_code
        self.provider_message = provider_message
        self.retryable        = retryable

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"status_code={self.status_code}, "
            f"retryable={self.retryable}, "
            f"message={str(self)!r})"
        )


class AuthenticationError(GroqHTTPError):
    """Raised when Groq returns 401 Unauthorized."""
    def __init__(self, provider_message: str = "") -> None:
        super().__init__(
            "Groq authentication failed. Check GROQ_API_KEY.",
            status_code=401,
            provider_message=provider_message,
            retryable=False,
        )


class RateLimitError(GroqHTTPError):
    """Raised when Groq returns 429 Too Many Requests."""
    def __init__(self, provider_message: str = "") -> None:
        super().__init__(
            "Groq rate limit exceeded.",
            status_code=429,
            provider_message=provider_message,
            retryable=True,
        )


class TimeoutError(GroqHTTPError):
    """Raised when the request times out."""
    def __init__(self, provider_message: str = "") -> None:
        super().__init__(
            "Groq request timed out.",
            status_code=0,
            provider_message=provider_message,
            retryable=True,
        )


class ServerError(GroqHTTPError):
    """Raised for Groq 5xx server errors."""
    def __init__(self, status_code: int, provider_message: str = "") -> None:
        super().__init__(
            f"Groq server error: HTTP {status_code}.",
            status_code=status_code,
            provider_message=provider_message,
            retryable=True,
        )


class ValidationError(GroqHTTPError):
    """Raised for HTTP 400 / 422 bad request errors."""
    def __init__(self, status_code: int, provider_message: str = "") -> None:
        super().__init__(
            f"Groq request validation error: HTTP {status_code}.",
            status_code=status_code,
            provider_message=provider_message,
            retryable=False,
        )


class ProviderError(GroqHTTPError):
    """Raised for any other non-retryable Groq provider error."""
    def __init__(self, status_code: int, provider_message: str = "") -> None:
        super().__init__(
            f"Groq provider error: HTTP {status_code}.",
            status_code=status_code,
            provider_message=provider_message,
            retryable=False,
        )


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class GroqHTTPConfig(BaseModel):
    """
    Immutable configuration for the Groq HTTP Client.

    Fields
    ------
    apiKey          : Groq API key (loaded from environment).
    endpoint        : Groq API endpoint URL.
    apiVersion      : Groq API version string.
    timeoutSeconds  : per-request timeout in seconds.
    maxRetries      : maximum number of retry attempts.
    retryDelayMs    : base delay between retries in milliseconds.
    verifySSL       : whether to verify SSL certificates.
    userAgent       : HTTP User-Agent header value.
    engineVersion   : GROQ_HTTP_CLIENT_ENGINE_VERSION.
    """
    apiKey        : str
    endpoint      : str
    apiVersion    : str
    timeoutSeconds: int
    maxRetries    : int
    retryDelayMs  : int
    verifySSL     : bool
    userAgent     : str
    engineVersion : str

    class Config:
        frozen = True

    def masked_key(self) -> str:
        """Return a safely masked representation of the API key."""
        k = self.apiKey
        if len(k) <= 8:
            return "***"
        return k[:4] + "***" + k[-4:]


class GroqHTTPRequest(BaseModel):
    """
    Immutable record of one outgoing HTTP request.

    Fields
    ------
    requestId      : deterministic UUIDv5 derived from payload hash.
    url            : target endpoint URL.
    headers        : HTTP headers (API key is masked in logs).
    payload        : JSON-serialisable request body dict.
    timeoutSeconds : timeout for this specific request.
    createdAt      : monotonic timestamp (ms) when this object was built.
    """
    requestId     : str
    url           : str
    headers       : Dict[str, str]
    payload       : Dict[str, Any]
    timeoutSeconds: int
    createdAt     : int   # monotonic ms

    class Config:
        frozen = True


class GroqHTTPResponse(BaseModel):
    """
    Immutable record of one raw HTTP response received from Groq.

    Fields
    ------
    responseId  : deterministic UUIDv5 derived from body hash.
    statusCode  : HTTP status code.
    headers     : response headers dict.
    body        : raw JSON body as a dict (or empty dict on error).
    latencyMs   : wall-clock ms between request send and response received.
    receivedAt  : monotonic timestamp (ms) when response was received.
    """
    responseId : str
    statusCode : int
    headers    : Dict[str, str]
    body       : Dict[str, Any]
    latencyMs  : int
    receivedAt : int   # monotonic ms

    class Config:
        frozen = True


class GroqHTTPResult(BaseModel):
    """
    Immutable result object returned to callers after one complete
    HTTP round-trip (including all retries).

    Fields
    ------
    request    : GroqHTTPRequest that was sent.
    response   : GroqHTTPResponse that was received (or None on total failure).
    success    : True if the request completed with a 2xx response.
    error      : GroqHTTPError subclass message string (None on success).
    retryCount : number of retries attempted (0 = no retries).
    metadata   : arbitrary provenance dict (engine version, timestamps, etc.).
    """
    request    : GroqHTTPRequest
    response   : Optional[GroqHTTPResponse]
    success    : bool
    error      : Optional[str]
    retryCount : int
    metadata   : Dict[str, Any]

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5_http(key: str) -> str:
    """UUIDv5(_HTTP_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_HTTP_NS, key))


def _mono_ms() -> int:
    """Monotonic clock in milliseconds (for latency measurement only)."""
    return int(time.monotonic() * 1000)


def _mask_api_key(key: str) -> str:
    """Safely mask an API key for logging. Never logs the real key."""
    if not key:
        return "***"
    if len(key) <= 8:
        return "***"
    return key[:4] + "***" + key[-4:]


# ===========================================================================
# Builder: build_http_config()
# ===========================================================================

def build_http_config(
    api_key        : Optional[str] = None,
    endpoint       : str           = GROQ_API_ENDPOINT,
    api_version    : str           = GROQ_API_VERSION,
    timeout_seconds: int           = GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS,
    max_retries    : int           = GROQ_HTTP_DEFAULT_MAX_RETRIES,
    retry_delay_ms : int           = GROQ_HTTP_DEFAULT_RETRY_DELAY_MS,
    verify_ssl     : bool          = True,
    user_agent     : str           = GROQ_HTTP_DEFAULT_USER_AGENT,
) -> GroqHTTPConfig:
    """
    Build an immutable GroqHTTPConfig.

    API key is read from the ``api_key`` parameter first; if None, falls back
    to GROQ_API_KEY from core/config.py (which reads the environment).
    Raises ValueError if no API key is found.

    Parameters
    ----------
    api_key         : explicit API key override (None = use env var).
    endpoint        : Groq REST endpoint URL.
    api_version     : Groq API version string.
    timeout_seconds : per-request HTTP timeout in seconds (≥ 1).
    max_retries     : max retry attempts (≥ 0).
    retry_delay_ms  : base retry delay in ms (≥ 0).
    verify_ssl      : whether to verify SSL certificates.
    user_agent      : HTTP User-Agent string.

    Returns
    -------
    GroqHTTPConfig (frozen / immutable)

    Raises
    ------
    ValueError : if no API key is available.
    """
    # Treat empty string as "not provided" — only fall back to env if caller
    # passed None (i.e. did not explicitly supply a key).
    if api_key is None:
        resolved_key = GROQ_API_KEY or ""
    else:
        resolved_key = api_key  # use exactly what was passed (even if empty)
    if not resolved_key:
        raise ValueError(
            "GROQ_API_KEY is not set. "
            "Set the GROQ_API_KEY environment variable or pass api_key explicitly."
        )
    return GroqHTTPConfig(
        apiKey         = resolved_key,
        endpoint       = endpoint.strip(),
        apiVersion     = api_version.strip(),
        timeoutSeconds = max(1, int(timeout_seconds)),
        maxRetries     = max(0, int(max_retries)),
        retryDelayMs   = max(0, int(retry_delay_ms)),
        verifySSL      = bool(verify_ssl),
        userAgent      = user_agent.strip(),
        engineVersion  = GROQ_HTTP_CLIENT_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_headers()
# ===========================================================================

def build_headers(config: GroqHTTPConfig) -> Dict[str, str]:
    """
    Build the HTTP headers dict for a Groq API request.

    The Authorization header includes the real API key.
    This dict must NEVER be logged directly — use _mask_headers() for logs.

    Parameters
    ----------
    config : GroqHTTPConfig

    Returns
    -------
    Dict[str, str] — headers dict (new object; config not mutated).
    """
    return {
        "Authorization" : f"Bearer {config.apiKey}",
        "Content-Type"  : GROQ_HTTP_CONTENT_TYPE,
        "Accept"        : GROQ_HTTP_ACCEPT,
        "User-Agent"    : config.userAgent,
        "X-Groq-Version": config.apiVersion,
    }


def _mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with the Authorization value masked."""
    masked = dict(headers)
    if "Authorization" in masked:
        auth = masked["Authorization"]
        # Keep "Bearer " prefix, mask the key part
        if auth.startswith("Bearer "):
            key_part = auth[7:]
            masked["Authorization"] = "Bearer " + _mask_api_key(key_part)
        else:
            masked["Authorization"] = "Bearer ***"
    return masked


# ===========================================================================
# Builder: build_payload()
# ===========================================================================

def build_payload(groq_request: GroqRequest) -> Dict[str, Any]:
    """
    Convert a GroqRequest into the JSON payload dict for the Groq API.

    Parameters
    ----------
    groq_request : GroqRequest from groq_provider_service.

    Returns
    -------
    Dict[str, Any] — JSON-serialisable payload (new dict; request not mutated).
    """
    messages = [
        {
            "role"   : m.role,
            "content": m.content,
            **({"name": m.name} if m.name else {}),
            **({"tool_call_id": m.toolCallId} if m.toolCallId else {}),
        }
        for m in groq_request.messages
    ]
    payload: Dict[str, Any] = {
        "model"      : groq_request.model,
        "messages"   : messages,
        "temperature": groq_request.temperature,
        "top_p"      : groq_request.topP,
        "max_tokens" : groq_request.maxTokens,
        "stream"     : groq_request.stream,
    }
    return payload


# ===========================================================================
# Builder: build_http_request()
# ===========================================================================

def build_http_request(
    config      : GroqHTTPConfig,
    groq_request: GroqRequest,
) -> GroqHTTPRequest:
    """
    Build an immutable GroqHTTPRequest from config + GroqRequest.

    requestId is UUIDv5 derived from the SHA256 of the payload JSON.
    This ensures identical payloads always produce identical requestIds.

    Parameters
    ----------
    config       : GroqHTTPConfig
    groq_request : GroqRequest to be sent.

    Returns
    -------
    GroqHTTPRequest (frozen / immutable)
    """
    headers = build_headers(config)
    payload = build_payload(groq_request)

    # Deterministic ID from payload content
    payload_json  = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    payload_hash  = _sha256_32(payload_json, groq_request.requestId)
    request_id    = _uuid5_http(payload_hash)

    return GroqHTTPRequest(
        requestId      = request_id,
        url            = config.endpoint,
        headers        = headers,
        payload        = payload,
        timeoutSeconds = config.timeoutSeconds,
        createdAt      = _mono_ms(),
    )


# ===========================================================================
# Builder: build_http_response()
# ===========================================================================

def build_http_response(
    status_code: int,
    headers    : Dict[str, str],
    body       : Dict[str, Any],
    latency_ms : int,
) -> GroqHTTPResponse:
    """
    Build an immutable GroqHTTPResponse from a raw httpx response.

    responseId is UUIDv5 derived from SHA256 of (statusCode + body JSON).

    Parameters
    ----------
    status_code : HTTP status code.
    headers     : response headers dict.
    body        : parsed JSON body (or empty dict).
    latency_ms  : wall-clock ms for this round-trip.

    Returns
    -------
    GroqHTTPResponse (frozen / immutable)
    """
    body_json   = json.dumps(body, sort_keys=True, ensure_ascii=True)
    resp_hash   = _sha256_32(str(status_code), body_json)
    response_id = _uuid5_http(resp_hash)

    return GroqHTTPResponse(
        responseId  = response_id,
        statusCode  = status_code,
        headers     = dict(headers),
        body        = body,
        latencyMs   = max(0, int(latency_ms)),
        receivedAt  = _mono_ms(),
    )


# ===========================================================================
# Builder: build_http_result()
# ===========================================================================

def build_http_result(
    http_request : GroqHTTPRequest,
    http_response: Optional[GroqHTTPResponse],
    success      : bool,
    error        : Optional[str],
    retry_count  : int,
    extra_meta   : Optional[Dict[str, Any]] = None,
) -> GroqHTTPResult:
    """
    Build an immutable GroqHTTPResult combining request, response, and metadata.

    Parameters
    ----------
    http_request  : GroqHTTPRequest that was sent.
    http_response : GroqHTTPResponse received (None on complete failure).
    success       : True if a 2xx response was received.
    error         : error message string (None on success).
    retry_count   : number of retries attempted.
    extra_meta    : additional metadata to merge.

    Returns
    -------
    GroqHTTPResult (frozen / immutable)
    """
    metadata: Dict[str, Any] = {
        "engineVersion": GROQ_HTTP_CLIENT_ENGINE_VERSION,
        "retryCount"   : retry_count,
        "success"      : success,
    }
    if extra_meta:
        metadata.update(extra_meta)

    return GroqHTTPResult(
        request    = http_request,
        response   = http_response,
        success    = success,
        error      = error,
        retryCount = max(0, int(retry_count)),
        metadata   = metadata,
    )


# ===========================================================================
# Error parsing
# ===========================================================================

def parse_error(
    status_code    : int,
    body           : Dict[str, Any],
    is_timeout     : bool = False,
) -> GroqHTTPError:
    """
    Parse a Groq API error response into a typed GroqHTTPError subclass.

    Retry rules:
    - 429 → RateLimitError  (retryable=True)
    - 500, 502, 503, 504 → ServerError  (retryable=True)
    - timeout → TimeoutError  (retryable=True)
    - 401 → AuthenticationError  (retryable=False)
    - 400, 403, 404 → ValidationError or ProviderError  (retryable=False)
    - other → ProviderError  (retryable=False)

    Parameters
    ----------
    status_code : HTTP status code (0 for connection/timeout errors).
    body        : parsed JSON error body dict.
    is_timeout  : True if the error was a timeout, not an HTTP status error.

    Returns
    -------
    A GroqHTTPError subclass (never raises).
    """
    # Extract provider error message from body
    provider_msg = ""
    error_obj = body.get("error", {})
    if isinstance(error_obj, dict):
        provider_msg = str(error_obj.get("message", ""))
    elif isinstance(error_obj, str):
        provider_msg = error_obj

    if is_timeout:
        return TimeoutError(provider_message=provider_msg)

    if status_code == 401:
        return AuthenticationError(provider_message=provider_msg)

    if status_code == 429:
        return RateLimitError(provider_message=provider_msg)

    if status_code in (400, 422):
        return ValidationError(status_code=status_code, provider_message=provider_msg)

    if status_code in (500, 502, 503, 504):
        return ServerError(status_code=status_code, provider_message=provider_msg)

    # 403, 404, or anything else non-retryable
    return ProviderError(status_code=status_code, provider_message=provider_msg)


# ===========================================================================
# Response parsing
# ===========================================================================

def parse_response(
    groq_request  : GroqRequest,
    http_response : GroqHTTPResponse,
    created_at    : str,
) -> GroqResponse:
    """
    Parse a successful GroqHTTPResponse into a GroqResponse.

    Uses build_response() from groq_provider_service to produce an
    immutable, deterministic GroqResponse with proper usage and metadata.

    Parameters
    ----------
    groq_request  : original GroqRequest (provides requestId, model).
    http_response : GroqHTTPResponse with parsed JSON body.
    created_at    : ISO-8601 timestamp for the response (caller-supplied).

    Returns
    -------
    GroqResponse (frozen / immutable)

    Raises
    ------
    ValidationError : if the response body structure is invalid.
    """
    body = http_response.body

    # Extract choices[0].message.content
    choices = body.get("choices", [])
    if not choices or not isinstance(choices, list):
        raise ValidationError(
            status_code=http_response.statusCode,
            provider_message="Response body missing 'choices' array.",
        )

    choice     = choices[0]
    message    = choice.get("message", {})
    content    = message.get("content", "") or ""
    finish_reason = str(choice.get("finish_reason", "stop") or "stop")

    # Extract usage
    usage_raw        = body.get("usage", {}) or {}
    prompt_tokens    = int(usage_raw.get("prompt_tokens",     0) or 0)
    completion_tokens= int(usage_raw.get("completion_tokens", 0) or 0)

    model = normalize_model_name(
        body.get("model", groq_request.model) or groq_request.model
    )

    return build_response(
        request_id         = groq_request.requestId,
        model              = model,
        content            = content,
        finish_reason      = finish_reason,
        created_at         = created_at,
        prompt_tokens      = prompt_tokens,
        completion_tokens  = completion_tokens,
        latency_ms         = http_response.latencyMs,
        processing_time_ms = 0,
        warnings           = [],
        validate           = True,
    )


# ===========================================================================
# Metrics tracker (pure, in-process, no external dependencies)
# ===========================================================================

class _HTTPMetrics:
    """
    Lightweight in-process metrics accumulator.

    Tracks: total requests, successes, failures, retries,
    total latency (ms), total tokens, estimated cost.

    Thread-safety: not guaranteed — suitable for single-threaded / asyncio use.
    """
    __slots__ = (
        "total_requests", "total_successes", "total_failures",
        "total_retries", "total_latency_ms", "total_tokens",
        "total_estimated_cost",
    )

    def __init__(self) -> None:
        self.total_requests      : int   = 0
        self.total_successes     : int   = 0
        self.total_failures      : int   = 0
        self.total_retries       : int   = 0
        self.total_latency_ms    : int   = 0
        self.total_tokens        : int   = 0
        self.total_estimated_cost: float = 0.0

    def record_success(
        self,
        latency_ms    : int,
        retry_count   : int,
        total_tokens  : int,
        estimated_cost: float,
    ) -> None:
        self.total_requests   += 1
        self.total_successes  += 1
        self.total_retries    += retry_count
        self.total_latency_ms += latency_ms
        self.total_tokens     += total_tokens
        self.total_estimated_cost += estimated_cost

    def record_failure(self, latency_ms: int, retry_count: int) -> None:
        self.total_requests   += 1
        self.total_failures   += 1
        self.total_retries    += retry_count
        self.total_latency_ms += latency_ms

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return round(self.total_successes / self.total_requests, 6)

    @property
    def failure_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return round(self.total_failures / self.total_requests, 6)

    @property
    def average_latency_ms(self) -> float:
        n = self.total_successes + self.total_failures
        if n == 0:
            return 0.0
        return round(self.total_latency_ms / n, 2)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "totalRequests"     : self.total_requests,
            "totalSuccesses"    : self.total_successes,
            "totalFailures"     : self.total_failures,
            "totalRetries"      : self.total_retries,
            "totalLatencyMs"    : self.total_latency_ms,
            "totalTokens"       : self.total_tokens,
            "totalEstimatedCost": round(self.total_estimated_cost, 8),
            "successRate"       : self.success_rate,
            "failureRate"       : self.failure_rate,
            "averageLatencyMs"  : self.average_latency_ms,
        }


# Module-level metrics instance (shared across all send_request calls)
_metrics = _HTTPMetrics()


def get_metrics_snapshot() -> Dict[str, Any]:
    """Return a snapshot of the current HTTP client metrics."""
    return _metrics.snapshot()


def reset_metrics() -> None:
    """Reset all accumulated metrics to zero (useful in tests)."""
    global _metrics
    _metrics = _HTTPMetrics()


# ===========================================================================
# Core async HTTP send
# ===========================================================================

async def send_async_request(
    config      : GroqHTTPConfig,
    groq_request: GroqRequest,
    created_at  : str,
) -> Tuple[GroqHTTPResult, Optional[GroqResponse]]:
    """
    Send a GroqRequest to the Groq REST API asynchronously.

    Implements configurable retry logic for transient errors.
    Retryable: HTTP 429, 500, 502, 503, 504, connection timeout.
    Non-retryable: HTTP 400, 401, 403, 404.

    Parameters
    ----------
    config       : GroqHTTPConfig — connection settings and credentials.
    groq_request : GroqRequest — the request to send.
    created_at   : ISO-8601 timestamp string (caller-supplied for determinism).

    Returns
    -------
    Tuple of:
      - GroqHTTPResult  — full round-trip record (always returned).
      - GroqResponse    — parsed response (None on failure).

    Raises
    ------
    Never raises — all errors are captured in GroqHTTPResult.error.
    """
    http_req    = build_http_request(config, groq_request)
    start_ms    = _mono_ms()
    retry_count = 0
    last_error  : Optional[str] = None
    last_http_response: Optional[GroqHTTPResponse] = None

    _log.info(
        f"[groq_http_client] request_started "
        f"request_id={http_req.requestId} "
        f"model={groq_request.model} "
        f"endpoint={config.endpoint} "
        f"max_retries={config.maxRetries} "
        f"timeout={config.timeoutSeconds}s "
        f"api_key={_mask_api_key(config.apiKey)}"
    )

    async with httpx.AsyncClient(verify=config.verifySSL) as client:
        for attempt in range(config.maxRetries + 1):
            attempt_start = _mono_ms()
            try:
                raw_resp = await client.post(
                    http_req.url,
                    headers = http_req.headers,
                    json    = http_req.payload,
                    timeout = config.timeoutSeconds,
                )
                attempt_end = _mono_ms()
                latency     = attempt_end - attempt_start

                # Parse raw response body
                try:
                    body = raw_resp.json()
                    if not isinstance(body, dict):
                        body = {"raw": body}
                except Exception:
                    body = {}

                resp_headers = dict(raw_resp.headers)
                last_http_response = build_http_response(
                    status_code = raw_resp.status_code,
                    headers     = resp_headers,
                    body        = body,
                    latency_ms  = latency,
                )

                if raw_resp.status_code == 200:
                    # Success path
                    total_ms = _mono_ms() - start_ms
                    groq_resp = parse_response(groq_request, last_http_response, created_at)
                    result = build_http_result(
                        http_request  = http_req,
                        http_response = last_http_response,
                        success       = True,
                        error         = None,
                        retry_count   = retry_count,
                        extra_meta    = {
                            "totalLatencyMs" : total_ms,
                            "attemptNumber"  : attempt + 1,
                        },
                    )
                    _metrics.record_success(
                        latency_ms     = total_ms,
                        retry_count    = retry_count,
                        total_tokens   = groq_resp.usage.totalTokens,
                        estimated_cost = groq_resp.usage.estimatedCost,
                    )
                    _log.info(
                        f"[groq_http_client] request_completed "
                        f"request_id={http_req.requestId} "
                        f"status=200 latency_ms={total_ms} "
                        f"retries={retry_count} "
                        f"tokens={groq_resp.usage.totalTokens} "
                        f"cost_usd={groq_resp.usage.estimatedCost}"
                    )
                    return result, groq_resp

                # Error path — determine if retryable
                err = parse_error(raw_resp.status_code, body, is_timeout=False)
                last_error = str(err)

                _log.warning(
                    f"[groq_http_client] request_failed "
                    f"request_id={http_req.requestId} "
                    f"status={raw_resp.status_code} "
                    f"retryable={err.retryable} "
                    f"attempt={attempt + 1}/{config.maxRetries + 1} "
                    f"error={last_error}"
                )

                if not err.retryable or attempt >= config.maxRetries:
                    break

                retry_count += 1
                delay_s = (config.retryDelayMs * (2 ** retry_count)) / 1000.0
                _log.info(
                    f"[groq_http_client] retry_scheduled "
                    f"request_id={http_req.requestId} "
                    f"retry={retry_count} "
                    f"delay_s={delay_s:.3f}"
                )
                await asyncio.sleep(delay_s)

            except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
                attempt_end = _mono_ms()
                latency = attempt_end - attempt_start
                err = TimeoutError(provider_message=str(exc))
                last_error = str(err)

                _log.warning(
                    f"[groq_http_client] timeout "
                    f"request_id={http_req.requestId} "
                    f"attempt={attempt + 1}/{config.maxRetries + 1} "
                    f"latency_ms={latency}"
                )

                if attempt >= config.maxRetries:
                    break

                retry_count += 1
                delay_s = (config.retryDelayMs * (2 ** retry_count)) / 1000.0
                _log.info(
                    f"[groq_http_client] retry_scheduled_after_timeout "
                    f"request_id={http_req.requestId} "
                    f"retry={retry_count} delay_s={delay_s:.3f}"
                )
                await asyncio.sleep(delay_s)

            except Exception as exc:
                last_error = f"Unexpected error: {exc}"
                _log.error(
                    f"[groq_http_client] unexpected_error "
                    f"request_id={http_req.requestId} "
                    f"attempt={attempt + 1} "
                    f"error={last_error}"
                )
                break

    # All attempts exhausted — return failure result
    total_ms = _mono_ms() - start_ms
    result = build_http_result(
        http_request  = http_req,
        http_response = last_http_response,
        success       = False,
        error         = last_error,
        retry_count   = retry_count,
        extra_meta    = {"totalLatencyMs": total_ms},
    )
    _metrics.record_failure(latency_ms=total_ms, retry_count=retry_count)
    _log.error(
        f"[groq_http_client] request_exhausted "
        f"request_id={http_req.requestId} "
        f"retries={retry_count} "
        f"total_ms={total_ms} "
        f"error={last_error}"
    )
    return result, None


# ===========================================================================
# Synchronous wrapper
# ===========================================================================

def send_request(
    config      : GroqHTTPConfig,
    groq_request: GroqRequest,
    created_at  : str,
) -> Tuple[GroqHTTPResult, Optional[GroqResponse]]:
    """
    Synchronous wrapper around send_async_request().

    Uses asyncio.run() when there is no running event loop, or falls back
    to creating a new event loop when one is already running.

    Parameters
    ----------
    config       : GroqHTTPConfig
    groq_request : GroqRequest
    created_at   : ISO-8601 timestamp string (caller-supplied for determinism).

    Returns
    -------
    Tuple[GroqHTTPResult, Optional[GroqResponse]]
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    coro = send_async_request(config, groq_request, created_at)

    if loop is None:
        # No running loop — safe to use asyncio.run()
        return asyncio.run(coro)
    else:
        # Running inside an existing event loop (e.g. Jupyter, some test runners)
        # Create a new loop in a thread to avoid nesting issues
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()


# ===========================================================================
# Public re-exports for streaming preparation
# ===========================================================================
# Streaming is NOT implemented in this version.
# The public API surface is designed so that a future streaming=True path
# can be added to send_async_request() without changing its signature.
# Callers should check GroqHTTPResult.success and inspect
# GroqResponse directly — no changes to their call sites will be needed.

__all__ = [
    # Exceptions
    "GroqHTTPError",
    "AuthenticationError",
    "RateLimitError",
    "TimeoutError",
    "ServerError",
    "ValidationError",
    "ProviderError",
    # Models
    "GroqHTTPConfig",
    "GroqHTTPRequest",
    "GroqHTTPResponse",
    "GroqHTTPResult",
    # Builders
    "build_http_config",
    "build_http_request",
    "build_http_response",
    "build_http_result",
    "build_headers",
    "build_payload",
    # HTTP functions
    "send_request",
    "send_async_request",
    # Parsers
    "parse_response",
    "parse_error",
    # Metrics
    "get_metrics_snapshot",
    "reset_metrics",
    # Constants re-export
    "GROQ_HTTP_CLIENT_ENGINE_VERSION",
]
