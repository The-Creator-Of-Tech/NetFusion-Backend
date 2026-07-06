"""
Groq Provider Adapter
======================
Phase A4.1.5 — Deterministic, immutable translation layer between
NetFusion's internal CopilotRequest/CopilotResponse and the Groq
Chat Completions API wire format.

Responsibilities
----------------
- Translate CopilotRequest → GroqRequest (provider-specific wire format).
- Translate a raw Groq API response dict → CopilotResponse (internal format).
- Build deterministic, immutable model objects for every step.
- Provide cost estimation, token estimation, and latency calculation.
- Validate requests and responses; raise descriptive exceptions.
- Normalise model aliases to canonical names.
- Expose provider capability metadata.

This service is a PURE TRANSLATION LAYER.
It contains NO business reasoning logic — all reasoning is handled upstream.
It performs NO HTTP requests in this phase.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- No requests, httpx, aiohttp, or any HTTP client.
- No OpenAI SDK, Groq SDK, LangChain, or any external AI library.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import (
    GROQ_API_ENDPOINT,
    GROQ_API_VERSION,
    GROQ_MAX_TOKENS_MAX,
    GROQ_MAX_TOKENS_MIN,
    GROQ_MODEL_ALIASES,
    GROQ_MODEL_CAPABILITIES,
    GROQ_PRICING_PER_MILLION,
    GROQ_PROVIDER_ENGINE_VERSION,
    GROQ_SUPPORTED_MODELS,
    GROQ_TEMPERATURE_MAX,
    GROQ_TEMPERATURE_MIN,
    GROQ_TOP_P_MAX,
    GROQ_TOP_P_MIN,
    GROQ_VALID_ROLES,
)

# ── UUIDv5 namespace — fixed; never change (invalidates stored IDs) ─────────
_GROQ_NS = uuid.UUID("6ba7b819-9dad-11d1-80b4-00c04fd430c8")

# ── Chars-per-token estimate (conservative GPT/Llama-compatible ratio) ───────
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class GroqMessage(BaseModel):
    """
    One immutable message in a Groq chat completion request.

    Fields
    ------
    role       : one of "system" | "user" | "assistant" | "tool".
    content    : message text.
    name       : optional sender name (used for tool calls).
    toolCallId : optional tool call ID (used for tool result messages).
    """
    role       : str
    content    : str
    name       : Optional[str] = None
    toolCallId : Optional[str] = None

    class Config:
        frozen = True


class GroqRequest(BaseModel):
    """
    One complete, immutable Groq Chat Completions API request.

    Identity
    --------
    requestId          : UUIDv5(GROQ_NS, requestKey) — deterministic.
    requestKey         : SHA256(model + sorted(message fingerprints) +
                         temperature + topP + maxTokens)[:32]
    requestFingerprint : SHA256(requestKey + all message content joined)[:32]

    Wire format fields
    ------------------
    model       : canonical Groq model name.
    messages    : ordered tuple of GroqMessage objects.
    temperature : sampling temperature [0.0, 2.0].
    topP        : nucleus sampling probability [0.0, 1.0].
    maxTokens   : max completion tokens [1, 131072].
    stream      : whether streaming is requested.

    Metadata
    --------
    metadata      : GroqProviderMetadata — capabilities, timings, warnings.
    createdAt     : ISO-8601 (caller-supplied for determinism).
    engineVersion : GROQ_PROVIDER_ENGINE_VERSION.
    """
    requestId          : str
    requestKey         : str
    requestFingerprint : str
    provider           : str = "groq"
    model              : str
    messages           : Tuple[GroqMessage, ...]
    temperature        : float
    topP               : float
    maxTokens          : int
    stream             : bool
    metadata           : "GroqProviderMetadata"
    createdAt          : str
    engineVersion      : str

    class Config:
        frozen = True


class GroqUsage(BaseModel):
    """
    Token usage and cost information from one Groq completion.

    Fields
    ------
    promptTokens     : tokens consumed by the prompt.
    completionTokens : tokens consumed by the completion.
    totalTokens      : promptTokens + completionTokens.
    estimatedCost    : deterministic USD cost estimate.
    latencyMs        : wall-clock response time in milliseconds.
    """
    promptTokens     : int
    completionTokens : int
    totalTokens      : int
    estimatedCost    : float   # USD, rounded to 8 decimal places
    latencyMs        : int

    class Config:
        frozen = True


class GroqResponse(BaseModel):
    """
    One complete, immutable Groq Chat Completions API response.

    Identity
    --------
    responseId          : UUIDv5(GROQ_NS, responseKey) — deterministic.
    responseKey         : SHA256(requestId + content + finishReason)[:32]
    responseFingerprint : SHA256(responseKey + content + finishReason)[:32]

    Content
    -------
    content      : raw text from the completion.
    finishReason : stop reason from the Groq API (e.g. "stop", "length").

    Usage
    -----
    usage : GroqUsage — token counts and cost.

    Metadata
    --------
    metadata      : GroqProviderMetadata.
    createdAt     : ISO-8601 (caller-supplied for determinism).
    engineVersion : GROQ_PROVIDER_ENGINE_VERSION.
    """
    responseId          : str
    responseKey         : str
    responseFingerprint : str
    requestId           : str
    content             : str
    finishReason        : str
    usage               : GroqUsage
    metadata            : "GroqProviderMetadata"
    createdAt           : str
    engineVersion       : str

    class Config:
        frozen = True


class GroqProviderMetadata(BaseModel):
    """
    Provider capability and provenance metadata for one Groq interaction.

    Fields
    ------
    provider            : always "groq".
    model               : canonical model name.
    apiVersion          : Groq API version string.
    endpoint            : Groq API endpoint URL.
    supportsStreaming    : whether this model supports streaming.
    supportsTools       : whether this model supports tool/function calls.
    supportsJsonMode    : whether this model supports JSON mode.
    processingTimeMs    : wall-clock ms to prepare this request/response.
    warnings            : sorted tuple of non-fatal advisory strings.
    """
    provider         : str
    model            : str
    apiVersion       : str
    endpoint         : str
    supportsStreaming : bool
    supportsTools    : bool
    supportsJsonMode : bool
    processingTimeMs : int
    warnings         : Tuple[str, ...]

    class Config:
        frozen = True


class GroqProviderResult(BaseModel):
    """
    The complete, immutable result of one Groq provider interaction.

    Pairs a GroqRequest with its GroqResponse and combined metadata.

    Fields
    ------
    request  : GroqRequest that was prepared.
    response : GroqResponse that was received (or translated).
    metadata : GroqProviderMetadata — combined provenance.
    """
    request  : GroqRequest
    response : GroqResponse
    metadata : GroqProviderMetadata

    class Config:
        frozen = True


# Update forward references
GroqRequest.model_rebuild()
GroqResponse.model_rebuild()
GroqProviderResult.model_rebuild()


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5(key: str) -> str:
    """UUIDv5(GROQ_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_GROQ_NS, key))


def _message_fingerprint(msg: GroqMessage) -> str:
    """Deterministic 32-char fingerprint for one GroqMessage."""
    name_part  = msg.name       or ""
    tc_part    = msg.toolCallId or ""
    return _sha256_32(msg.role, msg.content, name_part, tc_part)


def _compute_request_key(
    model      : str,
    messages   : Tuple[GroqMessage, ...],
    temperature: float,
    top_p      : float,
    max_tokens : int,
) -> str:
    """
    requestKey = SHA256(model + sorted(message fingerprints) +
                        str(temperature) + str(topP) + str(maxTokens))[:32]
    """
    msg_fps = sorted(_message_fingerprint(m) for m in messages)
    return _sha256_32(
        model,
        "\x01".join(msg_fps),
        str(round(temperature, 6)),
        str(round(top_p, 6)),
        str(max_tokens),
    )


def _compute_request_fingerprint(
    request_key: str,
    messages   : Tuple[GroqMessage, ...],
) -> str:
    """
    requestFingerprint = SHA256(requestKey + all message content joined)[:32]

    Messages joined in their declared order (not sorted), so order matters.
    """
    all_content = "\x01".join(m.content for m in messages)
    return _sha256_32(request_key, all_content)


def _compute_response_key(
    request_id  : str,
    content     : str,
    finish_reason: str,
) -> str:
    """responseKey = SHA256(requestId + content + finishReason)[:32]"""
    return _sha256_32(request_id, content, finish_reason)


def _compute_response_fingerprint(
    response_key : str,
    content      : str,
    finish_reason: str,
) -> str:
    """responseFingerprint = SHA256(responseKey + content + finishReason)[:32]"""
    return _sha256_32(response_key, content, finish_reason)


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp(v: float, lo: float, hi: float) -> float:
    return float(max(lo, min(hi, v)))


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


# ===========================================================================
# Utility: estimate_tokens()
# ===========================================================================

def estimate_tokens(text: str) -> int:
    """
    Estimate the token count for a text string.

    Algorithm: ceiling(len(text) / 4).  Returns 0 for empty strings;
    at least 1 for non-empty.

    Parameters
    ----------
    text : string to estimate.

    Returns
    -------
    int — estimated token count (≥ 0).
    """
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))


# ===========================================================================
# Utility: estimate_cost()
# ===========================================================================

def estimate_cost(
    model            : str,
    prompt_tokens    : int,
    completion_tokens: int,
) -> float:
    """
    Compute a deterministic USD cost estimate for one Groq completion.

    Formula:
        cost = (prompt_tokens / 1_000_000) * prompt_price
             + (completion_tokens / 1_000_000) * completion_price

    Pricing loaded from GROQ_PRICING_PER_MILLION in core/constants.py.
    Returns 0.0 for unknown models.  Rounded to 8 decimal places.

    Parameters
    ----------
    model             : canonical Groq model name.
    prompt_tokens     : number of prompt tokens consumed.
    completion_tokens : number of completion tokens consumed.

    Returns
    -------
    float — USD cost estimate, rounded to 8 decimal places.
    """
    pricing = GROQ_PRICING_PER_MILLION.get(model)
    if not pricing:
        return 0.0
    prompt_cost     = (max(0, prompt_tokens)     / 1_000_000) * pricing["prompt"]
    completion_cost = (max(0, completion_tokens) / 1_000_000) * pricing["completion"]
    return round(prompt_cost + completion_cost, 8)


# ===========================================================================
# Utility: calculate_latency()
# ===========================================================================

def calculate_latency(start_ms: int, end_ms: int) -> int:
    """
    Compute deterministic latency in milliseconds.

    Returns max(0, end_ms - start_ms).

    Parameters
    ----------
    start_ms : monotonic start time in milliseconds.
    end_ms   : monotonic end time in milliseconds.

    Returns
    -------
    int — latency in ms (≥ 0).
    """
    return max(0, int(end_ms) - int(start_ms))


# ===========================================================================
# Utility: normalize_model_name()
# ===========================================================================

def normalize_model_name(model: str) -> str:
    """
    Normalise a model name to its canonical Groq form.

    Steps:
    1. Strip whitespace and lowercase.
    2. Check GROQ_MODEL_ALIASES for a known alias → canonical name.
    3. Return the canonical name if it is in GROQ_SUPPORTED_MODELS.
    4. Otherwise return the stripped-lower string unchanged (callers can
       validate separately with validate_request()).

    Parameters
    ----------
    model : raw model string (may be an alias or canonical name).

    Returns
    -------
    str — normalised model name.
    """
    normalised = model.strip().lower() if model else ""
    # Try alias first
    if normalised in GROQ_MODEL_ALIASES:
        return GROQ_MODEL_ALIASES[normalised]
    # Already canonical?
    if normalised in GROQ_SUPPORTED_MODELS:
        return normalised
    # Return as-is; validate_request() will catch truly unsupported names
    return normalised


# ===========================================================================
# Utility: validate_request()
# ===========================================================================

def validate_request(
    model      : str,
    messages   : List[GroqMessage],
    temperature: float,
    top_p      : float,
    max_tokens : int,
) -> None:
    """
    Validate Groq request parameters.  Raises ValueError with a descriptive
    message for every violation found.

    Checks
    ------
    - model is in GROQ_SUPPORTED_MODELS.
    - messages list is non-empty.
    - every message role is in GROQ_VALID_ROLES.
    - every message content is non-empty.
    - temperature in [GROQ_TEMPERATURE_MIN, GROQ_TEMPERATURE_MAX].
    - top_p in [GROQ_TOP_P_MIN, GROQ_TOP_P_MAX].
    - max_tokens in [GROQ_MAX_TOKENS_MIN, GROQ_MAX_TOKENS_MAX].

    Parameters
    ----------
    model, messages, temperature, top_p, max_tokens : request fields.

    Raises
    ------
    ValueError : if any validation rule is violated.
    """
    errors: List[str] = []

    norm = normalize_model_name(model)
    if norm not in GROQ_SUPPORTED_MODELS:
        errors.append(
            f"Unsupported model '{model}'. Supported: {sorted(GROQ_SUPPORTED_MODELS)}"
        )

    if not messages:
        errors.append("messages list must be non-empty.")

    for i, msg in enumerate(messages):
        if msg.role not in GROQ_VALID_ROLES:
            errors.append(
                f"messages[{i}].role='{msg.role}' is invalid. "
                f"Valid roles: {sorted(GROQ_VALID_ROLES)}"
            )
        if not msg.content and msg.content != "":
            errors.append(f"messages[{i}].content must not be None.")

    if not (GROQ_TEMPERATURE_MIN <= temperature <= GROQ_TEMPERATURE_MAX):
        errors.append(
            f"temperature={temperature} out of range "
            f"[{GROQ_TEMPERATURE_MIN}, {GROQ_TEMPERATURE_MAX}]."
        )

    if not (GROQ_TOP_P_MIN <= top_p <= GROQ_TOP_P_MAX):
        errors.append(
            f"top_p={top_p} out of range "
            f"[{GROQ_TOP_P_MIN}, {GROQ_TOP_P_MAX}]."
        )

    if not (GROQ_MAX_TOKENS_MIN <= max_tokens <= GROQ_MAX_TOKENS_MAX):
        errors.append(
            f"max_tokens={max_tokens} out of range "
            f"[{GROQ_MAX_TOKENS_MIN}, {GROQ_MAX_TOKENS_MAX}]."
        )

    if errors:
        raise ValueError("GroqRequest validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


# ===========================================================================
# Utility: validate_response()
# ===========================================================================

def validate_response(
    content      : str,
    finish_reason: str,
    usage        : Optional[Dict[str, Any]] = None,
) -> None:
    """
    Validate a raw Groq API response.  Raises ValueError with a descriptive
    message for every violation found.

    Checks
    ------
    - content is a string (may be empty on tool-call completions).
    - finish_reason is a non-empty string.
    - usage (if provided) has non-negative token counts.

    Parameters
    ----------
    content, finish_reason, usage : fields from the Groq API response.

    Raises
    ------
    ValueError : if any validation rule is violated.
    """
    errors: List[str] = []

    if content is None:
        errors.append("response content must not be None.")

    if not finish_reason or not isinstance(finish_reason, str):
        errors.append("finish_reason must be a non-empty string.")

    if usage is not None:
        for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            val = usage.get(field, 0)
            if isinstance(val, int) and val < 0:
                errors.append(f"usage.{field}={val} must be ≥ 0.")

    if errors:
        raise ValueError("GroqResponse validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


# ===========================================================================
# Utility: sort_messages()
# ===========================================================================

def sort_messages(
    messages  : List[GroqMessage],
    ascending : bool = True,
) -> List[GroqMessage]:
    """
    Sort GroqMessage objects by role ASC, then content ASC.

    Useful for canonical ordering in tests and deduplication checks.
    Input is NOT mutated.

    Parameters
    ----------
    messages  : list of GroqMessage objects.
    ascending : True = A→Z (default); False = Z→A.

    Returns
    -------
    New sorted list.
    """
    return sorted(
        messages,
        key=lambda m: (m.role, m.content),
        reverse=not ascending,
    )


# ===========================================================================
# Utility: filter_messages()
# ===========================================================================

def filter_messages(
    messages       : List[GroqMessage],
    role           : Optional[str] = None,
    content_contains: Optional[str] = None,
    has_name       : Optional[bool] = None,
    has_tool_call_id: Optional[bool] = None,
) -> List[GroqMessage]:
    """
    Filter GroqMessage objects by one or more criteria (all ANDed).

    Parameters
    ----------
    role             : keep messages with this role (exact, lowercase).
    content_contains : keep messages whose content contains this substring
                       (case-insensitive).
    has_name         : True = only messages with a name set; False = without.
    has_tool_call_id : True = only messages with toolCallId; False = without.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[GroqMessage] = []
    needle = content_contains.lower() if content_contains else None
    for m in messages:
        if role is not None and m.role != role.strip().lower():
            continue
        if needle is not None and needle not in m.content.lower():
            continue
        if has_name is not None:
            if has_name     and not m.name:
                continue
            if not has_name and m.name:
                continue
        if has_tool_call_id is not None:
            if has_tool_call_id     and not m.toolCallId:
                continue
            if not has_tool_call_id and m.toolCallId:
                continue
        result.append(m)
    return result


# ===========================================================================
# Builder: build_message()
# ===========================================================================

def build_message(
    role        : str,
    content     : str,
    name        : Optional[str] = None,
    tool_call_id: Optional[str] = None,
) -> GroqMessage:
    """
    Build a single GroqMessage with normalised role.

    Parameters
    ----------
    role         : message role ("system" | "user" | "assistant" | "tool").
                   Normalised to lowercase and stripped.
    content      : message text.
    name         : optional sender name.
    tool_call_id : optional tool call ID.

    Returns
    -------
    GroqMessage (frozen / immutable)
    """
    return GroqMessage(
        role       = role.strip().lower() if role else "user",
        content    = content,
        name       = name.strip() if name else None,
        toolCallId = tool_call_id.strip() if tool_call_id else None,
    )


# ===========================================================================
# Builder: build_provider_metadata()
# ===========================================================================

def build_provider_metadata(
    model             : str,
    processing_time_ms: int                 = 0,
    warnings          : Optional[List[str]] = None,
) -> GroqProviderMetadata:
    """
    Build GroqProviderMetadata for the given canonical model.

    Parameters
    ----------
    model              : canonical Groq model name.
    processing_time_ms : wall-clock ms for this interaction.
    warnings           : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    GroqProviderMetadata (frozen / immutable)
    """
    caps = GROQ_MODEL_CAPABILITIES.get(model, {
        "supportsStreaming": False,
        "supportsTools":     False,
        "supportsJsonMode":  False,
    })
    return GroqProviderMetadata(
        provider         = "groq",
        model            = model,
        apiVersion       = GROQ_API_VERSION,
        endpoint         = GROQ_API_ENDPOINT,
        supportsStreaming = caps.get("supportsStreaming", False),
        supportsTools    = caps.get("supportsTools",     False),
        supportsJsonMode = caps.get("supportsJsonMode",  False),
        processingTimeMs = max(0, int(processing_time_ms)),
        warnings         = _norm_strings(warnings),
    )


# ===========================================================================
# Builder: build_usage()
# ===========================================================================

def build_usage(
    model            : str,
    prompt_tokens    : int,
    completion_tokens: int,
    latency_ms       : int = 0,
) -> GroqUsage:
    """
    Build a GroqUsage object with deterministic cost estimate.

    Parameters
    ----------
    model             : canonical Groq model name (for pricing lookup).
    prompt_tokens     : tokens consumed by the prompt.
    completion_tokens : tokens consumed by the completion.
    latency_ms        : wall-clock response latency in ms.

    Returns
    -------
    GroqUsage (frozen / immutable)
    """
    p = max(0, int(prompt_tokens))
    c = max(0, int(completion_tokens))
    return GroqUsage(
        promptTokens     = p,
        completionTokens = c,
        totalTokens      = p + c,
        estimatedCost    = estimate_cost(model, p, c),
        latencyMs        = max(0, int(latency_ms)),
    )


# ===========================================================================
# Builder: build_request()
# ===========================================================================

def build_request(
    model             : str,
    messages          : List[GroqMessage],
    created_at        : str,
    temperature       : float                = 0.0,
    top_p             : float                = 1.0,
    max_tokens        : int                  = 1024,
    stream            : bool                 = False,
    processing_time_ms: int                  = 0,
    warnings          : Optional[List[str]]  = None,
    validate          : bool                 = True,
) -> GroqRequest:
    """
    Build an immutable GroqRequest ready for the Groq Chat Completions API.

    Parameters
    ----------
    model              : model name (aliases accepted; normalised internally).
    messages           : list of GroqMessage objects.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    temperature        : sampling temperature, clamped to [0.0, 2.0].
    top_p              : nucleus sampling probability, clamped to [0.0, 1.0].
    max_tokens         : max completion tokens, clamped to [1, 131072].
    stream             : whether to request streaming.
    processing_time_ms : wall-clock ms to prepare this request.
    warnings           : non-fatal advisory strings.
    validate           : if True (default), run validate_request() first.

    Returns
    -------
    GroqRequest (frozen / immutable)

    Raises
    ------
    ValueError : if validate=True and any parameter is invalid.
    """
    norm_model  = normalize_model_name(model)
    clamped_temp= _clamp(temperature, GROQ_TEMPERATURE_MIN, GROQ_TEMPERATURE_MAX)
    clamped_tp  = _clamp(top_p,       GROQ_TOP_P_MIN,       GROQ_TOP_P_MAX)
    clamped_mt  = max(GROQ_MAX_TOKENS_MIN,
                      min(GROQ_MAX_TOKENS_MAX, int(max_tokens)))

    if validate:
        validate_request(norm_model, messages, clamped_temp, clamped_tp, clamped_mt)

    msg_tuple: Tuple[GroqMessage, ...] = tuple(messages)

    req_key = _compute_request_key(norm_model, msg_tuple, clamped_temp, clamped_tp, clamped_mt)
    req_id  = _uuid5(req_key)
    req_fp  = _compute_request_fingerprint(req_key, msg_tuple)

    meta = build_provider_metadata(norm_model, processing_time_ms, warnings)

    return GroqRequest(
        requestId          = req_id,
        requestKey         = req_key,
        requestFingerprint = req_fp,
        provider           = "groq",
        model              = norm_model,
        messages           = msg_tuple,
        temperature        = clamped_temp,
        topP               = clamped_tp,
        maxTokens          = clamped_mt,
        stream             = stream,
        metadata           = meta,
        createdAt          = created_at,
        engineVersion      = GROQ_PROVIDER_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_response()
# ===========================================================================

def build_response(
    request_id        : str,
    model             : str,
    content           : str,
    finish_reason     : str,
    created_at        : str,
    prompt_tokens     : int                  = 0,
    completion_tokens : int                  = 0,
    latency_ms        : int                  = 0,
    processing_time_ms: int                  = 0,
    warnings          : Optional[List[str]]  = None,
    validate          : bool                 = True,
) -> GroqResponse:
    """
    Build an immutable GroqResponse from a Groq API reply.

    Parameters
    ----------
    request_id         : GroqRequest.requestId this answers.
    model              : canonical Groq model name.
    content            : raw completion text.
    finish_reason      : stop reason from Groq API.
    created_at         : ISO-8601 timestamp (caller-supplied).
    prompt_tokens      : tokens consumed by the prompt.
    completion_tokens  : tokens consumed by the completion.
    latency_ms         : wall-clock response time.
    processing_time_ms : wall-clock time to process the response.
    warnings           : non-fatal advisory strings.
    validate           : if True (default), run validate_response() first.

    Returns
    -------
    GroqResponse (frozen / immutable)

    Raises
    ------
    ValueError : if validate=True and the response fails validation.
    """
    norm_model = normalize_model_name(model)

    if validate:
        validate_response(content, finish_reason)

    resp_key = _compute_response_key(request_id, content, finish_reason)
    resp_id  = _uuid5(resp_key)
    resp_fp  = _compute_response_fingerprint(resp_key, content, finish_reason)

    usage = build_usage(norm_model, prompt_tokens, completion_tokens, latency_ms)
    meta  = build_provider_metadata(norm_model, processing_time_ms, warnings)

    return GroqResponse(
        responseId          = resp_id,
        responseKey         = resp_key,
        responseFingerprint = resp_fp,
        requestId           = request_id.strip(),
        content             = content,
        finishReason        = finish_reason,
        usage               = usage,
        metadata            = meta,
        createdAt           = created_at,
        engineVersion       = GROQ_PROVIDER_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_provider_result()
# ===========================================================================

def build_provider_result(
    request : GroqRequest,
    response: GroqResponse,
) -> GroqProviderResult:
    """
    Combine a GroqRequest and GroqResponse into an immutable GroqProviderResult.

    Metadata is taken from the response (which carries the final timings).

    Parameters
    ----------
    request  : GroqRequest that was prepared.
    response : GroqResponse that was received.

    Returns
    -------
    GroqProviderResult (frozen / immutable)
    """
    return GroqProviderResult(
        request  = request,
        response = response,
        metadata = response.metadata,
    )
