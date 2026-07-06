"""
Chat Runtime Engine
====================
Phase A4.3.6 — Deterministic, immutable chat runtime pipeline modelling.

Responsibilities
----------------
- Model the full chat pipeline as immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute runtime fingerprints for cache/replay stability.
- Expose builder functions:
    build_runtime_request, build_runtime_response,
    build_runtime_metadata, build_runtime_session, build_runtime_statistics.
- Expose validation functions:
    validate_runtime_request, validate_runtime_response,
    validate_runtime_session.
- Expose integration helpers that bridge existing engines into RuntimeSession
  without executing AI.

Pipeline modelled
-----------------
Conversation  →  Session Memory  →  Context Window  →
Token Budget  →  Execution Result  →  Runtime Response

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No database. No HTTP. No provider SDK. No websocket.
- No streaming. No persistence. No retry logic.
- Provider-agnostic.

Out of scope
------------
- Streaming, retry/failover, HTTP, websocket, frontend wiring.
- Actual AI execution (those belong to later phases).
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import CHAT_RUNTIME_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("chat_runtime_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_RUNTIME_NS = uuid.UUID("6ba7b840-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# Approximate chars-per-token ratio (conservative GPT-style estimate)
# ---------------------------------------------------------------------------
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Enumerations (immutable)
# ===========================================================================

class ChatRuntimeStateEnum(str, Enum):
    """Lifecycle state of a RuntimeSession."""
    READY     = "READY"
    RUNNING   = "RUNNING"
    WAITING   = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ChatRuntimeError(Exception):
    """Base class for all Chat Runtime Engine errors."""


class InvalidChatSessionError(ChatRuntimeError):
    """Raised when a RuntimeSession fails validation."""


class InvalidRuntimeRequestError(ChatRuntimeError):
    """Raised when a RuntimeRequest fails validation."""


class InvalidRuntimeResponseError(ChatRuntimeError):
    """Raised when a RuntimeResponse fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class RuntimeRequest(BaseModel):
    """
    One immutable chat runtime request.

    Identity
    --------
    runtimeRequestKey : SHA256(conversationId + sessionId + userPrompt[:64])[:32]
    runtimeRequestId  : UUIDv5(_RUNTIME_NS, runtimeRequestKey)

    Fields
    ------
    runtimeRequestId  : deterministic UUID derived from runtimeRequestKey.
    runtimeRequestKey : 32-char SHA-256 key.
    conversationId    : owning conversation ID.
    sessionId         : owning session ID (may be empty if standalone).
    userPrompt        : user-supplied prompt text.
    systemPrompt      : system-role text (may be empty).
    provider          : LLM provider key (normalised lowercase).
    model             : model key (normalised lowercase).
    temperature       : sampling temperature [0.0, 2.0].
    maxTokens         : maximum output tokens (≥ 1).
    metadata          : arbitrary key→value extension bag.
    createdAt         : ISO-8601 timestamp (caller-supplied for determinism).
    engineVersion     : CHAT_RUNTIME_ENGINE_VERSION at build time.
    """
    runtimeRequestId  : str
    runtimeRequestKey : str
    conversationId    : str
    sessionId         : str
    userPrompt        : str
    systemPrompt      : str
    provider          : str
    model             : str
    temperature       : float
    maxTokens         : int
    metadata          : Dict[str, Any] = Field(default_factory=dict)
    createdAt         : str
    engineVersion     : str

    class Config:
        frozen = True


class RuntimeResponse(BaseModel):
    """
    One immutable chat runtime response.

    Identity
    --------
    runtimeResponseKey : SHA256(runtimeRequestId + content + finishReason)[:32]
    runtimeResponseId  : UUIDv5(_RUNTIME_NS, runtimeResponseKey)

    Fields
    ------
    runtimeResponseId  : deterministic UUID derived from runtimeResponseKey.
    runtimeResponseKey : 32-char SHA-256 key.
    runtimeRequestId   : RuntimeRequest.runtimeRequestId this answers.
    content            : response text content.
    finishReason       : stop reason (e.g. "stop", "length").
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    promptTokens       : tokens consumed by the prompt.
    completionTokens   : tokens consumed by the completion.
    totalTokens        : promptTokens + completionTokens.
    latencyMs          : wall-clock latency in ms (≥ 0).
    provider           : provider that generated the response.
    model              : model that generated the response.
    metadata           : arbitrary key→value extension bag.
    createdAt          : ISO-8601 timestamp.
    engineVersion      : CHAT_RUNTIME_ENGINE_VERSION at build time.
    """
    runtimeResponseId  : str
    runtimeResponseKey : str
    runtimeRequestId   : str
    content            : str
    finishReason       : str
    confidence         : float
    promptTokens       : int
    completionTokens   : int
    totalTokens        : int
    latencyMs          : int
    provider           : str
    model              : str
    metadata           : Dict[str, Any] = Field(default_factory=dict)
    createdAt          : str
    engineVersion      : str

    class Config:
        frozen = True


class RuntimeMetadata(BaseModel):
    """
    Provenance and aggregate metadata for one RuntimeSession.

    Fields
    ------
    conversationId    : owning conversation ID.
    sessionId         : owning session ID.
    provider          : LLM provider used.
    model             : model used.
    pipelineStages    : sorted tuple of pipeline stage labels traversed.
    totalTokens       : total tokens across request + response.
    latencyMs         : end-to-end latency in ms.
    success           : True if the session completed without fatal error.
    errorMessage      : error message (empty string on success).
    warnings          : sorted tuple of non-fatal advisory strings.
    engineVersion     : CHAT_RUNTIME_ENGINE_VERSION at build time.
    """
    conversationId : str
    sessionId      : str
    provider       : str
    model          : str
    pipelineStages : Tuple[str, ...]
    totalTokens    : int
    latencyMs      : int
    success        : bool
    errorMessage   : str
    warnings       : Tuple[str, ...]
    engineVersion  : str

    class Config:
        frozen = True


class RuntimeSession(BaseModel):
    """
    The complete, immutable chat runtime session.

    Identity
    --------
    runtimeSessionKey     : SHA256(conversationId + sessionId +
                                   runtimeRequestKey)[:32]
    runtimeSessionId      : UUIDv5(_RUNTIME_NS, runtimeSessionKey)
    runtimeFingerprint    : SHA256(runtimeSessionKey +
                                   runtimeRequestKey +
                                   runtimeResponseKey)[:32]
                           (runtimeResponseKey = "" when response is absent)

    Fields
    ------
    runtimeSessionId      : deterministic UUID.
    runtimeSessionKey     : 32-char SHA-256 key.
    runtimeFingerprint    : deterministic content fingerprint.
    state                 : ChatRuntimeStateEnum lifecycle state.
    request               : RuntimeRequest for this session.
    response              : RuntimeResponse (None until pipeline completes).
    metadata              : RuntimeMetadata provenance record.
    createdAt             : ISO-8601 creation timestamp.
    updatedAt             : ISO-8601 last-updated timestamp.
    """
    runtimeSessionId   : str
    runtimeSessionKey  : str
    runtimeFingerprint : str
    state              : ChatRuntimeStateEnum
    request            : RuntimeRequest
    response           : Optional[RuntimeResponse]
    metadata           : RuntimeMetadata
    createdAt          : str
    updatedAt          : str

    class Config:
        frozen = True


class RuntimeStatistics(BaseModel):
    """
    Aggregate statistics over a collection of RuntimeSession objects.

    Fields
    ------
    totalSessions     : total count of sessions.
    readySessions     : count in READY state.
    runningSessions   : count in RUNNING state.
    completedSessions : count in COMPLETED state.
    failedSessions    : count in FAILED state.
    averageLatency    : mean latencyMs across all sessions (0.0 if empty).
    averageTokens     : mean totalTokens across all sessions (0.0 if empty).
    averageConfidence : mean response.confidence across sessions that have
                        a response (0.0 if none).
    executionRate     : completedSessions / totalSessions (0.0 when empty).
    failureRate       : failedSessions / totalSessions (0.0 when empty).
    """
    totalSessions     : int
    readySessions     : int
    runningSessions   : int
    completedSessions : int
    failedSessions    : int
    averageLatency    : float
    averageTokens     : float
    averageConfidence : float
    executionRate     : float
    failureRate       : float

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _sha256_64(*parts: str) -> str:
    """SHA256(null-byte-joined parts) — 64 lowercase hex chars (full digest)."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _uuid5(key: str) -> str:
    """UUIDv5(_RUNTIME_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_RUNTIME_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _clamp_float(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


def _estimate_tokens(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))


# ---------------------------------------------------------------------------
# Key derivation functions (public — named per spec)
# ---------------------------------------------------------------------------

def runtimeRequestKey(
    conversation_id: str,
    session_id     : str,
    user_prompt    : str,
) -> str:
    """
    runtimeRequestKey = SHA256(conversationId + sessionId +
                               userPrompt[:64])[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        session_id.strip(),
        user_prompt[:64],
    )


def runtimeResponseKey(
    runtime_request_id: str,
    content           : str,
    finish_reason     : str,
) -> str:
    """
    runtimeResponseKey = SHA256(runtimeRequestId + content +
                                finishReason)[:32]
    """
    return _sha256_32(
        runtime_request_id.strip(),
        content,
        finish_reason.strip(),
    )


def runtimeSessionKey(
    conversation_id   : str,
    session_id        : str,
    runtime_request_key: str,
) -> str:
    """
    runtimeSessionKey = SHA256(conversationId + sessionId +
                               runtimeRequestKey)[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        session_id.strip(),
        runtime_request_key,
    )


def runtimeFingerprint(
    session_key        : str,
    req_key            : str,
    resp_key           : str,
) -> str:
    """
    runtimeFingerprint = SHA256(runtimeSessionKey +
                                runtimeRequestKey +
                                runtimeResponseKey)[:32]
    runtimeResponseKey = "" when no response is present.
    """
    return _sha256_32(
        session_key,
        req_key,
        resp_key,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_runtime_request(
    conversation_id: str,
    user_prompt    : str,
    provider       : str,
    model          : str,
    temperature    : float,
    max_tokens     : int,
    created_at     : str,
) -> None:
    """
    Validate RuntimeRequest construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - At least one of userPrompt or systemPrompt is non-empty (userPrompt checked here).
    - provider is non-empty.
    - model is non-empty.
    - temperature in [0.0, 2.0].
    - max_tokens >= 1.
    - created_at is non-empty.

    Raises
    ------
    InvalidRuntimeRequestError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not user_prompt or not user_prompt.strip():
        errors.append("userPrompt must not be empty.")
    if not provider or not provider.strip():
        errors.append("provider must not be empty.")
    if not model or not model.strip():
        errors.append("model must not be empty.")
    if not isinstance(temperature, (int, float)) or not (0.0 <= float(temperature) <= 2.0):
        errors.append(
            f"temperature={temperature!r} must be a float in [0.0, 2.0]."
        )
    if not isinstance(max_tokens, int) or max_tokens < 1:
        errors.append(
            f"maxTokens={max_tokens!r} must be an integer >= 1."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_runtime_request", "errors": errors},
        )
        raise InvalidRuntimeRequestError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_runtime_response(
    runtime_request_id: str,
    content           : str,
    finish_reason     : str,
    provider          : str,
    model             : str,
    created_at        : str,
) -> None:
    """
    Validate RuntimeResponse construction parameters.

    Checks
    ------
    - runtime_request_id is non-empty.
    - content is not None (may be empty for tool-call completions).
    - finish_reason is non-empty.
    - provider is non-empty.
    - model is non-empty.
    - created_at is non-empty.

    Raises
    ------
    InvalidRuntimeResponseError : if any rule is violated.
    """
    errors: List[str] = []

    if not runtime_request_id or not runtime_request_id.strip():
        errors.append("runtimeRequestId must not be empty.")
    if content is None:
        errors.append("content must not be None.")
    if not finish_reason or not isinstance(finish_reason, str):
        errors.append("finishReason must be a non-empty string.")
    if not provider or not provider.strip():
        errors.append("provider must not be empty.")
    if not model or not model.strip():
        errors.append("model must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_runtime_response", "errors": errors},
        )
        raise InvalidRuntimeResponseError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_runtime_session(
    conversation_id: str,
    created_at     : str,
    updated_at     : str,
    state          : ChatRuntimeStateEnum,
) -> None:
    """
    Validate RuntimeSession construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - created_at is non-empty.
    - updated_at is non-empty.
    - state is a valid ChatRuntimeStateEnum member.

    Raises
    ------
    InvalidChatSessionError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")
    if not updated_at or not updated_at.strip():
        errors.append("updatedAt must not be empty.")
    if not isinstance(state, ChatRuntimeStateEnum):
        errors.append(
            f"state must be a ChatRuntimeStateEnum member; got {state!r}."
        )

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_runtime_session", "errors": errors},
        )
        raise InvalidChatSessionError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_runtime_request()
# ===========================================================================

def build_runtime_request(
    conversation_id: str,
    user_prompt    : str,
    provider       : str,
    model          : str,
    created_at     : str,
    session_id     : str                      = "",
    system_prompt  : str                      = "",
    temperature    : float                    = 0.0,
    max_tokens     : int                      = 1024,
    metadata       : Optional[Dict[str, Any]] = None,
    validate       : bool                     = True,
) -> RuntimeRequest:
    """
    Build an immutable RuntimeRequest.

    runtimeRequestKey = SHA256(conversationId + sessionId +
                               userPrompt[:64])[:32]
    runtimeRequestId  = UUIDv5(_RUNTIME_NS, runtimeRequestKey)

    Parameters
    ----------
    conversation_id : owning conversation ID.
    user_prompt     : user-supplied prompt text (must be non-empty).
    provider        : LLM provider key (normalised lowercase).
    model           : model key (normalised lowercase).
    created_at      : ISO-8601 timestamp (caller-supplied for determinism).
    session_id      : owning session ID (may be empty).
    system_prompt   : system-role text (may be empty).
    temperature     : sampling temperature [0.0, 2.0] (clamped).
    max_tokens      : maximum output tokens (≥ 1).
    metadata        : arbitrary extension dict; copied, never mutated.
    validate        : if True, run validate_runtime_request() first.

    Returns
    -------
    RuntimeRequest (frozen / immutable)

    Raises
    ------
    InvalidRuntimeRequestError : if validate=True and validation fails.
    """
    norm_provider = _norm(provider)
    norm_model    = _norm(model)
    clamped_temp  = float(max(0.0, min(2.0, temperature)))
    clamped_mt    = max(1, int(max_tokens))

    if validate:
        validate_runtime_request(
            conversation_id, user_prompt,
            norm_provider, norm_model,
            clamped_temp, clamped_mt, created_at,
        )

    req_key = runtimeRequestKey(conversation_id, session_id, user_prompt)
    req_id  = _uuid5(req_key)

    return RuntimeRequest(
        runtimeRequestId  = req_id,
        runtimeRequestKey = req_key,
        conversationId    = conversation_id.strip(),
        sessionId         = session_id.strip(),
        userPrompt        = user_prompt,
        systemPrompt      = system_prompt,
        provider          = norm_provider,
        model             = norm_model,
        temperature       = clamped_temp,
        maxTokens         = clamped_mt,
        metadata          = dict(metadata) if metadata else {},
        createdAt         = created_at,
        engineVersion     = CHAT_RUNTIME_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_runtime_response()
# ===========================================================================

def build_runtime_response(
    runtime_request_id: str,
    content           : str,
    finish_reason     : str,
    provider          : str,
    model             : str,
    created_at        : str,
    confidence        : float                    = 0.0,
    prompt_tokens     : int                      = 0,
    completion_tokens : int                      = 0,
    latency_ms        : int                      = 0,
    metadata          : Optional[Dict[str, Any]] = None,
    validate          : bool                     = True,
) -> RuntimeResponse:
    """
    Build an immutable RuntimeResponse.

    runtimeResponseKey = SHA256(runtimeRequestId + content +
                                finishReason)[:32]
    runtimeResponseId  = UUIDv5(_RUNTIME_NS, runtimeResponseKey)

    Parameters
    ----------
    runtime_request_id : RuntimeRequest.runtimeRequestId this answers.
    content            : response text (may be empty for tool-call results).
    finish_reason      : stop reason (e.g. "stop", "length").
    provider           : provider that generated the response.
    model              : model that generated the response.
    created_at         : ISO-8601 timestamp.
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    prompt_tokens      : tokens consumed by the prompt (≥ 0).
    completion_tokens  : tokens consumed by the completion (≥ 0).
    latency_ms         : round-trip latency in ms (≥ 0).
    metadata           : arbitrary extension dict; copied, never mutated.
    validate           : if True, run validate_runtime_response() first.

    Returns
    -------
    RuntimeResponse (frozen / immutable)

    Raises
    ------
    InvalidRuntimeResponseError : if validate=True and validation fails.
    """
    norm_provider     = _norm(provider)
    norm_model        = _norm(model)
    clamped_confidence = _clamp_float(float(confidence), 0.0, 100.0)
    p_tok             = max(0, int(prompt_tokens))
    c_tok             = max(0, int(completion_tokens))

    if validate:
        validate_runtime_response(
            runtime_request_id, content, finish_reason,
            norm_provider, norm_model, created_at,
        )

    resp_key = runtimeResponseKey(runtime_request_id, content, finish_reason)
    resp_id  = _uuid5(resp_key)

    return RuntimeResponse(
        runtimeResponseId  = resp_id,
        runtimeResponseKey = resp_key,
        runtimeRequestId   = runtime_request_id.strip(),
        content            = content,
        finishReason       = finish_reason,
        confidence         = round(clamped_confidence, 4),
        promptTokens       = p_tok,
        completionTokens   = c_tok,
        totalTokens        = p_tok + c_tok,
        latencyMs          = max(0, int(latency_ms)),
        provider           = norm_provider,
        model              = norm_model,
        metadata           = dict(metadata) if metadata else {},
        createdAt          = created_at,
        engineVersion      = CHAT_RUNTIME_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_runtime_metadata()
# ===========================================================================

def build_runtime_metadata(
    conversation_id  : str,
    session_id       : str,
    provider         : str,
    model            : str,
    created_at       : str,
    pipeline_stages  : Optional[List[str]] = None,
    total_tokens     : int                 = 0,
    latency_ms       : int                 = 0,
    success          : bool                = True,
    error_message    : str                 = "",
    warnings         : Optional[List[str]] = None,
) -> RuntimeMetadata:
    """
    Build an immutable RuntimeMetadata record.

    Parameters
    ----------
    conversation_id : owning conversation ID.
    session_id      : owning session ID.
    provider        : LLM provider key.
    model           : model key.
    created_at      : ISO-8601 timestamp.
    pipeline_stages : ordered labels of traversed pipeline stages
                      (deduped + sorted for determinism).
    total_tokens    : total tokens across request + response (≥ 0).
    latency_ms      : end-to-end latency in ms (≥ 0).
    success         : True if the session completed without fatal error.
    error_message   : error description (empty on success).
    warnings        : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    RuntimeMetadata (frozen / immutable)
    """
    return RuntimeMetadata(
        conversationId = conversation_id.strip(),
        sessionId      = session_id.strip(),
        provider       = _norm(provider),
        model          = _norm(model),
        pipelineStages = _norm_strings(pipeline_stages),
        totalTokens    = max(0, int(total_tokens)),
        latencyMs      = max(0, int(latency_ms)),
        success        = bool(success),
        errorMessage   = error_message,
        warnings       = _norm_strings(warnings),
        engineVersion  = CHAT_RUNTIME_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_runtime_session()
# ===========================================================================

def build_runtime_session(
    request          : RuntimeRequest,
    created_at       : str,
    updated_at       : str,
    state            : ChatRuntimeStateEnum         = ChatRuntimeStateEnum.READY,
    response         : Optional[RuntimeResponse]    = None,
    pipeline_stages  : Optional[List[str]]          = None,
    latency_ms       : int                          = 0,
    success          : bool                         = True,
    error_message    : str                          = "",
    warnings         : Optional[List[str]]          = None,
    validate         : bool                         = True,
) -> RuntimeSession:
    """
    Assemble a complete, immutable RuntimeSession.

    runtimeSessionKey  = SHA256(conversationId + sessionId +
                                runtimeRequestKey)[:32]
    runtimeSessionId   = UUIDv5(_RUNTIME_NS, runtimeSessionKey)
    runtimeFingerprint = SHA256(runtimeSessionKey +
                                runtimeRequestKey +
                                runtimeResponseKey)[:32]
                        (runtimeResponseKey = "" when response is absent)

    Parameters
    ----------
    request         : RuntimeRequest for this session.
    created_at      : ISO-8601 creation timestamp.
    updated_at      : ISO-8601 last-updated timestamp.
    state           : ChatRuntimeStateEnum lifecycle state (default READY).
    response        : RuntimeResponse (None until pipeline completes).
    pipeline_stages : ordered labels of pipeline stages traversed.
    latency_ms      : end-to-end latency in ms (≥ 0).
    success         : True if the session completed without fatal error.
    error_message   : error description (empty on success).
    warnings        : non-fatal advisory strings.
    validate        : if True, run validate_runtime_session() first.

    Returns
    -------
    RuntimeSession (frozen / immutable)

    Raises
    ------
    InvalidChatSessionError : if validate=True and validation fails.
    """
    if validate:
        validate_runtime_session(
            request.conversationId, created_at, updated_at, state,
        )

    # Determine total tokens from response if available
    total_tokens = response.totalTokens if response is not None else 0

    meta = build_runtime_metadata(
        conversation_id = request.conversationId,
        session_id      = request.sessionId,
        provider        = request.provider,
        model           = request.model,
        created_at      = created_at,
        pipeline_stages = pipeline_stages,
        total_tokens    = total_tokens,
        latency_ms      = latency_ms,
        success         = success,
        error_message   = error_message,
        warnings        = warnings,
    )

    resp_key = response.runtimeResponseKey if response is not None else ""

    sess_key = runtimeSessionKey(
        request.conversationId,
        request.sessionId,
        request.runtimeRequestKey,
    )
    sess_id = _uuid5(sess_key)
    sess_fp = runtimeFingerprint(sess_key, request.runtimeRequestKey, resp_key)

    return RuntimeSession(
        runtimeSessionId   = sess_id,
        runtimeSessionKey  = sess_key,
        runtimeFingerprint = sess_fp,
        state              = state,
        request            = request,
        response           = response,
        metadata           = meta,
        createdAt          = created_at,
        updatedAt          = updated_at,
    )


# ===========================================================================
# Builder: build_runtime_statistics()
# ===========================================================================

def build_runtime_statistics(
    sessions: List[RuntimeSession],
) -> RuntimeStatistics:
    """
    Compute RuntimeStatistics over a list of RuntimeSession objects.

    Deterministic: canonical sort (by runtimeSessionId ASC) before
    accumulation so floating-point sums are identical across all runs.

    Parameters
    ----------
    sessions : any list of RuntimeSession objects.

    Returns
    -------
    RuntimeStatistics (frozen / immutable)
    """
    if not sessions:
        return RuntimeStatistics(
            totalSessions     = 0,
            readySessions     = 0,
            runningSessions   = 0,
            completedSessions = 0,
            failedSessions    = 0,
            averageLatency    = 0.0,
            averageTokens     = 0.0,
            averageConfidence = 0.0,
            executionRate     = 0.0,
            failureRate       = 0.0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(sessions, key=lambda s: s.runtimeSessionId)
    n       = len(ordered)

    ready     = sum(1 for s in ordered if s.state == ChatRuntimeStateEnum.READY)
    running   = sum(1 for s in ordered if s.state == ChatRuntimeStateEnum.RUNNING)
    completed = sum(1 for s in ordered if s.state == ChatRuntimeStateEnum.COMPLETED)
    failed    = sum(1 for s in ordered if s.state == ChatRuntimeStateEnum.FAILED)

    latency_sum = sum(s.metadata.latencyMs   for s in ordered)
    token_sum   = sum(s.metadata.totalTokens for s in ordered)

    # Confidence: only from sessions that have a response
    confidence_values: List[float] = [
        s.response.confidence
        for s in ordered
        if s.response is not None
    ]
    avg_confidence = (
        round(sum(confidence_values) / len(confidence_values), 4)
        if confidence_values else 0.0
    )

    return RuntimeStatistics(
        totalSessions     = n,
        readySessions     = ready,
        runningSessions   = running,
        completedSessions = completed,
        failedSessions    = failed,
        averageLatency    = round(latency_sum / n, 4),
        averageTokens     = round(token_sum   / n, 4),
        averageConfidence = avg_confidence,
        executionRate     = round(completed / n, 6),
        failureRate       = round(failed    / n, 6),
    )


# ===========================================================================
# Integration helpers — bridges from existing engines into RuntimeRequest /
# RuntimeResponse without executing AI.
# Only model transformation — no side effects, no I/O.
# ===========================================================================

def conversation_to_runtime_request(
    conversation     : Any,
    provider         : str,
    model            : str,
    created_at       : str,
    session_id       : str                      = "",
    temperature      : float                    = 0.0,
    max_tokens       : int                      = 1024,
    metadata         : Optional[Dict[str, Any]] = None,
    validate         : bool                     = True,
) -> RuntimeRequest:
    """
    Convert a Conversation (from conversation_manager_service) into a
    RuntimeRequest by extracting the last USER message as userPrompt and
    joining all SYSTEM messages as systemPrompt.

    Rules
    -----
    - Messages are consumed in sequenceNumber ASC order.
    - SYSTEM role messages are joined (newline-separated) → systemPrompt.
    - The content of the LAST USER message becomes userPrompt.
    - ASSISTANT and TOOL messages are ignored (they represent prior turns).
    - conversationId is taken from conversation.conversationId.

    Parameters
    ----------
    conversation : Conversation object from conversation_manager_service.
    provider     : LLM provider key.
    model        : model key.
    created_at   : ISO-8601 timestamp.
    session_id   : optional session grouping ID.
    temperature  : sampling temperature [0.0, 2.0].
    max_tokens   : maximum output tokens (≥ 1).
    metadata     : extra context forwarded to the request.
    validate     : if True, run validate_runtime_request().

    Returns
    -------
    RuntimeRequest (frozen / immutable)

    Raises
    ------
    InvalidRuntimeRequestError : if no USER message is found or validation fails.
    """
    sorted_msgs = sorted(
        conversation.messages,
        key=lambda m: (m.sequenceNumber, m.messageId),
    )

    system_parts: List[str] = []
    last_user_content: str  = ""

    for msg in sorted_msgs:
        role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
        if role.upper() == "SYSTEM" and msg.content:
            system_parts.append(msg.content)
        elif role.upper() == "USER" and msg.content:
            last_user_content = msg.content

    if not last_user_content:
        raise InvalidRuntimeRequestError(
            "conversation_to_runtime_request: no USER message found in conversation "
            f"'{conversation.conversationId}'."
        )

    _log.debug(
        "conversation_to_runtime_request",
        extra={
            "conversationId": conversation.conversationId,
            "systemParts"   : len(system_parts),
            "userPromptLen" : len(last_user_content),
        },
    )

    return build_runtime_request(
        conversation_id = conversation.conversationId,
        user_prompt     = last_user_content,
        provider        = provider,
        model           = model,
        created_at      = created_at,
        session_id      = session_id,
        system_prompt   = "\n".join(system_parts),
        temperature     = temperature,
        max_tokens      = max_tokens,
        metadata        = metadata,
        validate        = validate,
    )


def memory_to_runtime_request(
    session_memory   : Any,
    provider         : str,
    model            : str,
    created_at       : str,
    user_prompt      : str,
    session_id       : str                      = "",
    temperature      : float                    = 0.0,
    max_tokens       : int                      = 1024,
    memory_max_tokens: int                      = 2048,
    metadata         : Optional[Dict[str, Any]] = None,
    validate         : bool                     = True,
) -> RuntimeRequest:
    """
    Convert a SessionMemory (from session_memory_service) into a RuntimeRequest
    by serialising active memories into systemPrompt context.

    Rules
    -----
    - Only ACTIVE memory entries are included.
    - Entries are ordered by importanceScore DESC, then memoryId ASC.
    - Token budget (memory_max_tokens) is honoured; entries are truncated
      when the running total would exceed the budget.
    - The caller supplies user_prompt directly (memory does not contain it).
    - conversationId is taken from session_memory.conversationId.

    Parameters
    ----------
    session_memory    : SessionMemory from session_memory_service.
    provider          : LLM provider key.
    model             : model key.
    created_at        : ISO-8601 timestamp.
    user_prompt       : user-supplied prompt text.
    session_id        : optional session grouping ID.
    temperature       : sampling temperature [0.0, 2.0].
    max_tokens        : maximum output tokens (≥ 1).
    memory_max_tokens : approximate token budget for the memory context block.
    metadata          : extra context forwarded to the request.
    validate          : if True, run validate_runtime_request().

    Returns
    -------
    RuntimeRequest (frozen / immutable)
    """
    # Filter to ACTIVE entries; import enum value without creating a hard dep
    active_entries = [
        e for e in session_memory.memories
        if (e.state.value if hasattr(e.state, "value") else str(e.state)).upper()
           == "ACTIVE"
    ]

    ordered = sorted(active_entries, key=lambda e: (-e.importanceScore, e.memoryId))

    lines: List[str] = ["[SESSION MEMORY]"]
    accumulated = _estimate_tokens(lines[0])

    for entry in ordered:
        mem_type = entry.memoryType.value if hasattr(entry.memoryType, "value") else str(entry.memoryType)
        block = (
            f"[{mem_type}] {entry.title}\n"
            f"  confidence={entry.confidence:.2f} importance={entry.importanceScore:.2f}\n"
            f"  {entry.content}"
        )
        block_tokens = _estimate_tokens(block)
        if accumulated + block_tokens > memory_max_tokens:
            break
        lines.append(block)
        accumulated += block_tokens

    system_prompt = "\n".join(lines) if len(lines) > 1 else ""

    _log.debug(
        "memory_to_runtime_request",
        extra={
            "sessionId"    : session_memory.sessionId,
            "activeEntries": len(active_entries),
            "includedLines": len(lines) - 1,
        },
    )

    return build_runtime_request(
        conversation_id = session_memory.conversationId,
        user_prompt     = user_prompt,
        provider        = provider,
        model           = model,
        created_at      = created_at,
        session_id      = session_id or session_memory.sessionId,
        system_prompt   = system_prompt,
        temperature     = temperature,
        max_tokens      = max_tokens,
        metadata        = metadata,
        validate        = validate,
    )


def context_window_to_runtime_request(
    context_window   : Any,
    provider         : str,
    model            : str,
    created_at       : str,
    session_id       : str                      = "",
    temperature      : float                    = 0.0,
    max_tokens       : int                      = 1024,
    metadata         : Optional[Dict[str, Any]] = None,
    validate         : bool                     = True,
) -> RuntimeRequest:
    """
    Convert a ContextWindow (from context_window_service) into a RuntimeRequest
    by splitting items into systemPrompt and userPrompt.

    Rules
    -----
    - Items with source CONVERSATION or USER_INPUT → userPrompt (joined by newline).
    - All other items → systemPrompt formatted as structured context blocks.
    - Items are consumed in window order (already sorted by priority + importance).
    - conversationId is taken from context_window.conversationId.
    - userPrompt falls back to a placeholder when no USER/CONVERSATION items exist.

    Parameters
    ----------
    context_window : ContextWindow from context_window_service.
    provider       : LLM provider key.
    model          : model key.
    created_at     : ISO-8601 timestamp.
    session_id     : optional session grouping ID.
    temperature    : sampling temperature [0.0, 2.0].
    max_tokens     : maximum output tokens (≥ 1).
    metadata       : extra context forwarded to the request.
    validate       : if True, run validate_runtime_request().

    Returns
    -------
    RuntimeRequest (frozen / immutable)
    """
    _USER_SOURCES = {"CONVERSATION", "USER_INPUT"}

    system_parts: List[str] = []
    user_parts  : List[str] = []

    for item in context_window.items:
        src = item.source.value if hasattr(item.source, "value") else str(item.source)
        if src.upper() in _USER_SOURCES:
            user_parts.append(item.content)
        else:
            block = (
                f"[{src}] {item.title}\n"
                f"  priority={item.priority.value if hasattr(item.priority, 'value') else item.priority} "
                f"importance={item.importanceScore:.3f} "
                f"confidence={item.confidence:.3f}\n"
                f"  {item.content}"
            )
            system_parts.append(block)

    user_prompt   = "\n".join(user_parts) if user_parts else "[no user input]"
    system_prompt = "\n".join(system_parts)

    _log.debug(
        "context_window_to_runtime_request",
        extra={
            "windowId"    : context_window.windowId,
            "totalItems"  : len(context_window.items),
            "userParts"   : len(user_parts),
            "systemParts" : len(system_parts),
        },
    )

    return build_runtime_request(
        conversation_id = context_window.conversationId,
        user_prompt     = user_prompt,
        provider        = provider,
        model           = model,
        created_at      = created_at,
        session_id      = session_id,
        system_prompt   = system_prompt,
        temperature     = temperature,
        max_tokens      = max_tokens,
        metadata        = metadata,
        validate        = validate,
    )


def execution_result_to_runtime_response(
    execution_result   : Any,
    runtime_request_id : str,
    created_at         : str,
    confidence         : float                    = 0.0,
    metadata           : Optional[Dict[str, Any]] = None,
    validate           : bool                     = True,
) -> RuntimeResponse:
    """
    Convert an AIExecutionResult (from ai_execution_service) into a
    RuntimeResponse by extracting content, token counts, and latency.

    Rules
    -----
    - content        = execution_result.response.content  (or "" if no response)
    - finishReason   = execution_result.response.finishReason  (or "error")
    - promptTokens   = execution_result.response.promptTokens  (or 0)
    - completionTokens = execution_result.response.completionTokens (or 0)
    - latencyMs      = execution_result.metadata.processingTimeMs
    - provider / model taken from execution_result.metadata.

    Parameters
    ----------
    execution_result   : AIExecutionResult from ai_execution_service.
    runtime_request_id : RuntimeRequest.runtimeRequestId this answers.
    created_at         : ISO-8601 timestamp.
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    metadata           : extra context forwarded to the response.
    validate           : if True, run validate_runtime_response().

    Returns
    -------
    RuntimeResponse (frozen / immutable)
    """
    meta = execution_result.metadata
    resp = execution_result.response

    content       = resp.content      if resp is not None else ""
    finish_reason = resp.finishReason if resp is not None else "error"
    p_tok         = resp.promptTokens     if resp is not None else 0
    c_tok         = resp.completionTokens if resp is not None else 0
    latency_ms    = meta.processingTimeMs

    _log.debug(
        "execution_result_to_runtime_response",
        extra={
            "executionId": meta.executionId,
            "provider"   : meta.provider,
            "success"    : meta.success,
        },
    )

    return build_runtime_response(
        runtime_request_id = runtime_request_id,
        content            = content,
        finish_reason      = finish_reason,
        provider           = meta.provider,
        model              = meta.model,
        created_at         = created_at,
        confidence         = confidence,
        prompt_tokens      = p_tok,
        completion_tokens  = c_tok,
        latency_ms         = latency_ms,
        metadata           = metadata,
        validate           = validate,
    )


def copilot_session_to_runtime_response(
    copilot_session    : Any,
    runtime_request_id : str,
    created_at         : str,
    metadata           : Optional[Dict[str, Any]] = None,
    validate           : bool                     = True,
) -> RuntimeResponse:
    """
    Convert a CopilotSession (from copilot_orchestrator_service) into a
    RuntimeResponse by extracting content, confidence, and token estimates.

    Rules
    -----
    - content        = copilot_session.response.content
    - finishReason   = "stop"  (CopilotSession has no finishReason field)
    - confidence     = copilot_session.response.confidence
    - promptTokens   = copilot_session.metadata.promptTokenEstimate
    - completionTokens = copilot_session.metadata.responseTokenEstimate
    - latencyMs      = copilot_session.metadata.processingTimeMs
    - provider / model taken from copilot_session.request.

    Parameters
    ----------
    copilot_session    : CopilotSession from copilot_orchestrator_service.
    runtime_request_id : RuntimeRequest.runtimeRequestId this answers.
    created_at         : ISO-8601 timestamp.
    metadata           : extra context forwarded to the response.
    validate           : if True, run validate_runtime_response().

    Returns
    -------
    RuntimeResponse (frozen / immutable)
    """
    resp = copilot_session.response
    meta = copilot_session.metadata

    _log.debug(
        "copilot_session_to_runtime_response",
        extra={
            "sessionId": copilot_session.sessionId,
            "provider" : copilot_session.request.provider,
            "model"    : copilot_session.request.model,
        },
    )

    return build_runtime_response(
        runtime_request_id = runtime_request_id,
        content            = resp.content,
        finish_reason      = "stop",
        provider           = copilot_session.request.provider,
        model              = copilot_session.request.model,
        created_at         = created_at,
        confidence         = resp.confidence,
        prompt_tokens      = meta.promptTokenEstimate,
        completion_tokens  = meta.responseTokenEstimate,
        latency_ms         = meta.processingTimeMs,
        metadata           = metadata,
        validate           = validate,
    )

# ===========================================================================
# Runtime Lifecycle
# ===========================================================================
#
# Valid state transitions:
#   READY     → RUNNING
#   RUNNING   → COMPLETED
#   RUNNING   → FAILED
#   ANY STATE → READY  (via reset_runtime_session)
#
# All lifecycle functions return a NEW immutable RuntimeSession.
# Nothing is mutated.
# ===========================================================================

# Allowed forward transitions (source_state → allowed_target_states)
_ALLOWED_TRANSITIONS: Dict[ChatRuntimeStateEnum, Tuple[ChatRuntimeStateEnum, ...]] = {
    ChatRuntimeStateEnum.READY    : (ChatRuntimeStateEnum.RUNNING,),
    ChatRuntimeStateEnum.RUNNING  : (ChatRuntimeStateEnum.COMPLETED, ChatRuntimeStateEnum.FAILED),
    ChatRuntimeStateEnum.WAITING  : (ChatRuntimeStateEnum.RUNNING,),
    ChatRuntimeStateEnum.COMPLETED: (),
    ChatRuntimeStateEnum.FAILED   : (),
}


def _assert_transition(
    session   : RuntimeSession,
    target    : ChatRuntimeStateEnum,
) -> None:
    """
    Assert that transitioning session.state → target is allowed.

    Raises
    ------
    InvalidChatSessionError : when the transition is not permitted.
    """
    allowed = _ALLOWED_TRANSITIONS.get(session.state, ())
    if target not in allowed:
        raise InvalidChatSessionError(
            f"Invalid state transition: {session.state.value} → {target.value}. "
            f"Allowed from {session.state.value}: "
            f"{[s.value for s in allowed] or 'none'}."
        )


def start_runtime_session(
    session    : RuntimeSession,
    updated_at : str,
    warnings   : Optional[List[str]] = None,
) -> RuntimeSession:
    """
    Transition a RuntimeSession from READY → RUNNING.

    Returns a new RuntimeSession with state=RUNNING and an updated
    runtimeFingerprint reflecting the new state metadata.

    Parameters
    ----------
    session    : RuntimeSession in READY state.
    updated_at : ISO-8601 timestamp for the transition.
    warnings   : non-fatal advisory strings to carry forward.

    Returns
    -------
    RuntimeSession (frozen / immutable) in RUNNING state.

    Raises
    ------
    InvalidChatSessionError : if session is not in READY state.
    """
    _assert_transition(session, ChatRuntimeStateEnum.RUNNING)

    _log.info(
        "runtime_started",
        extra={
            "runtimeSessionId": session.runtimeSessionId,
            "conversationId"  : session.request.conversationId,
            "provider"        : session.request.provider,
            "model"           : session.request.model,
        },
    )

    new_meta = build_runtime_metadata(
        conversation_id = session.request.conversationId,
        session_id      = session.request.sessionId,
        provider        = session.request.provider,
        model           = session.request.model,
        created_at      = updated_at,
        pipeline_stages = list(session.metadata.pipelineStages),
        total_tokens    = session.metadata.totalTokens,
        latency_ms      = session.metadata.latencyMs,
        success         = True,
        error_message   = "",
        warnings        = list(session.metadata.warnings) + (list(warnings) if warnings else []),
    )

    resp_key = session.response.runtimeResponseKey if session.response is not None else ""
    new_fp   = runtimeFingerprint(session.runtimeSessionKey, session.request.runtimeRequestKey, resp_key)

    return RuntimeSession(
        runtimeSessionId   = session.runtimeSessionId,
        runtimeSessionKey  = session.runtimeSessionKey,
        runtimeFingerprint = new_fp,
        state              = ChatRuntimeStateEnum.RUNNING,
        request            = session.request,
        response           = session.response,
        metadata           = new_meta,
        createdAt          = session.createdAt,
        updatedAt          = updated_at,
    )


def complete_runtime_session(
    session    : RuntimeSession,
    response   : RuntimeResponse,
    updated_at : str,
    latency_ms : int                 = 0,
    pipeline_stages: Optional[List[str]] = None,
    warnings   : Optional[List[str]] = None,
) -> RuntimeSession:
    """
    Transition a RuntimeSession from RUNNING → COMPLETED.

    Attaches the RuntimeResponse and updates the runtimeFingerprint.

    Parameters
    ----------
    session         : RuntimeSession in RUNNING state.
    response        : RuntimeResponse to attach.
    updated_at      : ISO-8601 timestamp for the transition.
    latency_ms      : total end-to-end latency in ms.
    pipeline_stages : final pipeline stage labels (merged with existing).
    warnings        : non-fatal advisory strings.

    Returns
    -------
    RuntimeSession (frozen / immutable) in COMPLETED state.

    Raises
    ------
    InvalidChatSessionError : if session is not in RUNNING state.
    """
    _assert_transition(session, ChatRuntimeStateEnum.COMPLETED)

    merged_stages = list(session.metadata.pipelineStages) + (pipeline_stages or [])

    _log.info(
        "runtime_completed",
        extra={
            "runtimeSessionId": session.runtimeSessionId,
            "conversationId"  : session.request.conversationId,
            "totalTokens"     : response.totalTokens,
            "latencyMs"       : latency_ms,
        },
    )

    new_meta = build_runtime_metadata(
        conversation_id = session.request.conversationId,
        session_id      = session.request.sessionId,
        provider        = session.request.provider,
        model           = session.request.model,
        created_at      = updated_at,
        pipeline_stages = merged_stages,
        total_tokens    = response.totalTokens,
        latency_ms      = max(0, int(latency_ms)),
        success         = True,
        error_message   = "",
        warnings        = list(session.metadata.warnings) + (list(warnings) if warnings else []),
    )

    new_fp = runtimeFingerprint(
        session.runtimeSessionKey,
        session.request.runtimeRequestKey,
        response.runtimeResponseKey,
    )

    return RuntimeSession(
        runtimeSessionId   = session.runtimeSessionId,
        runtimeSessionKey  = session.runtimeSessionKey,
        runtimeFingerprint = new_fp,
        state              = ChatRuntimeStateEnum.COMPLETED,
        request            = session.request,
        response           = response,
        metadata           = new_meta,
        createdAt          = session.createdAt,
        updatedAt          = updated_at,
    )


def fail_runtime_session(
    session       : RuntimeSession,
    error_message : str,
    updated_at    : str,
    latency_ms    : int                 = 0,
    warnings      : Optional[List[str]] = None,
) -> RuntimeSession:
    """
    Transition a RuntimeSession from RUNNING → FAILED.

    Parameters
    ----------
    session       : RuntimeSession in RUNNING state.
    error_message : description of the failure.
    updated_at    : ISO-8601 timestamp for the transition.
    latency_ms    : latency at point of failure in ms.
    warnings      : non-fatal advisory strings.

    Returns
    -------
    RuntimeSession (frozen / immutable) in FAILED state.

    Raises
    ------
    InvalidChatSessionError : if session is not in RUNNING state.
    """
    _assert_transition(session, ChatRuntimeStateEnum.FAILED)

    _log.error(
        "runtime_failed",
        extra={
            "runtimeSessionId": session.runtimeSessionId,
            "conversationId"  : session.request.conversationId,
            "errorMessage"    : error_message,
            "latencyMs"       : latency_ms,
        },
    )

    new_meta = build_runtime_metadata(
        conversation_id = session.request.conversationId,
        session_id      = session.request.sessionId,
        provider        = session.request.provider,
        model           = session.request.model,
        created_at      = updated_at,
        pipeline_stages = list(session.metadata.pipelineStages),
        total_tokens    = session.metadata.totalTokens,
        latency_ms      = max(0, int(latency_ms)),
        success         = False,
        error_message   = error_message,
        warnings        = list(session.metadata.warnings) + (list(warnings) if warnings else []),
    )

    resp_key = session.response.runtimeResponseKey if session.response is not None else ""
    new_fp   = runtimeFingerprint(session.runtimeSessionKey, session.request.runtimeRequestKey, resp_key)

    return RuntimeSession(
        runtimeSessionId   = session.runtimeSessionId,
        runtimeSessionKey  = session.runtimeSessionKey,
        runtimeFingerprint = new_fp,
        state              = ChatRuntimeStateEnum.FAILED,
        request            = session.request,
        response           = session.response,
        metadata           = new_meta,
        createdAt          = session.createdAt,
        updatedAt          = updated_at,
    )


def reset_runtime_session(
    session    : RuntimeSession,
    updated_at : str,
    warnings   : Optional[List[str]] = None,
) -> RuntimeSession:
    """
    Reset a RuntimeSession to READY from any state.

    Clears response, resets metadata to a clean READY state, and
    recomputes the runtimeFingerprint (no response → resp_key = "").

    Parameters
    ----------
    session    : RuntimeSession in any state.
    updated_at : ISO-8601 timestamp for the reset.
    warnings   : non-fatal advisory strings.

    Returns
    -------
    RuntimeSession (frozen / immutable) in READY state.
    """
    _log.info(
        "runtime_reset",
        extra={
            "runtimeSessionId": session.runtimeSessionId,
            "previousState"   : session.state.value,
            "conversationId"  : session.request.conversationId,
        },
    )

    new_meta = build_runtime_metadata(
        conversation_id = session.request.conversationId,
        session_id      = session.request.sessionId,
        provider        = session.request.provider,
        model           = session.request.model,
        created_at      = updated_at,
        pipeline_stages = [],
        total_tokens    = 0,
        latency_ms      = 0,
        success         = True,
        error_message   = "",
        warnings        = list(warnings) if warnings else [],
    )

    new_fp = runtimeFingerprint(
        session.runtimeSessionKey,
        session.request.runtimeRequestKey,
        "",  # no response after reset
    )

    return RuntimeSession(
        runtimeSessionId   = session.runtimeSessionId,
        runtimeSessionKey  = session.runtimeSessionKey,
        runtimeFingerprint = new_fp,
        state              = ChatRuntimeStateEnum.READY,
        request            = session.request,
        response           = None,
        metadata           = new_meta,
        createdAt          = session.createdAt,
        updatedAt          = updated_at,
    )


# ===========================================================================
# Runtime Decisions
# ===========================================================================

def should_execute_runtime(session: RuntimeSession) -> bool:
    """
    Return True when the session is in a state where execution should proceed.

    A session should execute when it is READY or WAITING.
    RUNNING, COMPLETED, and FAILED sessions must not be executed again.

    Parameters
    ----------
    session : RuntimeSession to evaluate.

    Returns
    -------
    bool — deterministic, no side effects.
    """
    return session.state in (
        ChatRuntimeStateEnum.READY,
        ChatRuntimeStateEnum.WAITING,
    )


def can_resume_runtime(session: RuntimeSession) -> bool:
    """
    Return True when the session is in a resumable state.

    A session can resume when it is WAITING — it has been paused mid-pipeline
    and is eligible to continue. READY sessions have not started and are not
    resuming. RUNNING sessions are already active. COMPLETED and FAILED
    sessions are terminal.

    Parameters
    ----------
    session : RuntimeSession to evaluate.

    Returns
    -------
    bool — deterministic, no side effects.
    """
    return session.state == ChatRuntimeStateEnum.WAITING


def is_runtime_complete(session: RuntimeSession) -> bool:
    """
    Return True when the session has reached a terminal state.

    Terminal states are COMPLETED and FAILED. READY, RUNNING, and WAITING
    sessions are still active.

    Parameters
    ----------
    session : RuntimeSession to evaluate.

    Returns
    -------
    bool — deterministic, no side effects.
    """
    return session.state in (
        ChatRuntimeStateEnum.COMPLETED,
        ChatRuntimeStateEnum.FAILED,
    )


# ===========================================================================
# Runtime Utilities — RuntimeSession
# ===========================================================================

def sort_runtime_sessions(
    sessions  : List[RuntimeSession],
    key       : str  = "runtimeSessionId",
    ascending : bool = True,
) -> List[RuntimeSession]:
    """
    Sort a list of RuntimeSession objects by the specified key.

    Supported keys
    --------------
    "runtimeSessionId" (default) : stable deterministic sort by UUID string.
    "createdAt"                  : ISO-8601 creation timestamp.
    "updatedAt"                  : ISO-8601 last-updated timestamp.
    "state"                      : ChatRuntimeStateEnum.value string.
    "latencyMs"                  : metadata.latencyMs (numeric).
    "totalTokens"                : metadata.totalTokens (numeric).
    "conversationId"             : request.conversationId.

    All sorts use runtimeSessionId ASC as a tie-breaker for full determinism.

    Parameters
    ----------
    sessions  : list of RuntimeSession objects (not mutated).
    key       : sort attribute (see above).
    ascending : True = low→high / A→Z; False = high→low / Z→A.

    Returns
    -------
    New sorted list.

    Raises
    ------
    ValueError : if key is not a recognised attribute.
    """
    _VALID_KEYS = {
        "runtimeSessionId", "createdAt", "updatedAt", "state",
        "latencyMs", "totalTokens", "conversationId",
    }
    if key not in _VALID_KEYS:
        raise ValueError(
            f"sort_runtime_sessions: unknown key '{key}'. "
            f"Valid: {sorted(_VALID_KEYS)}"
        )

    def _key_fn(s: RuntimeSession):
        if key == "runtimeSessionId": primary = s.runtimeSessionId
        elif key == "createdAt"     : primary = s.createdAt
        elif key == "updatedAt"     : primary = s.updatedAt
        elif key == "state"         : primary = s.state.value
        elif key == "latencyMs"     : primary = s.metadata.latencyMs
        elif key == "totalTokens"   : primary = s.metadata.totalTokens
        else                        : primary = s.request.conversationId
        return (primary, s.runtimeSessionId)

    return sorted(sessions, key=_key_fn, reverse=not ascending)


def filter_runtime_sessions(
    sessions         : List[RuntimeSession],
    state            : Optional[ChatRuntimeStateEnum] = None,
    provider         : Optional[str]                  = None,
    model            : Optional[str]                  = None,
    conversation_id  : Optional[str]                  = None,
    has_response     : Optional[bool]                 = None,
    min_latency_ms   : Optional[int]                  = None,
    max_latency_ms   : Optional[int]                  = None,
    min_confidence   : Optional[float]                = None,
    success_only     : Optional[bool]                 = None,
) -> List[RuntimeSession]:
    """
    Filter sessions by one or more criteria (all ANDed).

    Parameters
    ----------
    state           : keep sessions in this state.
    provider        : keep sessions from this provider (case-insensitive).
    model           : keep sessions using this model (case-insensitive).
    conversation_id : keep sessions for this conversation.
    has_response    : True = only sessions with a response; False = without.
    min_latency_ms  : keep sessions with metadata.latencyMs >= value.
    max_latency_ms  : keep sessions with metadata.latencyMs <= value.
    min_confidence  : keep sessions with response.confidence >= value.
    success_only    : True = only metadata.success == True sessions.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[RuntimeSession] = []
    for s in sessions:
        if state           is not None and s.state                       != state:
            continue
        if provider        is not None and s.request.provider            != _norm(provider):
            continue
        if model           is not None and s.request.model               != _norm(model):
            continue
        if conversation_id is not None and s.request.conversationId      != conversation_id.strip():
            continue
        if has_response is not None:
            if has_response  and s.response is None:
                continue
            if not has_response and s.response is not None:
                continue
        if min_latency_ms  is not None and s.metadata.latencyMs          < min_latency_ms:
            continue
        if max_latency_ms  is not None and s.metadata.latencyMs          > max_latency_ms:
            continue
        if min_confidence is not None:
            if s.response is None or s.response.confidence < min_confidence:
                continue
        if success_only is not None:
            if success_only  and not s.metadata.success:
                continue
            if not success_only and s.metadata.success:
                continue
        result.append(s)
    return result


def group_runtime_sessions(
    sessions : List[RuntimeSession],
    group_by : str = "state",
) -> Dict[str, List[RuntimeSession]]:
    """
    Group RuntimeSession objects by an attribute.

    Supported group_by values
    -------------------------
    "state"          (default) : ChatRuntimeStateEnum.value.
    "provider"                 : request.provider.
    "model"                    : request.model.
    "conversationId"           : request.conversationId.
    "runtimeSessionId"         : one session per group (identity grouping).

    Each group is sorted by runtimeSessionId ASC for determinism.

    Returns
    -------
    Dict[str, List[RuntimeSession]]

    Raises
    ------
    ValueError : if group_by is not a recognised attribute.
    """
    _VALID = {"state", "provider", "model", "conversationId", "runtimeSessionId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_runtime_sessions: unknown key '{group_by}'. "
            f"Valid: {sorted(_VALID)}"
        )

    groups: Dict[str, List[RuntimeSession]] = {}
    for s in sessions:
        if group_by == "state"           : k = s.state.value
        elif group_by == "provider"      : k = s.request.provider
        elif group_by == "model"         : k = s.request.model
        elif group_by == "conversationId": k = s.request.conversationId
        else                             : k = s.runtimeSessionId
        groups.setdefault(k, []).append(s)

    return {k: sorted(v, key=lambda x: x.runtimeSessionId) for k, v in groups.items()}


def find_runtime_session(
    sessions          : List[RuntimeSession],
    runtime_session_id: str,
) -> Optional[RuntimeSession]:
    """
    Return the first RuntimeSession whose runtimeSessionId matches, or None.

    Parameters
    ----------
    sessions           : list to search.
    runtime_session_id : exact runtimeSessionId to find.

    Returns
    -------
    RuntimeSession or None.
    """
    target = runtime_session_id.strip()
    for s in sessions:
        if s.runtimeSessionId == target:
            return s
    return None


# ===========================================================================
# Runtime Utilities — RuntimeRequest
# ===========================================================================

def sort_runtime_requests(
    requests  : List[RuntimeRequest],
    key       : str  = "runtimeRequestId",
    ascending : bool = True,
) -> List[RuntimeRequest]:
    """
    Sort a list of RuntimeRequest objects by the specified key.

    Supported keys
    --------------
    "runtimeRequestId" (default) : stable deterministic sort by UUID string.
    "createdAt"                  : ISO-8601 creation timestamp.
    "conversationId"             : owning conversation ID.
    "provider"                   : provider string.
    "model"                      : model string.
    "maxTokens"                  : numeric max output tokens.
    "temperature"                : numeric sampling temperature.

    All sorts use runtimeRequestId ASC as a tie-breaker.

    Returns
    -------
    New sorted list (input is not mutated).

    Raises
    ------
    ValueError : if key is not recognised.
    """
    _VALID_KEYS = {
        "runtimeRequestId", "createdAt", "conversationId",
        "provider", "model", "maxTokens", "temperature",
    }
    if key not in _VALID_KEYS:
        raise ValueError(
            f"sort_runtime_requests: unknown key '{key}'. "
            f"Valid: {sorted(_VALID_KEYS)}"
        )

    def _key_fn(r: RuntimeRequest):
        if key == "runtimeRequestId": primary = r.runtimeRequestId
        elif key == "createdAt"     : primary = r.createdAt
        elif key == "conversationId": primary = r.conversationId
        elif key == "provider"      : primary = r.provider
        elif key == "model"         : primary = r.model
        elif key == "maxTokens"     : primary = r.maxTokens
        else                        : primary = r.temperature
        return (primary, r.runtimeRequestId)

    return sorted(requests, key=_key_fn, reverse=not ascending)


def filter_runtime_requests(
    requests        : List[RuntimeRequest],
    provider        : Optional[str]   = None,
    model           : Optional[str]   = None,
    conversation_id : Optional[str]   = None,
    session_id      : Optional[str]   = None,
    min_max_tokens  : Optional[int]   = None,
    max_temperature : Optional[float] = None,
) -> List[RuntimeRequest]:
    """
    Filter RuntimeRequest objects by one or more criteria (all ANDed).

    Parameters
    ----------
    provider        : keep requests from this provider (case-insensitive).
    model           : keep requests using this model (case-insensitive).
    conversation_id : keep requests for this conversation.
    session_id      : keep requests for this session.
    min_max_tokens  : keep requests with maxTokens >= value.
    max_temperature : keep requests with temperature <= value.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[RuntimeRequest] = []
    for r in requests:
        if provider        is not None and r.provider       != _norm(provider):
            continue
        if model           is not None and r.model          != _norm(model):
            continue
        if conversation_id is not None and r.conversationId != conversation_id.strip():
            continue
        if session_id      is not None and r.sessionId      != session_id.strip():
            continue
        if min_max_tokens  is not None and r.maxTokens       < min_max_tokens:
            continue
        if max_temperature is not None and r.temperature     > max_temperature:
            continue
        result.append(r)
    return result


def group_runtime_requests(
    requests : List[RuntimeRequest],
    group_by : str = "provider",
) -> Dict[str, List[RuntimeRequest]]:
    """
    Group RuntimeRequest objects by an attribute.

    Supported group_by values
    -------------------------
    "provider"         (default) : request.provider.
    "model"                      : request.model.
    "conversationId"             : request.conversationId.
    "sessionId"                  : request.sessionId.
    "runtimeRequestId"           : identity grouping.

    Each group is sorted by runtimeRequestId ASC.

    Returns
    -------
    Dict[str, List[RuntimeRequest]]

    Raises
    ------
    ValueError : if group_by is not recognised.
    """
    _VALID = {"provider", "model", "conversationId", "sessionId", "runtimeRequestId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_runtime_requests: unknown key '{group_by}'. "
            f"Valid: {sorted(_VALID)}"
        )

    groups: Dict[str, List[RuntimeRequest]] = {}
    for r in requests:
        if group_by == "provider"        : k = r.provider
        elif group_by == "model"         : k = r.model
        elif group_by == "conversationId": k = r.conversationId
        elif group_by == "sessionId"     : k = r.sessionId
        else                             : k = r.runtimeRequestId
        groups.setdefault(k, []).append(r)

    return {k: sorted(v, key=lambda x: x.runtimeRequestId) for k, v in groups.items()}


def find_runtime_request(
    requests          : List[RuntimeRequest],
    runtime_request_id: str,
) -> Optional[RuntimeRequest]:
    """
    Return the first RuntimeRequest whose runtimeRequestId matches, or None.

    Parameters
    ----------
    requests           : list to search.
    runtime_request_id : exact runtimeRequestId to find.

    Returns
    -------
    RuntimeRequest or None.
    """
    target = runtime_request_id.strip()
    for r in requests:
        if r.runtimeRequestId == target:
            return r
    return None
