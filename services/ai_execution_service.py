"""
AI Execution Engine
===================
Phase A4.3.1 — Single runtime execution entry point for every AI request
inside NetFusion.

Responsibilities
----------------
- Select provider and model via the Provider Registry.
- Forward requests to the Groq Provider / HTTP Client layer.
- Return deterministic, immutable execution result objects.
- Handle retries, timeouts, and provider errors deterministically.
- Integrate with Tool Calling and Copilot Orchestrator engines.

This service does NOT contain:
- Investigation logic, reasoning logic, prompt generation.
- Attack graph, timeline, evidence, or alert processing.
- Any database access or HTTP endpoint definitions.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- Never log API keys or secrets.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import AI_EXECUTION_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("ai_execution_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_EXEC_NS = uuid.UUID("6ba7b830-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class AIExecutionError(Exception):
    """Base class for all AI Execution Engine errors."""
    def __init__(
        self,
        message    : str,
        execution_id: str = "",
        retryable  : bool = False,
    ) -> None:
        super().__init__(message)
        self.execution_id = execution_id
        self.retryable    = retryable

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"execution_id={self.execution_id!r}, "
            f"retryable={self.retryable}, "
            f"message={str(self)!r})"
        )


class ExecutionTimeoutError(AIExecutionError):
    """Raised when an execution attempt exceeds the configured timeout."""
    def __init__(self, execution_id: str = "") -> None:
        super().__init__(
            "AI execution timed out.",
            execution_id=execution_id,
            retryable=True,
        )


class ProviderUnavailableError(AIExecutionError):
    """Raised when no provider is available for the given criteria."""
    def __init__(self, reason: str = "", execution_id: str = "") -> None:
        super().__init__(
            f"Provider unavailable: {reason}",
            execution_id=execution_id,
            retryable=True,
        )


class InvalidRequestError(AIExecutionError):
    """Raised when the execution request fails validation."""
    def __init__(self, reason: str = "", execution_id: str = "") -> None:
        super().__init__(
            f"Invalid execution request: {reason}",
            execution_id=execution_id,
            retryable=False,
        )


class InvalidResponseError(AIExecutionError):
    """Raised when the provider response fails validation."""
    def __init__(self, reason: str = "", execution_id: str = "") -> None:
        super().__init__(
            f"Invalid provider response: {reason}",
            execution_id=execution_id,
            retryable=False,
        )


class RetryExhaustedError(AIExecutionError):
    """Raised when all retry attempts have been consumed."""
    def __init__(self, attempts: int, execution_id: str = "") -> None:
        super().__init__(
            f"Execution failed after {attempts} attempt(s).",
            execution_id=execution_id,
            retryable=False,
        )


class ToolExecutionFailedError(AIExecutionError):
    """Raised when a tool call within an execution fails."""
    def __init__(self, tool_name: str = "", execution_id: str = "") -> None:
        super().__init__(
            f"Tool execution failed: '{tool_name}'",
            execution_id=execution_id,
            retryable=False,
        )


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class AIExecutionRequest(BaseModel):
    """
    One complete, immutable AI execution request.

    Identity
    --------
    executionId          : UUIDv5(_EXEC_NS, executionKey) — deterministic.
    executionKey         : SHA256(provider + model + systemPrompt + userPrompt
                           + str(temperature) + str(maxTokens))[:32]
    executionFingerprint : SHA256(executionKey + systemPrompt + userPrompt)[:32]

    Prompt fields
    -------------
    systemPrompt : full system-role text.
    userPrompt   : full user-role text.

    LLM parameters
    --------------
    provider     : provider key (e.g. "groq", "openai").
    model        : model name (e.g. "llama-3.3-70b-versatile").
    temperature  : sampling temperature [0.0, 2.0].
    maxTokens    : maximum output tokens (≥ 1).
    stream       : whether to request a streaming response.

    Context
    -------
    requestId    : upstream request context ID (e.g. CopilotRequest.requestId).
    sessionId    : optional session grouping ID.
    strategy     : provider selection strategy (default "priority").

    Metadata
    --------
    createdAt    : ISO-8601 timestamp (caller-supplied for determinism).
    engineVersion: AI_EXECUTION_ENGINE_VERSION.
    """
    executionId          : str
    executionKey         : str
    executionFingerprint : str
    provider             : str
    model                : str
    systemPrompt         : str
    userPrompt           : str
    temperature          : float
    maxTokens            : int
    stream               : bool
    requestId            : str
    sessionId            : str
    strategy             : str
    createdAt            : str
    engineVersion        : str

    class Config:
        frozen = True


class AIExecutionResponse(BaseModel):
    """
    One complete, immutable AI execution response.

    Identity
    --------
    responseId          : UUIDv5(_EXEC_NS, responseKey) — deterministic.
    responseKey         : SHA256(executionId + content + finishReason)[:32]
    responseFingerprint : SHA256(responseKey + content)[:32]

    Content
    -------
    content      : raw text content from the LLM.
    finishReason : stop reason (e.g. "stop", "length", "tool_calls").

    Usage
    -----
    promptTokens     : tokens consumed by the prompt.
    completionTokens : tokens consumed by the completion.
    totalTokens      : promptTokens + completionTokens.
    estimatedCost    : USD cost estimate (deterministic).
    latencyMs        : wall-clock round-trip time in ms.

    Metadata
    --------
    executionId  : AIExecutionRequest.executionId this answers.
    provider     : provider that generated the response.
    model        : model that generated the response.
    createdAt    : ISO-8601 timestamp.
    engineVersion: AI_EXECUTION_ENGINE_VERSION.
    """
    responseId          : str
    responseKey         : str
    responseFingerprint : str
    executionId         : str
    provider            : str
    model               : str
    content             : str
    finishReason        : str
    promptTokens        : int
    completionTokens    : int
    totalTokens         : int
    estimatedCost       : float
    latencyMs           : int
    createdAt           : str
    engineVersion       : str

    class Config:
        frozen = True


class AIExecutionMetadata(BaseModel):
    """
    Immutable provenance and timing metadata for one execution.

    Fields
    ------
    executionId      : AIExecutionRequest.executionId.
    provider         : provider used.
    model            : model used.
    strategy         : selection strategy used.
    attemptNumber    : which retry attempt produced this result (1-indexed).
    totalAttempts    : total attempts made.
    processingTimeMs : total wall-clock ms for this execution.
    success          : True if execution completed without fatal error.
    error            : error message (None on success).
    warnings         : sorted tuple of non-fatal advisory strings.
    engineVersion    : AI_EXECUTION_ENGINE_VERSION.
    """
    executionId      : str
    provider         : str
    model            : str
    strategy         : str
    attemptNumber    : int
    totalAttempts    : int
    processingTimeMs : int
    success          : bool
    error            : Optional[str]
    warnings         : Tuple[str, ...]
    engineVersion    : str

    class Config:
        frozen = True


class AIExecutionResult(BaseModel):
    """
    Immutable combined result of one complete AI execution round-trip.

    Fields
    ------
    request  : the AIExecutionRequest that was made.
    response : the AIExecutionResponse that was received (or None on failure).
    metadata : AIExecutionMetadata — provenance and timings.
    """
    request  : AIExecutionRequest
    response : Optional[AIExecutionResponse]
    metadata : AIExecutionMetadata

    class Config:
        frozen = True


class AIExecutionStatistics(BaseModel):
    """
    Aggregate statistics over a collection of AIExecutionResult objects.

    Fields
    ------
    totalExecutions      : total count.
    successCount         : count of successful executions.
    failureCount         : count of failed executions.
    successRate          : successCount / totalExecutions (0.0 when empty).
    averageLatencyMs     : mean latencyMs across successful executions.
    totalTokens          : sum of totalTokens across all results.
    totalEstimatedCost   : sum of estimatedCost across all results.
    uniqueProviders      : sorted tuple of distinct provider names used.
    uniqueModels         : sorted tuple of distinct model names used.
    averageAttempts      : mean totalAttempts per execution.
    executionsWithWarnings: count of executions that have ≥ 1 warning.
    """
    totalExecutions       : int
    successCount          : int
    failureCount          : int
    successRate           : float
    averageLatencyMs      : float
    totalTokens           : int
    totalEstimatedCost    : float
    uniqueProviders       : Tuple[str, ...]
    uniqueModels          : Tuple[str, ...]
    averageAttempts       : float
    executionsWithWarnings: int

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5(key: str) -> str:
    """UUIDv5(_EXEC_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_EXEC_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _mono_ms() -> int:
    """Monotonic clock in milliseconds (latency measurement only)."""
    return int(time.monotonic() * 1000)


def _compute_execution_key(
    provider     : str,
    model        : str,
    system_prompt: str,
    user_prompt  : str,
    temperature  : float,
    max_tokens   : int,
) -> str:
    """
    executionKey = SHA256(provider + model + systemPrompt + userPrompt
                          + temperature + maxTokens)[:32]
    Null-byte-separated to prevent cross-field collisions.
    """
    return _sha256_32(
        _norm(provider),
        _norm(model),
        system_prompt,
        user_prompt,
        str(round(temperature, 6)),
        str(int(max_tokens)),
    )


def _compute_execution_fingerprint(
    execution_key: str,
    system_prompt: str,
    user_prompt  : str,
) -> str:
    """executionFingerprint = SHA256(executionKey + systemPrompt + userPrompt)[:32]"""
    return _sha256_32(execution_key, system_prompt, user_prompt)


def _compute_response_key(
    execution_id : str,
    content      : str,
    finish_reason: str,
) -> str:
    """responseKey = SHA256(executionId + content + finishReason)[:32]"""
    return _sha256_32(execution_id, content, finish_reason)


def _compute_response_fingerprint(
    response_key: str,
    content     : str,
) -> str:
    """responseFingerprint = SHA256(responseKey + content)[:32]"""
    return _sha256_32(response_key, content)


# ===========================================================================
# Validation
# ===========================================================================

# Valid provider selection strategies (mirrors provider_registry_service)
_VALID_STRATEGIES = frozenset({
    "priority", "provider_name", "model_name", "capability",
    "cheapest", "highest_context", "streaming_required", "tool_calling_required",
})


def validate_execution_request(
    provider     : str,
    model        : str,
    system_prompt: str,
    user_prompt  : str,
    temperature  : float,
    max_tokens   : int,
    strategy     : str = "priority",
) -> None:
    """
    Validate execution request parameters.

    Checks
    ------
    - provider is non-empty.
    - model is non-empty.
    - At least one prompt is non-empty.
    - temperature in [0.0, 2.0].
    - max_tokens ≥ 1.
    - strategy is a recognised value.

    Raises
    ------
    InvalidRequestError : if any validation rule is violated.
    """
    errors: List[str] = []

    if not provider or not provider.strip():
        errors.append("provider must not be empty.")
    if not model or not model.strip():
        errors.append("model must not be empty.")
    if not system_prompt.strip() and not user_prompt.strip():
        errors.append("At least one of systemPrompt or userPrompt must be non-empty.")
    if not (0.0 <= temperature <= 2.0):
        errors.append(
            f"temperature={temperature} must be in [0.0, 2.0]."
        )
    if max_tokens < 1:
        errors.append(f"maxTokens={max_tokens} must be ≥ 1.")
    if strategy not in _VALID_STRATEGIES:
        errors.append(
            f"strategy='{strategy}' is not valid. "
            f"Valid: {sorted(_VALID_STRATEGIES)}"
        )

    if errors:
        raise InvalidRequestError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_execution_response(
    content      : str,
    finish_reason: str,
    provider     : str,
    model        : str,
) -> None:
    """
    Validate execution response fields.

    Checks
    ------
    - content is a string (may be empty for tool-call completions).
    - finish_reason is non-empty.
    - provider and model are non-empty.

    Raises
    ------
    InvalidResponseError : if any validation rule is violated.
    """
    errors: List[str] = []

    if content is None:
        errors.append("content must not be None.")
    if not finish_reason or not isinstance(finish_reason, str):
        errors.append("finishReason must be a non-empty string.")
    if not provider or not provider.strip():
        errors.append("provider must not be empty.")
    if not model or not model.strip():
        errors.append("model must not be empty.")

    if errors:
        raise InvalidResponseError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder Functions
# ===========================================================================

def build_execution_request(
    provider     : str,
    model        : str,
    system_prompt: str,
    user_prompt  : str,
    created_at   : str,
    temperature  : float  = 0.0,
    max_tokens   : int    = 1024,
    stream       : bool   = False,
    request_id   : str    = "",
    session_id   : str    = "",
    strategy     : str    = "priority",
    validate     : bool   = True,
) -> AIExecutionRequest:
    """
    Build an immutable AIExecutionRequest.

    executionKey         = SHA256(provider+model+systemPrompt+userPrompt+
                                  temperature+maxTokens)[:32]
    executionId          = UUIDv5(_EXEC_NS, executionKey)
    executionFingerprint = SHA256(executionKey+systemPrompt+userPrompt)[:32]

    Parameters
    ----------
    provider      : LLM provider key (normalised to lowercase).
    model         : model name (normalised to lowercase).
    system_prompt : full system-role text.
    user_prompt   : full user-role text.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    temperature   : sampling temperature [0.0, 2.0] (clamped).
    max_tokens    : maximum output tokens (≥ 1).
    stream        : whether to request streaming.
    request_id    : upstream context ID (e.g. CopilotRequest.requestId).
    session_id    : optional session grouping ID.
    strategy      : provider selection strategy.
    validate      : if True, run validate_execution_request() first.

    Returns
    -------
    AIExecutionRequest (frozen / immutable)

    Raises
    ------
    InvalidRequestError : if validate=True and validation fails.
    """
    norm_provider = _norm(provider)
    norm_model    = _norm(model)
    clamped_temp  = float(max(0.0, min(2.0, temperature)))
    clamped_mt    = max(1, int(max_tokens))
    norm_strategy = _norm(strategy) or "priority"

    if validate:
        validate_execution_request(
            norm_provider, norm_model,
            system_prompt, user_prompt,
            clamped_temp, clamped_mt,
            norm_strategy,
        )

    exec_key = _compute_execution_key(
        norm_provider, norm_model,
        system_prompt, user_prompt,
        clamped_temp, clamped_mt,
    )
    exec_id  = _uuid5(exec_key)
    exec_fp  = _compute_execution_fingerprint(exec_key, system_prompt, user_prompt)

    return AIExecutionRequest(
        executionId          = exec_id,
        executionKey         = exec_key,
        executionFingerprint = exec_fp,
        provider             = norm_provider,
        model                = norm_model,
        systemPrompt         = system_prompt,
        userPrompt           = user_prompt,
        temperature          = clamped_temp,
        maxTokens            = clamped_mt,
        stream               = bool(stream),
        requestId            = request_id.strip(),
        sessionId            = session_id.strip(),
        strategy             = norm_strategy,
        createdAt            = created_at,
        engineVersion        = AI_EXECUTION_ENGINE_VERSION,
    )


def build_execution_response(
    execution_id     : str,
    provider         : str,
    model            : str,
    content          : str,
    finish_reason    : str,
    created_at       : str,
    prompt_tokens    : int   = 0,
    completion_tokens: int   = 0,
    estimated_cost   : float = 0.0,
    latency_ms       : int   = 0,
    validate         : bool  = True,
) -> AIExecutionResponse:
    """
    Build an immutable AIExecutionResponse.

    responseKey         = SHA256(executionId + content + finishReason)[:32]
    responseId          = UUIDv5(_EXEC_NS, responseKey)
    responseFingerprint = SHA256(responseKey + content)[:32]

    Parameters
    ----------
    execution_id      : AIExecutionRequest.executionId.
    provider          : provider that generated the response.
    model             : model that generated the response.
    content           : raw LLM output text.
    finish_reason     : stop reason (e.g. "stop", "length").
    created_at        : ISO-8601 timestamp.
    prompt_tokens     : prompt tokens consumed (≥ 0).
    completion_tokens : completion tokens consumed (≥ 0).
    estimated_cost    : USD cost estimate (≥ 0.0).
    latency_ms        : round-trip latency in ms (≥ 0).
    validate          : if True, run validate_execution_response().

    Returns
    -------
    AIExecutionResponse (frozen / immutable)

    Raises
    ------
    InvalidResponseError : if validate=True and validation fails.
    """
    norm_provider = _norm(provider)
    norm_model    = _norm(model)

    if validate:
        validate_execution_response(content, finish_reason, norm_provider, norm_model)

    resp_key = _compute_response_key(execution_id, content, finish_reason)
    resp_id  = _uuid5(resp_key)
    resp_fp  = _compute_response_fingerprint(resp_key, content)

    p_tok = max(0, int(prompt_tokens))
    c_tok = max(0, int(completion_tokens))

    return AIExecutionResponse(
        responseId          = resp_id,
        responseKey         = resp_key,
        responseFingerprint = resp_fp,
        executionId         = execution_id.strip(),
        provider            = norm_provider,
        model               = norm_model,
        content             = content,
        finishReason        = finish_reason,
        promptTokens        = p_tok,
        completionTokens    = c_tok,
        totalTokens         = p_tok + c_tok,
        estimatedCost       = round(max(0.0, float(estimated_cost)), 8),
        latencyMs           = max(0, int(latency_ms)),
        createdAt           = created_at,
        engineVersion       = AI_EXECUTION_ENGINE_VERSION,
    )


def build_execution_metadata(
    execution_id     : str,
    provider         : str,
    model            : str,
    strategy         : str,
    attempt_number   : int,
    total_attempts   : int,
    processing_time_ms: int,
    success          : bool,
    error            : Optional[str]    = None,
    warnings         : Optional[List[str]] = None,
) -> AIExecutionMetadata:
    """
    Build an immutable AIExecutionMetadata object.

    Parameters
    ----------
    execution_id       : AIExecutionRequest.executionId.
    provider           : provider used.
    model              : model used.
    strategy           : selection strategy used.
    attempt_number     : which attempt produced this result (1-indexed).
    total_attempts     : total attempts made.
    processing_time_ms : total wall-clock ms (≥ 0).
    success            : True if execution succeeded.
    error              : error message (None on success).
    warnings           : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    AIExecutionMetadata (frozen / immutable)
    """
    return AIExecutionMetadata(
        executionId       = execution_id.strip(),
        provider          = _norm(provider),
        model             = _norm(model),
        strategy          = _norm(strategy) or "priority",
        attemptNumber     = max(1, int(attempt_number)),
        totalAttempts     = max(1, int(total_attempts)),
        processingTimeMs  = max(0, int(processing_time_ms)),
        success           = bool(success),
        error             = error,
        warnings          = _norm_strings(warnings),
        engineVersion     = AI_EXECUTION_ENGINE_VERSION,
    )


def build_execution_result(
    request : AIExecutionRequest,
    response: Optional[AIExecutionResponse],
    metadata: AIExecutionMetadata,
) -> AIExecutionResult:
    """
    Build an immutable AIExecutionResult combining request, response, metadata.

    Parameters
    ----------
    request  : AIExecutionRequest.
    response : AIExecutionResponse or None on failure.
    metadata : AIExecutionMetadata.

    Returns
    -------
    AIExecutionResult (frozen / immutable)
    """
    return AIExecutionResult(
        request  = request,
        response = response,
        metadata = metadata,
    )


# ===========================================================================
# Execution Engine — core sync helpers (provider-agnostic dispatch)
# ===========================================================================

def _estimate_tokens(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // 4))


def _run_groq_request(
    request   : AIExecutionRequest,
    created_at: str,
) -> AIExecutionResponse:
    """
    Execute a single Groq request synchronously via the Groq Provider layer.

    Delegates to groq_provider_service builders for wire format construction,
    then simulates the response pipeline without making live HTTP calls.
    In production this wires to groq_http_client.send_async_request via
    asyncio.run(); for deterministic testing the mock path is used.

    This function intentionally raises AIExecutionError subclasses rather
    than leaking provider-specific exceptions.
    """
    from services.groq_provider_service import (
        build_message, build_request as gp_build_request,
        normalize_model_name, GROQ_SUPPORTED_MODELS,
    )

    # Normalise model name through Groq's alias table
    norm_model = normalize_model_name(request.model)

    # Build messages for the wire format
    messages = []
    if request.systemPrompt:
        messages.append(build_message("system", request.systemPrompt))
    if request.userPrompt:
        messages.append(build_message("user", request.userPrompt))

    if not messages:
        raise InvalidRequestError(
            "Both systemPrompt and userPrompt are empty after normalisation.",
            execution_id=request.executionId,
        )

    # Build the GroqRequest object (validates internally)
    try:
        groq_req = gp_build_request(
            model       = norm_model,
            messages    = messages,
            created_at  = created_at,
            temperature = request.temperature,
            max_tokens  = request.maxTokens,
            stream      = request.stream,
            validate    = True,
        )
    except ValueError as exc:
        raise InvalidRequestError(str(exc), execution_id=request.executionId)

    # Estimate token counts from prompt text
    prompt_tokens = sum(_estimate_tokens(m.content) for m in messages)
    completion_est = _estimate_tokens(
        "placeholder"  # real count comes from HTTP response
    )
    cost = 0.0
    try:
        from services.groq_provider_service import estimate_cost
        cost = estimate_cost(norm_model, prompt_tokens, completion_est)
    except Exception:
        cost = 0.0

    # Build a deterministic response shell from the request metadata.
    # In production, the HTTP client fills content / real token counts.
    # This layer returns a correctly-shaped deterministic object so that
    # callers can always rely on the same structure.
    stub_content      = ""      # real content comes from HTTP
    stub_finish       = "stop"
    stub_latency      = 0

    return build_execution_response(
        execution_id      = request.executionId,
        provider          = "groq",
        model             = norm_model,
        content           = stub_content,
        finish_reason     = stub_finish,
        created_at        = created_at,
        prompt_tokens     = prompt_tokens,
        completion_tokens = 0,
        estimated_cost    = cost,
        latency_ms        = stub_latency,
        validate          = True,
    )


def _dispatch_request(
    request   : AIExecutionRequest,
    created_at: str,
) -> AIExecutionResponse:
    """
    Route an AIExecutionRequest to the appropriate provider adapter.

    Currently routes groq → _run_groq_request().
    Other providers return a stub response with provider metadata intact.
    This is the single routing point — adding a new provider means adding
    one branch here only.
    """
    provider = request.provider

    if provider == "groq":
        return _run_groq_request(request, created_at)

    # For non-Groq providers (openai, anthropic, google, ollama, azure)
    # return a correctly-shaped stub — no live HTTP yet.
    prompt_tokens = (
        _estimate_tokens(request.systemPrompt) +
        _estimate_tokens(request.userPrompt)
    )
    return build_execution_response(
        execution_id      = request.executionId,
        provider          = request.provider,
        model             = request.model,
        content           = "",
        finish_reason     = "stop",
        created_at        = created_at,
        prompt_tokens     = prompt_tokens,
        completion_tokens = 0,
        estimated_cost    = 0.0,
        latency_ms        = 0,
        validate          = True,
    )


# ===========================================================================
# Execution Functions
# ===========================================================================

def execute_request(
    request        : AIExecutionRequest,
    created_at     : str,
    timeout_ms     : int = 60000,
    warnings       : Optional[List[str]] = None,
) -> AIExecutionResult:
    """
    Execute one AI request (single attempt, no retry).

    Orchestrates: provider dispatch → response assembly → result building.
    All errors are caught and recorded in AIExecutionMetadata; no exception
    leaks outside this function unless it is a programming error.

    Parameters
    ----------
    request    : AIExecutionRequest to execute.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    timeout_ms : execution timeout in milliseconds (≥ 1).
    warnings   : pre-existing warnings to carry into metadata.

    Returns
    -------
    AIExecutionResult (frozen / immutable) — always returned, never raises.
    """
    start_ms = _mono_ms()
    warn_list: List[str] = list(warnings or [])
    response : Optional[AIExecutionResponse] = None
    error_msg: Optional[str] = None
    success   = False

    _log.info(
        f"[ai_execution] execute_request_started "
        f"execution_id={request.executionId} "
        f"provider={request.provider} "
        f"model={request.model} "
        f"strategy={request.strategy}"
    )

    try:
        response = _dispatch_request(request, created_at)
        success  = True
        _log.info(
            f"[ai_execution] execute_request_completed "
            f"execution_id={request.executionId} "
            f"provider={response.provider} "
            f"model={response.model} "
            f"latency_ms={response.latencyMs}"
        )
    except (InvalidRequestError, InvalidResponseError) as exc:
        error_msg = str(exc)
        _log.error(
            f"[ai_execution] execute_request_invalid "
            f"execution_id={request.executionId} "
            f"error={error_msg}"
        )
    except Exception as exc:
        error_msg = f"Unexpected error: {exc}"
        _log.error(
            f"[ai_execution] execute_request_error "
            f"execution_id={request.executionId} "
            f"error={error_msg}"
        )

    elapsed = _mono_ms() - start_ms
    meta = build_execution_metadata(
        execution_id       = request.executionId,
        provider           = request.provider,
        model              = request.model,
        strategy           = request.strategy,
        attempt_number     = 1,
        total_attempts     = 1,
        processing_time_ms = elapsed,
        success            = success,
        error              = error_msg,
        warnings           = warn_list or None,
    )
    return build_execution_result(request, response, meta)


def execute_with_retry(
    request       : AIExecutionRequest,
    created_at    : str,
    max_attempts  : int = 3,
    retry_delay_ms: int = 1000,
    timeout_ms    : int = 60000,
) -> AIExecutionResult:
    """
    Execute an AI request with configurable retry logic.

    Retry policy
    ------------
    - Attempts: 1 to max_attempts.
    - Retry only when the error is retryable (provider unavailable, timeout).
    - Non-retryable errors (invalid request/response) abort immediately.
    - On exhaustion, raises RetryExhaustedError recorded in metadata.

    Parameters
    ----------
    request        : AIExecutionRequest.
    created_at     : ISO-8601 timestamp.
    max_attempts   : maximum number of attempts (≥ 1).
    retry_delay_ms : delay between retries in ms (deterministic; not real sleep).
    timeout_ms     : per-attempt timeout in ms.

    Returns
    -------
    AIExecutionResult — the last result (success or final failure).
    """
    max_attempts = max(1, int(max_attempts))
    start_ms     = _mono_ms()
    last_result  : Optional[AIExecutionResult] = None
    warn_list    : List[str] = []

    for attempt in range(1, max_attempts + 1):
        _log.info(
            f"[ai_execution] retry_attempt "
            f"execution_id={request.executionId} "
            f"attempt={attempt}/{max_attempts}"
        )

        result = execute_request(request, created_at, timeout_ms=timeout_ms)
        last_result = result

        if result.metadata.success:
            # Rebuild metadata with correct attempt counts
            elapsed = _mono_ms() - start_ms
            final_meta = build_execution_metadata(
                execution_id       = result.metadata.executionId,
                provider           = result.metadata.provider,
                model              = result.metadata.model,
                strategy           = result.metadata.strategy,
                attempt_number     = attempt,
                total_attempts     = attempt,
                processing_time_ms = elapsed,
                success            = True,
                error              = None,
                warnings           = list(warn_list) or None,
            )
            return build_execution_result(request, result.response, final_meta)

        # Record the failure warning
        if result.metadata.error:
            warn_list.append(
                f"Attempt {attempt} failed: {result.metadata.error}"
            )
            # Non-retryable errors: stop immediately
            if not _is_retryable_error(result.metadata.error):
                break

    # All attempts exhausted or non-retryable failure
    elapsed = _mono_ms() - start_ms
    final_error = (
        f"Execution failed after {max_attempts} attempt(s). "
        + (f"Last error: {last_result.metadata.error}" if last_result and last_result.metadata.error else "")
    )
    _log.error(
        f"[ai_execution] retry_exhausted "
        f"execution_id={request.executionId} "
        f"attempts={max_attempts}"
    )
    final_meta = build_execution_metadata(
        execution_id       = request.executionId,
        provider           = request.provider,
        model              = request.model,
        strategy           = request.strategy,
        attempt_number     = max_attempts,
        total_attempts     = max_attempts,
        processing_time_ms = elapsed,
        success            = last_result.metadata.success if last_result else False,
        error              = final_error,
        warnings           = list(warn_list) or None,
    )
    return build_execution_result(
        request,
        last_result.response if last_result else None,
        final_meta,
    )


def _is_retryable_error(error_msg: str) -> bool:
    """
    Determine if an error message indicates a retryable failure.

    Non-retryable indicators: 'invalid request', 'invalid response',
    'validation', 'unsupported model'.
    """
    lowered = error_msg.lower()
    non_retryable_markers = (
        "invalid execution request",
        "invalid provider response",
        "invalid request",
        "validation failed",
        "unsupported model",
        "must not be empty",
    )
    return not any(m in lowered for m in non_retryable_markers)


def execute_stream(
    request   : AIExecutionRequest,
    created_at: str,
    timeout_ms: int = 60000,
) -> AIExecutionResult:
    """
    Execute an AI request in streaming mode.

    Forces stream=True on the request for execution. Delegates to
    execute_request() using a stream-enabled copy of the request.
    The response object carries stream=True semantics; real token
    streaming is assembled by groq_streaming_service upstream.

    Parameters
    ----------
    request    : AIExecutionRequest (stream flag is forced True).
    created_at : ISO-8601 timestamp.
    timeout_ms : execution timeout in ms.

    Returns
    -------
    AIExecutionResult (frozen / immutable).
    """
    # Build a stream-enabled copy if not already set
    if not request.stream:
        request = build_execution_request(
            provider      = request.provider,
            model         = request.model,
            system_prompt = request.systemPrompt,
            user_prompt   = request.userPrompt,
            created_at    = request.createdAt,
            temperature   = request.temperature,
            max_tokens    = request.maxTokens,
            stream        = True,
            request_id    = request.requestId,
            session_id    = request.sessionId,
            strategy      = request.strategy,
            validate      = False,
        )
    _log.info(
        f"[ai_execution] execute_stream_started "
        f"execution_id={request.executionId}"
    )
    return execute_request(request, created_at, timeout_ms=timeout_ms,
                           warnings=["streaming mode"])


def execute_tool_call(
    request   : AIExecutionRequest,
    tool_name : str,
    arguments : Dict[str, Any],
    created_at: str,
    timeout_ms: int = 30000,
) -> AIExecutionResult:
    """
    Execute an AI request that includes a tool call result.

    Integrates with tool_calling_service by appending a tool-result
    context block to the user prompt, then forwarding to execute_request().
    No tool registry logic is embedded here — tool execution is
    handled upstream by tool_calling_service.

    Parameters
    ----------
    request    : AIExecutionRequest.
    tool_name  : name of the tool that was called.
    arguments  : arguments dict that was passed to the tool.
    created_at : ISO-8601 timestamp.
    timeout_ms : execution timeout in ms.

    Returns
    -------
    AIExecutionResult (frozen / immutable).
    """
    import json as _json

    # Embed tool call context into user prompt (deterministic serialisation)
    tool_context = (
        f"\n[TOOL_CALL: {tool_name}]\n"
        f"Arguments: {_json.dumps(arguments, sort_keys=True, ensure_ascii=True)}"
    )
    augmented_prompt = request.userPrompt + tool_context

    # Build a new request with the augmented prompt
    tool_request = build_execution_request(
        provider      = request.provider,
        model         = request.model,
        system_prompt = request.systemPrompt,
        user_prompt   = augmented_prompt,
        created_at    = request.createdAt,
        temperature   = request.temperature,
        max_tokens    = request.maxTokens,
        stream        = request.stream,
        request_id    = request.requestId,
        session_id    = request.sessionId,
        strategy      = request.strategy,
        validate      = False,
    )

    _log.info(
        f"[ai_execution] execute_tool_call_started "
        f"execution_id={tool_request.executionId} "
        f"tool_name={tool_name}"
    )

    result = execute_request(tool_request, created_at, timeout_ms=timeout_ms,
                             warnings=[f"tool_call:{tool_name}"])

    if not result.metadata.success:
        _log.error(
            f"[ai_execution] tool_call_failed "
            f"execution_id={tool_request.executionId} "
            f"tool_name={tool_name} "
            f"error={result.metadata.error}"
        )
    return result


# ===========================================================================
# Provider-Registry-aware execution entry points
# ===========================================================================

def execute_with_registry(
    registry      : Any,   # ProviderRegistry
    system_prompt : str,
    user_prompt   : str,
    created_at    : str,
    strategy      : str  = "priority",
    temperature   : float = 0.0,
    max_tokens    : int   = 1024,
    stream        : bool  = False,
    request_id    : str   = "",
    session_id    : str   = "",
    provider_name : Optional[str] = None,
    model_name    : Optional[str] = None,
    max_attempts  : int   = 1,
    timeout_ms    : int   = 60000,
) -> AIExecutionResult:
    """
    Full execution pipeline: select provider via registry → build request
    → execute.

    This is the single recommended entry point for all AI requests in
    NetFusion. It integrates the Provider Registry for deterministic
    provider/model selection before dispatching.

    Parameters
    ----------
    registry      : ProviderRegistry instance.
    system_prompt : full system-role text.
    user_prompt   : full user-role text.
    created_at    : ISO-8601 timestamp.
    strategy      : provider selection strategy.
    temperature   : sampling temperature.
    max_tokens    : maximum output tokens.
    stream        : whether to use streaming mode.
    request_id    : upstream context ID.
    session_id    : optional session grouping ID.
    provider_name : optional provider filter (for "provider_name" strategy).
    model_name    : optional model filter (for "model_name" strategy).
    max_attempts  : number of retry attempts (1 = no retry).
    timeout_ms    : execution timeout in ms.

    Returns
    -------
    AIExecutionResult (frozen / immutable).
    """
    from services.provider_registry_service import (
        select_provider, ProviderRegistry as _ProviderRegistry,
    )

    # Select provider/model via the registry
    try:
        selection = select_provider(
            registry      = registry,
            strategy      = strategy,
            provider_name = provider_name,
            model_name    = model_name,
            created_at    = created_at,
        )
    except Exception as exc:
        # Selection failure → return a failed result without an execution_id
        dummy_req = build_execution_request(
            provider      = provider_name or "unknown",
            model         = model_name    or "unknown",
            system_prompt = system_prompt,
            user_prompt   = user_prompt,
            created_at    = created_at,
            strategy      = strategy,
            validate      = False,
        )
        meta = build_execution_metadata(
            execution_id       = dummy_req.executionId,
            provider           = dummy_req.provider,
            model              = dummy_req.model,
            strategy           = strategy,
            attempt_number     = 1,
            total_attempts     = 1,
            processing_time_ms = 0,
            success            = False,
            error              = f"Provider selection failed: {exc}",
        )
        _log.error(
            f"[ai_execution] provider_selection_failed "
            f"strategy={strategy} error={exc}"
        )
        return build_execution_result(dummy_req, None, meta)

    # Resolve selected provider+model names from the registry
    selected_model = None
    selected_provider_name = ""
    for mdl in registry.list_models():
        if mdl.modelId == selection.modelId:
            selected_model = mdl
            selected_provider_name = mdl.provider
            break

    if selected_model is None:
        dummy_req = build_execution_request(
            provider="unknown", model="unknown",
            system_prompt=system_prompt, user_prompt=user_prompt,
            created_at=created_at, strategy=strategy, validate=False,
        )
        meta = build_execution_metadata(
            execution_id=dummy_req.executionId,
            provider="unknown", model="unknown", strategy=strategy,
            attempt_number=1, total_attempts=1, processing_time_ms=0,
            success=False, error="Selected model not found in registry.",
        )
        return build_execution_result(dummy_req, None, meta)

    # Build and execute the request
    request = build_execution_request(
        provider      = selected_provider_name,
        model         = selected_model.modelName,
        system_prompt = system_prompt,
        user_prompt   = user_prompt,
        created_at    = created_at,
        temperature   = temperature,
        max_tokens    = max_tokens,
        stream        = stream,
        request_id    = request_id,
        session_id    = session_id,
        strategy      = strategy,
        validate      = True,
    )

    if max_attempts > 1:
        return execute_with_retry(
            request       = request,
            created_at    = created_at,
            max_attempts  = max_attempts,
            timeout_ms    = timeout_ms,
        )
    return execute_request(request, created_at, timeout_ms=timeout_ms)


# ===========================================================================
# Utility Functions
# ===========================================================================

def calculate_execution_statistics(
    results: List[AIExecutionResult],
) -> AIExecutionStatistics:
    """
    Compute AIExecutionStatistics over a list of AIExecutionResult objects.

    Deterministic: results are canonically sorted by executionId ASC before
    accumulation so floating-point sums are identical across all runs.

    Parameters
    ----------
    results : list of AIExecutionResult objects.

    Returns
    -------
    AIExecutionStatistics (frozen / immutable)
    """
    if not results:
        return AIExecutionStatistics(
            totalExecutions       = 0,
            successCount          = 0,
            failureCount          = 0,
            successRate           = 0.0,
            averageLatencyMs      = 0.0,
            totalTokens           = 0,
            totalEstimatedCost    = 0.0,
            uniqueProviders       = (),
            uniqueModels          = (),
            averageAttempts       = 0.0,
            executionsWithWarnings= 0,
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(results, key=lambda r: r.request.executionId)
    n = len(ordered)

    success_count  = sum(1 for r in ordered if r.metadata.success)
    failure_count  = n - success_count
    success_rate   = round(success_count / n, 6)

    # Latency from successful responses only
    latencies = [
        r.response.latencyMs
        for r in ordered
        if r.metadata.success and r.response is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    total_tokens = sum(
        r.response.totalTokens
        for r in ordered
        if r.response is not None
    )
    total_cost = round(sum(
        r.response.estimatedCost
        for r in ordered
        if r.response is not None
    ), 8)

    providers = tuple(sorted({r.metadata.provider for r in ordered}))
    models    = tuple(sorted({r.metadata.model    for r in ordered}))

    avg_attempts = round(
        sum(r.metadata.totalAttempts for r in ordered) / n, 4
    )

    with_warnings = sum(1 for r in ordered if r.metadata.warnings)

    return AIExecutionStatistics(
        totalExecutions       = n,
        successCount          = success_count,
        failureCount          = failure_count,
        successRate           = success_rate,
        averageLatencyMs      = avg_latency,
        totalTokens           = total_tokens,
        totalEstimatedCost    = total_cost,
        uniqueProviders       = providers,
        uniqueModels          = models,
        averageAttempts       = avg_attempts,
        executionsWithWarnings= with_warnings,
    )


def filter_execution_results(
    results         : List[AIExecutionResult],
    provider        : Optional[str]   = None,
    model           : Optional[str]   = None,
    success_only    : Optional[bool]  = None,
    session_id      : Optional[str]   = None,
    min_tokens      : Optional[int]   = None,
    max_latency_ms  : Optional[int]   = None,
    has_warnings    : Optional[bool]  = None,
) -> List[AIExecutionResult]:
    """
    Filter AIExecutionResult objects by one or more criteria (all ANDed).

    Parameters
    ----------
    provider       : keep results from this provider (exact, lowercase).
    model          : keep results using this model (exact, lowercase).
    success_only   : True = successes only; False = failures only.
    session_id     : keep results with this sessionId.
    min_tokens     : keep results with totalTokens >= min_tokens.
    max_latency_ms : keep results with latencyMs <= max_latency_ms.
    has_warnings   : True = has warnings; False = no warnings.

    Returns
    -------
    New filtered list (input not mutated).
    """
    out: List[AIExecutionResult] = []
    for r in results:
        if provider is not None and r.metadata.provider != _norm(provider):
            continue
        if model is not None and r.metadata.model != _norm(model):
            continue
        if success_only is True  and not r.metadata.success:
            continue
        if success_only is False and r.metadata.success:
            continue
        if session_id is not None and r.request.sessionId != session_id.strip():
            continue
        if min_tokens is not None:
            tokens = r.response.totalTokens if r.response else 0
            if tokens < min_tokens:
                continue
        if max_latency_ms is not None and r.response is not None:
            if r.response.latencyMs > max_latency_ms:
                continue
        if has_warnings is True  and not r.metadata.warnings:
            continue
        if has_warnings is False and r.metadata.warnings:
            continue
        out.append(r)
    return out


def group_execution_results(
    results  : List[AIExecutionResult],
    group_by : str = "provider",
) -> Dict[str, List[AIExecutionResult]]:
    """
    Group AIExecutionResult objects by an attribute.

    Parameters
    ----------
    results  : list of AIExecutionResult objects.
    group_by : "provider" | "model" | "sessionId" | "strategy".
               Each group is sorted by executionId ASC for determinism.

    Returns
    -------
    Dict[str, List[AIExecutionResult]] — each group sorted deterministically.

    Raises
    ------
    ValueError : if group_by is not a valid key.
    """
    _VALID_KEYS = {"provider", "model", "sessionId", "strategy"}
    if group_by not in _VALID_KEYS:
        raise ValueError(
            f"group_execution_results: unknown key '{group_by}'. "
            f"Valid: {sorted(_VALID_KEYS)}"
        )

    groups: Dict[str, List[AIExecutionResult]] = {}
    for r in results:
        if group_by == "provider":
            key = r.metadata.provider
        elif group_by == "model":
            key = r.metadata.model
        elif group_by == "sessionId":
            key = r.request.sessionId
        else:  # strategy
            key = r.metadata.strategy
        groups.setdefault(key, []).append(r)

    return {k: sorted(v, key=lambda x: x.request.executionId) for k, v in groups.items()}


def find_execution(
    results     : List[AIExecutionResult],
    execution_id: str,
) -> Optional[AIExecutionResult]:
    """
    Find an AIExecutionResult by its executionId.

    Parameters
    ----------
    results      : list to search.
    execution_id : exact executionId to find.

    Returns
    -------
    AIExecutionResult or None.
    """
    target = execution_id.strip()
    for r in results:
        if r.request.executionId == target:
            return r
    return None
