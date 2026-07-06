"""
Copilot Orchestrator Engine
============================
Phase A4.1.4 — Deterministic, immutable AI request/response orchestration.

Responsibilities
----------------
- Prepare deterministic CopilotRequest objects from context, reasoning,
  prompt packages, and narratives — ready for any LLM provider.
- Wrap raw LLM responses into deterministic CopilotResponse objects.
- Combine request + response into an immutable CopilotSession.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute fingerprints for every object for cache/replay stability.
- Expose builder functions: build_copilot_request, build_copilot_response,
  build_copilot_metadata, build_copilot_session.
- Expose utility functions: estimate_tokens, sort_citations, filter_sessions,
  group_sessions, calculate_session_statistics, find_session.

Orchestration flow
------------------
AI Context → Reasoning → Prompt Package → Investigation Narrative →
CopilotRequest → (External LLM — NOT implemented here) →
CopilotResponse → CopilotSession

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- NO external API calls. NO LLM SDK. NO network requests.
- No OpenAI, Claude, Gemini, Ollama, LangChain, or any AI SDK.
- No uuid4(). No random module. No unordered set iteration.
- Provider-agnostic: works equally for OpenAI, Claude, Gemini, Ollama,
  Azure OpenAI, and any future provider.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import COPILOT_ORCHESTRATOR_ENGINE_VERSION

# ── UUIDv5 namespace — fixed; changing it invalidates all stored IDs ────────
_COPILOT_NS = uuid.UUID("6ba7b818-9dad-11d1-80b4-00c04fd430c8")

# ── Approximate chars-per-token ratio (conservative GPT-style estimate) ─────
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class CopilotMetadata(BaseModel):
    """
    Provenance and performance metadata for one copilot interaction.

    Fields
    ------
    processingTimeMs      : wall-clock ms to prepare the request or
                            process the response.
    providerName          : normalised provider name (e.g. "openai",
                            "anthropic", "google", "ollama").
    modelName             : normalised model name (e.g. "gpt-4o",
                            "claude-3-5-sonnet", "gemini-1.5-pro").
    engineVersion         : COPILOT_ORCHESTRATOR_ENGINE_VERSION at build time.
    promptTokenEstimate   : estimated token count for the request prompts.
    responseTokenEstimate : estimated token count for the response content.
    warnings              : sorted tuple of non-fatal advisory strings.
    """
    processingTimeMs      : int
    providerName          : str
    modelName             : str
    engineVersion         : str
    promptTokenEstimate   : int
    responseTokenEstimate : int
    warnings              : Tuple[str, ...]

    class Config:
        frozen = True


class CopilotRequest(BaseModel):
    """
    One complete, immutable AI request prepared for any LLM provider.

    Identity
    --------
    requestId          : UUIDv5(COPILOT_NS, requestKey) — deterministic.
    requestKey         : SHA256(contextId + reasoningId + promptPackageId +
                         narrativeId + provider + model)[:32]
    requestFingerprint : SHA256(requestKey + systemPrompt + userPrompt +
                         provider + model)[:32]

    Prompts
    -------
    systemPrompt : full system-role text to send to the LLM.
    userPrompt   : full user-role text to send to the LLM.

    LLM Parameters
    --------------
    temperature : 0.0–2.0 sampling temperature (provider-dependent).
    maxTokens   : maximum completion tokens requested.

    Linkage
    -------
    contextId       : AIContext.contextId that provided the data.
    reasoningId     : ReasoningResult.reasoningId that drove this request.
    promptPackageId : PromptPackage.packageId used to assemble the prompts.
    narrativeId     : NarrativeDocument.narrativeId for this investigation.
    investigationId : Investigation.investigationId scope.
    provider        : LLM provider identifier (e.g. "openai", "anthropic").
    model           : model identifier (e.g. "gpt-4o", "claude-3-5-sonnet").

    Metadata
    --------
    metadata  : CopilotMetadata — provenance, timings, token estimates.
    createdAt : ISO-8601 timestamp (caller-supplied for determinism).
    """
    requestId          : str
    requestKey         : str
    requestFingerprint : str
    contextId          : str
    reasoningId        : str
    promptPackageId    : str
    narrativeId        : str
    investigationId    : str
    provider           : str
    model              : str
    systemPrompt       : str
    userPrompt         : str
    temperature        : float
    maxTokens          : int
    metadata           : CopilotMetadata
    createdAt          : str

    class Config:
        frozen = True


class CopilotResponse(BaseModel):
    """
    One complete, immutable AI response received from any LLM provider.

    Identity
    --------
    responseId          : UUIDv5(COPILOT_NS, responseKey) — deterministic.
    responseKey         : SHA256(requestId + content + provider + model)[:32]
    responseFingerprint : SHA256(responseKey + content + sorted citations)[:32]

    Content
    -------
    content   : the raw text content returned by the LLM.
    confidence: 0–100 confidence score (caller-assessed; never from LLM).
    citations : sorted tuple of citation strings extracted from the response.

    Linkage
    -------
    requestId : CopilotRequest.requestId this response answers.
    provider  : LLM provider that generated this response.
    model     : model that generated this response.

    Metadata
    --------
    metadata  : CopilotMetadata — provenance, timings, token estimates.
    createdAt : ISO-8601 timestamp (caller-supplied for determinism).
    """
    responseId          : str
    responseKey         : str
    responseFingerprint : str
    requestId           : str
    provider            : str
    model               : str
    content             : str
    confidence          : float
    citations           : Tuple[str, ...]
    metadata            : CopilotMetadata
    createdAt           : str

    class Config:
        frozen = True


class CopilotSession(BaseModel):
    """
    One complete, immutable copilot session pairing a request and response.

    Identity
    --------
    sessionId  : UUIDv5(COPILOT_NS, sessionKey) — deterministic.
    sessionKey : SHA256(requestKey + responseKey)[:32]

    Content
    -------
    request  : the CopilotRequest that was sent.
    response : the CopilotResponse that was received.

    Metadata
    --------
    metadata  : CopilotMetadata — combined provenance for the session.
    createdAt : ISO-8601 timestamp (caller-supplied for determinism).
    """
    sessionId  : str
    sessionKey : str
    request    : CopilotRequest
    response   : CopilotResponse
    metadata   : CopilotMetadata
    createdAt  : str

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_request_key(
    context_id        : str,
    reasoning_id      : str,
    prompt_package_id : str,
    narrative_id      : str,
    provider          : str,
    model             : str,
) -> str:
    """
    requestKey = SHA256(contextId + reasoningId + promptPackageId +
                        narrativeId + provider + model)[:32]

    Null-byte-separated to prevent cross-field collisions.
    Returns 32 hex characters.
    """
    parts = [
        context_id.strip(),
        reasoning_id.strip(),
        prompt_package_id.strip(),
        narrative_id.strip(),
        provider.strip().lower(),
        model.strip().lower(),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_request_id(request_key: str) -> str:
    """requestId = UUIDv5(COPILOT_NS, requestKey)."""
    return str(uuid.uuid5(_COPILOT_NS, request_key))


def _compute_request_fingerprint(
    request_key  : str,
    system_prompt: str,
    user_prompt  : str,
    provider     : str,
    model        : str,
) -> str:
    """
    requestFingerprint = SHA256(requestKey + systemPrompt +
                                userPrompt + provider + model)[:32]

    Returns 32 hex characters.
    """
    parts = [
        request_key,
        system_prompt,
        user_prompt,
        provider.strip().lower(),
        model.strip().lower(),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_response_key(
    request_id: str,
    content   : str,
    provider  : str,
    model     : str,
) -> str:
    """
    responseKey = SHA256(requestId + content + provider + model)[:32]

    Null-byte-separated. Returns 32 hex characters.
    """
    parts = [
        request_id.strip(),
        content,
        provider.strip().lower(),
        model.strip().lower(),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_response_id(response_key: str) -> str:
    """responseId = UUIDv5(COPILOT_NS, responseKey)."""
    return str(uuid.uuid5(_COPILOT_NS, response_key))


def _compute_response_fingerprint(
    response_key: str,
    content     : str,
    citations   : Tuple[str, ...],
) -> str:
    """
    responseFingerprint = SHA256(responseKey + content +
                                 sorted(citations))[:32]

    Citations are sorted before hashing — order-independent.
    Returns 32 hex characters.
    """
    parts = [
        response_key,
        content,
        "\x01".join(sorted(citations)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_session_key(
    request_key : str,
    response_key: str,
) -> str:
    """
    sessionKey = SHA256(requestKey + responseKey)[:32]

    Returns 32 hex characters.
    """
    raw = f"{request_key}\x00{response_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_session_id(session_key: str) -> str:
    """sessionId = UUIDv5(COPILOT_NS, sessionKey)."""
    return str(uuid.uuid5(_COPILOT_NS, session_key))


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


# ===========================================================================
# Utility: estimate_tokens()
# ===========================================================================

def estimate_tokens(text: str) -> int:
    """
    Estimate the token count of a text string.

    Algorithm: ceiling(len(text) / 4).
    Conservative ratio of 4 chars/token matches GPT-style tokenisers well
    for English prose mixed with JSON/code. Returns at least 1 for
    non-empty strings; 0 for empty.

    Parameters
    ----------
    text : string to estimate.

    Returns
    -------
    int — estimated token count (≥ 0).
    """
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))  # ceiling division


# ===========================================================================
# Builder: build_copilot_metadata()
# ===========================================================================

def build_copilot_metadata(
    provider_name          : str,
    model_name             : str,
    processing_time_ms     : int                  = 0,
    prompt_token_estimate  : int                  = 0,
    response_token_estimate: int                  = 0,
    warnings               : Optional[List[str]]  = None,
) -> CopilotMetadata:
    """
    Build a CopilotMetadata object.

    Parameters
    ----------
    provider_name           : normalised provider (e.g. "openai", "anthropic").
    model_name              : normalised model (e.g. "gpt-4o").
    processing_time_ms      : wall-clock ms (clamped to ≥ 0).
    prompt_token_estimate   : estimated prompt tokens (≥ 0).
    response_token_estimate : estimated response tokens (≥ 0).
    warnings                : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    CopilotMetadata (frozen / immutable)
    """
    return CopilotMetadata(
        processingTimeMs      = max(0, int(processing_time_ms)),
        providerName          = provider_name.strip().lower() if provider_name else "unknown",
        modelName             = model_name.strip().lower()    if model_name    else "unknown",
        engineVersion         = COPILOT_ORCHESTRATOR_ENGINE_VERSION,
        promptTokenEstimate   = max(0, int(prompt_token_estimate)),
        responseTokenEstimate = max(0, int(response_token_estimate)),
        warnings              = _norm_strings(warnings),
    )


# ===========================================================================
# Builder: build_copilot_request()
# ===========================================================================

def build_copilot_request(
    context_id        : str,
    reasoning_id      : str,
    prompt_package_id : str,
    narrative_id      : str,
    investigation_id  : str,
    provider          : str,
    model             : str,
    system_prompt     : str,
    user_prompt       : str,
    created_at        : str,
    temperature       : float                = 0.0,
    max_tokens        : int                  = 1024,
    processing_time_ms: int                  = 0,
    warnings          : Optional[List[str]]  = None,
) -> CopilotRequest:
    """
    Build an immutable CopilotRequest ready for any LLM provider.

    Parameters
    ----------
    context_id         : AIContext.contextId.
    reasoning_id       : ReasoningResult.reasoningId.
    prompt_package_id  : PromptPackage.packageId.
    narrative_id       : NarrativeDocument.narrativeId.
    investigation_id   : Investigation.investigationId.
    provider           : LLM provider key (e.g. "openai", "anthropic",
                         "google", "ollama").  Normalised to lowercase.
    model              : model key (e.g. "gpt-4o", "claude-3-5-sonnet").
                         Normalised to lowercase.
    system_prompt      : full system-role text.
    user_prompt        : full user-role text.
    created_at         : ISO-8601 timestamp (caller-supplied).
    temperature        : sampling temperature, clamped to [0.0, 2.0].
    max_tokens         : maximum completion tokens (≥ 1).
    processing_time_ms : wall-clock ms to prepare this request.
    warnings           : non-fatal advisory strings.

    Returns
    -------
    CopilotRequest (frozen / immutable)
    """
    norm_provider = provider.strip().lower() if provider else "unknown"
    norm_model    = model.strip().lower()    if model    else "unknown"

    req_key = _compute_request_key(
        context_id, reasoning_id, prompt_package_id,
        narrative_id, norm_provider, norm_model,
    )
    req_id  = _compute_request_id(req_key)
    req_fp  = _compute_request_fingerprint(
        req_key, system_prompt, user_prompt, norm_provider, norm_model,
    )

    prompt_tokens = estimate_tokens(system_prompt) + estimate_tokens(user_prompt)

    meta = build_copilot_metadata(
        provider_name          = norm_provider,
        model_name             = norm_model,
        processing_time_ms     = processing_time_ms,
        prompt_token_estimate  = prompt_tokens,
        response_token_estimate= 0,
        warnings               = warnings,
    )

    return CopilotRequest(
        requestId          = req_id,
        requestKey         = req_key,
        requestFingerprint = req_fp,
        contextId          = context_id.strip(),
        reasoningId        = reasoning_id.strip(),
        promptPackageId    = prompt_package_id.strip(),
        narrativeId        = narrative_id.strip(),
        investigationId    = investigation_id.strip(),
        provider           = norm_provider,
        model              = norm_model,
        systemPrompt       = system_prompt,
        userPrompt         = user_prompt,
        temperature        = _clamp(temperature, 0.0, 2.0),
        maxTokens          = max(1, int(max_tokens)),
        metadata           = meta,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_copilot_response()
# ===========================================================================

def build_copilot_response(
    request_id        : str,
    provider          : str,
    model             : str,
    content           : str,
    created_at        : str,
    confidence        : float                = 0.0,
    citations         : Optional[List[str]]  = None,
    processing_time_ms: int                  = 0,
    warnings          : Optional[List[str]]  = None,
) -> CopilotResponse:
    """
    Build an immutable CopilotResponse from a raw LLM reply.

    Parameters
    ----------
    request_id         : CopilotRequest.requestId this answers.
    provider           : LLM provider key (normalised to lowercase).
    model              : model key (normalised to lowercase).
    content            : raw text content returned by the LLM.
    created_at         : ISO-8601 timestamp (caller-supplied).
    confidence         : 0–100 caller-assessed confidence (clamped).
    citations          : citation strings extracted from the response
                         (deduped + sorted for determinism).
    processing_time_ms : wall-clock ms to receive this response.
    warnings           : non-fatal advisory strings.

    Returns
    -------
    CopilotResponse (frozen / immutable)
    """
    norm_provider = provider.strip().lower() if provider else "unknown"
    norm_model    = model.strip().lower()    if model    else "unknown"
    norm_citations: Tuple[str, ...] = _norm_strings(citations)

    resp_key = _compute_response_key(request_id, content, norm_provider, norm_model)
    resp_id  = _compute_response_id(resp_key)
    resp_fp  = _compute_response_fingerprint(resp_key, content, norm_citations)

    resp_tokens = estimate_tokens(content)

    meta = build_copilot_metadata(
        provider_name          = norm_provider,
        model_name             = norm_model,
        processing_time_ms     = processing_time_ms,
        prompt_token_estimate  = 0,
        response_token_estimate= resp_tokens,
        warnings               = warnings,
    )

    return CopilotResponse(
        responseId          = resp_id,
        responseKey         = resp_key,
        responseFingerprint = resp_fp,
        requestId           = request_id.strip(),
        provider            = norm_provider,
        model               = norm_model,
        content             = content,
        confidence          = _clamp(confidence),
        citations           = norm_citations,
        metadata            = meta,
        createdAt           = created_at,
    )


# ===========================================================================
# Builder: build_copilot_session()
# ===========================================================================

def build_copilot_session(
    request           : CopilotRequest,
    response          : CopilotResponse,
    created_at        : str,
    processing_time_ms: int                  = 0,
    warnings          : Optional[List[str]]  = None,
) -> CopilotSession:
    """
    Build an immutable CopilotSession from a matched request/response pair.

    Parameters
    ----------
    request            : CopilotRequest that was sent.
    response           : CopilotResponse that was received.
    created_at         : ISO-8601 timestamp (caller-supplied).
    processing_time_ms : total wall-clock ms for the full round-trip.
    warnings           : non-fatal advisory strings.

    Returns
    -------
    CopilotSession (frozen / immutable)
    """
    sess_key = _compute_session_key(request.requestKey, response.responseKey)
    sess_id  = _compute_session_id(sess_key)

    combined_prompt_tokens   = request.metadata.promptTokenEstimate
    combined_response_tokens = response.metadata.responseTokenEstimate

    meta = build_copilot_metadata(
        provider_name          = request.provider,
        model_name             = request.model,
        processing_time_ms     = processing_time_ms,
        prompt_token_estimate  = combined_prompt_tokens,
        response_token_estimate= combined_response_tokens,
        warnings               = warnings,
    )

    return CopilotSession(
        sessionId  = sess_id,
        sessionKey = sess_key,
        request    = request,
        response   = response,
        metadata   = meta,
        createdAt  = created_at,
    )


# ===========================================================================
# Utility: sort_citations()
# ===========================================================================

def sort_citations(
    citations : List[str],
    ascending : bool = True,
) -> List[str]:
    """
    Sort a list of citation strings.

    Parameters
    ----------
    citations : list of citation strings (stripped before sorting).
    ascending : True = A→Z (default); False = Z→A.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        (c.strip() for c in citations if c and c.strip()),
        reverse=not ascending,
    )


# ===========================================================================
# Utility: filter_sessions()
# ===========================================================================

def filter_sessions(
    sessions            : List[CopilotSession],
    provider            : Optional[str]   = None,
    model               : Optional[str]   = None,
    investigation_id    : Optional[str]   = None,
    min_confidence      : Optional[float] = None,
    max_confidence      : Optional[float] = None,
    has_citations       : Optional[bool]  = None,
    has_warnings        : Optional[bool]  = None,
) -> List[CopilotSession]:
    """
    Filter sessions by one or more criteria (all ANDed together).

    Parameters
    ----------
    provider         : keep sessions from this provider (exact, case-insensitive).
    model            : keep sessions using this model (exact, case-insensitive).
    investigation_id : keep sessions for this investigation.
    min_confidence   : keep sessions with response.confidence >= min_confidence.
    max_confidence   : keep sessions with response.confidence <= max_confidence.
    has_citations    : True = only sessions with citations; False = without.
    has_warnings     : True = only sessions with metadata.warnings; False = without.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[CopilotSession] = []
    for s in sessions:
        if provider         is not None and s.request.provider         != provider.strip().lower():
            continue
        if model            is not None and s.request.model            != model.strip().lower():
            continue
        if investigation_id is not None and s.request.investigationId  != investigation_id.strip():
            continue
        if min_confidence   is not None and s.response.confidence      < min_confidence:
            continue
        if max_confidence   is not None and s.response.confidence      > max_confidence:
            continue
        if has_citations is not None:
            if has_citations     and not s.response.citations:
                continue
            if not has_citations and s.response.citations:
                continue
        if has_warnings is not None:
            if has_warnings     and not s.metadata.warnings:
                continue
            if not has_warnings and s.metadata.warnings:
                continue
        result.append(s)
    return result


# ===========================================================================
# Utility: group_sessions()
# ===========================================================================

def group_sessions(
    sessions : List[CopilotSession],
    group_by : str = "provider",
) -> Dict[str, List[CopilotSession]]:
    """
    Group sessions by an attribute.

    Parameters
    ----------
    sessions : list of CopilotSession objects.
    group_by : "provider" (default) | "model" | "investigationId" |
               "sessionId".  Keyed by str(attribute value).
               Each group is sorted by sessionId ASC for determinism.

    Returns
    -------
    Dict[str, List[CopilotSession]] — each group sorted deterministically.
    """
    _VALID = {"provider", "model", "investigationId", "sessionId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_sessions: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )
    groups: Dict[str, List[CopilotSession]] = {}
    for s in sessions:
        if group_by == "provider":
            key = s.request.provider
        elif group_by == "model":
            key = s.request.model
        elif group_by == "investigationId":
            key = s.request.investigationId
        else:
            key = s.sessionId
        groups.setdefault(key, []).append(s)

    # Sort each group by sessionId ASC for determinism
    return {k: sorted(v, key=lambda x: x.sessionId) for k, v in groups.items()}


# ===========================================================================
# Statistics model + utility: calculate_session_statistics()
# ===========================================================================

class SessionStatistics(BaseModel):
    """
    Aggregate statistics over a list of CopilotSession objects.

    Fields
    ------
    totalSessions           : total count.
    averageConfidence       : mean response.confidence (0.0 when empty).
    averagePromptTokens     : mean promptTokenEstimate (0.0 when empty).
    averageResponseTokens   : mean responseTokenEstimate (0.0 when empty).
    uniqueProviders         : sorted tuple of distinct provider names.
    uniqueModels            : sorted tuple of distinct model names.
    uniqueInvestigationIds  : sorted tuple of distinct investigationIds.
    sessionsWithCitations   : count of sessions that have ≥ 1 citation.
    sessionsWithWarnings    : count of sessions that have ≥ 1 warning.
    """
    totalSessions          : int
    averageConfidence      : float
    averagePromptTokens    : float
    averageResponseTokens  : float
    uniqueProviders        : Tuple[str, ...]
    uniqueModels           : Tuple[str, ...]
    uniqueInvestigationIds : Tuple[str, ...]
    sessionsWithCitations  : int
    sessionsWithWarnings   : int

    class Config:
        frozen = True


def calculate_session_statistics(
    sessions: List[CopilotSession],
) -> SessionStatistics:
    """
    Compute SessionStatistics over a list of CopilotSessions.

    Deterministic: canonical sort (by sessionId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    sessions : any list of CopilotSession objects.

    Returns
    -------
    SessionStatistics (frozen / immutable)
    """
    if not sessions:
        return SessionStatistics(
            totalSessions          = 0,
            averageConfidence      = 0.0,
            averagePromptTokens    = 0.0,
            averageResponseTokens  = 0.0,
            uniqueProviders        = (),
            uniqueModels           = (),
            uniqueInvestigationIds = (),
            sessionsWithCitations  = 0,
            sessionsWithWarnings   = 0,
        )

    # Canonical order for accumulation
    ordered = sorted(sessions, key=lambda s: s.sessionId)
    n = len(ordered)

    conf_sum          = sum(s.response.confidence                      for s in ordered)
    prompt_tok_sum    = sum(s.metadata.promptTokenEstimate             for s in ordered)
    resp_tok_sum      = sum(s.metadata.responseTokenEstimate           for s in ordered)
    providers         = tuple(sorted({s.request.provider              for s in ordered}))
    models            = tuple(sorted({s.request.model                 for s in ordered}))
    inv_ids           = tuple(sorted({s.request.investigationId       for s in ordered}))
    with_citations    = sum(1 for s in ordered if s.response.citations)
    with_warnings     = sum(1 for s in ordered if s.metadata.warnings)

    return SessionStatistics(
        totalSessions          = n,
        averageConfidence      = round(conf_sum       / n, 4),
        averagePromptTokens    = round(prompt_tok_sum / n, 4),
        averageResponseTokens  = round(resp_tok_sum   / n, 4),
        uniqueProviders        = providers,
        uniqueModels           = models,
        uniqueInvestigationIds = inv_ids,
        sessionsWithCitations  = with_citations,
        sessionsWithWarnings   = with_warnings,
    )


# ===========================================================================
# Utility: find_session()
# ===========================================================================

def find_session(
    sessions   : List[CopilotSession],
    session_id : Optional[str] = None,
    request_id : Optional[str] = None,
    response_id: Optional[str] = None,
) -> Optional[CopilotSession]:
    """
    Return the first session matching the supplied lookup criterion.

    Priority order: session_id > request_id > response_id.
    Returns None if nothing matches or no criterion is supplied.

    Parameters
    ----------
    sessions    : list to search.
    session_id  : exact CopilotSession.sessionId to find.
    request_id  : exact CopilotRequest.requestId to find.
    response_id : exact CopilotResponse.responseId to find.

    Returns
    -------
    CopilotSession or None.
    """
    if session_id is not None:
        needle = session_id.strip()
        for s in sessions:
            if s.sessionId == needle:
                return s
        return None

    if request_id is not None:
        needle = request_id.strip()
        for s in sessions:
            if s.request.requestId == needle:
                return s
        return None

    if response_id is not None:
        needle = response_id.strip()
        for s in sessions:
            if s.response.responseId == needle:
                return s
        return None

    return None
