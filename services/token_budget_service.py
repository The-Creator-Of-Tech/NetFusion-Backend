"""
Token Budget Manager Engine
============================
Phase A4.5.2 — Deterministic, immutable token budget calculation, allocation,
and validation for AI request execution in NetFusion.

Responsibilities
----------------
- Calculate and validate token budgets before an AI request is executed.
- Allocate tokens across conversation, memory, reasoning, context, and prompts.
- Produce deterministic BudgetReport and BudgetStatistics objects.
- Provide integration helpers for context_window_service, ai_execution_service,
  and groq_provider_service.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.

Out of scope in this module
----------------------------
- Provider HTTP calls.
- Prompt generation.
- Context retrieval.
- Retry logic.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import TOKEN_BUDGET_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("token_budget_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_BUDGET_NS = uuid.UUID("6ba7b834-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations (immutable)
# ===========================================================================

class ProviderTypeEnum(str, Enum):
    """AI provider type."""
    GROQ      = "GROQ"
    OPENAI    = "OPENAI"
    ANTHROPIC = "ANTHROPIC"
    GOOGLE    = "GOOGLE"
    OLLAMA    = "OLLAMA"
    CUSTOM    = "CUSTOM"


class BudgetStateEnum(str, Enum):
    """Budget health state."""
    VALID    = "VALID"
    WARNING  = "WARNING"
    EXCEEDED = "EXCEEDED"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class TokenBudgetError(Exception):
    """Base class for all Token Budget Engine errors."""


class InvalidBudgetError(TokenBudgetError):
    """Raised when a TokenBudget fails validation."""


class InvalidAllocationError(TokenBudgetError):
    """Raised when a BudgetAllocation fails validation."""


class InvalidBudgetReportError(TokenBudgetError):
    """Raised when a BudgetReport fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class TokenBudget(BaseModel):
    """
    One immutable token budget for a single AI request slot.

    Identity
    --------
    budgetId  : UUIDv5(_BUDGET_NS, budgetKey) — deterministic.
    budgetKey : SHA256(provider + model + str(maxTokens) +
                       str(reservedOutputTokens))[:32]

    Fields
    ------
    budgetId              : deterministic UUID.
    budgetKey             : 32-char SHA-256 key.
    provider              : ProviderTypeEnum — the AI provider.
    model                 : canonical model name string.
    maxTokens             : total token limit for the model context window.
    reservedOutputTokens  : tokens reserved for model completion output.
    availableContextTokens: maxTokens minus reservedOutputTokens.
    usedContextTokens     : tokens already consumed by context/prompts.
    remainingTokens       : availableContextTokens minus usedContextTokens.
    state                 : BudgetStateEnum — VALID / WARNING / EXCEEDED.
    createdAt             : ISO-8601 timestamp (caller-supplied).
    """
    budgetId               : str
    budgetKey              : str
    provider               : ProviderTypeEnum
    model                  : str
    maxTokens              : int
    reservedOutputTokens   : int
    availableContextTokens : int
    usedContextTokens      : int
    remainingTokens        : int
    state                  : BudgetStateEnum
    createdAt              : str

    class Config:
        frozen = True


class BudgetAllocation(BaseModel):
    """
    One immutable token allocation breakdown for a single AI request.

    Identity
    --------
    allocationId  : UUIDv5(_BUDGET_NS, allocationKey) — deterministic.
    allocationKey : SHA256(budgetId + str(conversationTokens) +
                           str(memoryTokens) + str(reasoningTokens) +
                           str(contextTokens) + str(systemPromptTokens) +
                           str(userPromptTokens))[:32]

    Fields
    ------
    allocationId       : deterministic UUID.
    allocationKey      : 32-char SHA-256 key.
    conversationTokens : tokens allocated for conversation history.
    memoryTokens       : tokens allocated for session memory.
    reasoningTokens    : tokens allocated for reasoning context.
    contextTokens      : tokens allocated for investigation context items.
    systemPromptTokens : tokens allocated for the system prompt.
    userPromptTokens   : tokens allocated for the user prompt.
    totalAllocatedTokens: sum of all allocation buckets.
    createdAt          : ISO-8601 timestamp (caller-supplied).
    """
    allocationId         : str
    allocationKey        : str
    conversationTokens   : int
    memoryTokens         : int
    reasoningTokens      : int
    contextTokens        : int
    systemPromptTokens   : int
    userPromptTokens     : int
    totalAllocatedTokens : int
    createdAt            : str

    class Config:
        frozen = True


class BudgetReport(BaseModel):
    """
    One immutable budget report pairing a TokenBudget with its allocation.

    Identity
    --------
    reportId          : UUIDv5(_BUDGET_NS, reportKey) — deterministic.
    reportKey         : SHA256(budget.budgetKey + allocation.allocationKey)[:32]
    reportFingerprint : SHA256(reportKey + str(utilizationPercent) +
                               str(overflowDetected))[:32]

    Fields
    ------
    reportId           : deterministic UUID.
    reportKey          : 32-char SHA-256 key.
    budget             : TokenBudget — the budget being reported on.
    allocation         : BudgetAllocation — how tokens were allocated.
    utilizationPercent : totalAllocatedTokens / availableContextTokens * 100,
                         rounded to 4 decimal places. Clamped to [0.0, inf).
    overflowDetected   : True when totalAllocatedTokens > availableContextTokens.
    reportFingerprint  : deterministic content fingerprint (32-char hex).
    createdAt          : ISO-8601 timestamp (caller-supplied).
    """
    reportId          : str
    reportKey         : str
    budget            : TokenBudget
    allocation        : BudgetAllocation
    utilizationPercent: float
    overflowDetected  : bool
    reportFingerprint : str
    createdAt         : str

    class Config:
        frozen = True


class BudgetStatistics(BaseModel):
    """
    Aggregate statistics over a collection of BudgetReport objects.

    Fields
    ------
    totalBudgets         : total number of budgets (reports) counted.
    validBudgets         : count of reports where budget.state == VALID.
    warningBudgets       : count of reports where budget.state == WARNING.
    exceededBudgets      : count of reports where budget.state == EXCEEDED.
    averageUtilization   : mean utilizationPercent across all reports.
    averageRemainingTokens: mean remainingTokens across all TokenBudgets.
    """
    totalBudgets          : int
    validBudgets          : int
    warningBudgets        : int
    exceededBudgets       : int
    averageUtilization    : float
    averageRemainingTokens: float

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
    """UUIDv5(_BUDGET_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_BUDGET_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _clamp_int(v: int, lo: int) -> int:
    """Clamp an integer to [lo, +inf)."""
    return max(lo, int(v))


# ---------------------------------------------------------------------------
# Key derivation functions
# ---------------------------------------------------------------------------

def _compute_budget_key(
    provider             : str,
    model                : str,
    max_tokens           : int,
    reserved_output_tokens: int,
) -> str:
    """
    budgetKey = SHA256(provider + model + str(maxTokens) +
                       str(reservedOutputTokens))[:32]
    """
    return _sha256_32(
        provider.upper().strip(),
        model.strip(),
        str(int(max_tokens)),
        str(int(reserved_output_tokens)),
    )


def _compute_allocation_key(
    budget_id           : str,
    conversation_tokens : int,
    memory_tokens       : int,
    reasoning_tokens    : int,
    context_tokens      : int,
    system_prompt_tokens: int,
    user_prompt_tokens  : int,
) -> str:
    """
    allocationKey = SHA256(budgetId + all bucket token counts)[:32]
    """
    return _sha256_32(
        budget_id,
        str(int(conversation_tokens)),
        str(int(memory_tokens)),
        str(int(reasoning_tokens)),
        str(int(context_tokens)),
        str(int(system_prompt_tokens)),
        str(int(user_prompt_tokens)),
    )


def _compute_report_key(
    budget_key    : str,
    allocation_key: str,
) -> str:
    """reportKey = SHA256(budgetKey + allocationKey)[:32]"""
    return _sha256_32(budget_key, allocation_key)


def _compute_report_fingerprint(
    report_key         : str,
    utilization_percent: float,
    overflow_detected  : bool,
) -> str:
    """
    reportFingerprint = SHA256(reportKey + str(utilizationPercent) +
                               str(overflowDetected))[:32]
    """
    return _sha256_32(
        report_key,
        str(round(utilization_percent, 4)),
        str(bool(overflow_detected)),
    )


# ---------------------------------------------------------------------------
# Budget state determination
# ---------------------------------------------------------------------------

# WARNING threshold: 80 % utilisation (allocation / available context >= 0.80)
_WARNING_THRESHOLD: float = 0.80


def _determine_budget_state(
    available_context_tokens: int,
    used_context_tokens     : int,
) -> BudgetStateEnum:
    """
    Determine BudgetStateEnum from token counts.

    Rules
    -----
    - usedContextTokens > availableContextTokens → EXCEEDED
    - usedContextTokens / availableContextTokens >= 0.80 → WARNING
    - Otherwise → VALID
    """
    if available_context_tokens <= 0:
        return BudgetStateEnum.EXCEEDED if used_context_tokens > 0 else BudgetStateEnum.VALID
    if used_context_tokens >= available_context_tokens:
        return BudgetStateEnum.EXCEEDED
    utilization = used_context_tokens / available_context_tokens
    if utilization >= _WARNING_THRESHOLD:
        return BudgetStateEnum.WARNING
    return BudgetStateEnum.VALID


# ===========================================================================
# Validation
# ===========================================================================

def validate_budget(
    provider             : ProviderTypeEnum,
    model                : str,
    max_tokens           : int,
    reserved_output_tokens: int,
    used_context_tokens  : int,
    created_at           : str,
) -> None:
    """
    Validate TokenBudget construction parameters.

    Checks
    ------
    - provider is a valid ProviderTypeEnum member.
    - model is non-empty.
    - maxTokens >= 1.
    - reservedOutputTokens >= 0.
    - reservedOutputTokens < maxTokens.
    - usedContextTokens >= 0.
    - createdAt is non-empty.

    Raises
    ------
    InvalidBudgetError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(provider, ProviderTypeEnum):
        errors.append(
            f"provider must be a ProviderTypeEnum member; got {provider!r}."
        )
    if not model or not model.strip():
        errors.append("model must not be empty.")
    if max_tokens < 1:
        errors.append(f"maxTokens={max_tokens} must be >= 1.")
    if reserved_output_tokens < 0:
        errors.append(
            f"reservedOutputTokens={reserved_output_tokens} must be >= 0."
        )
    if max_tokens >= 1 and reserved_output_tokens >= max_tokens:
        errors.append(
            f"reservedOutputTokens={reserved_output_tokens} must be "
            f"< maxTokens={max_tokens}."
        )
    if used_context_tokens < 0:
        errors.append(
            f"usedContextTokens={used_context_tokens} must be >= 0."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_budget", "errors": errors},
        )
        raise InvalidBudgetError(
            "TokenBudget validation failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_allocation(
    budget_id           : str,
    conversation_tokens : int,
    memory_tokens       : int,
    reasoning_tokens    : int,
    context_tokens      : int,
    system_prompt_tokens: int,
    user_prompt_tokens  : int,
    created_at          : str,
) -> None:
    """
    Validate BudgetAllocation construction parameters.

    Checks
    ------
    - budgetId is non-empty.
    - All token bucket values are >= 0.
    - createdAt is non-empty.

    Raises
    ------
    InvalidAllocationError : if any rule is violated.
    """
    errors: List[str] = []

    if not budget_id or not budget_id.strip():
        errors.append("budgetId must not be empty.")

    buckets = {
        "conversationTokens"  : conversation_tokens,
        "memoryTokens"        : memory_tokens,
        "reasoningTokens"     : reasoning_tokens,
        "contextTokens"       : context_tokens,
        "systemPromptTokens"  : system_prompt_tokens,
        "userPromptTokens"    : user_prompt_tokens,
    }
    for name, val in buckets.items():
        if not isinstance(val, int) or val < 0:
            errors.append(f"{name}={val!r} must be an integer >= 0.")

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_allocation", "errors": errors},
        )
        raise InvalidAllocationError(
            "BudgetAllocation validation failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_report(
    budget    : TokenBudget,
    allocation: BudgetAllocation,
    created_at: str,
) -> None:
    """
    Validate BudgetReport construction parameters.

    Checks
    ------
    - budget is a TokenBudget instance.
    - allocation is a BudgetAllocation instance.
    - createdAt is non-empty.

    Raises
    ------
    InvalidBudgetReportError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(budget, TokenBudget):
        errors.append(
            f"budget must be a TokenBudget instance; got {type(budget)!r}."
        )
    if not isinstance(allocation, BudgetAllocation):
        errors.append(
            f"allocation must be a BudgetAllocation instance; got {type(allocation)!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_report", "errors": errors},
        )
        raise InvalidBudgetReportError(
            "BudgetReport validation failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_token_budget()
# ===========================================================================

def build_token_budget(
    provider              : ProviderTypeEnum,
    model                 : str,
    max_tokens            : int,
    created_at            : str,
    reserved_output_tokens: int   = 512,
    used_context_tokens   : int   = 0,
    validate              : bool  = True,
) -> TokenBudget:
    """
    Build an immutable TokenBudget.

    budgetKey = SHA256(provider + model + str(maxTokens) +
                       str(reservedOutputTokens))[:32]
    budgetId  = UUIDv5(_BUDGET_NS, budgetKey)

    Parameters
    ----------
    provider               : ProviderTypeEnum — the AI provider.
    model                  : canonical model name (non-empty).
    max_tokens             : total token limit for the model context window (>= 1).
    created_at             : ISO-8601 timestamp (caller-supplied for determinism).
    reserved_output_tokens : tokens reserved for completion output (>= 0,
                             < max_tokens). Defaults to 512.
    used_context_tokens    : tokens already consumed (>= 0). Defaults to 0.
    validate               : if True, run validate_budget() first.

    Returns
    -------
    TokenBudget (frozen / immutable)

    Raises
    ------
    InvalidBudgetError : if validate=True and validation fails.
    """
    clamped_reserved = _clamp_int(reserved_output_tokens, 0)
    clamped_used     = _clamp_int(used_context_tokens, 0)

    if validate:
        validate_budget(
            provider, model, max_tokens,
            clamped_reserved, clamped_used, created_at,
        )

    available = max(0, int(max_tokens) - clamped_reserved)
    remaining = max(0, available - clamped_used)
    state     = _determine_budget_state(available, clamped_used)

    budget_key = _compute_budget_key(
        provider.value, model, max_tokens, clamped_reserved,
    )
    budget_id = _uuid5(budget_key)

    _log.info(
        "budget_created",
        extra={
            "budgetId"               : budget_id,
            "provider"               : provider.value,
            "model"                  : model.strip(),
            "maxTokens"              : int(max_tokens),
            "reservedOutputTokens"   : clamped_reserved,
            "availableContextTokens" : available,
            "usedContextTokens"      : clamped_used,
            "remainingTokens"        : remaining,
            "state"                  : state.value,
        },
    )

    if state == BudgetStateEnum.EXCEEDED:
        _log.warning(
            "budget_exceeded",
            extra={
                "budgetId"        : budget_id,
                "provider"        : provider.value,
                "model"           : model.strip(),
                "usedContextTokens": clamped_used,
                "availableContextTokens": available,
            },
        )

    return TokenBudget(
        budgetId               = budget_id,
        budgetKey              = budget_key,
        provider               = provider,
        model                  = model.strip(),
        maxTokens              = int(max_tokens),
        reservedOutputTokens   = clamped_reserved,
        availableContextTokens = available,
        usedContextTokens      = clamped_used,
        remainingTokens        = remaining,
        state                  = state,
        createdAt              = created_at,
    )


# ===========================================================================
# Builder: build_budget_allocation()
# ===========================================================================

def build_budget_allocation(
    budget              : TokenBudget,
    created_at          : str,
    conversation_tokens : int = 0,
    memory_tokens       : int = 0,
    reasoning_tokens    : int = 0,
    context_tokens      : int = 0,
    system_prompt_tokens: int = 0,
    user_prompt_tokens  : int = 0,
    validate            : bool = True,
) -> BudgetAllocation:
    """
    Build an immutable BudgetAllocation for a given TokenBudget.

    allocationKey = SHA256(budgetId + all bucket token counts)[:32]
    allocationId  = UUIDv5(_BUDGET_NS, allocationKey)

    Parameters
    ----------
    budget               : TokenBudget — the owning budget.
    created_at           : ISO-8601 timestamp (caller-supplied).
    conversation_tokens  : tokens for conversation history (>= 0).
    memory_tokens        : tokens for session memory (>= 0).
    reasoning_tokens     : tokens for reasoning context (>= 0).
    context_tokens       : tokens for investigation context items (>= 0).
    system_prompt_tokens : tokens for the system prompt (>= 0).
    user_prompt_tokens   : tokens for the user prompt (>= 0).
    validate             : if True, run validate_allocation() first.

    Returns
    -------
    BudgetAllocation (frozen / immutable)

    Raises
    ------
    InvalidAllocationError : if validate=True and validation fails.
    """
    c_tok  = _clamp_int(conversation_tokens,  0)
    m_tok  = _clamp_int(memory_tokens,        0)
    r_tok  = _clamp_int(reasoning_tokens,     0)
    ctx_tok= _clamp_int(context_tokens,       0)
    sp_tok = _clamp_int(system_prompt_tokens, 0)
    up_tok = _clamp_int(user_prompt_tokens,   0)

    if validate:
        validate_allocation(
            budget.budgetId,
            c_tok, m_tok, r_tok, ctx_tok, sp_tok, up_tok,
            created_at,
        )

    total = c_tok + m_tok + r_tok + ctx_tok + sp_tok + up_tok

    alloc_key = _compute_allocation_key(
        budget.budgetId,
        c_tok, m_tok, r_tok, ctx_tok, sp_tok, up_tok,
    )
    alloc_id = _uuid5(alloc_key)

    return BudgetAllocation(
        allocationId         = alloc_id,
        allocationKey        = alloc_key,
        conversationTokens   = c_tok,
        memoryTokens         = m_tok,
        reasoningTokens      = r_tok,
        contextTokens        = ctx_tok,
        systemPromptTokens   = sp_tok,
        userPromptTokens     = up_tok,
        totalAllocatedTokens = total,
        createdAt            = created_at,
    )


# ===========================================================================
# Builder: build_budget_report()
# ===========================================================================

def build_budget_report(
    budget    : TokenBudget,
    allocation: BudgetAllocation,
    created_at: str,
    validate  : bool = True,
) -> BudgetReport:
    """
    Build an immutable BudgetReport pairing a TokenBudget and BudgetAllocation.

    reportKey         = SHA256(budgetKey + allocationKey)[:32]
    reportId          = UUIDv5(_BUDGET_NS, reportKey)
    reportFingerprint = SHA256(reportKey + str(utilizationPercent) +
                               str(overflowDetected))[:32]

    utilizationPercent = (totalAllocatedTokens / availableContextTokens) * 100
                         rounded to 4 decimal places. 0.0 when
                         availableContextTokens == 0.
    overflowDetected   = totalAllocatedTokens > availableContextTokens

    Parameters
    ----------
    budget     : TokenBudget — the budget being reported on.
    allocation : BudgetAllocation — how tokens were allocated.
    created_at : ISO-8601 timestamp (caller-supplied).
    validate   : if True, run validate_report() first.

    Returns
    -------
    BudgetReport (frozen / immutable)

    Raises
    ------
    InvalidBudgetReportError : if validate=True and validation fails.
    """
    if validate:
        validate_report(budget, allocation, created_at)

    available = budget.availableContextTokens
    total_alloc = allocation.totalAllocatedTokens

    if available > 0:
        util_pct = round((total_alloc / available) * 100.0, 4)
    else:
        util_pct = 0.0

    overflow = total_alloc > available

    report_key = _compute_report_key(budget.budgetKey, allocation.allocationKey)
    report_id  = _uuid5(report_key)
    report_fp  = _compute_report_fingerprint(report_key, util_pct, overflow)

    return BudgetReport(
        reportId          = report_id,
        reportKey         = report_key,
        budget            = budget,
        allocation        = allocation,
        utilizationPercent= util_pct,
        overflowDetected  = overflow,
        reportFingerprint = report_fp,
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_budget_statistics()
# ===========================================================================

def build_budget_statistics(
    reports: List[BudgetReport],
) -> BudgetStatistics:
    """
    Compute BudgetStatistics over a list of BudgetReport objects.

    Uses the new Budget Operations for calculation consistency:
    - State counts derived from group_reports(by="state").
    - averageUtilization uses calculate_utilization() semantics.
    - averageRemainingTokens uses calculate_remaining_tokens() semantics.

    Deterministic: canonical sort (by reportId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    reports : any list of BudgetReport objects.

    Returns
    -------
    BudgetStatistics (frozen / immutable)
    """
    if not reports:
        return BudgetStatistics(
            totalBudgets          = 0,
            validBudgets          = 0,
            warningBudgets        = 0,
            exceededBudgets       = 0,
            averageUtilization    = 0.0,
            averageRemainingTokens= 0.0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(reports, key=lambda r: r.reportId)
    n = len(ordered)

    # Use group_reports to count state buckets (consistent with the utility)
    state_groups: Dict[str, List[BudgetReport]] = {}
    for report in ordered:
        k = report.budget.state.value
        state_groups.setdefault(k, []).append(report)

    valid_count    = len(state_groups.get(BudgetStateEnum.VALID.value,    []))
    warning_count  = len(state_groups.get(BudgetStateEnum.WARNING.value,  []))
    exceeded_count = len(state_groups.get(BudgetStateEnum.EXCEEDED.value, []))

    # Accumulate using calculation helpers for consistency
    util_sum      = 0.0
    remaining_sum = 0
    for report in ordered:
        util_sum += report.utilizationPercent
        remaining_sum += calculate_remaining_tokens(
            report.budget.availableContextTokens,
            report.budget.usedContextTokens,
        )

    _log.info(
        "budget_statistics_built",
        extra={
            "totalBudgets"  : n,
            "validBudgets"  : valid_count,
            "warningBudgets": warning_count,
            "exceededBudgets": exceeded_count,
        },
    )

    return BudgetStatistics(
        totalBudgets          = n,
        validBudgets          = valid_count,
        warningBudgets        = warning_count,
        exceededBudgets       = exceeded_count,
        averageUtilization    = round(util_sum / n, 4),
        averageRemainingTokens= round(remaining_sum / n, 4),
    )


# ===========================================================================
# Integration helpers
# ===========================================================================

def budget_from_execution_request(
    execution_request: Any,
    provider         : ProviderTypeEnum,
    created_at       : str,
    max_tokens       : int = 8192,
) -> TokenBudget:
    """
    Derive a TokenBudget from an AIExecutionRequest object.

    Uses execution_request.maxTokens as reservedOutputTokens and
    the caller-supplied max_tokens as the context window ceiling.

    Parameters
    ----------
    execution_request : AIExecutionRequest from ai_execution_service.
    provider          : ProviderTypeEnum for the request.
    created_at        : ISO-8601 timestamp.
    max_tokens        : total model context window size.

    Returns
    -------
    TokenBudget (frozen / immutable)
    """
    reserved = getattr(execution_request, "maxTokens", 512)
    model    = getattr(execution_request, "model", "unknown")

    sys_tokens  = _estimate_tokens_from_text(
        getattr(execution_request, "systemPrompt", "")
    )
    user_tokens = _estimate_tokens_from_text(
        getattr(execution_request, "userPrompt", "")
    )
    used = sys_tokens + user_tokens

    return build_token_budget(
        provider               = provider,
        model                  = model,
        max_tokens             = max_tokens,
        created_at             = created_at,
        reserved_output_tokens = reserved,
        used_context_tokens    = used,
        validate               = True,
    )


def allocation_from_context_window(
    budget        : TokenBudget,
    context_window: Any,
    created_at    : str,
    system_prompt : str = "",
    user_prompt   : str = "",
) -> BudgetAllocation:
    """
    Build a BudgetAllocation from a ContextWindow object.

    Distributes token estimates from the context window items into their
    respective allocation buckets based on ContextSourceEnum.

    Bucket mapping
    --------------
    CONVERSATION / USER_INPUT → conversationTokens + userPromptTokens
    MEMORY                    → memoryTokens
    REASONING                 → reasoningTokens
    All others                → contextTokens
    systemPrompt text         → systemPromptTokens

    Parameters
    ----------
    budget         : TokenBudget — the owning budget.
    context_window : ContextWindow from context_window_service.
    created_at     : ISO-8601 timestamp.
    system_prompt  : system prompt text for token estimation.
    user_prompt    : user prompt text for token estimation.

    Returns
    -------
    BudgetAllocation (frozen / immutable)
    """
    conversation_tokens  = 0
    memory_tokens        = 0
    reasoning_tokens     = 0
    context_tokens       = 0
    user_prompt_tokens_w = 0

    items = getattr(context_window, "items", ())
    for item in items:
        source_val = item.source.value if hasattr(item.source, "value") else str(item.source)
        tok = getattr(item, "tokenEstimate", 0)
        if source_val in ("CONVERSATION",):
            conversation_tokens += tok
        elif source_val in ("USER_INPUT",):
            user_prompt_tokens_w += tok
        elif source_val == "MEMORY":
            memory_tokens += tok
        elif source_val == "REASONING":
            reasoning_tokens += tok
        else:
            context_tokens += tok

    sys_tok  = _estimate_tokens_from_text(system_prompt)
    user_tok = _estimate_tokens_from_text(user_prompt) + user_prompt_tokens_w

    return build_budget_allocation(
        budget               = budget,
        created_at           = created_at,
        conversation_tokens  = conversation_tokens,
        memory_tokens        = memory_tokens,
        reasoning_tokens     = reasoning_tokens,
        context_tokens       = context_tokens,
        system_prompt_tokens = sys_tok,
        user_prompt_tokens   = user_tok,
        validate             = True,
    )


def budget_fits(budget: TokenBudget, allocation: BudgetAllocation) -> bool:
    """
    Return True if the allocation fits within the budget without overflow.

    Equivalent to: allocation.totalAllocatedTokens <= budget.availableContextTokens
    """
    return allocation.totalAllocatedTokens <= budget.availableContextTokens


def groq_model_budget(
    model     : str,
    created_at: str,
    reserved_output_tokens: int = 512,
    used_context_tokens   : int = 0,
) -> TokenBudget:
    """
    Convenience builder: create a TokenBudget for a known Groq model.

    Looks up maxTokens from GROQ_MODEL_CAPABILITIES in constants.
    Falls back to 8192 for unknown models.

    Parameters
    ----------
    model                  : Groq model name (canonical or alias).
    created_at             : ISO-8601 timestamp.
    reserved_output_tokens : tokens reserved for output.
    used_context_tokens    : tokens already used.

    Returns
    -------
    TokenBudget (frozen / immutable)
    """
    from core.constants import GROQ_MODEL_CAPABILITIES, GROQ_MODEL_ALIASES

    norm = model.strip().lower()
    if norm in GROQ_MODEL_ALIASES:
        norm = GROQ_MODEL_ALIASES[norm]

    caps = GROQ_MODEL_CAPABILITIES.get(norm, {})
    max_tok = caps.get("maxTokens", 8192)

    return build_token_budget(
        provider               = ProviderTypeEnum.GROQ,
        model                  = norm,
        max_tokens             = max_tok,
        created_at             = created_at,
        reserved_output_tokens = reserved_output_tokens,
        used_context_tokens    = used_context_tokens,
        validate               = True,
    )


# ===========================================================================
# Internal utility
# ===========================================================================

def _estimate_tokens_from_text(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // 4))


# ===========================================================================
# Provider / model token limits (constants only — no HTTP)
# ===========================================================================

# Default context window sizes per provider (conservative, well-known values).
# All values from public documentation; never derived at runtime.
_PROVIDER_LIMITS: Dict[str, int] = {
    "GROQ"      : 131072,   # Groq API hard ceiling (llama models)
    "OPENAI"    : 128000,   # GPT-4o / GPT-4-turbo
    "ANTHROPIC" : 200000,   # Claude 3 family
    "GOOGLE"    : 1000000,  # Gemini 1.5 Pro
    "OLLAMA"    : 8192,     # conservative local default
    "CUSTOM"    : 8192,     # conservative custom default
}

# Per-model limits.  Key = canonical lowercase model name.
# Sourced from public API documentation; update via constants only.
_MODEL_LIMITS: Dict[str, int] = {
    # Groq
    "llama-3.3-70b-versatile"  : 128000,
    "llama-3.1-8b-instant"     : 128000,
    "openai/gpt-oss-120b"      : 8192,
    # OpenAI
    "gpt-4o"                   : 128000,
    "gpt-4o-mini"              : 128000,
    "gpt-4-turbo"              : 128000,
    "gpt-4"                    : 8192,
    "gpt-3.5-turbo"            : 16385,
    # Anthropic
    "claude-3-opus-20240229"   : 200000,
    "claude-3-sonnet-20240229" : 200000,
    "claude-3-haiku-20240307"  : 200000,
    "claude-3-5-sonnet-20241022": 200000,
    # Google
    "gemini-1.5-pro"           : 1000000,
    "gemini-1.5-flash"         : 1000000,
    "gemini-1.0-pro"           : 32760,
    # Ollama defaults
    "llama3"                   : 8192,
    "mistral"                  : 8192,
    "mixtral"                  : 32768,
    "phi3"                     : 4096,
    "codellama"                : 16384,
}

# Compression threshold: recommend context compression above this utilization.
_COMPRESSION_THRESHOLD: float = 0.70   # 70 %

# Truncation threshold: recommend truncation above this utilization.
_TRUNCATION_THRESHOLD: float = 0.90    # 90 %


def get_provider_limit(provider: ProviderTypeEnum) -> int:
    """
    Return the default maximum context window size (tokens) for a provider.

    Uses _PROVIDER_LIMITS — no HTTP, no runtime lookups.

    Parameters
    ----------
    provider : ProviderTypeEnum

    Returns
    -------
    int — token limit for the provider.
    """
    return _PROVIDER_LIMITS.get(provider.value, 8192)


def get_model_limit(model: str, provider: ProviderTypeEnum = ProviderTypeEnum.CUSTOM) -> int:
    """
    Return the maximum context window size (tokens) for a specific model.

    Lookup order:
    1. _MODEL_LIMITS[model.strip().lower()]
    2. GROQ_MODEL_CAPABILITIES (for Groq models) via constants
    3. get_provider_limit(provider) as fallback

    Parameters
    ----------
    model    : canonical model name string.
    provider : ProviderTypeEnum used as fallback when model is unknown.

    Returns
    -------
    int — token limit for the model.
    """
    norm = model.strip().lower() if model else ""

    # Direct lookup in our static table
    if norm in _MODEL_LIMITS:
        return _MODEL_LIMITS[norm]

    # Try GROQ_MODEL_CAPABILITIES for Groq provider
    if provider == ProviderTypeEnum.GROQ:
        from core.constants import GROQ_MODEL_CAPABILITIES, GROQ_MODEL_ALIASES
        resolved = GROQ_MODEL_ALIASES.get(norm, norm)
        caps = GROQ_MODEL_CAPABILITIES.get(resolved, {})
        if "maxTokens" in caps:
            return caps["maxTokens"]

    return get_provider_limit(provider)


# ===========================================================================
# Budget Operations — Calculations
# ===========================================================================

def calculate_available_tokens(
    max_tokens            : int,
    reserved_output_tokens: int,
) -> int:
    """
    Calculate available context tokens.

    available = max(0, maxTokens - reservedOutputTokens)

    Parameters
    ----------
    max_tokens             : total model context window size.
    reserved_output_tokens : tokens reserved for completion output.

    Returns
    -------
    int — available context tokens (>= 0).
    """
    return max(0, int(max_tokens) - max(0, int(reserved_output_tokens)))


def calculate_remaining_tokens(
    available_context_tokens: int,
    used_context_tokens     : int,
) -> int:
    """
    Calculate remaining context tokens.

    remaining = max(0, availableContextTokens - usedContextTokens)

    Parameters
    ----------
    available_context_tokens : tokens available for context.
    used_context_tokens      : tokens already consumed.

    Returns
    -------
    int — remaining tokens (>= 0, never negative).
    """
    return max(0, int(available_context_tokens) - max(0, int(used_context_tokens)))


def calculate_utilization(
    available_context_tokens: int,
    used_context_tokens     : int,
) -> float:
    """
    Calculate context utilization as a fraction in [0.0, +inf).

    utilization = usedContextTokens / availableContextTokens
                  Returns 0.0 when availableContextTokens == 0.

    Parameters
    ----------
    available_context_tokens : tokens available for context.
    used_context_tokens      : tokens already consumed.

    Returns
    -------
    float — utilization fraction, rounded to 6 decimal places.
    """
    if available_context_tokens <= 0:
        return 0.0
    return round(
        max(0, int(used_context_tokens)) / int(available_context_tokens),
        6,
    )


# ===========================================================================
# Budget Operations — Reserve / Release
# ===========================================================================

def reserve_output_tokens(
    budget              : TokenBudget,
    additional_reserved : int,
    created_at          : str,
) -> TokenBudget:
    """
    Return a new TokenBudget with additionalReserved tokens added to
    reservedOutputTokens.

    Since TokenBudget is immutable, this creates a NEW budget object with:
        newReserved  = reservedOutputTokens + additionalReserved
        newAvailable = max(0, maxTokens - newReserved)
        newRemaining = max(0, newAvailable - usedContextTokens)
        newState     = re-evaluated from newAvailable / usedContextTokens

    If newReserved >= maxTokens the budget is clamped so that newReserved
    = maxTokens - 1 (minimum 1 token must remain available).

    Parameters
    ----------
    budget              : existing TokenBudget (not mutated).
    additional_reserved : extra tokens to reserve (>= 0).
    created_at          : ISO-8601 timestamp for the new budget object.

    Returns
    -------
    TokenBudget (frozen / immutable) — NEW object.

    Raises
    ------
    InvalidBudgetError : if additional_reserved < 0.
    """
    add = int(additional_reserved)
    if add < 0:
        raise InvalidBudgetError(
            f"additional_reserved={add} must be >= 0."
        )

    new_reserved = budget.reservedOutputTokens + add
    # Clamp: keep at least 1 token available
    max_allowed_reserved = max(0, budget.maxTokens - 1)
    new_reserved = min(new_reserved, max_allowed_reserved)

    new_available = max(0, budget.maxTokens - new_reserved)
    new_remaining = max(0, new_available - budget.usedContextTokens)
    new_state     = _determine_budget_state(new_available, budget.usedContextTokens)

    # Recompute deterministic key with new reserved value
    new_key = _compute_budget_key(
        budget.provider.value, budget.model,
        budget.maxTokens, new_reserved,
    )
    new_id = _uuid5(new_key)

    _log.info(
        "budget_reserve_output_tokens",
        extra={
            "budgetId"          : budget.budgetId,
            "newBudgetId"       : new_id,
            "additionalReserved": add,
            "newReserved"       : new_reserved,
            "newAvailable"      : new_available,
        },
    )

    return TokenBudget(
        budgetId               = new_id,
        budgetKey              = new_key,
        provider               = budget.provider,
        model                  = budget.model,
        maxTokens              = budget.maxTokens,
        reservedOutputTokens   = new_reserved,
        availableContextTokens = new_available,
        usedContextTokens      = budget.usedContextTokens,
        remainingTokens        = new_remaining,
        state                  = new_state,
        createdAt              = created_at,
    )


def release_reserved_tokens(
    budget          : TokenBudget,
    tokens_to_release: int,
    created_at      : str,
) -> TokenBudget:
    """
    Return a new TokenBudget with tokens_to_release removed from
    reservedOutputTokens (floored at 0).

    newReserved  = max(0, reservedOutputTokens - tokensToRelease)
    newAvailable = max(0, maxTokens - newReserved)
    newRemaining = max(0, newAvailable - usedContextTokens)
    newState     = re-evaluated

    Parameters
    ----------
    budget           : existing TokenBudget (not mutated).
    tokens_to_release : tokens to release from reservation (>= 0).
    created_at       : ISO-8601 timestamp for the new budget object.

    Returns
    -------
    TokenBudget (frozen / immutable) — NEW object.

    Raises
    ------
    InvalidBudgetError : if tokens_to_release < 0.
    """
    rel = int(tokens_to_release)
    if rel < 0:
        raise InvalidBudgetError(
            f"tokens_to_release={rel} must be >= 0."
        )

    new_reserved  = max(0, budget.reservedOutputTokens - rel)
    new_available = max(0, budget.maxTokens - new_reserved)
    new_remaining = max(0, new_available - budget.usedContextTokens)
    new_state     = _determine_budget_state(new_available, budget.usedContextTokens)

    new_key = _compute_budget_key(
        budget.provider.value, budget.model,
        budget.maxTokens, new_reserved,
    )
    new_id = _uuid5(new_key)

    _log.info(
        "budget_release_reserved_tokens",
        extra={
            "budgetId"       : budget.budgetId,
            "newBudgetId"    : new_id,
            "tokensReleased" : rel,
            "newReserved"    : new_reserved,
            "newAvailable"   : new_available,
        },
    )

    return TokenBudget(
        budgetId               = new_id,
        budgetKey              = new_key,
        provider               = budget.provider,
        model                  = budget.model,
        maxTokens              = budget.maxTokens,
        reservedOutputTokens   = new_reserved,
        availableContextTokens = new_available,
        usedContextTokens      = budget.usedContextTokens,
        remainingTokens        = new_remaining,
        state                  = new_state,
        createdAt              = created_at,
    )


# ===========================================================================
# Budget Decisions
# ===========================================================================

def detect_overflow(
    budget    : TokenBudget,
    allocation: BudgetAllocation,
) -> bool:
    """
    Return True when the allocation exceeds the budget's available context.

    overflow = allocation.totalAllocatedTokens > budget.availableContextTokens

    Parameters
    ----------
    budget     : TokenBudget to check against.
    allocation : BudgetAllocation to evaluate.

    Returns
    -------
    bool — True if overflow detected.
    """
    overflow = allocation.totalAllocatedTokens > budget.availableContextTokens

    if overflow:
        _log.warning(
            "overflow_detected",
            extra={
                "budgetId"             : budget.budgetId,
                "allocationId"         : allocation.allocationId,
                "totalAllocatedTokens" : allocation.totalAllocatedTokens,
                "availableContextTokens": budget.availableContextTokens,
                "overflowBy"           : (
                    allocation.totalAllocatedTokens
                    - budget.availableContextTokens
                ),
            },
        )

    return overflow


def should_compress_context(
    budget    : TokenBudget,
    allocation: BudgetAllocation,
) -> bool:
    """
    Return True when context compression is recommended.

    Compression is recommended when:
        utilization >= _COMPRESSION_THRESHOLD (default 70%)
    AND there is no overflow yet.

    This gives the system an early warning to compress before hitting the
    truncation threshold.

    Parameters
    ----------
    budget     : TokenBudget to check.
    allocation : BudgetAllocation to evaluate.

    Returns
    -------
    bool — True when compression is recommended.
    """
    available = budget.availableContextTokens
    if available <= 0:
        return False

    utilization = allocation.totalAllocatedTokens / available
    compress = utilization >= _COMPRESSION_THRESHOLD

    if compress:
        _log.info(
            "compression_recommended",
            extra={
                "budgetId"    : budget.budgetId,
                "allocationId": allocation.allocationId,
                "utilization" : round(utilization, 4),
                "threshold"   : _COMPRESSION_THRESHOLD,
            },
        )

    return compress


def should_truncate_context(
    budget    : TokenBudget,
    allocation: BudgetAllocation,
) -> bool:
    """
    Return True when context truncation is recommended.

    Truncation is recommended when:
        utilization >= _TRUNCATION_THRESHOLD (default 90%)
    OR overflow is detected.

    Parameters
    ----------
    budget     : TokenBudget to check.
    allocation : BudgetAllocation to evaluate.

    Returns
    -------
    bool — True when truncation is recommended.
    """
    available = budget.availableContextTokens
    if available <= 0:
        return allocation.totalAllocatedTokens > 0

    utilization = allocation.totalAllocatedTokens / available
    truncate = (
        utilization >= _TRUNCATION_THRESHOLD
        or allocation.totalAllocatedTokens > available
    )

    return truncate


# ===========================================================================
# Utilities — Budget collection operations
# ===========================================================================

def sort_budgets(
    budgets   : List[TokenBudget],
    key       : str  = "remainingTokens",
    ascending : bool = True,
) -> List[TokenBudget]:
    """
    Return a new sorted list of TokenBudget objects.

    Supported sort keys
    -------------------
    "remainingTokens"       — ascending = lowest remaining first
    "availableContextTokens"— ascending = smallest window first
    "usedContextTokens"     — ascending = least used first
    "maxTokens"             — ascending = smallest max first
    "reservedOutputTokens"  — ascending = lowest reservation first
    "model"                 — lexicographic ASC/DESC
    "provider"              — lexicographic ASC/DESC by provider.value
    "state"                 — VALID < WARNING < EXCEEDED (ASC)
    "createdAt"             — lexicographic (ISO-8601 sorts correctly)

    Falls back to "budgetId" ASC for stable tie-breaking on all keys.

    Parameters
    ----------
    budgets   : list of TokenBudget objects (not mutated).
    key       : sort field name (see above). Default "remainingTokens".
    ascending : True = ascending (default); False = descending.

    Returns
    -------
    New sorted list of TokenBudget objects.

    Raises
    ------
    ValueError : if key is not a supported sort field.
    """
    _STATE_ORDER = {
        BudgetStateEnum.VALID    : 0,
        BudgetStateEnum.WARNING  : 1,
        BudgetStateEnum.EXCEEDED : 2,
    }
    _VALID_KEYS = {
        "remainingTokens", "availableContextTokens", "usedContextTokens",
        "maxTokens", "reservedOutputTokens", "model", "provider",
        "state", "createdAt",
    }
    if key not in _VALID_KEYS:
        raise ValueError(
            f"sort key '{key}' is not valid. Valid keys: {sorted(_VALID_KEYS)}"
        )

    def _sort_key(b: TokenBudget):
        if key == "state":
            primary = _STATE_ORDER.get(b.state, 99)
        elif key == "provider":
            primary = b.provider.value
        else:
            primary = getattr(b, key)
        return (primary, b.budgetId)   # stable tie-break

    return sorted(budgets, key=_sort_key, reverse=not ascending)


def filter_budgets(
    budgets  : List[TokenBudget],
    provider : Optional[ProviderTypeEnum]  = None,
    state    : Optional[BudgetStateEnum]   = None,
    model    : Optional[str]               = None,
    min_remaining: Optional[int]           = None,
    max_used    : Optional[int]            = None,
) -> List[TokenBudget]:
    """
    Return a filtered list of TokenBudget objects matching ALL supplied criteria.

    Parameters
    ----------
    budgets       : list of TokenBudget objects (not mutated).
    provider      : keep only budgets for this provider.
    state         : keep only budgets in this state.
    model         : keep only budgets whose model matches (exact, stripped).
    min_remaining : keep only budgets with remainingTokens >= this value.
    max_used      : keep only budgets with usedContextTokens <= this value.

    Returns
    -------
    New filtered list (input is not mutated), stable order preserved.
    """
    result: List[TokenBudget] = []
    norm_model = model.strip().lower() if model else None

    for b in budgets:
        if provider is not None and b.provider != provider:
            continue
        if state is not None and b.state != state:
            continue
        if norm_model is not None and b.model.lower() != norm_model:
            continue
        if min_remaining is not None and b.remainingTokens < min_remaining:
            continue
        if max_used is not None and b.usedContextTokens > max_used:
            continue
        result.append(b)

    return result


def group_budgets(
    budgets: List[TokenBudget],
    by     : str = "provider",
) -> Dict[str, List[TokenBudget]]:
    """
    Group TokenBudget objects into a dict keyed by a field value.

    Supported group keys: "provider", "state", "model".

    Within each group, budgets are ordered by budgetId ASC for determinism.

    Parameters
    ----------
    budgets : list of TokenBudget objects (not mutated).
    by      : grouping field. Default "provider".

    Returns
    -------
    Dict[str, List[TokenBudget]] — keys are string values of the field.

    Raises
    ------
    ValueError : if by is not a supported group key.
    """
    _VALID_GROUP_KEYS = {"provider", "state", "model"}
    if by not in _VALID_GROUP_KEYS:
        raise ValueError(
            f"group key '{by}' is not valid. Valid: {sorted(_VALID_GROUP_KEYS)}"
        )

    groups: Dict[str, List[TokenBudget]] = {}
    for b in sorted(budgets, key=lambda x: x.budgetId):
        if by == "provider":
            k = b.provider.value
        elif by == "state":
            k = b.state.value
        else:
            k = b.model
        groups.setdefault(k, []).append(b)

    return groups


def find_budget(
    budgets  : List[TokenBudget],
    budget_id: str,
) -> Optional[TokenBudget]:
    """
    Find the first TokenBudget with the given budgetId.

    Parameters
    ----------
    budgets   : list of TokenBudget objects.
    budget_id : budgetId to search for.

    Returns
    -------
    TokenBudget if found, None otherwise.
    """
    target = budget_id.strip()
    for b in budgets:
        if b.budgetId == target:
            return b
    return None


# ===========================================================================
# Utilities — Report collection operations
# ===========================================================================

def sort_reports(
    reports  : List[BudgetReport],
    key      : str  = "utilizationPercent",
    ascending: bool = True,
) -> List[BudgetReport]:
    """
    Return a new sorted list of BudgetReport objects.

    Supported sort keys
    -------------------
    "utilizationPercent"    — ascending = lowest utilization first
    "overflowDetected"      — False < True (ascending)
    "totalAllocatedTokens"  — via allocation.totalAllocatedTokens
    "remainingTokens"       — via budget.remainingTokens
    "state"                 — VALID < WARNING < EXCEEDED
    "createdAt"             — lexicographic (ISO-8601)
    "provider"              — lexicographic by budget.provider.value
    "model"                 — lexicographic by budget.model

    Stable tie-break on reportId ASC.

    Parameters
    ----------
    reports   : list of BudgetReport objects (not mutated).
    key       : sort field name. Default "utilizationPercent".
    ascending : True = ascending (default); False = descending.

    Returns
    -------
    New sorted list.

    Raises
    ------
    ValueError : if key is not a supported sort field.
    """
    _STATE_ORDER = {
        BudgetStateEnum.VALID    : 0,
        BudgetStateEnum.WARNING  : 1,
        BudgetStateEnum.EXCEEDED : 2,
    }
    _VALID_KEYS = {
        "utilizationPercent", "overflowDetected", "totalAllocatedTokens",
        "remainingTokens", "state", "createdAt", "provider", "model",
    }
    if key not in _VALID_KEYS:
        raise ValueError(
            f"sort key '{key}' is not valid. Valid keys: {sorted(_VALID_KEYS)}"
        )

    def _sort_key(r: BudgetReport):
        if key == "utilizationPercent":
            primary = r.utilizationPercent
        elif key == "overflowDetected":
            primary = int(r.overflowDetected)
        elif key == "totalAllocatedTokens":
            primary = r.allocation.totalAllocatedTokens
        elif key == "remainingTokens":
            primary = r.budget.remainingTokens
        elif key == "state":
            primary = _STATE_ORDER.get(r.budget.state, 99)
        elif key == "createdAt":
            primary = r.createdAt
        elif key == "provider":
            primary = r.budget.provider.value
        else:  # model
            primary = r.budget.model
        return (primary, r.reportId)

    return sorted(reports, key=_sort_key, reverse=not ascending)


def filter_reports(
    reports          : List[BudgetReport],
    provider         : Optional[ProviderTypeEnum] = None,
    state            : Optional[BudgetStateEnum]  = None,
    overflow_only    : Optional[bool]              = None,
    min_utilization  : Optional[float]             = None,
    max_utilization  : Optional[float]             = None,
    model            : Optional[str]               = None,
) -> List[BudgetReport]:
    """
    Return a filtered list of BudgetReport objects matching ALL criteria.

    Parameters
    ----------
    reports         : list of BudgetReport objects (not mutated).
    provider        : keep only reports for this provider.
    state           : keep only reports where budget.state matches.
    overflow_only   : if True, keep only reports where overflowDetected=True.
                      if False, keep only reports where overflowDetected=False.
    min_utilization : keep only reports with utilizationPercent >= this value.
    max_utilization : keep only reports with utilizationPercent <= this value.
    model           : keep only reports whose budget.model matches (exact, stripped).

    Returns
    -------
    New filtered list, stable order preserved.
    """
    norm_model = model.strip().lower() if model else None
    result: List[BudgetReport] = []

    for r in reports:
        if provider is not None and r.budget.provider != provider:
            continue
        if state is not None and r.budget.state != state:
            continue
        if overflow_only is True and not r.overflowDetected:
            continue
        if overflow_only is False and r.overflowDetected:
            continue
        if min_utilization is not None and r.utilizationPercent < min_utilization:
            continue
        if max_utilization is not None and r.utilizationPercent > max_utilization:
            continue
        if norm_model is not None and r.budget.model.lower() != norm_model:
            continue
        result.append(r)

    return result


def group_reports(
    reports: List[BudgetReport],
    by     : str = "state",
) -> Dict[str, List[BudgetReport]]:
    """
    Group BudgetReport objects into a dict keyed by a field value.

    Supported group keys: "state", "provider", "model", "overflow".

    Within each group, reports are ordered by reportId ASC for determinism.

    Parameters
    ----------
    reports : list of BudgetReport objects (not mutated).
    by      : grouping field. Default "state".

    Returns
    -------
    Dict[str, List[BudgetReport]] — keys are string values of the field.

    Raises
    ------
    ValueError : if by is not a supported group key.
    """
    _VALID_GROUP_KEYS = {"state", "provider", "model", "overflow"}
    if by not in _VALID_GROUP_KEYS:
        raise ValueError(
            f"group key '{by}' is not valid. Valid: {sorted(_VALID_GROUP_KEYS)}"
        )

    groups: Dict[str, List[BudgetReport]] = {}
    for r in sorted(reports, key=lambda x: x.reportId):
        if by == "state":
            k = r.budget.state.value
        elif by == "provider":
            k = r.budget.provider.value
        elif by == "model":
            k = r.budget.model
        else:  # overflow
            k = str(r.overflowDetected)
        groups.setdefault(k, []).append(r)

    return groups


def find_report(
    reports  : List[BudgetReport],
    report_id: str,
) -> Optional[BudgetReport]:
    """
    Find the first BudgetReport with the given reportId.

    Parameters
    ----------
    reports   : list of BudgetReport objects.
    report_id : reportId to search for.

    Returns
    -------
    BudgetReport if found, None otherwise.
    """
    target = report_id.strip()
    for r in reports:
        if r.reportId == target:
            return r
    return None

