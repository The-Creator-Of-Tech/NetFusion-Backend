"""
Retry & Failover Manager Engine
================================
Phase A4.5.3 — Deterministic, immutable retry policy management, failover
planning, provider health tracking, and execution decision engine for
NetFusion AI Copilot.

Responsibilities
----------------
- Define and build immutable retry policies with configurable strategies.
- Track provider health status (HEALTHY / DEGRADED / UNAVAILABLE).
- Produce deterministic RetryResult and RetryStatistics objects.
- Provide integration helpers for ai_execution_service, provider_registry_service,
  and token_budget_service.

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
- HTTP requests or provider SDK calls.
- AI model execution or inference.
- Streaming implementation.
- Database access.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import RETRY_FAILOVER_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("retry_failover_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_RETRY_NS = uuid.UUID("6ba7b835-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations (immutable str-Enum)
# ===========================================================================

class RetryStrategyEnum(str, Enum):
    """Strategy used to schedule retry attempts."""
    NONE               = "NONE"
    IMMEDIATE          = "IMMEDIATE"
    FIXED_DELAY        = "FIXED_DELAY"
    EXPONENTIAL_BACKOFF = "EXPONENTIAL_BACKOFF"


class ProviderHealthEnum(str, Enum):
    """Health state of an AI provider at a point in time."""
    HEALTHY     = "HEALTHY"
    DEGRADED    = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class RetryDecisionEnum(str, Enum):
    """Decision produced by the retry/failover engine for a failed attempt."""
    RETRY    = "RETRY"
    FAILOVER = "FAILOVER"
    ABORT    = "ABORT"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class RetryFailoverError(Exception):
    """Base class for all Retry & Failover Engine errors."""
    def __init__(self, message: str, policy_id: str = "", retry_id: str = "") -> None:
        super().__init__(message)
        self.policy_id = policy_id
        self.retry_id  = retry_id

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"policy_id={self.policy_id!r}, "
            f"retry_id={self.retry_id!r}, "
            f"message={str(self)!r})"
        )


class InvalidRetryPolicyError(RetryFailoverError):
    """Raised when a RetryPolicy fails validation."""


class InvalidProviderStatusError(RetryFailoverError):
    """Raised when a ProviderStatus fails validation."""


class InvalidRetryResultError(RetryFailoverError):
    """Raised when a RetryResult fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class RetryPolicy(BaseModel):
    """
    Immutable retry policy configuration.

    Identity
    --------
    policyId  : UUIDv5(_RETRY_NS, policyKey) — deterministic.
    policyKey : SHA256(strategy + str(maxRetries) + str(delayMilliseconds)
                       + str(backoffMultiplier))[:32]

    Fields
    ------
    policyId            : deterministic UUID string.
    policyKey           : 32-char SHA-256 hex key.
    strategy            : RetryStrategyEnum value.
    maxRetries          : maximum number of retry attempts (0 = no retry).
    delayMilliseconds   : base delay between retries in ms (>= 0).
    backoffMultiplier   : exponential backoff factor (>= 1.0).
    retryableExceptions : sorted tuple of exception class names that are
                          eligible for retry.
    createdAt           : ISO-8601 timestamp (caller-supplied).
    """
    policyId            : str
    policyKey           : str
    strategy            : RetryStrategyEnum
    maxRetries          : int
    delayMilliseconds   : int
    backoffMultiplier   : float
    retryableExceptions : Tuple[str, ...]
    createdAt           : str

    class Config:
        frozen = True


class ProviderStatus(BaseModel):
    """
    Immutable health snapshot for one AI provider/model pair.

    Identity
    --------
    providerId  : UUIDv5(_RETRY_NS, providerKey) — deterministic.
    providerKey : SHA256(provider + model)[:32]

    Fields
    ------
    providerId    : deterministic UUID string.
    providerKey   : 32-char SHA-256 hex key.
    provider      : provider key (e.g. "groq", "openai").
    model         : model name (e.g. "llama-3.3-70b-versatile").
    health        : ProviderHealthEnum snapshot value.
    priority      : selection priority (higher = preferred; 0 = lowest).
    failureCount  : cumulative failure observations.
    successCount  : cumulative success observations.
    lastFailureAt : ISO-8601 timestamp of most recent failure (or empty).
    createdAt     : ISO-8601 timestamp (caller-supplied).
    """
    providerId    : str
    providerKey   : str
    provider      : str
    model         : str
    health        : ProviderHealthEnum
    priority      : int
    failureCount  : int
    successCount  : int
    lastFailureAt : str
    createdAt     : str

    class Config:
        frozen = True


class RetryResult(BaseModel):
    """
    Immutable result of one retry/failover decision cycle.

    Identity
    --------
    retryId          : UUIDv5(_RETRY_NS, retryKey) — deterministic.
    retryKey         : SHA256(policyId + providerId + str(attemptNumber)
                              + decision)[:32]
    retryFingerprint : SHA256(retryKey + errorClass + str(attemptNumber))[:32]

    Fields
    ------
    retryId          : deterministic UUID string.
    retryKey         : 32-char SHA-256 hex key.
    retryFingerprint : 32-char deterministic content fingerprint.
    policyId         : RetryPolicy.policyId that drove this decision.
    providerId       : ProviderStatus.providerId for the failing provider.
    attemptNumber    : which attempt this result covers (1-indexed).
    maxAttempts      : maxRetries + 1 (total allowed attempts).
    decision         : RetryDecisionEnum — RETRY / FAILOVER / ABORT.
    delayMilliseconds: computed delay before the next attempt (ms).
    errorClass       : exception class name that triggered the retry cycle.
    errorMessage     : brief error description (never secrets/keys).
    failoverProvider : providerId to failover to (empty when not FAILOVER).
    createdAt        : ISO-8601 timestamp (caller-supplied).
    engineVersion    : RETRY_FAILOVER_ENGINE_VERSION.
    """
    retryId          : str
    retryKey         : str
    retryFingerprint : str
    policyId         : str
    providerId       : str
    attemptNumber    : int
    maxAttempts      : int
    decision         : RetryDecisionEnum
    delayMilliseconds: int
    errorClass       : str
    errorMessage     : str
    failoverProvider : str
    createdAt        : str
    engineVersion    : str

    class Config:
        frozen = True


class RetryStatistics(BaseModel):
    """
    Aggregate statistics over a collection of RetryResult objects.

    Fields
    ------
    totalAttempts       : total RetryResult objects counted.
    retryCount          : count of results with decision == RETRY.
    failoverCount       : count of results with decision == FAILOVER.
    abortCount          : count of results with decision == ABORT.
    retryRate           : retryCount / totalAttempts (0.0 when empty).
    failoverRate        : failoverCount / totalAttempts (0.0 when empty).
    abortRate           : abortCount / totalAttempts (0.0 when empty).
    averageDelayMs      : mean delayMilliseconds across all results.
    uniquePolicies      : sorted tuple of distinct policyId strings.
    uniqueProviders     : sorted tuple of distinct providerId strings.
    uniqueErrorClasses  : sorted tuple of distinct errorClass strings.
    """
    totalAttempts      : int
    retryCount         : int
    failoverCount      : int
    abortCount         : int
    retryRate          : float
    failoverRate       : float
    abortRate          : float
    averageDelayMs     : float
    uniquePolicies     : Tuple[str, ...]
    uniqueProviders    : Tuple[str, ...]
    uniqueErrorClasses : Tuple[str, ...]

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
    """UUIDv5(_RETRY_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_RETRY_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def policy_key(
    strategy            : str,
    max_retries         : int,
    delay_ms            : int,
    backoff_multiplier  : float,
) -> str:
    """
    policyKey = SHA256(strategy + str(maxRetries) + str(delayMs)
                       + str(backoffMultiplier))[:32]
    Null-byte-separated to prevent cross-field collisions.
    """
    return _sha256_32(
        _norm(strategy),
        str(int(max_retries)),
        str(int(delay_ms)),
        str(round(float(backoff_multiplier), 6)),
    )


def provider_key(provider: str, model: str) -> str:
    """
    providerKey = SHA256(provider + model)[:32]
    Null-byte-separated.
    """
    return _sha256_32(_norm(provider), _norm(model))


def retry_key(
    policy_id     : str,
    provider_id   : str,
    attempt_number: int,
    decision      : str,
) -> str:
    """
    retryKey = SHA256(policyId + providerId + str(attemptNumber) + decision)[:32]
    """
    return _sha256_32(
        policy_id.strip(),
        provider_id.strip(),
        str(int(attempt_number)),
        _norm(decision),
    )


def retry_fingerprint(
    r_key         : str,
    error_class   : str,
    attempt_number: int,
) -> str:
    """
    retryFingerprint = SHA256(retryKey + errorClass + str(attemptNumber))[:32]
    """
    return _sha256_32(r_key, error_class.strip(), str(int(attempt_number)))


# ===========================================================================
# Validation Functions
# ===========================================================================

def validate_retry_policy(
    strategy           : RetryStrategyEnum,
    max_retries        : int,
    delay_ms           : int,
    backoff_multiplier : float,
    created_at         : str,
) -> None:
    """
    Validate RetryPolicy construction parameters.

    Checks
    ------
    - strategy is a valid RetryStrategyEnum member.
    - maxRetries >= 0.
    - delayMilliseconds >= 0.
    - backoffMultiplier >= 1.0.
    - createdAt is non-empty.

    Raises
    ------
    InvalidRetryPolicyError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(strategy, RetryStrategyEnum):
        errors.append(
            f"strategy must be a RetryStrategyEnum member; got {strategy!r}."
        )
    if max_retries < 0:
        errors.append(f"maxRetries={max_retries} must be >= 0.")
    if delay_ms < 0:
        errors.append(f"delayMilliseconds={delay_ms} must be >= 0.")
    if float(backoff_multiplier) < 1.0:
        errors.append(
            f"backoffMultiplier={backoff_multiplier} must be >= 1.0."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        raise InvalidRetryPolicyError(
            "RetryPolicy validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def validate_provider_status(
    provider     : str,
    model        : str,
    health       : ProviderHealthEnum,
    priority     : int,
    failure_count: int,
    success_count: int,
    created_at   : str,
) -> None:
    """
    Validate ProviderStatus construction parameters.

    Checks
    ------
    - provider is non-empty.
    - model is non-empty.
    - health is a valid ProviderHealthEnum member.
    - priority >= 0.
    - failureCount >= 0.
    - successCount >= 0.
    - createdAt is non-empty.

    Raises
    ------
    InvalidProviderStatusError : if any rule is violated.
    """
    errors: List[str] = []

    if not provider or not provider.strip():
        errors.append("provider must not be empty.")
    if not model or not model.strip():
        errors.append("model must not be empty.")
    if not isinstance(health, ProviderHealthEnum):
        errors.append(
            f"health must be a ProviderHealthEnum member; got {health!r}."
        )
    if priority < 0:
        errors.append(f"priority={priority} must be >= 0.")
    if failure_count < 0:
        errors.append(f"failureCount={failure_count} must be >= 0.")
    if success_count < 0:
        errors.append(f"successCount={success_count} must be >= 0.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        raise InvalidProviderStatusError(
            "ProviderStatus validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def validate_retry_result(
    policy_id     : str,
    provider_id   : str,
    attempt_number: int,
    max_attempts  : int,
    decision      : RetryDecisionEnum,
    delay_ms      : int,
    error_class   : str,
    created_at    : str,
) -> None:
    """
    Validate RetryResult construction parameters.

    Checks
    ------
    - policyId is non-empty.
    - providerId is non-empty.
    - attemptNumber >= 1.
    - maxAttempts >= 1.
    - attemptNumber <= maxAttempts.
    - decision is a valid RetryDecisionEnum member.
    - delayMilliseconds >= 0.
    - errorClass is non-empty.
    - createdAt is non-empty.

    Raises
    ------
    InvalidRetryResultError : if any rule is violated.
    """
    errors: List[str] = []

    if not policy_id or not policy_id.strip():
        errors.append("policyId must not be empty.")
    if not provider_id or not provider_id.strip():
        errors.append("providerId must not be empty.")
    if attempt_number < 1:
        errors.append(f"attemptNumber={attempt_number} must be >= 1.")
    if max_attempts < 1:
        errors.append(f"maxAttempts={max_attempts} must be >= 1.")
    if attempt_number > max_attempts:
        errors.append(
            f"attemptNumber={attempt_number} must be <= "
            f"maxAttempts={max_attempts}."
        )
    if not isinstance(decision, RetryDecisionEnum):
        errors.append(
            f"decision must be a RetryDecisionEnum member; got {decision!r}."
        )
    if delay_ms < 0:
        errors.append(f"delayMilliseconds={delay_ms} must be >= 0.")
    if not error_class or not error_class.strip():
        errors.append("errorClass must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        raise InvalidRetryResultError(
            "RetryResult validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder Functions
# ===========================================================================

def build_retry_policy(
    strategy             : RetryStrategyEnum,
    created_at           : str,
    max_retries          : int          = 3,
    delay_ms             : int          = 1000,
    backoff_multiplier   : float        = 2.0,
    retryable_exceptions : Optional[List[str]] = None,
    validate             : bool         = True,
) -> RetryPolicy:
    """
    Build an immutable RetryPolicy.

    policyKey = SHA256(strategy + str(maxRetries) + str(delayMs)
                       + str(backoffMultiplier))[:32]
    policyId  = UUIDv5(_RETRY_NS, policyKey)

    Parameters
    ----------
    strategy             : RetryStrategyEnum value.
    created_at           : ISO-8601 timestamp (caller-supplied for determinism).
    max_retries          : maximum retry attempts (>= 0). Default 3.
    delay_ms             : base delay in ms (>= 0). Default 1000.
    backoff_multiplier   : exponential factor (>= 1.0). Default 2.0.
    retryable_exceptions : exception class names eligible for retry
                           (deduped + sorted). Default empty.
    validate             : if True, run validate_retry_policy() first.

    Returns
    -------
    RetryPolicy (frozen / immutable)

    Raises
    ------
    InvalidRetryPolicyError : if validate=True and validation fails.
    """
    clamped_retries = max(0, int(max_retries))
    clamped_delay   = max(0, int(delay_ms))
    clamped_backoff = max(1.0, float(backoff_multiplier))

    if validate:
        validate_retry_policy(
            strategy, clamped_retries, clamped_delay,
            clamped_backoff, created_at,
        )

    p_key = policy_key(
        strategy.value, clamped_retries, clamped_delay, clamped_backoff,
    )
    p_id = _uuid5(p_key)

    exc_tuple: Tuple[str, ...] = ()
    if retryable_exceptions:
        exc_tuple = tuple(
            sorted({e.strip() for e in retryable_exceptions if e and e.strip()})
        )

    _log.info(
        f"[retry_failover] policy_built "
        f"policyId={p_id} "
        f"strategy={strategy.value} "
        f"maxRetries={clamped_retries} "
        f"delayMs={clamped_delay} "
        f"backoffMultiplier={clamped_backoff} "
        f"engine={RETRY_FAILOVER_ENGINE_VERSION}"
    )

    return RetryPolicy(
        policyId            = p_id,
        policyKey           = p_key,
        strategy            = strategy,
        maxRetries          = clamped_retries,
        delayMilliseconds   = clamped_delay,
        backoffMultiplier   = clamped_backoff,
        retryableExceptions = exc_tuple,
        createdAt           = created_at,
    )


def build_provider_status(
    provider       : str,
    model          : str,
    created_at     : str,
    health         : ProviderHealthEnum = ProviderHealthEnum.HEALTHY,
    priority       : int                = 50,
    failure_count  : int                = 0,
    success_count  : int                = 0,
    last_failure_at: str                = "",
    validate       : bool               = True,
) -> ProviderStatus:
    """
    Build an immutable ProviderStatus snapshot.

    providerKey = SHA256(provider + model)[:32]
    providerId  = UUIDv5(_RETRY_NS, providerKey)

    Parameters
    ----------
    provider        : provider key (e.g. "groq"). Normalised to lowercase.
    model           : model name (e.g. "llama-3.3-70b-versatile"). Normalised.
    created_at      : ISO-8601 timestamp (caller-supplied for determinism).
    health          : ProviderHealthEnum snapshot. Default HEALTHY.
    priority        : selection priority (>= 0). Default 50.
    failure_count   : cumulative failures observed (>= 0). Default 0.
    success_count   : cumulative successes observed (>= 0). Default 0.
    last_failure_at : ISO-8601 timestamp of most recent failure (or "").
    validate        : if True, run validate_provider_status() first.

    Returns
    -------
    ProviderStatus (frozen / immutable)

    Raises
    ------
    InvalidProviderStatusError : if validate=True and validation fails.
    """
    norm_provider = _norm(provider)
    norm_model    = _norm(model)
    clamped_prio  = max(0, int(priority))
    clamped_fail  = max(0, int(failure_count))
    clamped_succ  = max(0, int(success_count))

    if validate:
        validate_provider_status(
            norm_provider, norm_model, health,
            clamped_prio, clamped_fail, clamped_succ, created_at,
        )

    p_key = provider_key(norm_provider, norm_model)
    p_id  = _uuid5(p_key)

    _log.info(
        f"[retry_failover] provider_status_built "
        f"providerId={p_id} "
        f"provider={norm_provider} "
        f"model={norm_model} "
        f"health={health.value} "
        f"engine={RETRY_FAILOVER_ENGINE_VERSION}"
    )

    return ProviderStatus(
        providerId    = p_id,
        providerKey   = p_key,
        provider      = norm_provider,
        model         = norm_model,
        health        = health,
        priority      = clamped_prio,
        failureCount  = clamped_fail,
        successCount  = clamped_succ,
        lastFailureAt = last_failure_at.strip(),
        createdAt     = created_at,
    )


def _compute_delay(
    policy        : RetryPolicy,
    attempt_number: int,
) -> int:
    """
    Compute the delay in ms for a given attempt according to the policy strategy.

    NONE / IMMEDIATE          → 0 ms
    FIXED_DELAY               → policy.delayMilliseconds
    EXPONENTIAL_BACKOFF       → floor(delayMs * backoffMultiplier^(attempt-1))

    attempt_number is 1-indexed; first retry = attempt 2.
    """
    if policy.strategy in (
        RetryStrategyEnum.NONE,
        RetryStrategyEnum.IMMEDIATE,
    ):
        return 0

    if policy.strategy == RetryStrategyEnum.FIXED_DELAY:
        return policy.delayMilliseconds

    # EXPONENTIAL_BACKOFF
    exponent = max(0, int(attempt_number) - 1)
    computed = policy.delayMilliseconds * (policy.backoffMultiplier ** exponent)
    return max(0, int(computed))


def build_retry_result(
    policy          : RetryPolicy,
    provider_status : ProviderStatus,
    attempt_number  : int,
    decision        : RetryDecisionEnum,
    error_class     : str,
    created_at      : str,
    error_message   : str = "",
    failover_provider: str = "",
    validate        : bool = True,
) -> RetryResult:
    """
    Build an immutable RetryResult for one retry/failover cycle.

    retryKey         = SHA256(policyId + providerId + str(attemptNumber)
                              + decision)[:32]
    retryId          = UUIDv5(_RETRY_NS, retryKey)
    retryFingerprint = SHA256(retryKey + errorClass + str(attemptNumber))[:32]

    delayMilliseconds is deterministically computed from the policy strategy
    and attempt_number.

    Parameters
    ----------
    policy            : RetryPolicy driving this decision.
    provider_status   : ProviderStatus for the failing provider.
    attempt_number    : which attempt this covers (1-indexed, <= maxAttempts).
    decision          : RetryDecisionEnum — RETRY / FAILOVER / ABORT.
    error_class       : exception class name that triggered the cycle.
    created_at        : ISO-8601 timestamp (caller-supplied).
    error_message     : brief error description (never secrets/keys).
    failover_provider : providerId to failover to (empty when not FAILOVER).
    validate          : if True, run validate_retry_result() first.

    Returns
    -------
    RetryResult (frozen / immutable)

    Raises
    ------
    InvalidRetryResultError : if validate=True and validation fails.
    """
    max_attempts   = policy.maxRetries + 1
    computed_delay = _compute_delay(policy, attempt_number)

    if validate:
        validate_retry_result(
            policy.policyId,
            provider_status.providerId,
            attempt_number,
            max_attempts,
            decision,
            computed_delay,
            error_class,
            created_at,
        )

    r_key = retry_key(
        policy.policyId,
        provider_status.providerId,
        attempt_number,
        decision.value,
    )
    r_id = _uuid5(r_key)
    r_fp = retry_fingerprint(r_key, error_class.strip(), attempt_number)

    _log.info(
        f"[retry_failover] retry_result_built "
        f"retryId={r_id} "
        f"decision={decision.value} "
        f"attempt={attempt_number}/{max_attempts} "
        f"delayMs={computed_delay} "
        f"engine={RETRY_FAILOVER_ENGINE_VERSION}"
    )

    return RetryResult(
        retryId          = r_id,
        retryKey         = r_key,
        retryFingerprint = r_fp,
        policyId         = policy.policyId,
        providerId       = provider_status.providerId,
        attemptNumber    = int(attempt_number),
        maxAttempts      = max_attempts,
        decision         = decision,
        delayMilliseconds= computed_delay,
        errorClass       = error_class.strip(),
        errorMessage     = error_message.strip(),
        failoverProvider = failover_provider.strip(),
        createdAt        = created_at,
        engineVersion    = RETRY_FAILOVER_ENGINE_VERSION,
    )


def build_retry_statistics(
    results: List[RetryResult],
) -> RetryStatistics:
    """
    Compute RetryStatistics over a list of RetryResult objects.

    Deterministic: canonical sort by retryId ASC before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    results : any list of RetryResult objects.

    Returns
    -------
    RetryStatistics (frozen / immutable)
    """
    if not results:
        return RetryStatistics(
            totalAttempts      = 0,
            retryCount         = 0,
            failoverCount      = 0,
            abortCount         = 0,
            retryRate          = 0.0,
            failoverRate       = 0.0,
            abortRate          = 0.0,
            averageDelayMs     = 0.0,
            uniquePolicies     = (),
            uniqueProviders    = (),
            uniqueErrorClasses = (),
        )

    # Canonical deterministic order
    ordered = sorted(results, key=lambda r: r.retryId)
    n = len(ordered)

    retry_count    = sum(1 for r in ordered if r.decision == RetryDecisionEnum.RETRY)
    failover_count = sum(1 for r in ordered if r.decision == RetryDecisionEnum.FAILOVER)
    abort_count    = sum(1 for r in ordered if r.decision == RetryDecisionEnum.ABORT)
    delay_sum      = sum(r.delayMilliseconds for r in ordered)

    unique_policies     = tuple(sorted({r.policyId   for r in ordered}))
    unique_providers    = tuple(sorted({r.providerId  for r in ordered}))
    unique_error_classes= tuple(sorted({r.errorClass  for r in ordered}))

    _log.info(
        f"[retry_failover] statistics_built "
        f"total={n} retry={retry_count} "
        f"failover={failover_count} abort={abort_count}"
    )

    return RetryStatistics(
        totalAttempts      = n,
        retryCount         = retry_count,
        failoverCount      = failover_count,
        abortCount         = abort_count,
        retryRate          = round(retry_count    / n, 6),
        failoverRate       = round(failover_count / n, 6),
        abortRate          = round(abort_count    / n, 6),
        averageDelayMs     = round(delay_sum      / n, 4),
        uniquePolicies     = unique_policies,
        uniqueProviders    = unique_providers,
        uniqueErrorClasses = unique_error_classes,
    )


# ===========================================================================
# Integration helpers
# ===========================================================================

# ---------------------------------------------------------------------------
# ai_execution_service integration
# ---------------------------------------------------------------------------

def policy_for_execution(
    max_retries       : int   = 3,
    delay_ms          : int   = 1000,
    backoff_multiplier: float = 2.0,
    created_at        : str   = "",
) -> RetryPolicy:
    """
    Build the default exponential-backoff RetryPolicy suitable for
    ai_execution_service retry loops.

    retryableExceptions is pre-populated with the canonical set of
    retryable AIExecutionError subclass names from ai_execution_service:
      - ExecutionTimeoutError
      - ProviderUnavailableError
      - RetryExhaustedError  (not re-retried; included for logging)

    Parameters
    ----------
    max_retries        : override for maxRetries (>= 0).
    delay_ms           : override for base delay in ms (>= 0).
    backoff_multiplier : override for backoff factor (>= 1.0).
    created_at         : ISO-8601 timestamp; falls back to empty string.

    Returns
    -------
    RetryPolicy (frozen / immutable)
    """
    return build_retry_policy(
        strategy             = RetryStrategyEnum.EXPONENTIAL_BACKOFF,
        created_at           = created_at,
        max_retries          = max_retries,
        delay_ms             = delay_ms,
        backoff_multiplier   = backoff_multiplier,
        retryable_exceptions = [
            "ExecutionTimeoutError",
            "ProviderUnavailableError",
            "RetryExhaustedError",
        ],
        validate = True,
    )


def execution_provider_status(
    provider   : str,
    model      : str,
    created_at : str,
    health     : ProviderHealthEnum = ProviderHealthEnum.HEALTHY,
    priority   : int                = 50,
) -> ProviderStatus:
    """
    Build a ProviderStatus snapshot from an ai_execution_service provider/model pair.

    Thin wrapper over build_provider_status() that defaults to zero
    counters — callers supply observed failure/success counts directly
    when they need to reflect live state.

    Parameters
    ----------
    provider   : provider key (e.g. "groq").
    model      : model name (e.g. "llama-3.3-70b-versatile").
    created_at : ISO-8601 timestamp.
    health     : current health snapshot. Default HEALTHY.
    priority   : selection priority. Default 50.

    Returns
    -------
    ProviderStatus (frozen / immutable)
    """
    return build_provider_status(
        provider      = provider,
        model         = model,
        created_at    = created_at,
        health        = health,
        priority      = priority,
        failure_count = 0,
        success_count = 0,
        validate      = True,
    )


# ---------------------------------------------------------------------------
# provider_registry_service integration
# ---------------------------------------------------------------------------

def provider_status_from_registry_model(
    provider_model : Any,
    created_at     : str,
    health         : ProviderHealthEnum = ProviderHealthEnum.HEALTHY,
) -> ProviderStatus:
    """
    Build a ProviderStatus from a provider_registry_service.ProviderModel.

    Reads .provider, .modelName, and .priority from the ProviderModel
    object via attribute access so this helper stays decoupled from a
    direct import of the provider_registry_service module.

    Parameters
    ----------
    provider_model : ProviderModel instance from provider_registry_service.
    created_at     : ISO-8601 timestamp.
    health         : health snapshot for this provider. Default HEALTHY.

    Returns
    -------
    ProviderStatus (frozen / immutable)

    Raises
    ------
    InvalidProviderStatusError : if required attributes are missing or empty.
    """
    try:
        prov  = str(getattr(provider_model, "provider",   "") or "")
        model = str(getattr(provider_model, "modelName",  "") or "")
        prio  = int(getattr(provider_model, "priority",   50))
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidProviderStatusError(
            f"Cannot extract provider/model/priority from ProviderModel: {exc}"
        ) from exc

    return build_provider_status(
        provider      = prov,
        model         = model,
        created_at    = created_at,
        health        = health,
        priority      = prio,
        failure_count = 0,
        success_count = 0,
        validate      = True,
    )


def select_failover_provider(
    current_provider_id : str,
    provider_statuses   : List[ProviderStatus],
) -> Optional[ProviderStatus]:
    """
    Select the best HEALTHY failover candidate excluding the failing provider.

    Selection rules (deterministic, no random)
    ------------------------------------------
    1. Exclude ProviderStatus entries where providerId == current_provider_id.
    2. Exclude entries where health != HEALTHY.
    3. Sort remaining candidates by (priority DESC, providerId ASC) for
       stable tie-breaking.
    4. Return the first candidate, or None if no candidate exists.

    Parameters
    ----------
    current_provider_id : providerId of the provider that is failing.
    provider_statuses   : all known ProviderStatus snapshots.

    Returns
    -------
    ProviderStatus or None
    """
    candidates = [
        ps for ps in provider_statuses
        if ps.providerId != current_provider_id
        and ps.health == ProviderHealthEnum.HEALTHY
    ]
    if not candidates:
        return None

    # Deterministic sort: priority descending, then providerId ascending
    candidates.sort(key=lambda ps: (-ps.priority, ps.providerId))
    return candidates[0]


# ---------------------------------------------------------------------------
# token_budget_service integration
# ---------------------------------------------------------------------------

def policy_for_budget_overflow(
    created_at: str,
) -> RetryPolicy:
    """
    Build a minimal IMMEDIATE-retry RetryPolicy used when a token-budget
    overflow forces a prompt truncation and re-attempt.

    maxRetries = 1 (one re-attempt after truncation).
    delayMs    = 0 (immediate; truncation is instant, not a rate-limit issue).
    backoffMultiplier = 1.0 (no backoff needed for immediate retry).
    retryableExceptions = ["InvalidBudgetReportError", "InvalidBudgetError"].

    Parameters
    ----------
    created_at : ISO-8601 timestamp (caller-supplied for determinism).

    Returns
    -------
    RetryPolicy (frozen / immutable)
    """
    return build_retry_policy(
        strategy             = RetryStrategyEnum.IMMEDIATE,
        created_at           = created_at,
        max_retries          = 1,
        delay_ms             = 0,
        backoff_multiplier   = 1.0,
        retryable_exceptions = [
            "InvalidBudgetReportError",
            "InvalidBudgetError",
        ],
        validate = True,
    )


def budget_retry_result(
    policy         : RetryPolicy,
    provider_status: ProviderStatus,
    attempt_number : int,
    overflow       : bool,
    created_at     : str,
) -> RetryResult:
    """
    Build a RetryResult reflecting a token-budget-overflow-driven retry.

    Decision logic
    --------------
    - overflow=True  and attemptNumber < maxAttempts → RETRY
    - overflow=True  and attemptNumber >= maxAttempts → ABORT
    - overflow=False → ABORT  (budget is healthy; nothing to retry)

    Parameters
    ----------
    policy          : RetryPolicy (typically from policy_for_budget_overflow()).
    provider_status : ProviderStatus for the current provider.
    attempt_number  : current attempt (1-indexed).
    overflow        : True when BudgetReport.overflowDetected is True.
    created_at      : ISO-8601 timestamp.

    Returns
    -------
    RetryResult (frozen / immutable)
    """
    max_attempts = policy.maxRetries + 1

    if overflow and attempt_number < max_attempts:
        decision    = RetryDecisionEnum.RETRY
        error_class = "InvalidBudgetReportError"
        error_msg   = "Token budget overflow detected; retrying with truncated prompt."
    else:
        decision    = RetryDecisionEnum.ABORT
        error_class = "InvalidBudgetReportError" if overflow else "NoBudgetOverflow"
        error_msg   = (
            "Token budget overflow; max retry attempts exhausted."
            if overflow
            else "No budget overflow; no retry needed."
        )

    return build_retry_result(
        policy           = policy,
        provider_status  = provider_status,
        attempt_number   = attempt_number,
        decision         = decision,
        error_class      = error_class,
        created_at       = created_at,
        error_message    = error_msg,
        failover_provider= "",
        validate         = True,
    )

# ===========================================================================
# Part B — Retry Engine
# ===========================================================================

def should_retry(
    policy        : RetryPolicy,
    attempt_number: int,
    error_class   : str = "",
) -> bool:
    """
    Determine whether another retry attempt is permitted.

    Rules (fully deterministic, no side-effects)
    --------------------------------------------
    1. strategy == NONE → always False.
    2. attempt_number >= maxRetries + 1 → False (budget exhausted).
    3. retryableExceptions is non-empty AND error_class is not in it → False.
    4. Otherwise → True.

    Parameters
    ----------
    policy         : RetryPolicy to evaluate.
    attempt_number : the attempt that just failed (1-indexed).
    error_class    : exception class name; empty string skips exception check.

    Returns
    -------
    bool
    """
    if policy.strategy == RetryStrategyEnum.NONE:
        _log.info(
            f"[retry_failover] retry_decision strategy=NONE "
            f"attempt={attempt_number} result=no_retry"
        )
        return False

    max_attempts = policy.maxRetries + 1
    if attempt_number >= max_attempts:
        _log.info(
            f"[retry_failover] retry_exhausted "
            f"attempt={attempt_number} maxAttempts={max_attempts}"
        )
        return False

    if policy.retryableExceptions and error_class:
        if error_class.strip() not in policy.retryableExceptions:
            _log.info(
                f"[retry_failover] retry_decision "
                f"error_class={error_class!r} not_in_retryable_list "
                f"result=no_retry"
            )
            return False

    _log.info(
        f"[retry_failover] retry_scheduled "
        f"attempt={attempt_number} maxAttempts={max_attempts} "
        f"strategy={policy.strategy.value}"
    )
    return True


def next_retry_delay(
    policy        : RetryPolicy,
    attempt_number: int,
) -> int:
    """
    Return the delay in milliseconds before the next attempt.

    This is a pure wrapper around _compute_delay() exposed as a public API
    so callers never need to access the private helper directly.

    Parameters
    ----------
    policy         : RetryPolicy in effect.
    attempt_number : the attempt that just completed (1-indexed).
                     The delay is for the NEXT attempt.

    Returns
    -------
    int — milliseconds to wait (0 means immediate).
    """
    delay = _compute_delay(policy, attempt_number + 1)
    _log.info(
        f"[retry_failover] next_retry_delay "
        f"strategy={policy.strategy.value} "
        f"attempt={attempt_number} nextDelay={delay}ms"
    )
    return delay


def increment_retry_attempt(
    result    : RetryResult,
    policy    : RetryPolicy,
    created_at: str,
) -> RetryResult:
    """
    Return a NEW RetryResult advancing attempt_number by 1.

    The decision on the new result is set by evaluating should_retry()
    for the incremented attempt against the same policy and error_class.
    If should_retry() returns False the decision becomes ABORT.

    No mutation — returns a brand-new frozen RetryResult.

    Parameters
    ----------
    result     : the RetryResult to advance from.
    policy     : the RetryPolicy governing retries.
    created_at : ISO-8601 timestamp for the new result.

    Returns
    -------
    RetryResult (frozen / immutable)
    """
    next_attempt = result.attemptNumber + 1

    # Check if next_attempt is within budget:
    # should_retry evaluates attempt_number as "the attempt that just failed".
    # Passing result.attemptNumber checks if THAT attempt can be followed by a retry.
    # But we already computed next_attempt = result.attemptNumber + 1.
    # The cleaner check: next_attempt <= policy.maxRetries (i.e. < maxAttempts).
    max_attempts = policy.maxRetries + 1
    if next_attempt < max_attempts and should_retry(policy, next_attempt - 1, result.errorClass):
        new_decision = RetryDecisionEnum.RETRY
    else:
        new_decision = RetryDecisionEnum.ABORT

    # Rebuild a ProviderStatus shell to satisfy build_retry_result signature.
    # providerId is preserved; provider/model fields are reconstructed from key.
    stub_ps = ProviderStatus(
        providerId    = result.providerId,
        providerKey   = result.providerId,   # placeholder — key not stored in result
        provider      = "unknown",
        model         = "unknown",
        health        = ProviderHealthEnum.HEALTHY,
        priority      = 0,
        failureCount  = 0,
        successCount  = 0,
        lastFailureAt = "",
        createdAt     = created_at,
    )

    new_result = build_retry_result(
        policy           = policy,
        provider_status  = stub_ps,
        attempt_number   = next_attempt,
        decision         = new_decision,
        error_class      = result.errorClass,
        created_at       = created_at,
        error_message    = result.errorMessage,
        failover_provider= result.failoverProvider,
        validate         = True,
    )
    _log.info(
        f"[retry_failover] retry_executed "
        f"retryId={new_result.retryId} "
        f"attempt={next_attempt}/{new_result.maxAttempts} "
        f"decision={new_decision.value}"
    )
    return new_result

# ===========================================================================
# Part B — Provider Health Engine
# ===========================================================================

# Health transition thresholds (deterministic constants)
_DEGRADED_FAILURE_THRESHOLD   : int = 3   # failures to enter DEGRADED
_UNAVAILABLE_FAILURE_THRESHOLD: int = 5   # failures to enter UNAVAILABLE
_RECOVERY_SUCCESS_THRESHOLD   : int = 2   # consecutive successes to recover


def calculate_provider_health(
    failure_count: int,
    success_count: int,
) -> ProviderHealthEnum:
    """
    Derive ProviderHealthEnum from cumulative counters.

    Transition rules (deterministic)
    ---------------------------------
    failure_count >= _UNAVAILABLE_FAILURE_THRESHOLD (5)  → UNAVAILABLE
    failure_count >= _DEGRADED_FAILURE_THRESHOLD    (3)  → DEGRADED
    Otherwise                                             → HEALTHY

    Recovery override: if success_count >= _RECOVERY_SUCCESS_THRESHOLD (2)
    AND failure_count < _UNAVAILABLE_FAILURE_THRESHOLD, the state is HEALTHY
    regardless of failure_count.

    Parameters
    ----------
    failure_count : cumulative failures observed.
    success_count : cumulative successes observed.

    Returns
    -------
    ProviderHealthEnum
    """
    fc = max(0, int(failure_count))
    sc = max(0, int(success_count))

    if fc >= _UNAVAILABLE_FAILURE_THRESHOLD:
        # Recovery from UNAVAILABLE requires success_count >= threshold
        if sc >= _RECOVERY_SUCCESS_THRESHOLD and fc < _UNAVAILABLE_FAILURE_THRESHOLD:
            return ProviderHealthEnum.HEALTHY
        return ProviderHealthEnum.UNAVAILABLE

    if fc >= _DEGRADED_FAILURE_THRESHOLD:
        if sc >= _RECOVERY_SUCCESS_THRESHOLD:
            return ProviderHealthEnum.HEALTHY
        return ProviderHealthEnum.DEGRADED

    return ProviderHealthEnum.HEALTHY


def mark_provider_success(
    status    : ProviderStatus,
    created_at: str,
) -> ProviderStatus:
    """
    Return a new ProviderStatus reflecting one additional success observation.

    successCount is incremented by 1.
    health is recalculated via calculate_provider_health().
    All other fields are preserved unchanged.

    Parameters
    ----------
    status     : existing ProviderStatus snapshot.
    created_at : ISO-8601 timestamp for the new snapshot.

    Returns
    -------
    ProviderStatus (frozen / immutable)
    """
    new_success = status.successCount + 1
    new_health  = calculate_provider_health(status.failureCount, new_success)

    if new_health != status.health:
        _log.info(
            f"[retry_failover] provider_recovered "
            f"providerId={status.providerId} "
            f"provider={status.provider} "
            f"model={status.model} "
            f"old_health={status.health.value} "
            f"new_health={new_health.value} "
            f"successCount={new_success}"
        )

    updated = build_provider_status(
        provider        = status.provider,
        model           = status.model,
        created_at      = created_at,
        health          = new_health,
        priority        = status.priority,
        failure_count   = status.failureCount,
        success_count   = new_success,
        last_failure_at = status.lastFailureAt,
        validate        = True,
    )
    return updated


def mark_provider_failure(
    status        : ProviderStatus,
    created_at    : str,
    last_failure_at: str = "",
) -> ProviderStatus:
    """
    Return a new ProviderStatus reflecting one additional failure observation.

    failureCount is incremented by 1.
    health is recalculated via calculate_provider_health().
    lastFailureAt is updated to last_failure_at (or created_at if empty).
    successCount is reset to 0 (failure resets recovery progress).

    Parameters
    ----------
    status          : existing ProviderStatus snapshot.
    created_at      : ISO-8601 timestamp for the new snapshot.
    last_failure_at : timestamp of this failure; defaults to created_at.

    Returns
    -------
    ProviderStatus (frozen / immutable)
    """
    new_failure = status.failureCount + 1
    # Failures reset recovery progress
    new_success = 0
    new_health  = calculate_provider_health(new_failure, new_success)
    failure_ts  = last_failure_at.strip() or created_at

    if new_health != status.health:
        event = (
            "provider_unavailable"
            if new_health == ProviderHealthEnum.UNAVAILABLE
            else "provider_degraded"
        )
        _log.info(
            f"[retry_failover] {event} "
            f"providerId={status.providerId} "
            f"provider={status.provider} "
            f"model={status.model} "
            f"old_health={status.health.value} "
            f"new_health={new_health.value} "
            f"failureCount={new_failure}"
        )

    updated = build_provider_status(
        provider        = status.provider,
        model           = status.model,
        created_at      = created_at,
        health          = new_health,
        priority        = status.priority,
        failure_count   = new_failure,
        success_count   = new_success,
        last_failure_at = failure_ts,
        validate        = True,
    )
    return updated


def reset_provider_health(
    status    : ProviderStatus,
    created_at: str,
) -> ProviderStatus:
    """
    Return a new ProviderStatus with counters reset to zero and health HEALTHY.

    Parameters
    ----------
    status     : existing ProviderStatus snapshot.
    created_at : ISO-8601 timestamp for the new snapshot.

    Returns
    -------
    ProviderStatus (frozen / immutable)
    """
    _log.info(
        f"[retry_failover] provider_recovered "
        f"providerId={status.providerId} "
        f"provider={status.provider} "
        f"model={status.model} "
        f"old_health={status.health.value} "
        f"new_health=HEALTHY "
        f"reason=explicit_reset"
    )
    return build_provider_status(
        provider        = status.provider,
        model           = status.model,
        created_at      = created_at,
        health          = ProviderHealthEnum.HEALTHY,
        priority        = status.priority,
        failure_count   = 0,
        success_count   = 0,
        last_failure_at = "",
        validate        = True,
    )

# ===========================================================================
# Part B — Failover Engine
# ===========================================================================

class RetryPlan(BaseModel):
    """
    Immutable plan describing the full retry/failover strategy for one
    execution attempt.

    Fields
    ------
    planId            : UUIDv5(_RETRY_NS, planKey) — deterministic.
    planKey           : SHA256(policyId + primaryProviderId + errorClass)[:32]
    policyId          : RetryPolicy.policyId driving the plan.
    primaryProviderId : the provider that failed.
    failoverProviderId: provider selected for failover (empty if none/retry).
    decision          : RetryDecisionEnum — RETRY / FAILOVER / ABORT.
    attemptNumber     : attempt that triggered this plan (1-indexed).
    maxAttempts       : maximum allowed attempts under this policy.
    delayMilliseconds : delay before executing the decision.
    errorClass        : error that triggered this plan.
    errorMessage      : brief description (never secrets).
    createdAt         : ISO-8601 timestamp.
    engineVersion     : RETRY_FAILOVER_ENGINE_VERSION.
    """
    planId             : str
    planKey            : str
    policyId           : str
    primaryProviderId  : str
    failoverProviderId : str
    decision           : RetryDecisionEnum
    attemptNumber      : int
    maxAttempts        : int
    delayMilliseconds  : int
    errorClass         : str
    errorMessage       : str
    createdAt          : str
    engineVersion      : str

    class Config:
        frozen = True


def build_retry_plan(
    policy            : RetryPolicy,
    primary_status    : ProviderStatus,
    attempt_number    : int,
    error_class       : str,
    created_at        : str,
    all_provider_statuses: Optional[List[ProviderStatus]] = None,
    error_message     : str = "",
) -> RetryPlan:
    """
    Build an immutable RetryPlan for one failed execution attempt.

    Decision logic (deterministic)
    --------------------------------
    1. should_retry(policy, attempt_number, error_class) → RETRY
       delay = _compute_delay(policy, attempt_number + 1)
       failoverProviderId = ""
    2. primary health is UNAVAILABLE or attempts exhausted → try FAILOVER
       select_failover_provider(primary, all_provider_statuses)
       If a candidate exists → FAILOVER, failoverProviderId = candidate.providerId
    3. No candidates → ABORT

    planKey = SHA256(policyId + primaryProviderId + errorClass)[:32]
    planId  = UUIDv5(_RETRY_NS, planKey)

    Parameters
    ----------
    policy                : RetryPolicy in effect.
    primary_status        : ProviderStatus of the failing provider.
    attempt_number        : current attempt (1-indexed).
    error_class           : exception class name.
    created_at            : ISO-8601 timestamp.
    all_provider_statuses : full list of known ProviderStatus objects for
                            failover candidate selection (may be None/empty).
    error_message         : brief error description.

    Returns
    -------
    RetryPlan (frozen / immutable)
    """
    max_attempts    = policy.maxRetries + 1
    statuses        = all_provider_statuses or []

    # Step 1: check if retry is allowed
    if should_retry(policy, attempt_number, error_class):
        decision           = RetryDecisionEnum.RETRY
        failover_id        = ""
        delay              = _compute_delay(policy, attempt_number + 1)
    else:
        # Step 2: look for failover candidate
        candidate = select_failover_provider(primary_status.providerId, statuses)
        if candidate is not None:
            decision    = RetryDecisionEnum.FAILOVER
            failover_id = candidate.providerId
            delay       = 0
            _log.info(
                f"[retry_failover] failover_selected "
                f"from={primary_status.providerId} "
                f"to={failover_id} "
                f"candidateProvider={candidate.provider}"
            )
        else:
            decision    = RetryDecisionEnum.ABORT
            failover_id = ""
            delay       = 0
            _log.info(
                f"[retry_failover] retry_exhausted "
                f"primaryProviderId={primary_status.providerId} "
                f"attempt={attempt_number}/{max_attempts} "
                f"noFailoverAvailable=True"
            )

    plan_key = _sha256_32(
        policy.policyId,
        primary_status.providerId,
        error_class.strip(),
    )
    plan_id = _uuid5(plan_key)

    return RetryPlan(
        planId             = plan_id,
        planKey            = plan_key,
        policyId           = policy.policyId,
        primaryProviderId  = primary_status.providerId,
        failoverProviderId = failover_id,
        decision           = decision,
        attemptNumber      = int(attempt_number),
        maxAttempts        = max_attempts,
        delayMilliseconds  = delay,
        errorClass         = error_class.strip(),
        errorMessage       = error_message.strip(),
        createdAt          = created_at,
        engineVersion      = RETRY_FAILOVER_ENGINE_VERSION,
    )


def execute_failover_decision(
    plan           : RetryPlan,
    policy         : RetryPolicy,
    primary_status : ProviderStatus,
    created_at     : str,
    all_provider_statuses: Optional[List[ProviderStatus]] = None,
) -> RetryResult:
    """
    Convert a RetryPlan into a concrete RetryResult.

    The plan's decision is preserved exactly; this function materialises
    it as an immutable RetryResult with the correct IDs and delay.

    Parameters
    ----------
    plan                  : RetryPlan produced by build_retry_plan().
    policy                : RetryPolicy in effect.
    primary_status        : ProviderStatus of the failing provider.
    created_at            : ISO-8601 timestamp.
    all_provider_statuses : known ProviderStatus objects (used to resolve
                            failover provider text if needed).

    Returns
    -------
    RetryResult (frozen / immutable)
    """
    # Resolve a stub ProviderStatus matching the failover candidate if needed
    failover_pid = plan.failoverProviderId

    result = build_retry_result(
        policy            = policy,
        provider_status   = primary_status,
        attempt_number    = plan.attemptNumber,
        decision          = plan.decision,
        error_class       = plan.errorClass,
        created_at        = created_at,
        error_message     = plan.errorMessage,
        failover_provider = failover_pid,
        validate          = True,
    )

    _log.info(
        f"[retry_failover] retry_executed "
        f"retryId={result.retryId} "
        f"planId={plan.planId} "
        f"decision={plan.decision.value} "
        f"attempt={plan.attemptNumber}/{plan.maxAttempts}"
    )
    return result

# ===========================================================================
# Part B — Utility functions: RetryResult
# ===========================================================================

def sort_retry_results(
    results  : List[RetryResult],
    by       : str = "attemptNumber",
    ascending: bool = True,
) -> List[RetryResult]:
    """
    Return a new sorted list of RetryResult objects.

    Sort keys (always tie-broken by retryId ASC for determinism)
    ------------------------------------------------------------
    "attemptNumber" (default) : attemptNumber, then retryId
    "decision"                : decision.value, then attemptNumber, then retryId
    "delayMs"                 : delayMilliseconds, then retryId
    "errorClass"              : errorClass, then retryId
    "policyId"                : policyId, then retryId
    "providerId"              : providerId, then retryId
    "retryId"                 : retryId only

    Parameters
    ----------
    results   : list to sort (not mutated).
    by        : sort key name (case-insensitive).
    ascending : True = ascending, False = descending primary key.

    Returns
    -------
    List[RetryResult] — new list, originals unchanged.
    """
    key_map: Dict[str, Any] = {
        "attemptnumber" : lambda r: (r.attemptNumber,       r.retryId),
        "decision"      : lambda r: (r.decision.value,      r.attemptNumber, r.retryId),
        "delayms"       : lambda r: (r.delayMilliseconds,   r.retryId),
        "errorclass"    : lambda r: (r.errorClass,          r.retryId),
        "policyid"      : lambda r: (r.policyId,            r.retryId),
        "providerid"    : lambda r: (r.providerId,          r.retryId),
        "retryid"       : lambda r: (r.retryId,),
    }
    norm_by = by.strip().lower()
    key_fn  = key_map.get(norm_by, key_map["attemptnumber"])
    return sorted(results, key=key_fn, reverse=not ascending)


def filter_retry_results(
    results    : List[RetryResult],
    decision   : Optional[RetryDecisionEnum] = None,
    policy_id  : Optional[str] = None,
    provider_id: Optional[str] = None,
    error_class: Optional[str] = None,
) -> List[RetryResult]:
    """
    Return a filtered subset of RetryResult objects.

    All supplied filters are AND-combined.
    Unspecified filters (None) are ignored.

    Parameters
    ----------
    results     : list to filter.
    decision    : keep only results with this decision.
    policy_id   : keep only results with this policyId.
    provider_id : keep only results with this providerId.
    error_class : keep only results with this errorClass (exact match).

    Returns
    -------
    List[RetryResult] — new list, originals unchanged.
    """
    out = list(results)
    if decision is not None:
        out = [r for r in out if r.decision == decision]
    if policy_id is not None:
        out = [r for r in out if r.policyId == policy_id.strip()]
    if provider_id is not None:
        out = [r for r in out if r.providerId == provider_id.strip()]
    if error_class is not None:
        out = [r for r in out if r.errorClass == error_class.strip()]
    return out


def group_retry_results(
    results: List[RetryResult],
    by     : str = "decision",
) -> Dict[str, List[RetryResult]]:
    """
    Group RetryResult objects into a dict keyed by a field value.

    Group keys
    ----------
    "decision"   (default) : RetryDecisionEnum.value
    "policyId"             : policyId
    "providerId"           : providerId
    "errorClass"           : errorClass

    Each group list is sorted by (attemptNumber ASC, retryId ASC).

    Parameters
    ----------
    results : list to group.
    by      : field name (case-insensitive).

    Returns
    -------
    Dict[str, List[RetryResult]]
    """
    norm_by = by.strip().lower()
    groups: Dict[str, List[RetryResult]] = {}

    for r in results:
        if norm_by == "decision":
            key = r.decision.value
        elif norm_by == "policyid":
            key = r.policyId
        elif norm_by == "providerid":
            key = r.providerId
        elif norm_by == "errorclass":
            key = r.errorClass
        else:
            key = r.decision.value
        groups.setdefault(key, []).append(r)

    # Sort each group deterministically
    for k in groups:
        groups[k] = sorted(groups[k], key=lambda r: (r.attemptNumber, r.retryId))
    return groups


def find_retry_result(
    results    : List[RetryResult],
    retry_id   : Optional[str] = None,
    policy_id  : Optional[str] = None,
    provider_id: Optional[str] = None,
    decision   : Optional[RetryDecisionEnum] = None,
) -> Optional[RetryResult]:
    """
    Return the first matching RetryResult, or None.

    Filters are AND-combined.  "First" is defined as lowest attemptNumber,
    tie-broken by retryId ASC (deterministic).

    Parameters
    ----------
    results     : list to search.
    retry_id    : exact retryId to match.
    policy_id   : exact policyId to match.
    provider_id : exact providerId to match.
    decision    : exact decision to match.

    Returns
    -------
    RetryResult or None
    """
    candidates = filter_retry_results(
        results,
        decision    = decision,
        policy_id   = policy_id,
        provider_id = provider_id,
    )
    if retry_id is not None:
        candidates = [r for r in candidates if r.retryId == retry_id.strip()]
    if not candidates:
        return None
    return min(candidates, key=lambda r: (r.attemptNumber, r.retryId))

# ===========================================================================
# Part B — Utility functions: ProviderStatus
# ===========================================================================

def sort_provider_status(
    statuses : List[ProviderStatus],
    by       : str = "priority",
    ascending: bool = False,
) -> List[ProviderStatus]:
    """
    Return a new sorted list of ProviderStatus objects.

    Sort keys (always tie-broken by providerId ASC)
    -----------------------------------------------
    "priority"    (default) : priority (desc by default), then providerId ASC
    "health"                : health.value, then providerId
    "failureCount"          : failureCount, then providerId
    "successCount"          : successCount, then providerId
    "provider"              : provider, then model, then providerId
    "providerId"            : providerId only

    Parameters
    ----------
    statuses  : list to sort (not mutated).
    by        : sort key name (case-insensitive).
    ascending : True = ascending primary key; default False (highest priority first).

    Returns
    -------
    List[ProviderStatus] — new list.
    """
    key_map: Dict[str, Any] = {
        "priority"     : lambda ps: (ps.priority,      ps.providerId),
        "health"       : lambda ps: (ps.health.value,  ps.providerId),
        "failurecount" : lambda ps: (ps.failureCount,  ps.providerId),
        "successcount" : lambda ps: (ps.successCount,  ps.providerId),
        "provider"     : lambda ps: (ps.provider, ps.model, ps.providerId),
        "providerid"   : lambda ps: (ps.providerId,),
    }
    norm_by = by.strip().lower()
    key_fn  = key_map.get(norm_by, key_map["priority"])
    return sorted(statuses, key=key_fn, reverse=not ascending)


def filter_provider_status(
    statuses: List[ProviderStatus],
    health  : Optional[ProviderHealthEnum] = None,
    provider: Optional[str] = None,
    model   : Optional[str] = None,
    min_priority: Optional[int] = None,
) -> List[ProviderStatus]:
    """
    Return a filtered subset of ProviderStatus objects.

    All supplied filters are AND-combined.

    Parameters
    ----------
    statuses     : list to filter.
    health       : keep only entries with this health state.
    provider     : keep only entries with this provider (case-insensitive).
    model        : keep only entries with this model (case-insensitive).
    min_priority : keep only entries with priority >= this value.

    Returns
    -------
    List[ProviderStatus] — new list.
    """
    out = list(statuses)
    if health is not None:
        out = [ps for ps in out if ps.health == health]
    if provider is not None:
        norm = provider.strip().lower()
        out = [ps for ps in out if ps.provider == norm]
    if model is not None:
        norm = model.strip().lower()
        out = [ps for ps in out if ps.model == norm]
    if min_priority is not None:
        out = [ps for ps in out if ps.priority >= int(min_priority)]
    return out


def group_provider_status(
    statuses: List[ProviderStatus],
    by      : str = "health",
) -> Dict[str, List[ProviderStatus]]:
    """
    Group ProviderStatus objects into a dict keyed by a field value.

    Group keys
    ----------
    "health"    (default) : ProviderHealthEnum.value
    "provider"            : provider name
    "model"               : model name

    Each group list is sorted by (priority DESC, providerId ASC).

    Parameters
    ----------
    statuses : list to group.
    by       : field name (case-insensitive).

    Returns
    -------
    Dict[str, List[ProviderStatus]]
    """
    norm_by = by.strip().lower()
    groups: Dict[str, List[ProviderStatus]] = {}

    for ps in statuses:
        if norm_by == "provider":
            key = ps.provider
        elif norm_by == "model":
            key = ps.model
        else:
            key = ps.health.value
        groups.setdefault(key, []).append(ps)

    for k in groups:
        groups[k] = sorted(groups[k], key=lambda ps: (-ps.priority, ps.providerId))
    return groups


def find_provider_status(
    statuses    : List[ProviderStatus],
    provider_id : Optional[str] = None,
    provider    : Optional[str] = None,
    model       : Optional[str] = None,
    health      : Optional[ProviderHealthEnum] = None,
    min_priority: Optional[int] = None,
) -> Optional[ProviderStatus]:
    """
    Return the first matching ProviderStatus, or None.

    Filters are AND-combined.  "First" is highest priority, tie-broken
    by providerId ASC (deterministic).

    Parameters
    ----------
    statuses    : list to search.
    provider_id : exact providerId to match.
    provider    : provider name (case-insensitive).
    model       : model name (case-insensitive).
    health      : exact health state to match.

    Returns
    -------
    ProviderStatus or None
    """
    candidates = filter_provider_status(
        statuses,
        health       = health,
        provider     = provider,
        model        = model,
        min_priority = min_priority,
    )
    if provider_id is not None:
        candidates = [ps for ps in candidates if ps.providerId == provider_id.strip()]
    if not candidates:
        return None
    # Deterministic: highest priority first, then lexicographically smallest providerId
    return sorted(candidates, key=lambda ps: (-ps.priority, ps.providerId))[0]

# ===========================================================================
# Part B — Extended Statistics (provider success/failure included)
# ===========================================================================

class ExtendedRetryStatistics(BaseModel):
    """
    Extended aggregate statistics pairing RetryResult and ProviderStatus data.

    Adds provider-level success/failure totals and rates on top of the
    base RetryStatistics fields.

    Fields (additions over RetryStatistics)
    ----------------------------------------
    totalProviderSuccesses : sum of successCount across all ProviderStatus objects.
    totalProviderFailures  : sum of failureCount across all ProviderStatus objects.
    providerSuccessRate    : totalProviderSuccesses / (successes + failures).
    providerFailureRate    : totalProviderFailures  / (successes + failures).
    healthyProviders       : count of ProviderStatus with health == HEALTHY.
    degradedProviders      : count of ProviderStatus with health == DEGRADED.
    unavailableProviders   : count of ProviderStatus with health == UNAVAILABLE.
    """
    # Base RetryStatistics fields (duplicated for flat model)
    totalAttempts         : int
    retryCount            : int
    failoverCount         : int
    abortCount            : int
    retryRate             : float
    failoverRate          : float
    abortRate             : float
    averageDelayMs        : float
    uniquePolicies        : Tuple[str, ...]
    uniqueProviders       : Tuple[str, ...]
    uniqueErrorClasses    : Tuple[str, ...]
    # Provider health fields
    totalProviderSuccesses: int
    totalProviderFailures : int
    providerSuccessRate   : float
    providerFailureRate   : float
    healthyProviders      : int
    degradedProviders     : int
    unavailableProviders  : int

    class Config:
        frozen = True


def build_extended_retry_statistics(
    results  : List[RetryResult],
    statuses : Optional[List[ProviderStatus]] = None,
) -> ExtendedRetryStatistics:
    """
    Compute ExtendedRetryStatistics over RetryResult + ProviderStatus lists.

    Deterministic: canonical sort by retryId / providerId ASC before accumulation.

    Parameters
    ----------
    results  : RetryResult objects to aggregate.
    statuses : ProviderStatus snapshots to include in provider metrics
               (may be None/empty).

    Returns
    -------
    ExtendedRetryStatistics (frozen / immutable)
    """
    base = build_retry_statistics(results)
    ps_list = list(statuses or [])

    total_succ = sum(ps.successCount for ps in ps_list)
    total_fail = sum(ps.failureCount for ps in ps_list)
    total_obs  = total_succ + total_fail

    succ_rate = round(total_succ / total_obs, 6) if total_obs > 0 else 0.0
    fail_rate = round(total_fail / total_obs, 6) if total_obs > 0 else 0.0

    healthy_cnt     = sum(1 for ps in ps_list if ps.health == ProviderHealthEnum.HEALTHY)
    degraded_cnt    = sum(1 for ps in ps_list if ps.health == ProviderHealthEnum.DEGRADED)
    unavailable_cnt = sum(1 for ps in ps_list if ps.health == ProviderHealthEnum.UNAVAILABLE)

    return ExtendedRetryStatistics(
        totalAttempts          = base.totalAttempts,
        retryCount             = base.retryCount,
        failoverCount          = base.failoverCount,
        abortCount             = base.abortCount,
        retryRate              = base.retryRate,
        failoverRate           = base.failoverRate,
        abortRate              = base.abortRate,
        averageDelayMs         = base.averageDelayMs,
        uniquePolicies         = base.uniquePolicies,
        uniqueProviders        = base.uniqueProviders,
        uniqueErrorClasses     = base.uniqueErrorClasses,
        totalProviderSuccesses = total_succ,
        totalProviderFailures  = total_fail,
        providerSuccessRate    = succ_rate,
        providerFailureRate    = fail_rate,
        healthyProviders       = healthy_cnt,
        degradedProviders      = degraded_cnt,
        unavailableProviders   = unavailable_cnt,
    )
