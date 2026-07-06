"""
Smoke Test — Retry & Failover Engine (Phase A4.5.3)
====================================================
Target: 650+ assertions, 0 failures.

Sections
--------
 1. Imports & helpers
 2. RetryPolicy builders & validators
 3. ProviderStatus builders & validators
 4. RetryResult builders & validators
 5. RetryStatistics
 6. Deterministic ID helpers (policy_key, provider_key, retry_key, retry_fingerprint)
 7. Retry Engine (should_retry, next_retry_delay, increment_retry_attempt)
 8. Delay calculations — all strategies
 9. Exponential backoff series
10. Provider Health Engine (mark_success/failure, calculate_health, reset)
11. Health transitions (HEALTHY → DEGRADED → UNAVAILABLE → recovery)
12. Failover Engine (build_retry_plan, execute_failover_decision)
13. Provider selection determinism
14. RetryPlan serialisation & immutability
15. Sort utilities — RetryResult
16. Filter utilities — RetryResult
17. Group utilities — RetryResult
18. Find utilities — RetryResult
19. Sort utilities — ProviderStatus
20. Filter utilities — ProviderStatus
21. Group utilities — ProviderStatus
22. Find utilities — ProviderStatus
23. ExtendedRetryStatistics
24. Statistics order-independence
25. Integration helpers
26. Edge cases
27. Zero-randomness guarantee
28. Serialisation & immutability
"""

from __future__ import annotations

import json
from typing import List

from services.retry_failover_service import (
    # Enums
    RetryStrategyEnum, ProviderHealthEnum, RetryDecisionEnum,
    # Exceptions
    RetryFailoverError, InvalidRetryPolicyError,
    InvalidProviderStatusError, InvalidRetryResultError,
    # Models
    RetryPolicy, ProviderStatus, RetryResult, RetryStatistics,
    RetryPlan, ExtendedRetryStatistics,
    # Deterministic helpers
    policy_key, provider_key, retry_key, retry_fingerprint,
    # Builders
    build_retry_policy, build_provider_status,
    build_retry_result, build_retry_statistics,
    build_retry_plan, execute_failover_decision,
    build_extended_retry_statistics,
    # Validators
    validate_retry_policy, validate_provider_status, validate_retry_result,
    # Retry engine
    should_retry, next_retry_delay, increment_retry_attempt,
    # Provider health engine
    mark_provider_success, mark_provider_failure,
    calculate_provider_health, reset_provider_health,
    # Utilities
    sort_retry_results, filter_retry_results, group_retry_results, find_retry_result,
    sort_provider_status, filter_provider_status, group_provider_status, find_provider_status,
    # Integration helpers
    policy_for_execution, execution_provider_status,
    provider_status_from_registry_model, select_failover_provider,
    policy_for_budget_overflow, budget_retry_result,
    # Internal helpers exposed for testing
    _compute_delay,
    _DEGRADED_FAILURE_THRESHOLD,
    _UNAVAILABLE_FAILURE_THRESHOLD,
    _RECOVERY_SUCCESS_THRESHOLD,
)

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------
_passed  = 0
_failed  = 0
_section = ""


def _section_header(name: str) -> None:
    global _section
    _section = name
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")


def _ok(label: str) -> None:
    global _passed
    _passed += 1
    print(f"    [PASS] {label}")


def _fail(label: str, detail: str = "") -> None:
    global _failed
    _failed += 1
    msg = f"    [FAIL] {label}"
    if detail:
        msg += f" — {detail}"
    print(msg)


def chk(condition: bool, label: str, detail: str = "") -> None:
    if condition:
        _ok(label)
    else:
        _fail(label, detail)


def chk_raises(exc_type, fn, label: str) -> None:
    try:
        fn()
        _fail(label, f"expected {exc_type.__name__} not raised")
    except exc_type:
        _ok(label)
    except Exception as e:
        _fail(label, f"wrong exception type {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
TS  = "2026-07-01T00:00:00Z"
TS2 = "2026-07-01T01:00:00Z"
TS3 = "2026-07-01T02:00:00Z"


def _policy(strategy=RetryStrategyEnum.EXPONENTIAL_BACKOFF,
            max_retries=3, delay_ms=1000, backoff=2.0) -> RetryPolicy:
    return build_retry_policy(strategy, TS, max_retries=max_retries,
                               delay_ms=delay_ms, backoff_multiplier=backoff)


def _status(provider="groq", model="llama-3.3-70b-versatile",
            health=ProviderHealthEnum.HEALTHY, priority=50,
            failures=0, successes=0) -> ProviderStatus:
    return build_provider_status(provider, model, TS, health=health,
                                  priority=priority, failure_count=failures,
                                  success_count=successes)


def _result(policy, status, attempt=1,
            decision=RetryDecisionEnum.RETRY,
            error="TimeoutError") -> RetryResult:
    return build_retry_result(policy, status, attempt, decision, error, TS)


# ===========================================================================
# Section 2: RetryPolicy builders & validators
# ===========================================================================
_section_header("2. RetryPolicy builders & validators")

pol = _policy()
chk(len(pol.policyId) == 36,          "policyId is 36-char UUID")
chk(len(pol.policyKey) == 32,         "policyKey is 32-char hex")
chk(pol.strategy == RetryStrategyEnum.EXPONENTIAL_BACKOFF, "strategy stored")
chk(pol.maxRetries == 3,              "maxRetries stored")
chk(pol.delayMilliseconds == 1000,    "delayMs stored")
chk(pol.backoffMultiplier == 2.0,     "backoffMultiplier stored")
chk(pol.createdAt == TS,              "createdAt stored")
chk(isinstance(pol.retryableExceptions, tuple), "retryableExceptions is tuple")

# With retryable exceptions
pol_exc = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS,
                              max_retries=2, delay_ms=500,
                              retryable_exceptions=["Foo", "Bar", "Foo"])
chk(pol_exc.retryableExceptions == ("Bar", "Foo"), "exceptions deduped+sorted")
chk(pol_exc.strategy == RetryStrategyEnum.FIXED_DELAY, "FIXED_DELAY strategy")

# NONE strategy
pol_none = build_retry_policy(RetryStrategyEnum.NONE, TS, max_retries=0, delay_ms=0)
chk(pol_none.maxRetries == 0,         "NONE policy maxRetries=0")
chk(pol_none.strategy == RetryStrategyEnum.NONE, "NONE strategy stored")

# IMMEDIATE strategy
pol_imm = build_retry_policy(RetryStrategyEnum.IMMEDIATE, TS, max_retries=5, delay_ms=0)
chk(pol_imm.strategy == RetryStrategyEnum.IMMEDIATE, "IMMEDIATE strategy")
chk(pol_imm.delayMilliseconds == 0,   "IMMEDIATE delayMs=0")

# Clamping
pol_clamp = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS,
                                max_retries=-1, delay_ms=-100,
                                backoff_multiplier=0.5, validate=False)
chk(pol_clamp.maxRetries == 0,        "maxRetries clamped to 0")
chk(pol_clamp.delayMilliseconds == 0, "delayMs clamped to 0")
chk(pol_clamp.backoffMultiplier == 1.0, "backoffMultiplier clamped to 1.0")

# Validation errors
chk_raises(InvalidRetryPolicyError,
           lambda: validate_retry_policy(RetryStrategyEnum.FIXED_DELAY, -1, 0, 1.0, TS),
           "validate: negative maxRetries raises")
chk_raises(InvalidRetryPolicyError,
           lambda: validate_retry_policy(RetryStrategyEnum.FIXED_DELAY, 1, -5, 1.0, TS),
           "validate: negative delayMs raises")
chk_raises(InvalidRetryPolicyError,
           lambda: validate_retry_policy(RetryStrategyEnum.FIXED_DELAY, 1, 0, 0.9, TS),
           "validate: backoffMultiplier < 1.0 raises")
chk_raises(InvalidRetryPolicyError,
           lambda: validate_retry_policy(RetryStrategyEnum.FIXED_DELAY, 1, 0, 1.0, ""),
           "validate: empty createdAt raises")

# Frozen / immutable
try:
    pol.maxRetries = 99  # type: ignore
    chk(False, "RetryPolicy is NOT immutable")
except Exception:
    chk(True, "RetryPolicy is immutable (frozen)")


# ===========================================================================
# Section 3: ProviderStatus builders & validators
# ===========================================================================
_section_header("3. ProviderStatus builders & validators")

ps = _status()
chk(len(ps.providerId) == 36,         "providerId is 36-char UUID")
chk(len(ps.providerKey) == 32,        "providerKey is 32-char hex")
chk(ps.provider == "groq",            "provider stored+normalised")
chk(ps.model == "llama-3.3-70b-versatile", "model stored")
chk(ps.health == ProviderHealthEnum.HEALTHY, "health default HEALTHY")
chk(ps.priority == 50,                "priority stored")
chk(ps.failureCount == 0,             "failureCount default 0")
chk(ps.successCount == 0,             "successCount default 0")
chk(ps.lastFailureAt == "",           "lastFailureAt default empty")
chk(ps.createdAt == TS,               "createdAt stored")

# Normalisation
ps_upper = build_provider_status("GROQ", "  LLAMA-3.3-70B-VERSATILE  ", TS)
chk(ps_upper.provider == "groq",      "provider normalised to lowercase")
chk(ps_upper.model == "llama-3.3-70b-versatile", "model normalised")

# DEGRADED / UNAVAILABLE
ps_deg  = _status(health=ProviderHealthEnum.DEGRADED,    priority=30)
ps_unav = _status(health=ProviderHealthEnum.UNAVAILABLE, priority=10)
chk(ps_deg.health  == ProviderHealthEnum.DEGRADED,    "DEGRADED health stored")
chk(ps_unav.health == ProviderHealthEnum.UNAVAILABLE, "UNAVAILABLE health stored")

# With lastFailureAt
ps_fail = build_provider_status("openai", "gpt-4", TS,
                                 failure_count=2, success_count=1,
                                 last_failure_at=TS2)
chk(ps_fail.failureCount   == 2,  "failureCount stored")
chk(ps_fail.successCount   == 1,  "successCount stored")
chk(ps_fail.lastFailureAt  == TS2,"lastFailureAt stored")

# Validation errors
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("", "gpt-4", ProviderHealthEnum.HEALTHY, 0, 0, 0, TS),
           "validate: empty provider raises")
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("groq", "", ProviderHealthEnum.HEALTHY, 0, 0, 0, TS),
           "validate: empty model raises")
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("groq", "m", ProviderHealthEnum.HEALTHY, -1, 0, 0, TS),
           "validate: negative priority raises")
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("groq", "m", ProviderHealthEnum.HEALTHY, 0, -1, 0, TS),
           "validate: negative failureCount raises")
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("groq", "m", ProviderHealthEnum.HEALTHY, 0, 0, -1, TS),
           "validate: negative successCount raises")
chk_raises(InvalidProviderStatusError,
           lambda: validate_provider_status("groq", "m", ProviderHealthEnum.HEALTHY, 0, 0, 0, ""),
           "validate: empty createdAt raises")

# Frozen
try:
    ps.priority = 99  # type: ignore
    chk(False, "ProviderStatus is NOT immutable")
except Exception:
    chk(True, "ProviderStatus is immutable (frozen)")


# ===========================================================================
# Section 4: RetryResult builders & validators
# ===========================================================================
_section_header("4. RetryResult builders & validators")

pol4 = _policy()
ps4  = _status()
rr   = _result(pol4, ps4, attempt=1, decision=RetryDecisionEnum.RETRY)

chk(len(rr.retryId) == 36,            "retryId is 36-char UUID")
chk(len(rr.retryKey) == 32,           "retryKey is 32-char hex")
chk(len(rr.retryFingerprint) == 32,   "retryFingerprint is 32-char hex")
chk(rr.policyId    == pol4.policyId,  "policyId stored")
chk(rr.providerId  == ps4.providerId, "providerId stored")
chk(rr.attemptNumber == 1,            "attemptNumber stored")
chk(rr.maxAttempts == 4,              "maxAttempts = maxRetries+1")
chk(rr.decision    == RetryDecisionEnum.RETRY, "decision stored")
chk(rr.errorClass  == "TimeoutError", "errorClass stored")
chk(rr.failoverProvider == "",        "failoverProvider default empty")
chk(rr.engineVersion.startswith("retry-failover"), "engineVersion correct prefix")

# FAILOVER result with failover_provider
rr_fo = build_retry_result(pol4, ps4, 4, RetryDecisionEnum.FAILOVER,
                            "ProviderError", TS, failover_provider="alt-id-123")
chk(rr_fo.failoverProvider == "alt-id-123", "failoverProvider stored")
chk(rr_fo.decision == RetryDecisionEnum.FAILOVER, "FAILOVER decision stored")

# ABORT
rr_ab = build_retry_result(pol4, ps4, 4, RetryDecisionEnum.ABORT, "FatalError", TS)
chk(rr_ab.decision == RetryDecisionEnum.ABORT, "ABORT decision stored")

# Validation errors
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result("", ps4.providerId, 1, 4,
                                         RetryDecisionEnum.RETRY, 0, "E", TS),
           "validate: empty policyId raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, "", 1, 4,
                                         RetryDecisionEnum.RETRY, 0, "E", TS),
           "validate: empty providerId raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, ps4.providerId, 0, 4,
                                         RetryDecisionEnum.RETRY, 0, "E", TS),
           "validate: attemptNumber=0 raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, ps4.providerId, 5, 4,
                                         RetryDecisionEnum.RETRY, 0, "E", TS),
           "validate: attemptNumber > maxAttempts raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, ps4.providerId, 1, 4,
                                         RetryDecisionEnum.RETRY, -1, "E", TS),
           "validate: negative delayMs raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, ps4.providerId, 1, 4,
                                         RetryDecisionEnum.RETRY, 0, "", TS),
           "validate: empty errorClass raises")
chk_raises(InvalidRetryResultError,
           lambda: validate_retry_result(pol4.policyId, ps4.providerId, 1, 4,
                                         RetryDecisionEnum.RETRY, 0, "E", ""),
           "validate: empty createdAt raises")

# Frozen
try:
    rr.attemptNumber = 99  # type: ignore
    chk(False, "RetryResult is NOT immutable")
except Exception:
    chk(True, "RetryResult is immutable (frozen)")


# ===========================================================================
# Section 5: RetryStatistics
# ===========================================================================
_section_header("5. RetryStatistics")

pol5 = _policy()
ps5  = _status()

rr_r  = _result(pol5, ps5, 1, RetryDecisionEnum.RETRY)
rr_f  = _result(pol5, ps5, 2, RetryDecisionEnum.FAILOVER, "ProviderError")
rr_a  = _result(pol5, ps5, 3, RetryDecisionEnum.ABORT,    "FatalError")
rr_r2 = _result(pol5, ps5, 4, RetryDecisionEnum.RETRY)

stats = build_retry_statistics([rr_r, rr_f, rr_a, rr_r2])
chk(stats.totalAttempts  == 4,     "totalAttempts=4")
chk(stats.retryCount     == 2,     "retryCount=2")
chk(stats.failoverCount  == 1,     "failoverCount=1")
chk(stats.abortCount     == 1,     "abortCount=1")
chk(abs(stats.retryRate    - 0.5)  < 1e-6, "retryRate=0.5")
chk(abs(stats.failoverRate - 0.25) < 1e-6, "failoverRate=0.25")
chk(abs(stats.abortRate    - 0.25) < 1e-6, "abortRate=0.25")
chk(len(stats.uniquePolicies)  == 1, "uniquePolicies deduped")
chk(len(stats.uniqueProviders) == 1, "uniqueProviders deduped")
chk(len(stats.uniqueErrorClasses) == 3, "uniqueErrorClasses=3")
chk("TimeoutError"   in stats.uniqueErrorClasses, "TimeoutError in uniqueErrorClasses")
chk("ProviderError"  in stats.uniqueErrorClasses, "ProviderError in uniqueErrorClasses")
chk("FatalError"     in stats.uniqueErrorClasses, "FatalError in uniqueErrorClasses")

# Empty list
empty_stats = build_retry_statistics([])
chk(empty_stats.totalAttempts == 0,  "empty: totalAttempts=0")
chk(empty_stats.retryRate     == 0.0,"empty: retryRate=0.0")
chk(empty_stats.uniquePolicies == (), "empty: uniquePolicies=()")

# averageDelayMs
pol_exp = _policy(strategy=RetryStrategyEnum.EXPONENTIAL_BACKOFF,
                  max_retries=4, delay_ms=100, backoff=2.0)
rrs_delays = [_result(pol_exp, ps5, i, RetryDecisionEnum.RETRY) for i in range(1, 4)]
# delays: attempt1→100, attempt2→200, attempt3→400 (next-attempt delays)
# but _compute_delay uses current attempt_number: 1→100, 2→200, 3→400
delay_stats = build_retry_statistics(rrs_delays)
chk(delay_stats.totalAttempts == 3, "delay stats totalAttempts=3")
chk(delay_stats.averageDelayMs > 0, "averageDelayMs > 0 for exp backoff")

# Frozen
try:
    stats.totalAttempts = 99  # type: ignore
    chk(False, "RetryStatistics is NOT immutable")
except Exception:
    chk(True, "RetryStatistics is immutable (frozen)")


# ===========================================================================
# Section 6: Deterministic ID helpers
# ===========================================================================
_section_header("6. Deterministic ID helpers")

# policy_key — same inputs → same output
pk1 = policy_key("EXPONENTIAL_BACKOFF", 3, 1000, 2.0)
pk2 = policy_key("EXPONENTIAL_BACKOFF", 3, 1000, 2.0)
chk(pk1 == pk2,              "policy_key is deterministic")
chk(len(pk1) == 32,          "policy_key length=32")

# Different inputs → different keys
pk3 = policy_key("FIXED_DELAY", 3, 1000, 2.0)
chk(pk1 != pk3,              "policy_key: strategy change produces different key")
pk4 = policy_key("EXPONENTIAL_BACKOFF", 4, 1000, 2.0)
chk(pk1 != pk4,              "policy_key: maxRetries change produces different key")
pk5 = policy_key("EXPONENTIAL_BACKOFF", 3, 500, 2.0)
chk(pk1 != pk5,              "policy_key: delayMs change produces different key")
pk6 = policy_key("EXPONENTIAL_BACKOFF", 3, 1000, 3.0)
chk(pk1 != pk6,              "policy_key: backoff change produces different key")

# provider_key
pvk1 = provider_key("groq", "llama-3.3-70b-versatile")
pvk2 = provider_key("groq", "llama-3.3-70b-versatile")
chk(pvk1 == pvk2,            "provider_key is deterministic")
chk(len(pvk1) == 32,         "provider_key length=32")
pvk3 = provider_key("openai", "gpt-4")
chk(pvk1 != pvk3,            "provider_key: different provider/model")

# provider_key is case-insensitive (normalised internally)
pvk_up = provider_key("GROQ", "LLAMA-3.3-70B-VERSATILE")
chk(pvk1 == pvk_up,          "provider_key normalises case")

# retry_key
rk1 = retry_key("pid1", "pvid1", 1, "RETRY")
rk2 = retry_key("pid1", "pvid1", 1, "RETRY")
chk(rk1 == rk2,              "retry_key is deterministic")
chk(len(rk1) == 32,          "retry_key length=32")
rk3 = retry_key("pid1", "pvid1", 2, "RETRY")
chk(rk1 != rk3,              "retry_key: different attempt is different")
rk4 = retry_key("pid1", "pvid1", 1, "ABORT")
chk(rk1 != rk4,              "retry_key: different decision is different")

# retry_fingerprint
rfp1 = retry_fingerprint(rk1, "TimeoutError", 1)
rfp2 = retry_fingerprint(rk1, "TimeoutError", 1)
chk(rfp1 == rfp2,            "retry_fingerprint is deterministic")
chk(len(rfp1) == 32,         "retry_fingerprint length=32")
rfp3 = retry_fingerprint(rk1, "OtherError", 1)
chk(rfp1 != rfp3,            "retry_fingerprint: different errorClass")

# Policy IDs are deterministic across builds
pol_a = _policy()
pol_b = _policy()
chk(pol_a.policyId == pol_b.policyId, "policyId deterministic across builds")

# Provider IDs are deterministic across builds
ps_a = _status()
ps_b = _status()
chk(ps_a.providerId == ps_b.providerId, "providerId deterministic across builds")

# RetryResult IDs are deterministic across builds
rr_a2 = _result(pol_a, ps_a, 1, RetryDecisionEnum.RETRY)
rr_b2 = _result(pol_b, ps_b, 1, RetryDecisionEnum.RETRY)
chk(rr_a2.retryId == rr_b2.retryId,            "retryId deterministic across builds")
chk(rr_a2.retryFingerprint == rr_b2.retryFingerprint, "retryFingerprint deterministic")


# ===========================================================================
# Section 7: Retry Engine — should_retry, next_retry_delay, increment
# ===========================================================================
_section_header("7. Retry Engine")

pol7 = _policy(max_retries=3)

# should_retry: NONE strategy always False
pol_none7 = build_retry_policy(RetryStrategyEnum.NONE, TS, max_retries=5, delay_ms=0)
chk(should_retry(pol_none7, 1) is False, "NONE strategy: attempt 1 → no retry")
chk(should_retry(pol_none7, 5) is False, "NONE strategy: attempt 5 → no retry")

# should_retry: maxRetries=3 → maxAttempts=4; attempt >= 4 is exhausted
chk(should_retry(pol7, 4) is False, "exhausted at maxAttempts: attempt=4 (==maxAttempts) -> False")
chk(should_retry(pol7, 5) is False, "exhausted: attempt=5 > maxAttempts -> False")

# should_retry: within budget (maxRetries=3, maxAttempts=4, attempts 1-3 are within)
chk(should_retry(pol7, 1) is True,  "within budget: attempt=1 -> True")
chk(should_retry(pol7, 2) is True,  "within budget: attempt=2 -> True")
chk(should_retry(pol7, 3) is True,  "within budget: attempt=3 -> True (< maxAttempts=4)")

# should_retry: retryableExceptions filter
pol7_exc = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=3,
                               retryable_exceptions=["AllowedError"])
chk(should_retry(pol7_exc, 1, "AllowedError") is True,  "allowed exception → True")
chk(should_retry(pol7_exc, 1, "BannedError")  is False, "banned exception → False")
chk(should_retry(pol7_exc, 1, "")             is True,  "empty error_class skips filter → True")

# next_retry_delay
pol_fd = _policy(strategy=RetryStrategyEnum.FIXED_DELAY, delay_ms=250)
d1 = next_retry_delay(pol_fd, 1)
d2 = next_retry_delay(pol_fd, 2)
d3 = next_retry_delay(pol_fd, 3)
chk(d1 == 250, "FIXED_DELAY: next delay always 250 (attempt 1→2)")
chk(d2 == 250, "FIXED_DELAY: next delay always 250 (attempt 2→3)")
chk(d3 == 250, "FIXED_DELAY: next delay always 250 (attempt 3→4)")

pol_imm7 = _policy(strategy=RetryStrategyEnum.IMMEDIATE)
chk(next_retry_delay(pol_imm7, 1) == 0, "IMMEDIATE: next delay=0")

# increment_retry_attempt: attempt=1 → 2 (within budget)
ps7  = _status()
rr7  = _result(pol7, ps7, 1, RetryDecisionEnum.RETRY)
rr7b = increment_retry_attempt(rr7, pol7, TS2)
chk(rr7b.attemptNumber == 2,               "increment: attemptNumber=2")
chk(rr7b.decision == RetryDecisionEnum.RETRY, "increment: still RETRY within budget")
chk(rr7b.errorClass == rr7.errorClass,     "increment: errorClass preserved")
chk(rr7b.retryId != rr7.retryId,           "increment: new retryId")

# increment attempt=2 → 3 (still within budget: attempt 3 < maxAttempts 4)
rr7c = increment_retry_attempt(rr7b, pol7, TS2)
chk(rr7c.attemptNumber == 3,               "increment: attemptNumber=3")
chk(rr7c.decision == RetryDecisionEnum.RETRY, "increment: attempt 3 still RETRY (< maxAttempts=4)")

# increment attempt=3 → 4 (attempt 4 == maxAttempts=4 → exhausted → ABORT)
rr7d = increment_retry_attempt(rr7c, pol7, TS2)
chk(rr7d.attemptNumber == 4,               "increment: attemptNumber=4")
chk(rr7d.decision == RetryDecisionEnum.ABORT, "increment: attempt=4 == maxAttempts -> ABORT")


# ===========================================================================
# Section 8 & 9: Delay calculations — all strategies + exponential backoff
# ===========================================================================
_section_header("8 & 9. Delay calculations & exponential backoff")

# NONE
pol_n = build_retry_policy(RetryStrategyEnum.NONE, TS, delay_ms=500)
chk(_compute_delay(pol_n, 1) == 0, "NONE: delay=0")
chk(_compute_delay(pol_n, 3) == 0, "NONE: delay=0 any attempt")

# IMMEDIATE
pol_i = build_retry_policy(RetryStrategyEnum.IMMEDIATE, TS, delay_ms=999)
chk(_compute_delay(pol_i, 1) == 0, "IMMEDIATE: delay=0")
chk(_compute_delay(pol_i, 5) == 0, "IMMEDIATE: delay=0 any attempt")

# FIXED_DELAY
pol_f = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, delay_ms=300)
chk(_compute_delay(pol_f, 1) == 300, "FIXED: attempt 1 → 300ms")
chk(_compute_delay(pol_f, 2) == 300, "FIXED: attempt 2 → 300ms")
chk(_compute_delay(pol_f, 5) == 300, "FIXED: attempt 5 → 300ms")

# EXPONENTIAL_BACKOFF — base=100, multiplier=2
pol_e = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                            delay_ms=100, backoff_multiplier=2.0)
# attempt 1: 100 * 2^0 = 100
# attempt 2: 100 * 2^1 = 200
# attempt 3: 100 * 2^2 = 400
# attempt 4: 100 * 2^3 = 800
chk(_compute_delay(pol_e, 1) == 100,  "EXP: attempt 1 → 100ms")
chk(_compute_delay(pol_e, 2) == 200,  "EXP: attempt 2 → 200ms")
chk(_compute_delay(pol_e, 3) == 400,  "EXP: attempt 3 → 400ms")
chk(_compute_delay(pol_e, 4) == 800,  "EXP: attempt 4 → 800ms")
chk(_compute_delay(pol_e, 5) == 1600, "EXP: attempt 5 → 1600ms")

# EXP with multiplier=3
pol_e3 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                             delay_ms=50, backoff_multiplier=3.0)
chk(_compute_delay(pol_e3, 1) == 50,   "EXP x3: attempt 1 → 50ms")
chk(_compute_delay(pol_e3, 2) == 150,  "EXP x3: attempt 2 → 150ms")
chk(_compute_delay(pol_e3, 3) == 450,  "EXP x3: attempt 3 → 450ms")

# EXP with multiplier=1.0 (no growth)
pol_e1 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                             delay_ms=200, backoff_multiplier=1.0)
chk(_compute_delay(pol_e1, 1) == 200,  "EXP x1: attempt 1 → 200ms")
chk(_compute_delay(pol_e1, 3) == 200,  "EXP x1: attempt 3 → 200ms (no growth)")

# EXP with zero base delay
pol_e0 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                             delay_ms=0, backoff_multiplier=2.0)
chk(_compute_delay(pol_e0, 1) == 0, "EXP zero base: delay=0")
chk(_compute_delay(pol_e0, 5) == 0, "EXP zero base: delay=0 any attempt")

# Determinism: same inputs → same delays
chk(_compute_delay(pol_e, 3) == _compute_delay(pol_e, 3), "EXP delay deterministic")

# Built RetryResults carry correct delays
ps9 = _status()
rr9_1 = build_retry_result(pol_e, ps9, 1, RetryDecisionEnum.RETRY, "E", TS)
rr9_2 = build_retry_result(pol_e, ps9, 2, RetryDecisionEnum.RETRY, "E", TS)
rr9_3 = build_retry_result(pol_e, ps9, 3, RetryDecisionEnum.RETRY, "E", TS)
chk(rr9_1.delayMilliseconds == 100,  "built result: delay attempt 1 = 100")
chk(rr9_2.delayMilliseconds == 200,  "built result: delay attempt 2 = 200")
chk(rr9_3.delayMilliseconds == 400,  "built result: delay attempt 3 = 400")


# ===========================================================================
# Section 10: Provider Health Engine
# ===========================================================================
_section_header("10. Provider Health Engine — calculate_provider_health")

H  = ProviderHealthEnum.HEALTHY
D  = ProviderHealthEnum.DEGRADED
U  = ProviderHealthEnum.UNAVAILABLE

# Thresholds
DFAIL = _DEGRADED_FAILURE_THRESHOLD
UFAIL = _UNAVAILABLE_FAILURE_THRESHOLD
RSUCC = _RECOVERY_SUCCESS_THRESHOLD

chk(DFAIL < UFAIL,    "DEGRADED threshold < UNAVAILABLE threshold")
chk(RSUCC >= 1,       "RECOVERY threshold >= 1")

# Pure calculate_provider_health
chk(calculate_provider_health(0, 0) == H,    "0 fail 0 succ → HEALTHY")
chk(calculate_provider_health(1, 0) == H,    "1 fail → HEALTHY (below DEGRADED)")
chk(calculate_provider_health(2, 0) == H,    "2 fail → HEALTHY")
chk(calculate_provider_health(DFAIL, 0) == D, f"{DFAIL} fail → DEGRADED")
chk(calculate_provider_health(DFAIL+1, 0) == D, f"{DFAIL+1} fail → DEGRADED")
chk(calculate_provider_health(UFAIL, 0) == U,  f"{UFAIL} fail → UNAVAILABLE")
chk(calculate_provider_health(UFAIL+5, 0) == U, "many failures → UNAVAILABLE")

# Recovery: DEGRADED + enough successes → HEALTHY
chk(calculate_provider_health(DFAIL, RSUCC) == H,
    f"DEGRADED recovers with {RSUCC} successes → HEALTHY")
chk(calculate_provider_health(DFAIL, RSUCC-1) == D,
    f"DEGRADED with {RSUCC-1} successes stays DEGRADED")

# UNAVAILABLE does NOT recover via calculate_provider_health alone
# (requires reset_provider_health or explicit override)
chk(calculate_provider_health(UFAIL, RSUCC) == U,
    "UNAVAILABLE does not recover via calculate alone")

# mark_provider_success
ps10 = _status(failures=0, successes=0)
ps10a = mark_provider_success(ps10, TS2)
chk(ps10a.successCount == 1,           "mark_success: successCount+1")
chk(ps10a.failureCount == 0,           "mark_success: failureCount unchanged")
chk(ps10a.health == H,                 "mark_success from HEALTHY stays HEALTHY")
chk(ps10a.providerId == ps10.providerId, "mark_success: same providerId")
chk(ps10a is not ps10,                 "mark_success: new object (immutable)")

# mark_provider_failure
ps10b = mark_provider_failure(ps10, TS2)
chk(ps10b.failureCount == 1,           "mark_failure: failureCount+1")
chk(ps10b.successCount == 0,           "mark_failure: successCount reset to 0")
chk(ps10b.health == H,                 "1 failure stays HEALTHY")
chk(ps10b is not ps10,                 "mark_failure: new object")

# lastFailureAt default to created_at
ps10c = mark_provider_failure(ps10, TS2)
chk(ps10c.lastFailureAt == TS2,        "mark_failure: lastFailureAt = created_at")

# lastFailureAt explicit
ps10d = mark_provider_failure(ps10, TS2, last_failure_at=TS3)
chk(ps10d.lastFailureAt == TS3,        "mark_failure: lastFailureAt explicit")

# reset_provider_health
ps10e = _status(failures=10, successes=0, health=ProviderHealthEnum.UNAVAILABLE)
ps10f = reset_provider_health(ps10e, TS2)
chk(ps10f.health       == H,           "reset: health → HEALTHY")
chk(ps10f.failureCount == 0,           "reset: failureCount=0")
chk(ps10f.successCount == 0,           "reset: successCount=0")
chk(ps10f.lastFailureAt == "",         "reset: lastFailureAt cleared")
chk(ps10f.providerId == ps10e.providerId, "reset: same providerId")


# ===========================================================================
# Section 11: Health transitions (HEALTHY → DEGRADED → UNAVAILABLE → recovery)
# ===========================================================================
_section_header("11. Health transitions")

ps_t = _status(failures=0, successes=0)

# Drive through failure transitions
for i in range(1, UFAIL + 2):
    ps_t = mark_provider_failure(ps_t, TS)

chk(ps_t.failureCount == UFAIL + 1,   f"after {UFAIL+1} failures: failureCount correct")
chk(ps_t.health == U,                  "after enough failures: UNAVAILABLE")

# Explicit reset brings back HEALTHY
ps_t_reset = reset_provider_health(ps_t, TS2)
chk(ps_t_reset.health       == H,      "after reset: HEALTHY")
chk(ps_t_reset.failureCount == 0,      "after reset: failureCount=0")
chk(ps_t_reset.successCount == 0,      "after reset: successCount=0")

# Gradual HEALTHY → DEGRADED
ps_d = _status()
for _ in range(DFAIL):
    ps_d = mark_provider_failure(ps_d, TS)
chk(ps_d.health == D, f"after {DFAIL} failures: DEGRADED")
chk(ps_d.failureCount == DFAIL, "failureCount == DFAIL after transition")

# Recovery from DEGRADED via successes
ps_dr = ps_d
for _ in range(RSUCC):
    ps_dr = mark_provider_success(ps_dr, TS2)
chk(ps_dr.health == H, "DEGRADED recovers after enough successes")
chk(ps_dr.successCount == RSUCC, "successCount accumulated during recovery")

# Partial recovery (one less success) stays DEGRADED
ps_partial = _status(failures=DFAIL, successes=0, health=D)
for _ in range(RSUCC - 1):
    ps_partial = mark_provider_success(ps_partial, TS2)
chk(ps_partial.health == D, "partial recovery: still DEGRADED")

# Failure resets recovery counter
ps_reset_rec = _status(failures=DFAIL, successes=0, health=D)
ps_reset_rec = mark_provider_success(ps_reset_rec, TS2)  # 1 success
ps_reset_rec = mark_provider_failure(ps_reset_rec, TS2)  # failure resets succ
chk(ps_reset_rec.successCount == 0, "failure resets successCount (recovery counter)")

# HEALTHY → 1 failure → HEALTHY (under threshold)
ps_one_fail = _status()
ps_one_fail = mark_provider_failure(ps_one_fail, TS2)
chk(ps_one_fail.health == H, "1 failure from HEALTHY stays HEALTHY")

# Transitions emit deterministic providerId
ps_same_id = _status()
ps_same_id2 = mark_provider_failure(ps_same_id, TS2)
chk(ps_same_id.providerId == ps_same_id2.providerId,
    "providerId preserved across health transitions")


# ===========================================================================
# Section 12: Failover Engine
# ===========================================================================
_section_header("12. Failover Engine — build_retry_plan, execute_failover_decision")

pol12 = _policy(max_retries=3)
ps_primary   = _status("groq",      "llama-3.3-70b-versatile",  priority=80)
ps_healthy   = _status("openai",    "gpt-4",  health=H,          priority=60)
ps_degraded  = _status("anthropic", "claude", health=D,          priority=50)
ps_unavail   = _status("google",    "gemini", health=U,          priority=40)

all_statuses = [ps_primary, ps_healthy, ps_degraded, ps_unavail]

# Attempt 1 — should retry (within budget, policy allows)
plan12a = build_retry_plan(pol12, ps_primary, 1, "TimeoutError", TS,
                            all_statuses, "timeout")
chk(plan12a.decision == RetryDecisionEnum.RETRY,       "plan attempt 1 → RETRY")
chk(plan12a.failoverProviderId == "",                  "plan RETRY: no failover provider")
chk(plan12a.delayMilliseconds > 0,                     "plan RETRY: delay > 0")
chk(plan12a.policyId == pol12.policyId,                "plan policyId stored")
chk(plan12a.primaryProviderId == ps_primary.providerId,"plan primaryProviderId stored")
chk(plan12a.errorClass == "TimeoutError",              "plan errorClass stored")
chk(len(plan12a.planId) == 36,                         "plan planId is UUID")
chk(len(plan12a.planKey) == 32,                        "plan planKey length=32")
chk(plan12a.maxAttempts == 4,                          "plan maxAttempts=4")

# Attempt 4 (==maxAttempts=4) — exhausted -> should failover to ps_healthy
plan12b = build_retry_plan(pol12, ps_primary, 4, "TimeoutError", TS,
                            all_statuses, "timeout")
chk(plan12b.decision == RetryDecisionEnum.FAILOVER,    "attempt 4 exhausted -> FAILOVER")
chk(plan12b.failoverProviderId == ps_healthy.providerId,
    "failover selects highest-priority HEALTHY non-primary")

# Attempt 4 — no healthy candidates -> ABORT
plan12c = build_retry_plan(pol12, ps_primary, 4, "TimeoutError", TS,
                            [ps_primary, ps_degraded, ps_unavail])
chk(plan12c.decision == RetryDecisionEnum.ABORT,       "no healthy candidates -> ABORT")
chk(plan12c.failoverProviderId == "",                  "ABORT: no failoverProviderId")

# No provider list provided -> ABORT when exhausted
plan12d = build_retry_plan(pol12, ps_primary, 4, "TimeoutError", TS)
chk(plan12d.decision == RetryDecisionEnum.ABORT,       "None provider list -> ABORT when exhausted")

# execute_failover_decision materialises the plan
result12 = execute_failover_decision(plan12a, pol12, ps_primary, TS, all_statuses)
chk(isinstance(result12, RetryResult),                 "execute returns RetryResult")
chk(result12.decision == RetryDecisionEnum.RETRY,      "execute preserves RETRY decision")
chk(result12.policyId == pol12.policyId,               "execute retryResult.policyId correct")
chk(result12.providerId == ps_primary.providerId,      "execute retryResult.providerId correct")

result12b = execute_failover_decision(plan12b, pol12, ps_primary, TS, all_statuses)
chk(result12b.decision == RetryDecisionEnum.FAILOVER,  "execute preserves FAILOVER decision")
chk(result12b.failoverProvider == ps_healthy.providerId,"execute failoverProvider correct")

# RetryPlan is frozen
try:
    plan12a.decision = RetryDecisionEnum.ABORT  # type: ignore
    chk(False, "RetryPlan is NOT immutable")
except Exception:
    chk(True, "RetryPlan is immutable (frozen)")


# ===========================================================================
# Section 13: Provider selection determinism
# ===========================================================================
_section_header("13. Provider selection determinism")

ps_a13 = _status("openai",    "gpt-4",   priority=70)
ps_b13 = _status("anthropic", "claude",  priority=70)  # same priority
ps_c13 = _status("groq",      "llama",   priority=80)
ps_d13 = _status("google",    "gemini",  priority=60)
ps_prim = _status("azure",    "gpt-35",  priority=90)

statuses_13 = [ps_a13, ps_b13, ps_c13, ps_d13, ps_prim]

# select_failover_provider — stable tie-breaking by providerId
sel1 = select_failover_provider(ps_prim.providerId, statuses_13)
sel2 = select_failover_provider(ps_prim.providerId, statuses_13)
chk(sel1 is not None,           "selection finds a candidate")
chk(sel1.providerId == sel2.providerId, "selection is deterministic")
chk(sel1.provider   == "groq",  "highest priority (80) selected")

# After removing highest, next is one of the priority-70 pair
statuses_13b = [ps_a13, ps_b13, ps_d13, ps_prim]
sel3 = select_failover_provider(ps_prim.providerId, statuses_13b)
chk(sel3 is not None, "tie-breaking: candidate found")
# The alphabetically smaller providerId wins the tie
sel4 = select_failover_provider(ps_prim.providerId, statuses_13b)
chk(sel3.providerId == sel4.providerId, "tie-breaking: deterministic")

# No healthy candidates returns None
ps_all_bad = [
    _status("x", "m1", health=D),
    _status("y", "m2", health=U),
]
chk(select_failover_provider("any", ps_all_bad) is None,
    "all degraded/unavailable → None")

# Self excluded even if highest priority
chk(select_failover_provider(ps_c13.providerId, [ps_c13]) is None,
    "self-only list → None")

# Only current provider excluded, not all
chk(select_failover_provider(ps_prim.providerId, [ps_prim, ps_c13]) is not None,
    "non-self healthy provider found")

# Determinism across different orderings of input list
import random as _random_module
shuffled = list(statuses_13)
# manual shuffle without random: reverse
shuffled2 = list(reversed(statuses_13))
sel5 = select_failover_provider(ps_prim.providerId, shuffled)
sel6 = select_failover_provider(ps_prim.providerId, shuffled2)
chk(sel5.providerId == sel6.providerId, "selection deterministic regardless of input order")


# ===========================================================================
# Section 14: RetryPlan serialisation & immutability
# ===========================================================================
_section_header("14. RetryPlan serialisation & immutability")

pol14 = _policy()
ps14  = _status()
plan14 = build_retry_plan(pol14, ps14, 1, "E", TS,
                           [ps14, _status("openai", "gpt-4", priority=60)])

# dict / JSON round-trip
d14 = plan14.model_dump()
chk(isinstance(d14, dict),               "plan.model_dump() returns dict")
chk("planId" in d14,                     "planId in dict")
chk("decision" in d14,                   "decision in dict")
chk(d14["engineVersion"].startswith("retry-failover"), "engineVersion in dict")

j14 = plan14.model_dump_json()
chk(isinstance(j14, str),                "plan.model_dump_json() returns str")
obj14 = json.loads(j14)
chk(obj14["planId"] == plan14.planId,    "json round-trip planId")
chk(obj14["policyId"] == plan14.policyId,"json round-trip policyId")

# Rebuild from dict
plan14b = RetryPlan(**d14)
chk(plan14b.planId == plan14.planId,     "rebuild from dict: planId matches")
chk(plan14b.decision == plan14.decision, "rebuild from dict: decision matches")

# Immutability
try:
    plan14.errorClass = "mutated"  # type: ignore
    chk(False, "RetryPlan allows mutation — WRONG")
except Exception:
    chk(True, "RetryPlan is frozen")

# planKey determinism
plan14c = build_retry_plan(pol14, ps14, 1, "E", TS2)
chk(plan14.planKey == plan14c.planKey,   "planKey deterministic (timestamp ignored)")
chk(plan14.planId  == plan14c.planId,    "planId deterministic (timestamp ignored)")


# ===========================================================================
# Section 15: sort_retry_results
# ===========================================================================
_section_header("15. sort_retry_results")

pol15 = _policy(strategy=RetryStrategyEnum.EXPONENTIAL_BACKOFF,
                max_retries=5, delay_ms=100, backoff=2.0)
ps15  = _status()
rrs15 = [
    build_retry_result(pol15, ps15, 3, RetryDecisionEnum.ABORT,    "E3", TS),
    build_retry_result(pol15, ps15, 1, RetryDecisionEnum.RETRY,    "E1", TS),
    build_retry_result(pol15, ps15, 2, RetryDecisionEnum.FAILOVER, "E2", TS),
    build_retry_result(pol15, ps15, 5, RetryDecisionEnum.RETRY,    "E5", TS),
    build_retry_result(pol15, ps15, 4, RetryDecisionEnum.ABORT,    "E4", TS),
]

# Sort by attemptNumber ascending (default)
s_asc = sort_retry_results(rrs15, by="attemptNumber", ascending=True)
chk(s_asc[0].attemptNumber == 1,           "sort ASC: first=1")
chk(s_asc[-1].attemptNumber == 5,          "sort ASC: last=5")
chk([r.attemptNumber for r in s_asc] == [1,2,3,4,5], "sort ASC: correct order")

# Sort descending
s_desc = sort_retry_results(rrs15, by="attemptNumber", ascending=False)
chk(s_desc[0].attemptNumber == 5,          "sort DESC: first=5")
chk(s_desc[-1].attemptNumber == 1,         "sort DESC: last=1")

# Sort by decision
s_dec = sort_retry_results(rrs15, by="decision", ascending=True)
decisions = [r.decision.value for r in s_dec]
chk(decisions == sorted(decisions),        "sort by decision: alphabetical")

# Sort by delayMs
s_delay = sort_retry_results(rrs15, by="delayMs", ascending=True)
delays = [r.delayMilliseconds for r in s_delay]
chk(delays == sorted(delays),              "sort by delayMs: ascending")

# Sort by errorClass
s_err = sort_retry_results(rrs15, by="errorClass", ascending=True)
errs = [r.errorClass for r in s_err]
chk(errs == sorted(errs),                  "sort by errorClass")

# Sort by retryId
s_id = sort_retry_results(rrs15, by="retryId", ascending=True)
ids = [r.retryId for r in s_id]
chk(ids == sorted(ids),                    "sort by retryId: ascending")

# Input list not mutated
original_first = rrs15[0].attemptNumber
chk(original_first == 3,                   "original list not mutated by sort")

# Unknown sort key defaults to attemptNumber ASC (ascending=True is default)
s_unk = sort_retry_results(rrs15, by="unknown_field")
chk(s_unk[0].attemptNumber == 1,           "unknown sort key: defaults to attemptNumber ASC")


# ===========================================================================
# Section 16: filter_retry_results
# ===========================================================================
_section_header("16. filter_retry_results")

pol16a = _policy()
pol16b = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=2, delay_ms=200)
ps16a  = _status("groq",   "llama")
ps16b  = _status("openai", "gpt-4")

rrs16 = [
    build_retry_result(pol16a, ps16a, 1, RetryDecisionEnum.RETRY,    "TimeoutError",  TS),
    build_retry_result(pol16a, ps16a, 2, RetryDecisionEnum.RETRY,    "TimeoutError",  TS),
    build_retry_result(pol16a, ps16b, 1, RetryDecisionEnum.FAILOVER, "ProviderError", TS),
    build_retry_result(pol16b, ps16b, 2, RetryDecisionEnum.ABORT,    "FatalError",    TS),
    build_retry_result(pol16b, ps16a, 1, RetryDecisionEnum.RETRY,    "TimeoutError",  TS),
]

# Filter by decision
retries = filter_retry_results(rrs16, decision=RetryDecisionEnum.RETRY)
chk(len(retries) == 3,                    "filter RETRY: 3 results")
chk(all(r.decision == RetryDecisionEnum.RETRY for r in retries), "all are RETRY")

failovers = filter_retry_results(rrs16, decision=RetryDecisionEnum.FAILOVER)
chk(len(failovers) == 1,                  "filter FAILOVER: 1 result")

aborts = filter_retry_results(rrs16, decision=RetryDecisionEnum.ABORT)
chk(len(aborts) == 1,                     "filter ABORT: 1 result")

# Filter by policy_id
by_pol_a = filter_retry_results(rrs16, policy_id=pol16a.policyId)
chk(len(by_pol_a) == 3,                   "filter by policyId A: 3 results")
by_pol_b = filter_retry_results(rrs16, policy_id=pol16b.policyId)
chk(len(by_pol_b) == 2,                   "filter by policyId B: 2 results")

# Filter by provider_id
by_prov_a = filter_retry_results(rrs16, provider_id=ps16a.providerId)
chk(len(by_prov_a) == 3,                  "filter by providerId A: 3 results")
by_prov_b = filter_retry_results(rrs16, provider_id=ps16b.providerId)
chk(len(by_prov_b) == 2,                  "filter by providerId B: 2 results")

# Filter by error_class
by_err = filter_retry_results(rrs16, error_class="TimeoutError")
chk(len(by_err) == 3,                     "filter by errorClass: 3 TimeoutErrors")

# Combined filters
combined = filter_retry_results(rrs16,
                                 decision=RetryDecisionEnum.RETRY,
                                 provider_id=ps16a.providerId)
chk(len(combined) == 3,                   "combined filter (RETRY + providerA): 3")

# No match
no_match = filter_retry_results(rrs16, error_class="NoSuchError")
chk(len(no_match) == 0,                   "no-match filter: empty list")

# All-None filters returns all
all_results = filter_retry_results(rrs16)
chk(len(all_results) == 5,                "no filters: all 5 returned")

# Input not mutated
chk(len(rrs16) == 5,                      "filter: original list not mutated")


# ===========================================================================
# Section 17: group_retry_results
# ===========================================================================
_section_header("17. group_retry_results")

pol17 = _policy()
ps17  = _status()
rrs17 = [
    build_retry_result(pol17, ps17, 1, RetryDecisionEnum.RETRY,    "E", TS),
    build_retry_result(pol17, ps17, 2, RetryDecisionEnum.RETRY,    "E", TS),
    build_retry_result(pol17, ps17, 3, RetryDecisionEnum.FAILOVER, "E", TS),
    build_retry_result(pol17, ps17, 4, RetryDecisionEnum.ABORT,    "E", TS),
]

g_dec = group_retry_results(rrs17, by="decision")
chk("RETRY"    in g_dec,                   "group by decision: RETRY key present")
chk("FAILOVER" in g_dec,                   "group by decision: FAILOVER key present")
chk("ABORT"    in g_dec,                   "group by decision: ABORT key present")
chk(len(g_dec["RETRY"]) == 2,             "group RETRY: 2 items")
chk(len(g_dec["FAILOVER"]) == 1,          "group FAILOVER: 1 item")
chk(len(g_dec["ABORT"]) == 1,             "group ABORT: 1 item")

# Groups are sorted by attemptNumber ASC
chk(g_dec["RETRY"][0].attemptNumber == 1, "group sorted: RETRY[0].attempt=1")
chk(g_dec["RETRY"][1].attemptNumber == 2, "group sorted: RETRY[1].attempt=2")

# Group by policyId
g_pol = group_retry_results(rrs17, by="policyId")
chk(len(g_pol) == 1,                      "group by policyId: 1 key (same policy)")
chk(len(list(g_pol.values())[0]) == 4,    "group by policyId: 4 items")

# Group by providerId
g_pv = group_retry_results(rrs17, by="providerId")
chk(len(g_pv) == 1,                       "group by providerId: 1 key")

# Group by errorClass
g_err = group_retry_results(rrs17, by="errorClass")
chk(len(g_err) == 1,                      "group by errorClass: 1 key ('E')")

# Unknown key defaults to decision grouping
g_unk = group_retry_results(rrs17, by="nonsense")
chk("RETRY" in g_unk,                     "unknown group-by defaults to decision")

# Empty list
g_empty = group_retry_results([], by="decision")
chk(len(g_empty) == 0,                    "group empty list: empty dict")


# ===========================================================================
# Section 18: find_retry_result
# ===========================================================================
_section_header("18. find_retry_result")

pol18 = _policy()
ps18  = _status()
rrs18 = [
    build_retry_result(pol18, ps18, 2, RetryDecisionEnum.RETRY,    "T", TS),
    build_retry_result(pol18, ps18, 1, RetryDecisionEnum.RETRY,    "T", TS),
    build_retry_result(pol18, ps18, 3, RetryDecisionEnum.FAILOVER, "F", TS),
]

# Find by decision — returns lowest attemptNumber
found = find_retry_result(rrs18, decision=RetryDecisionEnum.RETRY)
chk(found is not None,                        "find RETRY: found")
chk(found.attemptNumber == 1,                 "find RETRY: returns lowest attempt")

found_fo = find_retry_result(rrs18, decision=RetryDecisionEnum.FAILOVER)
chk(found_fo is not None,                     "find FAILOVER: found")
chk(found_fo.decision == RetryDecisionEnum.FAILOVER, "find FAILOVER: correct decision")

# Find by retryId
specific = find_retry_result(rrs18, retry_id=rrs18[2].retryId)
chk(specific is not None,                     "find by retryId: found")
chk(specific.retryId == rrs18[2].retryId,     "find by retryId: correct result")

# No match
none_found = find_retry_result(rrs18, decision=RetryDecisionEnum.ABORT)
chk(none_found is None,                       "find no match: None returned")

# Find in empty list
chk(find_retry_result([], decision=RetryDecisionEnum.RETRY) is None,
    "find in empty list: None")

# Combined filters
ps18b  = _status("openai", "gpt-4")
rr18_other = build_retry_result(pol18, ps18b, 1, RetryDecisionEnum.RETRY, "T", TS)
found_combined = find_retry_result(
    rrs18 + [rr18_other],
    decision    = RetryDecisionEnum.RETRY,
    provider_id = ps18.providerId,
)
chk(found_combined is not None, "combined find: found")
chk(found_combined.providerId == ps18.providerId, "combined find: correct providerId")


# ===========================================================================
# Section 19: sort_provider_status
# ===========================================================================
_section_header("19. sort_provider_status")

ps_list19 = [
    _status("groq",      "llama",  health=H, priority=50, failures=2),
    _status("openai",    "gpt-4",  health=D, priority=80, failures=3),
    _status("anthropic", "claude", health=H, priority=80, failures=0),
    _status("google",    "gemini", health=U, priority=10, failures=6),
    _status("azure",     "gpt-35", health=H, priority=50, failures=1),
]

# Default: priority DESC
s_prio = sort_provider_status(ps_list19)
chk(s_prio[0].priority >= s_prio[-1].priority,  "sort priority DESC: first >= last")
chk(s_prio[0].priority == 80,                   "sort priority DESC: first=80")

# Priority ASC
s_prio_asc = sort_provider_status(ps_list19, ascending=True)
chk(s_prio_asc[0].priority == 10,               "sort priority ASC: first=10")

# Sort by health (alphabetical: DEGRADED < HEALTHY < UNAVAILABLE)
s_health = sort_provider_status(ps_list19, by="health", ascending=True)
healths = [ps.health.value for ps in s_health]
chk(healths == sorted(healths),                 "sort by health: alphabetical")

# Sort by failureCount ASC
s_fail = sort_provider_status(ps_list19, by="failureCount", ascending=True)
fails = [ps.failureCount for ps in s_fail]
chk(fails == sorted(fails),                     "sort by failureCount ASC")

# Sort by successCount DESC
s_succ = sort_provider_status(ps_list19, by="successCount", ascending=False)
succs = [ps.successCount for ps in s_succ]
chk(succs == sorted(succs, reverse=True),       "sort by successCount DESC")

# Sort by provider name
s_prov = sort_provider_status(ps_list19, by="provider", ascending=True)
provs = [ps.provider for ps in s_prov]
chk(provs == sorted(provs),                     "sort by provider name ASC")

# Sort by providerId
s_id = sort_provider_status(ps_list19, by="providerId", ascending=True)
ids = [ps.providerId for ps in s_id]
chk(ids == sorted(ids),                         "sort by providerId ASC")

# Deterministic — same result on repeated calls
s1 = sort_provider_status(ps_list19)
s2 = sort_provider_status(ps_list19)
chk([ps.providerId for ps in s1] == [ps.providerId for ps in s2],
    "sort_provider_status deterministic")

# Input not mutated
chk(ps_list19[0].provider == "groq",            "original list not mutated")


# ===========================================================================
# Section 20: filter_provider_status
# ===========================================================================
_section_header("20. filter_provider_status")

ps_list20 = [
    _status("groq",      "llama",   health=H, priority=80),
    _status("openai",    "gpt-4",   health=D, priority=60),
    _status("anthropic", "claude",  health=H, priority=50),
    _status("google",    "gemini",  health=U, priority=40),
    _status("azure",     "gpt-35",  health=H, priority=70),
]

# Filter by health
healthy = filter_provider_status(ps_list20, health=H)
chk(len(healthy) == 3,                    "filter HEALTHY: 3")
chk(all(ps.health == H for ps in healthy),"all filtered are HEALTHY")

degraded = filter_provider_status(ps_list20, health=D)
chk(len(degraded) == 1,                   "filter DEGRADED: 1")

unavail = filter_provider_status(ps_list20, health=U)
chk(len(unavail) == 1,                    "filter UNAVAILABLE: 1")

# Filter by provider
by_groq = filter_provider_status(ps_list20, provider="groq")
chk(len(by_groq) == 1,                    "filter provider=groq: 1")
chk(by_groq[0].provider == "groq",        "filter provider: correct provider")

# Filter by provider (case-insensitive)
by_groq_up = filter_provider_status(ps_list20, provider="GROQ")
chk(len(by_groq_up) == 1,                 "filter provider: case-insensitive")

# Filter by model
by_gpt4 = filter_provider_status(ps_list20, model="gpt-4")
chk(len(by_gpt4) == 1,                    "filter model=gpt-4: 1")

# Filter by min_priority
high_prio = filter_provider_status(ps_list20, min_priority=70)
chk(len(high_prio) == 2,                  "filter min_priority=70: 2 (80 and 70)")

# Combined filters
h_high = filter_provider_status(ps_list20, health=H, min_priority=70)
chk(len(h_high) == 2,                     "combined HEALTHY + prio>=70: 2")

# No match
none_match = filter_provider_status(ps_list20, provider="nonexistent")
chk(len(none_match) == 0,                 "no match: empty list")

# All None: all returned
all20 = filter_provider_status(ps_list20)
chk(len(all20) == 5,                      "no filters: all 5 returned")

# Input not mutated
chk(len(ps_list20) == 5,                  "filter: input not mutated")


# ===========================================================================
# Section 21: group_provider_status
# ===========================================================================
_section_header("21. group_provider_status")

ps_list21 = [
    _status("groq",      "llama",  health=H, priority=80),
    _status("openai",    "gpt-4",  health=D, priority=60),
    _status("anthropic", "llama",  health=H, priority=50),
    _status("google",    "gemini", health=U, priority=40),
    _status("azure",     "llama",  health=H, priority=70),
]

# Group by health (default)
g21h = group_provider_status(ps_list21, by="health")
chk("HEALTHY"     in g21h,              "group health: HEALTHY key")
chk("DEGRADED"    in g21h,              "group health: DEGRADED key")
chk("UNAVAILABLE" in g21h,              "group health: UNAVAILABLE key")
chk(len(g21h["HEALTHY"])     == 3,      "group HEALTHY: 3 members")
chk(len(g21h["DEGRADED"])    == 1,      "group DEGRADED: 1 member")
chk(len(g21h["UNAVAILABLE"]) == 1,      "group UNAVAILABLE: 1 member")

# Groups sorted by priority DESC then providerId ASC
healthy21 = g21h["HEALTHY"]
chk(healthy21[0].priority == 80,        "group HEALTHY sorted: first priority=80")
chk(healthy21[1].priority == 70,        "group HEALTHY sorted: second priority=70")

# Group by provider
g21p = group_provider_status(ps_list21, by="provider")
chk(len(g21p) == 5,                     "group by provider: 5 distinct providers")
chk("groq" in g21p,                     "group by provider: groq present")

# Group by model
g21m = group_provider_status(ps_list21, by="model")
chk("llama"  in g21m,                   "group by model: llama key")
chk("gpt-4"  in g21m,                   "group by model: gpt-4 key")
chk("gemini" in g21m,                   "group by model: gemini key")
chk(len(g21m["llama"]) == 3,            "group model llama: 3 entries")

# Unknown by → defaults to health
g21_unk = group_provider_status(ps_list21, by="bogus")
chk("HEALTHY" in g21_unk,               "unknown group-by: defaults to health")

# Empty list
g21_empty = group_provider_status([])
chk(len(g21_empty) == 0,                "group empty: empty dict")


# ===========================================================================
# Section 22: find_provider_status
# ===========================================================================
_section_header("22. find_provider_status")

ps_list22 = [
    _status("groq",      "llama",  health=H, priority=80),
    _status("openai",    "gpt-4",  health=D, priority=60),
    _status("anthropic", "claude", health=H, priority=50),
    _status("google",    "gemini", health=U, priority=40),
    _status("azure",     "gpt-35", health=H, priority=70),
]

# Find by providerId
for ps22 in ps_list22:
    found22 = find_provider_status(ps_list22, provider_id=ps22.providerId)
    chk(found22 is not None,                      f"find providerId: {ps22.provider}")
    chk(found22.providerId == ps22.providerId,    f"find providerId exact: {ps22.provider}")

# Find by provider name
f22a = find_provider_status(ps_list22, provider="groq")
chk(f22a is not None,                             "find by provider name: found")
chk(f22a.provider == "groq",                      "find by provider name: correct")

# Find by model
f22b = find_provider_status(ps_list22, model="gpt-4")
chk(f22b is not None,                             "find by model: found")
chk(f22b.model == "gpt-4",                        "find by model: correct")

# Find by health — returns highest priority
f22c = find_provider_status(ps_list22, health=H)
chk(f22c is not None,                             "find by health=HEALTHY: found")
chk(f22c.priority == 80,                          "find HEALTHY: highest priority=80")

# Find by health=DEGRADED
f22d = find_provider_status(ps_list22, health=D)
chk(f22d is not None,                             "find DEGRADED: found")
chk(f22d.health == D,                             "find DEGRADED: correct health")

# No match
f22e = find_provider_status(ps_list22, provider="nonexistent")
chk(f22e is None,                                 "find no match: None")

# Empty list
chk(find_provider_status([]) is None,             "find empty list: None")

# Combined filters
f22f = find_provider_status(ps_list22, health=H, min_priority=70)
chk(f22f is not None,                             "combined find: found")
chk(f22f.priority == 80,                          "combined find: highest priority")


# ===========================================================================
# Section 23: ExtendedRetryStatistics
# ===========================================================================
_section_header("23. ExtendedRetryStatistics")

pol23 = _policy()
ps23a = build_provider_status("groq",   "llama", TS, failure_count=2, success_count=5)
ps23b = build_provider_status("openai", "gpt-4", TS, failure_count=1, success_count=3,
                               health=ProviderHealthEnum.DEGRADED)
ps23c = build_provider_status("azure",  "gpt35", TS, failure_count=6, success_count=0,
                               health=ProviderHealthEnum.UNAVAILABLE)

rrs23 = [
    build_retry_result(pol23, ps23a, 1, RetryDecisionEnum.RETRY,    "E", TS),
    build_retry_result(pol23, ps23a, 2, RetryDecisionEnum.FAILOVER, "E", TS),
    build_retry_result(pol23, ps23b, 3, RetryDecisionEnum.ABORT,    "E", TS),
]

ext = build_extended_retry_statistics(rrs23, [ps23a, ps23b, ps23c])

chk(ext.totalAttempts    == 3,          "ext: totalAttempts=3")
chk(ext.retryCount       == 1,          "ext: retryCount=1")
chk(ext.failoverCount    == 1,          "ext: failoverCount=1")
chk(ext.abortCount       == 1,          "ext: abortCount=1")

total_succ = ps23a.successCount + ps23b.successCount + ps23c.successCount
total_fail = ps23a.failureCount + ps23b.failureCount + ps23c.failureCount
chk(ext.totalProviderSuccesses == total_succ, "ext: totalProviderSuccesses correct")
chk(ext.totalProviderFailures  == total_fail, "ext: totalProviderFailures correct")

total_obs = total_succ + total_fail
expected_succ_rate = round(total_succ / total_obs, 6)
chk(abs(ext.providerSuccessRate - expected_succ_rate) < 1e-5, "ext: providerSuccessRate correct")

chk(ext.healthyProviders     == 1,      "ext: healthyProviders=1 (groq only)")
chk(ext.degradedProviders    == 1,      "ext: degradedProviders=1")
chk(ext.unavailableProviders == 1,      "ext: unavailableProviders=1")

# No statuses provided
ext_no_ps = build_extended_retry_statistics(rrs23)
chk(ext_no_ps.totalProviderSuccesses == 0, "ext no statuses: successes=0")
chk(ext_no_ps.totalProviderFailures  == 0, "ext no statuses: failures=0")
chk(ext_no_ps.providerSuccessRate    == 0.0,"ext no statuses: rate=0.0")
chk(ext_no_ps.healthyProviders       == 0, "ext no statuses: healthy=0")

# Empty results + empty statuses
ext_empty = build_extended_retry_statistics([], [])
chk(ext_empty.totalAttempts == 0,      "ext empty: totalAttempts=0")
chk(ext_empty.retryRate     == 0.0,    "ext empty: retryRate=0.0")

# Frozen
try:
    ext.totalAttempts = 99  # type: ignore
    chk(False, "ExtendedRetryStatistics is NOT immutable")
except Exception:
    chk(True, "ExtendedRetryStatistics is immutable (frozen)")


# ===========================================================================
# Section 24: Statistics order-independence
# ===========================================================================
_section_header("24. Statistics order-independence")

pol24 = _policy()
ps24  = _status()

rr24_a = build_retry_result(pol24, ps24, 1, RetryDecisionEnum.RETRY,    "Err", TS)
rr24_b = build_retry_result(pol24, ps24, 2, RetryDecisionEnum.FAILOVER, "Err", TS)
rr24_c = build_retry_result(pol24, ps24, 3, RetryDecisionEnum.ABORT,    "Err", TS)

# Statistics should be identical regardless of input order
orders = [
    [rr24_a, rr24_b, rr24_c],
    [rr24_c, rr24_a, rr24_b],
    [rr24_b, rr24_c, rr24_a],
    [rr24_c, rr24_b, rr24_a],
]

stats_list = [build_retry_statistics(order) for order in orders]
ref = stats_list[0]
for i, s in enumerate(stats_list[1:], 1):
    chk(s.totalAttempts  == ref.totalAttempts,  f"order {i}: totalAttempts matches")
    chk(s.retryCount     == ref.retryCount,     f"order {i}: retryCount matches")
    chk(s.failoverCount  == ref.failoverCount,  f"order {i}: failoverCount matches")
    chk(s.abortCount     == ref.abortCount,     f"order {i}: abortCount matches")
    chk(abs(s.retryRate  - ref.retryRate) < 1e-9, f"order {i}: retryRate matches")
    chk(abs(s.averageDelayMs - ref.averageDelayMs) < 1e-6,
        f"order {i}: averageDelayMs matches")
    chk(s.uniquePolicies     == ref.uniquePolicies,    f"order {i}: uniquePolicies match")
    chk(s.uniqueProviders    == ref.uniqueProviders,   f"order {i}: uniqueProviders match")
    chk(s.uniqueErrorClasses == ref.uniqueErrorClasses,f"order {i}: uniqueErrorClasses match")

# Extended statistics order-independence
ps24b  = _status("openai", "gpt-4")
ext_orders = [
    build_extended_retry_statistics([rr24_a, rr24_b, rr24_c], [ps24, ps24b]),
    build_extended_retry_statistics([rr24_c, rr24_b, rr24_a], [ps24b, ps24]),
    build_extended_retry_statistics([rr24_b, rr24_a, rr24_c], [ps24, ps24b]),
]
ext_ref = ext_orders[0]
for i, ext in enumerate(ext_orders[1:], 1):
    chk(ext.totalProviderSuccesses == ext_ref.totalProviderSuccesses,
        f"ext order {i}: providerSuccesses match")
    chk(ext.healthyProviders       == ext_ref.healthyProviders,
        f"ext order {i}: healthyProviders match")


# ===========================================================================
# Section 25: Integration helpers
# ===========================================================================
_section_header("25. Integration helpers")

# policy_for_execution
exec_pol = policy_for_execution(created_at=TS)
chk(exec_pol.strategy == RetryStrategyEnum.EXPONENTIAL_BACKOFF, "exec policy: EXP BACKOFF")
chk(exec_pol.maxRetries == 3,                                    "exec policy: maxRetries=3")
chk("ExecutionTimeoutError"   in exec_pol.retryableExceptions,   "exec policy: TimeoutError listed")
chk("ProviderUnavailableError" in exec_pol.retryableExceptions,  "exec policy: ProviderUnavailableError listed")

exec_pol2 = policy_for_execution(max_retries=5, delay_ms=500, created_at=TS)
chk(exec_pol2.maxRetries == 5,          "exec policy override: maxRetries=5")
chk(exec_pol2.delayMilliseconds == 500, "exec policy override: delay=500")

# execution_provider_status
exec_ps = execution_provider_status("groq", "llama-3.3-70b-versatile", TS)
chk(exec_ps.provider == "groq",         "exec ps: provider=groq")
chk(exec_ps.failureCount == 0,          "exec ps: failureCount=0")
chk(exec_ps.successCount == 0,          "exec ps: successCount=0")
chk(exec_ps.health == H,                "exec ps: health=HEALTHY")

exec_ps2 = execution_provider_status("groq", "llama", TS, health=D, priority=30)
chk(exec_ps2.health    == D,            "exec ps: health=DEGRADED")
chk(exec_ps2.priority  == 30,           "exec ps: priority=30")

# provider_status_from_registry_model
class FakeModel:
    provider  = "groq"
    modelName = "llama-3.1-8b-instant"
    priority  = 75

from_reg = provider_status_from_registry_model(FakeModel(), TS)
chk(from_reg.provider == "groq",         "from_registry: provider=groq")
chk(from_reg.model    == "llama-3.1-8b-instant", "from_registry: model correct")
chk(from_reg.priority == 75,             "from_registry: priority=75")
chk(from_reg.health   == H,              "from_registry: default HEALTHY")

# Missing attribute falls back to defaults
class MinimalModel:
    provider  = "openai"
    modelName = "gpt-4"

from_min = provider_status_from_registry_model(MinimalModel(), TS)
chk(from_min.priority == 50,             "from_registry minimal: default priority=50")

# policy_for_budget_overflow
bud_pol = policy_for_budget_overflow(TS)
chk(bud_pol.strategy    == RetryStrategyEnum.IMMEDIATE, "budget pol: IMMEDIATE")
chk(bud_pol.maxRetries  == 1,                           "budget pol: maxRetries=1")
chk(bud_pol.delayMilliseconds == 0,                     "budget pol: delay=0")
chk("InvalidBudgetReportError" in bud_pol.retryableExceptions, "budget pol: exception listed")

# budget_retry_result
bud_ps = build_provider_status("groq", "llama", TS)
bud_rr1 = budget_retry_result(bud_pol, bud_ps, 1, True, TS)   # overflow, attempt 1 < max 2
bud_rr2 = budget_retry_result(bud_pol, bud_ps, 2, True, TS)   # overflow, attempt 2 == max 2
bud_rr3 = budget_retry_result(bud_pol, bud_ps, 1, False, TS)  # no overflow

chk(bud_rr1.decision == RetryDecisionEnum.RETRY,  "budget rr: overflow + attempt < max → RETRY")
chk(bud_rr2.decision == RetryDecisionEnum.ABORT,  "budget rr: overflow + attempt == max → ABORT")
chk(bud_rr3.decision == RetryDecisionEnum.ABORT,  "budget rr: no overflow → ABORT")
chk(bud_rr1.errorClass == "InvalidBudgetReportError", "budget rr: errorClass correct")


# ===========================================================================
# Section 26: Edge cases
# ===========================================================================
_section_header("26. Edge cases")

# Policy with 0 retries — should_retry always False for attempt >= 1
pol_0 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                            max_retries=0, delay_ms=1000)
chk(should_retry(pol_0, 1) is False,     "maxRetries=0: attempt 1 → no retry")
plan_0 = build_retry_plan(pol_0, _status(), 1, "E", TS,
                           [_status("openai", "gpt-4", priority=60)])
chk(plan_0.decision in (RetryDecisionEnum.FAILOVER, RetryDecisionEnum.ABORT),
    "maxRetries=0: plan is FAILOVER or ABORT")

# Single provider, no failover
ps_solo = _status("groq", "llama")
plan_solo = build_retry_plan(_policy(max_retries=0), ps_solo, 1, "E", TS, [ps_solo])
chk(plan_solo.decision == RetryDecisionEnum.ABORT, "single provider (self): ABORT")

# Very large attempt number
pol_big = _policy(max_retries=100, delay_ms=10, backoff=1.5)
chk(should_retry(pol_big, 99)  is True,    "large maxRetries: attempt 99 ok")
chk(should_retry(pol_big, 100) is True,    "large maxRetries: attempt 100 still ok (< maxAttempts=101)")
chk(should_retry(pol_big, 101) is False,   "large maxRetries: attempt 101 exhausted (== maxAttempts)")

# Exponential overflow safety (very large exponent)
pol_big_exp = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                                  delay_ms=1, backoff_multiplier=2.0,
                                  max_retries=200)
delay_big = _compute_delay(pol_big_exp, 60)
chk(delay_big >= 0,                       "large exponent: delay is non-negative int")
chk(isinstance(delay_big, int),           "large exponent: delay is int")

# Empty retryableExceptions — all errors retryable
pol_any = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=2,
                              retryable_exceptions=[])
chk(should_retry(pol_any, 1, "AnyError") is True, "empty exceptions: any error retryable")

# Provider with same name but different model → different key
ps_same_prov_a = _status("groq", "model-a")
ps_same_prov_b = _status("groq", "model-b")
chk(ps_same_prov_a.providerKey != ps_same_prov_b.providerKey,
    "same provider, different model → different providerKey")
chk(ps_same_prov_a.providerId  != ps_same_prov_b.providerId,
    "same provider, different model → different providerId")

# Retry statistics with single entry
pol_one = _policy()
ps_one  = _status()
rr_one  = _result(pol_one, ps_one, 1, RetryDecisionEnum.RETRY)
stats_one = build_retry_statistics([rr_one])
chk(stats_one.totalAttempts == 1,         "single-entry stats: totalAttempts=1")
chk(stats_one.retryRate     == 1.0,       "single-entry stats: retryRate=1.0")
chk(stats_one.failoverRate  == 0.0,       "single-entry stats: failoverRate=0.0")

# find_retry_result with duplicate decisions (returns lowest attempt)
pol_dup = _policy()
ps_dup  = _status()
dups    = [build_retry_result(pol_dup, ps_dup, i, RetryDecisionEnum.RETRY, "E", TS)
           for i in range(1, 4)]
found_dup = find_retry_result(dups, decision=RetryDecisionEnum.RETRY)
chk(found_dup.attemptNumber == 1,         "find with duplicates: lowest attempt returned")


# ===========================================================================
# Section 27: Zero-randomness guarantee
# ===========================================================================
_section_header("27. Zero-randomness guarantee")

import sys as _sys
import types as _types

# Verify 'random' module is not imported inside retry_failover_service
import services.retry_failover_service as _svc
svc_src = _sys.modules[_svc.__name__].__file__

with open(svc_src, "r", encoding="utf-8") as _f:
    _src = _f.read()

chk("import random" not in _src,          "source: 'import random' not present")
chk("from random"   not in _src,          "source: 'from random' not present")
# uuid4 appears in a comment as a reminder not to use it; check no actual call exists
import re as _re
chk(not bool(_re.search(r'\buuid\.uuid4\s*\(', _src)),
    "source: 'uuid.uuid4()' call not present")

# Verify determinism by building identical objects 10 times
_pol_ref = _policy()
for _i in range(10):
    _pol_i = _policy()
    chk(_pol_i.policyId == _pol_ref.policyId, f"determinism run {_i+1}: policyId stable")

_ps_ref = _status()
for _i in range(10):
    _ps_i = _status()
    chk(_ps_i.providerId == _ps_ref.providerId, f"determinism run {_i+1}: providerId stable")

# RetryResult IDs stable
_rr_ref = _result(_pol_ref, _ps_ref, 2, RetryDecisionEnum.FAILOVER)
for _i in range(5):
    _rr_i = _result(_pol_ref, _ps_ref, 2, RetryDecisionEnum.FAILOVER)
    chk(_rr_i.retryId == _rr_ref.retryId,   f"determinism run {_i+1}: retryId stable")
    chk(_rr_i.retryFingerprint == _rr_ref.retryFingerprint,
        f"determinism run {_i+1}: fingerprint stable")

# Health calculations are deterministic
for _fc, _sc, _expected in [
    (0, 0, H), (1, 0, H), (2, 0, H),
    (DFAIL, 0, D), (DFAIL+1, 0, D),
    (UFAIL, 0, U), (UFAIL+2, 0, U),
    (DFAIL, RSUCC, H),
]:
    _h1 = calculate_provider_health(_fc, _sc)
    _h2 = calculate_provider_health(_fc, _sc)
    chk(_h1 == _h2 == _expected,
        f"health deterministic: fc={_fc} sc={_sc} → {_expected.value}")


# ===========================================================================
# Section 28: Serialisation & immutability — full round-trip
# ===========================================================================
_section_header("28. Serialisation & immutability")

pol28 = _policy()
ps28  = _status()
rr28  = build_retry_result(pol28, ps28, 2, RetryDecisionEnum.FAILOVER,
                            "Err", TS, failover_provider="failover-id-x")

# RetryPolicy round-trip
d_pol = pol28.model_dump()
chk(isinstance(d_pol, dict),                  "pol.model_dump(): dict")
pol28b = RetryPolicy(**d_pol)
chk(pol28b.policyId == pol28.policyId,         "pol round-trip: policyId")
chk(pol28b.strategy == pol28.strategy,         "pol round-trip: strategy")

j_pol = pol28.model_dump_json()
obj_pol = json.loads(j_pol)
chk(obj_pol["policyKey"] == pol28.policyKey,   "pol json: policyKey")

# ProviderStatus round-trip
d_ps = ps28.model_dump()
ps28b = ProviderStatus(**d_ps)
chk(ps28b.providerId == ps28.providerId,       "ps round-trip: providerId")
chk(ps28b.health     == ps28.health,           "ps round-trip: health")

j_ps = ps28.model_dump_json()
obj_ps = json.loads(j_ps)
chk(obj_ps["provider"] == ps28.provider,       "ps json: provider")

# RetryResult round-trip
d_rr = rr28.model_dump()
rr28b = RetryResult(**d_rr)
chk(rr28b.retryId   == rr28.retryId,           "rr round-trip: retryId")
chk(rr28b.decision  == rr28.decision,          "rr round-trip: decision")
chk(rr28b.delayMilliseconds == rr28.delayMilliseconds, "rr round-trip: delayMs")

j_rr = rr28.model_dump_json()
obj_rr = json.loads(j_rr)
chk(obj_rr["retryFingerprint"] == rr28.retryFingerprint, "rr json: fingerprint")

# Immutability checks for all models — normal assignment must raise
for _model, _name in [
    (pol28, "RetryPolicy"),
    (ps28,  "ProviderStatus"),
    (rr28,  "RetryResult"),
]:
    try:
        _model.createdAt = "mutated"  # type: ignore
        chk(False, f"{_name} allows normal assignment — NOT frozen")
    except Exception:
        chk(True, f"{_name} is frozen (normal assignment raises)")

# RetryStatistics immutability
stats28 = build_retry_statistics([rr28])
try:
    stats28.totalAttempts = 0  # type: ignore
    chk(False, "RetryStatistics not frozen")
except Exception:
    chk(True, "RetryStatistics frozen")

# ExtendedRetryStatistics round-trip
ext28 = build_extended_retry_statistics([rr28], [ps28])
d_ext = ext28.model_dump()
ext28b = ExtendedRetryStatistics(**d_ext)
chk(ext28b.totalAttempts == ext28.totalAttempts, "ext round-trip: totalAttempts")
chk(ext28b.healthyProviders == ext28.healthyProviders, "ext round-trip: healthyProviders")


# ===========================================================================
# Section 29: Additional retry engine edge cases (exhaustion boundaries)
# ===========================================================================
_section_header("29. Retry exhaustion boundaries")

# maxRetries=0 edge cases (no retries allowed at all)
pol29_0 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS, max_retries=0)
chk(pol29_0.maxRetries == 0,                        "maxRetries=0: stored")
chk(pol29_0.maxRetries + 1 == 1,                    "maxRetries=0: maxAttempts=1")
chk(should_retry(pol29_0, 1) is False,              "maxRetries=0: attempt=1 exhausted")
chk(should_retry(pol29_0, 0) is True,               "maxRetries=0: attempt=0 < 1 allowed (edge)")

# maxRetries=1 (exactly 2 attempts total: maxAttempts=2)
pol29_1 = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=1, delay_ms=100)
# attempt=1 < maxAttempts=2 -> True
chk(should_retry(pol29_1, 1) is True,               "maxRetries=1: attempt=1 < maxAttempts=2 -> True")
# attempt=2 >= maxAttempts=2 -> False
chk(should_retry(pol29_1, 2) is False,              "maxRetries=1: attempt=2 == maxAttempts -> False")
chk(should_retry(pol29_1, 3) is False,              "maxRetries=1: attempt=3 > maxAttempts -> False")

# delay_ms=0 with EXP_BACKOFF should always be 0
pol29_zero = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                                 max_retries=5, delay_ms=0, backoff_multiplier=10.0)
for _a in range(1, 7):
    chk(_compute_delay(pol29_zero, _a) == 0, f"zero-base EXP: attempt {_a} delay=0")

# Large backoff multiplier correctness
pol29_big = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                                max_retries=4, delay_ms=1, backoff_multiplier=10.0)
chk(_compute_delay(pol29_big, 1) == 1,      "big mult: attempt 1 = 1ms")
chk(_compute_delay(pol29_big, 2) == 10,     "big mult: attempt 2 = 10ms")
chk(_compute_delay(pol29_big, 3) == 100,    "big mult: attempt 3 = 100ms")
chk(_compute_delay(pol29_big, 4) == 1000,   "big mult: attempt 4 = 1000ms")

# next_retry_delay wraps _compute_delay correctly
pol29_fd = build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, delay_ms=77)
chk(next_retry_delay(pol29_fd, 1) == 77,    "next_retry_delay FIXED: attempt 1->2 = 77")
chk(next_retry_delay(pol29_fd, 5) == 77,    "next_retry_delay FIXED: attempt 5->6 = 77")

pol29_exp = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                                delay_ms=10, backoff_multiplier=3.0)
# next_retry_delay returns _compute_delay(pol, attempt+1)
# attempt=1 → _compute_delay(pol, 2) = 10*3^1=30
chk(next_retry_delay(pol29_exp, 1) == 30,   "next_retry_delay EXP: attempt 1->2 = 30")
chk(next_retry_delay(pol29_exp, 2) == 90,   "next_retry_delay EXP: attempt 2->3 = 90")

# increment chain: NONE policy should abort immediately
pol29_none = build_retry_policy(RetryStrategyEnum.NONE, TS, max_retries=5)
ps29       = _status()
rr29_start = build_retry_result(pol29_none, ps29, 1, RetryDecisionEnum.ABORT, "E", TS)
# build_retry_result allows any decision — increment checks should_retry
# But NONE strategy → should_retry always False
rr29_inc = increment_retry_attempt(rr29_start, pol29_none, TS2)
chk(rr29_inc.decision == RetryDecisionEnum.ABORT, "NONE policy increment always ABORT")

# ===========================================================================
# Section 30: Provider health — extended transitions and edge cases
# ===========================================================================
_section_header("30. Provider health extended")

# Exactly at thresholds
chk(calculate_provider_health(DFAIL - 1, 0) == H, "1 below DEGRADED: HEALTHY")
chk(calculate_provider_health(DFAIL,     0) == D, "exactly DEGRADED threshold")
chk(calculate_provider_health(UFAIL - 1, 0) == D, "1 below UNAVAILABLE: DEGRADED")
chk(calculate_provider_health(UFAIL,     0) == U, "exactly UNAVAILABLE threshold")

# Recovery exactly at threshold
chk(calculate_provider_health(DFAIL, RSUCC - 1) == D, "1 below recovery: still DEGRADED")
chk(calculate_provider_health(DFAIL, RSUCC)     == H, "exactly recovery: HEALTHY")
chk(calculate_provider_health(DFAIL, RSUCC + 5) == H, "above recovery: HEALTHY")

# Zero counters
chk(calculate_provider_health(0, 0) == H, "0/0: HEALTHY")
chk(calculate_provider_health(0, 100) == H, "0 fail, many successes: HEALTHY")

# Chain: healthy fresh provider goes through all transitions
ps30 = _status("provider30", "model30", priority=99)
chk(ps30.health == H, "fresh: HEALTHY")

# Apply DFAIL failures one at a time
for _i in range(DFAIL):
    ps30 = mark_provider_failure(ps30, TS)
chk(ps30.health == D, f"after {DFAIL} failures: DEGRADED")
chk(ps30.failureCount == DFAIL, "failureCount == DFAIL")
chk(ps30.successCount == 0, "successCount reset to 0 after failures")

# Apply more failures to reach UNAVAILABLE
for _i in range(UFAIL - DFAIL):
    ps30 = mark_provider_failure(ps30, TS)
chk(ps30.health == U, f"after {UFAIL} total failures: UNAVAILABLE")

# Mark success on UNAVAILABLE — health doesn't auto-recover
ps30_succ = mark_provider_success(ps30, TS2)
chk(ps30_succ.health == U, "UNAVAILABLE: success does not auto-recover (stays UNAVAILABLE)")
chk(ps30_succ.successCount == 1, "UNAVAILABLE: successCount increments")

# reset_provider_health works from any state
ps30_reset = reset_provider_health(ps30, TS2)
chk(ps30_reset.health == H, "reset from UNAVAILABLE: HEALTHY")
chk(ps30_reset.failureCount == 0, "reset: failures cleared")
chk(ps30_reset.successCount == 0, "reset: successes cleared")
chk(ps30_reset.lastFailureAt == "", "reset: lastFailureAt cleared")

# Multiple successes from DEGRADED
ps30_deg = _status("p30d", "m", failures=DFAIL, successes=0, health=D)
# Apply successes one by one
ps30_r1 = mark_provider_success(ps30_deg, TS2)
chk(ps30_r1.health == D, "DEGRADED: 1 success still DEGRADED")
ps30_r2 = mark_provider_success(ps30_r1, TS2)
chk(ps30_r2.health == H, f"DEGRADED: {RSUCC} successes -> HEALTHY")

# lastFailureAt preserved on mark_success
ps30_with_fail = build_provider_status("p30f", "m", TS,
                                         failure_count=2, last_failure_at=TS)
ps30_after_succ = mark_provider_success(ps30_with_fail, TS2)
chk(ps30_after_succ.lastFailureAt == TS, "mark_success: lastFailureAt preserved")

# ===========================================================================
# Section 31: Failover engine — extended plan scenarios
# ===========================================================================
_section_header("31. Failover engine extended scenarios")

pol31 = _policy(max_retries=2)  # maxAttempts=3
ps31_prim = _status("groq",  "llama",  priority=90)
ps31_hA   = _status("openai","gpt-4",  priority=80)
ps31_hB   = _status("azure", "gpt-35", priority=70)
ps31_deg  = _status("anth",  "claude", health=D, priority=60)

all31 = [ps31_prim, ps31_hA, ps31_hB, ps31_deg]

# attempt=1: retry (within budget)
p31a = build_retry_plan(pol31, ps31_prim, 1, "E", TS, all31)
chk(p31a.decision == RetryDecisionEnum.RETRY,     "plan31 attempt=1: RETRY")
chk(p31a.delayMilliseconds > 0,                   "plan31 attempt=1: delay>0")

# attempt=2: retry (within budget, maxAttempts=3)
p31b = build_retry_plan(pol31, ps31_prim, 2, "E", TS, all31)
chk(p31b.decision == RetryDecisionEnum.RETRY,     "plan31 attempt=2: RETRY")

# attempt=3: exhausted → failover to highest-priority healthy non-primary
p31c = build_retry_plan(pol31, ps31_prim, 3, "E", TS, all31)
chk(p31c.decision == RetryDecisionEnum.FAILOVER,  "plan31 attempt=3: FAILOVER")
chk(p31c.failoverProviderId == ps31_hA.providerId,"plan31: hA selected (priority 80)")
chk(p31c.delayMilliseconds == 0,                  "plan31 FAILOVER: no delay")

# If primary is currently hA (was already selected), hB gets picked next
p31d = build_retry_plan(pol31, ps31_hA, 3, "E", TS, all31)
chk(p31d.decision == RetryDecisionEnum.FAILOVER,   "plan31 hA primary: FAILOVER")
chk(p31d.failoverProviderId == ps31_prim.providerId or
    p31d.failoverProviderId == ps31_hB.providerId,
    "plan31 hA primary: failover to another healthy provider")

# NONE strategy → always abort (no retry allowed) → goes straight to failover
pol31_none = build_retry_policy(RetryStrategyEnum.NONE, TS, max_retries=5)
p31e = build_retry_plan(pol31_none, ps31_prim, 1, "E", TS, all31)
chk(p31e.decision == RetryDecisionEnum.FAILOVER,  "NONE strategy: goes straight to FAILOVER")

# NONE strategy, no healthy candidates → ABORT
p31f = build_retry_plan(pol31_none, ps31_prim, 1, "E", TS, [ps31_prim, ps31_deg])
chk(p31f.decision == RetryDecisionEnum.ABORT,     "NONE + no healthy: ABORT")

# planKey determinism depends only on policyId, primaryProviderId, errorClass
p31g = build_retry_plan(pol31, ps31_prim, 1, "E", TS,  all31)
p31h = build_retry_plan(pol31, ps31_prim, 1, "E", TS2, all31)  # different timestamp
chk(p31g.planKey == p31h.planKey,                 "planKey deterministic: timestamp-independent")
chk(p31g.planId  == p31h.planId,                  "planId deterministic: timestamp-independent")

# Different errorClass → different planKey
p31i = build_retry_plan(pol31, ps31_prim, 1, "OtherError", TS, all31)
chk(p31i.planKey != p31g.planKey,                 "planKey: different errorClass -> different key")

# execute_failover_decision materialises all three decision types
res31_retry   = execute_failover_decision(p31a, pol31, ps31_prim, TS, all31)
res31_failover= execute_failover_decision(p31c, pol31, ps31_prim, TS, all31)
res31_abort   = execute_failover_decision(
    build_retry_plan(pol31, ps31_prim, 3, "E", TS, [ps31_prim, ps31_deg]),
    pol31, ps31_prim, TS, [ps31_prim, ps31_deg]
)
chk(res31_retry.decision    == RetryDecisionEnum.RETRY,   "exec: RETRY result")
chk(res31_failover.decision == RetryDecisionEnum.FAILOVER,"exec: FAILOVER result")
chk(res31_abort.decision    == RetryDecisionEnum.ABORT,   "exec: ABORT result")
chk(isinstance(res31_retry,    RetryResult), "exec returns RetryResult (RETRY)")
chk(isinstance(res31_failover, RetryResult), "exec returns RetryResult (FAILOVER)")
chk(isinstance(res31_abort,    RetryResult), "exec returns RetryResult (ABORT)")

# ===========================================================================
# Section 32: Sorting stability and determinism across all utilities
# ===========================================================================
_section_header("32. Sorting stability and determinism")

# Build a deterministic set of results with the same attemptNumber (tie-breaking by retryId)
pol32 = _policy()
ps32a = _status("provA", "m1")
ps32b = _status("provB", "m2")

rr32_list = [
    build_retry_result(pol32, ps32a, 2, RetryDecisionEnum.RETRY, "E", TS),
    build_retry_result(pol32, ps32b, 2, RetryDecisionEnum.ABORT, "E", TS),
    build_retry_result(pol32, ps32a, 1, RetryDecisionEnum.RETRY, "E", TS),
    build_retry_result(pol32, ps32b, 1, RetryDecisionEnum.ABORT, "E", TS),
]

# Sort by attemptNumber ASC: ties broken by retryId ASC
s32 = sort_retry_results(rr32_list, by="attemptNumber", ascending=True)
chk(s32[0].attemptNumber == 1, "sort stable: first attempt=1")
chk(s32[1].attemptNumber == 1, "sort stable: second attempt=1")
chk(s32[0].retryId < s32[1].retryId, "sort stable: retryId tie-break for attempt=1")
chk(s32[2].attemptNumber == 2, "sort stable: third attempt=2")
chk(s32[3].attemptNumber == 2, "sort stable: fourth attempt=2")
chk(s32[2].retryId < s32[3].retryId, "sort stable: retryId tie-break for attempt=2")

# Repeated sorts give identical results
s32_a = sort_retry_results(rr32_list)
s32_b = sort_retry_results(rr32_list)
chk([r.retryId for r in s32_a] == [r.retryId for r in s32_b],
    "repeated sort: identical results")

# sort_provider_status stability at same priority
ps32_x = _status("provX", "m", priority=50)
ps32_y = _status("provY", "m", priority=50)
ps32_z = _status("provZ", "m", priority=50)
# ascending=False (default): key=(-priority, providerId) reversed → providerId DESC
sp32   = sort_provider_status([ps32_x, ps32_z, ps32_y], by="priority", ascending=False)
ids32  = [ps.providerId for ps in sp32]
chk(ids32 == sorted(ids32, reverse=True),
    "sort_provider_status DESC: same priority tie-broken by providerId DESC")

# ascending=True: key=(-priority, providerId) not reversed → providerId ASC
sp32_asc = sort_provider_status([ps32_x, ps32_z, ps32_y], by="priority", ascending=True)
ids32_asc = [ps.providerId for ps in sp32_asc]
chk(ids32_asc == sorted(ids32_asc),
    "sort_provider_status ASC: same priority tie-broken by providerId ASC")

# group_retry_results preserves all items
rr32_all = rr32_list + [build_retry_result(pol32, ps32a, 3, RetryDecisionEnum.FAILOVER, "E", TS)]
g32 = group_retry_results(rr32_all, by="decision")
total_in_groups = sum(len(v) for v in g32.values())
chk(total_in_groups == len(rr32_all), "group: no items lost")

# group_provider_status preserves all items
ps32_list = [ps32a, ps32b, ps32_x, ps32_y, ps32_z]
g32ps = group_provider_status(ps32_list, by="health")
total_ps_in_groups = sum(len(v) for v in g32ps.values())
chk(total_ps_in_groups == len(ps32_list), "group_provider_status: no items lost")

# ===========================================================================
# Section 33: Statistics completeness — rates, unique counts, averages
# ===========================================================================
_section_header("33. Statistics completeness")

pol33 = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, TS,
                            max_retries=5, delay_ms=200, backoff_multiplier=2.0)
ps33a = _status("groq",   "llama", priority=80)
ps33b = _status("openai", "gpt-4", priority=60)

rrs33: List[RetryResult] = []
# 3 retries on ps33a
for i in range(1, 4):
    rrs33.append(build_retry_result(pol33, ps33a, i, RetryDecisionEnum.RETRY, "TimeoutError", TS))
# 2 failovers on ps33b
for i in range(1, 3):
    rrs33.append(build_retry_result(pol33, ps33b, i, RetryDecisionEnum.FAILOVER, "ProviderError", TS))
# 1 abort on ps33a
rrs33.append(build_retry_result(pol33, ps33a, 6, RetryDecisionEnum.ABORT, "FatalError", TS))

s33 = build_retry_statistics(rrs33)
chk(s33.totalAttempts  == 6, "stats33: totalAttempts=6")
chk(s33.retryCount     == 3, "stats33: retryCount=3")
chk(s33.failoverCount  == 2, "stats33: failoverCount=2")
chk(s33.abortCount     == 1, "stats33: abortCount=1")
chk(abs(s33.retryRate    - 3/6) < 1e-6, "stats33: retryRate=0.5")
chk(abs(s33.failoverRate - 2/6) < 1e-6, "stats33: failoverRate=0.333")
chk(abs(s33.abortRate    - 1/6) < 1e-6, "stats33: abortRate=0.167")
chk(s33.retryRate + s33.failoverRate + s33.abortRate <= 1.0 + 1e-9,
    "stats33: rates sum to <= 1.0")
chk(len(s33.uniquePolicies)     == 1, "stats33: 1 unique policy")
chk(len(s33.uniqueProviders)    == 2, "stats33: 2 unique providers")
chk(len(s33.uniqueErrorClasses) == 3, "stats33: 3 unique errorClasses")
chk(s33.uniqueProviders == tuple(sorted(s33.uniqueProviders)), "stats33: uniqueProviders sorted")
chk(s33.uniqueErrorClasses == tuple(sorted(s33.uniqueErrorClasses)), "stats33: errors sorted")

# averageDelayMs computation check:
# delays for EXP(200, x2): att1=200, att2=400, att3=800, att1=200, att2=400, att6=6400
expected_delays = [
    _compute_delay(pol33, i) for i in [1, 2, 3, 1, 2, 6]
]
expected_avg = round(sum(expected_delays) / 6, 4)
chk(abs(s33.averageDelayMs - expected_avg) < 0.01, "stats33: averageDelayMs correct")

# Extended stats: provider health summary
ps33_deg  = _status("azure", "gpt35", health=D, failures=3)
ps33_unav = _status("google", "gemini", health=U, failures=7)
ext33 = build_extended_retry_statistics(rrs33, [ps33a, ps33b, ps33_deg, ps33_unav])
chk(ext33.healthyProviders     == 2, "ext33: 2 healthy")
chk(ext33.degradedProviders    == 1, "ext33: 1 degraded")
chk(ext33.unavailableProviders == 1, "ext33: 1 unavailable")
total_succ33 = ps33a.successCount + ps33b.successCount
total_fail33 = ps33a.failureCount + ps33b.failureCount + ps33_deg.failureCount + ps33_unav.failureCount
chk(ext33.totalProviderSuccesses == total_succ33, "ext33: providerSuccesses correct")
chk(ext33.totalProviderFailures  == total_fail33, "ext33: providerFailures correct")
chk(ext33.retryCount    == s33.retryCount,    "ext33: retryCount matches base")
chk(ext33.failoverCount == s33.failoverCount, "ext33: failoverCount matches base")
chk(ext33.abortCount    == s33.abortCount,    "ext33: abortCount matches base")

# ===========================================================================
# Section 34: Cross-function determinism — full pipeline
# ===========================================================================
_section_header("34. Full pipeline determinism")

# Build the same pipeline twice and verify every ID matches
def _run_pipeline(ts_override: str = TS):
    pol = build_retry_policy(RetryStrategyEnum.EXPONENTIAL_BACKOFF, ts_override,
                              max_retries=3, delay_ms=500, backoff_multiplier=2.0,
                              retryable_exceptions=["TimeoutError"])
    ps_p = build_provider_status("groq", "llama", ts_override, priority=80)
    ps_f = build_provider_status("openai", "gpt-4", ts_override, priority=60)

    results = []
    # Attempts 1-3: RETRY; attempt 4: FAILOVER
    for att in range(1, 4):
        plan = build_retry_plan(pol, ps_p, att, "TimeoutError", ts_override, [ps_p, ps_f])
        res  = execute_failover_decision(plan, pol, ps_p, ts_override, [ps_p, ps_f])
        results.append(res)

    plan4 = build_retry_plan(pol, ps_p, 4, "TimeoutError", ts_override, [ps_p, ps_f])
    res4  = execute_failover_decision(plan4, pol, ps_p, ts_override, [ps_p, ps_f])
    results.append(res4)

    stats = build_retry_statistics(results)
    return pol, ps_p, results, stats

pol_p1, ps_p1, res_p1, stats_p1 = _run_pipeline(TS)
pol_p2, ps_p2, res_p2, stats_p2 = _run_pipeline(TS2)  # different timestamp

# Policy and provider IDs are timestamp-independent
chk(pol_p1.policyId == pol_p2.policyId,  "pipeline: policyId timestamp-independent")
chk(ps_p1.providerId == ps_p2.providerId,"pipeline: providerId timestamp-independent")

# RetryResult IDs are timestamp-independent (keyed on policyId+providerId+attempt+decision)
for i, (r1, r2) in enumerate(zip(res_p1, res_p2)):
    chk(r1.retryId == r2.retryId,
        f"pipeline result {i+1}: retryId timestamp-independent")
    chk(r1.decision == r2.decision,
        f"pipeline result {i+1}: decision matches")
    chk(r1.delayMilliseconds == r2.delayMilliseconds,
        f"pipeline result {i+1}: delay matches")

# Statistics from both runs are identical
chk(stats_p1.totalAttempts  == stats_p2.totalAttempts,  "pipeline stats: totalAttempts match")
chk(stats_p1.retryCount     == stats_p2.retryCount,     "pipeline stats: retryCount match")
chk(stats_p1.failoverCount  == stats_p2.failoverCount,  "pipeline stats: failoverCount match")
chk(stats_p1.abortCount     == stats_p2.abortCount,     "pipeline stats: abortCount match")
chk(abs(stats_p1.averageDelayMs - stats_p2.averageDelayMs) < 1e-6,
    "pipeline stats: averageDelayMs match")

# Statistics values sanity
chk(stats_p1.retryCount    == 3, "pipeline: 3 RETRYs")
chk(stats_p1.failoverCount == 1, "pipeline: 1 FAILOVER")
chk(stats_p1.abortCount    == 0, "pipeline: 0 ABORTs")
chk(stats_p1.totalAttempts == 4, "pipeline: 4 total attempts")

# ===========================================================================
# Section 35: Enum values and model field validation
# ===========================================================================
_section_header("35. Enum values and field contract")

# RetryStrategyEnum values
chk(RetryStrategyEnum.NONE.value               == "NONE",               "enum NONE value")
chk(RetryStrategyEnum.IMMEDIATE.value          == "IMMEDIATE",          "enum IMMEDIATE value")
chk(RetryStrategyEnum.FIXED_DELAY.value        == "FIXED_DELAY",        "enum FIXED_DELAY value")
chk(RetryStrategyEnum.EXPONENTIAL_BACKOFF.value== "EXPONENTIAL_BACKOFF","enum EXP_BACKOFF value")
chk(len(list(RetryStrategyEnum)) == 4,          "4 strategy enum values")

# ProviderHealthEnum values
chk(ProviderHealthEnum.HEALTHY.value     == "HEALTHY",     "enum HEALTHY value")
chk(ProviderHealthEnum.DEGRADED.value    == "DEGRADED",    "enum DEGRADED value")
chk(ProviderHealthEnum.UNAVAILABLE.value == "UNAVAILABLE", "enum UNAVAILABLE value")
chk(len(list(ProviderHealthEnum)) == 3,  "3 health enum values")

# RetryDecisionEnum values
chk(RetryDecisionEnum.RETRY.value    == "RETRY",    "enum RETRY value")
chk(RetryDecisionEnum.FAILOVER.value == "FAILOVER", "enum FAILOVER value")
chk(RetryDecisionEnum.ABORT.value    == "ABORT",    "enum ABORT value")
chk(len(list(RetryDecisionEnum)) == 3, "3 decision enum values")

# RetryPolicy field types
pol35 = _policy()
chk(isinstance(pol35.policyId,           str),   "RetryPolicy.policyId: str")
chk(isinstance(pol35.policyKey,          str),   "RetryPolicy.policyKey: str")
chk(isinstance(pol35.strategy,           RetryStrategyEnum), "RetryPolicy.strategy: enum")
chk(isinstance(pol35.maxRetries,         int),   "RetryPolicy.maxRetries: int")
chk(isinstance(pol35.delayMilliseconds,  int),   "RetryPolicy.delayMilliseconds: int")
chk(isinstance(pol35.backoffMultiplier,  float), "RetryPolicy.backoffMultiplier: float")
chk(isinstance(pol35.retryableExceptions,tuple), "RetryPolicy.retryableExceptions: tuple")
chk(isinstance(pol35.createdAt,          str),   "RetryPolicy.createdAt: str")

# ProviderStatus field types
ps35 = _status()
chk(isinstance(ps35.providerId,    str),                "ProviderStatus.providerId: str")
chk(isinstance(ps35.providerKey,   str),                "ProviderStatus.providerKey: str")
chk(isinstance(ps35.provider,      str),                "ProviderStatus.provider: str")
chk(isinstance(ps35.model,         str),                "ProviderStatus.model: str")
chk(isinstance(ps35.health,        ProviderHealthEnum), "ProviderStatus.health: enum")
chk(isinstance(ps35.priority,      int),                "ProviderStatus.priority: int")
chk(isinstance(ps35.failureCount,  int),                "ProviderStatus.failureCount: int")
chk(isinstance(ps35.successCount,  int),                "ProviderStatus.successCount: int")
chk(isinstance(ps35.lastFailureAt, str),                "ProviderStatus.lastFailureAt: str")
chk(isinstance(ps35.createdAt,     str),                "ProviderStatus.createdAt: str")

# RetryResult field types
rr35 = _result(pol35, ps35)
chk(isinstance(rr35.retryId,          str),             "RetryResult.retryId: str")
chk(isinstance(rr35.retryKey,         str),             "RetryResult.retryKey: str")
chk(isinstance(rr35.retryFingerprint, str),             "RetryResult.retryFingerprint: str")
chk(isinstance(rr35.policyId,         str),             "RetryResult.policyId: str")
chk(isinstance(rr35.providerId,       str),             "RetryResult.providerId: str")
chk(isinstance(rr35.attemptNumber,    int),             "RetryResult.attemptNumber: int")
chk(isinstance(rr35.maxAttempts,      int),             "RetryResult.maxAttempts: int")
chk(isinstance(rr35.decision,         RetryDecisionEnum),"RetryResult.decision: enum")
chk(isinstance(rr35.delayMilliseconds,int),             "RetryResult.delayMilliseconds: int")
chk(isinstance(rr35.errorClass,       str),             "RetryResult.errorClass: str")
chk(isinstance(rr35.errorMessage,     str),             "RetryResult.errorMessage: str")
chk(isinstance(rr35.failoverProvider, str),             "RetryResult.failoverProvider: str")
chk(isinstance(rr35.createdAt,        str),             "RetryResult.createdAt: str")
chk(isinstance(rr35.engineVersion,    str),             "RetryResult.engineVersion: str")

# RetryPlan field types
plan35 = build_retry_plan(pol35, ps35, 1, "E", TS)
chk(isinstance(plan35.planId,             str),             "RetryPlan.planId: str")
chk(isinstance(plan35.planKey,            str),             "RetryPlan.planKey: str")
chk(isinstance(plan35.policyId,           str),             "RetryPlan.policyId: str")
chk(isinstance(plan35.primaryProviderId,  str),             "RetryPlan.primaryProviderId: str")
chk(isinstance(plan35.failoverProviderId, str),             "RetryPlan.failoverProviderId: str")
chk(isinstance(plan35.decision,           RetryDecisionEnum),"RetryPlan.decision: enum")
chk(isinstance(plan35.attemptNumber,      int),             "RetryPlan.attemptNumber: int")
chk(isinstance(plan35.maxAttempts,        int),             "RetryPlan.maxAttempts: int")
chk(isinstance(plan35.delayMilliseconds,  int),             "RetryPlan.delayMilliseconds: int")
chk(isinstance(plan35.errorClass,         str),             "RetryPlan.errorClass: str")
chk(isinstance(plan35.engineVersion,      str),             "RetryPlan.engineVersion: str")

# ===========================================================================
# Section 36: Exception hierarchy and error metadata
# ===========================================================================
_section_header("36. Exception hierarchy")

# All custom exceptions inherit from RetryFailoverError
chk(issubclass(InvalidRetryPolicyError,   RetryFailoverError), "InvalidRetryPolicyError < RetryFailoverError")
chk(issubclass(InvalidProviderStatusError,RetryFailoverError), "InvalidProviderStatusError < RetryFailoverError")
chk(issubclass(InvalidRetryResultError,   RetryFailoverError), "InvalidRetryResultError < RetryFailoverError")
chk(issubclass(RetryFailoverError,        Exception),          "RetryFailoverError < Exception")

# policy_id and retry_id metadata on base exception
err = RetryFailoverError("test msg", policy_id="pid1", retry_id="rid1")
chk(err.policy_id == "pid1",  "RetryFailoverError.policy_id stored")
chk(err.retry_id  == "rid1",  "RetryFailoverError.retry_id stored")
chk(str(err)      == "test msg", "RetryFailoverError message correct")
chk("pid1" in repr(err),      "RetryFailoverError repr contains policy_id")
chk("rid1" in repr(err),      "RetryFailoverError repr contains retry_id")

# InvalidRetryPolicyError carries message
try:
    build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=-1)
except InvalidRetryPolicyError as e:
    chk("maxRetries" in str(e),    "InvalidRetryPolicyError: message mentions maxRetries")
    chk(isinstance(e, RetryFailoverError), "InvalidRetryPolicyError is RetryFailoverError")

# InvalidProviderStatusError
try:
    build_provider_status("", "model", TS)
except InvalidProviderStatusError as e:
    chk("provider" in str(e).lower(), "InvalidProviderStatusError: message mentions provider")

# InvalidRetryResultError
pol36 = _policy()
ps36  = _status()
try:
    build_retry_result(pol36, ps36, 0, RetryDecisionEnum.RETRY, "E", TS)
except InvalidRetryResultError as e:
    chk("attemptNumber" in str(e), "InvalidRetryResultError: message mentions attemptNumber")

# Exception can be caught as base class
try:
    build_retry_policy(RetryStrategyEnum.FIXED_DELAY, TS, max_retries=-1)
except RetryFailoverError:
    chk(True, "InvalidRetryPolicyError caught as RetryFailoverError")


# ===========================================================================
# Final Summary
# ===========================================================================
print(f"\n{'='*60}")
print(f"  SMOKE TEST COMPLETE — Retry & Failover Engine")
print(f"{'='*60}")
print(f"  Passed : {_passed}")
print(f"  Failed : {_failed}")
print(f"  Total  : {_passed + _failed}")
print(f"{'='*60}")

if _failed > 0:
    print(f"\n  *** {_failed} FAILURE(S) — see [FAIL] lines above ***\n")
    raise SystemExit(1)
else:
    print(f"\n  *** ALL {_passed} ASSERTIONS PASSED ***\n")
