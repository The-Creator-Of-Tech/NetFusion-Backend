"""
Smoke Test — Token Budget Manager Engine
==========================================
Phase A4.5.2 — Verifies every model, builder, validator, serialisation path,
integration helper, fingerprint, and statistic in
services/token_budget_service.py.

Run:
    python smoke_test_token_budget_engine.py
Expected: 220+/220 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. Pure model / builder / validator / helper tests.
- Same inputs → same outputs (fully deterministic).
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, List

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
def _le(a, b, msg):  _assert(a <= b,  f"{msg} — {a!r} not <= {b!r}")
def _is(a, t, msg):  _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
def _true(v, msg):   _assert(bool(v),  f"{msg}")
def _false(v, msg):  _assert(not bool(v), f"{msg}")


# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.token_budget_service import (
    # Enumerations
    ProviderTypeEnum, BudgetStateEnum,
    # Exceptions
    TokenBudgetError, InvalidBudgetError,
    InvalidAllocationError, InvalidBudgetReportError,
    # Models
    TokenBudget, BudgetAllocation, BudgetReport, BudgetStatistics,
    # Builders
    build_token_budget, build_budget_allocation,
    build_budget_report, build_budget_statistics,
    # Validators
    validate_budget, validate_allocation, validate_report,
    # ID helpers
    _sha256_32, _sha256_64, _uuid5,
    _compute_budget_key, _compute_allocation_key,
    _compute_report_key, _compute_report_fingerprint,
    _determine_budget_state,
    # Integration helpers
    budget_from_execution_request, allocation_from_context_window,
    budget_fits, groq_model_budget,
    # Budget Operations
    calculate_available_tokens, calculate_remaining_tokens, calculate_utilization,
    reserve_output_tokens, release_reserved_tokens,
    # Budget Decisions
    detect_overflow, should_compress_context, should_truncate_context,
    # Provider Limits
    get_provider_limit, get_model_limit,
    # Utilities — budgets
    sort_budgets, filter_budgets, group_budgets, find_budget,
    # Utilities — reports
    sort_reports, filter_reports, group_reports, find_report,
    # Internal constants
    _COMPRESSION_THRESHOLD, _TRUNCATION_THRESHOLD, _WARNING_THRESHOLD,
    # Internal utility
    _estimate_tokens_from_text,
    # Version constant re-export
    TOKEN_BUDGET_ENGINE_VERSION,
)
from core.constants import TOKEN_BUDGET_ENGINE_VERSION as CONST_VERSION

TS  = "2026-07-01T12:00:00Z"
TS2 = "2026-07-01T13:00:00Z"

# ===========================================================================
# Section 1 — Engine Version
# ===========================================================================

def test_version_constant() -> None:
    _eq(TOKEN_BUDGET_ENGINE_VERSION, "token-budget-v1", "engine version string")
    _eq(CONST_VERSION, "token-budget-v1", "constant from core.constants")
    _eq(TOKEN_BUDGET_ENGINE_VERSION, CONST_VERSION, "both imports identical")
    _is(TOKEN_BUDGET_ENGINE_VERSION, str, "version is str")


test_version_constant()

# ===========================================================================
# Section 2 — Enumerations
# ===========================================================================

def test_enumerations() -> None:
    # ProviderTypeEnum
    _eq(ProviderTypeEnum.GROQ.value,      "GROQ",      "GROQ value")
    _eq(ProviderTypeEnum.OPENAI.value,    "OPENAI",    "OPENAI value")
    _eq(ProviderTypeEnum.ANTHROPIC.value, "ANTHROPIC", "ANTHROPIC value")
    _eq(ProviderTypeEnum.GOOGLE.value,    "GOOGLE",    "GOOGLE value")
    _eq(ProviderTypeEnum.OLLAMA.value,    "OLLAMA",    "OLLAMA value")
    _eq(ProviderTypeEnum.CUSTOM.value,    "CUSTOM",    "CUSTOM value")
    _eq(len(ProviderTypeEnum), 6, "ProviderTypeEnum has 6 members")

    # BudgetStateEnum
    _eq(BudgetStateEnum.VALID.value,    "VALID",    "VALID value")
    _eq(BudgetStateEnum.WARNING.value,  "WARNING",  "WARNING value")
    _eq(BudgetStateEnum.EXCEEDED.value, "EXCEEDED", "EXCEEDED value")
    _eq(len(BudgetStateEnum), 3, "BudgetStateEnum has 3 members")

    # Membership
    _in(ProviderTypeEnum.GROQ, ProviderTypeEnum, "GROQ in enum")
    _in(BudgetStateEnum.VALID, BudgetStateEnum, "VALID in enum")

    # str subclass behaviour
    _true(ProviderTypeEnum.GROQ == "GROQ",   "GROQ str equality")
    _true(BudgetStateEnum.VALID == "VALID",  "VALID str equality")


test_enumerations()


# ===========================================================================
# Section 3 — Deterministic ID helpers
# ===========================================================================

def test_id_helpers() -> None:
    # SHA-256 32-char key
    k1 = _sha256_32("GROQ", "llama-3.3-70b-versatile", "8192", "512")
    k2 = _sha256_32("GROQ", "llama-3.3-70b-versatile", "8192", "512")
    _eq(k1, k2, "sha256_32 is deterministic")
    _eq(len(k1), 32, "sha256_32 produces 32-char hex")
    _true(all(c in "0123456789abcdef" for c in k1), "sha256_32 is lowercase hex")

    # SHA-256 64-char full digest
    f1 = _sha256_64("GROQ", "model")
    f2 = _sha256_64("GROQ", "model")
    _eq(f1, f2, "sha256_64 is deterministic")
    _eq(len(f1), 64, "sha256_64 produces 64-char hex")

    # Different inputs → different keys
    k3 = _sha256_32("OPENAI", "gpt-4", "8192", "512")
    _ne(k1, k3, "different inputs produce different keys")

    # UUIDv5
    u1 = _uuid5(k1)
    u2 = _uuid5(k1)
    _eq(u1, u2, "uuid5 is deterministic")
    _eq(len(u1), 36, "uuid5 produces 36-char string")
    _in("-", u1, "uuid5 has dashes")
    _ne(_uuid5(k1), _uuid5(k3), "different keys → different UUIDs")

    # Null-byte separation: _sha256_32("a","b") joins as "a\x00b",
    # so it equals _sha256_32("a\x00b") — which is expected same behaviour.
    # Verify it differs from _sha256_32("ab") (no separator)
    k_ab    = _sha256_32("a", "b")     # "a\x00b"
    k_nojoin = _sha256_32("ab")        # "ab"
    _ne(k_ab, k_nojoin, "null-byte separator prevents collision with 'ab'")

    # Budget key derivation
    bk1 = _compute_budget_key("GROQ", "llama-3.3-70b-versatile", 8192, 512)
    bk2 = _compute_budget_key("GROQ", "llama-3.3-70b-versatile", 8192, 512)
    _eq(bk1, bk2, "budget key is deterministic")
    _eq(len(bk1), 32, "budget key is 32 chars")

    # Different reserved → different key
    bk3 = _compute_budget_key("GROQ", "llama-3.3-70b-versatile", 8192, 1024)
    _ne(bk1, bk3, "different reserved → different budget key")

    # Allocation key derivation
    ak1 = _compute_allocation_key("budget-id-123", 100, 50, 30, 200, 80, 40)
    ak2 = _compute_allocation_key("budget-id-123", 100, 50, 30, 200, 80, 40)
    _eq(ak1, ak2, "allocation key is deterministic")
    _eq(len(ak1), 32, "allocation key is 32 chars")

    # Different budget_id → different alloc key
    ak3 = _compute_allocation_key("budget-id-999", 100, 50, 30, 200, 80, 40)
    _ne(ak1, ak3, "different budgetId → different allocation key")

    # Report key
    rk1 = _compute_report_key("bkey1", "akey1")
    rk2 = _compute_report_key("bkey1", "akey1")
    _eq(rk1, rk2, "report key is deterministic")
    _eq(len(rk1), 32, "report key is 32 chars")

    # Report fingerprint
    rfp1 = _compute_report_fingerprint("rkey1", 75.5, False)
    rfp2 = _compute_report_fingerprint("rkey1", 75.5, False)
    _eq(rfp1, rfp2, "report fingerprint is deterministic")
    _eq(len(rfp1), 32, "report fingerprint is 32 chars")

    # Fingerprint changes with different overflow
    rfp3 = _compute_report_fingerprint("rkey1", 75.5, True)
    _ne(rfp1, rfp3, "overflow change → different fingerprint")

    # Fingerprint changes with different utilization
    rfp4 = _compute_report_fingerprint("rkey1", 90.0, False)
    _ne(rfp1, rfp4, "utilization change → different fingerprint")


test_id_helpers()


# ===========================================================================
# Section 4 — Budget state determination
# ===========================================================================

def test_budget_state() -> None:
    # VALID: used = 0 / 1000
    _eq(_determine_budget_state(1000, 0),   BudgetStateEnum.VALID,    "0% = VALID")
    # VALID: used < 80%
    _eq(_determine_budget_state(1000, 799), BudgetStateEnum.VALID,    "79.9% = VALID")
    # WARNING: used == 80%
    _eq(_determine_budget_state(1000, 800), BudgetStateEnum.WARNING,  "80% = WARNING")
    # WARNING: used 85%
    _eq(_determine_budget_state(1000, 850), BudgetStateEnum.WARNING,  "85% = WARNING")
    # WARNING: used 99%
    _eq(_determine_budget_state(1000, 999), BudgetStateEnum.WARNING,  "99% = WARNING")
    # EXCEEDED: used == available
    _eq(_determine_budget_state(1000, 1000), BudgetStateEnum.EXCEEDED, "100% = EXCEEDED")
    # EXCEEDED: used > available
    _eq(_determine_budget_state(1000, 1500), BudgetStateEnum.EXCEEDED, "150% = EXCEEDED")
    # Edge: available = 0, used = 0 → VALID
    _eq(_determine_budget_state(0, 0), BudgetStateEnum.VALID,    "0/0 = VALID")
    # Edge: available = 0, used > 0 → EXCEEDED
    _eq(_determine_budget_state(0, 1), BudgetStateEnum.EXCEEDED, "1/0 = EXCEEDED")


test_budget_state()

# ===========================================================================
# Section 5 — Token estimator utility
# ===========================================================================

def test_token_estimator() -> None:
    _eq(_estimate_tokens_from_text(""),          0, "empty string = 0 tokens")
    _eq(_estimate_tokens_from_text("abcd"),      1, "4-char string = 1 token")
    _eq(_estimate_tokens_from_text("abcde"),     2, "5-char string = 2 tokens (ceiling)")
    _eq(_estimate_tokens_from_text("a" * 400),  100, "400 chars = 100 tokens")
    _eq(_estimate_tokens_from_text("a" * 401),  101, "401 chars = 101 tokens (ceiling)")
    # Non-empty string always >= 1
    _ge(_estimate_tokens_from_text("x"),         1, "single char >= 1 token")


test_token_estimator()


# ===========================================================================
# Section 6 — validate_budget()
# ===========================================================================

def test_validate_budget() -> None:
    import traceback as _tb

    # Valid params — no exception
    try:
        validate_budget(ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile",
                        8192, 512, 0, TS)
        _true(True, "validate_budget: valid params pass")
    except Exception as e:
        _true(False, f"validate_budget: valid params raised {e!r}")

    # Invalid provider type
    try:
        validate_budget("GROQ", "model", 8192, 512, 0, TS)
        _true(False, "validate_budget: string provider should raise")
    except InvalidBudgetError as e:
        _in("provider", str(e), "provider error mentions 'provider'")

    # Empty model
    try:
        validate_budget(ProviderTypeEnum.GROQ, "", 8192, 512, 0, TS)
        _true(False, "validate_budget: empty model should raise")
    except InvalidBudgetError as e:
        _in("model", str(e), "model error mentions 'model'")

    # maxTokens < 1
    try:
        validate_budget(ProviderTypeEnum.GROQ, "model", 0, 0, 0, TS)
        _true(False, "validate_budget: maxTokens=0 should raise")
    except InvalidBudgetError as e:
        _in("maxTokens", str(e), "maxTokens error mentions 'maxTokens'")

    # reservedOutputTokens < 0
    try:
        validate_budget(ProviderTypeEnum.GROQ, "model", 8192, -1, 0, TS)
        _true(False, "validate_budget: negative reserved should raise")
    except InvalidBudgetError as e:
        _in("reservedOutputTokens", str(e), "reserved error text")

    # reservedOutputTokens >= maxTokens
    try:
        validate_budget(ProviderTypeEnum.GROQ, "model", 8192, 8192, 0, TS)
        _true(False, "validate_budget: reserved >= maxTokens should raise")
    except InvalidBudgetError as e:
        _in("reservedOutputTokens", str(e), "reserved >= max error text")

    # usedContextTokens < 0
    try:
        validate_budget(ProviderTypeEnum.GROQ, "model", 8192, 512, -1, TS)
        _true(False, "validate_budget: negative used should raise")
    except InvalidBudgetError as e:
        _in("usedContextTokens", str(e), "used error text")

    # Empty createdAt
    try:
        validate_budget(ProviderTypeEnum.GROQ, "model", 8192, 512, 0, "")
        _true(False, "validate_budget: empty createdAt should raise")
    except InvalidBudgetError as e:
        _in("createdAt", str(e), "createdAt error text")

    # Subclass of TokenBudgetError
    try:
        validate_budget(ProviderTypeEnum.GROQ, "", 8192, 512, 0, TS)
    except TokenBudgetError:
        _true(True, "InvalidBudgetError is subclass of TokenBudgetError")


test_validate_budget()


# ===========================================================================
# Section 7 — validate_allocation()
# ===========================================================================

def test_validate_allocation() -> None:
    # Valid params
    try:
        validate_allocation("budget-id", 100, 50, 30, 200, 80, 40, TS)
        _true(True, "validate_allocation: valid params pass")
    except Exception as e:
        _true(False, f"validate_allocation raised {e!r}")

    # Empty budgetId
    try:
        validate_allocation("", 100, 50, 30, 200, 80, 40, TS)
        _true(False, "validate_allocation: empty budgetId should raise")
    except InvalidAllocationError as e:
        _in("budgetId", str(e), "budgetId error text")

    # Negative bucket
    try:
        validate_allocation("bid", -1, 50, 30, 200, 80, 40, TS)
        _true(False, "validate_allocation: negative conversationTokens should raise")
    except InvalidAllocationError as e:
        _in("conversationTokens", str(e), "negative bucket error text")

    # Negative memoryTokens
    try:
        validate_allocation("bid", 100, -1, 30, 200, 80, 40, TS)
        _true(False, "validate_allocation: negative memoryTokens should raise")
    except InvalidAllocationError as e:
        _in("memoryTokens", str(e), "memoryTokens negative error text")

    # Empty createdAt
    try:
        validate_allocation("bid", 0, 0, 0, 0, 0, 0, "")
        _true(False, "validate_allocation: empty createdAt should raise")
    except InvalidAllocationError as e:
        _in("createdAt", str(e), "createdAt error text")

    # Subclass check
    try:
        validate_allocation("", 0, 0, 0, 0, 0, 0, TS)
    except TokenBudgetError:
        _true(True, "InvalidAllocationError is subclass of TokenBudgetError")


test_validate_allocation()


# ===========================================================================
# Section 8 — validate_report()
# ===========================================================================

def test_validate_report() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
    )
    allocation = build_budget_allocation(budget, TS, 100, 50, 30, 200, 80, 40)

    # Valid
    try:
        validate_report(budget, allocation, TS)
        _true(True, "validate_report: valid params pass")
    except Exception as e:
        _true(False, f"validate_report raised {e!r}")

    # Non-TokenBudget object
    try:
        validate_report("not-a-budget", allocation, TS)
        _true(False, "validate_report: non-budget should raise")
    except InvalidBudgetReportError as e:
        _in("budget", str(e), "budget type error text")

    # Non-BudgetAllocation object
    try:
        validate_report(budget, "not-an-alloc", TS)
        _true(False, "validate_report: non-allocation should raise")
    except InvalidBudgetReportError as e:
        _in("allocation", str(e), "allocation type error text")

    # Empty createdAt
    try:
        validate_report(budget, allocation, "")
        _true(False, "validate_report: empty createdAt should raise")
    except InvalidBudgetReportError as e:
        _in("createdAt", str(e), "createdAt error text")

    # Subclass check
    try:
        validate_report(budget, "bad", TS)
    except TokenBudgetError:
        _true(True, "InvalidBudgetReportError is subclass of TokenBudgetError")


test_validate_report()


# ===========================================================================
# Section 9 — build_token_budget()
# ===========================================================================

def test_build_token_budget() -> None:
    b = build_token_budget(
        provider               = ProviderTypeEnum.GROQ,
        model                  = "llama-3.3-70b-versatile",
        max_tokens             = 8192,
        created_at             = TS,
        reserved_output_tokens = 512,
        used_context_tokens    = 0,
    )

    # Type and immutability
    _is(b, TokenBudget, "build_token_budget returns TokenBudget")
    try:
        b.model = "hacked"
        _true(False, "TokenBudget should be immutable")
    except Exception:
        _true(True, "TokenBudget is immutable (frozen)")

    # Field values
    _eq(b.provider,               ProviderTypeEnum.GROQ,           "provider")
    _eq(b.model,                  "llama-3.3-70b-versatile",        "model")
    _eq(b.maxTokens,              8192,                             "maxTokens")
    _eq(b.reservedOutputTokens,   512,                              "reservedOutputTokens")
    _eq(b.availableContextTokens, 8192 - 512,                       "availableContextTokens")
    _eq(b.usedContextTokens,      0,                                "usedContextTokens")
    _eq(b.remainingTokens,        8192 - 512,                       "remainingTokens")
    _eq(b.state,                  BudgetStateEnum.VALID,            "state VALID")
    _eq(b.createdAt,              TS,                               "createdAt")

    # Deterministic IDs
    _is(b.budgetId,  str, "budgetId is str")
    _is(b.budgetKey, str, "budgetKey is str")
    _eq(len(b.budgetKey), 32, "budgetKey is 32 chars")
    _eq(len(b.budgetId),  36, "budgetId is UUID string (36 chars)")

    # Determinism: same inputs → same outputs
    b2 = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=0,
    )
    _eq(b.budgetKey, b2.budgetKey, "budgetKey is deterministic")
    _eq(b.budgetId,  b2.budgetId,  "budgetId is deterministic")

    # Different inputs → different IDs
    b3 = build_token_budget(
        ProviderTypeEnum.OPENAI, "gpt-4", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=0,
    )
    _ne(b.budgetKey, b3.budgetKey, "different provider → different key")

    # WARNING state
    bw = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=6800,
    )
    _eq(bw.state, BudgetStateEnum.WARNING, "high usage → WARNING")
    _eq(bw.usedContextTokens,  6800,           "usedContextTokens stored")
    _eq(bw.remainingTokens,    8192-512-6800,   "remainingTokens = available - used")

    # EXCEEDED state
    be = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=8000,
    )
    _eq(be.state, BudgetStateEnum.EXCEEDED, "over limit → EXCEEDED")
    _eq(be.remainingTokens, 0, "remainingTokens clamped to 0 when exceeded")

    # validate=False skips validation
    try:
        b_nv = build_token_budget(
            ProviderTypeEnum.GROQ, "model", 8192, TS, validate=False,
        )
        _true(True, "validate=False does not raise")
    except Exception as e:
        _true(False, f"validate=False should not raise: {e!r}")


test_build_token_budget()


# ===========================================================================
# Section 10 — build_budget_allocation()
# ===========================================================================

def test_build_budget_allocation() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
    )
    alloc = build_budget_allocation(
        budget               = budget,
        created_at           = TS,
        conversation_tokens  = 100,
        memory_tokens        = 50,
        reasoning_tokens     = 30,
        context_tokens       = 200,
        system_prompt_tokens = 80,
        user_prompt_tokens   = 40,
    )

    # Type and immutability
    _is(alloc, BudgetAllocation, "build_budget_allocation returns BudgetAllocation")
    try:
        alloc.conversationTokens = 999
        _true(False, "BudgetAllocation should be immutable")
    except Exception:
        _true(True, "BudgetAllocation is immutable")

    # Field values
    _eq(alloc.conversationTokens,   100, "conversationTokens")
    _eq(alloc.memoryTokens,          50, "memoryTokens")
    _eq(alloc.reasoningTokens,       30, "reasoningTokens")
    _eq(alloc.contextTokens,        200, "contextTokens")
    _eq(alloc.systemPromptTokens,    80, "systemPromptTokens")
    _eq(alloc.userPromptTokens,      40, "userPromptTokens")
    _eq(alloc.totalAllocatedTokens, 100+50+30+200+80+40, "totalAllocatedTokens = sum")
    _eq(alloc.createdAt, TS, "createdAt")

    # Deterministic IDs
    _is(alloc.allocationId,  str, "allocationId is str")
    _is(alloc.allocationKey, str, "allocationKey is str")
    _eq(len(alloc.allocationKey), 32, "allocationKey is 32 chars")
    _eq(len(alloc.allocationId),  36, "allocationId is 36-char UUID string")

    # Determinism
    alloc2 = build_budget_allocation(
        budget, TS,
        conversation_tokens=100, memory_tokens=50, reasoning_tokens=30,
        context_tokens=200, system_prompt_tokens=80, user_prompt_tokens=40,
    )
    _eq(alloc.allocationKey, alloc2.allocationKey, "allocationKey is deterministic")
    _eq(alloc.allocationId,  alloc2.allocationId,  "allocationId is deterministic")

    # Different budgetId → different key
    budget2 = build_token_budget(
        ProviderTypeEnum.OPENAI, "gpt-4", 8192, TS,
    )
    alloc3 = build_budget_allocation(
        budget2, TS,
        conversation_tokens=100, memory_tokens=50, reasoning_tokens=30,
        context_tokens=200, system_prompt_tokens=80, user_prompt_tokens=40,
    )
    _ne(alloc.allocationKey, alloc3.allocationKey, "different budget → different alloc key")

    # Zero allocations
    alloc_zero = build_budget_allocation(budget, TS)
    _eq(alloc_zero.totalAllocatedTokens, 0, "zero allocation = 0 total")

    # validate=False skips validation
    try:
        build_budget_allocation(budget, TS, validate=False)
        _true(True, "validate=False works")
    except Exception as e:
        _true(False, f"validate=False raised {e!r}")


test_build_budget_allocation()


# ===========================================================================
# Section 11 — build_budget_report()
# ===========================================================================

def test_build_budget_report() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,
    )
    # available = 8192 - 512 = 7680
    alloc = build_budget_allocation(
        budget, TS,
        conversation_tokens=500, memory_tokens=300, reasoning_tokens=200,
        context_tokens=1000, system_prompt_tokens=400, user_prompt_tokens=200,
    )
    # total = 2600, available = 7680 → util = 2600/7680*100 ≈ 33.8542

    report = build_budget_report(budget, alloc, TS)

    # Type and immutability
    _is(report, BudgetReport, "build_budget_report returns BudgetReport")
    try:
        report.reportKey = "hacked"
        _true(False, "BudgetReport should be immutable")
    except Exception:
        _true(True, "BudgetReport is immutable")

    # Nested objects
    _is(report.budget,     TokenBudget,     "report.budget is TokenBudget")
    _is(report.allocation, BudgetAllocation, "report.allocation is BudgetAllocation")
    _eq(report.budget.budgetId,     budget.budgetId,     "nested budget id")
    _eq(report.allocation.allocationId, alloc.allocationId, "nested alloc id")

    # utilization
    expected_util = round((2600 / 7680) * 100.0, 4)
    _eq(report.utilizationPercent, expected_util, "utilizationPercent correct")

    # overflow
    _false(report.overflowDetected, "no overflow when alloc < available")

    # Deterministic IDs
    _eq(len(report.reportKey), 32, "reportKey is 32 chars")
    _eq(len(report.reportId),  36, "reportId is 36-char UUID")
    _eq(len(report.reportFingerprint), 32, "reportFingerprint is 32 chars")

    # Determinism
    report2 = build_budget_report(budget, alloc, TS)
    _eq(report.reportKey,         report2.reportKey,         "reportKey deterministic")
    _eq(report.reportId,          report2.reportId,          "reportId deterministic")
    _eq(report.reportFingerprint, report2.reportFingerprint, "fingerprint deterministic")

    # Overflow scenario
    budget_small = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.1-8b-instant", 1000, TS,
        reserved_output_tokens=100,
    )
    alloc_big = build_budget_allocation(
        budget_small, TS,
        context_tokens=5000,
    )
    report_ov = build_budget_report(budget_small, alloc_big, TS)
    _true(report_ov.overflowDetected, "overflow detected when alloc > available")
    _gt(report_ov.utilizationPercent, 100.0, "utilization > 100 when overflowed")

    # Different allocation → different fingerprint
    alloc_diff = build_budget_allocation(budget, TS, context_tokens=999)
    report_diff = build_budget_report(budget, alloc_diff, TS)
    _ne(report.reportFingerprint, report_diff.reportFingerprint,
        "different allocation → different fingerprint")

    # createdAt stored
    _eq(report.createdAt, TS, "createdAt stored on report")


test_build_budget_report()


# ===========================================================================
# Section 12 — build_budget_statistics()
# ===========================================================================

def test_build_budget_statistics() -> None:
    # Empty list
    stats_empty = build_budget_statistics([])
    _is(stats_empty, BudgetStatistics, "empty returns BudgetStatistics")
    _eq(stats_empty.totalBudgets,           0,   "empty: totalBudgets=0")
    _eq(stats_empty.validBudgets,           0,   "empty: validBudgets=0")
    _eq(stats_empty.warningBudgets,         0,   "empty: warningBudgets=0")
    _eq(stats_empty.exceededBudgets,        0,   "empty: exceededBudgets=0")
    _eq(stats_empty.averageUtilization,     0.0, "empty: avgUtil=0.0")
    _eq(stats_empty.averageRemainingTokens, 0.0, "empty: avgRemaining=0.0")

    # Three reports: VALID, WARNING, EXCEEDED
    b_valid = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=1000,
    )
    b_warn = build_token_budget(
        ProviderTypeEnum.OPENAI, "gpt-4", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=6800,
    )
    b_exc = build_token_budget(
        ProviderTypeEnum.ANTHROPIC, "claude-3", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=8000,
    )
    a_valid = build_budget_allocation(b_valid, TS, context_tokens=1000)
    a_warn  = build_budget_allocation(b_warn,  TS, context_tokens=6800)
    a_exc   = build_budget_allocation(b_exc,   TS, context_tokens=9000)

    r_valid = build_budget_report(b_valid, a_valid, TS)
    r_warn  = build_budget_report(b_warn,  a_warn,  TS)
    r_exc   = build_budget_report(b_exc,   a_exc,   TS)

    stats = build_budget_statistics([r_valid, r_warn, r_exc])

    # Immutability
    try:
        stats.totalBudgets = 999
        _true(False, "BudgetStatistics should be immutable")
    except Exception:
        _true(True, "BudgetStatistics is immutable")

    _eq(stats.totalBudgets,    3, "totalBudgets=3")
    _eq(stats.validBudgets,    1, "validBudgets=1")
    _eq(stats.warningBudgets,  1, "warningBudgets=1")
    _eq(stats.exceededBudgets, 1, "exceededBudgets=1")

    # averageUtilization = mean of the three utilization percents
    avg_util = round(
        (r_valid.utilizationPercent + r_warn.utilizationPercent + r_exc.utilizationPercent) / 3,
        4
    )
    _eq(stats.averageUtilization, avg_util, "averageUtilization correct")

    # averageRemainingTokens = mean of remainingTokens
    avg_rem = round(
        (b_valid.remainingTokens + b_warn.remainingTokens + b_exc.remainingTokens) / 3,
        4
    )
    _eq(stats.averageRemainingTokens, avg_rem, "averageRemainingTokens correct")

    # Determinism: same list → same result
    stats2 = build_budget_statistics([r_valid, r_warn, r_exc])
    _eq(stats.averageUtilization,     stats2.averageUtilization,     "stats deterministic util")
    _eq(stats.averageRemainingTokens, stats2.averageRemainingTokens, "stats deterministic remaining")

    # Order-independent (should produce same result regardless of list order)
    stats3 = build_budget_statistics([r_exc, r_valid, r_warn])
    _eq(stats.averageUtilization, stats3.averageUtilization, "stats order-independent")
    _eq(stats.totalBudgets,       stats3.totalBudgets,       "totalBudgets order-independent")


test_build_budget_statistics()


# ===========================================================================
# Section 13 — Serialisation (model_dump / JSON round-trip)
# ===========================================================================

def test_serialisation() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,
    )
    alloc  = build_budget_allocation(budget, TS, context_tokens=500)
    report = build_budget_report(budget, alloc, TS)

    # TokenBudget serialises to dict
    bd = budget.model_dump()
    _is(bd, dict, "budget.model_dump() returns dict")
    _in("budgetId",  bd, "budgetId in dump")
    _in("budgetKey", bd, "budgetKey in dump")
    _in("provider",  bd, "provider in dump")
    _in("model",     bd, "model in dump")
    _in("state",     bd, "state in dump")
    _eq(bd["maxTokens"], 8192, "maxTokens correct in dump")

    # BudgetAllocation serialises to dict
    ad = alloc.model_dump()
    _is(ad, dict, "alloc.model_dump() returns dict")
    _in("allocationId",  ad, "allocationId in alloc dump")
    _in("totalAllocatedTokens", ad, "totalAllocatedTokens in alloc dump")
    _eq(ad["contextTokens"], 500, "contextTokens in dump")

    # BudgetReport serialises to dict
    rd = report.model_dump()
    _is(rd, dict, "report.model_dump() returns dict")
    _in("reportId",          rd, "reportId in report dump")
    _in("reportFingerprint", rd, "reportFingerprint in report dump")
    _in("utilizationPercent",rd, "utilizationPercent in report dump")
    _in("budget",            rd, "nested budget in report dump")
    _in("allocation",        rd, "nested allocation in report dump")
    _is(rd["budget"], dict, "nested budget is dict in dump")

    # JSON round-trip for TokenBudget
    import json
    bj = budget.model_dump_json()
    _is(bj, str, "model_dump_json returns str")
    parsed = json.loads(bj)
    _eq(parsed["budgetId"], budget.budgetId, "JSON round-trip budgetId")
    _eq(parsed["maxTokens"], budget.maxTokens, "JSON round-trip maxTokens")

    # JSON round-trip for BudgetReport
    rj = report.model_dump_json()
    parsed_r = json.loads(rj)
    _eq(parsed_r["reportKey"], report.reportKey, "JSON round-trip reportKey")
    _eq(
        parsed_r["budget"]["budgetKey"],
        report.budget.budgetKey,
        "JSON round-trip nested budgetKey"
    )

    # Statistics serialises
    stats = build_budget_statistics([report])
    sd = stats.model_dump()
    _is(sd, dict, "stats.model_dump() returns dict")
    _in("totalBudgets", sd, "totalBudgets in stats dump")
    _in("averageUtilization", sd, "averageUtilization in stats dump")


test_serialisation()


# ===========================================================================
# Section 14 — Integration helpers
# ===========================================================================

def test_integration_helpers() -> None:
    # ------------------------------------------------------------------ #
    # 14a — budget_from_execution_request()                               #
    # ------------------------------------------------------------------ #
    class FakeExecRequest:
        maxTokens    = 512
        model        = "llama-3.3-70b-versatile"
        systemPrompt = "You are a security analyst."
        userPrompt   = "Summarise the findings."

    req = FakeExecRequest()
    b = budget_from_execution_request(req, ProviderTypeEnum.GROQ, TS, max_tokens=8192)
    _is(b, TokenBudget, "budget_from_execution_request returns TokenBudget")
    _eq(b.provider, ProviderTypeEnum.GROQ, "provider is GROQ")
    _eq(b.model, "llama-3.3-70b-versatile", "model from exec request")
    _eq(b.maxTokens, 8192, "maxTokens from call param")
    _eq(b.reservedOutputTokens, 512, "reserved from exec_request.maxTokens")
    _gt(b.usedContextTokens, 0, "used tokens estimated from prompts")

    # Deterministic: same request → same budget key
    b2 = budget_from_execution_request(req, ProviderTypeEnum.GROQ, TS, max_tokens=8192)
    _eq(b.budgetKey, b2.budgetKey, "budget_from_execution_request deterministic")

    # ------------------------------------------------------------------ #
    # 14b — allocation_from_context_window()                              #
    # ------------------------------------------------------------------ #
    class FakeContextItem:
        def __init__(self, source_val: str, token_estimate: int):
            class _Source:
                def __init__(self, v): self.value = v
            self.source        = _Source(source_val)
            self.tokenEstimate = token_estimate

    class FakeContextWindow:
        def __init__(self, items):
            self.items = items

    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
    )
    window = FakeContextWindow([
        FakeContextItem("CONVERSATION", 200),
        FakeContextItem("MEMORY",       150),
        FakeContextItem("REASONING",    100),
        FakeContextItem("FINDING",      300),
        FakeContextItem("ALERT",         50),
        FakeContextItem("USER_INPUT",   120),
    ])

    alloc = allocation_from_context_window(
        budget, window, TS,
        system_prompt="You are a security AI.",
        user_prompt="Investigate this.",
    )
    _is(alloc, BudgetAllocation, "allocation_from_context_window returns BudgetAllocation")
    _eq(alloc.conversationTokens, 200, "CONVERSATION mapped correctly")
    _eq(alloc.memoryTokens,       150, "MEMORY mapped correctly")
    _eq(alloc.reasoningTokens,    100, "REASONING mapped correctly")
    _eq(alloc.contextTokens,      350, "FINDING+ALERT → contextTokens")
    _gt(alloc.userPromptTokens,   120, "USER_INPUT + user prompt text in userPromptTokens")
    _gt(alloc.systemPromptTokens, 0,   "system prompt produces tokens")

    # Deterministic
    alloc2 = allocation_from_context_window(
        budget, window, TS,
        system_prompt="You are a security AI.",
        user_prompt="Investigate this.",
    )
    _eq(alloc.allocationKey, alloc2.allocationKey, "allocation_from_context_window deterministic")

    # ------------------------------------------------------------------ #
    # 14c — budget_fits()                                                 #
    # ------------------------------------------------------------------ #
    b_fit  = build_token_budget(ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS)
    a_fit  = build_budget_allocation(b_fit, TS, context_tokens=500)
    a_over = build_budget_allocation(b_fit, TS, context_tokens=10000)
    _true(budget_fits(b_fit, a_fit),  "fits: alloc within budget")
    _false(budget_fits(b_fit, a_over), "does not fit: alloc exceeds budget")

    # ------------------------------------------------------------------ #
    # 14d — groq_model_budget()                                           #
    # ------------------------------------------------------------------ #
    gb = groq_model_budget("llama-3.3-70b-versatile", TS)
    _is(gb, TokenBudget, "groq_model_budget returns TokenBudget")
    _eq(gb.provider, ProviderTypeEnum.GROQ, "groq_model_budget provider=GROQ")
    _eq(gb.maxTokens, 8192, "groq_model_budget maxTokens from capabilities")
    _eq(gb.model, "llama-3.3-70b-versatile", "groq_model_budget model correct")

    # Alias resolution
    gb_alias = groq_model_budget("llama3.3-70b", TS)
    _eq(gb_alias.model, "llama-3.3-70b-versatile", "groq_model_budget resolves alias")
    _eq(gb_alias.maxTokens, 8192, "alias model maxTokens correct")

    # Unknown model falls back to 8192
    gb_unk = groq_model_budget("unknown-model-xyz", TS)
    _eq(gb_unk.maxTokens, 8192, "unknown model fallback to 8192")

    # Deterministic
    gb2 = groq_model_budget("llama-3.3-70b-versatile", TS)
    _eq(gb.budgetKey, gb2.budgetKey, "groq_model_budget deterministic")


test_integration_helpers()


# ===========================================================================
# Section 15 — Deterministic fingerprints (zero randomness)
# ===========================================================================

def test_deterministic_fingerprints() -> None:
    # Verify NO timestamp component bleeds into IDs
    budget_a = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.1-8b-instant", 8192, TS,
        reserved_output_tokens=256,
    )
    budget_b = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.1-8b-instant", 8192, TS2,  # different TS
        reserved_output_tokens=256,
    )
    # budgetKey should be SAME (TS not part of key derivation)
    _eq(budget_a.budgetKey, budget_b.budgetKey, "budgetKey does not depend on createdAt")
    _eq(budget_a.budgetId,  budget_b.budgetId,  "budgetId does not depend on createdAt")

    # Allocation: different TS → same key (TS not in key)
    alloc_a = build_budget_allocation(budget_a, TS,  context_tokens=1000)
    alloc_b = build_budget_allocation(budget_a, TS2, context_tokens=1000)
    _eq(alloc_a.allocationKey, alloc_b.allocationKey, "allocationKey does not depend on createdAt")

    # Report fingerprint: same data → same fingerprint across TS
    report_a = build_budget_report(budget_a, alloc_a, TS)
    report_b = build_budget_report(budget_b, alloc_b, TS2)
    _eq(report_a.reportKey,         report_b.reportKey,         "reportKey does not depend on createdAt")
    _eq(report_a.reportFingerprint, report_b.reportFingerprint, "reportFingerprint not TS-dependent")

    # Changing any meaningful input changes the fingerprint
    alloc_c = build_budget_allocation(budget_a, TS, context_tokens=1001)
    report_c = build_budget_report(budget_a, alloc_c, TS)
    _ne(report_a.reportFingerprint, report_c.reportFingerprint,
        "different allocation → different fingerprint")

    # Changing provider changes budget fingerprint chain
    budget_openai = build_token_budget(
        ProviderTypeEnum.OPENAI, "llama-3.1-8b-instant", 8192, TS,
        reserved_output_tokens=256,
    )
    _ne(budget_a.budgetKey, budget_openai.budgetKey, "provider change → different key")
    _ne(budget_a.budgetId,  budget_openai.budgetId,  "provider change → different id")

    # Report reportId is UUIDv5 of reportKey
    from services.token_budget_service import _uuid5 as _u5
    _eq(report_a.reportId, _u5(report_a.reportKey), "reportId = UUIDv5(reportKey)")

    # Budget budgetId is UUIDv5 of budgetKey
    _eq(budget_a.budgetId, _u5(budget_a.budgetKey), "budgetId = UUIDv5(budgetKey)")

    # Allocation allocationId is UUIDv5 of allocationKey
    _eq(alloc_a.allocationId, _u5(alloc_a.allocationKey), "allocationId = UUIDv5(allocationKey)")


test_deterministic_fingerprints()


# ===========================================================================
# Section 16 — All provider types covered
# ===========================================================================

def test_all_provider_types() -> None:
    providers = [
        ProviderTypeEnum.GROQ,
        ProviderTypeEnum.OPENAI,
        ProviderTypeEnum.ANTHROPIC,
        ProviderTypeEnum.GOOGLE,
        ProviderTypeEnum.OLLAMA,
        ProviderTypeEnum.CUSTOM,
    ]
    budgets = []
    for p in providers:
        b = build_token_budget(p, "test-model", 4096, TS, reserved_output_tokens=256)
        _is(b, TokenBudget, f"{p.value}: returns TokenBudget")
        _eq(b.provider, p, f"{p.value}: provider stored correctly")
        budgets.append(b)

    # All keys are unique (different providers → different keys)
    keys = [b.budgetKey for b in budgets]
    _eq(len(keys), len(set(keys)), "all provider budget keys are unique")


test_all_provider_types()

# ===========================================================================
# Section 17 — Edge cases and boundary conditions
# ===========================================================================

def test_edge_cases() -> None:
    # maxTokens = 1, reservedOutputTokens = 0 → available = 1
    b = build_token_budget(ProviderTypeEnum.GROQ, "model", 1, TS, reserved_output_tokens=0)
    _eq(b.maxTokens,             1, "min maxTokens = 1")
    _eq(b.availableContextTokens, 1, "available = 1 when reserved = 0")
    _eq(b.remainingTokens,        1, "remaining = 1 when nothing used")

    # Used exactly equal to available → EXCEEDED (100% utilization)
    b_eq = build_token_budget(
        ProviderTypeEnum.GROQ, "model", 1000, TS,
        reserved_output_tokens=0, used_context_tokens=1000,
    )
    _eq(b_eq.state, BudgetStateEnum.EXCEEDED, "used == available → EXCEEDED")
    _eq(b_eq.remainingTokens, 0, "remaining = 0 when fully used")

    # White-space model name is stripped
    b_ws = build_token_budget(
        ProviderTypeEnum.GROQ, "  model-name  ", 8192, TS,
    )
    _eq(b_ws.model, "model-name", "model name stripped")

    # Very large token values
    b_big = build_token_budget(
        ProviderTypeEnum.GROQ, "model", 1_000_000, TS,
        reserved_output_tokens=10_000, used_context_tokens=50_000,
    )
    _eq(b_big.availableContextTokens, 990_000,  "large available correct")
    _eq(b_big.remainingTokens,        940_000,  "large remaining correct")
    _eq(b_big.state, BudgetStateEnum.VALID, "low utilization = VALID")

    # Allocation with single bucket
    budget = build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS)
    alloc_single = build_budget_allocation(budget, TS, system_prompt_tokens=200)
    _eq(alloc_single.totalAllocatedTokens, 200, "single bucket total")
    _eq(alloc_single.conversationTokens,     0, "other buckets = 0")

    # Report with zero utilization
    b_zero = build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS)
    a_zero = build_budget_allocation(b_zero, TS)
    r_zero = build_budget_report(b_zero, a_zero, TS)
    _eq(r_zero.utilizationPercent, 0.0, "zero allocation = 0% utilization")
    _false(r_zero.overflowDetected, "zero allocation = no overflow")

    # Statistics with single report
    stats_single = build_budget_statistics([r_zero])
    _eq(stats_single.totalBudgets, 1, "single report statistics")
    _eq(stats_single.validBudgets, 1, "single VALID report")


test_edge_cases()


# ===========================================================================
# Section 18 — Exception hierarchy
# ===========================================================================

def test_exception_hierarchy() -> None:
    _true(issubclass(InvalidBudgetError,      TokenBudgetError), "InvalidBudgetError < TokenBudgetError")
    _true(issubclass(InvalidAllocationError,  TokenBudgetError), "InvalidAllocationError < TokenBudgetError")
    _true(issubclass(InvalidBudgetReportError,TokenBudgetError), "InvalidBudgetReportError < TokenBudgetError")
    _true(issubclass(TokenBudgetError,        Exception),        "TokenBudgetError < Exception")

    # All three are catchable as TokenBudgetError
    for exc_cls, name in [
        (InvalidBudgetError, "InvalidBudgetError"),
        (InvalidAllocationError, "InvalidAllocationError"),
        (InvalidBudgetReportError, "InvalidBudgetReportError"),
    ]:
        try:
            raise exc_cls("test")
        except TokenBudgetError:
            _true(True, f"{name} caught as TokenBudgetError")
        except Exception:
            _true(False, f"{name} not caught as TokenBudgetError")


test_exception_hierarchy()

# ===========================================================================
# Section 19 — Build pipeline: budget → allocation → report → statistics
# ===========================================================================

def test_full_pipeline() -> None:
    """End-to-end pipeline: build budget, allocate, report, aggregate stats."""
    b1 = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=1000,
    )
    b2 = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.1-8b-instant", 8192, TS,
        reserved_output_tokens=256, used_context_tokens=6800,
    )
    b3 = build_token_budget(
        ProviderTypeEnum.OPENAI, "gpt-4", 8192, TS,
        reserved_output_tokens=1024, used_context_tokens=8000,
    )

    a1 = build_budget_allocation(b1, TS, conversation_tokens=300, context_tokens=700)
    a2 = build_budget_allocation(b2, TS, conversation_tokens=1000, memory_tokens=500,
                                  reasoning_tokens=300, context_tokens=5000)
    a3 = build_budget_allocation(b3, TS, system_prompt_tokens=2000, user_prompt_tokens=6000)

    r1 = build_budget_report(b1, a1, TS)
    r2 = build_budget_report(b2, a2, TS)
    r3 = build_budget_report(b3, a3, TS)

    # b1: VALID, b2: WARNING, b3: EXCEEDED
    _eq(b1.state, BudgetStateEnum.VALID,    "pipeline b1=VALID")
    _eq(b2.state, BudgetStateEnum.WARNING,  "pipeline b2=WARNING")
    _eq(b3.state, BudgetStateEnum.EXCEEDED, "pipeline b3=EXCEEDED")

    # Reports have correct overflow flags
    _false(r1.overflowDetected, "pipeline r1: no overflow")
    # r2: alloc=6800 vs available=8192-256=7936 → no overflow
    _false(r2.overflowDetected, "pipeline r2: no overflow (alloc < available)")
    # r3: alloc=8000 vs available=8192-1024=7168 → overflow
    _true(r3.overflowDetected, "pipeline r3: overflow detected")

    stats = build_budget_statistics([r1, r2, r3])
    _eq(stats.totalBudgets,    3, "pipeline: 3 budgets")
    _eq(stats.validBudgets,    1, "pipeline: 1 valid")
    _eq(stats.warningBudgets,  1, "pipeline: 1 warning")
    _eq(stats.exceededBudgets, 1, "pipeline: 1 exceeded")

    # Statistics are deterministic across calls
    stats2 = build_budget_statistics([r1, r2, r3])
    _eq(stats.averageUtilization,     stats2.averageUtilization,     "pipeline stats deterministic")
    _eq(stats.averageRemainingTokens, stats2.averageRemainingTokens, "pipeline remaining deterministic")


test_full_pipeline()


# ===========================================================================
# Section 20 — Model field presence and types
# ===========================================================================

def test_model_fields() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
    )
    alloc  = build_budget_allocation(budget, TS, context_tokens=500)
    report = build_budget_report(budget, alloc, TS)
    stats  = build_budget_statistics([report])

    # TokenBudget fields
    for field in ["budgetId", "budgetKey", "provider", "model", "maxTokens",
                  "reservedOutputTokens", "availableContextTokens",
                  "usedContextTokens", "remainingTokens", "state", "createdAt"]:
        _true(hasattr(budget, field), f"TokenBudget has field: {field}")

    # BudgetAllocation fields
    for field in ["allocationId", "allocationKey", "conversationTokens",
                  "memoryTokens", "reasoningTokens", "contextTokens",
                  "systemPromptTokens", "userPromptTokens",
                  "totalAllocatedTokens", "createdAt"]:
        _true(hasattr(alloc, field), f"BudgetAllocation has field: {field}")

    # BudgetReport fields
    for field in ["reportId", "reportKey", "budget", "allocation",
                  "utilizationPercent", "overflowDetected",
                  "reportFingerprint", "createdAt"]:
        _true(hasattr(report, field), f"BudgetReport has field: {field}")

    # BudgetStatistics fields
    for field in ["totalBudgets", "validBudgets", "warningBudgets",
                  "exceededBudgets", "averageUtilization",
                  "averageRemainingTokens"]:
        _true(hasattr(stats, field), f"BudgetStatistics has field: {field}")

    # Type checks
    _is(budget.maxTokens,              int,             "maxTokens is int")
    _is(budget.reservedOutputTokens,   int,             "reservedOutputTokens is int")
    _is(budget.availableContextTokens, int,             "availableContextTokens is int")
    _is(budget.usedContextTokens,      int,             "usedContextTokens is int")
    _is(budget.remainingTokens,        int,             "remainingTokens is int")
    _is(budget.state,                  BudgetStateEnum, "state is BudgetStateEnum")
    _is(budget.provider,               ProviderTypeEnum,"provider is ProviderTypeEnum")
    _is(report.utilizationPercent,     float,           "utilizationPercent is float")
    _is(report.overflowDetected,       bool,            "overflowDetected is bool")
    _is(stats.averageUtilization,      float,           "averageUtilization is float")
    _is(stats.averageRemainingTokens,  float,           "averageRemainingTokens is float")


test_model_fields()


# ===========================================================================
# Section 21 — calculate_available_tokens()
# ===========================================================================

def test_calculate_available_tokens() -> None:
    _eq(calculate_available_tokens(8192, 512),  7680, "8192-512=7680")
    _eq(calculate_available_tokens(8192, 0),    8192, "reserved=0 → all available")
    _eq(calculate_available_tokens(1000, 1000),    0, "reserved=max → 0 available")
    _eq(calculate_available_tokens(1000, 2000),    0, "over-reserved clamped to 0")
    _eq(calculate_available_tokens(0, 0),           0, "0-0=0")
    _eq(calculate_available_tokens(4096, 256),   3840, "4096-256=3840")
    # Large values
    _eq(calculate_available_tokens(1_000_000, 10_000), 990_000, "large value correct")
    # Return type
    _is(calculate_available_tokens(8192, 512), int, "returns int")


test_calculate_available_tokens()

# ===========================================================================
# Section 22 — calculate_remaining_tokens()
# ===========================================================================

def test_calculate_remaining_tokens() -> None:
    _eq(calculate_remaining_tokens(7680, 0),    7680, "unused → all remaining")
    _eq(calculate_remaining_tokens(7680, 1000), 6680, "7680-1000=6680")
    _eq(calculate_remaining_tokens(7680, 7680),    0, "fully used → 0 remaining")
    _eq(calculate_remaining_tokens(7680, 9000),    0, "over-used clamped to 0")
    _eq(calculate_remaining_tokens(0, 0),           0, "0 available, 0 used → 0")
    _eq(calculate_remaining_tokens(0, 100),         0, "0 available, used>0 → 0")
    _is(calculate_remaining_tokens(7680, 1000), int, "returns int")
    # Consistent with budget model
    b = build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS,
                           reserved_output_tokens=512, used_context_tokens=2000)
    _eq(
        calculate_remaining_tokens(b.availableContextTokens, b.usedContextTokens),
        b.remainingTokens,
        "consistent with budget.remainingTokens",
    )


test_calculate_remaining_tokens()

# ===========================================================================
# Section 23 — calculate_utilization()
# ===========================================================================

def test_calculate_utilization() -> None:
    _eq(calculate_utilization(1000, 0),    0.0,    "0% utilization")
    _eq(calculate_utilization(1000, 500),  0.5,    "50% utilization")
    _eq(calculate_utilization(1000, 800),  0.8,    "80% utilization")
    _eq(calculate_utilization(1000, 1000), 1.0,    "100% utilization")
    _eq(calculate_utilization(1000, 1500), 1.5,    "150% (over capacity)")
    _eq(calculate_utilization(0, 0),       0.0,    "0/0 = 0.0")
    _eq(calculate_utilization(0, 100),     0.0,    "x/0 = 0.0 (no div by zero)")
    _is(calculate_utilization(1000, 500), float,   "returns float")
    # Rounding to 6 decimal places
    util = calculate_utilization(3000, 1000)
    _eq(util, round(1000/3000, 6), "rounded to 6dp")
    # Consistent with budget state transitions
    _lt(calculate_utilization(1000, 799), _WARNING_THRESHOLD, "79.9% < warning threshold")
    _ge(calculate_utilization(1000, 800), _WARNING_THRESHOLD, "80% >= warning threshold")


test_calculate_utilization()


# ===========================================================================
# Section 24 — reserve_output_tokens()
# ===========================================================================

def test_reserve_output_tokens() -> None:
    b = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,
    )
    b2 = reserve_output_tokens(b, 256, TS2)
    _is(b2, TokenBudget, "reserve returns TokenBudget")
    _eq(b2.reservedOutputTokens,   512+256, "reserved increased by 256")
    _eq(b2.availableContextTokens, 8192-512-256, "available decreased")
    _eq(b2.maxTokens, 8192, "maxTokens unchanged")
    _eq(b2.provider, b.provider, "provider unchanged")
    _eq(b2.model, b.model, "model unchanged")
    _eq(b2.createdAt, TS2, "createdAt is new timestamp")

    # Original NOT mutated
    _eq(b.reservedOutputTokens, 512, "original reserved unchanged")
    _eq(b.availableContextTokens, 8192-512, "original available unchanged")

    # Different key from original
    _ne(b.budgetKey, b2.budgetKey, "new budget different key")
    _ne(b.budgetId,  b2.budgetId,  "new budget different id")

    # Reserve 0 — same key
    b3 = reserve_output_tokens(b, 0, TS)
    _eq(b3.reservedOutputTokens,   b.reservedOutputTokens, "reserve 0 = same reserved")
    _eq(b3.availableContextTokens, b.availableContextTokens, "reserve 0 = same available")
    _eq(b3.budgetKey, b.budgetKey, "reserve 0 = same key")

    # Clamping: cannot reserve >= maxTokens
    b4 = reserve_output_tokens(b, 100_000, TS)
    _lt(b4.reservedOutputTokens, b4.maxTokens, "reserved clamped below maxTokens")
    _ge(b4.availableContextTokens, 1, "at least 1 token always available after clamp")

    # State recalculated
    b_used = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512, used_context_tokens=6800,
    )
    _eq(b_used.state, BudgetStateEnum.WARNING, "precondition: WARNING state")
    b_used2 = reserve_output_tokens(b_used, 500, TS)
    # available = 8192-1012=7180, used=6800, util=94.7% → WARNING (< 100%)
    _eq(b_used2.state, BudgetStateEnum.WARNING, "state re-evaluated: stays WARNING at 94.7%")

    # Negative raises
    try:
        reserve_output_tokens(b, -1, TS)
        _true(False, "negative reserve should raise")
    except InvalidBudgetError:
        _true(True, "negative reserve raises InvalidBudgetError")

    # Deterministic
    b5a = reserve_output_tokens(b, 128, TS)
    b5b = reserve_output_tokens(b, 128, TS)
    _eq(b5a.budgetKey, b5b.budgetKey, "reserve is deterministic")
    _eq(b5a.budgetId,  b5b.budgetId,  "reserve id is deterministic")


test_reserve_output_tokens()

# ===========================================================================
# Section 25 — release_reserved_tokens()
# ===========================================================================

def test_release_reserved_tokens() -> None:
    b = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=1024,
    )
    b2 = release_reserved_tokens(b, 512, TS2)
    _is(b2, TokenBudget, "release returns TokenBudget")
    _eq(b2.reservedOutputTokens,   1024-512, "reserved decreased")
    _eq(b2.availableContextTokens, 8192-(1024-512), "available increased")
    _eq(b2.maxTokens, 8192, "maxTokens unchanged")
    _eq(b2.createdAt, TS2, "createdAt is new timestamp")

    # Original NOT mutated
    _eq(b.reservedOutputTokens, 1024, "original reserved unchanged")
    _ne(b.budgetKey, b2.budgetKey, "different key after release")

    # Release all → reserved = 0
    b3 = release_reserved_tokens(b, 10_000, TS)
    _eq(b3.reservedOutputTokens,   0, "release all → reserved = 0")
    _eq(b3.availableContextTokens, b3.maxTokens, "release all → full availability")

    # Release 0 — same result
    b4 = release_reserved_tokens(b, 0, TS)
    _eq(b4.reservedOutputTokens, b.reservedOutputTokens, "release 0 = unchanged")
    _eq(b4.budgetKey, b.budgetKey, "release 0 = same key")

    # State re-evaluated
    b_warn = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=1024, used_context_tokens=6200,
    )
    b_released = release_reserved_tokens(b_warn, 800, TS)
    _in(b_released.state, list(BudgetStateEnum), "state is valid after release")
    # After release: reserved=224, available=7968, used=6200, util=77.8% → VALID (< 80%)
    _eq(b_released.state, BudgetStateEnum.VALID, "re-evaluated to VALID after release")

    # Negative raises
    try:
        release_reserved_tokens(b, -1, TS)
        _true(False, "negative release should raise")
    except InvalidBudgetError:
        _true(True, "negative release raises InvalidBudgetError")

    # Deterministic
    b5a = release_reserved_tokens(b, 256, TS)
    b5b = release_reserved_tokens(b, 256, TS)
    _eq(b5a.budgetKey, b5b.budgetKey, "release is deterministic")
    _eq(b5a.budgetId,  b5b.budgetId,  "release id is deterministic")


test_release_reserved_tokens()

# ===========================================================================
# Section 26 — detect_overflow()
# ===========================================================================

def test_detect_overflow() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,   # available = 7680
    )
    alloc_fit = build_budget_allocation(budget, TS, context_tokens=5000)
    _false(detect_overflow(budget, alloc_fit),  "alloc < available → no overflow")

    alloc_exact = build_budget_allocation(budget, TS, context_tokens=7680)
    _false(detect_overflow(budget, alloc_exact), "alloc == available → no overflow")

    alloc_over = build_budget_allocation(budget, TS, context_tokens=7681)
    _true(detect_overflow(budget, alloc_over),  "alloc > available → overflow")

    b_tiny = build_token_budget(
        ProviderTypeEnum.GROQ, "model", 8192, TS, reserved_output_tokens=8191,
    )
    alloc_tiny = build_budget_allocation(b_tiny, TS, context_tokens=2)
    _true(detect_overflow(b_tiny, alloc_tiny), "2 > 1 available → overflow")

    _is(detect_overflow(budget, alloc_fit), bool, "detect_overflow returns bool")

    # Consistent with BudgetReport
    r_fit  = build_budget_report(budget, alloc_fit, TS)
    r_over = build_budget_report(budget, alloc_over, TS)
    _eq(detect_overflow(budget, alloc_fit),  r_fit.overflowDetected,  "consistent with report (fit)")
    _eq(detect_overflow(budget, alloc_over), r_over.overflowDetected, "consistent with report (over)")


test_detect_overflow()

# ===========================================================================
# Section 27 — should_compress_context()
# ===========================================================================

def test_should_compress_context() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,   # available = 7680
    )

    # Below 70%
    alloc_low = build_budget_allocation(budget, TS, context_tokens=5000)  # ~65%
    _false(should_compress_context(budget, alloc_low), "65% < 70% → no compress")

    # Exactly at 70%
    at_tokens = int(7680 * _COMPRESSION_THRESHOLD)
    alloc_at = build_budget_allocation(budget, TS, context_tokens=at_tokens)
    _true(should_compress_context(budget, alloc_at), "exactly 70% → compress")

    # Above 70%, below 90%
    alloc_mid = build_budget_allocation(budget, TS, context_tokens=6500)  # ~84.6%
    _true(should_compress_context(budget, alloc_mid), "84% → compress")

    # Overflow: compress still true
    alloc_over = build_budget_allocation(budget, TS, context_tokens=9000)
    _true(should_compress_context(budget, alloc_over), "overflow → compress true")

    # Zero used → no compress
    alloc_zero = build_budget_allocation(budget, TS)
    _false(should_compress_context(budget, alloc_zero), "0% → no compress")

    _is(should_compress_context(budget, alloc_low), bool, "returns bool")
    _eq(_COMPRESSION_THRESHOLD, 0.70, "compression threshold constant = 0.70")


test_should_compress_context()

# ===========================================================================
# Section 28 — should_truncate_context()
# ===========================================================================

def test_should_truncate_context() -> None:
    budget = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,   # available = 7680
    )

    # Below 90%
    alloc_low = build_budget_allocation(budget, TS, context_tokens=6000)  # ~78%
    _false(should_truncate_context(budget, alloc_low), "78% < 90% → no truncate")

    # Exactly at 90%
    at_tokens = int(7680 * _TRUNCATION_THRESHOLD)
    alloc_at = build_budget_allocation(budget, TS, context_tokens=at_tokens)
    _true(should_truncate_context(budget, alloc_at), "exactly 90% → truncate")

    # Between 90-100%
    alloc_high = build_budget_allocation(budget, TS, context_tokens=7500)
    _true(should_truncate_context(budget, alloc_high), "97% → truncate")

    # Overflow
    alloc_over = build_budget_allocation(budget, TS, context_tokens=8000)
    _true(should_truncate_context(budget, alloc_over), "overflow → truncate")

    # Zero → no truncate
    alloc_zero = build_budget_allocation(budget, TS)
    _false(should_truncate_context(budget, alloc_zero), "0% → no truncate")

    _is(should_truncate_context(budget, alloc_low), bool, "returns bool")
    _eq(_TRUNCATION_THRESHOLD, 0.90, "truncation threshold constant = 0.90")
    _lt(_COMPRESSION_THRESHOLD, _TRUNCATION_THRESHOLD, "compress < truncate threshold")


test_should_truncate_context()


# ===========================================================================
# Section 29 — get_provider_limit()
# ===========================================================================

def test_get_provider_limit() -> None:
    _eq(get_provider_limit(ProviderTypeEnum.GROQ),      131072,  "GROQ limit = 131072")
    _eq(get_provider_limit(ProviderTypeEnum.OPENAI),    128000,  "OPENAI limit = 128000")
    _eq(get_provider_limit(ProviderTypeEnum.ANTHROPIC), 200000,  "ANTHROPIC limit = 200000")
    _eq(get_provider_limit(ProviderTypeEnum.GOOGLE),    1000000, "GOOGLE limit = 1000000")
    _eq(get_provider_limit(ProviderTypeEnum.OLLAMA),    8192,    "OLLAMA limit = 8192")
    _eq(get_provider_limit(ProviderTypeEnum.CUSTOM),    8192,    "CUSTOM limit = 8192")
    # All return int
    for p in ProviderTypeEnum:
        _is(get_provider_limit(p), int, f"{p.value} limit is int")
    # All are > 0
    for p in ProviderTypeEnum:
        _gt(get_provider_limit(p), 0, f"{p.value} limit > 0")
    # Deterministic
    _eq(get_provider_limit(ProviderTypeEnum.GROQ),
        get_provider_limit(ProviderTypeEnum.GROQ), "GROQ limit is deterministic")


test_get_provider_limit()


# ===========================================================================
# Section 30 — get_model_limit()
# ===========================================================================

def test_get_model_limit() -> None:
    # Groq models
    _eq(get_model_limit("llama-3.3-70b-versatile", ProviderTypeEnum.GROQ),
        128000, "llama-3.3-70b-versatile limit")
    _eq(get_model_limit("llama-3.1-8b-instant", ProviderTypeEnum.GROQ),
        128000, "llama-3.1-8b-instant limit")
    # OpenAI models
    _eq(get_model_limit("gpt-4o", ProviderTypeEnum.OPENAI),   128000, "gpt-4o limit")
    _eq(get_model_limit("gpt-4",  ProviderTypeEnum.OPENAI),   8192,   "gpt-4 limit")
    _eq(get_model_limit("gpt-3.5-turbo", ProviderTypeEnum.OPENAI), 16385, "gpt-3.5-turbo")
    # Anthropic models
    _eq(get_model_limit("claude-3-opus-20240229", ProviderTypeEnum.ANTHROPIC),
        200000, "claude-3-opus limit")
    _eq(get_model_limit("claude-3-5-sonnet-20241022", ProviderTypeEnum.ANTHROPIC),
        200000, "claude-3-5-sonnet limit")
    # Google models
    _eq(get_model_limit("gemini-1.5-pro", ProviderTypeEnum.GOOGLE),
        1000000, "gemini-1.5-pro limit")
    _eq(get_model_limit("gemini-1.0-pro", ProviderTypeEnum.GOOGLE),
        32760, "gemini-1.0-pro limit")
    # Ollama models
    _eq(get_model_limit("llama3", ProviderTypeEnum.OLLAMA), 8192, "llama3 limit")
    _eq(get_model_limit("mixtral", ProviderTypeEnum.OLLAMA), 32768, "mixtral limit")
    # Unknown model → provider fallback
    unk = get_model_limit("completely-unknown-model", ProviderTypeEnum.GROQ)
    _eq(unk, get_provider_limit(ProviderTypeEnum.GROQ), "unknown model falls back to provider limit")
    # Return type
    _is(get_model_limit("gpt-4o", ProviderTypeEnum.OPENAI), int, "returns int")
    # All known model limits > 0
    for m in ["gpt-4o", "claude-3-opus-20240229", "gemini-1.5-pro", "llama3"]:
        _gt(get_model_limit(m), 0, f"{m} limit > 0")
    # Deterministic
    _eq(
        get_model_limit("gpt-4o", ProviderTypeEnum.OPENAI),
        get_model_limit("gpt-4o", ProviderTypeEnum.OPENAI),
        "model limit is deterministic",
    )


test_get_model_limit()


# ===========================================================================
# Section 31 — sort_budgets()
# ===========================================================================

def _make_budget_set():
    """Return 4 budgets with distinct providers, states, tokens."""
    b1 = build_token_budget(ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile",
                            8192, TS, reserved_output_tokens=512, used_context_tokens=500)
    b2 = build_token_budget(ProviderTypeEnum.OPENAI, "gpt-4",
                            8192, TS, reserved_output_tokens=512, used_context_tokens=6800)
    b3 = build_token_budget(ProviderTypeEnum.ANTHROPIC, "claude-3-opus-20240229",
                            8192, TS, reserved_output_tokens=512, used_context_tokens=8000)
    b4 = build_token_budget(ProviderTypeEnum.GOOGLE, "gemini-1.5-pro",
                            8192, TS, reserved_output_tokens=256, used_context_tokens=2000)
    return [b1, b2, b3, b4]

def test_sort_budgets() -> None:
    budgets = _make_budget_set()

    # Sort by remainingTokens ASC
    s = sort_budgets(budgets, key="remainingTokens", ascending=True)
    _is(s, list, "sort_budgets returns list")
    _eq(len(s), 4, "all budgets returned")
    for i in range(len(s)-1):
        _le(s[i].remainingTokens, s[i+1].remainingTokens, f"remainingTokens ASC [{i}]")

    # Sort by remainingTokens DESC
    sd = sort_budgets(budgets, key="remainingTokens", ascending=False)
    for i in range(len(sd)-1):
        _ge(sd[i].remainingTokens, sd[i+1].remainingTokens, f"remainingTokens DESC [{i}]")

    # Sort by state ASC (VALID < WARNING < EXCEEDED)
    ss = sort_budgets(budgets, key="state", ascending=True)
    state_order = {"VALID": 0, "WARNING": 1, "EXCEEDED": 2}
    for i in range(len(ss)-1):
        _le(state_order[ss[i].state.value], state_order[ss[i+1].state.value],
            f"state ASC [{i}]")

    # Sort by model ASC
    sm = sort_budgets(budgets, key="model", ascending=True)
    for i in range(len(sm)-1):
        _le(sm[i].model, sm[i+1].model, f"model ASC [{i}]")

    # Sort by provider ASC
    sp = sort_budgets(budgets, key="provider", ascending=True)
    for i in range(len(sp)-1):
        _le(sp[i].provider.value, sp[i+1].provider.value, f"provider ASC [{i}]")

    # Sort by maxTokens
    sb = sort_budgets(budgets, key="maxTokens")
    _is(sb, list, "sort by maxTokens returns list")

    # Input not mutated
    original_first = budgets[0].budgetId
    _ = sort_budgets(budgets, key="remainingTokens")
    _eq(budgets[0].budgetId, original_first, "input list not mutated")

    # Invalid key raises
    try:
        sort_budgets(budgets, key="invalid_key")
        _true(False, "invalid key should raise")
    except ValueError as e:
        _in("invalid_key", str(e), "ValueError mentions bad key")

    # Empty list
    _eq(sort_budgets([], key="remainingTokens"), [], "empty list returns empty")

    # Deterministic: same inputs → same order
    s1 = sort_budgets(budgets, key="remainingTokens")
    s2 = sort_budgets(budgets, key="remainingTokens")
    _eq([b.budgetId for b in s1], [b.budgetId for b in s2], "sort is deterministic")


test_sort_budgets()


# ===========================================================================
# Section 32 — filter_budgets()
# ===========================================================================

def test_filter_budgets() -> None:
    budgets = _make_budget_set()  # GROQ/VALID, OPENAI/WARNING, ANTHROPIC/EXCEEDED, GOOGLE/VALID

    # Filter by provider
    groq_only = filter_budgets(budgets, provider=ProviderTypeEnum.GROQ)
    _eq(len(groq_only), 1, "filter GROQ: 1 result")
    _eq(groq_only[0].provider, ProviderTypeEnum.GROQ, "filtered provider is GROQ")

    # Filter by state VALID
    valid_only = filter_budgets(budgets, state=BudgetStateEnum.VALID)
    _ge(len(valid_only), 1, "at least 1 VALID budget")
    for b in valid_only:
        _eq(b.state, BudgetStateEnum.VALID, "all filtered budgets are VALID")

    # Filter by state EXCEEDED
    exc_only = filter_budgets(budgets, state=BudgetStateEnum.EXCEEDED)
    _eq(len(exc_only), 1, "1 EXCEEDED budget")
    _eq(exc_only[0].state, BudgetStateEnum.EXCEEDED, "filtered is EXCEEDED")

    # Filter by model
    groq_model_match = filter_budgets(budgets, model="llama-3.3-70b-versatile")
    _eq(len(groq_model_match), 1, "model filter: 1 match")
    _eq(groq_model_match[0].model, "llama-3.3-70b-versatile", "model filter correct")

    # Filter by min_remaining
    high_remaining = filter_budgets(budgets, min_remaining=5000)
    for b in high_remaining:
        _ge(b.remainingTokens, 5000, "all have >= 5000 remaining")

    # Filter by max_used
    low_used = filter_budgets(budgets, max_used=1000)
    for b in low_used:
        _le(b.usedContextTokens, 1000, "all have <= 1000 used")

    # Combined filter
    combined = filter_budgets(
        budgets, provider=ProviderTypeEnum.GROQ, state=BudgetStateEnum.VALID,
    )
    _true(len(combined) <= 1, "combined filter narrows correctly")

    # No criteria → all pass
    all_pass = filter_budgets(budgets)
    _eq(len(all_pass), 4, "no filter = all pass")

    # No matches
    no_match = filter_budgets(budgets, model="no-such-model")
    _eq(no_match, [], "no match returns empty list")

    # Empty input
    _eq(filter_budgets([]), [], "empty list returns empty")

    # Input not mutated
    original_len = len(budgets)
    _ = filter_budgets(budgets, state=BudgetStateEnum.VALID)
    _eq(len(budgets), original_len, "input not mutated")


test_filter_budgets()


# ===========================================================================
# Section 33 — group_budgets()
# ===========================================================================

def test_group_budgets() -> None:
    budgets = _make_budget_set()

    # Group by provider
    by_prov = group_budgets(budgets, by="provider")
    _is(by_prov, dict, "group_budgets returns dict")
    _in("GROQ",      by_prov, "GROQ key present")
    _in("OPENAI",    by_prov, "OPENAI key present")
    _in("ANTHROPIC", by_prov, "ANTHROPIC key present")
    _in("GOOGLE",    by_prov, "GOOGLE key present")
    total = sum(len(v) for v in by_prov.values())
    _eq(total, 4, "all budgets accounted for in provider groups")

    # Group by state
    by_state = group_budgets(budgets, by="state")
    _is(by_state, dict, "group by state returns dict")
    total_s = sum(len(v) for v in by_state.values())
    _eq(total_s, 4, "all budgets accounted for in state groups")
    # Each group contains only that state
    for state_val, grp in by_state.items():
        for b in grp:
            _eq(b.state.value, state_val, f"state group {state_val!r} correct")

    # Group by model
    by_model = group_budgets(budgets, by="model")
    _is(by_model, dict, "group by model returns dict")
    total_m = sum(len(v) for v in by_model.values())
    _eq(total_m, 4, "all budgets in model groups")

    # Within each group, order is budgetId ASC
    for key, grp in by_prov.items():
        ids = [b.budgetId for b in grp]
        _eq(ids, sorted(ids), f"provider group {key!r} sorted by budgetId")

    # Invalid key raises
    try:
        group_budgets(budgets, by="invalid")
        _true(False, "invalid group key should raise")
    except ValueError:
        _true(True, "invalid group key raises ValueError")

    # Empty input
    _eq(group_budgets([], by="provider"), {}, "empty input → empty dict")

    # Deterministic
    g1 = group_budgets(budgets, by="state")
    g2 = group_budgets(budgets, by="state")
    for k in g1:
        ids1 = [b.budgetId for b in g1[k]]
        ids2 = [b.budgetId for b in g2[k]]
        _eq(ids1, ids2, f"group_budgets state={k!r} deterministic")


test_group_budgets()

# ===========================================================================
# Section 34 — find_budget()
# ===========================================================================

def test_find_budget() -> None:
    budgets = _make_budget_set()

    # Find existing
    target = budgets[2]
    found = find_budget(budgets, target.budgetId)
    _true(found is not None, "find_budget: existing budget found")
    _eq(found.budgetId, target.budgetId, "found correct budget")

    # Not found
    _true(find_budget(budgets, "nonexistent-id") is None, "not found returns None")

    # Empty list
    _true(find_budget([], budgets[0].budgetId) is None, "empty list returns None")

    # Whitespace stripped
    found_ws = find_budget(budgets, "  " + target.budgetId + "  ")
    _true(found_ws is not None, "find_budget strips whitespace")

    # First match returned (unique IDs in practice)
    duped = [budgets[0], budgets[0], budgets[1]]
    found2 = find_budget(duped, budgets[0].budgetId)
    _eq(found2.budgetId, budgets[0].budgetId, "find returns first match")


test_find_budget()


# ===========================================================================
# Section 35 — sort_reports()
# ===========================================================================

def _make_report_set():
    """Return 4 reports spanning all states and overflow scenarios."""
    b1 = build_token_budget(ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile",
                            8192, TS, reserved_output_tokens=512)
    b2 = build_token_budget(ProviderTypeEnum.OPENAI, "gpt-4",
                            8192, TS, reserved_output_tokens=512, used_context_tokens=6800)
    b3 = build_token_budget(ProviderTypeEnum.ANTHROPIC, "claude-3-opus-20240229",
                            8192, TS, reserved_output_tokens=512, used_context_tokens=8000)
    b4 = build_token_budget(ProviderTypeEnum.GOOGLE, "gemini-1.5-pro",
                            8192, TS, reserved_output_tokens=256)
    a1 = build_budget_allocation(b1, TS, context_tokens=1000)
    a2 = build_budget_allocation(b2, TS, context_tokens=6800)
    a3 = build_budget_allocation(b3, TS, context_tokens=9000)   # overflow
    a4 = build_budget_allocation(b4, TS, context_tokens=3000)
    return [
        build_budget_report(b1, a1, TS),
        build_budget_report(b2, a2, TS),
        build_budget_report(b3, a3, TS),
        build_budget_report(b4, a4, TS),
    ]

def test_sort_reports() -> None:
    reports = _make_report_set()

    # Sort by utilizationPercent ASC
    s = sort_reports(reports, key="utilizationPercent", ascending=True)
    _is(s, list, "sort_reports returns list")
    _eq(len(s), 4, "all reports returned")
    for i in range(len(s)-1):
        _le(s[i].utilizationPercent, s[i+1].utilizationPercent,
            f"utilizationPercent ASC [{i}]")

    # Sort by utilizationPercent DESC
    sd = sort_reports(reports, key="utilizationPercent", ascending=False)
    for i in range(len(sd)-1):
        _ge(sd[i].utilizationPercent, sd[i+1].utilizationPercent,
            f"utilizationPercent DESC [{i}]")

    # Sort by overflowDetected ASC (False first)
    so = sort_reports(reports, key="overflowDetected", ascending=True)
    first_overflow_idx = next(
        (i for i, r in enumerate(so) if r.overflowDetected), len(so)
    )
    for i in range(first_overflow_idx):
        _false(so[i].overflowDetected, f"no-overflow before overflow [{i}]")

    # Sort by totalAllocatedTokens ASC
    st = sort_reports(reports, key="totalAllocatedTokens", ascending=True)
    for i in range(len(st)-1):
        _le(st[i].allocation.totalAllocatedTokens,
            st[i+1].allocation.totalAllocatedTokens,
            f"totalAllocatedTokens ASC [{i}]")

    # Sort by remainingTokens ASC
    sr = sort_reports(reports, key="remainingTokens", ascending=True)
    for i in range(len(sr)-1):
        _le(sr[i].budget.remainingTokens, sr[i+1].budget.remainingTokens,
            f"remainingTokens ASC [{i}]")

    # Sort by state
    ss = sort_reports(reports, key="state", ascending=True)
    _is(ss, list, "sort by state returns list")

    # Sort by provider
    sp = sort_reports(reports, key="provider", ascending=True)
    for i in range(len(sp)-1):
        _le(sp[i].budget.provider.value, sp[i+1].budget.provider.value,
            f"provider ASC [{i}]")

    # Sort by model
    sm = sort_reports(reports, key="model", ascending=True)
    for i in range(len(sm)-1):
        _le(sm[i].budget.model, sm[i+1].budget.model, f"model ASC [{i}]")

    # Sort by createdAt
    sc = sort_reports(reports, key="createdAt")
    _is(sc, list, "sort by createdAt returns list")

    # Invalid key raises
    try:
        sort_reports(reports, key="bad_key")
        _true(False, "invalid key should raise")
    except ValueError:
        _true(True, "invalid key raises ValueError")

    # Empty list
    _eq(sort_reports([]), [], "empty list")

    # Deterministic
    s1 = sort_reports(reports, key="utilizationPercent")
    s2 = sort_reports(reports, key="utilizationPercent")
    _eq([r.reportId for r in s1], [r.reportId for r in s2], "sort deterministic")

    # Input not mutated
    orig_first = reports[0].reportId
    _ = sort_reports(reports, key="utilizationPercent")
    _eq(reports[0].reportId, orig_first, "input not mutated")


test_sort_reports()


# ===========================================================================
# Section 36 — filter_reports()
# ===========================================================================

def test_filter_reports() -> None:
    reports = _make_report_set()

    # Filter by provider
    groq_rpts = filter_reports(reports, provider=ProviderTypeEnum.GROQ)
    _eq(len(groq_rpts), 1, "filter GROQ: 1 report")
    _eq(groq_rpts[0].budget.provider, ProviderTypeEnum.GROQ, "GROQ provider correct")

    # Filter by state
    exceeded_rpts = filter_reports(reports, state=BudgetStateEnum.EXCEEDED)
    _ge(len(exceeded_rpts), 1, "at least 1 EXCEEDED report")
    for r in exceeded_rpts:
        _eq(r.budget.state, BudgetStateEnum.EXCEEDED, "state EXCEEDED")

    # Filter overflow_only=True
    overflow_rpts = filter_reports(reports, overflow_only=True)
    for r in overflow_rpts:
        _true(r.overflowDetected, "overflow_only=True: all have overflow")

    # Filter overflow_only=False
    no_overflow_rpts = filter_reports(reports, overflow_only=False)
    for r in no_overflow_rpts:
        _false(r.overflowDetected, "overflow_only=False: none have overflow")

    # Filter by min_utilization
    high_util = filter_reports(reports, min_utilization=50.0)
    for r in high_util:
        _ge(r.utilizationPercent, 50.0, "util >= 50%")

    # Filter by max_utilization
    low_util = filter_reports(reports, max_utilization=50.0)
    for r in low_util:
        _le(r.utilizationPercent, 50.0, "util <= 50%")

    # Filter by model
    model_rpts = filter_reports(reports, model="gpt-4")
    _eq(len(model_rpts), 1, "model filter: 1 match")
    _eq(model_rpts[0].budget.model, "gpt-4", "model filter correct")

    # No criteria → all pass
    all_pass = filter_reports(reports)
    _eq(len(all_pass), 4, "no filter = all pass")

    # No match
    _eq(filter_reports(reports, model="no-model"), [], "no match returns empty")

    # Empty input
    _eq(filter_reports([]), [], "empty input returns empty")


test_filter_reports()

# ===========================================================================
# Section 37 — group_reports()
# ===========================================================================

def test_group_reports() -> None:
    reports = _make_report_set()

    # Group by state
    by_state = group_reports(reports, by="state")
    _is(by_state, dict, "group_reports returns dict")
    total = sum(len(v) for v in by_state.values())
    _eq(total, 4, "all reports accounted for")
    for state_val, grp in by_state.items():
        for r in grp:
            _eq(r.budget.state.value, state_val, f"state group {state_val!r} correct")

    # Group by provider
    by_prov = group_reports(reports, by="provider")
    _is(by_prov, dict, "group by provider returns dict")
    total_p = sum(len(v) for v in by_prov.values())
    _eq(total_p, 4, "all reports in provider groups")

    # Group by model
    by_model = group_reports(reports, by="model")
    _is(by_model, dict, "group by model returns dict")
    total_m = sum(len(v) for v in by_model.values())
    _eq(total_m, 4, "all reports in model groups")

    # Group by overflow
    by_overflow = group_reports(reports, by="overflow")
    _is(by_overflow, dict, "group by overflow returns dict")
    total_o = sum(len(v) for v in by_overflow.values())
    _eq(total_o, 4, "all reports in overflow groups")
    if "True" in by_overflow:
        for r in by_overflow["True"]:
            _true(r.overflowDetected, "overflow=True group has overflow")
    if "False" in by_overflow:
        for r in by_overflow["False"]:
            _false(r.overflowDetected, "overflow=False group has no overflow")

    # Within each group: reportId ASC
    for key, grp in by_state.items():
        ids = [r.reportId for r in grp]
        _eq(ids, sorted(ids), f"state group {key!r} sorted by reportId")

    # Invalid key raises
    try:
        group_reports(reports, by="invalid")
        _true(False, "invalid key should raise")
    except ValueError:
        _true(True, "invalid key raises ValueError")

    # Empty input
    _eq(group_reports([]), {}, "empty input → empty dict")

    # Deterministic
    g1 = group_reports(reports, by="state")
    g2 = group_reports(reports, by="state")
    for k in g1:
        ids1 = [r.reportId for r in g1[k]]
        ids2 = [r.reportId for r in g2[k]]
        _eq(ids1, ids2, f"group_reports state={k!r} deterministic")


test_group_reports()

# ===========================================================================
# Section 38 — find_report()
# ===========================================================================

def test_find_report() -> None:
    reports = _make_report_set()

    # Find existing
    target = reports[1]
    found = find_report(reports, target.reportId)
    _true(found is not None, "find_report: found existing")
    _eq(found.reportId, target.reportId, "found correct report")

    # Not found
    _true(find_report(reports, "nonexistent") is None, "not found returns None")

    # Empty list
    _true(find_report([], target.reportId) is None, "empty list returns None")

    # Whitespace stripped
    found_ws = find_report(reports, "  " + target.reportId + "  ")
    _true(found_ws is not None, "whitespace stripped")

    # Last report findable
    last = reports[-1]
    found_last = find_report(reports, last.reportId)
    _eq(found_last.reportId, last.reportId, "find last report")


test_find_report()


# ===========================================================================
# Section 39 — build_budget_statistics() with new operations
# ===========================================================================

def test_build_budget_statistics_extended() -> None:
    """Verify statistics uses calculate_remaining_tokens consistently."""
    reports = _make_report_set()

    stats = build_budget_statistics(reports)
    _is(stats, BudgetStatistics, "returns BudgetStatistics")

    # State counts match manual grouping
    grp = group_reports(reports, by="state")
    _eq(stats.validBudgets,
        len(grp.get("VALID", [])), "validBudgets matches group_reports count")
    _eq(stats.warningBudgets,
        len(grp.get("WARNING", [])), "warningBudgets matches group_reports count")
    _eq(stats.exceededBudgets,
        len(grp.get("EXCEEDED", [])), "exceededBudgets matches group_reports count")

    # averageRemainingTokens uses calculate_remaining_tokens
    manual_remaining = [
        calculate_remaining_tokens(
            r.budget.availableContextTokens, r.budget.usedContextTokens
        )
        for r in sorted(reports, key=lambda x: x.reportId)
    ]
    manual_avg = round(sum(manual_remaining) / len(manual_remaining), 4)
    _eq(stats.averageRemainingTokens, manual_avg,
        "averageRemainingTokens consistent with calculate_remaining_tokens")

    # averageUtilization matches manual calculation
    ordered = sorted(reports, key=lambda r: r.reportId)
    manual_util_avg = round(
        sum(r.utilizationPercent for r in ordered) / len(ordered), 4
    )
    _eq(stats.averageUtilization, manual_util_avg, "averageUtilization correct")

    # Order-independent
    stats_rev = build_budget_statistics(list(reversed(reports)))
    _eq(stats.averageUtilization,     stats_rev.averageUtilization,     "order-independent util")
    _eq(stats.averageRemainingTokens, stats_rev.averageRemainingTokens, "order-independent remaining")
    _eq(stats.totalBudgets,           stats_rev.totalBudgets,           "order-independent total")

    # Empty still works
    stats_empty = build_budget_statistics([])
    _eq(stats_empty.totalBudgets, 0, "empty: totalBudgets=0")
    _eq(stats_empty.averageUtilization, 0.0, "empty: averageUtilization=0.0")


test_build_budget_statistics_extended()

# ===========================================================================
# Section 40 — Deterministic updates (reserve/release chain)
# ===========================================================================

def test_deterministic_updates() -> None:
    """Reserve then release should produce a deterministic result chain."""
    b0 = build_token_budget(
        ProviderTypeEnum.GROQ, "llama-3.3-70b-versatile", 8192, TS,
        reserved_output_tokens=512,
    )

    # reserve 128 then release 128 → should return to same key
    b1 = reserve_output_tokens(b0, 128, TS)
    b2 = release_reserved_tokens(b1, 128, TS)
    _eq(b2.reservedOutputTokens,   b0.reservedOutputTokens,   "reserve+release = original reserved")
    _eq(b2.availableContextTokens, b0.availableContextTokens, "reserve+release = original available")
    _eq(b2.budgetKey, b0.budgetKey, "reserve+release returns to original key")
    _eq(b2.budgetId,  b0.budgetId,  "reserve+release returns to original id")

    # Repeated reserves are additive and deterministic
    ba = reserve_output_tokens(b0, 100, TS)
    bb = reserve_output_tokens(ba, 100, TS)
    bc_direct = reserve_output_tokens(b0, 200, TS)
    _eq(bb.reservedOutputTokens, bc_direct.reservedOutputTokens,
        "two x 100 reserve = one x 200 reserve")
    _eq(bb.budgetKey, bc_direct.budgetKey, "cumulative reserve = direct reserve key")

    # Release more than reserved → clamped at 0
    b_rel = release_reserved_tokens(b0, 10_000, TS)
    _eq(b_rel.reservedOutputTokens, 0, "over-release clamped to 0")

    # Operations produce stable IDs across timestamps
    b3a = reserve_output_tokens(b0, 64, TS)
    b3b = reserve_output_tokens(b0, 64, TS2)
    _eq(b3a.budgetKey, b3b.budgetKey, "reserve: same delta → same key regardless of TS")

    # Release is likewise TS-independent for key
    b4a = release_reserved_tokens(b0, 64, TS)
    b4b = release_reserved_tokens(b0, 64, TS2)
    _eq(b4a.budgetKey, b4b.budgetKey, "release: same delta → same key regardless of TS")

    # Build report after update — deterministic fingerprint
    alloc = build_budget_allocation(b2, TS, context_tokens=1000)
    rep1 = build_budget_report(b2, alloc, TS)
    rep2 = build_budget_report(b2, alloc, TS)
    _eq(rep1.reportFingerprint, rep2.reportFingerprint, "post-update report fingerprint deterministic")


test_deterministic_updates()

# ===========================================================================
# Section 41 — Statistics with decision functions
# ===========================================================================

def test_statistics_with_decisions() -> None:
    """Verify decisions are consistent with statistics state counts."""
    reports = _make_report_set()
    stats = build_budget_statistics(reports)

    overflow_count = sum(1 for r in reports if detect_overflow(r.budget, r.allocation))
    compress_count = sum(1 for r in reports if should_compress_context(r.budget, r.allocation))
    truncate_count = sum(1 for r in reports if should_truncate_context(r.budget, r.allocation))

    # Exceeded budgets are a subset of those with overflow
    _le(stats.exceededBudgets, overflow_count + 1,
        "exceeded budgets <= overflow_count + slack")

    # Compress count >= truncate count (lower threshold)
    _ge(compress_count, truncate_count, "compress recommendations >= truncate recommendations")

    # All overflow reports should recommend truncation
    overflow_reports = filter_reports(reports, overflow_only=True)
    for r in overflow_reports:
        _true(should_truncate_context(r.budget, r.allocation),
              "overflow report → truncate recommended")

    # All truncate-recommended reports should also be compress-recommended
    for r in reports:
        if should_truncate_context(r.budget, r.allocation):
            _true(should_compress_context(r.budget, r.allocation),
                  "truncate recommended → compress also recommended")

    # Return types
    _is(overflow_count, int, "overflow_count is int")
    _is(compress_count, int, "compress_count is int")
    _is(truncate_count, int, "truncate_count is int")


test_statistics_with_decisions()

# ===========================================================================
# Section 42 — Edge cases for new operations
# ===========================================================================

def test_edge_cases_part_a() -> None:
    # calculate_available_tokens: floats coerced
    _eq(calculate_available_tokens(8192, 512), 7680, "int inputs work")

    # calculate_utilization: boundary at exactly 1.0
    _eq(calculate_utilization(100, 100), 1.0, "exactly 100% = 1.0")

    # reserve with amount larger than remaining headroom
    b = build_token_budget(ProviderTypeEnum.GROQ, "model", 100, TS,
                           reserved_output_tokens=50)  # available=50
    b_big_res = reserve_output_tokens(b, 200, TS)
    # maxTokens=100, clamp to maxAllowedReserved=99
    _eq(b_big_res.reservedOutputTokens, 99, "over-reservation clamped to maxTokens-1")
    _eq(b_big_res.availableContextTokens, 1, "1 token always available")

    # release from zero reserved → still 0
    b_zero_res = build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS,
                                    reserved_output_tokens=0, validate=False)
    b_rel = release_reserved_tokens(b_zero_res, 100, TS)
    _eq(b_rel.reservedOutputTokens, 0, "release from 0 reserved = 0")

    # detect_overflow: empty allocation (0 tokens) never overflows
    b_any = build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS)
    a_empty = build_budget_allocation(b_any, TS)
    _false(detect_overflow(b_any, a_empty), "empty allocation = no overflow")

    # should_compress and should_truncate: single-token budget
    b_one = build_token_budget(ProviderTypeEnum.GROQ, "model", 100, TS,
                               reserved_output_tokens=0)
    a_one = build_budget_allocation(b_one, TS, context_tokens=70)
    _true(should_compress_context(b_one, a_one), "70/100 = 70% → compress")
    _false(should_truncate_context(b_one, a_one), "70/100 = 70% → no truncate")
    a_ninety = build_budget_allocation(b_one, TS, context_tokens=90)
    _true(should_truncate_context(b_one, a_ninety), "90/100 → truncate")

    # sort/filter/group on single-element lists
    single = [build_token_budget(ProviderTypeEnum.GROQ, "model", 8192, TS)]
    _eq(len(sort_budgets(single)),   1, "single-element sort")
    _eq(len(filter_budgets(single)), 1, "single-element filter")
    grp = group_budgets(single, by="state")
    _eq(sum(len(v) for v in grp.values()), 1, "single-element group")

    # find_budget with one element
    _true(find_budget(single, single[0].budgetId) is not None, "find in single list")

    # group_budgets with duplicate states
    b_v1 = build_token_budget(ProviderTypeEnum.GROQ,   "model-a", 8192, TS)
    b_v2 = build_token_budget(ProviderTypeEnum.OPENAI,  "model-b", 8192, TS)
    grp2 = group_budgets([b_v1, b_v2], by="state")
    total = sum(len(v) for v in grp2.values())
    _eq(total, 2, "two VALID budgets grouped correctly")


test_edge_cases_part_a()



print(f"Token Budget Engine Smoke Test")
print(f"{'='*60}")
print(f"PASSED: {_PASS}")
print(f"FAILED: {_FAIL}")
print(f"TOTAL:  {_PASS + _FAIL}")

if _ERRORS:
    print(f"\nFailures:")
    for err in _ERRORS:
        print(f"  {err}")

print(f"{'='*60}")

if _FAIL > 0:
    sys.exit(1)
else:
    print("All assertions passed.")
    sys.exit(0)
