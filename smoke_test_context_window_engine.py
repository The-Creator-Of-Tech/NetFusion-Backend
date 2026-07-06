"""
Smoke Test — Context Window Manager Engine
===========================================
Phase A4.5.1 — Verifies every model, builder, validator, serialisation path,
integration helper, fingerprint, and statistic in
services/context_window_service.py.

Run:
    python smoke_test_context_window_engine.py
Expected: 220+/220 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. Pure model / builder / validator / helper tests.
- Same inputs → same outputs (fully deterministic).
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Dict, List

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
def _is(a, t, msg):
    if isinstance(t, tuple):
        _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
    else:
        _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
def _true(v, msg):   _assert(bool(v), f"{msg}")
def _false(v, msg):  _assert(not bool(v), f"{msg}")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.context_window_service import (
    # Enumerations
    ContextSourceEnum, ContextPriorityEnum,
    # Exceptions
    ContextWindowError, InvalidContextItemError, InvalidContextWindowError,
    # Models
    ContextItem, ContextWindow, ContextStatistics,
    # Builders
    build_context_item, build_context_window, build_context_statistics,
    # Validators
    validate_context_item, validate_context_window,
    # ID helpers (internal, exported for testing)
    _sha256_32, _sha256_64, _uuid5,
    _compute_context_item_key, _compute_window_key, _compute_context_fingerprint,
    # Integration helpers
    conversation_messages_to_context_items,
    memory_entries_to_context_items,
    reasoning_result_to_context_item,
    context_window_to_execution_prompts,
    context_window_to_copilot_context,
    # Token estimator
    _estimate_tokens,
    # Version constant re-export
    CONTEXT_WINDOW_ENGINE_VERSION,
)
from core.constants import CONTEXT_WINDOW_ENGINE_VERSION as CONST_VERSION

TS = "2026-07-01T12:00:00Z"
TS2 = "2026-07-01T13:00:00Z"

# ===========================================================================
# Section 1 — Engine Version
# ===========================================================================

def test_version_constant() -> None:
    _eq(CONTEXT_WINDOW_ENGINE_VERSION, "context-window-v1", "engine version string")
    _eq(CONST_VERSION, "context-window-v1", "constant matches import from core.constants")
    _eq(CONTEXT_WINDOW_ENGINE_VERSION, CONST_VERSION, "both imports are identical")
    _is(CONTEXT_WINDOW_ENGINE_VERSION, str, "version is str")


test_version_constant()

# ===========================================================================
# Section 2 — Enumerations
# ===========================================================================

def test_enumerations() -> None:
    # ContextSourceEnum
    _true(ContextSourceEnum.CONVERSATION.value  == "CONVERSATION",  "CONVERSATION value")
    _true(ContextSourceEnum.MEMORY.value        == "MEMORY",        "MEMORY value")
    _true(ContextSourceEnum.REASONING.value     == "REASONING",     "REASONING value")
    _true(ContextSourceEnum.TIMELINE.value      == "TIMELINE",      "TIMELINE value")
    _true(ContextSourceEnum.ATTACK_GRAPH.value  == "ATTACK_GRAPH",  "ATTACK_GRAPH value")
    _true(ContextSourceEnum.FINDING.value       == "FINDING",       "FINDING value")
    _true(ContextSourceEnum.ALERT.value         == "ALERT",         "ALERT value")
    _true(ContextSourceEnum.EVIDENCE.value      == "EVIDENCE",      "EVIDENCE value")
    _true(ContextSourceEnum.USER_INPUT.value    == "USER_INPUT",    "USER_INPUT value")
    _eq(len(ContextSourceEnum), 9, "ContextSourceEnum has 9 members")

    # ContextPriorityEnum
    _true(ContextPriorityEnum.CRITICAL.value == "CRITICAL", "CRITICAL value")
    _true(ContextPriorityEnum.HIGH.value     == "HIGH",     "HIGH value")
    _true(ContextPriorityEnum.NORMAL.value   == "NORMAL",   "NORMAL value")
    _true(ContextPriorityEnum.LOW.value      == "LOW",      "LOW value")
    _eq(len(ContextPriorityEnum), 4, "ContextPriorityEnum has 4 members")

    # str-enum behaviour
    _eq(ContextSourceEnum.FINDING, "FINDING", "ContextSourceEnum is str-enum")
    _eq(ContextPriorityEnum.HIGH, "HIGH", "ContextPriorityEnum is str-enum")


test_enumerations()

# ===========================================================================
# Section 3 — Deterministic ID helpers
# ===========================================================================

def test_id_helpers() -> None:
    # _sha256_32 returns 32 hex chars
    h = _sha256_32("a", "b", "c")
    _eq(len(h), 32, "sha256_32 length")
    _true(all(c in "0123456789abcdef" for c in h), "sha256_32 hex chars only")

    # Deterministic — same inputs = same output
    _eq(_sha256_32("a", "b"), _sha256_32("a", "b"), "sha256_32 deterministic")

    # Different inputs = different output
    _ne(_sha256_32("a", "b"), _sha256_32("b", "a"), "sha256_32 order matters")
    _ne(_sha256_32("a"), _sha256_32("b"), "sha256_32 different inputs differ")

    # _sha256_64 returns 64 hex chars
    h64 = _sha256_64("hello", "world")
    _eq(len(h64), 64, "sha256_64 length")
    _true(all(c in "0123456789abcdef" for c in h64), "sha256_64 hex chars only")
    _eq(_sha256_64("hello", "world"), _sha256_64("hello", "world"), "sha256_64 deterministic")

    # _uuid5 returns valid UUID string
    uid = _uuid5("test-key-1")
    _eq(len(uid), 36, "uuid5 length")
    _true(uid[8] == "-" and uid[13] == "-" and uid[18] == "-" and uid[23] == "-",
          "uuid5 format dashes")
    _eq(_uuid5("test-key-1"), _uuid5("test-key-1"), "uuid5 deterministic")
    _ne(_uuid5("test-key-1"), _uuid5("test-key-2"), "uuid5 different keys differ")

    # Key derivation — context item key
    k1 = _compute_context_item_key("FINDING", "HIGH", "ref-1", "Title A", "Content body")
    k2 = _compute_context_item_key("FINDING", "HIGH", "ref-1", "Title A", "Content body")
    _eq(k1, k2, "context item key deterministic")
    _eq(len(k1), 32, "context item key is 32 chars")

    k3 = _compute_context_item_key("ALERT", "HIGH", "ref-1", "Title A", "Content body")
    _ne(k1, k3, "different source → different key")

    # Window key
    wk1 = _compute_window_key("inv-1", "conv-1", ("key-a", "key-b"))
    wk2 = _compute_window_key("inv-1", "conv-1", ("key-a", "key-b"))
    _eq(wk1, wk2, "window key deterministic")
    _eq(len(wk1), 32, "window key is 32 chars")

    wk3 = _compute_window_key("inv-1", "conv-2", ("key-a", "key-b"))
    _ne(wk1, wk3, "different conversation → different window key")

    # Context fingerprint
    fp1 = _compute_context_fingerprint("wkey1", ("ik-a", "ik-b"))
    fp2 = _compute_context_fingerprint("wkey1", ("ik-a", "ik-b"))
    _eq(fp1, fp2, "context fingerprint deterministic")
    _eq(len(fp1), 32, "fingerprint is 32 chars")

    fp3 = _compute_context_fingerprint("wkey1", ("ik-a",))
    _ne(fp1, fp3, "different item keys → different fingerprint")


test_id_helpers()

# ===========================================================================
# Section 4 — Token estimator
# ===========================================================================

def test_token_estimator() -> None:
    _eq(_estimate_tokens(""), 0, "empty string → 0 tokens")
    _eq(_estimate_tokens("abcd"), 1, "4-char string → 1 token")
    _eq(_estimate_tokens("a" * 8), 2, "8-char string → 2 tokens")
    _eq(_estimate_tokens("a" * 100), 25, "100-char string → 25 tokens")
    # ceiling division: 5 chars → ceil(5/4) = 2
    _eq(_estimate_tokens("abcde"), 2, "5-char string → 2 tokens (ceiling)")
    _gt(_estimate_tokens("hello world"), 0, "non-empty gives positive token count")


test_token_estimator()

# ===========================================================================
# Section 5 — ContextItem model (frozen / immutable)
# ===========================================================================

def test_context_item_model() -> None:
    item = build_context_item(
        source           = ContextSourceEnum.FINDING,
        priority         = ContextPriorityEnum.HIGH,
        title            = "Critical SQL Injection",
        content          = "SQL injection detected on endpoint /api/login",
        created_at       = TS,
        reference_id     = "finding-001",
        importance_score = 0.9,
        confidence       = 0.85,
        metadata         = {"severity": "HIGH"},
    )

    # Field types
    _is(item, ContextItem, "ContextItem instance")
    _is(item.contextItemId,   str,  "contextItemId is str")
    _is(item.contextItemKey,  str,  "contextItemKey is str")
    _is(item.source,          ContextSourceEnum,   "source is ContextSourceEnum")
    _is(item.priority,        ContextPriorityEnum, "priority is ContextPriorityEnum")
    _is(item.title,           str,  "title is str")
    _is(item.content,         str,  "content is str")
    _is(item.referenceId,     str,  "referenceId is str")
    _is(item.tokenEstimate,   int,  "tokenEstimate is int")
    _is(item.importanceScore, float,"importanceScore is float")
    _is(item.confidence,      float,"confidence is float")
    _is(item.metadata,        dict, "metadata is dict")
    _is(item.createdAt,       str,  "createdAt is str")

    # Values
    _eq(item.source,   ContextSourceEnum.FINDING,   "source value")
    _eq(item.priority, ContextPriorityEnum.HIGH,     "priority value")
    _eq(item.title,    "Critical SQL Injection",     "title value")
    _eq(item.referenceId, "finding-001",             "referenceId value")
    _eq(item.createdAt, TS,                          "createdAt value")
    _gt(item.tokenEstimate, 0,                       "tokenEstimate positive")
    _ge(item.importanceScore, 0.0,                   "importanceScore >= 0")
    _le(item.importanceScore, 1.0,                   "importanceScore <= 1")
    _ge(item.confidence, 0.0,                        "confidence >= 0")
    _le(item.confidence, 1.0,                        "confidence <= 1")
    _eq(len(item.contextItemKey), 32,                "contextItemKey 32 chars")
    _eq(len(item.contextItemId), 36,                 "contextItemId is UUID")

    # Immutability — Pydantic frozen models raise ValidationError or TypeError
    raised = False
    try:
        item.title = "mutated"  # type: ignore
        raised = False
    except Exception:
        raised = True
    if not raised:
        try:
            object.__setattr__(item, "title", "mutated")
            raised = False
        except Exception:
            raised = True
    _true(raised, "ContextItem is immutable (assignment raises)")


test_context_item_model()

# ===========================================================================
# Section 6 — ContextItem deterministic IDs
# ===========================================================================

def test_context_item_determinism() -> None:
    kwargs = dict(
        source           = ContextSourceEnum.ALERT,
        priority         = ContextPriorityEnum.CRITICAL,
        title            = "Port Scan Detected",
        content          = "Multiple ports scanned from 192.168.1.5",
        created_at       = TS,
        reference_id     = "alert-42",
        importance_score = 0.75,
        confidence       = 0.9,
    )

    item1 = build_context_item(**kwargs)
    item2 = build_context_item(**kwargs)

    _eq(item1.contextItemKey, item2.contextItemKey, "contextItemKey deterministic")
    _eq(item1.contextItemId,  item2.contextItemId,  "contextItemId deterministic")
    _eq(item1.tokenEstimate,  item2.tokenEstimate,  "tokenEstimate deterministic")
    _eq(item1.importanceScore,item2.importanceScore,"importanceScore deterministic")
    _eq(item1.confidence,     item2.confidence,     "confidence deterministic")

    # Different source → different key
    item_diff = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.CRITICAL,
        title="Port Scan Detected", content="Multiple ports scanned from 192.168.1.5",
        created_at=TS, reference_id="alert-42",
    )
    _ne(item1.contextItemKey, item_diff.contextItemKey, "different source → different key")
    _ne(item1.contextItemId,  item_diff.contextItemId,  "different source → different id")

    # Different title → different key
    item_t = build_context_item(
        source=ContextSourceEnum.ALERT, priority=ContextPriorityEnum.CRITICAL,
        title="Different Title", content="Multiple ports scanned from 192.168.1.5",
        created_at=TS, reference_id="alert-42",
    )
    _ne(item1.contextItemKey, item_t.contextItemKey, "different title → different key")

    # Different content prefix → different key
    item_c = build_context_item(
        source=ContextSourceEnum.ALERT, priority=ContextPriorityEnum.CRITICAL,
        title="Port Scan Detected", content="Completely different content here XYZ",
        created_at=TS, reference_id="alert-42",
    )
    _ne(item1.contextItemKey, item_c.contextItemKey, "different content → different key")


test_context_item_determinism()

# ===========================================================================
# Section 7 — validate_context_item()
# ===========================================================================

def test_validate_context_item() -> None:
    import traceback as _tb

    # Valid invocation — must not raise
    try:
        validate_context_item(
            source=ContextSourceEnum.EVIDENCE,
            priority=ContextPriorityEnum.NORMAL,
            title="Evidence item",
            content="Packet capture shows ARP request",
            importance_score=0.6,
            confidence=0.8,
            created_at=TS,
        )
        _true(True, "validate_context_item: valid params — no exception")
    except Exception as exc:
        _false(True, f"validate_context_item raised unexpectedly: {exc}")

    # Invalid source type
    try:
        validate_context_item(
            source="FINDING",  # type: ignore
            priority=ContextPriorityEnum.NORMAL,
            title="X", content="Y", importance_score=0.5, confidence=0.5,
            created_at=TS,
        )
        _false(True, "should raise for non-enum source")
    except InvalidContextItemError as exc:
        _in("source", str(exc), "error mentions 'source'")
        _true(True, "InvalidContextItemError raised for bad source")

    # Empty title
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
            title="   ", content="Y", importance_score=0.5, confidence=0.5,
            created_at=TS,
        )
        _false(True, "should raise for empty title")
    except InvalidContextItemError as exc:
        _in("title", str(exc), "error mentions 'title'")

    # None content
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
            title="T", content=None, importance_score=0.5, confidence=0.5,  # type: ignore
            created_at=TS,
        )
        _false(True, "should raise for None content")
    except InvalidContextItemError as exc:
        _in("content", str(exc), "error mentions 'content'")

    # importance_score out of range
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
            title="T", content="C", importance_score=1.5, confidence=0.5,
            created_at=TS,
        )
        _false(True, "should raise for importance_score > 1.0")
    except InvalidContextItemError as exc:
        _in("importanceScore", str(exc), "error mentions 'importanceScore'")

    # confidence out of range (negative)
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
            title="T", content="C", importance_score=0.5, confidence=-0.1,
            created_at=TS,
        )
        _false(True, "should raise for confidence < 0.0")
    except InvalidContextItemError as exc:
        _in("confidence", str(exc), "error mentions 'confidence'")

    # Empty created_at
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
            title="T", content="C", importance_score=0.5, confidence=0.5,
            created_at="",
        )
        _false(True, "should raise for empty created_at")
    except InvalidContextItemError as exc:
        _in("createdAt", str(exc), "error mentions 'createdAt'")

    # Invalid priority
    try:
        validate_context_item(
            source=ContextSourceEnum.FINDING, priority="ULTRA",  # type: ignore
            title="T", content="C", importance_score=0.5, confidence=0.5,
            created_at=TS,
        )
        _false(True, "should raise for non-enum priority")
    except InvalidContextItemError as exc:
        _in("priority", str(exc), "error mentions 'priority'")


test_validate_context_item()

# ===========================================================================
# Section 8 — validate_context_window()
# ===========================================================================

def test_validate_context_window() -> None:
    # Valid call
    try:
        validate_context_window(conversation_id="conv-1", created_at=TS)
        _true(True, "validate_context_window: valid — no exception")
    except Exception as exc:
        _false(True, f"validate_context_window raised: {exc}")

    # Empty conversation_id is OK (optional field)
    try:
        validate_context_window(conversation_id="", created_at=TS)
        _true(True, "empty conversationId is allowed")
    except Exception:
        _false(True, "empty conversationId should be allowed")

    # None conversation_id raises
    try:
        validate_context_window(conversation_id=None, created_at=TS)  # type: ignore
        _false(True, "None conversationId should raise")
    except InvalidContextWindowError as exc:
        _in("conversationId", str(exc), "error mentions conversationId")

    # Empty created_at raises
    try:
        validate_context_window(conversation_id="conv-1", created_at="")
        _false(True, "empty created_at should raise")
    except InvalidContextWindowError as exc:
        _in("createdAt", str(exc), "error mentions createdAt")

    # Whitespace-only created_at raises
    try:
        validate_context_window(conversation_id="conv-1", created_at="   ")
        _false(True, "whitespace created_at should raise")
    except InvalidContextWindowError as exc:
        _in("createdAt", str(exc), "error mentions createdAt for whitespace")


test_validate_context_window()

# ===========================================================================
# Section 9 — build_context_item() — clamping and edge cases
# ===========================================================================

def test_build_context_item_clamping() -> None:
    # importance_score > 1 is clamped to 1.0
    item = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
        title="T", content="C", created_at=TS, importance_score=5.0, confidence=0.5,
        validate=False,
    )
    _le(item.importanceScore, 1.0, "importanceScore clamped to <= 1.0")

    # confidence < 0 is clamped to 0.0
    item2 = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
        title="T2", content="C2", created_at=TS, importance_score=0.5, confidence=-2.0,
        validate=False,
    )
    _ge(item2.confidence, 0.0, "confidence clamped to >= 0.0")

    # Empty content is allowed
    item3 = build_context_item(
        source=ContextSourceEnum.USER_INPUT, priority=ContextPriorityEnum.HIGH,
        title="Empty content", content="", created_at=TS,
    )
    _eq(item3.content, "", "empty content accepted")
    _eq(item3.tokenEstimate, 0, "empty content → 0 tokens")

    # metadata is copied, not shared
    meta = {"x": 1}
    item4 = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.LOW,
        title="Meta test", content="content", created_at=TS, metadata=meta,
    )
    meta["x"] = 999
    _eq(item4.metadata.get("x"), 1, "metadata is a copy, not shared reference")

    # validate=False skips OUR validate_context_item() call but Pydantic
    # still enforces field types at model construction time.
    # verify that passing validate=False with valid types (but no explicit check)
    # does not double-validate — use a valid item with validate=False.
    try:
        item5 = build_context_item(
            source=ContextSourceEnum.EVIDENCE, priority=ContextPriorityEnum.LOW,
            title="No-validate item", content="C", created_at=TS, validate=False,
        )
        _true(True, "validate=False with valid fields: no exception")
        _is(item5, ContextItem, "validate=False: still returns ContextItem")
    except Exception as exc:
        _false(True, f"validate=False should not raise for valid fields: {exc}")


test_build_context_item_clamping()

# ===========================================================================
# Section 10 — ContextWindow model and build_context_window()
# ===========================================================================

def _make_item(source, priority, title, importance, ref="ref-0"):
    return build_context_item(
        source=source, priority=priority,
        title=title, content=f"Content for {title}",
        created_at=TS, reference_id=ref,
        importance_score=importance, confidence=0.9,
    )


def test_context_window_model() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "Finding A", 0.8, "f1"),
        _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "Alert B", 0.95, "a1"),
        _make_item(ContextSourceEnum.MEMORY, ContextPriorityEnum.NORMAL, "Memory C", 0.5, "m1"),
    ]

    window = build_context_window(
        created_at       = TS,
        investigation_id = "inv-001",
        conversation_id  = "conv-001",
        items            = items,
    )

    # Type checks
    _is(window, ContextWindow, "ContextWindow instance")
    _is(window.windowId,           str,   "windowId is str")
    _is(window.windowKey,          str,   "windowKey is str")
    _is(window.investigationId,    str,   "investigationId is str")
    _is(window.conversationId,     str,   "conversationId is str")
    _is(window.items,              tuple, "items is tuple")
    _is(window.totalTokenEstimate, int,   "totalTokenEstimate is int")
    _is(window.contextFingerprint, str,   "contextFingerprint is str")
    _is(window.createdAt,          str,   "createdAt is str")

    # Value checks
    _eq(window.investigationId, "inv-001", "investigationId stored")
    _eq(window.conversationId,  "conv-001", "conversationId stored")
    _eq(len(window.items), 3,  "3 items in window")
    _eq(len(window.windowId), 36, "windowId is UUID")
    _eq(len(window.windowKey), 32, "windowKey 32 chars")
    _eq(len(window.contextFingerprint), 32, "contextFingerprint 32 chars")
    _gt(window.totalTokenEstimate, 0, "totalTokenEstimate positive")

    # Total token estimate equals sum of item estimates
    expected_total = sum(i.tokenEstimate for i in window.items)
    _eq(window.totalTokenEstimate, expected_total, "totalTokenEstimate is sum of item estimates")

    # Immutability — Pydantic frozen models raise on assignment
    raised = False
    try:
        window.windowId = "hacked"  # type: ignore
        raised = False
    except Exception:
        raised = True
    if not raised:
        try:
            object.__setattr__(window, "windowId", "hacked")
            raised = False
        except Exception:
            raised = True
    _true(raised, "ContextWindow is immutable (assignment raises)")


test_context_window_model()

# ===========================================================================
# Section 11 — Item sort order in ContextWindow
# ===========================================================================

def test_context_window_sort_order() -> None:
    # Build items intentionally out of intended sort order
    low_item     = _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.LOW,      "Low item",     0.3, "e1")
    normal_item  = _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.NORMAL,   "Normal item",  0.5, "m1")
    high_item    = _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "High item",    0.7, "f1")
    critical_item= _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "Critical item",0.9, "a1")

    window = build_context_window(
        created_at = TS,
        items      = [low_item, normal_item, high_item, critical_item],
    )

    # First item must be CRITICAL
    _eq(window.items[0].priority, ContextPriorityEnum.CRITICAL, "first item is CRITICAL")
    # Second item must be HIGH
    _eq(window.items[1].priority, ContextPriorityEnum.HIGH,     "second item is HIGH")
    # Third item must be NORMAL
    _eq(window.items[2].priority, ContextPriorityEnum.NORMAL,   "third item is NORMAL")
    # Fourth item must be LOW
    _eq(window.items[3].priority, ContextPriorityEnum.LOW,      "fourth item is LOW")

    # Within same priority, higher importanceScore comes first
    hi_a = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "High A", 0.9, "ha")
    hi_b = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "High B", 0.6, "hb")
    window2 = build_context_window(created_at=TS, items=[hi_b, hi_a])
    _eq(window2.items[0].importanceScore, 0.9, "higher importance first within same priority")
    _eq(window2.items[1].importanceScore, 0.6, "lower importance second")


test_context_window_sort_order()

# ===========================================================================
# Section 12 — ContextWindow deterministic IDs and fingerprint
# ===========================================================================

def test_context_window_determinism() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1"),
        _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1"),
    ]

    w1 = build_context_window(
        created_at="2026-07-01T00:00:00Z", investigation_id="inv-X", conversation_id="conv-Y",
        items=items,
    )
    w2 = build_context_window(
        created_at="2026-07-01T00:00:00Z", investigation_id="inv-X", conversation_id="conv-Y",
        items=items,
    )

    _eq(w1.windowKey,          w2.windowKey,          "windowKey deterministic")
    _eq(w1.windowId,           w2.windowId,           "windowId deterministic")
    _eq(w1.contextFingerprint, w2.contextFingerprint, "contextFingerprint deterministic")
    _eq(w1.totalTokenEstimate, w2.totalTokenEstimate, "totalTokenEstimate deterministic")

    # Different items → different fingerprint
    other_items = [
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL, "E1", 0.5, "ev1"),
    ]
    w3 = build_context_window(
        created_at="2026-07-01T00:00:00Z", investigation_id="inv-X", conversation_id="conv-Y",
        items=other_items,
    )
    _ne(w1.contextFingerprint, w3.contextFingerprint, "different items → different fingerprint")
    _ne(w1.windowKey,          w3.windowKey,          "different items → different window key")

    # Empty window
    w_empty = build_context_window(created_at=TS)
    _eq(len(w_empty.items), 0,             "empty window has 0 items")
    _eq(w_empty.totalTokenEstimate, 0,     "empty window has 0 tokens")
    _eq(len(w_empty.windowKey), 32,        "empty window has valid windowKey")
    _eq(len(w_empty.contextFingerprint), 32, "empty window has valid fingerprint")


test_context_window_determinism()

# ===========================================================================
# Section 13 — build_context_statistics()
# ===========================================================================

def test_build_context_statistics() -> None:
    # Empty list
    stats0 = build_context_statistics([])
    _is(stats0, ContextStatistics, "ContextStatistics instance on empty")
    _eq(stats0.totalWindows,      0,   "empty: totalWindows=0")
    _eq(stats0.totalItems,        0,   "empty: totalItems=0")
    _eq(stats0.averageTokens,     0.0, "empty: averageTokens=0.0")
    _eq(stats0.averageImportance, 0.0, "empty: averageImportance=0.0")
    _eq(stats0.averageConfidence, 0.0, "empty: averageConfidence=0.0")
    _is(stats0.itemsBySource,   dict, "itemsBySource is dict")
    _is(stats0.itemsByPriority, dict, "itemsByPriority is dict")
    # All source keys present at 0
    for src in ContextSourceEnum:
        _eq(stats0.itemsBySource.get(src.value, -1), 0, f"empty: {src.value}=0 in itemsBySource")
    for pri in ContextPriorityEnum:
        _eq(stats0.itemsByPriority.get(pri.value, -1), 0, f"empty: {pri.value}=0 in itemsByPriority")

    # Single window with mixed items
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.CRITICAL, "F1", 0.9, "f1"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.HIGH,     "A1", 0.8, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "E1", 0.5, "e1"),
        _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "M1", 0.3, "m1"),
    ]
    w = build_context_window(created_at=TS, items=items)
    stats1 = build_context_statistics([w])

    _eq(stats1.totalWindows, 1, "single window: totalWindows=1")
    _eq(stats1.totalItems,   4, "single window: totalItems=4")
    _gt(stats1.averageTokens, 0.0, "averageTokens positive")
    _gt(stats1.averageImportance, 0.0, "averageImportance positive")
    _gt(stats1.averageConfidence, 0.0, "averageConfidence positive")
    _le(stats1.averageImportance, 1.0, "averageImportance <= 1.0")
    _le(stats1.averageConfidence, 1.0, "averageConfidence <= 1.0")

    # itemsBySource counts
    _eq(stats1.itemsBySource["FINDING"],  1, "1 FINDING item")
    _eq(stats1.itemsBySource["ALERT"],    1, "1 ALERT item")
    _eq(stats1.itemsBySource["EVIDENCE"], 1, "1 EVIDENCE item")
    _eq(stats1.itemsBySource["MEMORY"],   1, "1 MEMORY item")
    _eq(stats1.itemsBySource["CONVERSATION"], 0, "0 CONVERSATION items")

    # itemsByPriority counts
    _eq(stats1.itemsByPriority["CRITICAL"], 1, "1 CRITICAL item")
    _eq(stats1.itemsByPriority["HIGH"],     1, "1 HIGH item")
    _eq(stats1.itemsByPriority["NORMAL"],   1, "1 NORMAL item")
    _eq(stats1.itemsByPriority["LOW"],      1, "1 LOW item")

    # Two windows
    items2 = [
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F2", 0.7, "f2"),
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F3", 0.6, "f3"),
    ]
    w2 = build_context_window(created_at=TS2, items=items2)
    stats2 = build_context_statistics([w, w2])

    _eq(stats2.totalWindows, 2, "two windows: totalWindows=2")
    _eq(stats2.totalItems,   6, "two windows: totalItems=6")
    _eq(stats2.itemsBySource["FINDING"], 3, "3 FINDING items across 2 windows")

    # Immutability — Pydantic frozen models raise on assignment
    raised = False
    try:
        stats1.totalWindows = 99  # type: ignore
        raised = False
    except Exception:
        raised = True
    if not raised:
        try:
            object.__setattr__(stats1, "totalWindows", 99)
            raised = False
        except Exception:
            raised = True
    _true(raised, "ContextStatistics is immutable (assignment raises)")

    # Deterministic — same input twice
    stats1a = build_context_statistics([w])
    stats1b = build_context_statistics([w])
    _eq(stats1a.averageImportance, stats1b.averageImportance, "statistics deterministic")
    _eq(stats1a.totalItems, stats1b.totalItems, "totalItems deterministic")


test_build_context_statistics()

# ===========================================================================
# Section 14 — Serialisation (model_dump / dict)
# ===========================================================================

def test_serialisation() -> None:
    item = _make_item(ContextSourceEnum.TIMELINE, ContextPriorityEnum.NORMAL, "Timeline event", 0.6, "tl1")
    d = item.model_dump()

    _is(d, dict, "model_dump returns dict")
    _in("contextItemId",   d, "contextItemId in dump")
    _in("contextItemKey",  d, "contextItemKey in dump")
    _in("source",          d, "source in dump")
    _in("priority",        d, "priority in dump")
    _in("title",           d, "title in dump")
    _in("content",         d, "content in dump")
    _in("referenceId",     d, "referenceId in dump")
    _in("tokenEstimate",   d, "tokenEstimate in dump")
    _in("importanceScore", d, "importanceScore in dump")
    _in("confidence",      d, "confidence in dump")
    _in("metadata",        d, "metadata in dump")
    _in("createdAt",       d, "createdAt in dump")

    # Window serialisation
    window = build_context_window(
        created_at="2026-07-01T00:00:00Z",
        investigation_id="inv-ser",
        conversation_id="conv-ser",
        items=[item],
    )
    wd = window.model_dump()
    _is(wd, dict, "window model_dump returns dict")
    _in("windowId",           wd, "windowId in window dump")
    _in("windowKey",          wd, "windowKey in window dump")
    _in("investigationId",    wd, "investigationId in window dump")
    _in("conversationId",     wd, "conversationId in window dump")
    _in("items",              wd, "items in window dump")
    _in("totalTokenEstimate", wd, "totalTokenEstimate in window dump")
    _in("contextFingerprint", wd, "contextFingerprint in window dump")
    _in("createdAt",          wd, "createdAt in window dump")
    _is(wd["items"], (list, tuple), "items serialised as list or tuple")
    _eq(len(wd["items"]), 1, "1 item in serialised window")

    # JSON round-trip
    import json
    json_str = window.model_dump_json()
    _is(json_str, str, "model_dump_json returns str")
    parsed = json.loads(json_str)
    _eq(parsed["windowId"], window.windowId, "windowId survives JSON round-trip")
    _eq(parsed["contextFingerprint"], window.contextFingerprint,
        "contextFingerprint survives JSON round-trip")


test_serialisation()

# ===========================================================================
# Section 15 — Integration helper: conversation_messages_to_context_items()
# ===========================================================================

def test_conversation_messages_to_context_items() -> None:
    """Use lightweight stubs — no real conversation_manager_service import needed."""
    from types import SimpleNamespace

    # Stub messages in reverse sequence order to confirm sorting
    def _msg(mid, role, content, seq, cid="conv-test"):
        class _Role:
            value = role
        m = SimpleNamespace(
            messageId=mid, role=_Role(), content=content,
            sequenceNumber=seq, conversationId=cid,
        )
        return m

    msgs = [
        _msg("m3", "ASSISTANT", "Acknowledged threat.", 3),
        _msg("m1", "SYSTEM",    "You are NetFusion AI.",1),
        _msg("m2", "USER",      "Analyse this alert.", 2),
    ]

    items = conversation_messages_to_context_items(msgs, created_at=TS)

    _is(items, list,          "returns list")
    _eq(len(items), 3,        "3 messages → 3 items")

    # Items are sorted by sequenceNumber
    _eq(items[0].referenceId, "m1", "first item is message m1 (seq=1)")
    _eq(items[1].referenceId, "m2", "second item is message m2 (seq=2)")
    _eq(items[2].referenceId, "m3", "third item is message m3 (seq=3)")

    # All items have CONVERSATION source
    for it in items:
        _eq(it.source, ContextSourceEnum.CONVERSATION, "all items have CONVERSATION source")

    # SYSTEM message has highest importance (1.0)
    system_item = next(i for i in items if i.referenceId == "m1")
    _eq(system_item.importanceScore, 1.0, "SYSTEM message has importance=1.0")

    # USER message has importance 0.8
    user_item = next(i for i in items if i.referenceId == "m2")
    _eq(user_item.importanceScore, 0.8, "USER message has importance=0.8")

    # ASSISTANT message has importance 0.7
    asst_item = next(i for i in items if i.referenceId == "m3")
    _eq(asst_item.importanceScore, 0.7, "ASSISTANT message has importance=0.7")

    # Metadata includes conversationId and sequenceNumber
    _in("conversationId",  system_item.metadata, "metadata has conversationId")
    _in("sequenceNumber",  system_item.metadata, "metadata has sequenceNumber")

    # Deterministic — same inputs, same output
    items2 = conversation_messages_to_context_items(msgs, created_at=TS)
    for a, b in zip(items, items2):
        _eq(a.contextItemId, b.contextItemId, f"item {a.referenceId} deterministic id")

    # Custom priority is forwarded
    items3 = conversation_messages_to_context_items(
        msgs, created_at=TS, priority=ContextPriorityEnum.CRITICAL
    )
    for it in items3:
        _eq(it.priority, ContextPriorityEnum.CRITICAL, "custom priority forwarded")

    # Empty list → empty result
    _eq(conversation_messages_to_context_items([], created_at=TS), [], "empty list → []")


test_conversation_messages_to_context_items()

# ===========================================================================
# Section 16 — Integration helper: memory_entries_to_context_items()
# ===========================================================================

def test_memory_entries_to_context_items() -> None:
    from types import SimpleNamespace

    def _mem(mid, mtype, title, content, importance, confidence):
        class _MType:
            value = mtype
        m = SimpleNamespace(
            memoryId=mid, memoryType=_MType(),
            title=title, content=content,
            importanceScore=importance, confidence=confidence,
            conversationId="conv-mem-test",
        )
        return m

    mems = [
        _mem("mem-c", "SHORT_TERM",    "Low memory",    "Less important fact.",      0.3, 0.7),
        _mem("mem-a", "INVESTIGATION", "Critical fact", "Very important context.",   0.9, 0.95),
        _mem("mem-b", "LONG_TERM",     "Medium memory", "Moderately important info.",0.6, 0.8),
    ]

    items = memory_entries_to_context_items(mems, created_at=TS)

    _is(items, list,    "returns list")
    _eq(len(items), 3,  "3 entries → 3 items")

    # Sorted by importance DESC, then memoryId ASC
    _eq(items[0].referenceId, "mem-a", "first is highest importance (mem-a 0.9)")
    _eq(items[1].referenceId, "mem-b", "second is (mem-b 0.6)")
    _eq(items[2].referenceId, "mem-c", "third is lowest importance (mem-c 0.3)")

    # All items have MEMORY source
    for it in items:
        _eq(it.source, ContextSourceEnum.MEMORY, "all items have MEMORY source")

    # importanceScore and confidence are preserved
    _eq(items[0].importanceScore, 0.9, "importanceScore preserved for mem-a")
    _eq(round(items[0].confidence, 6), round(0.95, 6), "confidence preserved for mem-a")

    # Metadata has memoryType and conversationId
    _in("memoryType",     items[0].metadata, "metadata has memoryType")
    _in("conversationId", items[0].metadata, "metadata has conversationId")

    # Deterministic
    items2 = memory_entries_to_context_items(mems, created_at=TS)
    for a, b in zip(items, items2):
        _eq(a.contextItemId, b.contextItemId, f"memory item {a.referenceId} deterministic")

    # Empty list → empty result
    _eq(memory_entries_to_context_items([], created_at=TS), [], "empty list → []")


test_memory_entries_to_context_items()

# ===========================================================================
# Section 17 — Integration helper: reasoning_result_to_context_item()
# ===========================================================================

def test_reasoning_result_to_context_item() -> None:
    from types import SimpleNamespace

    class _Explanation:
        summary = "Evidence strongly suggests lateral movement pattern."

    reasoning = SimpleNamespace(
        reasoningId          = "reason-001",
        reasoningKey         = "rk-deadbeef" * 3,
        overallConfidence    = 82.5,
        overallRisk          = 65.0,
        decision             = "High-confidence lateral movement detected.",
        decisionExplanation  = _Explanation(),
        engineVersion        = "reasoning-engine-v1",
    )

    item = reasoning_result_to_context_item(reasoning, created_at=TS)

    _is(item, ContextItem, "returns ContextItem")
    _eq(item.source,   ContextSourceEnum.REASONING,    "source is REASONING")
    _eq(item.priority, ContextPriorityEnum.HIGH,       "default priority is HIGH")
    _eq(item.referenceId, "reason-001",                "referenceId is reasoningId")

    # Confidence and importance are normalised from overallConfidence / 100
    expected_conf = round(82.5 / 100.0, 6)
    _eq(item.confidence,      expected_conf, "confidence = overallConfidence/100")
    _eq(item.importanceScore, expected_conf, "importanceScore = overallConfidence/100")

    # Content includes decision and explanation
    _in("lateral movement detected", item.content, "content has decision text")
    _in("lateral movement pattern",  item.content, "content has explanation summary")

    # Metadata
    _in("overallRisk",   item.metadata, "metadata has overallRisk")
    _in("reasoningKey",  item.metadata, "metadata has reasoningKey")
    _in("engineVersion", item.metadata, "metadata has engineVersion")

    # Deterministic
    item2 = reasoning_result_to_context_item(reasoning, created_at=TS)
    _eq(item.contextItemId, item2.contextItemId, "reasoning item deterministic")

    # Custom priority
    item3 = reasoning_result_to_context_item(
        reasoning, created_at=TS, priority=ContextPriorityEnum.CRITICAL
    )
    _eq(item3.priority, ContextPriorityEnum.CRITICAL, "custom priority forwarded")

    # Confidence=0 edge case
    reasoning_zero = SimpleNamespace(
        reasoningId="r-zero", reasoningKey="rk0", overallConfidence=0.0,
        overallRisk=0.0, decision="Unknown.", decisionExplanation=None,
        engineVersion="reasoning-engine-v1",
    )
    item_zero = reasoning_result_to_context_item(reasoning_zero, created_at=TS)
    _eq(item_zero.confidence, 0.0, "zero confidence handled")

    # Confidence=100 edge case
    reasoning_full = SimpleNamespace(
        reasoningId="r-full", reasoningKey="rkfull", overallConfidence=100.0,
        overallRisk=10.0, decision="Confirmed.", decisionExplanation=None,
        engineVersion="reasoning-engine-v1",
    )
    item_full = reasoning_result_to_context_item(reasoning_full, created_at=TS)
    _le(item_full.confidence, 1.0, "full confidence clamped to <= 1.0")


test_reasoning_result_to_context_item()

# ===========================================================================
# Section 18 — Integration helper: context_window_to_execution_prompts()
# ===========================================================================

def test_context_window_to_execution_prompts() -> None:
    conv_item = build_context_item(
        source=ContextSourceEnum.CONVERSATION, priority=ContextPriorityEnum.NORMAL,
        title="User message #1", content="What is the threat?", created_at=TS,
        reference_id="m-conv",
    )
    user_input_item = build_context_item(
        source=ContextSourceEnum.USER_INPUT, priority=ContextPriorityEnum.HIGH,
        title="User question", content="Analyse the finding.", created_at=TS,
        reference_id="m-user",
    )
    finding_item = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.CRITICAL,
        title="SQL Injection Found", content="Injection at /api/auth", created_at=TS,
        reference_id="f1",
    )
    reasoning_item = build_context_item(
        source=ContextSourceEnum.REASONING, priority=ContextPriorityEnum.HIGH,
        title="Reasoning decision", content="High-risk behaviour confirmed.", created_at=TS,
        reference_id="r1",
    )

    window = build_context_window(
        created_at=TS,
        items=[conv_item, user_input_item, finding_item, reasoning_item],
    )

    sys_prompt, usr_prompt = context_window_to_execution_prompts(window)

    _is(sys_prompt, str, "system_prompt is str")
    _is(usr_prompt, str, "user_prompt is str")

    # CONVERSATION and USER_INPUT go to user_prompt
    _in("What is the threat?",       usr_prompt, "conv content in user_prompt")
    _in("Analyse the finding.",      usr_prompt, "user_input content in user_prompt")

    # FINDING and REASONING go to system_prompt
    _in("SQL Injection Found",       sys_prompt, "finding title in system_prompt")
    _in("Injection at /api/auth",    sys_prompt, "finding content in system_prompt")
    _in("High-risk behaviour",       sys_prompt, "reasoning content in system_prompt")

    # Conversation items should NOT appear in system_prompt
    _ni("What is the threat?",   sys_prompt, "conv content not in system_prompt")

    # Empty window returns ("", "")
    empty_window = build_context_window(created_at=TS)
    sp, up = context_window_to_execution_prompts(empty_window)
    _eq(sp, "", "empty window: system_prompt is empty")
    _eq(up, "", "empty window: user_prompt is empty")

    # Deterministic
    sp2, up2 = context_window_to_execution_prompts(window)
    _eq(sys_prompt, sp2, "system_prompt deterministic")
    _eq(usr_prompt, up2, "user_prompt deterministic")


test_context_window_to_execution_prompts()

# ===========================================================================
# Section 19 — Integration helper: context_window_to_copilot_context()
# ===========================================================================

def test_context_window_to_copilot_context() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.CRITICAL, "F1", 0.9, "f1"),
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "F2", 0.7, "f2"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.HIGH,     "A1", 0.8, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "E1", 0.5, "e1"),
    ]
    window = build_context_window(
        created_at="2026-07-01T10:00:00Z",
        investigation_id="inv-copilot",
        conversation_id="conv-copilot",
        items=items,
    )

    ctx = context_window_to_copilot_context(window)

    _is(ctx, dict, "returns dict")
    _in("windowId",           ctx, "windowId in ctx")
    _in("windowKey",          ctx, "windowKey in ctx")
    _in("investigationId",    ctx, "investigationId in ctx")
    _in("conversationId",     ctx, "conversationId in ctx")
    _in("totalItems",         ctx, "totalItems in ctx")
    _in("totalTokenEstimate", ctx, "totalTokenEstimate in ctx")
    _in("contextFingerprint", ctx, "contextFingerprint in ctx")
    _in("itemsBySource",      ctx, "itemsBySource in ctx")
    _in("engineVersion",      ctx, "engineVersion in ctx")

    _eq(ctx["windowId"],        window.windowId,        "windowId matches")
    _eq(ctx["investigationId"], "inv-copilot",           "investigationId matches")
    _eq(ctx["conversationId"],  "conv-copilot",          "conversationId matches")
    _eq(ctx["totalItems"],      4,                       "totalItems=4")
    _eq(ctx["engineVersion"],   CONTEXT_WINDOW_ENGINE_VERSION, "engineVersion matches")

    # itemsBySource counts
    src_counts = ctx["itemsBySource"]
    _eq(src_counts["FINDING"],  2, "2 FINDING items")
    _eq(src_counts["ALERT"],    1, "1 ALERT item")
    _eq(src_counts["EVIDENCE"], 1, "1 EVIDENCE item")
    _eq(src_counts["MEMORY"],   0, "0 MEMORY items")

    # JSON-serialisable (no Pydantic objects)
    import json
    json_str = json.dumps(ctx)
    _is(json_str, str, "copilot ctx is JSON-serialisable")

    # Deterministic
    ctx2 = context_window_to_copilot_context(window)
    _eq(ctx["contextFingerprint"], ctx2["contextFingerprint"], "copilot ctx deterministic")


test_context_window_to_copilot_context()

# ===========================================================================
# Section 20 — All sources and priorities round-trip through build_context_item
# ===========================================================================

def test_all_sources_and_priorities() -> None:
    for source in ContextSourceEnum:
        for priority in ContextPriorityEnum:
            item = build_context_item(
                source=source, priority=priority,
                title=f"{source.value} {priority.value} item",
                content=f"Content for {source.value} at {priority.value} priority.",
                created_at=TS,
                reference_id=f"ref-{source.value}-{priority.value}",
            )
            _is(item, ContextItem,
                f"{source.value}/{priority.value}: is ContextItem")
            _eq(item.source,   source,   f"{source.value}: source preserved")
            _eq(item.priority, priority, f"{priority.value}: priority preserved")
            _eq(len(item.contextItemKey), 32,
                f"{source.value}/{priority.value}: key 32 chars")
            _eq(len(item.contextItemId), 36,
                f"{source.value}/{priority.value}: id is UUID")


test_all_sources_and_priorities()

# ===========================================================================
# Section 21 — Fingerprint stability (insert order independence)
# ===========================================================================

def test_fingerprint_insert_order_independence() -> None:
    """Fingerprint must be identical regardless of insertion order of items."""
    i1 = _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "F", 0.8, "f")
    i2 = _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "A", 0.9, "a")
    i3 = _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "E", 0.5, "e")

    w_abc = build_context_window(created_at=TS, investigation_id="X", conversation_id="Y",
                                  items=[i1, i2, i3])
    w_cba = build_context_window(created_at=TS, investigation_id="X", conversation_id="Y",
                                  items=[i3, i2, i1])
    w_bac = build_context_window(created_at=TS, investigation_id="X", conversation_id="Y",
                                  items=[i2, i1, i3])

    _eq(w_abc.contextFingerprint, w_cba.contextFingerprint,
        "fingerprint stable: abc vs cba")
    _eq(w_abc.contextFingerprint, w_bac.contextFingerprint,
        "fingerprint stable: abc vs bac")
    _eq(w_abc.windowKey, w_cba.windowKey,
        "windowKey stable: abc vs cba")
    _eq(w_abc.windowKey, w_bac.windowKey,
        "windowKey stable: abc vs bac")


test_fingerprint_insert_order_independence()

# ===========================================================================
# Section 22 — Exception hierarchy
# ===========================================================================

def test_exception_hierarchy() -> None:
    _true(issubclass(InvalidContextItemError,  ContextWindowError), "InvalidContextItemError < ContextWindowError")
    _true(issubclass(InvalidContextWindowError, ContextWindowError), "InvalidContextWindowError < ContextWindowError")
    _true(issubclass(ContextWindowError,        Exception),          "ContextWindowError < Exception")

    # Raise and catch as base class
    try:
        raise InvalidContextItemError("test item error")
    except ContextWindowError as e:
        _in("test item error", str(e), "InvalidContextItemError caught as ContextWindowError")

    try:
        raise InvalidContextWindowError("test window error")
    except ContextWindowError as e:
        _in("test window error", str(e), "InvalidContextWindowError caught as ContextWindowError")


test_exception_hierarchy()

# ===========================================================================
# Section 23 — Zero randomness verification (cross-process determinism)
# ===========================================================================

def test_zero_randomness() -> None:
    """
    Verify that IDs are stable hex/UUID strings with no runtime randomness.
    Same inputs called twice in the same process must always produce equal IDs.
    """
    params = dict(
        source=ContextSourceEnum.ATTACK_GRAPH, priority=ContextPriorityEnum.HIGH,
        title="Attack path discovered", content="Lateral movement via SMB.",
        created_at="2026-07-01T09:00:00Z", reference_id="ag-1",
        importance_score=0.85, confidence=0.9,
    )

    results = [build_context_item(**params) for _ in range(5)]
    ref_id  = results[0].contextItemId
    ref_key = results[0].contextItemKey

    for i, item in enumerate(results[1:], 1):
        _eq(item.contextItemId,  ref_id,  f"run {i}: contextItemId identical")
        _eq(item.contextItemKey, ref_key, f"run {i}: contextItemKey identical")

    # Window zero-randomness
    items = [build_context_item(**params)]
    wins  = [
        build_context_window(
            created_at="2026-07-01T09:00:00Z",
            investigation_id="inv-det",
            conversation_id="conv-det",
            items=items,
        )
        for _ in range(5)
    ]
    ref_wid = wins[0].windowId
    ref_fp  = wins[0].contextFingerprint
    for j, w in enumerate(wins[1:], 1):
        _eq(w.windowId,           ref_wid, f"window run {j}: windowId identical")
        _eq(w.contextFingerprint, ref_fp,  f"window run {j}: fingerprint identical")


test_zero_randomness()

# ===========================================================================
# Section 24 — Large window (stress test for sort stability and token count)
# ===========================================================================

def test_large_window() -> None:
    sources    = list(ContextSourceEnum)
    priorities = list(ContextPriorityEnum)

    items = []
    for i in range(36):
        src = sources[i % len(sources)]
        pri = priorities[i % len(priorities)]
        items.append(build_context_item(
            source=src, priority=pri,
            title=f"Item {i:02d}",
            content=f"This is context content for item number {i}. " * 3,
            created_at=TS,
            reference_id=f"ref-{i:03d}",
            importance_score=round((i % 10) / 10.0, 2),
            confidence=round(0.5 + (i % 5) * 0.1, 2),
        ))

    window = build_context_window(
        created_at=TS,
        investigation_id="inv-large",
        conversation_id="conv-large",
        items=items,
    )

    _eq(len(window.items), 36,       "large window: 36 items")
    _gt(window.totalTokenEstimate, 0,"large window: positive total tokens")
    _eq(len(window.windowId), 36,    "large window: valid windowId")
    _eq(len(window.contextFingerprint), 32, "large window: valid fingerprint")

    # Verify sort invariant holds across all items
    prev_priority_order = -1
    for item in window.items:
        from services.context_window_service import _PRIORITY_ORDER
        curr_order = _PRIORITY_ORDER[item.priority]
        _ge(curr_order, prev_priority_order,
            f"sort stable: {item.priority.value} order {curr_order} >= {prev_priority_order}")
        prev_priority_order = curr_order

    # Statistics on large window
    stats = build_context_statistics([window])
    _eq(stats.totalWindows, 1,  "large: 1 window")
    _eq(stats.totalItems,  36,  "large: 36 items in stats")
    _gt(stats.averageTokens, 0, "large: averageTokens positive")


test_large_window()

# ===========================================================================
# Section 25 — build_context_window() with validate=False
# ===========================================================================

def test_build_context_window_validate_false() -> None:
    # validate=False skips OUR validate_context_window() call.
    # conversationId="" is valid (empty is permitted), so no exception expected.
    try:
        w = build_context_window(created_at=TS, conversation_id="", validate=False)
        _true(True, "validate=False: no exception for empty conversation_id")
        _is(w, ContextWindow, "validate=False: returns ContextWindow")
    except Exception as exc:
        _false(True, f"validate=False should not raise for valid params: {exc}")


test_build_context_window_validate_false()

# ===========================================================================
# Section 26 — Distinct namespace from other services
# ===========================================================================

def test_uuid_namespace_isolation() -> None:
    """UUIDs generated by context_window_service must not collide with
    those generated by other services that use different namespaces."""
    key = "shared-test-key-12345"
    ctx_uuid = _uuid5(key)

    # Reproduce what session_memory_service would generate for the same key
    import uuid as _uuid
    _MEM_NS   = _uuid.UUID("6ba7b832-9dad-11d1-80b4-00c04fd430c8")
    _CONV_NS  = _uuid.UUID("6ba7b831-9dad-11d1-80b4-00c04fd430c8")

    mem_uuid  = str(_uuid.uuid5(_MEM_NS,  key))
    conv_uuid = str(_uuid.uuid5(_CONV_NS, key))

    _ne(ctx_uuid, mem_uuid,  "ctx namespace differs from memory namespace")
    _ne(ctx_uuid, conv_uuid, "ctx namespace differs from conversation namespace")
    _ne(mem_uuid, conv_uuid, "memory and conversation namespaces differ")


test_uuid_namespace_isolation()

# ===========================================================================
# Section 27 — ContextStatistics immutability
# ===========================================================================

def test_context_statistics_immutability() -> None:
    stats = build_context_statistics([])
    raised = False
    try:
        stats.totalWindows = 99  # type: ignore
        raised = False
    except Exception:
        raised = True
    if not raised:
        try:
            object.__setattr__(stats, "totalWindows", 99)
            raised = False
        except Exception:
            raised = True
    _true(raised, "ContextStatistics is immutable (assignment raises)")

    # itemsBySource dict is a plain dict (mutable snapshot), not frozen
    # but the ContextStatistics object itself cannot be replaced
    _is(stats.itemsBySource,   dict, "itemsBySource is a dict")
    _is(stats.itemsByPriority, dict, "itemsByPriority is a dict")


test_context_statistics_immutability()

# ===========================================================================
# Section 28 — CONTEXT_WINDOW_ENGINE_VERSION exported from constants
# ===========================================================================

def test_constant_exported_from_constants_module() -> None:
    from core.constants import CONTEXT_WINDOW_ENGINE_VERSION as CV
    _eq(CV, "context-window-v1", "constant value in core.constants")
    _is(CV, str, "constant is str")
    _true(CV.startswith("context-window"), "constant starts with 'context-window'")


test_constant_exported_from_constants_module()

# ===========================================================================
# Part B imports
# ===========================================================================
from services.context_window_service import (
    # Context Selection
    add_context_item, update_context_item, remove_context_item,
    # Context Ranking
    rank_by_priority, rank_by_importance, rank_by_confidence,
    # Context Assembly
    merge_context_windows, deduplicate_context_items, build_execution_context,
    # Retrieval
    retrieve_by_source, retrieve_by_priority, retrieve_by_reference,
    # Item Utilities
    sort_context_items, filter_context_items, group_context_items, find_context_item,
    # Window Utilities
    sort_context_windows, filter_context_windows, group_context_windows, find_context_window,
    # Priority order map (internal)
    _PRIORITY_ORDER,
)

# ===========================================================================
# Part B — Section 29 — add_context_item()
# ===========================================================================

def test_add_context_item() -> None:
    base = build_context_window(
        created_at="2026-07-01T10:00:00Z",
        investigation_id="inv-add",
        conversation_id="conv-add",
        items=[
            _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1"),
        ],
    )

    new_item = _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")

    # Add a new item
    w2 = add_context_item(base, new_item)
    _is(w2, ContextWindow, "add returns ContextWindow")
    _ne(w2.windowKey, base.windowKey, "windowKey changes after add")
    _ne(w2.contextFingerprint, base.contextFingerprint, "fingerprint changes after add")
    _eq(len(w2.items), 2, "2 items after add")
    _true(any(i.contextItemKey == new_item.contextItemKey for i in w2.items),
          "added item is present")
    # original window is unchanged (immutable)
    _eq(len(base.items), 1, "original window unchanged after add")

    # Idempotent add — adding same item again returns unchanged window
    w3 = add_context_item(w2, new_item)
    _eq(len(w3.items), 2, "idempotent: still 2 items after duplicate add")
    _eq(w3.contextFingerprint, w2.contextFingerprint, "fingerprint unchanged on duplicate add")

    # Sort order is preserved: CRITICAL before HIGH
    _eq(w2.items[0].priority, ContextPriorityEnum.CRITICAL, "sort maintained: CRITICAL first")
    _eq(w2.items[1].priority, ContextPriorityEnum.HIGH,     "sort maintained: HIGH second")

    # Deterministic — two identical adds produce identical windows
    w4 = add_context_item(base, new_item)
    _eq(w4.contextFingerprint, w2.contextFingerprint, "add is deterministic")

    # Base window metadata is preserved
    _eq(w2.investigationId, "inv-add",  "investigationId preserved after add")
    _eq(w2.conversationId,  "conv-add", "conversationId preserved after add")
    _eq(w2.createdAt, "2026-07-01T10:00:00Z", "createdAt preserved after add")


test_add_context_item()

# ===========================================================================
# Part B — Section 30 — update_context_item()
# ===========================================================================

def test_update_context_item() -> None:
    original_item = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.NORMAL, "Old title", 0.5, "f-upd")
    base = build_context_window(
        created_at="2026-07-01T10:00:00Z",
        investigation_id="inv-upd",
        conversation_id="conv-upd",
        items=[original_item],
    )

    # Build a replacement with the same key (same source+priority+title+content[:64]+ref)
    # but we rebuild via update_context_item; key equality confirmed below.
    # Note: contextItemKey depends on source, priority, referenceId, title, content[:64].
    # To keep same key we must use identical source/priority/title/content/referenceId.
    # We simulate an "update" by rebuilding with validate=False and mutated metadata.
    replacement = build_context_item(
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.NORMAL,
        title="Old title", content=f"Content for Old title",
        created_at=TS, reference_id="f-upd",
        importance_score=0.95, confidence=0.99,
    )
    # replacement has same key as original_item (same source/priority/title/content/ref)
    _eq(replacement.contextItemKey, original_item.contextItemKey, "same key for update test")

    w2 = update_context_item(base, replacement)
    _is(w2, ContextWindow, "update returns ContextWindow")
    _eq(len(w2.items), 1, "still 1 item after update (replace, not append)")

    # The item in the window should be the replacement (same key, higher scores)
    updated = w2.items[0]
    _eq(updated.priority, ContextPriorityEnum.NORMAL, "priority unchanged (same key)")
    _eq(updated.importanceScore, 0.95, "importanceScore updated")
    _eq(updated.confidence, 0.99, "confidence updated")

    # Since contextItemKey is derived from source+priority+title+content[:64]+referenceId,
    # and the replacement uses identical values for those fields, the key is the same —
    # so the window fingerprint is unchanged (same item set, same keys).
    _eq(w2.contextFingerprint, base.contextFingerprint,
        "fingerprint unchanged when replacement has same key")

    # Upsert: updating with a key not in the window appends it
    new_item = _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.HIGH, "New Alert", 0.7, "a-new")
    _true(all(i.contextItemKey != new_item.contextItemKey for i in base.items),
          "new_item key not in base")
    w3 = update_context_item(base, new_item)
    _eq(len(w3.items), 2, "upsert: 2 items after update with unknown key")
    _true(any(i.contextItemKey == new_item.contextItemKey for i in w3.items),
          "upserted item is present")

    # Deterministic
    w4 = update_context_item(base, replacement)
    _eq(w4.contextFingerprint, w2.contextFingerprint, "update is deterministic")


test_update_context_item()

# ===========================================================================
# Part B — Section 31 — remove_context_item()
# ===========================================================================

def test_remove_context_item() -> None:
    i1 = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1")
    i2 = _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")
    i3 = _make_item(ContextSourceEnum.MEMORY,  ContextPriorityEnum.NORMAL, "M1", 0.5, "m1")

    base = build_context_window(
        created_at="2026-07-01T10:00:00Z",
        investigation_id="inv-rm",
        conversation_id="conv-rm",
        items=[i1, i2, i3],
    )
    _eq(len(base.items), 3, "base has 3 items")

    # Remove middle item
    w2 = remove_context_item(base, i2.contextItemKey)
    _eq(len(w2.items), 2, "2 items after remove")
    _true(all(i.contextItemKey != i2.contextItemKey for i in w2.items),
          "removed item no longer present")
    _eq(len(base.items), 3, "original window unchanged after remove")

    # Fingerprint changes
    _ne(w2.contextFingerprint, base.contextFingerprint, "fingerprint changes after remove")

    # Removing a non-existent key returns unchanged window
    w3 = remove_context_item(base, "nonexistent-key-xyz")
    _eq(len(w3.items), 3, "no change when key not found")
    _eq(w3.contextFingerprint, base.contextFingerprint, "fingerprint unchanged when key not found")

    # Remove all items
    w4 = remove_context_item(w2, i1.contextItemKey)
    w5 = remove_context_item(w4, i3.contextItemKey)
    _eq(len(w5.items), 0, "empty window after removing all items")

    # Deterministic
    w6 = remove_context_item(base, i2.contextItemKey)
    _eq(w6.contextFingerprint, w2.contextFingerprint, "remove is deterministic")


test_remove_context_item()

print()
print("=" * 60)
print(f"Context Window Engine — Smoke Test Results")
print("=" * 60)
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print(f"  TOTAL  : {_PASS + _FAIL}")
print("=" * 60)

if _ERRORS:
    print()
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

if _FAIL == 0:
    print(f"ALL {_PASS} ASSERTIONS PASSED ✓")
    sys.exit(0)
else:
    print(f"{_FAIL} ASSERTION(S) FAILED ✗")
    sys.exit(1)

# ===========================================================================
# Part B — Section 32 — rank_by_priority()
# ===========================================================================

def test_rank_by_priority() -> None:
    items = [
        _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "L", 0.3, "l"),
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.NORMAL,   "N", 0.5, "n"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "C", 0.9, "c"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.HIGH,     "H", 0.7, "h"),
    ]

    ranked_asc  = rank_by_priority(items, ascending=True)
    ranked_desc = rank_by_priority(items, ascending=False)

    _eq(ranked_asc[0].priority,  ContextPriorityEnum.CRITICAL, "asc: CRITICAL first")
    _eq(ranked_asc[-1].priority, ContextPriorityEnum.LOW,      "asc: LOW last")
    _eq(ranked_desc[0].priority, ContextPriorityEnum.LOW,      "desc: LOW first")
    _eq(ranked_desc[-1].priority,ContextPriorityEnum.CRITICAL, "desc: CRITICAL last")

    # Input not mutated
    _eq(items[0].priority, ContextPriorityEnum.LOW, "input not mutated by rank_by_priority")

    # Tie-break by importanceScore DESC within same tier
    same_pri = [
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "H-low",  0.3, "h-lo"),
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "H-high", 0.9, "h-hi"),
    ]
    ranked_tie = rank_by_priority(same_pri)
    _eq(ranked_tie[0].importanceScore, 0.9, "tie-break: higher importance first")

    # Deterministic
    r1 = rank_by_priority(items)
    r2 = rank_by_priority(items)
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "rank_by_priority deterministic")


test_rank_by_priority()

# ===========================================================================
# Part B — Section 33 — rank_by_importance()
# ===========================================================================

def test_rank_by_importance() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.NORMAL, "I-low",  0.2, "il"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.HIGH,   "I-high", 0.9, "ih"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.LOW,    "I-mid",  0.5, "im"),
    ]

    ranked_desc = rank_by_importance(items, ascending=False)
    _eq(ranked_desc[0].importanceScore, 0.9, "desc: highest importance first")
    _eq(ranked_desc[-1].importanceScore, 0.2, "desc: lowest importance last")

    ranked_asc = rank_by_importance(items, ascending=True)
    _eq(ranked_asc[0].importanceScore, 0.2, "asc: lowest importance first")
    _eq(ranked_asc[-1].importanceScore, 0.9, "asc: highest importance last")

    # Input not mutated
    _eq(items[0].importanceScore, 0.2, "input not mutated by rank_by_importance")

    # Deterministic
    r1 = rank_by_importance(items)
    r2 = rank_by_importance(items)
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "rank_by_importance deterministic")


test_rank_by_importance()

# ===========================================================================
# Part B — Section 34 — rank_by_confidence()
# ===========================================================================

def test_rank_by_confidence() -> None:
    items = [
        build_context_item(ContextSourceEnum.FINDING, ContextPriorityEnum.NORMAL, "C-low",  "C", TS, "c-lo", 0.5, 0.2),
        build_context_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.HIGH,   "C-high", "C", TS, "c-hi", 0.5, 0.95),
        build_context_item(ContextSourceEnum.MEMORY,  ContextPriorityEnum.LOW,    "C-mid",  "C", TS, "c-mi", 0.5, 0.6),
    ]

    ranked_desc = rank_by_confidence(items, ascending=False)
    _eq(ranked_desc[0].confidence, 0.95, "desc: highest confidence first")
    _eq(ranked_desc[-1].confidence, 0.2, "desc: lowest confidence last")

    ranked_asc = rank_by_confidence(items, ascending=True)
    _eq(ranked_asc[0].confidence, 0.2,  "asc: lowest confidence first")
    _eq(ranked_asc[-1].confidence, 0.95,"asc: highest confidence last")

    # Input not mutated
    _eq(items[0].confidence, 0.2, "input not mutated by rank_by_confidence")

    # Deterministic
    r1 = rank_by_confidence(items)
    r2 = rank_by_confidence(items)
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "rank_by_confidence deterministic")


test_rank_by_confidence()

# ===========================================================================
# Part B — Section 35 — merge_context_windows()
# ===========================================================================

def test_merge_context_windows() -> None:
    i1 = _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "F1", 0.8, "f1")
    i2 = _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")
    i3 = _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "E1", 0.5, "e1")
    i4 = _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "M1", 0.3, "m1")

    w1 = build_context_window(created_at=TS,  investigation_id="inv-m", conversation_id="conv-m", items=[i1, i2])
    w2 = build_context_window(created_at=TS2, investigation_id="inv-m", conversation_id="conv-m", items=[i3, i4])

    merged = merge_context_windows([w1, w2], created_at=TS)
    _is(merged, ContextWindow, "merge returns ContextWindow")
    _eq(len(merged.items), 4, "merged has all 4 items")

    # Sort order maintained: CRITICAL → HIGH → NORMAL → LOW
    priorities = [i.priority for i in merged.items]
    _eq(priorities[0], ContextPriorityEnum.CRITICAL, "merged: CRITICAL first")
    _eq(priorities[-1], ContextPriorityEnum.LOW,     "merged: LOW last")

    # IDs from first window are used by default
    _eq(merged.investigationId, "inv-m",  "merged investigationId from first window")
    _eq(merged.conversationId,  "conv-m", "merged conversationId from first window")

    # Caller can override IDs
    merged_ovr = merge_context_windows(
        [w1, w2], created_at=TS,
        investigation_id="inv-override", conversation_id="conv-override",
    )
    _eq(merged_ovr.investigationId, "inv-override", "override investigationId")
    _eq(merged_ovr.conversationId,  "conv-override", "override conversationId")

    # Empty merge
    empty_merged = merge_context_windows([], created_at=TS)
    _eq(len(empty_merged.items), 0, "empty merge: 0 items")

    # Single-window merge
    single = merge_context_windows([w1], created_at=TS)
    _eq(len(single.items), 2, "single-window merge preserves items")

    # Deduplication: add a duplicate item across two windows
    i1_dup = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1")  # same key as i1
    _eq(i1_dup.contextItemKey, i1.contextItemKey, "duplicate key confirmed")
    w3 = build_context_window(created_at=TS, items=[i1_dup, i3])
    merged_dedup = merge_context_windows([w1, w3], created_at=TS, deduplicate=True)
    keys_after = [i.contextItemKey for i in merged_dedup.items]
    _eq(len(keys_after), len(set(keys_after)), "no duplicate keys after dedup merge")

    # Without deduplication
    merged_no_dedup = merge_context_windows([w1, w3], created_at=TS, deduplicate=False)
    _eq(len(merged_no_dedup.items), 4, "no-dedup: all 4 items kept (2+2)")

    # Deterministic
    m1 = merge_context_windows([w1, w2], created_at=TS)
    m2 = merge_context_windows([w1, w2], created_at=TS)
    _eq(m1.contextFingerprint, m2.contextFingerprint, "merge is deterministic")


test_merge_context_windows()

# ===========================================================================
# Part B — Section 36 — deduplicate_context_items()
# ===========================================================================

def test_deduplicate_context_items() -> None:
    i1 = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH,   "F1", 0.8, "f1")
    i1_dup_low  = build_context_item(  # same key, lower importance
        source=ContextSourceEnum.FINDING, priority=ContextPriorityEnum.HIGH,
        title="F1", content="Content for F1", created_at=TS, reference_id="f1",
        importance_score=0.3, confidence=0.5,
        validate=False,
    )
    # Same key: i1 and i1_dup_low have same contextItemKey since key derivation doesn't include importance
    _eq(i1.contextItemKey, i1_dup_low.contextItemKey, "same key for dedup test")

    i2 = _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")

    deduped = deduplicate_context_items([i1, i1_dup_low, i2])
    _eq(len(deduped), 2, "2 unique items after dedup")

    # Best representative kept: i1 has higher importance (0.8 > 0.3)
    kept = next(i for i in deduped if i.contextItemKey == i1.contextItemKey)
    _eq(kept.importanceScore, 0.8, "best representative kept (higher importance)")

    # No duplicates in output
    keys = [i.contextItemKey for i in deduped]
    _eq(len(keys), len(set(keys)), "no duplicate keys in deduped output")

    # Empty list
    _eq(deduplicate_context_items([]), [], "empty list → empty output")

    # No duplicates — returns all items
    unique = [i1, i2]
    result = deduplicate_context_items(unique)
    _eq(len(result), 2, "no duplicates: all items retained")

    # Deterministic
    d1 = deduplicate_context_items([i1, i1_dup_low, i2])
    d2 = deduplicate_context_items([i1, i1_dup_low, i2])
    _eq([i.contextItemKey for i in d1], [i.contextItemKey for i in d2],
        "deduplicate is deterministic")


test_deduplicate_context_items()

# ===========================================================================
# Part B — Section 37 — build_execution_context()
# ===========================================================================

def test_build_execution_context() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,      ContextPriorityEnum.CRITICAL, "F1", 0.9, "f1"),
        _make_item(ContextSourceEnum.ALERT,        ContextPriorityEnum.HIGH,     "A1", 0.8, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE,     ContextPriorityEnum.NORMAL,   "E1", 0.5, "e1"),
        _make_item(ContextSourceEnum.MEMORY,       ContextPriorityEnum.LOW,      "M1", 0.2, "m1"),
        _make_item(ContextSourceEnum.CONVERSATION, ContextPriorityEnum.NORMAL,   "C1", 0.6, "c1"),
    ]
    w = build_context_window(created_at=TS, investigation_id="inv-exec", conversation_id="conv-exec", items=items)

    # Filter by sources
    exec_ctx = build_execution_context(w, sources=[ContextSourceEnum.FINDING, ContextSourceEnum.ALERT])
    _eq(len(exec_ctx.items), 2, "filtered to 2 sources")
    _true(all(i.source in {ContextSourceEnum.FINDING, ContextSourceEnum.ALERT} for i in exec_ctx.items),
          "only FINDING and ALERT remain")

    # Filter by priority
    exec_pri = build_execution_context(w, priorities=[ContextPriorityEnum.CRITICAL, ContextPriorityEnum.HIGH])
    _eq(len(exec_pri.items), 2, "filtered to CRITICAL+HIGH: 2 items")

    # Filter by min_importance
    exec_imp = build_execution_context(w, min_importance=0.7)
    _true(all(i.importanceScore >= 0.7 for i in exec_imp.items), "all items >= 0.7 importance")

    # Filter by min_confidence
    exec_conf = build_execution_context(w, min_confidence=0.85)
    _true(all(i.confidence >= 0.85 for i in exec_conf.items), "all items >= 0.85 confidence")

    # Combined filters
    exec_combined = build_execution_context(
        w,
        sources=[ContextSourceEnum.FINDING, ContextSourceEnum.ALERT, ContextSourceEnum.EVIDENCE],
        min_importance=0.5,
    )
    _true(all(i.importanceScore >= 0.5 for i in exec_combined.items), "combined: importance filter holds")
    _true(all(i.source in {ContextSourceEnum.FINDING, ContextSourceEnum.ALERT, ContextSourceEnum.EVIDENCE}
              for i in exec_combined.items), "combined: source filter holds")

    # No filters — returns all items (different window key due to rebuild)
    exec_all = build_execution_context(w)
    _eq(len(exec_all.items), len(w.items), "no filters: all items returned")

    # Returns ContextWindow
    _is(exec_ctx, ContextWindow, "build_execution_context returns ContextWindow")

    # Metadata preserved
    _eq(exec_ctx.investigationId, "inv-exec",  "investigationId preserved")
    _eq(exec_ctx.conversationId,  "conv-exec", "conversationId preserved")


test_build_execution_context()

# ===========================================================================
# Part B — Section 38 — retrieve_by_source()
# ===========================================================================

def test_retrieve_by_source() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,   "F1", 0.8, "f1"),
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.NORMAL, "F2", 0.6, "f2"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL,"A1", 0.9, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.LOW,    "E1", 0.3, "e1"),
    ]
    w = build_context_window(created_at=TS, items=items)

    findings = retrieve_by_source(w, ContextSourceEnum.FINDING)
    _eq(len(findings), 2, "2 FINDING items retrieved")
    _true(all(i.source == ContextSourceEnum.FINDING for i in findings), "all are FINDING")

    alerts = retrieve_by_source(w, ContextSourceEnum.ALERT)
    _eq(len(alerts), 1, "1 ALERT item retrieved")

    # Source not present
    memories = retrieve_by_source(w, ContextSourceEnum.MEMORY)
    _eq(len(memories), 0, "0 MEMORY items (none present)")

    # Deterministic
    r1 = retrieve_by_source(w, ContextSourceEnum.FINDING)
    r2 = retrieve_by_source(w, ContextSourceEnum.FINDING)
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "retrieve_by_source deterministic")


test_retrieve_by_source()

# ===========================================================================
# Part B — Section 39 — retrieve_by_priority()
# ===========================================================================

def test_retrieve_by_priority() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.CRITICAL, "F1", 0.9, "f1"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.HIGH,     "A1", 0.8, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.HIGH,     "E1", 0.7, "e1"),
        _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "M1", 0.3, "m1"),
    ]
    w = build_context_window(created_at=TS, items=items)

    high_items = retrieve_by_priority(w, ContextPriorityEnum.HIGH)
    _eq(len(high_items), 2, "2 HIGH priority items retrieved")
    _true(all(i.priority == ContextPriorityEnum.HIGH for i in high_items), "all are HIGH")

    critical = retrieve_by_priority(w, ContextPriorityEnum.CRITICAL)
    _eq(len(critical), 1, "1 CRITICAL item retrieved")

    normal = retrieve_by_priority(w, ContextPriorityEnum.NORMAL)
    _eq(len(normal), 0, "0 NORMAL items (none present)")

    # Deterministic
    r1 = retrieve_by_priority(w, ContextPriorityEnum.HIGH)
    r2 = retrieve_by_priority(w, ContextPriorityEnum.HIGH)
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "retrieve_by_priority deterministic")


test_retrieve_by_priority()

# ===========================================================================
# Part B — Section 40 — retrieve_by_reference()
# ===========================================================================

def test_retrieve_by_reference() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,   "F1", 0.8, "shared-ref"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL,"A1", 0.9, "shared-ref"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL, "E1", 0.5, "other-ref"),
    ]
    w = build_context_window(created_at=TS, items=items)

    shared = retrieve_by_reference(w, "shared-ref")
    _eq(len(shared), 2, "2 items share 'shared-ref'")
    _true(all(i.referenceId == "shared-ref" for i in shared), "all have shared-ref")

    single = retrieve_by_reference(w, "other-ref")
    _eq(len(single), 1, "1 item with 'other-ref'")

    none = retrieve_by_reference(w, "no-such-ref")
    _eq(len(none), 0, "0 items for missing referenceId")

    # Deterministic
    r1 = retrieve_by_reference(w, "shared-ref")
    r2 = retrieve_by_reference(w, "shared-ref")
    _eq([i.contextItemKey for i in r1], [i.contextItemKey for i in r2], "retrieve_by_reference deterministic")


test_retrieve_by_reference()

# ===========================================================================
# Part B — Section 41 — sort_context_items()
# ===========================================================================

def test_sort_context_items() -> None:
    items = [
        build_context_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.LOW,      "Z title",   "c", TS, "ref-z", 0.2, 0.3),
        build_context_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "A title",   "c", TS, "ref-a", 0.9, 0.95),
        build_context_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "M title",   "c", TS, "ref-m", 0.5, 0.6),
        build_context_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.HIGH,     "B title",   "c" * 40, TS, "ref-b", 0.7, 0.8),
    ]

    # Sort by priority ASC (CRITICAL first)
    by_pri = sort_context_items(items, by="priority", ascending=True)
    _eq(by_pri[0].priority, ContextPriorityEnum.CRITICAL, "priority ASC: CRITICAL first")
    _eq(by_pri[-1].priority, ContextPriorityEnum.LOW,     "priority ASC: LOW last")

    # Sort by importance DESC (default)
    by_imp = sort_context_items(items, by="importance", ascending=False)
    _eq(by_imp[0].importanceScore, 0.9, "importance DESC: highest first")
    _eq(by_imp[-1].importanceScore, 0.2,"importance DESC: lowest last")

    # Sort by importance ASC
    by_imp_asc = sort_context_items(items, by="importance", ascending=True)
    _eq(by_imp_asc[0].importanceScore, 0.2, "importance ASC: lowest first")

    # Sort by confidence DESC
    by_conf = sort_context_items(items, by="confidence", ascending=False)
    _eq(by_conf[0].confidence, 0.95, "confidence DESC: highest first")

    # Sort by title ASC
    by_title = sort_context_items(items, by="title", ascending=True)
    _eq(by_title[0].title, "A title", "title ASC: A first")
    _eq(by_title[-1].title, "Z title","title ASC: Z last")

    # Sort by tokenEstimate DESC
    by_tok = sort_context_items(items, by="tokenEstimate", ascending=False)
    _ge(by_tok[0].tokenEstimate, by_tok[-1].tokenEstimate, "tokenEstimate DESC: largest first")

    # Sort by source ASC
    by_src = sort_context_items(items, by="source", ascending=True)
    _true(by_src[0].source.value <= by_src[-1].source.value, "source ASC: alphabetical")

    # Sort by createdAt ASC (all same timestamp here — tie-break by id)
    by_ts = sort_context_items(items, by="createdAt", ascending=True)
    _is(by_ts, list, "createdAt sort returns list")

    # Unknown key raises ValueError
    try:
        sort_context_items(items, by="nonexistent")
        _false(True, "unknown key should raise ValueError")
    except ValueError as exc:
        _in("nonexistent", str(exc), "ValueError mentions unknown key")

    # Input not mutated
    orig_order = [i.contextItemKey for i in items]
    sort_context_items(items, by="importance")
    _eq([i.contextItemKey for i in items], orig_order, "input not mutated")

    # Deterministic
    s1 = sort_context_items(items, by="importance")
    s2 = sort_context_items(items, by="importance")
    _eq([i.contextItemKey for i in s1], [i.contextItemKey for i in s2], "sort deterministic")


test_sort_context_items()

# ===========================================================================
# Part B — Section 42 — filter_context_items()
# ===========================================================================

def test_filter_context_items() -> None:
    items = [
        build_context_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "Finding A",  "content A",    TS, "f1", 0.9, 0.95),
        build_context_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.NORMAL,   "Finding B",  "content B",    TS, "f2", 0.4, 0.6),
        build_context_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "Alert C",    "content C",    TS, "a1", 0.8, 0.9),
        build_context_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "Memory D",   "content D" * 5,TS, "m1", 0.2, 0.3),
        build_context_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.HIGH,     "Evidence E", "content E",    TS, "e1", 0.7, 0.85),
    ]

    # Filter by source
    findings = filter_context_items(items, source=ContextSourceEnum.FINDING)
    _eq(len(findings), 2, "filter by source: 2 FINDING items")

    # Filter by priority
    high_items = filter_context_items(items, priority=ContextPriorityEnum.HIGH)
    _eq(len(high_items), 2, "filter by priority: 2 HIGH items")

    # Filter by min_importance
    hi_imp = filter_context_items(items, min_importance=0.7)
    _true(all(i.importanceScore >= 0.7 for i in hi_imp), "min_importance filter")
    _eq(len(hi_imp), 3, "3 items >= 0.7 importance")

    # Filter by max_importance
    lo_imp = filter_context_items(items, max_importance=0.5)
    _true(all(i.importanceScore <= 0.5 for i in lo_imp), "max_importance filter")

    # Filter by min_confidence
    hi_conf = filter_context_items(items, min_confidence=0.85)
    _true(all(i.confidence >= 0.85 for i in hi_conf), "min_confidence filter")

    # Filter by max_confidence
    lo_conf = filter_context_items(items, max_confidence=0.6)
    _true(all(i.confidence <= 0.6 for i in lo_conf), "max_confidence filter")

    # Filter by reference_id
    by_ref = filter_context_items(items, reference_id="f1")
    _eq(len(by_ref), 1, "filter by referenceId: 1 match")
    _eq(by_ref[0].referenceId, "f1", "correct item returned")

    # Filter by title_contains (case-insensitive)
    by_title = filter_context_items(items, title_contains="finding")
    _eq(len(by_title), 2, "title_contains 'finding': 2 matches (case-insensitive)")

    # Filter by token range
    min_tok = min(i.tokenEstimate for i in items)
    max_tok = max(i.tokenEstimate for i in items)
    by_tok = filter_context_items(items, min_tokens=min_tok, max_tokens=max_tok)
    _eq(len(by_tok), len(items), "token range covering all: all items returned")

    # Combined filter: FINDING + min_importance
    combo = filter_context_items(items, source=ContextSourceEnum.FINDING, min_importance=0.8)
    _eq(len(combo), 1, "FINDING + importance>=0.8: 1 item")
    _eq(combo[0].referenceId, "f1", "correct item in combined filter")

    # No filters — all items returned
    all_items = filter_context_items(items)
    _eq(len(all_items), 5, "no filters: all 5 items")

    # Input not mutated
    orig_count = len(items)
    filter_context_items(items, source=ContextSourceEnum.FINDING)
    _eq(len(items), orig_count, "input not mutated by filter")

    # Empty input
    _eq(filter_context_items([], source=ContextSourceEnum.FINDING), [], "empty input → empty output")


test_filter_context_items()

# ===========================================================================
# Part B — Section 43 — group_context_items()
# ===========================================================================

def test_group_context_items() -> None:
    items = [
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.HIGH,     "F1", 0.8, "f1"),
        _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.NORMAL,   "F2", 0.6, "f2"),
        _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1"),
        _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.HIGH,     "E1", 0.7, "e1"),
    ]

    # Group by source
    by_source = group_context_items(items, group_by="source")
    _is(by_source, dict, "group_by source returns dict")
    _in("FINDING",  by_source, "FINDING group present")
    _in("ALERT",    by_source, "ALERT group present")
    _in("EVIDENCE", by_source, "EVIDENCE group present")
    _eq(len(by_source["FINDING"]),  2, "2 items in FINDING group")
    _eq(len(by_source["ALERT"]),    1, "1 item in ALERT group")
    _eq(len(by_source["EVIDENCE"]), 1, "1 item in EVIDENCE group")

    # Each group is sorted canonically
    for grp_items in by_source.values():
        for j in range(len(grp_items) - 1):
            a, b = grp_items[j], grp_items[j + 1]
            a_ord = _PRIORITY_ORDER.get(a.priority, 99)
            b_ord = _PRIORITY_ORDER.get(b.priority, 99)
            _le(a_ord, b_ord, f"group sorted: {a.priority} <= {b.priority}")

    # Group by priority
    by_priority = group_context_items(items, group_by="priority")
    _is(by_priority, dict, "group_by priority returns dict")
    _in("HIGH",     by_priority, "HIGH group present")
    _in("CRITICAL", by_priority, "CRITICAL group present")
    _in("NORMAL",   by_priority, "NORMAL group present")
    _eq(len(by_priority["HIGH"]), 2, "2 HIGH items")

    # Unknown key raises
    try:
        group_context_items(items, group_by="unknown_field")
        _false(True, "unknown group_by should raise ValueError")
    except ValueError as exc:
        _in("unknown_field", str(exc), "ValueError mentions unknown key")

    # Empty input
    empty_grp = group_context_items([], group_by="source")
    _eq(empty_grp, {}, "empty input → empty dict")

    # Deterministic
    g1 = group_context_items(items, group_by="source")
    g2 = group_context_items(items, group_by="source")
    for key in g1:
        _eq(
            [i.contextItemKey for i in g1[key]],
            [i.contextItemKey for i in g2[key]],
            f"group {key} deterministic",
        )


test_group_context_items()

# ===========================================================================
# Part B — Section 44 — find_context_item()
# ===========================================================================

def test_find_context_item() -> None:
    i1 = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH,   "F1", 0.8, "f1")
    i2 = _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.CRITICAL,"A1", 0.9, "a1")

    items = [i1, i2]

    # Found
    found = find_context_item(items, i1.contextItemKey)
    _true(found is not None, "find returns item when found")
    _eq(found.contextItemKey, i1.contextItemKey, "correct item found")

    # Not found
    not_found = find_context_item(items, "nonexistent-key")
    _true(not_found is None, "find returns None when not found")

    # Empty list
    _true(find_context_item([], i1.contextItemKey) is None, "find on empty list returns None")

    # Deterministic
    f1 = find_context_item(items, i2.contextItemKey)
    f2 = find_context_item(items, i2.contextItemKey)
    _eq(f1.contextItemKey, f2.contextItemKey, "find is deterministic")


test_find_context_item()

# ===========================================================================
# Part B — Section 45 — sort_context_windows()
# ===========================================================================

def test_sort_context_windows() -> None:
    w1 = build_context_window(
        created_at="2026-07-01T08:00:00Z", investigation_id="inv-s", conversation_id="conv-s",
        items=[_make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1")],
    )
    w2 = build_context_window(
        created_at="2026-07-01T10:00:00Z", investigation_id="inv-s", conversation_id="conv-s",
        items=[
            _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1"),
            _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.HIGH,     "A2", 0.7, "a2"),
        ],
    )
    w3 = build_context_window(
        created_at="2026-07-01T09:00:00Z", investigation_id="inv-s", conversation_id="conv-s",
        items=[_make_item(ContextSourceEnum.MEMORY, ContextPriorityEnum.LOW, "M1", 0.3, "m1")],
    )

    windows = [w2, w3, w1]

    # Sort by createdAt ASC
    by_ts_asc = sort_context_windows(windows, by="createdAt", ascending=True)
    _eq(by_ts_asc[0].createdAt, "2026-07-01T08:00:00Z", "createdAt ASC: earliest first")
    _eq(by_ts_asc[-1].createdAt,"2026-07-01T10:00:00Z", "createdAt ASC: latest last")

    # Sort by createdAt DESC
    by_ts_desc = sort_context_windows(windows, by="createdAt", ascending=False)
    _eq(by_ts_desc[0].createdAt,"2026-07-01T10:00:00Z", "createdAt DESC: latest first")

    # Sort by itemCount ASC
    by_items_asc = sort_context_windows(windows, by="itemCount", ascending=True)
    _le(len(by_items_asc[0].items), len(by_items_asc[-1].items), "itemCount ASC")

    # Sort by itemCount DESC
    by_items_desc = sort_context_windows(windows, by="itemCount", ascending=False)
    _ge(len(by_items_desc[0].items), len(by_items_desc[-1].items), "itemCount DESC")

    # Sort by totalTokenEstimate
    by_tok = sort_context_windows(windows, by="totalTokenEstimate", ascending=False)
    _ge(by_tok[0].totalTokenEstimate, by_tok[-1].totalTokenEstimate, "tokenEstimate DESC")

    # Sort by windowId / windowKey / contextFingerprint
    by_wid = sort_context_windows(windows, by="windowId")
    _is(by_wid, list, "sorted by windowId returns list")
    by_wk = sort_context_windows(windows, by="windowKey")
    _is(by_wk, list, "sorted by windowKey returns list")
    by_fp = sort_context_windows(windows, by="contextFingerprint")
    _is(by_fp, list, "sorted by contextFingerprint returns list")

    # Unknown key raises
    try:
        sort_context_windows(windows, by="unknown")
        _false(True, "unknown key should raise ValueError")
    except ValueError as exc:
        _in("unknown", str(exc), "ValueError mentions unknown key")

    # Input not mutated
    orig = [w.windowKey for w in windows]
    sort_context_windows(windows, by="createdAt")
    _eq([w.windowKey for w in windows], orig, "input not mutated")

    # Deterministic
    s1 = sort_context_windows(windows, by="createdAt")
    s2 = sort_context_windows(windows, by="createdAt")
    _eq([w.windowKey for w in s1], [w.windowKey for w in s2], "sort deterministic")

    # Empty list
    _eq(sort_context_windows([], by="createdAt"), [], "empty list → empty output")


test_sort_context_windows()

# ===========================================================================
# Part B — Section 46 — filter_context_windows()
# ===========================================================================

def test_filter_context_windows() -> None:
    w_a = build_context_window(
        created_at=TS, investigation_id="inv-A", conversation_id="conv-1",
        items=[
            _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH,     "F1", 0.9, "f1"),
            _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.CRITICAL, "A1", 0.8, "a1"),
        ],
    )
    w_b = build_context_window(
        created_at=TS2, investigation_id="inv-B", conversation_id="conv-2",
        items=[
            _make_item(ContextSourceEnum.MEMORY, ContextPriorityEnum.LOW, "M1", 0.3, "m1"),
        ],
    )
    w_c = build_context_window(
        created_at=TS, investigation_id="inv-A", conversation_id="conv-1",
        items=[
            _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL, "E1", 0.5, "e1"),
            _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL, "E2", 0.4, "e2"),
            _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL, "E3", 0.3, "e3"),
        ],
    )
    windows = [w_a, w_b, w_c]

    # Filter by investigationId
    inv_a = filter_context_windows(windows, investigation_id="inv-A")
    _eq(len(inv_a), 2, "2 windows for inv-A")
    _true(all(w.investigationId == "inv-A" for w in inv_a), "all inv-A")

    # Filter by conversationId
    conv_1 = filter_context_windows(windows, conversation_id="conv-1")
    _eq(len(conv_1), 2, "2 windows for conv-1")

    # Filter by min_items
    big = filter_context_windows(windows, min_items=2)
    _true(all(len(w.items) >= 2 for w in big), "min_items=2: all have >= 2 items")

    # Filter by max_items
    small = filter_context_windows(windows, max_items=1)
    _true(all(len(w.items) <= 1 for w in small), "max_items=1: all have <= 1 item")

    # Filter by token range
    tok_min = min(w.totalTokenEstimate for w in windows)
    tok_max = max(w.totalTokenEstimate for w in windows)
    all_tok = filter_context_windows(windows, min_token_estimate=tok_min, max_token_estimate=tok_max)
    _eq(len(all_tok), 3, "token range covering all: all 3 windows")

    # Filter has_source — windows containing at least one FINDING
    has_finding = filter_context_windows(windows, has_source=ContextSourceEnum.FINDING)
    _eq(len(has_finding), 1, "1 window has FINDING items")

    # Filter has_priority — windows containing at least one CRITICAL
    has_critical = filter_context_windows(windows, has_priority=ContextPriorityEnum.CRITICAL)
    _eq(len(has_critical), 1, "1 window has CRITICAL item")

    # No filters
    all_windows = filter_context_windows(windows)
    _eq(len(all_windows), 3, "no filters: all 3 windows returned")

    # Empty input
    _eq(filter_context_windows([]), [], "empty input → empty output")

    # Input not mutated
    orig_count = len(windows)
    filter_context_windows(windows, investigation_id="inv-A")
    _eq(len(windows), orig_count, "input not mutated")


test_filter_context_windows()

# ===========================================================================
# Part B — Section 47 — group_context_windows()
# ===========================================================================

def test_group_context_windows() -> None:
    w1 = build_context_window(
        created_at="2026-07-01T08:00:00Z",
        investigation_id="inv-X", conversation_id="conv-1",
        items=[_make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1")],
    )
    w2 = build_context_window(
        created_at="2026-07-01T09:00:00Z",
        investigation_id="inv-X", conversation_id="conv-2",
        items=[_make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")],
    )
    w3 = build_context_window(
        created_at="2026-07-01T10:00:00Z",
        investigation_id="inv-Y", conversation_id="conv-1",
        items=[_make_item(ContextSourceEnum.MEMORY, ContextPriorityEnum.LOW, "M1", 0.3, "m1")],
    )
    windows = [w3, w1, w2]

    # Group by investigationId
    by_inv = group_context_windows(windows, group_by="investigationId")
    _is(by_inv, dict, "group_by investigationId returns dict")
    _in("inv-X", by_inv, "inv-X group present")
    _in("inv-Y", by_inv, "inv-Y group present")
    _eq(len(by_inv["inv-X"]), 2, "2 windows for inv-X")
    _eq(len(by_inv["inv-Y"]), 1, "1 window for inv-Y")

    # Groups sorted by createdAt ASC
    x_group = by_inv["inv-X"]
    _le(x_group[0].createdAt, x_group[-1].createdAt, "inv-X group sorted by createdAt ASC")

    # Group by conversationId
    by_conv = group_context_windows(windows, group_by="conversationId")
    _in("conv-1", by_conv, "conv-1 group present")
    _in("conv-2", by_conv, "conv-2 group present")
    _eq(len(by_conv["conv-1"]), 2, "2 windows for conv-1")

    # Unknown key raises
    try:
        group_context_windows(windows, group_by="bad_field")
        _false(True, "unknown group_by should raise ValueError")
    except ValueError as exc:
        _in("bad_field", str(exc), "ValueError mentions bad field")

    # Empty input
    _eq(group_context_windows([]), {}, "empty input → empty dict")

    # Deterministic
    g1 = group_context_windows(windows, group_by="investigationId")
    g2 = group_context_windows(windows, group_by="investigationId")
    for key in g1:
        _eq(
            [w.windowKey for w in g1[key]],
            [w.windowKey for w in g2[key]],
            f"group {key} deterministic",
        )


test_group_context_windows()

# ===========================================================================
# Part B — Section 48 — find_context_window()
# ===========================================================================

def test_find_context_window() -> None:
    w1 = build_context_window(
        created_at=TS, investigation_id="inv-find", conversation_id="conv-find",
        items=[_make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1")],
    )
    w2 = build_context_window(
        created_at=TS2, investigation_id="inv-find", conversation_id="conv-find",
        items=[_make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")],
    )
    windows = [w1, w2]

    found = find_context_window(windows, w1.windowKey)
    _true(found is not None, "find_context_window: found")
    _eq(found.windowKey, w1.windowKey, "correct window found")

    not_found = find_context_window(windows, "nonexistent-key-xyz")
    _true(not_found is None, "find returns None when not found")

    _true(find_context_window([], w1.windowKey) is None, "find on empty list returns None")

    # Deterministic
    f1 = find_context_window(windows, w2.windowKey)
    f2 = find_context_window(windows, w2.windowKey)
    _eq(f1.windowKey, f2.windowKey, "find_context_window deterministic")


test_find_context_window()

# ===========================================================================
# Part B — Section 49 — Extended build_context_statistics()
# ===========================================================================

def test_extended_build_context_statistics() -> None:
    # Mirrors Part A test but verifies the extended implementation via group_context_items
    i1 = _make_item(ContextSourceEnum.FINDING,  ContextPriorityEnum.CRITICAL, "F1", 0.9, "f1")
    i2 = _make_item(ContextSourceEnum.ALERT,    ContextPriorityEnum.HIGH,     "A1", 0.8, "a1")
    i3 = _make_item(ContextSourceEnum.EVIDENCE, ContextPriorityEnum.NORMAL,   "E1", 0.5, "e1")
    i4 = _make_item(ContextSourceEnum.MEMORY,   ContextPriorityEnum.LOW,      "M1", 0.3, "m1")

    w1 = build_context_window(created_at=TS,  items=[i1, i2])
    w2 = build_context_window(created_at=TS2, items=[i3, i4])

    stats = build_context_statistics([w1, w2])

    _eq(stats.totalWindows, 2,  "totalWindows=2")
    _eq(stats.totalItems,   4,  "totalItems=4")
    _gt(stats.averageTokens, 0, "averageTokens > 0")
    _gt(stats.averageImportance, 0.0, "averageImportance > 0")
    _gt(stats.averageConfidence, 0.0, "averageConfidence > 0")
    _le(stats.averageImportance, 1.0, "averageImportance <= 1")
    _le(stats.averageConfidence, 1.0, "averageConfidence <= 1")

    # itemsBySource correctness (via group_context_items)
    _eq(stats.itemsBySource["FINDING"],  1, "itemsBySource: 1 FINDING")
    _eq(stats.itemsBySource["ALERT"],    1, "itemsBySource: 1 ALERT")
    _eq(stats.itemsBySource["EVIDENCE"], 1, "itemsBySource: 1 EVIDENCE")
    _eq(stats.itemsBySource["MEMORY"],   1, "itemsBySource: 1 MEMORY")
    _eq(stats.itemsBySource.get("CONVERSATION", 0), 0, "itemsBySource: 0 CONVERSATION")

    # itemsByPriority correctness
    _eq(stats.itemsByPriority["CRITICAL"], 1, "itemsByPriority: 1 CRITICAL")
    _eq(stats.itemsByPriority["HIGH"],     1, "itemsByPriority: 1 HIGH")
    _eq(stats.itemsByPriority["NORMAL"],   1, "itemsByPriority: 1 NORMAL")
    _eq(stats.itemsByPriority["LOW"],      1, "itemsByPriority: 1 LOW")

    # All enum values present (even at 0)
    for src in ContextSourceEnum:
        _in(src.value, stats.itemsBySource, f"{src.value} key present in itemsBySource")
    for pri in ContextPriorityEnum:
        _in(pri.value, stats.itemsByPriority, f"{pri.value} key present in itemsByPriority")

    # Empty list
    stats0 = build_context_statistics([])
    _eq(stats0.totalWindows,      0,   "empty: 0 windows")
    _eq(stats0.totalItems,        0,   "empty: 0 items")
    _eq(stats0.averageTokens,     0.0, "empty: 0.0 tokens")
    _eq(stats0.averageImportance, 0.0, "empty: 0.0 importance")
    _eq(stats0.averageConfidence, 0.0, "empty: 0.0 confidence")

    # Deterministic
    s1 = build_context_statistics([w1, w2])
    s2 = build_context_statistics([w1, w2])
    _eq(s1.averageImportance, s2.averageImportance, "statistics deterministic")
    _eq(s1.itemsBySource,     s2.itemsBySource,     "itemsBySource deterministic")
    _eq(s1.itemsByPriority,   s2.itemsByPriority,   "itemsByPriority deterministic")

    # Insert order independence for statistics
    s3 = build_context_statistics([w2, w1])
    _eq(s1.totalItems,        s3.totalItems,        "statistics insert-order independent (items)")
    _eq(s1.averageImportance, s3.averageImportance, "statistics insert-order independent (importance)")


test_extended_build_context_statistics()

# ===========================================================================
# Part B — Section 50 — Deterministic updates (add/update/remove chains)
# ===========================================================================

def test_deterministic_update_chains() -> None:
    """Verify that any chain of add/update/remove operations is deterministic."""
    i1 = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH,     "F1", 0.8, "f1")
    i2 = _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.CRITICAL, "A1", 0.9, "a1")
    i3 = _make_item(ContextSourceEnum.MEMORY,  ContextPriorityEnum.NORMAL,   "M1", 0.5, "m1")

    base = build_context_window(created_at=TS, items=[i1])

    def _chain(start):
        w = add_context_item(start, i2)
        w = add_context_item(w, i3)
        w = update_context_item(w, _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.CRITICAL, "F1", 0.99, "f1"))
        w = remove_context_item(w, i3.contextItemKey)
        return w

    result_a = _chain(base)
    result_b = _chain(base)

    _eq(result_a.contextFingerprint, result_b.contextFingerprint,
        "chained add/update/remove is deterministic")
    _eq(len(result_a.items), 2, "expected 2 items after chain")
    _eq(result_a.items[0].priority, ContextPriorityEnum.CRITICAL, "sort maintained after chain (CRITICAL first)")


test_deterministic_update_chains()

# ===========================================================================
# Part B — Section 51 — Edge cases
# ===========================================================================

def test_edge_cases() -> None:
    # Single item window add/remove cycle returns to original fingerprint
    i = _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "Singleton", 0.7, "s1")
    base = build_context_window(created_at=TS, items=[i])
    w2 = add_context_item(base, _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.LOW, "Extra", 0.2, "x1"))
    w3 = remove_context_item(w2, _make_item(ContextSourceEnum.ALERT, ContextPriorityEnum.LOW, "Extra", 0.2, "x1").contextItemKey)
    _eq(w3.contextFingerprint, base.contextFingerprint,
        "add then remove returns to original fingerprint")

    # Merge of a window with itself results in same items (after dedup)
    m = merge_context_windows([base, base], created_at=TS, deduplicate=True)
    _eq(len(m.items), 1, "merge of window with itself: dedup gives 1 item")

    # filter_context_items with no match returns empty list
    items = [_make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F", 0.5, "f")]
    _eq(filter_context_items(items, source=ContextSourceEnum.ALERT), [], "no-match filter → empty")

    # rank_by_priority on empty list
    _eq(rank_by_priority([]), [], "rank_by_priority on empty → empty")
    _eq(rank_by_importance([]), [], "rank_by_importance on empty → empty")
    _eq(rank_by_confidence([]), [], "rank_by_confidence on empty → empty")

    # sort_context_items on single item
    single = [_make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.NORMAL, "Only", 0.5, "o")]
    _eq(sort_context_items(single, by="importance"), single, "single item sort unchanged")

    # group_context_items groups are disjoint (no item in two groups)
    multi = [
        _make_item(ContextSourceEnum.FINDING, ContextPriorityEnum.HIGH, "F1", 0.8, "f1"),
        _make_item(ContextSourceEnum.ALERT,   ContextPriorityEnum.LOW,  "A1", 0.3, "a1"),
    ]
    groups = group_context_items(multi, group_by="source")
    all_keys = []
    for grp_items in groups.values():
        all_keys.extend(i.contextItemKey for i in grp_items)
    _eq(len(all_keys), len(set(all_keys)), "group_context_items groups are disjoint")

    # build_execution_context with no matching items returns empty window
    w = build_context_window(created_at=TS, items=multi)
    empty_exec = build_execution_context(w, sources=[ContextSourceEnum.MEMORY])
    _eq(len(empty_exec.items), 0, "build_execution_context: no match → empty window")

    # retrieve functions on empty window
    empty_win = build_context_window(created_at=TS)
    _eq(retrieve_by_source(empty_win, ContextSourceEnum.FINDING),     [], "retrieve_by_source on empty window")
    _eq(retrieve_by_priority(empty_win, ContextPriorityEnum.CRITICAL),[],  "retrieve_by_priority on empty window")
    _eq(retrieve_by_reference(empty_win, "ref"),                       [], "retrieve_by_reference on empty window")


test_edge_cases()

# ===========================================================================
# Final report
# ===========================================================================

print()
print("=" * 60)
print("Context Window Engine — Smoke Test Results (Part A + B)")
print("=" * 60)
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print(f"  TOTAL  : {_PASS + _FAIL}")
print("=" * 60)

if _ERRORS:
    print()
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

if _FAIL == 0:
    print(f"ALL {_PASS} ASSERTIONS PASSED ✓")
    sys.exit(0)
else:
    print(f"{_FAIL} ASSERTION(S) FAILED ✗")
    sys.exit(1)
