"""
Smoke Test — Session Memory Engine
=====================================
Phase A4.5.0 — Verifies every model, builder, validator, serialisation path,
integration helper, fingerprint, and statistic in
services/session_memory_service.py.

Run:
    python smoke_test_session_memory_engine.py
Expected: 200+/200 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. Pure model / builder / validator tests.
- Same inputs -> same outputs (fully deterministic).
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
def _is(a, t, msg):  _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
def _true(v, msg):   _assert(bool(v), f"{msg}")
def _false(v, msg):  _assert(not bool(v), f"{msg}")


# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.session_memory_service import (
    # Enumerations
    MemoryTypeEnum, MemoryStateEnum,
    # Exceptions
    SessionMemoryError, InvalidMemoryEntryError,
    InvalidMemorySummaryError, InvalidSessionMemoryError,
    # Models
    MemoryEntry, MemorySummary, SessionMemory, MemoryStatistics,
    # Builders
    build_memory_entry, build_memory_summary,
    build_session_memory, build_memory_statistics,
    # Validators
    validate_memory_entry, validate_memory_summary, validate_session_memory,
    # ID helpers (internal, exported for testing)
    _sha256_32, _sha256_64, _uuid5,
    _compute_memory_key, _compute_summary_key,
    _compute_session_key, _compute_memory_fingerprint,
    # Integration helpers
    memories_to_execution_context,
    session_memory_to_copilot_context,
    session_memory_to_conversation_context,
    # Version constant re-export
    SESSION_MEMORY_ENGINE_VERSION,
)
from core.constants import SESSION_MEMORY_ENGINE_VERSION as CONST_SMV

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS   = "2026-07-01T12:00:00Z"
_TS2  = "2026-07-01T13:00:00Z"
_TS3  = "2026-07-01T14:00:00Z"
_CONV_ID  = "conv-test-001"
_CONV_ID2 = "conv-test-002"
_INV_ID   = "inv-abc-123"


# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version ...")
_eq(SESSION_MEMORY_ENGINE_VERSION, "session-memory-v1", "version value")
_eq(CONST_SMV, SESSION_MEMORY_ENGINE_VERSION, "core.constants matches service")
_is(SESSION_MEMORY_ENGINE_VERSION, str, "version is str")
_in("session-memory", SESSION_MEMORY_ENGINE_VERSION, "version contains 'session-memory'")
_in("v1", SESSION_MEMORY_ENGINE_VERSION, "version contains 'v1'")


# ===========================================================================
# §2  MemoryTypeEnum
# ===========================================================================
print("§2  MemoryTypeEnum ...")
_eq(MemoryTypeEnum.SHORT_TERM.value,    "SHORT_TERM",    "SHORT_TERM value")
_eq(MemoryTypeEnum.LONG_TERM.value,     "LONG_TERM",     "LONG_TERM value")
_eq(MemoryTypeEnum.SUMMARY.value,       "SUMMARY",       "SUMMARY value")
_eq(MemoryTypeEnum.EPISODIC.value,      "EPISODIC",      "EPISODIC value")
_eq(MemoryTypeEnum.INVESTIGATION.value, "INVESTIGATION", "INVESTIGATION value")
_eq(len(MemoryTypeEnum), 5, "MemoryTypeEnum has exactly 5 members")
# All values are strings
for member in MemoryTypeEnum:
    _is(member.value, str, f"MemoryTypeEnum.{member.name} value is str")
# Round-trip from string
_eq(MemoryTypeEnum("SHORT_TERM"),    MemoryTypeEnum.SHORT_TERM,    "SHORT_TERM round-trip")
_eq(MemoryTypeEnum("INVESTIGATION"), MemoryTypeEnum.INVESTIGATION, "INVESTIGATION round-trip")


# ===========================================================================
# §3  MemoryStateEnum
# ===========================================================================
print("§3  MemoryStateEnum ...")
_eq(MemoryStateEnum.ACTIVE.value,     "ACTIVE",     "ACTIVE value")
_eq(MemoryStateEnum.ARCHIVED.value,   "ARCHIVED",   "ARCHIVED value")
_eq(MemoryStateEnum.COMPRESSED.value, "COMPRESSED", "COMPRESSED value")
_eq(MemoryStateEnum.EXPIRED.value,    "EXPIRED",    "EXPIRED value")
_eq(len(MemoryStateEnum), 4, "MemoryStateEnum has exactly 4 members")
for member in MemoryStateEnum:
    _is(member.value, str, f"MemoryStateEnum.{member.name} value is str")
_eq(MemoryStateEnum("ACTIVE"),   MemoryStateEnum.ACTIVE,   "ACTIVE round-trip")
_eq(MemoryStateEnum("ARCHIVED"), MemoryStateEnum.ARCHIVED, "ARCHIVED round-trip")


# ===========================================================================
# §4  Exception hierarchy
# ===========================================================================
print("§4  Exception hierarchy ...")
_true(issubclass(InvalidMemoryEntryError,   SessionMemoryError), "InvalidMemoryEntryError < SessionMemoryError")
_true(issubclass(InvalidMemorySummaryError, SessionMemoryError), "InvalidMemorySummaryError < SessionMemoryError")
_true(issubclass(InvalidSessionMemoryError, SessionMemoryError), "InvalidSessionMemoryError < SessionMemoryError")
_true(issubclass(SessionMemoryError,        Exception),          "SessionMemoryError < Exception")


# ===========================================================================
# §5  Deterministic ID helpers
# ===========================================================================
print("§5  Deterministic ID helpers ...")
# _sha256_32 — length and determinism
h1 = _sha256_32("abc", "def")
h2 = _sha256_32("abc", "def")
_eq(len(h1), 32, "_sha256_32 returns 32 chars")
_eq(h1, h2, "_sha256_32 deterministic")
# Different inputs produce different hashes
h3 = _sha256_32("abc", "xyz")
_ne(h1, h3, "_sha256_32 different inputs differ")
# Null-byte separation: 'ab' + 'c' != 'a' + 'bc'
_ne(_sha256_32("ab", "c"), _sha256_32("a", "bc"), "_sha256_32 null-byte prevents collision")

# _sha256_64 — length and determinism
h4 = _sha256_64("hello", "world")
h5 = _sha256_64("hello", "world")
_eq(len(h4), 64, "_sha256_64 returns 64 chars")
_eq(h4, h5, "_sha256_64 deterministic")
_ne(_sha256_64("a"), _sha256_64("b"), "_sha256_64 different inputs differ")

# _uuid5 — format and determinism
u1 = _uuid5("test-key-001")
u2 = _uuid5("test-key-001")
_eq(u1, u2, "_uuid5 deterministic")
_eq(len(u1), 36, "_uuid5 returns 36-char UUID string")
_in("-", u1, "_uuid5 contains hyphens")
u3 = _uuid5("test-key-002")
_ne(u1, u3, "_uuid5 different keys differ")
# Must NOT be uuid4 — version digit is '5'
_eq(u1[14], "5", "_uuid5 version digit is '5'")


# ===========================================================================
# §6  Key derivation functions
# ===========================================================================
print("§6  Key derivation functions ...")

# _compute_memory_key
mk1 = _compute_memory_key(_CONV_ID, "SHORT_TERM", "Test Title", "Test content here")
mk2 = _compute_memory_key(_CONV_ID, "SHORT_TERM", "Test Title", "Test content here")
_eq(mk1, mk2, "_compute_memory_key deterministic")
_eq(len(mk1), 32, "_compute_memory_key returns 32 chars")
mk3 = _compute_memory_key(_CONV_ID, "LONG_TERM", "Test Title", "Test content here")
_ne(mk1, mk3, "_compute_memory_key type change produces different key")
mk4 = _compute_memory_key(_CONV_ID2, "SHORT_TERM", "Test Title", "Test content here")
_ne(mk1, mk4, "_compute_memory_key conv_id change produces different key")

# _compute_summary_key
sk1 = _compute_summary_key(_CONV_ID, "Summary text here", ("id-1", "id-2"))
sk2 = _compute_summary_key(_CONV_ID, "Summary text here", ("id-1", "id-2"))
_eq(sk1, sk2, "_compute_summary_key deterministic")
_eq(len(sk1), 32, "_compute_summary_key returns 32 chars")
sk3 = _compute_summary_key(_CONV_ID, "Different summary", ("id-1", "id-2"))
_ne(sk1, sk3, "_compute_summary_key text change produces different key")

# _compute_session_key
sek1 = _compute_session_key(_CONV_ID, _INV_ID)
sek2 = _compute_session_key(_CONV_ID, _INV_ID)
_eq(sek1, sek2, "_compute_session_key deterministic")
_eq(len(sek1), 32, "_compute_session_key returns 32 chars")
sek3 = _compute_session_key(_CONV_ID2, _INV_ID)
_ne(sek1, sek3, "_compute_session_key conv_id change produces different key")

# _compute_memory_fingerprint
fp1 = _compute_memory_fingerprint("sess-key-1", ("mk-a", "mk-b"), ("sk-x",))
fp2 = _compute_memory_fingerprint("sess-key-1", ("mk-a", "mk-b"), ("sk-x",))
_eq(fp1, fp2, "_compute_memory_fingerprint deterministic")
_eq(len(fp1), 32, "_compute_memory_fingerprint returns 32 chars")
# Order-independence for memory keys
fp3 = _compute_memory_fingerprint("sess-key-1", ("mk-b", "mk-a"), ("sk-x",))
_eq(fp1, fp3, "_compute_memory_fingerprint order-independent (memory keys sorted)")
# Order-independence for summary keys
fp4 = _compute_memory_fingerprint("sess-key-1", ("mk-a", "mk-b"), ("sk-x",))
_eq(fp1, fp4, "_compute_memory_fingerprint consistent with same inputs")


# ===========================================================================
# §7  validate_memory_entry
# ===========================================================================
print("§7  validate_memory_entry ...")

# Happy path — should not raise
try:
    validate_memory_entry(
        _CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
        "Test Title", "Content here", 0.8, 0.9, _TS,
    )
    _pass_v = True
except Exception:
    _pass_v = False
_true(_pass_v, "validate_memory_entry passes valid input")

# Empty conversationId
_raised = False
try:
    validate_memory_entry("", MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "T", "c", 0.5, 0.5, _TS)
except InvalidMemoryEntryError as e:
    _raised = True
    _in("conversationId", str(e), "empty conversationId error message")
_true(_raised, "validate_memory_entry raises on empty conversationId")

# Invalid memory_type
_raised = False
try:
    validate_memory_entry(_CONV_ID, "WRONG_TYPE", MemoryStateEnum.ACTIVE,
                          "T", "c", 0.5, 0.5, _TS)
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "validate_memory_entry raises on invalid memoryType")

# Empty title
_raised = False
try:
    validate_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "", "c", 0.5, 0.5, _TS)
except InvalidMemoryEntryError as e:
    _raised = True
    _in("title", str(e), "empty title error message")
_true(_raised, "validate_memory_entry raises on empty title")

# importanceScore out of range (>1.0)
_raised = False
try:
    validate_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "T", "c", 1.5, 0.5, _TS)
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "validate_memory_entry raises on importanceScore > 1.0")

# confidence out of range (<0.0)
_raised = False
try:
    validate_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "T", "c", 0.5, -0.1, _TS)
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "validate_memory_entry raises on confidence < 0.0")

# None content should raise
_raised = False
try:
    validate_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "T", None, 0.5, 0.5, _TS)
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "validate_memory_entry raises on None content")

# Empty createdAt
_raised = False
try:
    validate_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, MemoryStateEnum.ACTIVE,
                          "T", "c", 0.5, 0.5, "")
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "validate_memory_entry raises on empty createdAt")


# ===========================================================================
# §8  validate_memory_summary
# ===========================================================================
print("§8  validate_memory_summary ...")

# Happy path
try:
    validate_memory_summary(_CONV_ID, "A good summary", ("id-1", "id-2"), _TS)
    _pass_s = True
except Exception:
    _pass_s = False
_true(_pass_s, "validate_memory_summary passes valid input")

# Empty conversationId
_raised = False
try:
    validate_memory_summary("", "Summary", ("id-1",), _TS)
except InvalidMemorySummaryError as e:
    _raised = True
    _in("conversationId", str(e), "empty conversationId message in summary error")
_true(_raised, "validate_memory_summary raises on empty conversationId")

# Empty summary text
_raised = False
try:
    validate_memory_summary(_CONV_ID, "", ("id-1",), _TS)
except InvalidMemorySummaryError as e:
    _raised = True
    _in("summary", str(e), "empty summary text message")
_true(_raised, "validate_memory_summary raises on empty summary")

# Empty coveredMemoryIds
_raised = False
try:
    validate_memory_summary(_CONV_ID, "Summary text", (), _TS)
except InvalidMemorySummaryError as e:
    _raised = True
    _in("coveredMemoryIds", str(e), "empty coveredMemoryIds message")
_true(_raised, "validate_memory_summary raises on empty coveredMemoryIds")

# Empty createdAt
_raised = False
try:
    validate_memory_summary(_CONV_ID, "Summary text", ("id-1",), "")
except InvalidMemorySummaryError:
    _raised = True
_true(_raised, "validate_memory_summary raises on empty createdAt")


# ===========================================================================
# §9  validate_session_memory
# ===========================================================================
print("§9  validate_session_memory ...")

# Happy path
try:
    validate_session_memory(_CONV_ID, _TS, _TS2)
    _pass_sm = True
except Exception:
    _pass_sm = False
_true(_pass_sm, "validate_session_memory passes valid input")

# Empty conversationId
_raised = False
try:
    validate_session_memory("", _TS, _TS2)
except InvalidSessionMemoryError as e:
    _raised = True
    _in("conversationId", str(e), "empty conversationId message in session error")
_true(_raised, "validate_session_memory raises on empty conversationId")

# Empty createdAt
_raised = False
try:
    validate_session_memory(_CONV_ID, "", _TS2)
except InvalidSessionMemoryError:
    _raised = True
_true(_raised, "validate_session_memory raises on empty createdAt")

# Empty updatedAt
_raised = False
try:
    validate_session_memory(_CONV_ID, _TS, "")
except InvalidSessionMemoryError:
    _raised = True
_true(_raised, "validate_session_memory raises on empty updatedAt")


# ===========================================================================
# §10  build_memory_entry — basic construction
# ===========================================================================
print("§10  build_memory_entry basic ...")

entry1 = build_memory_entry(
    conversation_id  = _CONV_ID,
    memory_type      = MemoryTypeEnum.SHORT_TERM,
    title            = "Network anomaly detected",
    content          = "Unusual port scan from 192.168.1.50",
    created_at       = _TS,
    investigation_id = _INV_ID,
    state            = MemoryStateEnum.ACTIVE,
    importance_score = 0.9,
    confidence       = 0.85,
    source_id        = "msg-001",
    tags             = ["anomaly", "port-scan", "network"],
    metadata         = {"analyst": "alice"},
)

# Type checks
_is(entry1, MemoryEntry, "build_memory_entry returns MemoryEntry")
_is(entry1.memoryId,   str, "memoryId is str")
_is(entry1.memoryKey,  str, "memoryKey is str")
_is(entry1.tags,       tuple, "tags is tuple")
_is(entry1.metadata,   dict, "metadata is dict")

# Field values
_eq(entry1.conversationId,  _CONV_ID,   "conversationId stored")
_eq(entry1.investigationId, _INV_ID,    "investigationId stored")
_eq(entry1.memoryType,  MemoryTypeEnum.SHORT_TERM,  "memoryType stored")
_eq(entry1.state,       MemoryStateEnum.ACTIVE,      "state stored")
_eq(entry1.title,       "Network anomaly detected",  "title stored")
_eq(entry1.sourceId,    "msg-001",                   "sourceId stored")
_eq(entry1.createdAt,   _TS,                         "createdAt stored")

# ID lengths
_eq(len(entry1.memoryId),  36, "memoryId is 36-char UUID")
_eq(len(entry1.memoryKey), 32, "memoryKey is 32 chars")

# Scores clamped and stored
_ge(entry1.importanceScore, 0.0, "importanceScore >= 0")
_le(entry1.importanceScore, 1.0, "importanceScore <= 1")
_ge(entry1.confidence, 0.0, "confidence >= 0")
_le(entry1.confidence, 1.0, "confidence <= 1")

# Tags deduped, lowercased, sorted
_eq(entry1.tags, ("anomaly", "network", "port-scan"), "tags normalised")

# Metadata copied
_eq(entry1.metadata, {"analyst": "alice"}, "metadata copied")

# Immutability — frozen model should raise on assignment
_raised = False
try:
    entry1.title = "mutated"  # type: ignore[misc]
except Exception:
    _raised = True
_true(_raised, "MemoryEntry is immutable (frozen)")


# ===========================================================================
# §11  build_memory_entry — deterministic IDs
# ===========================================================================
print("§11  build_memory_entry deterministic IDs ...")

entry1_dup = build_memory_entry(
    conversation_id  = _CONV_ID,
    memory_type      = MemoryTypeEnum.SHORT_TERM,
    title            = "Network anomaly detected",
    content          = "Unusual port scan from 192.168.1.50",
    created_at       = _TS,
    investigation_id = _INV_ID,
    state            = MemoryStateEnum.ACTIVE,
    importance_score = 0.9,
    confidence       = 0.85,
    source_id        = "msg-001",
    tags             = ["anomaly", "port-scan", "network"],
    metadata         = {"analyst": "alice"},
)
_eq(entry1.memoryId,  entry1_dup.memoryId,  "memoryId deterministic")
_eq(entry1.memoryKey, entry1_dup.memoryKey, "memoryKey deterministic")

# Different content -> different key/id
entry2 = build_memory_entry(
    conversation_id = _CONV_ID,
    memory_type     = MemoryTypeEnum.LONG_TERM,
    title           = "Critical finding",
    content         = "SSH brute-force attempt logged",
    created_at      = _TS2,
    importance_score= 0.75,
    confidence      = 1.0,
)
_ne(entry1.memoryId,  entry2.memoryId,  "different entries have different memoryIds")
_ne(entry1.memoryKey, entry2.memoryKey, "different entries have different memoryKeys")

# memoryId is UUIDv5 — version digit
_eq(entry1.memoryId[14], "5", "memoryId version digit is '5' (UUIDv5)")

# Verify memoryKey matches manual computation
expected_key = _compute_memory_key(_CONV_ID, "SHORT_TERM", "Network anomaly detected", "Unusual port scan from 192.168.1.50")
_eq(entry1.memoryKey, expected_key, "memoryKey matches manual _compute_memory_key")

# Verify memoryId matches _uuid5(memoryKey)
expected_id = _uuid5(entry1.memoryKey)
_eq(entry1.memoryId, expected_id, "memoryId matches _uuid5(memoryKey)")


# ===========================================================================
# §12  build_memory_entry — edge cases & clamping
# ===========================================================================
print("§12  build_memory_entry edge cases ...")

# Importance score clamped to 1.0
entry_clamped = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.EPISODIC, "Edge", "Content",
    _TS, importance_score=99.0, confidence=99.0,
)
_eq(entry_clamped.importanceScore, 1.0, "importanceScore clamped to 1.0")
_eq(entry_clamped.confidence, 1.0, "confidence clamped to 1.0")

# Scores clamped to 0.0
entry_zero = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.EPISODIC, "Zero", "Content",
    _TS, importance_score=-5.0, confidence=-3.0,
)
_eq(entry_zero.importanceScore, 0.0, "importanceScore clamped to 0.0")
_eq(entry_zero.confidence, 0.0, "confidence clamped to 0.0")

# Empty content is allowed
entry_empty_content = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SUMMARY, "Placeholder", "", _TS,
)
_eq(entry_empty_content.content, "", "empty content allowed")
_is(entry_empty_content, MemoryEntry, "entry with empty content is MemoryEntry")

# Tags deduplication
entry_dup_tags = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "Tag Test", "Content", _TS,
    tags=["alpha", "ALPHA", "  alpha  ", "beta"],
)
_eq(entry_dup_tags.tags, ("alpha", "beta"), "duplicate tags deduplicated")

# No tags -> empty tuple
entry_no_tags = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "No Tags", "Content", _TS,
)
_eq(entry_no_tags.tags, (), "no tags -> empty tuple")

# Empty metadata -> empty dict
entry_no_meta = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "No Meta", "Content", _TS,
)
_eq(entry_no_meta.metadata, {}, "no metadata -> empty dict")

# All MemoryTypeEnum values work
for mt in MemoryTypeEnum:
    e = build_memory_entry(_CONV_ID, mt, f"Title-{mt.value}", "Content", _TS)
    _eq(e.memoryType, mt, f"memoryType={mt.value} stored correctly")

# All MemoryStateEnum values work
for ms in MemoryStateEnum:
    e = build_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, f"State-{ms.value}",
                           "Content", _TS, state=ms)
    _eq(e.state, ms, f"state={ms.value} stored correctly")

# validate=False skips validation (allows bad inputs)
entry_no_val = build_memory_entry(
    "", MemoryTypeEnum.SHORT_TERM, "T", "c", _TS, validate=False,
)
_is(entry_no_val, MemoryEntry, "validate=False builds MemoryEntry even with empty conversationId")

# validate=True raises on bad input
_raised = False
try:
    build_memory_entry("", MemoryTypeEnum.SHORT_TERM, "T", "c", _TS, validate=True)
except InvalidMemoryEntryError:
    _raised = True
_true(_raised, "build_memory_entry validate=True raises InvalidMemoryEntryError")


# ===========================================================================
# §13  build_memory_summary — basic construction
# ===========================================================================
print("§13  build_memory_summary basic ...")

summary1 = build_memory_summary(
    conversation_id    = _CONV_ID,
    summary            = "Three anomalies detected: port scan, brute-force, exfil.",
    covered_memory_ids = [entry1.memoryId, entry2.memoryId],
    created_at         = _TS,
)

_is(summary1, MemorySummary, "build_memory_summary returns MemorySummary")
_eq(summary1.conversationId, _CONV_ID, "conversationId stored")
_is(summary1.coveredMemoryIds, tuple, "coveredMemoryIds is tuple")
_gt(summary1.tokenEstimate, 0, "tokenEstimate > 0 for non-empty summary")
_eq(len(summary1.summaryId),  36, "summaryId is 36-char UUID")
_eq(len(summary1.summaryKey), 32, "summaryKey is 32 chars")
_eq(summary1.createdAt, _TS, "createdAt stored")

# coveredMemoryIds sorted
_eq(summary1.coveredMemoryIds, tuple(sorted([entry1.memoryId, entry2.memoryId])),
    "coveredMemoryIds sorted")

# Immutability
_raised = False
try:
    summary1.summary = "mutated"  # type: ignore[misc]
except Exception:
    _raised = True
_true(_raised, "MemorySummary is immutable (frozen)")


# ===========================================================================
# §14  build_memory_summary — deterministic IDs
# ===========================================================================
print("§14  build_memory_summary deterministic IDs ...")

summary1_dup = build_memory_summary(
    conversation_id    = _CONV_ID,
    summary            = "Three anomalies detected: port scan, brute-force, exfil.",
    covered_memory_ids = [entry1.memoryId, entry2.memoryId],
    created_at         = _TS,
)
_eq(summary1.summaryId,  summary1_dup.summaryId,  "summaryId deterministic")
_eq(summary1.summaryKey, summary1_dup.summaryKey, "summaryKey deterministic")

# Order-independent coveredMemoryIds
summary1_reordered = build_memory_summary(
    conversation_id    = _CONV_ID,
    summary            = "Three anomalies detected: port scan, brute-force, exfil.",
    covered_memory_ids = [entry2.memoryId, entry1.memoryId],  # reversed
    created_at         = _TS,
)
_eq(summary1.summaryId,  summary1_reordered.summaryId,  "summaryId order-independent")
_eq(summary1.summaryKey, summary1_reordered.summaryKey, "summaryKey order-independent")

# Different summary text -> different key/id
summary2 = build_memory_summary(
    conversation_id    = _CONV_ID,
    summary            = "A completely different summary.",
    covered_memory_ids = [entry1.memoryId],
    created_at         = _TS2,
)
_ne(summary1.summaryId,  summary2.summaryId,  "different summaries have different summaryIds")
_ne(summary1.summaryKey, summary2.summaryKey, "different summaries have different summaryKeys")

# summaryId version digit
_eq(summary1.summaryId[14], "5", "summaryId version digit is '5' (UUIDv5)")

# Verify summaryKey matches manual computation
expected_skey = _compute_summary_key(
    _CONV_ID,
    "Three anomalies detected: port scan, brute-force, exfil.",
    tuple(sorted([entry1.memoryId, entry2.memoryId])),
)
_eq(summary1.summaryKey, expected_skey, "summaryKey matches manual _compute_summary_key")

# Verify summaryId matches _uuid5(summaryKey)
_eq(summary1.summaryId, _uuid5(summary1.summaryKey), "summaryId matches _uuid5(summaryKey)")


# ===========================================================================
# §15  build_memory_summary — token estimate
# ===========================================================================
print("§15  build_memory_summary token estimate ...")

short_text = "Hi"
long_text  = "A" * 400
s_short = build_memory_summary(_CONV_ID, short_text, [entry1.memoryId], _TS)
s_long  = build_memory_summary(_CONV_ID, long_text,  [entry1.memoryId], _TS2)
_gt(s_short.tokenEstimate, 0,                   "short summary token > 0")
_gt(s_long.tokenEstimate,  s_short.tokenEstimate,"long summary has more tokens")
# Ceiling(400/4) = 100
_eq(s_long.tokenEstimate, 100, "400-char summary -> 100 tokens")


# ===========================================================================
# §16  build_session_memory — basic construction
# ===========================================================================
print("§16  build_session_memory basic ...")

entry3 = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.EPISODIC, "Login event", "User logged in at 03:00",
    _TS3, investigation_id=_INV_ID, importance_score=0.6, confidence=0.95,
)

session1 = build_session_memory(
    conversation_id  = _CONV_ID,
    created_at       = _TS,
    updated_at       = _TS2,
    investigation_id = _INV_ID,
    memories         = [entry1, entry2, entry3],
    summaries        = [summary1],
)

_is(session1, SessionMemory, "build_session_memory returns SessionMemory")
_eq(session1.conversationId,  _CONV_ID, "conversationId stored")
_eq(session1.investigationId, _INV_ID,  "investigationId stored")
_eq(session1.createdAt,  _TS,  "createdAt stored")
_eq(session1.updatedAt,  _TS2, "updatedAt stored")
_eq(len(session1.memories),   3, "3 memories stored")
_eq(len(session1.summaries),  1, "1 summary stored")
_eq(len(session1.sessionId),  36, "sessionId is 36-char UUID")
_eq(len(session1.sessionKey), 32, "sessionKey is 32 chars")
_eq(len(session1.memoryFingerprint), 32, "memoryFingerprint is 32 chars")
_is(session1.memories,  tuple, "memories is tuple")
_is(session1.summaries, tuple, "summaries is tuple")

# Immutability
_raised = False
try:
    session1.conversationId = "mutated"  # type: ignore[misc]
except Exception:
    _raised = True
_true(_raised, "SessionMemory is immutable (frozen)")


# ===========================================================================
# §17  build_session_memory — deterministic IDs
# ===========================================================================
print("§17  build_session_memory deterministic IDs ...")

session1_dup = build_session_memory(
    conversation_id  = _CONV_ID,
    created_at       = _TS,
    updated_at       = _TS2,
    investigation_id = _INV_ID,
    memories         = [entry1, entry2, entry3],
    summaries        = [summary1],
)
_eq(session1.sessionId,         session1_dup.sessionId,         "sessionId deterministic")
_eq(session1.sessionKey,        session1_dup.sessionKey,        "sessionKey deterministic")
_eq(session1.memoryFingerprint, session1_dup.memoryFingerprint, "memoryFingerprint deterministic")

# Different conversationId -> different session
session_diff = build_session_memory(
    conversation_id  = _CONV_ID2,
    created_at       = _TS,
    updated_at       = _TS2,
    investigation_id = _INV_ID,
    memories         = [entry1],
)
_ne(session1.sessionId,  session_diff.sessionId,  "different conv -> different sessionId")
_ne(session1.sessionKey, session_diff.sessionKey, "different conv -> different sessionKey")

# Fingerprint changes when memories change
session_no_mem = build_session_memory(
    conversation_id  = _CONV_ID,
    created_at       = _TS,
    updated_at       = _TS2,
    investigation_id = _INV_ID,
    memories         = [],
)
_ne(session1.memoryFingerprint, session_no_mem.memoryFingerprint,
    "fingerprint differs when memories differ")

# sessionId version digit
_eq(session1.sessionId[14], "5", "sessionId version digit is '5' (UUIDv5)")

# Verify sessionKey matches manual computation
expected_sess_key = _compute_session_key(_CONV_ID, _INV_ID)
_eq(session1.sessionKey, expected_sess_key, "sessionKey matches manual _compute_session_key")

# Verify sessionId matches _uuid5(sessionKey)
_eq(session1.sessionId, _uuid5(session1.sessionKey), "sessionId matches _uuid5(sessionKey)")

# Verify fingerprint matches manual computation
manual_fp = _compute_memory_fingerprint(
    session1.sessionKey,
    tuple(m.memoryKey  for m in session1.memories),
    tuple(s.summaryKey for s in session1.summaries),
)
_eq(session1.memoryFingerprint, manual_fp, "memoryFingerprint matches manual computation")


# ===========================================================================
# §18  build_session_memory — sorting order
# ===========================================================================
print("§18  build_session_memory sorting ...")

# Memories sorted by (createdAt ASC, memoryId ASC)
entry_early = build_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, "Early", "e", _TS)
entry_mid   = build_memory_entry(_CONV_ID, MemoryTypeEnum.LONG_TERM,  "Mid",   "m", _TS2)
entry_late  = build_memory_entry(_CONV_ID, MemoryTypeEnum.EPISODIC,   "Late",  "l", _TS3)

# Supply in reverse order
sess_order = build_session_memory(
    _CONV_ID, _TS, _TS,
    memories=[entry_late, entry_early, entry_mid],
)
_eq(sess_order.memories[0].createdAt, _TS,  "first memory has earliest createdAt")
_eq(sess_order.memories[1].createdAt, _TS2, "second memory has middle createdAt")
_eq(sess_order.memories[2].createdAt, _TS3, "third memory has latest createdAt")

# Empty memories / summaries
sess_empty = build_session_memory(_CONV_ID, _TS, _TS)
_eq(len(sess_empty.memories),  0, "empty memories tuple")
_eq(len(sess_empty.summaries), 0, "empty summaries tuple")
_is(sess_empty.memories,  tuple, "empty memories is tuple")
_is(sess_empty.summaries, tuple, "empty summaries is tuple")

# Empty investigationId allowed
sess_no_inv = build_session_memory(_CONV_ID, _TS, _TS, investigation_id="")
_eq(sess_no_inv.investigationId, "", "empty investigationId allowed")
_ne(sess_no_inv.sessionKey, session1.sessionKey, "empty inv_id gives different sessionKey")


# ===========================================================================
# §19  build_memory_statistics — empty
# ===========================================================================
print("§19  build_memory_statistics empty ...")

stats_empty = build_memory_statistics([])
_is(stats_empty, MemoryStatistics, "empty stats returns MemoryStatistics")
_eq(stats_empty.totalSessions,      0,   "totalSessions=0")
_eq(stats_empty.totalMemories,      0,   "totalMemories=0")
_eq(stats_empty.activeMemories,     0,   "activeMemories=0")
_eq(stats_empty.archivedMemories,   0,   "archivedMemories=0")
_eq(stats_empty.compressedMemories, 0,   "compressedMemories=0")
_eq(stats_empty.expiredMemories,    0,   "expiredMemories=0")
_eq(stats_empty.averageImportance,  0.0, "averageImportance=0.0")
_eq(stats_empty.averageConfidence,  0.0, "averageConfidence=0.0")

# Immutability
_raised = False
try:
    stats_empty.totalSessions = 1  # type: ignore[misc]
except Exception:
    _raised = True
_true(_raised, "MemoryStatistics is immutable (frozen)")


# ===========================================================================
# §20  build_memory_statistics — populated
# ===========================================================================
print("§20  build_memory_statistics populated ...")

entry_archived = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.LONG_TERM, "Archived memory",
    "Old content", _TS, state=MemoryStateEnum.ARCHIVED,
    importance_score=0.3, confidence=0.7,
)
entry_compressed = build_memory_entry(
    _CONV_ID2, MemoryTypeEnum.SUMMARY, "Compressed",
    "Compressed text", _TS, state=MemoryStateEnum.COMPRESSED,
    importance_score=0.1, confidence=0.5,
)
entry_expired = build_memory_entry(
    _CONV_ID2, MemoryTypeEnum.SHORT_TERM, "Expired",
    "Stale content", _TS2, state=MemoryStateEnum.EXPIRED,
    importance_score=0.2, confidence=0.4,
)

sess_a = build_session_memory(
    _CONV_ID, _TS, _TS,
    investigation_id=_INV_ID,
    memories=[entry1, entry2, entry_archived],
)
sess_b = build_session_memory(
    _CONV_ID2, _TS, _TS,
    memories=[entry_compressed, entry_expired],
)

stats = build_memory_statistics([sess_a, sess_b])
_is(stats, MemoryStatistics, "populated stats returns MemoryStatistics")
_eq(stats.totalSessions,       2, "totalSessions=2")
_eq(stats.totalMemories,       5, "totalMemories=5 (3+2)")
_eq(stats.activeMemories,      2, "activeMemories=2 (entry1 + entry2 are ACTIVE)")
_eq(stats.archivedMemories,    1, "archivedMemories=1")
_eq(stats.compressedMemories,  1, "compressedMemories=1")
_eq(stats.expiredMemories,     1, "expiredMemories=1")
_ge(stats.averageImportance,   0.0, "averageImportance >= 0")
_le(stats.averageImportance,   1.0, "averageImportance <= 1")
_ge(stats.averageConfidence,   0.0, "averageConfidence >= 0")
_le(stats.averageConfidence,   1.0, "averageConfidence <= 1")

# Stats are deterministic
stats2 = build_memory_statistics([sess_b, sess_a])  # reversed input
_eq(stats.averageImportance, stats2.averageImportance, "averageImportance deterministic regardless of session order")
_eq(stats.averageConfidence, stats2.averageConfidence, "averageConfidence deterministic regardless of session order")
_eq(stats.totalMemories,     stats2.totalMemories,     "totalMemories deterministic")


# ===========================================================================
# §21  Serialisation — model_dump / JSON round-trip
# ===========================================================================
print("§21  Serialisation ...")
import json

# MemoryEntry JSON round-trip
entry_dict = entry1.model_dump()
_is(entry_dict, dict, "MemoryEntry.model_dump() returns dict")
_in("memoryId",        entry_dict, "memoryId in dict")
_in("memoryKey",       entry_dict, "memoryKey in dict")
_in("memoryType",      entry_dict, "memoryType in dict")
_in("state",           entry_dict, "state in dict")
_in("importanceScore", entry_dict, "importanceScore in dict")
_in("confidence",      entry_dict, "confidence in dict")
_in("tags",            entry_dict, "tags in dict")
_in("metadata",        entry_dict, "metadata in dict")
_in("createdAt",       entry_dict, "createdAt in dict")

entry_json = entry1.model_dump_json()
_is(entry_json, str, "MemoryEntry.model_dump_json() returns str")
parsed = json.loads(entry_json)
_eq(parsed["memoryId"],  entry1.memoryId,  "JSON memoryId round-trip")
_eq(parsed["memoryKey"], entry1.memoryKey, "JSON memoryKey round-trip")
_eq(parsed["title"],     entry1.title,     "JSON title round-trip")

# MemorySummary JSON round-trip
summ_dict = summary1.model_dump()
_in("summaryId",        summ_dict, "summaryId in summary dict")
_in("summaryKey",       summ_dict, "summaryKey in summary dict")
_in("coveredMemoryIds", summ_dict, "coveredMemoryIds in summary dict")
_in("tokenEstimate",    summ_dict, "tokenEstimate in summary dict")

summ_json = summary1.model_dump_json()
_is(summ_json, str, "MemorySummary.model_dump_json() returns str")
parsed_s = json.loads(summ_json)
_eq(parsed_s["summaryId"],  summary1.summaryId,  "JSON summaryId round-trip")

# SessionMemory JSON round-trip
sess_dict = session1.model_dump()
_in("sessionId",         sess_dict, "sessionId in session dict")
_in("sessionKey",        sess_dict, "sessionKey in session dict")
_in("memoryFingerprint", sess_dict, "memoryFingerprint in session dict")
_in("memories",          sess_dict, "memories in session dict")
_in("summaries",         sess_dict, "summaries in session dict")
_is(sess_dict["memories"], (list, tuple), "memories serialised as list/tuple in dict")

sess_json = session1.model_dump_json()
_is(sess_json, str, "SessionMemory.model_dump_json() returns str")
parsed_sess = json.loads(sess_json)
_eq(parsed_sess["sessionId"],  session1.sessionId,  "JSON sessionId round-trip")
_eq(len(parsed_sess["memories"]), 3, "JSON memories list has 3 items")

# MemoryStatistics JSON round-trip
stats_dict = stats.model_dump()
_in("totalSessions",      stats_dict, "totalSessions in stats dict")
_in("averageImportance",  stats_dict, "averageImportance in stats dict")
_in("averageConfidence",  stats_dict, "averageConfidence in stats dict")
stats_json = stats.model_dump_json()
_is(stats_json, str, "MemoryStatistics.model_dump_json() returns str")


# ===========================================================================
# §22  Zero-randomness guarantee
# ===========================================================================
print("§22  Zero randomness ...")

# Build 10 identical entries and verify all keys/ids match
keys_set = set()
ids_set  = set()
for _ in range(10):
    e = build_memory_entry(
        _CONV_ID, MemoryTypeEnum.INVESTIGATION,
        "Repeated title", "Repeated content", _TS,
    )
    keys_set.add(e.memoryKey)
    ids_set.add(e.memoryId)
_eq(len(keys_set), 1, "10 identical builds produce exactly 1 unique memoryKey")
_eq(len(ids_set),  1, "10 identical builds produce exactly 1 unique memoryId")

# Build 5 identical summaries
skeys = set()
sids  = set()
for _ in range(5):
    s = build_memory_summary(_CONV_ID, "Same summary", [entry1.memoryId], _TS)
    skeys.add(s.summaryKey)
    sids.add(s.summaryId)
_eq(len(skeys), 1, "5 identical summary builds produce 1 unique summaryKey")
_eq(len(sids),  1, "5 identical summary builds produce 1 unique summaryId")

# Build 5 identical sessions
sess_keys = set()
sess_fps  = set()
for _ in range(5):
    sm = build_session_memory(_CONV_ID, _TS, _TS2, _INV_ID, memories=[entry1, entry2])
    sess_keys.add(sm.sessionKey)
    sess_fps.add(sm.memoryFingerprint)
_eq(len(sess_keys), 1, "5 identical session builds produce 1 unique sessionKey")
_eq(len(sess_fps),  1, "5 identical session builds produce 1 unique fingerprint")


# ===========================================================================
# §23  Integration helper — memories_to_execution_context
# ===========================================================================
print("§23  memories_to_execution_context ...")

ctx = memories_to_execution_context(session1.memories)
_is(ctx, str, "memories_to_execution_context returns str")
_true(len(ctx) > 0, "context string is non-empty for non-empty memories")
_in("[SESSION MEMORY CONTEXT]", ctx, "context header present")
_in("Network anomaly detected", ctx, "entry1 title in context")

# Empty memories -> empty string
ctx_empty = memories_to_execution_context(())
_eq(ctx_empty, "", "empty memories -> empty context string")

# Token budget respected — use tiny budget
ctx_tiny = memories_to_execution_context(session1.memories, max_tokens=5)
# With max_tokens=5 we only fit the header at most
_is(ctx_tiny, str, "tiny budget still returns str")

# Importance ordering: higher importance entries appear first
entry_high = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "HighImp", "high importance content",
    _TS, importance_score=0.99,
)
entry_low = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "LowImp", "low importance content",
    _TS, importance_score=0.01,
)
ctx_ordered = memories_to_execution_context((entry_low, entry_high))
idx_high = ctx_ordered.find("HighImp")
idx_low  = ctx_ordered.find("LowImp")
_lt(idx_high, idx_low, "high importance entry appears before low importance entry")

# Deterministic: same call produces same result
ctx_a = memories_to_execution_context(session1.memories)
ctx_b = memories_to_execution_context(session1.memories)
_eq(ctx_a, ctx_b, "memories_to_execution_context is deterministic")


# ===========================================================================
# §24  Integration helper — session_memory_to_copilot_context
# ===========================================================================
print("§24  session_memory_to_copilot_context ...")

copilot_ctx = session_memory_to_copilot_context(session1)
_is(copilot_ctx, dict, "session_memory_to_copilot_context returns dict")
_eq(copilot_ctx["sessionId"],         session1.sessionId,         "sessionId in copilot ctx")
_eq(copilot_ctx["sessionKey"],        session1.sessionKey,        "sessionKey in copilot ctx")
_eq(copilot_ctx["conversationId"],    session1.conversationId,    "conversationId in copilot ctx")
_eq(copilot_ctx["investigationId"],   session1.investigationId,   "investigationId in copilot ctx")
_eq(copilot_ctx["memoryFingerprint"], session1.memoryFingerprint, "memoryFingerprint in copilot ctx")
_eq(copilot_ctx["totalMemories"],     len(session1.memories),     "totalMemories in copilot ctx")
_eq(copilot_ctx["totalSummaries"],    len(session1.summaries),    "totalSummaries in copilot ctx")
_in("activeMemories",  copilot_ctx, "activeMemories in copilot ctx")
_in("engineVersion",   copilot_ctx, "engineVersion in copilot ctx")
_eq(copilot_ctx["engineVersion"], SESSION_MEMORY_ENGINE_VERSION, "engineVersion matches constant")

# JSON serialisable
json_str = json.dumps(copilot_ctx)
_is(json_str, str, "copilot_ctx is JSON-serialisable")

# Deterministic
ctx2 = session_memory_to_copilot_context(session1)
_eq(copilot_ctx, ctx2, "session_memory_to_copilot_context is deterministic")


# ===========================================================================
# §25  Integration helper — session_memory_to_conversation_context
# ===========================================================================
print("§25  session_memory_to_conversation_context ...")

conv_ctx = session_memory_to_conversation_context(session1)
_is(conv_ctx, dict, "session_memory_to_conversation_context returns dict")
_eq(conv_ctx["memorySessionId"],   session1.sessionId,         "memorySessionId in conv ctx")
_eq(conv_ctx["memoryFingerprint"], session1.memoryFingerprint, "memoryFingerprint in conv ctx")
_eq(conv_ctx["memoryCount"],       len(session1.memories),     "memoryCount in conv ctx")
_eq(conv_ctx["summaryCount"],      len(session1.summaries),    "summaryCount in conv ctx")
_eq(conv_ctx["investigationId"],   session1.investigationId,   "investigationId in conv ctx")
_in("engineVersion", conv_ctx, "engineVersion in conv ctx")
_eq(conv_ctx["engineVersion"], SESSION_MEMORY_ENGINE_VERSION, "conv ctx engineVersion correct")

# JSON serialisable
_is(json.dumps(conv_ctx), str, "conv_ctx is JSON-serialisable")

# Deterministic
conv_ctx2 = session_memory_to_conversation_context(session1)
_eq(conv_ctx, conv_ctx2, "session_memory_to_conversation_context is deterministic")


# ===========================================================================
# §26  Fingerprint sensitivity
# ===========================================================================
print("§26  Fingerprint sensitivity ...")

# Adding a memory changes the fingerprint
sess_base    = build_session_memory(_CONV_ID, _TS, _TS, _INV_ID, memories=[entry1])
sess_plus    = build_session_memory(_CONV_ID, _TS, _TS, _INV_ID, memories=[entry1, entry2])
_ne(sess_base.memoryFingerprint, sess_plus.memoryFingerprint,
    "adding a memory changes fingerprint")

# Adding a summary changes the fingerprint
sess_no_summ  = build_session_memory(_CONV_ID, _TS, _TS, _INV_ID, memories=[entry1])
sess_with_summ = build_session_memory(_CONV_ID, _TS, _TS, _INV_ID,
                                      memories=[entry1], summaries=[summary1])
_ne(sess_no_summ.memoryFingerprint, sess_with_summ.memoryFingerprint,
    "adding a summary changes fingerprint")

# Same sessionKey regardless of timestamps (sessionKey depends only on conv+inv)
sess_ts_a = build_session_memory(_CONV_ID, _TS,  _TS2, _INV_ID)
sess_ts_b = build_session_memory(_CONV_ID, _TS2, _TS3, _INV_ID)
_eq(sess_ts_a.sessionKey, sess_ts_b.sessionKey,
    "sessionKey independent of timestamps")
_eq(sess_ts_a.sessionId,  sess_ts_b.sessionId,
    "sessionId independent of timestamps")

# Fingerprint includes all memory keys
entry_a = build_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, "A", "Alpha", _TS)
entry_b = build_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, "B", "Beta",  _TS)
sess_ab = build_session_memory(_CONV_ID, _TS, _TS, memories=[entry_a, entry_b])
sess_ba = build_session_memory(_CONV_ID, _TS, _TS, memories=[entry_b, entry_a])
_eq(sess_ab.memoryFingerprint, sess_ba.memoryFingerprint,
    "fingerprint order-independent (sorted keys)")


# ===========================================================================
# §27  MemoryEntry content length variants
# ===========================================================================
print("§27  Content length variants ...")

# Very long content — key uses content[:64]
long_content = "X" * 1000
entry_long = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.LONG_TERM, "Long Content", long_content, _TS,
)
_is(entry_long, MemoryEntry, "long content entry builds fine")
_eq(entry_long.content, long_content, "full long content stored")

# Key anchored on first 64 chars
entry_same_prefix = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.LONG_TERM, "Long Content", "X" * 64 + "different suffix", _TS,
)
# They share the same first 64 chars of content, same title, same type, same conv
_eq(entry_long.memoryKey, entry_same_prefix.memoryKey,
    "memoryKey anchored on content[:64] — same prefix -> same key")

# Different first 64 chars -> different key
entry_diff_prefix = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.LONG_TERM, "Long Content", "Y" * 64, _TS,
)
_ne(entry_long.memoryKey, entry_diff_prefix.memoryKey,
    "different first 64 chars -> different memoryKey")


# ===========================================================================
# §28  Multiple investigation IDs
# ===========================================================================
print("§28  Multiple investigation IDs ...")

sess_inv1 = build_session_memory(_CONV_ID, _TS, _TS, investigation_id="inv-001")
sess_inv2 = build_session_memory(_CONV_ID, _TS, _TS, investigation_id="inv-002")
sess_inv3 = build_session_memory(_CONV_ID, _TS, _TS, investigation_id="inv-001")

_ne(sess_inv1.sessionId,  sess_inv2.sessionId,  "different inv -> different sessionId")
_ne(sess_inv1.sessionKey, sess_inv2.sessionKey, "different inv -> different sessionKey")
_eq(sess_inv1.sessionId,  sess_inv3.sessionId,  "same inputs -> same sessionId")
_eq(sess_inv1.sessionKey, sess_inv3.sessionKey, "same inputs -> same sessionKey")


# ===========================================================================
# §29  MemoryEntry metadata mutability guard
# ===========================================================================
print("§29  Metadata mutability guard ...")

# Mutating the original dict AFTER build should NOT affect the entry
original_meta = {"key": "value", "count": 1}
entry_meta = build_memory_entry(
    _CONV_ID, MemoryTypeEnum.SHORT_TERM, "Meta Test", "Content", _TS,
    metadata=original_meta,
)
original_meta["injected"] = "evil"
_ni("injected", entry_meta.metadata, "post-build mutation of source dict does not affect entry")


# ===========================================================================
# §30  build_memory_statistics — single session
# ===========================================================================
print("§30  Statistics single session ...")

sess_single = build_session_memory(
    _CONV_ID, _TS, _TS, _INV_ID,
    memories=[
        build_memory_entry(_CONV_ID, MemoryTypeEnum.SHORT_TERM, "S1", "c", _TS,
                           importance_score=0.8, confidence=0.9),
        build_memory_entry(_CONV_ID, MemoryTypeEnum.LONG_TERM,  "S2", "c", _TS2,
                           importance_score=0.4, confidence=0.6),
    ],
)
stats_single = build_memory_statistics([sess_single])
_eq(stats_single.totalSessions,  1, "single session totalSessions=1")
_eq(stats_single.totalMemories,  2, "single session totalMemories=2")
_eq(stats_single.activeMemories, 2, "both entries are ACTIVE")
# Average importance = (0.8 + 0.4) / 2 = 0.6
_eq(round(stats_single.averageImportance, 4), 0.6, "averageImportance=0.6")
# Average confidence = (0.9 + 0.6) / 2 = 0.75
_eq(round(stats_single.averageConfidence, 4), 0.75, "averageConfidence=0.75")


# ===========================================================================
# §31  Nested model access
# ===========================================================================
print("§31  Nested model access ...")

# Access session memories' sub-fields
_eq(session1.memories[0].conversationId, _CONV_ID, "nested memory conversationId accessible")
_is(session1.memories[0].tags,   tuple, "nested memory tags is tuple")
_is(session1.memories[0].metadata, dict, "nested memory metadata is dict")
_is(session1.summaries[0].coveredMemoryIds, tuple, "nested summary coveredMemoryIds is tuple")

# Summary references are intact
_eq(session1.summaries[0].conversationId, _CONV_ID, "nested summary conversationId accessible")
_gt(session1.summaries[0].tokenEstimate, 0, "nested summary tokenEstimate > 0")


# ===========================================================================
# §32  Cross-field collision prevention
# ===========================================================================
print("§32  Cross-field collision prevention ...")

# SHA-256 null-byte separation prevents "conv" + "idtitle" == "convid" + "title"
key_a = _sha256_32("conv", "id", "title", "SHORT_TERM")
key_b = _sha256_32("convid", "title", "SHORT_TERM", "")
_ne(key_a, key_b, "null-byte separation prevents cross-field hash collision")

# Different types with same title/content get different keys
mk_short = _compute_memory_key(_CONV_ID, "SHORT_TERM",  "Same Title", "Same Content")
mk_long  = _compute_memory_key(_CONV_ID, "LONG_TERM",   "Same Title", "Same Content")
mk_summ  = _compute_memory_key(_CONV_ID, "SUMMARY",     "Same Title", "Same Content")
mk_epis  = _compute_memory_key(_CONV_ID, "EPISODIC",    "Same Title", "Same Content")
mk_inv   = _compute_memory_key(_CONV_ID, "INVESTIGATION","Same Title","Same Content")
all_keys = {mk_short, mk_long, mk_summ, mk_epis, mk_inv}
_eq(len(all_keys), 5, "all 5 memory types produce distinct keys for same title+content")


# ===========================================================================
# §33  Summary coveredMemoryIds deduplication
# ===========================================================================
print("§33  Summary coveredMemoryIds deduplication ...")

# Duplicate IDs are deduplicated and sorted
summ_dup_ids = build_memory_summary(
    _CONV_ID, "Dedup summary",
    [entry1.memoryId, entry1.memoryId, entry2.memoryId, entry2.memoryId],
    _TS,
)
_eq(summ_dup_ids.coveredMemoryIds,
    tuple(sorted({entry1.memoryId, entry2.memoryId})),
    "duplicate coveredMemoryIds deduplicated and sorted")


# ===========================================================================
# §34  All model fields present in model_dump output
# ===========================================================================
print("§34  All model fields in dict output ...")

MEMORY_ENTRY_FIELDS = {
    "memoryId", "memoryKey", "conversationId", "investigationId",
    "memoryType", "state", "title", "content", "importanceScore",
    "confidence", "sourceId", "tags", "metadata", "createdAt",
}
entry_keys = set(entry1.model_dump().keys())
for field in MEMORY_ENTRY_FIELDS:
    _in(field, entry_keys, f"MemoryEntry field '{field}' present in model_dump")

MEMORY_SUMMARY_FIELDS = {
    "summaryId", "summaryKey", "conversationId", "summary",
    "coveredMemoryIds", "tokenEstimate", "createdAt",
}
summ_keys = set(summary1.model_dump().keys())
for field in MEMORY_SUMMARY_FIELDS:
    _in(field, summ_keys, f"MemorySummary field '{field}' present in model_dump")

SESSION_MEMORY_FIELDS = {
    "sessionId", "sessionKey", "conversationId", "investigationId",
    "memories", "summaries", "memoryFingerprint", "createdAt", "updatedAt",
}
sess_keys = set(session1.model_dump().keys())
for field in SESSION_MEMORY_FIELDS:
    _in(field, sess_keys, f"SessionMemory field '{field}' present in model_dump")

STATS_FIELDS = {
    "totalSessions", "totalMemories", "activeMemories", "archivedMemories",
    "compressedMemories", "expiredMemories", "averageImportance", "averageConfidence",
}
stats_keys = set(stats.model_dump().keys())
for field in STATS_FIELDS:
    _in(field, stats_keys, f"MemoryStatistics field '{field}' present in model_dump")


# ===========================================================================
# Extended imports — Part B operations
# ===========================================================================
from services.session_memory_service import (
    # Lifecycle
    add_memory, update_memory, delete_memory,
    archive_memory, compress_memory, expire_memory,
    # Summary operations
    create_summary, rebuild_summary, merge_summaries, find_summary,
    # Retrieval
    retrieve_recent_memories, retrieve_by_importance,
    retrieve_by_tags, retrieve_by_type,
    # Memory utilities
    sort_memories, filter_memories, group_memories, find_memory,
    # Session utilities
    sort_sessions, filter_sessions, group_sessions, find_session,
)

# ---------------------------------------------------------------------------
# Shared fixtures for Part B
# ---------------------------------------------------------------------------
_TS4 = "2026-07-01T15:00:00Z"
_TS5 = "2026-07-01T16:00:00Z"
_TS6 = "2026-07-01T17:00:00Z"

def _make_entry(title, content, created_at=_TS,
                conv_id=_CONV_ID, inv_id=_INV_ID,
                mtype=MemoryTypeEnum.SHORT_TERM,
                state=MemoryStateEnum.ACTIVE,
                importance=0.5, confidence=0.8,
                tags=None):
    return build_memory_entry(
        conv_id, mtype, title, content, created_at,
        investigation_id=inv_id, state=state,
        importance_score=importance, confidence=confidence,
        tags=tags or [],
    )

def _make_base_session():
    """Fresh 3-entry session used across Part B sections."""
    e1 = _make_entry("Alpha", "alpha content", _TS,  importance=0.9, tags=["net","scan"])
    e2 = _make_entry("Beta",  "beta content",  _TS2, importance=0.6, tags=["net"])
    e3 = _make_entry("Gamma", "gamma content", _TS3, importance=0.3, tags=["host"])
    return build_session_memory(_CONV_ID, _TS, _TS, _INV_ID, memories=[e1, e2, e3])


# ===========================================================================
# §36  add_memory — basic
# ===========================================================================
print("§36  add_memory basic ...")

_base = _make_base_session()
_new_e = _make_entry("Delta", "delta content", _TS4, importance=0.7, tags=["scan"])
_sess_added = add_memory(_base, _new_e, _TS4)

_is(_sess_added, SessionMemory, "add_memory returns SessionMemory")
_eq(len(_sess_added.memories), 4, "add_memory: session now has 4 memories")
_eq(_sess_added.updatedAt, _TS4, "add_memory: updatedAt updated")
# Base session unchanged (immutability)
_eq(len(_base.memories), 3, "add_memory: original session unchanged")
# New fingerprint differs
_ne(_sess_added.memoryFingerprint, _base.memoryFingerprint,
    "add_memory: fingerprint changes after addition")
# New entry is present
found = find_memory(_sess_added, _new_e.memoryId)
_true(found is not None, "add_memory: new entry findable by id")
_eq(found.title, "Delta", "add_memory: new entry title correct")

# Idempotent re-add: adding same entry again replaces it
_sess_readd = add_memory(_sess_added, _new_e, _TS5)
_eq(len(_sess_readd.memories), 4, "add_memory: re-adding same entry does not duplicate")


# ===========================================================================
# §37  add_memory — sort order preserved
# ===========================================================================
print("§37  add_memory sort order ...")

_sorted_check = add_memory(_make_base_session(),
                           _make_entry("Early-Insert", "e", _TS), _TS)
# The new entry has _TS as createdAt — it tie-breaks with existing _TS entry by memoryId
_is(_sorted_check.memories, tuple, "memories remain tuple after add")
# Verify sorted: each entry's createdAt <= next entry's createdAt
for i in range(len(_sorted_check.memories) - 1):
    _le(_sorted_check.memories[i].createdAt, _sorted_check.memories[i + 1].createdAt,
        f"sort order preserved at position {i}")


# ===========================================================================
# §38  update_memory
# ===========================================================================
print("§38  update_memory ...")

_base2 = _make_base_session()
_first_id = _base2.memories[0].memoryId

# Update title only
_sess_upd = update_memory(_base2, _first_id, _TS4, title="Alpha-Renamed")
_eq(len(_sess_upd.memories), 3, "update_memory: count unchanged")
_eq(_sess_upd.updatedAt, _TS4, "update_memory: updatedAt updated")
# Original session unchanged
_eq(_base2.memories[0].title, "Alpha", "update_memory: original session unchanged")
# Find updated entry (note: key changes because title changed)
renamed = next((m for m in _sess_upd.memories if m.title == "Alpha-Renamed"), None)
_true(renamed is not None, "update_memory: renamed entry found")

# Update importance
_sess_imp = update_memory(_base2, _first_id, _TS4, importance_score=0.1)
upd_entry = next((m for m in _sess_imp.memories if m.importanceScore == 0.1), None)
_true(upd_entry is not None, "update_memory: importanceScore updated")

# Update tags
_sess_tags = update_memory(_base2, _first_id, _TS4, tags=["new-tag", "net"])
upd_tagged = next((m for m in _sess_tags.memories
                   if "new-tag" in m.tags), None)
_true(upd_tagged is not None, "update_memory: tags updated")
_in("net", upd_tagged.tags, "update_memory: existing tag retained")

# Update metadata
_sess_meta = update_memory(_base2, _first_id, _TS4, metadata={"analyst": "bob"})
upd_meta_entry = next((m for m in _sess_meta.memories
                       if m.metadata.get("analyst") == "bob"), None)
_true(upd_meta_entry is not None, "update_memory: metadata updated")

# Update confidence (clamped)
_sess_conf = update_memory(_base2, _first_id, _TS4, confidence=1.5)
upd_conf_entry = next((m for m in _sess_conf.memories
                       if m.confidence == 1.0), None)
_true(upd_conf_entry is not None, "update_memory: confidence clamped to 1.0")

# Missing memory_id raises KeyError
_raised = False
try:
    update_memory(_base2, "nonexistent-id", _TS4, title="X")
except KeyError:
    _raised = True
_true(_raised, "update_memory: raises KeyError for unknown id")

# Deterministic: same update twice produces same result
_upd_a = update_memory(_base2, _first_id, _TS4, title="Alpha-Same")
_upd_b = update_memory(_base2, _first_id, _TS4, title="Alpha-Same")
_eq(_upd_a.memoryFingerprint, _upd_b.memoryFingerprint,
    "update_memory: deterministic fingerprint")


# ===========================================================================
# §39  delete_memory
# ===========================================================================
print("§39  delete_memory ...")

_base3 = _make_base_session()
_del_id = _base3.memories[1].memoryId
_sess_del = delete_memory(_base3, _del_id, _TS4)

_is(_sess_del, SessionMemory, "delete_memory returns SessionMemory")
_eq(len(_sess_del.memories), 2, "delete_memory: one entry removed")
_eq(_sess_del.updatedAt, _TS4, "delete_memory: updatedAt updated")
# Entry is gone
_true(find_memory(_sess_del, _del_id) is None, "delete_memory: entry no longer findable")
# Original session unchanged
_eq(len(_base3.memories), 3, "delete_memory: original session unchanged")
# Fingerprint changed
_ne(_sess_del.memoryFingerprint, _base3.memoryFingerprint,
    "delete_memory: fingerprint changed after deletion")

# Missing id raises KeyError
_raised = False
try:
    delete_memory(_base3, "nonexistent-id", _TS4)
except KeyError:
    _raised = True
_true(_raised, "delete_memory: raises KeyError for unknown id")

# Delete all entries
_sess_empty = _make_base_session()
for m in list(_sess_empty.memories):
    _sess_empty = delete_memory(_sess_empty, m.memoryId, _TS4)
_eq(len(_sess_empty.memories), 0, "delete_memory: can delete all entries")


# ===========================================================================
# §40  archive_memory / compress_memory / expire_memory
# ===========================================================================
print("§40  lifecycle state transitions ...")

_base4 = _make_base_session()
_m0_id = _base4.memories[0].memoryId
_m1_id = _base4.memories[1].memoryId
_m2_id = _base4.memories[2].memoryId

# Archive
_sess_arch = archive_memory(_base4, _m0_id, _TS4)
arch_entry = find_memory(_sess_arch, _m0_id)
_eq(arch_entry.state, MemoryStateEnum.ARCHIVED, "archive_memory: state is ARCHIVED")
_eq(_sess_arch.updatedAt, _TS4, "archive_memory: updatedAt updated")
# Other entries unchanged
_eq(find_memory(_sess_arch, _m1_id).state, MemoryStateEnum.ACTIVE,
    "archive_memory: other entries remain ACTIVE")
# Original unchanged
_eq(find_memory(_base4, _m0_id).state, MemoryStateEnum.ACTIVE,
    "archive_memory: original session unchanged")

# Compress
_sess_comp = compress_memory(_base4, _m1_id, _TS4)
comp_entry = find_memory(_sess_comp, _m1_id)
_eq(comp_entry.state, MemoryStateEnum.COMPRESSED, "compress_memory: state is COMPRESSED")
_eq(_sess_comp.updatedAt, _TS4, "compress_memory: updatedAt updated")

# Expire
_sess_exp = expire_memory(_base4, _m2_id, _TS4)
exp_entry = find_memory(_sess_exp, _m2_id)
_eq(exp_entry.state, MemoryStateEnum.EXPIRED, "expire_memory: state is EXPIRED")
_eq(_sess_exp.updatedAt, _TS4, "expire_memory: updatedAt updated")

# Chained transitions: active -> archive -> compress
_sess_chain = archive_memory(_base4, _m0_id, _TS4)
_sess_chain = compress_memory(_sess_chain, _m0_id, _TS5)
chain_entry = find_memory(_sess_chain, _m0_id)
_eq(chain_entry.state, MemoryStateEnum.COMPRESSED,
    "lifecycle chain: active->archive->compress ends in COMPRESSED")

# Fingerprint changes on add/lifecycle — note: state transitions do NOT change
# the memoryKey (key is based on title/content/type, not state), so the
# fingerprint is the same before and after a pure state transition.
# This is correct by design — the fingerprint tracks content identity, not state.
_eq(_base4.memoryFingerprint, _sess_arch.memoryFingerprint,
    "archive_memory: fingerprint stable (state not in key)")
_eq(_base4.memoryFingerprint, _sess_comp.memoryFingerprint,
    "compress_memory: fingerprint stable (state not in key)")
_eq(_base4.memoryFingerprint, _sess_exp.memoryFingerprint,
    "expire_memory: fingerprint stable (state not in key)")

# Missing id raises KeyError for all transitions
for fn, label in [(archive_memory, "archive"), (compress_memory, "compress"),
                  (expire_memory, "expire")]:
    _raised = False
    try:
        fn(_base4, "bad-id", _TS4)
    except KeyError:
        _raised = True
    _true(_raised, f"{label}_memory raises KeyError for unknown id")

# Transitions are deterministic
_arch_a = archive_memory(_base4, _m0_id, _TS4)
_arch_b = archive_memory(_base4, _m0_id, _TS4)
_eq(_arch_a.memoryFingerprint, _arch_b.memoryFingerprint,
    "archive_memory: deterministic fingerprint")


# ===========================================================================
# §41  create_summary / find_summary
# ===========================================================================
print("§41  create_summary / find_summary ...")

_base5 = _make_base_session()
_mem_ids = [m.memoryId for m in _base5.memories]

_sess_s1 = create_summary(_base5, "Incident summary: three events observed.",
                           _mem_ids, _TS4, _TS4)

_is(_sess_s1, SessionMemory, "create_summary returns SessionMemory")
_eq(len(_sess_s1.summaries), 1, "create_summary: one summary added")
_eq(_sess_s1.updatedAt, _TS4, "create_summary: updatedAt updated")
# Original unchanged
_eq(len(_base5.summaries), 0, "create_summary: original session unchanged")
# Fingerprint changed
_ne(_sess_s1.memoryFingerprint, _base5.memoryFingerprint,
    "create_summary: fingerprint changed")
# find_summary
found_s = find_summary(_sess_s1, _sess_s1.summaries[0].summaryId)
_true(found_s is not None, "find_summary: finds existing summary")
_eq(found_s.summary, "Incident summary: three events observed.", "find_summary: correct content")
# Not found returns None
_true(find_summary(_sess_s1, "nonexistent-id") is None, "find_summary: returns None for unknown id")

# Idempotent re-create (same key) does not duplicate
_sess_s1b = create_summary(_sess_s1, "Incident summary: three events observed.",
                            _mem_ids, _TS4, _TS5)
_eq(len(_sess_s1b.summaries), 1, "create_summary: idempotent — no duplicate")

# Validation enforced
_raised = False
try:
    create_summary(_base5, "", _mem_ids, _TS4, _TS4)
except Exception:
    _raised = True
_true(_raised, "create_summary: raises on empty summary text")


# ===========================================================================
# §42  rebuild_summary
# ===========================================================================
print("§42  rebuild_summary ...")

_sid = _sess_s1.summaries[0].summaryId
_sess_rebuilt = rebuild_summary(_sess_s1, _sid, "Rebuilt summary text.", _TS5)

_is(_sess_rebuilt, SessionMemory, "rebuild_summary returns SessionMemory")
_eq(len(_sess_rebuilt.summaries), 1, "rebuild_summary: still one summary")
_eq(_sess_rebuilt.updatedAt, _TS5, "rebuild_summary: updatedAt updated")
# New summary has the new text
_eq(_sess_rebuilt.summaries[0].summary, "Rebuilt summary text.",
    "rebuild_summary: summary text updated")
# Covered IDs preserved
_eq(
    set(_sess_rebuilt.summaries[0].coveredMemoryIds),
    set(_sess_s1.summaries[0].coveredMemoryIds),
    "rebuild_summary: coveredMemoryIds preserved",
)
# Original unchanged
_eq(_sess_s1.summaries[0].summary, "Incident summary: three events observed.",
    "rebuild_summary: original session unchanged")

# Deterministic
_reb_a = rebuild_summary(_sess_s1, _sid, "Same new text", _TS5)
_reb_b = rebuild_summary(_sess_s1, _sid, "Same new text", _TS5)
_eq(_reb_a.memoryFingerprint, _reb_b.memoryFingerprint,
    "rebuild_summary: deterministic fingerprint")

# Missing id raises KeyError
_raised = False
try:
    rebuild_summary(_sess_s1, "bad-id", "text", _TS5)
except KeyError:
    _raised = True
_true(_raised, "rebuild_summary: raises KeyError for unknown id")


# ===========================================================================
# §43  merge_summaries
# ===========================================================================
print("§43  merge_summaries ...")

# Create two summaries to merge
_base6 = _make_base_session()
_ids_a  = [_base6.memories[0].memoryId]
_ids_b  = [_base6.memories[1].memoryId, _base6.memories[2].memoryId]
_sess_two = create_summary(_base6, "Summary A", _ids_a, _TS4, _TS4)
_sess_two = create_summary(_sess_two, "Summary B", _ids_b, _TS4, _TS4)
_eq(len(_sess_two.summaries), 2, "setup: two summaries created")

_sA_id = _sess_two.summaries[0].summaryId
_sB_id = _sess_two.summaries[1].summaryId

_sess_merged = merge_summaries(_sess_two, [_sA_id, _sB_id],
                                "Merged summary covering all events.", _TS5, _TS5)

_is(_sess_merged, SessionMemory, "merge_summaries returns SessionMemory")
_eq(len(_sess_merged.summaries), 1, "merge_summaries: two summaries collapsed to one")
_eq(_sess_merged.updatedAt, _TS5, "merge_summaries: updatedAt updated")
# Merged summary covers all IDs
merged_covered = set(_sess_merged.summaries[0].coveredMemoryIds)
expected_covered = {_base6.memories[0].memoryId, _base6.memories[1].memoryId,
                    _base6.memories[2].memoryId}
_eq(merged_covered, expected_covered, "merge_summaries: union of all coveredMemoryIds")
# Original unchanged
_eq(len(_sess_two.summaries), 2, "merge_summaries: original session unchanged")

# Empty summary_ids raises ValueError
_raised = False
try:
    merge_summaries(_sess_two, [], "text", _TS5, _TS5)
except ValueError:
    _raised = True
_true(_raised, "merge_summaries: raises ValueError for empty summary_ids")

# Unknown summary_id raises KeyError
_raised = False
try:
    merge_summaries(_sess_two, ["bad-id"], "text", _TS5, _TS5)
except KeyError:
    _raised = True
_true(_raised, "merge_summaries: raises KeyError for unknown summary_id")


# ===========================================================================
# §44  retrieve_recent_memories
# ===========================================================================
print("§44  retrieve_recent_memories ...")

# Base session has Alpha@_TS, Beta@_TS2, Gamma@_TS3 (all ACTIVE)
_base7 = _make_base_session()
recent = retrieve_recent_memories(_base7, limit=2)
_is(recent, tuple, "retrieve_recent_memories returns tuple")
_eq(len(recent), 2, "retrieve_recent_memories: limit=2 returns 2")
# Most recent first
_eq(recent[0].createdAt, _TS3, "retrieve_recent_memories: first is most recent")
_eq(recent[1].createdAt, _TS2, "retrieve_recent_memories: second is middle")

# With no ACTIVE entries
_empty_sess = build_session_memory(_CONV_ID, _TS, _TS)
_eq(len(retrieve_recent_memories(_empty_sess)), 0,
    "retrieve_recent_memories: empty session returns empty tuple")

# Archived entries excluded
_with_arch = archive_memory(_base7, _base7.memories[0].memoryId, _TS4)
recent_arch = retrieve_recent_memories(_with_arch, limit=10)
for m in recent_arch:
    _ne(m.state, MemoryStateEnum.ARCHIVED, "retrieve_recent_memories: no ARCHIVED entries")

# Limit clamped to >= 1
_eq(len(retrieve_recent_memories(_base7, limit=0)), 1,
    "retrieve_recent_memories: limit=0 clamped to 1")

# Deterministic
r1 = retrieve_recent_memories(_base7, limit=3)
r2 = retrieve_recent_memories(_base7, limit=3)
_eq(r1, r2, "retrieve_recent_memories: deterministic")


# ===========================================================================
# §45  retrieve_by_importance
# ===========================================================================
print("§45  retrieve_by_importance ...")

_base8 = _make_base_session()  # Alpha=0.9, Beta=0.6, Gamma=0.3
imp_all = retrieve_by_importance(_base8, min_importance=0.0, limit=10)
_eq(len(imp_all), 3, "retrieve_by_importance: all entries above 0.0")
# First has highest importance
_ge(imp_all[0].importanceScore, imp_all[1].importanceScore,
    "retrieve_by_importance: descending order")
_ge(imp_all[1].importanceScore, imp_all[2].importanceScore,
    "retrieve_by_importance: descending order 2")

# Filter by threshold
imp_high = retrieve_by_importance(_base8, min_importance=0.7)
_eq(len(imp_high), 1, "retrieve_by_importance: only Alpha >= 0.7")
_eq(imp_high[0].title, "Alpha", "retrieve_by_importance: correct entry returned")

# Ascending
imp_asc = retrieve_by_importance(_base8, min_importance=0.0, limit=3, descending=False)
_le(imp_asc[0].importanceScore, imp_asc[1].importanceScore,
    "retrieve_by_importance: ascending order")

# Limit
imp_limited = retrieve_by_importance(_base8, min_importance=0.0, limit=2)
_eq(len(imp_limited), 2, "retrieve_by_importance: limit=2 respected")

# Deterministic
ri1 = retrieve_by_importance(_base8)
ri2 = retrieve_by_importance(_base8)
_eq(ri1, ri2, "retrieve_by_importance: deterministic")


# ===========================================================================
# §46  retrieve_by_tags
# ===========================================================================
print("§46  retrieve_by_tags ...")

# Alpha has ["net","scan"], Beta has ["net"], Gamma has ["host"]
_base9 = _make_base_session()
by_net = retrieve_by_tags(_base9, ["net"])
_eq(len(by_net), 2, "retrieve_by_tags: 'net' matches Alpha and Beta")
by_scan = retrieve_by_tags(_base9, ["scan"])
_eq(len(by_scan), 1, "retrieve_by_tags: 'scan' matches only Alpha")
_eq(by_scan[0].title, "Alpha", "retrieve_by_tags: correct entry")

# OR logic (default)
by_net_or_host = retrieve_by_tags(_base9, ["net", "host"])
_eq(len(by_net_or_host), 3, "retrieve_by_tags: OR logic matches all 3")

# AND logic
by_net_and_scan = retrieve_by_tags(_base9, ["net", "scan"], match_all=True)
_eq(len(by_net_and_scan), 1, "retrieve_by_tags: AND logic matches only Alpha")

# Case-insensitive
by_upper = retrieve_by_tags(_base9, ["NET"])
_eq(len(by_upper), 2, "retrieve_by_tags: case-insensitive matching")

# No match
by_none = retrieve_by_tags(_base9, ["nomatch"])
_eq(len(by_none), 0, "retrieve_by_tags: no match returns empty tuple")

# Empty tags list returns empty
by_empty_tags = retrieve_by_tags(_base9, [])
_eq(len(by_empty_tags), 0, "retrieve_by_tags: empty tags list returns empty")

# Sorted by importance DESC
by_net_sorted = retrieve_by_tags(_base9, ["net"])
_ge(by_net_sorted[0].importanceScore, by_net_sorted[1].importanceScore,
    "retrieve_by_tags: sorted by importance DESC")

# Deterministic
rt1 = retrieve_by_tags(_base9, ["net"])
rt2 = retrieve_by_tags(_base9, ["net"])
_eq(rt1, rt2, "retrieve_by_tags: deterministic")


# ===========================================================================
# §47  retrieve_by_type
# ===========================================================================
print("§47  retrieve_by_type ...")

_base10 = _make_base_session()  # all SHORT_TERM
by_short = retrieve_by_type(_base10, MemoryTypeEnum.SHORT_TERM)
_eq(len(by_short), 3, "retrieve_by_type: all 3 are SHORT_TERM")

# Add a LONG_TERM entry
_lt_entry = _make_entry("LT-Entry", "long term", _TS4,
                         mtype=MemoryTypeEnum.LONG_TERM)
_base10b = add_memory(_base10, _lt_entry, _TS4)
by_long = retrieve_by_type(_base10b, MemoryTypeEnum.LONG_TERM)
_eq(len(by_long), 1, "retrieve_by_type: one LONG_TERM entry")
_eq(by_long[0].title, "LT-Entry", "retrieve_by_type: correct entry")

# No match returns empty
by_epis = retrieve_by_type(_base10, MemoryTypeEnum.EPISODIC)
_eq(len(by_epis), 0, "retrieve_by_type: no EPISODIC entries")

# Sorted by (createdAt, memoryId)
by_short_sorted = retrieve_by_type(_base10b, MemoryTypeEnum.SHORT_TERM)
for i in range(len(by_short_sorted) - 1):
    _le(by_short_sorted[i].createdAt, by_short_sorted[i + 1].createdAt,
        f"retrieve_by_type: sort order at position {i}")

# Deterministic
_eq(retrieve_by_type(_base10, MemoryTypeEnum.SHORT_TERM),
    retrieve_by_type(_base10, MemoryTypeEnum.SHORT_TERM),
    "retrieve_by_type: deterministic")


# ===========================================================================
# §48  sort_memories
# ===========================================================================
print("§48  sort_memories ...")

_base11 = _make_base_session()
mems = list(_base11.memories)

# By createdAt ASC (default)
s_cat = sort_memories(mems, key="createdAt", ascending=True)
_eq(s_cat[0].createdAt, _TS,  "sort createdAt ASC: first is earliest")
_eq(s_cat[-1].createdAt, _TS3, "sort createdAt ASC: last is latest")

# By createdAt DESC
s_cat_d = sort_memories(mems, key="createdAt", ascending=False)
_eq(s_cat_d[0].createdAt, _TS3, "sort createdAt DESC: first is latest")

# By importanceScore DESC (Alpha=0.9 first)
s_imp = sort_memories(mems, key="importanceScore", ascending=False)
_eq(s_imp[0].title, "Alpha", "sort importanceScore DESC: Alpha first")
_eq(s_imp[-1].title, "Gamma", "sort importanceScore DESC: Gamma last")

# By importanceScore ASC
s_imp_a = sort_memories(mems, key="importanceScore", ascending=True)
_eq(s_imp_a[0].title, "Gamma", "sort importanceScore ASC: Gamma first")

# By title ASC
s_title = sort_memories(mems, key="title", ascending=True)
_eq(s_title[0].title, "Alpha", "sort title ASC: Alpha first")
_eq(s_title[-1].title, "Gamma", "sort title ASC: Gamma last")

# By state ASC
s_state = sort_memories(mems, key="state")
_is(s_state, list, "sort_memories returns list")

# By confidence ASC
s_conf = sort_memories(mems, key="confidence", ascending=True)
_is(s_conf, list, "sort confidence returns list")

# Input not mutated
_eq([m.title for m in mems], ["Alpha", "Beta", "Gamma"],
    "sort_memories: input list not mutated")

# Invalid key raises ValueError
_raised = False
try:
    sort_memories(mems, key="invalid_key")
except ValueError:
    _raised = True
_true(_raised, "sort_memories: raises ValueError for invalid key")

# Deterministic
_eq(sort_memories(mems, "importanceScore", False),
    sort_memories(mems, "importanceScore", False),
    "sort_memories: deterministic")


# ===========================================================================
# §49  filter_memories
# ===========================================================================
print("§49  filter_memories ...")

# Base: Alpha=SHORT_TERM/ACTIVE/0.9, Beta=SHORT_TERM/ACTIVE/0.6, Gamma=SHORT_TERM/ACTIVE/0.3
_base12 = _make_base_session()
mems12 = list(_base12.memories)

# Filter by type
f_type = filter_memories(mems12, memory_type=MemoryTypeEnum.SHORT_TERM)
_eq(len(f_type), 3, "filter_memories by type: all 3")

# Filter by state
f_state = filter_memories(mems12, state=MemoryStateEnum.ACTIVE)
_eq(len(f_state), 3, "filter_memories by state ACTIVE: all 3")

# Filter by min_importance
f_imp = filter_memories(mems12, min_importance=0.7)
_eq(len(f_imp), 1, "filter_memories min_importance=0.7: only Alpha")
_eq(f_imp[0].title, "Alpha", "filter_memories min_importance: correct entry")

# Filter by max_importance
f_max = filter_memories(mems12, max_importance=0.5)
_eq(len(f_max), 1, "filter_memories max_importance=0.5: only Gamma")

# Filter by tags (OR)
f_tags = filter_memories(mems12, tags=["scan"])
_eq(len(f_tags), 1, "filter_memories by tags ['scan']: only Alpha")

# Filter by conversation_id
f_conv = filter_memories(mems12, conversation_id=_CONV_ID)
_eq(len(f_conv), 3, "filter_memories by conversation_id: all 3")
f_conv_none = filter_memories(mems12, conversation_id="other-conv")
_eq(len(f_conv_none), 0, "filter_memories by wrong conversation_id: 0")

# Filter by investigation_id
f_inv = filter_memories(mems12, investigation_id=_INV_ID)
_eq(len(f_inv), 3, "filter_memories by investigation_id: all 3")

# Combined filters
f_combined = filter_memories(mems12, min_importance=0.5, tags=["net"])
_eq(len(f_combined), 2, "filter_memories combined min_imp + tag: Alpha and Beta")

# No criteria returns all
f_all = filter_memories(mems12)
_eq(len(f_all), 3, "filter_memories no criteria: all 3")

# Input not mutated
_eq(len(mems12), 3, "filter_memories: input not mutated")

# Deterministic
_eq(filter_memories(mems12, min_importance=0.5),
    filter_memories(mems12, min_importance=0.5),
    "filter_memories: deterministic")


# ===========================================================================
# §50  group_memories
# ===========================================================================
print("§50  group_memories ...")

_base13 = _make_base_session()
# Add a LONG_TERM entry and an ARCHIVED entry
_lt_e = _make_entry("LT", "lt", _TS4, mtype=MemoryTypeEnum.LONG_TERM)
_arch_e_base = _make_entry("Arch", "arch", _TS5, state=MemoryStateEnum.ARCHIVED)
_base13 = add_memory(_base13, _lt_e, _TS4)
_base13 = add_memory(_base13, _arch_e_base, _TS5)
mems13 = list(_base13.memories)

# Group by memoryType
g_type = group_memories(mems13, group_by="memoryType")
_is(g_type, dict, "group_memories returns dict")
_in("SHORT_TERM", g_type, "SHORT_TERM group exists")
_in("LONG_TERM",  g_type, "LONG_TERM group exists")
_eq(len(g_type["SHORT_TERM"]), 4, "SHORT_TERM group has 4 entries (3 base + 1 Arch)")
_eq(len(g_type["LONG_TERM"]),  1, "LONG_TERM group has 1 entry")

# Group by state
g_state = group_memories(mems13, group_by="state")
_in("ACTIVE",   g_state, "ACTIVE state group exists")
_in("ARCHIVED", g_state, "ARCHIVED state group exists")
_eq(len(g_state["ARCHIVED"]), 1, "ARCHIVED group has 1 entry")

# Group by conversationId
g_conv = group_memories(mems13, group_by="conversationId")
_in(_CONV_ID, g_conv, "conversationId group exists")
_eq(len(g_conv[_CONV_ID]), 5, "all 5 in same conversationId group")

# Group by investigationId
g_inv = group_memories(mems13, group_by="investigationId")
_in(_INV_ID, g_inv, "investigationId group exists")

# Each group is sorted
for grp in g_type.values():
    for i in range(len(grp) - 1):
        _le(grp[i].createdAt, grp[i + 1].createdAt,
            "group_memories: each group sorted by createdAt ASC")

# Invalid key raises ValueError
_raised = False
try:
    group_memories(mems13, group_by="invalid")
except ValueError:
    _raised = True
_true(_raised, "group_memories: raises ValueError for invalid key")


# ===========================================================================
# §51  find_memory
# ===========================================================================
print("§51  find_memory ...")

_base14 = _make_base_session()
_target_id = _base14.memories[1].memoryId
found_m = find_memory(_base14, _target_id)
_true(found_m is not None, "find_memory: finds existing entry")
_eq(found_m.memoryId, _target_id, "find_memory: correct entry returned")
_eq(found_m.title, "Beta", "find_memory: correct title")

# Not found returns None
_true(find_memory(_base14, "bad-id") is None, "find_memory: returns None for unknown id")
# Empty session
_true(find_memory(build_session_memory(_CONV_ID, _TS, _TS), "any-id") is None,
      "find_memory: returns None for empty session")


# ===========================================================================
# §52  sort_sessions / filter_sessions / group_sessions / find_session
# ===========================================================================
print("§52  Session utilities ...")

# Build three distinct sessions
_s1 = build_session_memory(_CONV_ID,  _TS,  _TS2, _INV_ID,
                            memories=[_make_entry("E1","c",_TS),
                                      _make_entry("E2","c",_TS2)])
_s2 = build_session_memory(_CONV_ID2, _TS2, _TS3, "inv-002",
                            memories=[_make_entry("E3","c",_TS3,
                                                  conv_id=_CONV_ID2,
                                                  inv_id="inv-002")])
_s3 = build_session_memory(_CONV_ID,  _TS3, _TS4, _INV_ID,
                            memories=[_make_entry("E4","c",_TS4),
                                      _make_entry("E5","c",_TS5),
                                      _make_entry("E6","c",_TS6)])
_all_sessions = [_s1, _s2, _s3]

# --- sort_sessions ---
# By createdAt ASC
ss_cat = sort_sessions(_all_sessions, key="createdAt", ascending=True)
_eq(ss_cat[0].createdAt, _TS, "sort_sessions createdAt ASC: first is earliest")
_eq(ss_cat[-1].createdAt, _TS3, "sort_sessions createdAt ASC: last is latest")

# By createdAt DESC
ss_cat_d = sort_sessions(_all_sessions, key="createdAt", ascending=False)
_eq(ss_cat_d[0].createdAt, _TS3, "sort_sessions createdAt DESC: first is latest")

# By memoryCount DESC
ss_mc = sort_sessions(_all_sessions, key="memoryCount", ascending=False)
_eq(len(ss_mc[0].memories), 3, "sort_sessions memoryCount DESC: 3-memory session first")

# By updatedAt
ss_upd = sort_sessions(_all_sessions, key="updatedAt", ascending=True)
_is(ss_upd, list, "sort_sessions updatedAt returns list")

# By sessionId
ss_sid = sort_sessions(_all_sessions, key="sessionId")
_is(ss_sid, list, "sort_sessions sessionId returns list")

# Input not mutated
_eq(len(_all_sessions), 3, "sort_sessions: input not mutated")

# Invalid key raises ValueError
_raised = False
try:
    sort_sessions(_all_sessions, key="bad")
except ValueError:
    _raised = True
_true(_raised, "sort_sessions: raises ValueError for invalid key")

# Deterministic
_eq(sort_sessions(_all_sessions, "createdAt", True),
    sort_sessions(_all_sessions, "createdAt", True),
    "sort_sessions: deterministic")

# --- filter_sessions ---
# Filter by conversation_id
fs_conv = filter_sessions(_all_sessions, conversation_id=_CONV_ID)
_eq(len(fs_conv), 2, "filter_sessions by conversationId: 2 sessions")

# Filter by investigation_id
fs_inv = filter_sessions(_all_sessions, investigation_id=_INV_ID)
_eq(len(fs_inv), 2, "filter_sessions by investigationId: 2 sessions")

# Filter by min_memories
fs_min = filter_sessions(_all_sessions, min_memories=2)
_eq(len(fs_min), 2, "filter_sessions min_memories=2: 2 sessions")

# Filter by max_memories
fs_max = filter_sessions(_all_sessions, max_memories=2)
_eq(len(fs_max), 2, "filter_sessions max_memories=2: 2 sessions (1-mem and 2-mem sessions)")

# Filter by has_summaries (none have summaries)
fs_summ = filter_sessions(_all_sessions, has_summaries=True)
_eq(len(fs_summ), 0, "filter_sessions has_summaries=True: 0 (none have summaries)")
fs_no_summ = filter_sessions(_all_sessions, has_summaries=False)
_eq(len(fs_no_summ), 3, "filter_sessions has_summaries=False: all 3")

# Combined filter
fs_comb = filter_sessions(_all_sessions, conversation_id=_CONV_ID, min_memories=3)
_eq(len(fs_comb), 1, "filter_sessions combined: 1 session")

# No criteria
fs_all = filter_sessions(_all_sessions)
_eq(len(fs_all), 3, "filter_sessions no criteria: all 3")

# Input not mutated
_eq(len(_all_sessions), 3, "filter_sessions: input not mutated")

# Deterministic
_eq(filter_sessions(_all_sessions, conversation_id=_CONV_ID),
    filter_sessions(_all_sessions, conversation_id=_CONV_ID),
    "filter_sessions: deterministic")

# --- group_sessions ---
gs_inv = group_sessions(_all_sessions, group_by="investigationId")
_is(gs_inv, dict, "group_sessions returns dict")
_in(_INV_ID,    gs_inv, "investigationId group exists")
_in("inv-002", gs_inv, "inv-002 group exists")
_eq(len(gs_inv[_INV_ID]), 2, "investigationId group has 2 sessions")

gs_conv = group_sessions(_all_sessions, group_by="conversationId")
_in(_CONV_ID, gs_conv, "conversationId group exists")
_eq(len(gs_conv[_CONV_ID]), 2, "conversationId group has 2 sessions")

# Each group sorted by sessionId
for grp in gs_inv.values():
    for i in range(len(grp) - 1):
        _le(grp[i].sessionId, grp[i + 1].sessionId,
            "group_sessions: each group sorted by sessionId ASC")

# Invalid group_by raises ValueError
_raised = False
try:
    group_sessions(_all_sessions, group_by="invalid")
except ValueError:
    _raised = True
_true(_raised, "group_sessions: raises ValueError for invalid key")

# --- find_session ---
found_sess = find_session(_all_sessions, _s2.sessionId)
_true(found_sess is not None, "find_session: finds existing session")
_eq(found_sess.sessionId, _s2.sessionId, "find_session: correct session returned")
_true(find_session(_all_sessions, "bad-id") is None,
      "find_session: returns None for unknown id")
_true(find_session([], _s1.sessionId) is None,
      "find_session: returns None for empty list")


# ===========================================================================
# §53  build_memory_statistics — with lifecycle operations
# ===========================================================================
print("§53  Statistics with lifecycle operations ...")

# Build a controlled session with all four states
_stat_base = _make_base_session()
# Add entries in each state
_e_active     = _make_entry("SA", "sa", _TS,  importance=0.9, confidence=0.9)
_e_archived   = _make_entry("SB", "sb", _TS2, importance=0.6, confidence=0.7,
                             state=MemoryStateEnum.ARCHIVED)
_e_compressed = _make_entry("SC", "sc", _TS3, importance=0.4, confidence=0.5,
                             state=MemoryStateEnum.COMPRESSED)
_e_expired    = _make_entry("SD", "sd", _TS4, importance=0.2, confidence=0.3,
                             state=MemoryStateEnum.EXPIRED)

_stat_sess = build_session_memory(
    _CONV_ID, _TS, _TS, _INV_ID,
    memories=[_e_active, _e_archived, _e_compressed, _e_expired],
)
_stats_lc = build_memory_statistics([_stat_sess])

_eq(_stats_lc.totalSessions,      1, "stats with lifecycle: totalSessions=1")
_eq(_stats_lc.totalMemories,      4, "stats with lifecycle: totalMemories=4")
_eq(_stats_lc.activeMemories,     1, "stats with lifecycle: activeMemories=1")
_eq(_stats_lc.archivedMemories,   1, "stats with lifecycle: archivedMemories=1")
_eq(_stats_lc.compressedMemories, 1, "stats with lifecycle: compressedMemories=1")
_eq(_stats_lc.expiredMemories,    1, "stats with lifecycle: expiredMemories=1")

# Average importance = (0.9+0.6+0.4+0.2)/4 = 0.525
_eq(round(_stats_lc.averageImportance, 4), 0.525, "stats averageImportance=0.525")
# Average confidence = (0.9+0.7+0.5+0.3)/4 = 0.6
_eq(round(_stats_lc.averageConfidence, 4), 0.6, "stats averageConfidence=0.6")

# Lifecycle changes are reflected in statistics
_arch_sess = archive_memory(_stat_sess, _e_active.memoryId, _TS5)
_stats_post = build_memory_statistics([_arch_sess])
_eq(_stats_post.activeMemories,   0, "stats post-archive: activeMemories=0")
_eq(_stats_post.archivedMemories, 2, "stats post-archive: archivedMemories=2")

# Multiple sessions
_sess_stats2 = build_session_memory(
    _CONV_ID2, _TS, _TS,
    memories=[_make_entry("X1", "c", _TS, conv_id=_CONV_ID2, inv_id="",
                           state=MemoryStateEnum.ACTIVE, importance=1.0, confidence=1.0)],
)
_multi_stats = build_memory_statistics([_stat_sess, _sess_stats2])
_eq(_multi_stats.totalSessions, 2, "multi-session stats: totalSessions=2")
_eq(_multi_stats.totalMemories, 5, "multi-session stats: totalMemories=5")
_eq(_multi_stats.activeMemories, 2, "multi-session stats: activeMemories=2")


# ===========================================================================
# §54  Deterministic updates — full chain
# ===========================================================================
print("§54  Deterministic update chains ...")

def _build_chain(seed_ts: str) -> SessionMemory:
    """Build an identical session from scratch for determinism verification."""
    e = _make_entry("Chain-Entry", "chain content", seed_ts, importance=0.8)
    s = build_session_memory(_CONV_ID, seed_ts, seed_ts, _INV_ID, memories=[e])
    s = update_memory(s, e.memoryId, seed_ts, title="Chain-Entry-Updated")
    s = archive_memory(s, s.memories[0].memoryId, seed_ts)
    return s

c1 = _build_chain(_TS)
c2 = _build_chain(_TS)
_eq(c1.memoryFingerprint, c2.memoryFingerprint,
    "full update chain: same fingerprint when rebuilt from same inputs")
_eq(c1.sessionId, c2.sessionId,
    "full update chain: same sessionId when rebuilt from same inputs")

# Build chain — fingerprint changes at each step
s_step0 = build_session_memory(_CONV_ID, _TS, _TS, _INV_ID,
                                memories=[_make_entry("P", "p", _TS)])
s_step1 = update_memory(s_step0, s_step0.memories[0].memoryId, _TS2, content="new p")
s_step2 = archive_memory(s_step1, s_step1.memories[0].memoryId, _TS3)
s_step3 = compress_memory(s_step2, s_step2.memories[0].memoryId, _TS4)

# All four fingerprints: step0 and step1 differ (content changed), steps 1-3
# keep the same fingerprint (state transitions don't change the memoryKey).
_ne(s_step0.memoryFingerprint, s_step1.memoryFingerprint,
    "deterministic chain: content update changes fingerprint (step0 → step1)")
_eq(s_step1.memoryFingerprint, s_step2.memoryFingerprint,
    "deterministic chain: state transition preserves fingerprint (step1 → step2)")
_eq(s_step2.memoryFingerprint, s_step3.memoryFingerprint,
    "deterministic chain: state transition preserves fingerprint (step2 → step3)")

# Idempotency: applying same state-transition op twice converges
s_idem1 = archive_memory(s_step0, s_step0.memories[0].memoryId, _TS2)
s_idem2 = archive_memory(s_idem1, s_idem1.memories[0].memoryId, _TS2)
_eq(s_idem1.memoryFingerprint, s_idem2.memoryFingerprint,
    "lifecycle idempotency: archiving already-archived entry unchanged fingerprint")


# ===========================================================================
# §55  Edge cases
# ===========================================================================
print("§55  Edge cases ...")

# update_memory with NO changes (all None kwargs)
_base15 = _make_base_session()
_eid = _base15.memories[0].memoryId
_sess_noop = update_memory(_base15, _eid, _TS4)
# Title should still be Alpha
noop_e = find_memory(_sess_noop, _sess_noop.memories[0].memoryId)
_true(noop_e is not None, "update no-op: entry still present")

# retrieve_by_importance on empty session
_empty_imp = retrieve_by_importance(build_session_memory(_CONV_ID, _TS, _TS))
_eq(len(_empty_imp), 0, "retrieve_by_importance: empty session returns empty tuple")

# sort_memories on empty list
_eq(sort_memories([]), [], "sort_memories: empty list returns empty list")

# filter_memories on empty list
_eq(filter_memories([]), [], "filter_memories: empty list returns empty list")

# group_memories on empty list
_eq(group_memories([]), {}, "group_memories: empty list returns empty dict")

# sort_sessions on empty list
_eq(sort_sessions([]), [], "sort_sessions: empty list returns empty list")

# filter_sessions on empty list
_eq(filter_sessions([]), [], "filter_sessions: empty list returns empty list")

# group_sessions on empty list
_eq(group_sessions([]), {}, "group_sessions: empty list returns empty dict")

# merge_summaries with a single summary_id
_single_merge_base = _make_base_session()
_single_merge_base = create_summary(_single_merge_base, "Only summary",
                                     [_single_merge_base.memories[0].memoryId], _TS4, _TS4)
_sid_single = _single_merge_base.summaries[0].summaryId
_sess_single_merge = merge_summaries(_single_merge_base, [_sid_single],
                                      "Re-expressed", _TS5, _TS5)
_eq(len(_sess_single_merge.summaries), 1, "merge_summaries single: one summary remains")
_eq(_sess_single_merge.summaries[0].summary, "Re-expressed",
    "merge_summaries single: text updated")

# create_summary with all memory IDs covered
all_ids = [m.memoryId for m in _base15.memories]
_sess_full_summ = create_summary(_base15, "Full coverage summary", all_ids, _TS4, _TS4)
_eq(len(_sess_full_summ.summaries[0].coveredMemoryIds), len(all_ids),
    "create_summary: all memory IDs covered")

# retrieve_by_tags with whitespace tags
_ws_entry = _make_entry("WS", "ws", _TS, tags=["  net  ", "SCAN"])
_ws_sess  = add_memory(build_session_memory(_CONV_ID, _TS, _TS), _ws_entry, _TS)
ws_result = retrieve_by_tags(_ws_sess, ["net"])
_eq(len(ws_result), 1, "retrieve_by_tags: whitespace-normalised tags match")


# ===========================================================================
# §56  Final report
# ===========================================================================
print()
print("=" * 60)
print(f"Session Memory Engine Smoke Test")
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print("=" * 60)

if _ERRORS:
    print()
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")

if _FAIL > 0:
    sys.exit(1)
else:
    print(f"\nAll {_PASS} assertions passed. ✓")
