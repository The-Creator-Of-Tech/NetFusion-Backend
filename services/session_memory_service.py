"""
Session Memory Engine
======================
Phase A4.5.0 — Deterministic, immutable AI memory management across
conversations and investigations.

Responsibilities
----------------
- Model memory entries, summaries, and sessions as immutable objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute memory fingerprints for cache/replay stability.
- Expose builder functions: build_memory_entry, build_memory_summary,
  build_session_memory, build_memory_statistics.
- Expose validation functions: validate_memory_entry, validate_memory_summary,
  validate_session_memory.
- Integrate with conversation_manager_service, ai_execution_service, and
  copilot_orchestrator_service as upstream/downstream context providers.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs -> same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No database. No HTTP. No providers.

Out of scope in this module
----------------------------
- Memory retrieval, compression, ranking, lifecycle operations.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import SESSION_MEMORY_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("session_memory_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_MEM_NS = uuid.UUID("6ba7b832-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# Approximate chars-per-token ratio (conservative GPT-style estimate)
# ---------------------------------------------------------------------------
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Enumerations (immutable)
# ===========================================================================

class MemoryTypeEnum(str, Enum):
    """Type / tier of a memory entry."""
    SHORT_TERM    = "SHORT_TERM"
    LONG_TERM     = "LONG_TERM"
    SUMMARY       = "SUMMARY"
    EPISODIC      = "EPISODIC"
    INVESTIGATION = "INVESTIGATION"


class MemoryStateEnum(str, Enum):
    """Lifecycle state of a memory entry."""
    ACTIVE     = "ACTIVE"
    ARCHIVED   = "ARCHIVED"
    COMPRESSED = "COMPRESSED"
    EXPIRED    = "EXPIRED"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class SessionMemoryError(Exception):
    """Base class for all Session Memory Engine errors."""


class InvalidMemoryEntryError(SessionMemoryError):
    """Raised when a MemoryEntry fails validation."""


class InvalidMemorySummaryError(SessionMemoryError):
    """Raised when a MemorySummary fails validation."""


class InvalidSessionMemoryError(SessionMemoryError):
    """Raised when a SessionMemory fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class MemoryEntry(BaseModel):
    """
    One immutable memory entry.

    Identity
    --------
    memoryId  : UUIDv5(_MEM_NS, memoryKey) — deterministic.
    memoryKey : SHA256(conversationId + memoryType + title + content[:64])[:32]

    Fields
    ------
    memoryId         : deterministic UUID derived from memoryKey.
    memoryKey        : 32-char SHA-256 key.
    conversationId   : owning conversation ID.
    investigationId  : owning investigation ID (may be empty).
    memoryType       : MemoryTypeEnum classification.
    state            : MemoryStateEnum lifecycle state.
    title            : short human-readable label.
    content          : full memory content text.
    importanceScore  : 0.0–1.0 importance weight.
    confidence       : 0.0–1.0 confidence in the memory accuracy.
    sourceId         : origin ID (message ID, execution ID, etc.).
    tags             : sorted tuple of lowercase tag strings.
    metadata         : arbitrary key→value extension bag.
    createdAt        : ISO-8601 timestamp (caller-supplied for determinism).
    """
    memoryId        : str
    memoryKey       : str
    conversationId  : str
    investigationId : str
    memoryType      : MemoryTypeEnum
    state           : MemoryStateEnum
    title           : str
    content         : str
    importanceScore : float
    confidence      : float
    sourceId        : str
    tags            : Tuple[str, ...]
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class MemorySummary(BaseModel):
    """
    An immutable summary covering a set of memory entries.

    Identity
    --------
    summaryId  : UUIDv5(_MEM_NS, summaryKey) — deterministic.
    summaryKey : SHA256(conversationId + summary[:64] +
                        sorted(coveredMemoryIds))[:32]

    Fields
    ------
    summaryId        : deterministic UUID.
    summaryKey       : 32-char SHA-256 key.
    conversationId   : owning conversation ID.
    summary          : condensed text covering the memory entries.
    coveredMemoryIds : sorted tuple of MemoryEntry memoryId values covered.
    tokenEstimate    : estimated token count of the summary text.
    createdAt        : ISO-8601 timestamp.
    """
    summaryId        : str
    summaryKey       : str
    conversationId   : str
    summary          : str
    coveredMemoryIds : Tuple[str, ...]
    tokenEstimate    : int
    createdAt        : str

    class Config:
        frozen = True


class SessionMemory(BaseModel):
    """
    The complete, immutable session memory record.

    Identity
    --------
    sessionId         : UUIDv5(_MEM_NS, sessionKey) — deterministic.
    sessionKey        : SHA256(conversationId + investigationId)[:32]
    memoryFingerprint : SHA256(sessionKey + sorted(memoryKeys) +
                                sorted(summaryKeys))[:32]

    Fields
    ------
    sessionId         : deterministic UUID.
    sessionKey        : 32-char SHA-256 key.
    conversationId    : owning conversation ID.
    investigationId   : owning investigation ID (may be empty).
    memories          : tuple of MemoryEntry sorted by createdAt then memoryId.
    summaries         : tuple of MemorySummary sorted by summaryId.
    memoryFingerprint : deterministic content fingerprint.
    createdAt         : ISO-8601 creation timestamp.
    updatedAt         : ISO-8601 last-updated timestamp.
    """
    sessionId         : str
    sessionKey        : str
    conversationId    : str
    investigationId   : str
    memories          : Tuple[MemoryEntry, ...]
    summaries         : Tuple[MemorySummary, ...]
    memoryFingerprint : str
    createdAt         : str
    updatedAt         : str

    class Config:
        frozen = True


class MemoryStatistics(BaseModel):
    """
    Aggregate statistics over a collection of SessionMemory objects.

    Fields
    ------
    totalSessions       : total session count.
    totalMemories       : sum of memory entries across all sessions.
    activeMemories      : count of entries in ACTIVE state.
    archivedMemories    : count of entries in ARCHIVED state.
    compressedMemories  : count of entries in COMPRESSED state.
    expiredMemories     : count of entries in EXPIRED state.
    averageImportance   : mean importanceScore across all entries (0.0 if none).
    averageConfidence   : mean confidence across all entries (0.0 if none).
    """
    totalSessions      : int
    totalMemories      : int
    activeMemories     : int
    archivedMemories   : int
    compressedMemories : int
    expiredMemories    : int
    averageImportance  : float
    averageConfidence  : float

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
    """UUIDv5(_MEM_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_MEM_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _norm_tags(tags: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, lowercase, strip, and sort tag strings."""
    if not tags:
        return ()
    return tuple(sorted({t.strip().lower() for t in tags if t and t.strip()}))


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _clamp_float(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


def _estimate_tokens(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))


# ---------------------------------------------------------------------------
# Key derivation functions
# ---------------------------------------------------------------------------

def _compute_memory_key(
    conversation_id : str,
    memory_type     : str,
    title           : str,
    content         : str,
) -> str:
    """
    memoryKey = SHA256(conversationId + memoryType + title + content[:64])[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        memory_type.upper().strip(),
        title.strip(),
        content[:64],
    )


def _compute_summary_key(
    conversation_id   : str,
    summary_text      : str,
    covered_memory_ids: Tuple[str, ...],
) -> str:
    """
    summaryKey = SHA256(conversationId + summary[:64] +
                        sorted(coveredMemoryIds))[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        summary_text[:64],
        "\x01".join(sorted(covered_memory_ids)),
    )


def _compute_session_key(
    conversation_id : str,
    investigation_id: str,
) -> str:
    """sessionKey = SHA256(conversationId + investigationId)[:32]"""
    return _sha256_32(
        conversation_id.strip(),
        investigation_id.strip(),
    )


def _compute_memory_fingerprint(
    session_key  : str,
    memory_keys  : Tuple[str, ...],
    summary_keys : Tuple[str, ...],
) -> str:
    """
    memoryFingerprint = SHA256(sessionKey + sorted(memoryKeys) +
                                sorted(summaryKeys))[:32]
    """
    return _sha256_32(
        session_key,
        "\x01".join(sorted(memory_keys)),
        "\x01".join(sorted(summary_keys)),
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_memory_entry(
    conversation_id : str,
    memory_type     : MemoryTypeEnum,
    state           : MemoryStateEnum,
    title           : str,
    content         : str,
    importance_score: float,
    confidence      : float,
    created_at      : str,
) -> None:
    """
    Validate MemoryEntry construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - memory_type is a valid MemoryTypeEnum member.
    - state is a valid MemoryStateEnum member.
    - title is non-empty.
    - content is not None (may be empty for placeholder entries).
    - importance_score in [0.0, 1.0].
    - confidence in [0.0, 1.0].
    - created_at is a non-empty string.

    Raises
    ------
    InvalidMemoryEntryError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not isinstance(memory_type, MemoryTypeEnum):
        errors.append(f"memoryType must be a MemoryTypeEnum member; got {memory_type!r}.")
    if not isinstance(state, MemoryStateEnum):
        errors.append(f"state must be a MemoryStateEnum member; got {state!r}.")
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if content is None:
        errors.append("content must not be None.")
    if not isinstance(importance_score, (int, float)) or not (0.0 <= float(importance_score) <= 1.0):
        errors.append(
            f"importanceScore={importance_score!r} must be a float in [0.0, 1.0]."
        )
    if not isinstance(confidence, (int, float)) or not (0.0 <= float(confidence) <= 1.0):
        errors.append(
            f"confidence={confidence!r} must be a float in [0.0, 1.0]."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_memory_entry", "errors": errors},
        )
        raise InvalidMemoryEntryError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_memory_summary(
    conversation_id   : str,
    summary           : str,
    covered_memory_ids: Tuple[str, ...],
    created_at        : str,
) -> None:
    """
    Validate MemorySummary construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - summary is non-empty.
    - covered_memory_ids is a non-empty sequence.
    - created_at is a non-empty string.

    Raises
    ------
    InvalidMemorySummaryError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not summary or not summary.strip():
        errors.append("summary must not be empty.")
    if not covered_memory_ids:
        errors.append("coveredMemoryIds must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_memory_summary", "errors": errors},
        )
        raise InvalidMemorySummaryError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_session_memory(
    conversation_id : str,
    created_at      : str,
    updated_at      : str,
) -> None:
    """
    Validate SessionMemory construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - created_at is non-empty.
    - updated_at is non-empty.

    Note: investigation_id may be empty (session not yet linked).

    Raises
    ------
    InvalidSessionMemoryError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")
    if not updated_at or not updated_at.strip():
        errors.append("updatedAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_session_memory", "errors": errors},
        )
        raise InvalidSessionMemoryError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_memory_entry()
# ===========================================================================

def build_memory_entry(
    conversation_id  : str,
    memory_type      : MemoryTypeEnum,
    title            : str,
    content          : str,
    created_at       : str,
    investigation_id : str                      = "",
    state            : MemoryStateEnum          = MemoryStateEnum.ACTIVE,
    importance_score : float                    = 0.5,
    confidence       : float                    = 1.0,
    source_id        : str                      = "",
    tags             : Optional[List[str]]      = None,
    metadata         : Optional[Dict[str, Any]] = None,
    validate         : bool                     = True,
) -> MemoryEntry:
    """
    Build an immutable MemoryEntry.

    memoryKey = SHA256(conversationId + memoryType + title + content[:64])[:32]
    memoryId  = UUIDv5(_MEM_NS, memoryKey)

    Parameters
    ----------
    conversation_id  : owning conversation ID.
    memory_type      : MemoryTypeEnum classification.
    title            : short human-readable label (must be non-empty).
    content          : full memory text (may be empty for placeholders).
    created_at       : ISO-8601 timestamp (caller-supplied for determinism).
    investigation_id : owning investigation ID (may be empty).
    state            : MemoryStateEnum lifecycle state (default ACTIVE).
    importance_score : 0.0–1.0 importance weight (clamped; default 0.5).
    confidence       : 0.0–1.0 accuracy confidence (clamped; default 1.0).
    source_id        : origin ID (e.g. messageId, executionId).
    tags             : classification tags (deduped + lowercase + sorted).
    metadata         : arbitrary extension dict; copied, never mutated.
    validate         : if True, run validate_memory_entry() first.

    Returns
    -------
    MemoryEntry (frozen / immutable)

    Raises
    ------
    InvalidMemoryEntryError : if validate=True and validation fails.
    """
    clamped_importance = _clamp_float(float(importance_score))
    clamped_confidence = _clamp_float(float(confidence))

    if validate:
        validate_memory_entry(
            conversation_id, memory_type, state, title, content,
            clamped_importance, clamped_confidence, created_at,
        )

    mem_key = _compute_memory_key(
        conversation_id, memory_type.value, title, content
    )
    mem_id = _uuid5(mem_key)

    return MemoryEntry(
        memoryId        = mem_id,
        memoryKey       = mem_key,
        conversationId  = conversation_id.strip(),
        investigationId = investigation_id.strip(),
        memoryType      = memory_type,
        state           = state,
        title           = title.strip(),
        content         = content,
        importanceScore = round(clamped_importance, 6),
        confidence      = round(clamped_confidence, 6),
        sourceId        = source_id.strip(),
        tags            = _norm_tags(tags),
        metadata        = dict(metadata) if metadata else {},
        createdAt       = created_at,
    )


# ===========================================================================
# Builder: build_memory_summary()
# ===========================================================================

def build_memory_summary(
    conversation_id   : str,
    summary           : str,
    covered_memory_ids: List[str],
    created_at        : str,
    validate          : bool = True,
) -> MemorySummary:
    """
    Build an immutable MemorySummary.

    summaryKey = SHA256(conversationId + summary[:64] +
                        sorted(coveredMemoryIds))[:32]
    summaryId  = UUIDv5(_MEM_NS, summaryKey)

    Parameters
    ----------
    conversation_id    : owning conversation ID.
    summary            : condensed text covering the memory entries.
    covered_memory_ids : memoryId values covered by this summary.
    created_at         : ISO-8601 timestamp.
    validate           : if True, run validate_memory_summary() first.

    Returns
    -------
    MemorySummary (frozen / immutable)

    Raises
    ------
    InvalidMemorySummaryError : if validate=True and validation fails.
    """
    norm_ids: Tuple[str, ...] = _norm_strings(covered_memory_ids)

    if validate:
        validate_memory_summary(conversation_id, summary, norm_ids, created_at)

    summ_key = _compute_summary_key(conversation_id, summary, norm_ids)
    summ_id  = _uuid5(summ_key)

    return MemorySummary(
        summaryId        = summ_id,
        summaryKey       = summ_key,
        conversationId   = conversation_id.strip(),
        summary          = summary,
        coveredMemoryIds = norm_ids,
        tokenEstimate    = _estimate_tokens(summary),
        createdAt        = created_at,
    )


# ===========================================================================
# Builder: build_session_memory()
# ===========================================================================

def build_session_memory(
    conversation_id  : str,
    created_at       : str,
    updated_at       : str,
    investigation_id : str                             = "",
    memories         : Optional[List[MemoryEntry]]    = None,
    summaries        : Optional[List[MemorySummary]]  = None,
    validate         : bool                            = True,
) -> SessionMemory:
    """
    Assemble a complete, immutable SessionMemory.

    sessionKey        = SHA256(conversationId + investigationId)[:32]
    sessionId         = UUIDv5(_MEM_NS, sessionKey)
    memoryFingerprint = SHA256(sessionKey + sorted(memoryKeys) +
                                sorted(summaryKeys))[:32]

    Parameters
    ----------
    conversation_id  : owning conversation ID.
    created_at       : ISO-8601 creation timestamp.
    updated_at       : ISO-8601 last-updated timestamp.
    investigation_id : owning investigation ID (may be empty).
    memories         : list of MemoryEntry objects.
    summaries        : list of MemorySummary objects.
    validate         : if True, run validate_session_memory() first.

    Returns
    -------
    SessionMemory (frozen / immutable)

    Raises
    ------
    InvalidSessionMemoryError : if validate=True and validation fails.
    """
    if validate:
        validate_session_memory(conversation_id, created_at, updated_at)

    # Sort memories by (createdAt ASC, memoryId ASC) for determinism
    sorted_memories: Tuple[MemoryEntry, ...] = tuple(
        sorted(
            memories or [],
            key=lambda m: (m.createdAt, m.memoryId),
        )
    )

    # Sort summaries by summaryId ASC for determinism
    sorted_summaries: Tuple[MemorySummary, ...] = tuple(
        sorted(summaries or [], key=lambda s: s.summaryId)
    )

    sess_key = _compute_session_key(conversation_id, investigation_id)
    sess_id  = _uuid5(sess_key)

    memory_keys : Tuple[str, ...] = tuple(m.memoryKey  for m in sorted_memories)
    summary_keys: Tuple[str, ...] = tuple(s.summaryKey for s in sorted_summaries)

    mem_fp = _compute_memory_fingerprint(sess_key, memory_keys, summary_keys)

    return SessionMemory(
        sessionId         = sess_id,
        sessionKey        = sess_key,
        conversationId    = conversation_id.strip(),
        investigationId   = investigation_id.strip(),
        memories          = sorted_memories,
        summaries         = sorted_summaries,
        memoryFingerprint = mem_fp,
        createdAt         = created_at,
        updatedAt         = updated_at,
    )


# ===========================================================================
# Builder: build_memory_statistics()
# ===========================================================================

def build_memory_statistics(
    sessions: List[SessionMemory],
) -> MemoryStatistics:
    """
    Compute MemoryStatistics over a list of SessionMemory objects.

    Deterministic: canonical sort (by sessionId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    sessions : any list of SessionMemory objects.

    Returns
    -------
    MemoryStatistics (frozen / immutable)
    """
    if not sessions:
        return MemoryStatistics(
            totalSessions      = 0,
            totalMemories      = 0,
            activeMemories     = 0,
            archivedMemories   = 0,
            compressedMemories = 0,
            expiredMemories    = 0,
            averageImportance  = 0.0,
            averageConfidence  = 0.0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(sessions, key=lambda s: s.sessionId)

    all_entries: List[MemoryEntry] = [
        entry
        for sess in ordered
        for entry in sess.memories
    ]

    n_entries = len(all_entries)

    active_count     = sum(1 for e in all_entries if e.state == MemoryStateEnum.ACTIVE)
    archived_count   = sum(1 for e in all_entries if e.state == MemoryStateEnum.ARCHIVED)
    compressed_count = sum(1 for e in all_entries if e.state == MemoryStateEnum.COMPRESSED)
    expired_count    = sum(1 for e in all_entries if e.state == MemoryStateEnum.EXPIRED)

    if n_entries > 0:
        avg_importance = round(sum(e.importanceScore for e in all_entries) / n_entries, 6)
        avg_confidence = round(sum(e.confidence      for e in all_entries) / n_entries, 6)
    else:
        avg_importance = 0.0
        avg_confidence = 0.0

    return MemoryStatistics(
        totalSessions      = len(ordered),
        totalMemories      = n_entries,
        activeMemories     = active_count,
        archivedMemories   = archived_count,
        compressedMemories = compressed_count,
        expiredMemories    = expired_count,
        averageImportance  = avg_importance,
        averageConfidence  = avg_confidence,
    )


# ===========================================================================
# Integration helpers — context bridges to upstream/downstream services
# ===========================================================================

def memories_to_execution_context(
    memories: Tuple[MemoryEntry, ...],
    max_tokens: int = 2048,
) -> str:
    """
    Serialize a tuple of MemoryEntry objects into a context string suitable
    for inclusion in an ai_execution_service prompt.

    Entries are ordered by importanceScore DESC, then memoryId ASC, so the
    most important memories appear first. Token budget is honoured: once
    accumulated token estimate exceeds max_tokens, remaining entries are
    omitted (the output is always deterministic for the same input set).

    Parameters
    ----------
    memories   : tuple of MemoryEntry objects.
    max_tokens : approximate token budget for the context block.

    Returns
    -------
    str — formatted context block (empty string if memories is empty).
    """
    if not memories:
        return ""

    # Deterministic order: importance DESC, then memoryId ASC for tie-break
    ordered = sorted(
        memories,
        key=lambda m: (-m.importanceScore, m.memoryId),
    )

    lines: List[str] = ["[SESSION MEMORY CONTEXT]"]
    accumulated = _estimate_tokens(lines[0])

    for entry in ordered:
        block = (
            f"[{entry.memoryType.value}] {entry.title}\n"
            f"  confidence={entry.confidence:.2f} importance={entry.importanceScore:.2f}\n"
            f"  {entry.content}"
        )
        block_tokens = _estimate_tokens(block)
        if accumulated + block_tokens > max_tokens:
            break
        lines.append(block)
        accumulated += block_tokens

    return "\n".join(lines)


def session_memory_to_copilot_context(
    session: SessionMemory,
) -> Dict[str, Any]:
    """
    Convert a SessionMemory into a flat dict suitable for injection into a
    copilot_orchestrator_service CopilotRequest's metadata or context fields.

    Returns a plain JSON-serialisable dict — no Pydantic objects.

    Parameters
    ----------
    session : SessionMemory object.

    Returns
    -------
    Dict[str, Any] — copilot-ready context dict.
    """
    return {
        "sessionId"         : session.sessionId,
        "sessionKey"        : session.sessionKey,
        "conversationId"    : session.conversationId,
        "investigationId"   : session.investigationId,
        "memoryFingerprint" : session.memoryFingerprint,
        "totalMemories"     : len(session.memories),
        "totalSummaries"    : len(session.summaries),
        "activeMemories"    : sum(
            1 for m in session.memories if m.state == MemoryStateEnum.ACTIVE
        ),
        "engineVersion"     : SESSION_MEMORY_ENGINE_VERSION,
    }


def session_memory_to_conversation_context(
    session: SessionMemory,
) -> Dict[str, Any]:
    """
    Convert a SessionMemory into a flat dict suitable for the
    conversation_manager_service conversation metadata extension bag.

    Parameters
    ----------
    session : SessionMemory object.

    Returns
    -------
    Dict[str, Any] — conversation-manager-compatible context dict.
    """
    return {
        "memorySessionId"   : session.sessionId,
        "memoryFingerprint" : session.memoryFingerprint,
        "memoryCount"       : len(session.memories),
        "summaryCount"      : len(session.summaries),
        "investigationId"   : session.investigationId,
        "engineVersion"     : SESSION_MEMORY_ENGINE_VERSION,
    }


# ===========================================================================
# Memory Lifecycle Operations
# ===========================================================================

def add_memory(
    session    : SessionMemory,
    entry      : MemoryEntry,
    updated_at : str,
) -> SessionMemory:
    """
    Return a new SessionMemory with *entry* appended to its memories.

    The entry is inserted in sort order (createdAt ASC, memoryId ASC) and the
    memoryFingerprint is recomputed.  The session's updatedAt is set to
    *updated_at*.  If an entry with the same memoryId already exists it is
    replaced by the new one.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    entry      : MemoryEntry to add.
    updated_at : ISO-8601 timestamp for the updated session.

    Returns
    -------
    New SessionMemory (frozen / immutable)
    """
    # Replace if already present, otherwise append
    existing = [m for m in session.memories if m.memoryId != entry.memoryId]
    merged = existing + [entry]

    sorted_mems: Tuple[MemoryEntry, ...] = tuple(
        sorted(merged, key=lambda m: (m.createdAt, m.memoryId))
    )

    mem_keys    = tuple(m.memoryKey  for m in sorted_mems)
    summ_keys   = tuple(s.summaryKey for s in session.summaries)
    new_fp      = _compute_memory_fingerprint(session.sessionKey, mem_keys, summ_keys)

    _log.info(
        "memory_created",
        extra={
            "sessionId"   : session.sessionId,
            "memoryId"    : entry.memoryId,
            "memoryType"  : entry.memoryType.value,
            "memoryState" : entry.state.value,
            "importance"  : entry.importanceScore,
            "confidence"  : entry.confidence,
        },
    )

    return SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = sorted_mems,
        summaries         = session.summaries,
        memoryFingerprint = new_fp,
        createdAt         = session.createdAt,
        updatedAt         = updated_at,
    )


def update_memory(
    session    : SessionMemory,
    memory_id  : str,
    updated_at : str,
    title      : Optional[str]                = None,
    content    : Optional[str]                = None,
    importance_score: Optional[float]         = None,
    confidence : Optional[float]              = None,
    state      : Optional[MemoryStateEnum]    = None,
    tags       : Optional[List[str]]          = None,
    metadata   : Optional[Dict[str, Any]]     = None,
    source_id  : Optional[str]                = None,
) -> SessionMemory:
    """
    Return a new SessionMemory with the matching MemoryEntry replaced by an
    updated copy.  Only fields that are explicitly provided (non-None) are
    changed; all others carry over from the existing entry.

    A new memoryKey/memoryId is computed if title, content, or memoryType
    changes (because those affect the key derivation).  Otherwise the key
    and id are preserved.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    memory_id  : memoryId of the entry to update.
    updated_at : ISO-8601 timestamp for the updated session.
    title / content / importance_score / confidence / state / tags /
    metadata / source_id : fields to update (None = keep existing value).

    Returns
    -------
    New SessionMemory with the updated entry.

    Raises
    ------
    KeyError : if no entry with *memory_id* exists in the session.
    """
    original = next((m for m in session.memories if m.memoryId == memory_id), None)
    if original is None:
        raise KeyError(f"update_memory: memoryId '{memory_id}' not found in session.")

    new_title   = title   if title   is not None else original.title
    new_content = content if content is not None else original.content
    new_imp     = _clamp_float(float(importance_score)) if importance_score is not None else original.importanceScore
    new_conf    = _clamp_float(float(confidence))       if confidence       is not None else original.confidence
    new_state   = state    if state    is not None else original.state
    new_tags    = _norm_tags(tags) if tags is not None else original.tags
    new_meta    = dict(metadata)   if metadata is not None else dict(original.metadata)
    new_src     = source_id.strip() if source_id is not None else original.sourceId

    # Recompute key (title or content may have changed)
    new_key = _compute_memory_key(
        original.conversationId, original.memoryType.value, new_title, new_content
    )
    new_id = _uuid5(new_key)

    updated_entry = MemoryEntry(
        memoryId        = new_id,
        memoryKey       = new_key,
        conversationId  = original.conversationId,
        investigationId = original.investigationId,
        memoryType      = original.memoryType,
        state           = new_state,
        title           = new_title,
        content         = new_content,
        importanceScore = round(new_imp,  6),
        confidence      = round(new_conf, 6),
        sourceId        = new_src,
        tags            = new_tags,
        metadata        = new_meta,
        createdAt       = original.createdAt,
    )

    _log.info(
        "memory_updated",
        extra={
            "sessionId"   : session.sessionId,
            "oldMemoryId" : memory_id,
            "newMemoryId" : new_id,
            "memoryType"  : original.memoryType.value,
        },
    )

    # Remove the original entry first, then add the updated one.
    # We can't use add_memory here directly because the memoryId may have changed
    # (title/content updates recompute the key), so we must remove by old id first.
    session_without_old = SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = tuple(m for m in session.memories if m.memoryId != memory_id),
        summaries         = session.summaries,
        memoryFingerprint = session.memoryFingerprint,
        createdAt         = session.createdAt,
        updatedAt         = session.updatedAt,
    )
    return add_memory(session_without_old, updated_entry, updated_at)


def delete_memory(
    session    : SessionMemory,
    memory_id  : str,
    updated_at : str,
) -> SessionMemory:
    """
    Return a new SessionMemory with the matching MemoryEntry removed.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    memory_id  : memoryId of the entry to remove.
    updated_at : ISO-8601 timestamp.

    Returns
    -------
    New SessionMemory without the deleted entry.

    Raises
    ------
    KeyError : if no entry with *memory_id* exists.
    """
    if not any(m.memoryId == memory_id for m in session.memories):
        raise KeyError(f"delete_memory: memoryId '{memory_id}' not found in session.")

    remaining = tuple(m for m in session.memories if m.memoryId != memory_id)
    mem_keys  = tuple(m.memoryKey  for m in remaining)
    summ_keys = tuple(s.summaryKey for s in session.summaries)
    new_fp    = _compute_memory_fingerprint(session.sessionKey, mem_keys, summ_keys)

    return SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = remaining,
        summaries         = session.summaries,
        memoryFingerprint = new_fp,
        createdAt         = session.createdAt,
        updatedAt         = updated_at,
    )


def _transition_state(
    session    : SessionMemory,
    memory_id  : str,
    new_state  : MemoryStateEnum,
    updated_at : str,
    log_event  : str,
) -> SessionMemory:
    """Internal helper: transition a memory entry to a new state."""
    original = next((m for m in session.memories if m.memoryId == memory_id), None)
    if original is None:
        raise KeyError(f"{log_event}: memoryId '{memory_id}' not found in session.")

    # State stays the same → no-op but still return a new session with updated timestamp
    new_entry = MemoryEntry(
        memoryId        = original.memoryId,
        memoryKey       = original.memoryKey,
        conversationId  = original.conversationId,
        investigationId = original.investigationId,
        memoryType      = original.memoryType,
        state           = new_state,
        title           = original.title,
        content         = original.content,
        importanceScore = original.importanceScore,
        confidence      = original.confidence,
        sourceId        = original.sourceId,
        tags            = original.tags,
        metadata        = dict(original.metadata),
        createdAt       = original.createdAt,
    )

    _log.info(
        log_event,
        extra={
            "sessionId" : session.sessionId,
            "memoryId"  : memory_id,
            "oldState"  : original.state.value,
            "newState"  : new_state.value,
        },
    )

    return add_memory(session, new_entry, updated_at)


def archive_memory(
    session    : SessionMemory,
    memory_id  : str,
    updated_at : str,
) -> SessionMemory:
    """
    Transition a memory entry to ARCHIVED state.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    memory_id  : memoryId of the entry to archive.
    updated_at : ISO-8601 timestamp.

    Returns
    -------
    New SessionMemory with the entry in ARCHIVED state.

    Raises
    ------
    KeyError : if memory_id not found.
    """
    return _transition_state(
        session, memory_id, MemoryStateEnum.ARCHIVED, updated_at, "memory_archived"
    )


def compress_memory(
    session    : SessionMemory,
    memory_id  : str,
    updated_at : str,
) -> SessionMemory:
    """
    Transition a memory entry to COMPRESSED state.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    memory_id  : memoryId of the entry to compress.
    updated_at : ISO-8601 timestamp.

    Returns
    -------
    New SessionMemory with the entry in COMPRESSED state.

    Raises
    ------
    KeyError : if memory_id not found.
    """
    return _transition_state(
        session, memory_id, MemoryStateEnum.COMPRESSED, updated_at, "memory_compressed"
    )


def expire_memory(
    session    : SessionMemory,
    memory_id  : str,
    updated_at : str,
) -> SessionMemory:
    """
    Transition a memory entry to EXPIRED state.

    Parameters
    ----------
    session    : existing SessionMemory (not mutated).
    memory_id  : memoryId of the entry to expire.
    updated_at : ISO-8601 timestamp.

    Returns
    -------
    New SessionMemory with the entry in EXPIRED state.

    Raises
    ------
    KeyError : if memory_id not found.
    """
    return _transition_state(
        session, memory_id, MemoryStateEnum.EXPIRED, updated_at, "memory_expired"
    )


# ===========================================================================
# Summary Operations
# ===========================================================================

def create_summary(
    session            : SessionMemory,
    summary_text       : str,
    covered_memory_ids : List[str],
    created_at         : str,
    updated_at         : str,
) -> SessionMemory:
    """
    Return a new SessionMemory with a MemorySummary added.

    If a summary with the same summaryKey already exists it is replaced.

    Parameters
    ----------
    session             : existing SessionMemory (not mutated).
    summary_text        : condensed text for the new summary.
    covered_memory_ids  : memoryIds covered by this summary.
    created_at          : ISO-8601 timestamp for the summary.
    updated_at          : ISO-8601 timestamp for the session updatedAt.

    Returns
    -------
    New SessionMemory (frozen / immutable)

    Raises
    ------
    InvalidMemorySummaryError : if validation fails.
    """
    new_summary = build_memory_summary(
        conversation_id    = session.conversationId,
        summary            = summary_text,
        covered_memory_ids = covered_memory_ids,
        created_at         = created_at,
        validate           = True,
    )

    # Replace if already present
    existing = [s for s in session.summaries if s.summaryId != new_summary.summaryId]
    merged   = tuple(sorted(existing + [new_summary], key=lambda s: s.summaryId))

    mem_keys  = tuple(m.memoryKey  for m in session.memories)
    summ_keys = tuple(s.summaryKey for s in merged)
    new_fp    = _compute_memory_fingerprint(session.sessionKey, mem_keys, summ_keys)

    _log.info(
        "summary_created",
        extra={
            "sessionId"    : session.sessionId,
            "summaryId"    : new_summary.summaryId,
            "coveredCount" : len(new_summary.coveredMemoryIds),
            "tokenEstimate": new_summary.tokenEstimate,
        },
    )

    return SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = session.memories,
        summaries         = merged,
        memoryFingerprint = new_fp,
        createdAt         = session.createdAt,
        updatedAt         = updated_at,
    )


def rebuild_summary(
    session            : SessionMemory,
    summary_id         : str,
    new_summary_text   : str,
    updated_at         : str,
) -> SessionMemory:
    """
    Return a new SessionMemory with an existing MemorySummary replaced by a
    rebuilt one using *new_summary_text* but the same coveredMemoryIds and
    conversationId.

    Parameters
    ----------
    session          : existing SessionMemory (not mutated).
    summary_id       : summaryId of the summary to rebuild.
    new_summary_text : replacement text.
    updated_at       : ISO-8601 timestamp for the session updatedAt.

    Returns
    -------
    New SessionMemory (frozen / immutable)

    Raises
    ------
    KeyError : if summary_id not found.
    """
    original = next((s for s in session.summaries if s.summaryId == summary_id), None)
    if original is None:
        raise KeyError(f"rebuild_summary: summaryId '{summary_id}' not found in session.")

    # Remove original first so create_summary doesn't need to match summaryId
    session_without = SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = session.memories,
        summaries         = tuple(s for s in session.summaries if s.summaryId != summary_id),
        memoryFingerprint = session.memoryFingerprint,
        createdAt         = session.createdAt,
        updatedAt         = session.updatedAt,
    )

    return create_summary(
        session            = session_without,
        summary_text       = new_summary_text,
        covered_memory_ids = list(original.coveredMemoryIds),
        created_at         = original.createdAt,
        updated_at         = updated_at,
    )


def merge_summaries(
    session      : SessionMemory,
    summary_ids  : List[str],
    merged_text  : str,
    created_at   : str,
    updated_at   : str,
) -> SessionMemory:
    """
    Merge multiple MemorySummary objects into one new summary, removing the
    originals and inserting the merged result.

    The new summary's coveredMemoryIds is the union of all source summaries'
    coveredMemoryIds, deduplicated and sorted.

    Parameters
    ----------
    session      : existing SessionMemory (not mutated).
    summary_ids  : summaryIds of the summaries to merge (must all exist).
    merged_text  : text for the new merged summary.
    created_at   : ISO-8601 timestamp for the new summary.
    updated_at   : ISO-8601 timestamp for the session updatedAt.

    Returns
    -------
    New SessionMemory (frozen / immutable)

    Raises
    ------
    KeyError              : if any summaryId is not found.
    InvalidMemorySummaryError : if merged_text is empty.
    ValueError            : if summary_ids is empty.
    """
    if not summary_ids:
        raise ValueError("merge_summaries: summary_ids must not be empty.")

    sources: List[MemorySummary] = []
    for sid in summary_ids:
        s = next((x for x in session.summaries if x.summaryId == sid), None)
        if s is None:
            raise KeyError(f"merge_summaries: summaryId '{sid}' not found in session.")
        sources.append(s)

    # Union of all covered IDs
    all_covered: List[str] = []
    for s in sources:
        all_covered.extend(s.coveredMemoryIds)
    # Dedup via _norm_strings
    merged_covered = list(_norm_strings(all_covered))

    # Remove originals
    remaining_summaries = [
        s for s in session.summaries if s.summaryId not in set(summary_ids)
    ]

    new_summary = build_memory_summary(
        conversation_id    = session.conversationId,
        summary            = merged_text,
        covered_memory_ids = merged_covered,
        created_at         = created_at,
        validate           = True,
    )

    merged_tuple = tuple(
        sorted(remaining_summaries + [new_summary], key=lambda s: s.summaryId)
    )

    mem_keys  = tuple(m.memoryKey  for m in session.memories)
    summ_keys = tuple(s.summaryKey for s in merged_tuple)
    new_fp    = _compute_memory_fingerprint(session.sessionKey, mem_keys, summ_keys)

    return SessionMemory(
        sessionId         = session.sessionId,
        sessionKey        = session.sessionKey,
        conversationId    = session.conversationId,
        investigationId   = session.investigationId,
        memories          = session.memories,
        summaries         = merged_tuple,
        memoryFingerprint = new_fp,
        createdAt         = session.createdAt,
        updatedAt         = updated_at,
    )


def find_summary(
    session    : SessionMemory,
    summary_id : str,
) -> Optional[MemorySummary]:
    """
    Return the MemorySummary with *summary_id*, or None if not found.

    Parameters
    ----------
    session    : SessionMemory to search.
    summary_id : summaryId to look up.

    Returns
    -------
    MemorySummary or None.
    """
    return next((s for s in session.summaries if s.summaryId == summary_id), None)


# ===========================================================================
# Retrieval
# ===========================================================================

def retrieve_recent_memories(
    session : SessionMemory,
    limit   : int = 10,
) -> Tuple[MemoryEntry, ...]:
    """
    Return up to *limit* MemoryEntry objects ordered by createdAt DESC
    (most recent first), tie-breaking by memoryId DESC.

    Only ACTIVE entries are returned.

    Parameters
    ----------
    session : SessionMemory to query.
    limit   : maximum number of entries to return (clamped to >= 1).

    Returns
    -------
    Tuple of MemoryEntry (newest first).
    """
    limit = max(1, int(limit))
    active = [m for m in session.memories if m.state == MemoryStateEnum.ACTIVE]
    ordered = sorted(active, key=lambda m: (m.createdAt, m.memoryId), reverse=True)
    return tuple(ordered[:limit])


def retrieve_by_importance(
    session          : SessionMemory,
    min_importance   : float = 0.0,
    limit            : int   = 10,
    descending       : bool  = True,
) -> Tuple[MemoryEntry, ...]:
    """
    Return up to *limit* MemoryEntry objects filtered by importanceScore
    >= *min_importance*, ordered by importanceScore (descending by default),
    tie-breaking by memoryId ASC for determinism.

    All states are included (caller may filter separately).

    Parameters
    ----------
    session        : SessionMemory to query.
    min_importance : minimum importanceScore threshold (0.0 – 1.0).
    limit          : maximum entries to return (clamped to >= 1).
    descending     : True = highest importance first (default).

    Returns
    -------
    Tuple of MemoryEntry.
    """
    limit     = max(1, int(limit))
    threshold = _clamp_float(float(min_importance))
    filtered  = [m for m in session.memories if m.importanceScore >= threshold]
    ordered   = sorted(
        filtered,
        key     = lambda m: (-m.importanceScore if descending else m.importanceScore,
                             m.memoryId),
    )
    return tuple(ordered[:limit])


def retrieve_by_tags(
    session         : SessionMemory,
    tags            : List[str],
    match_all       : bool = False,
) -> Tuple[MemoryEntry, ...]:
    """
    Return all MemoryEntry objects whose tags overlap with *tags*.

    Parameters
    ----------
    session   : SessionMemory to query.
    tags      : tag strings to search for (normalised: lowercase + strip).
    match_all : if True, entry must contain ALL provided tags (AND logic).
                if False (default), entry must contain at least one (OR logic).

    Returns
    -------
    Tuple of MemoryEntry sorted by (importanceScore DESC, memoryId ASC).
    """
    norm = {t.strip().lower() for t in tags if t and t.strip()}
    if not norm:
        return ()

    results: List[MemoryEntry] = []
    for m in session.memories:
        entry_tags = set(m.tags)
        if match_all:
            if norm.issubset(entry_tags):
                results.append(m)
        else:
            if norm & entry_tags:
                results.append(m)

    return tuple(sorted(results, key=lambda m: (-m.importanceScore, m.memoryId)))


def retrieve_by_type(
    session      : SessionMemory,
    memory_type  : MemoryTypeEnum,
) -> Tuple[MemoryEntry, ...]:
    """
    Return all MemoryEntry objects of a specific MemoryTypeEnum, sorted by
    (createdAt ASC, memoryId ASC).

    Parameters
    ----------
    session     : SessionMemory to query.
    memory_type : MemoryTypeEnum to filter by.

    Returns
    -------
    Tuple of MemoryEntry.
    """
    filtered = [m for m in session.memories if m.memoryType == memory_type]
    return tuple(sorted(filtered, key=lambda m: (m.createdAt, m.memoryId)))


# ===========================================================================
# Memory Utilities
# ===========================================================================

def sort_memories(
    memories  : List[MemoryEntry],
    key       : str  = "createdAt",
    ascending : bool = True,
) -> List[MemoryEntry]:
    """
    Sort a list of MemoryEntry objects by the specified key.

    Parameters
    ----------
    memories  : list to sort (not mutated).
    key       : "createdAt" | "importanceScore" | "confidence" | "memoryType"
                | "state" | "title".  Default "createdAt".
    ascending : True = low → high (default); False = high → low.

    Returns
    -------
    New sorted list.

    Raises
    ------
    ValueError : if *key* is not a supported sort field.
    """
    _VALID = {"createdAt", "importanceScore", "confidence", "memoryType", "state", "title"}
    if key not in _VALID:
        raise ValueError(f"sort_memories: unknown key '{key}'. Valid: {sorted(_VALID)}")

    def _sort_key(m: MemoryEntry):
        if key == "createdAt":      return (m.createdAt,       m.memoryId)
        if key == "importanceScore":return (m.importanceScore, m.memoryId)
        if key == "confidence":     return (m.confidence,      m.memoryId)
        if key == "memoryType":     return (m.memoryType.value, m.memoryId)
        if key == "state":          return (m.state.value,      m.memoryId)
        if key == "title":          return (m.title.lower(),    m.memoryId)

    return sorted(memories, key=_sort_key, reverse=not ascending)


def filter_memories(
    memories         : List[MemoryEntry],
    memory_type      : Optional[MemoryTypeEnum]  = None,
    state            : Optional[MemoryStateEnum] = None,
    min_importance   : Optional[float]           = None,
    max_importance   : Optional[float]           = None,
    min_confidence   : Optional[float]           = None,
    tags             : Optional[List[str]]       = None,
    conversation_id  : Optional[str]             = None,
    investigation_id : Optional[str]             = None,
) -> List[MemoryEntry]:
    """
    Filter a list of MemoryEntry objects by one or more criteria (all ANDed).

    Parameters
    ----------
    memories         : source list (not mutated).
    memory_type      : keep entries of this type.
    state            : keep entries in this state.
    min_importance   : keep entries with importanceScore >= value.
    max_importance   : keep entries with importanceScore <= value.
    min_confidence   : keep entries with confidence >= value.
    tags             : keep entries that contain at least one of these tags
                       (normalised before comparison).
    conversation_id  : keep entries for this conversation.
    investigation_id : keep entries for this investigation.

    Returns
    -------
    New filtered list (input not mutated).
    """
    result: List[MemoryEntry] = []
    norm_tags = {t.strip().lower() for t in (tags or []) if t and t.strip()}

    for m in memories:
        if memory_type      is not None and m.memoryType      != memory_type:      continue
        if state            is not None and m.state           != state:            continue
        if min_importance   is not None and m.importanceScore  < min_importance:   continue
        if max_importance   is not None and m.importanceScore  > max_importance:   continue
        if min_confidence   is not None and m.confidence       < min_confidence:   continue
        if conversation_id  is not None and m.conversationId  != conversation_id:  continue
        if investigation_id is not None and m.investigationId != investigation_id: continue
        if norm_tags and not (norm_tags & set(m.tags)):                            continue
        result.append(m)

    return result


def group_memories(
    memories : List[MemoryEntry],
    group_by : str = "memoryType",
) -> Dict[str, List[MemoryEntry]]:
    """
    Group a list of MemoryEntry objects by an attribute.

    Parameters
    ----------
    memories : source list (not mutated).
    group_by : "memoryType" (default) | "state" | "conversationId"
               | "investigationId".

    Returns
    -------
    Dict[str, List[MemoryEntry]] — each group sorted by
    (createdAt ASC, memoryId ASC) for determinism.

    Raises
    ------
    ValueError : if *group_by* is not supported.
    """
    _VALID = {"memoryType", "state", "conversationId", "investigationId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_memories: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )
    groups: Dict[str, List[MemoryEntry]] = {}
    for m in memories:
        if group_by == "memoryType":      k = m.memoryType.value
        elif group_by == "state":         k = m.state.value
        elif group_by == "conversationId":k = m.conversationId
        else:                             k = m.investigationId
        groups.setdefault(k, []).append(m)

    return {
        k: sorted(v, key=lambda m: (m.createdAt, m.memoryId))
        for k, v in groups.items()
    }


def find_memory(
    session   : SessionMemory,
    memory_id : str,
) -> Optional[MemoryEntry]:
    """
    Return the MemoryEntry with *memory_id* from *session*, or None.

    Parameters
    ----------
    session   : SessionMemory to search.
    memory_id : memoryId to look up.

    Returns
    -------
    MemoryEntry or None.
    """
    return next((m for m in session.memories if m.memoryId == memory_id), None)


# ===========================================================================
# Session Utilities
# ===========================================================================

def sort_sessions(
    sessions  : List[SessionMemory],
    key       : str  = "createdAt",
    ascending : bool = True,
) -> List[SessionMemory]:
    """
    Sort a list of SessionMemory objects by the specified key.

    Parameters
    ----------
    sessions  : list to sort (not mutated).
    key       : "createdAt" | "updatedAt" | "memoryCount" | "sessionId".
    ascending : True = low → high (default); False = high → low.

    Returns
    -------
    New sorted list.

    Raises
    ------
    ValueError : if *key* is not supported.
    """
    _VALID = {"createdAt", "updatedAt", "memoryCount", "sessionId"}
    if key not in _VALID:
        raise ValueError(f"sort_sessions: unknown key '{key}'. Valid: {sorted(_VALID)}")

    def _sort_key(s: SessionMemory):
        if key == "createdAt":   return (s.createdAt,       s.sessionId)
        if key == "updatedAt":   return (s.updatedAt,       s.sessionId)
        if key == "memoryCount": return (len(s.memories),   s.sessionId)
        if key == "sessionId":   return (s.sessionId,       "")

    return sorted(sessions, key=_sort_key, reverse=not ascending)


def filter_sessions(
    sessions         : List[SessionMemory],
    conversation_id  : Optional[str] = None,
    investigation_id : Optional[str] = None,
    min_memories     : Optional[int] = None,
    max_memories     : Optional[int] = None,
    has_summaries    : Optional[bool]= None,
) -> List[SessionMemory]:
    """
    Filter a list of SessionMemory objects by one or more criteria (all ANDed).

    Parameters
    ----------
    sessions         : source list (not mutated).
    conversation_id  : keep sessions for this conversation.
    investigation_id : keep sessions for this investigation.
    min_memories     : keep sessions with len(memories) >= value.
    max_memories     : keep sessions with len(memories) <= value.
    has_summaries    : True = only sessions with >= 1 summary;
                       False = only sessions with 0 summaries.

    Returns
    -------
    New filtered list (input not mutated).
    """
    result: List[SessionMemory] = []
    for s in sessions:
        if conversation_id  is not None and s.conversationId  != conversation_id:  continue
        if investigation_id is not None and s.investigationId != investigation_id: continue
        if min_memories     is not None and len(s.memories)    < min_memories:     continue
        if max_memories     is not None and len(s.memories)    > max_memories:     continue
        if has_summaries is not None:
            if has_summaries     and not s.summaries: continue
            if not has_summaries and s.summaries:     continue
        result.append(s)
    return result


def group_sessions(
    sessions : List[SessionMemory],
    group_by : str = "investigationId",
) -> Dict[str, List[SessionMemory]]:
    """
    Group a list of SessionMemory objects by an attribute.

    Parameters
    ----------
    sessions : source list (not mutated).
    group_by : "investigationId" (default) | "conversationId".

    Returns
    -------
    Dict[str, List[SessionMemory]] — each group sorted by sessionId ASC.

    Raises
    ------
    ValueError : if *group_by* is not supported.
    """
    _VALID = {"investigationId", "conversationId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_sessions: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )
    groups: Dict[str, List[SessionMemory]] = {}
    for s in sessions:
        k = s.investigationId if group_by == "investigationId" else s.conversationId
        groups.setdefault(k, []).append(s)

    return {k: sorted(v, key=lambda s: s.sessionId) for k, v in groups.items()}


def find_session(
    sessions   : List[SessionMemory],
    session_id : str,
) -> Optional[SessionMemory]:
    """
    Return the SessionMemory with *session_id* from *sessions*, or None.

    Parameters
    ----------
    sessions   : list to search.
    session_id : sessionId to look up.

    Returns
    -------
    SessionMemory or None.
    """
    return next((s for s in sessions if s.sessionId == session_id), None)
