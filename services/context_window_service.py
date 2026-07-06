"""
Context Window Manager Engine
==============================
Phase A4.5.1 — Deterministic, immutable context window assembly for AI models.

Responsibilities
----------------
- Model context items and windows as immutable, typed objects.
- Rank and select the optimal investigation context items.
- Assemble ContextWindow objects ready for downstream AI execution.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute contextFingerprint for cache/replay stability.
- Expose builder functions: build_context_item, build_context_window,
  build_context_statistics.
- Expose validation functions: validate_context_item, validate_context_window.
- Integrate with conversation_manager_service, session_memory_service,
  reasoning_service, and ai_execution_service as upstream/downstream bridges.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No database. No HTTP. No providers. No token budgeting.

Out of scope in this module
----------------------------
- Token budgeting and limits.
- Provider selection and model routing.
- Prompt generation and assembly.
- Memory retrieval and compression.
- HTTP communication.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import CONTEXT_WINDOW_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("context_window_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_CTX_NS = uuid.UUID("6ba7b833-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# Approximate chars-per-token ratio (conservative GPT-style estimate)
# ---------------------------------------------------------------------------
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Enumerations (immutable)
# ===========================================================================

class ContextSourceEnum(str, Enum):
    """Origin domain of a context item."""
    CONVERSATION  = "CONVERSATION"
    MEMORY        = "MEMORY"
    REASONING     = "REASONING"
    TIMELINE      = "TIMELINE"
    ATTACK_GRAPH  = "ATTACK_GRAPH"
    FINDING       = "FINDING"
    ALERT         = "ALERT"
    EVIDENCE      = "EVIDENCE"
    USER_INPUT    = "USER_INPUT"


class ContextPriorityEnum(str, Enum):
    """Assembly priority tier for a context item."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    NORMAL   = "NORMAL"
    LOW      = "LOW"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ContextWindowError(Exception):
    """Base class for all Context Window Engine errors."""


class InvalidContextItemError(ContextWindowError):
    """Raised when a ContextItem fails validation."""


class InvalidContextWindowError(ContextWindowError):
    """Raised when a ContextWindow fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ContextItem(BaseModel):
    """
    One immutable context item to be assembled into a ContextWindow.

    Identity
    --------
    contextItemId  : UUIDv5(_CTX_NS, contextItemKey) — deterministic.
    contextItemKey : SHA256(source + priority + referenceId + title +
                            content[:64])[:32]

    Fields
    ------
    contextItemId   : deterministic UUID derived from contextItemKey.
    contextItemKey  : 32-char SHA-256 key.
    source          : ContextSourceEnum — origin domain of the item.
    priority        : ContextPriorityEnum — assembly priority tier.
    title           : short human-readable label.
    content         : full text content of the item.
    referenceId     : ID of the originating object (finding, alert, message…).
    tokenEstimate   : estimated token count for content.
    importanceScore : 0.0–1.0 importance weight for ranking.
    confidence      : 0.0–1.0 confidence in the item's accuracy.
    metadata        : arbitrary key→value extension bag.
    createdAt       : ISO-8601 timestamp (caller-supplied for determinism).
    """
    contextItemId   : str
    contextItemKey  : str
    source          : ContextSourceEnum
    priority        : ContextPriorityEnum
    title           : str
    content         : str
    referenceId     : str
    tokenEstimate   : int
    importanceScore : float
    confidence      : float
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class ContextWindow(BaseModel):
    """
    The complete, immutable assembled context window.

    Identity
    --------
    windowId            : UUIDv5(_CTX_NS, windowKey) — deterministic.
    windowKey           : SHA256(investigationId + conversationId +
                                 sorted(contextItemKeys))[:32]
    contextFingerprint  : SHA256(windowKey + sorted(contextItemKeys))[:32]

    Fields
    ------
    windowId            : deterministic UUID.
    windowKey           : 32-char SHA-256 key.
    investigationId     : owning investigation ID (may be empty).
    conversationId      : owning conversation ID (may be empty).
    items               : tuple of ContextItem sorted by priority then
                          importanceScore DESC then contextItemId ASC.
    totalTokenEstimate  : sum of tokenEstimate across all items.
    contextFingerprint  : deterministic content fingerprint.
    createdAt           : ISO-8601 timestamp (caller-supplied).
    """
    windowId           : str
    windowKey          : str
    investigationId    : str
    conversationId     : str
    items              : Tuple[ContextItem, ...]
    totalTokenEstimate : int
    contextFingerprint : str
    createdAt          : str

    class Config:
        frozen = True


class ContextStatistics(BaseModel):
    """
    Aggregate statistics over a collection of ContextWindow objects.

    Fields
    ------
    totalWindows      : total count of windows.
    totalItems        : sum of item counts across all windows.
    averageTokens     : mean totalTokenEstimate per window (0.0 if empty).
    averageImportance : mean importanceScore across all items (0.0 if none).
    averageConfidence : mean confidence across all items (0.0 if none).
    itemsBySource     : dict mapping ContextSourceEnum.value → item count.
    itemsByPriority   : dict mapping ContextPriorityEnum.value → item count.
    """
    totalWindows      : int
    totalItems        : int
    averageTokens     : float
    averageImportance : float
    averageConfidence : float
    itemsBySource     : Dict[str, int]
    itemsByPriority   : Dict[str, int]

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
    """UUIDv5(_CTX_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_CTX_NS, key))


def _norm(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _clamp_float(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


def _estimate_tokens(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))


# ---------------------------------------------------------------------------
# Priority ordering map — lower integer = higher assembly precedence
# ---------------------------------------------------------------------------
_PRIORITY_ORDER: Dict[ContextPriorityEnum, int] = {
    ContextPriorityEnum.CRITICAL : 0,
    ContextPriorityEnum.HIGH     : 1,
    ContextPriorityEnum.NORMAL   : 2,
    ContextPriorityEnum.LOW      : 3,
}

# ---------------------------------------------------------------------------
# Key derivation functions
# ---------------------------------------------------------------------------

def _compute_context_item_key(
    source      : str,
    priority    : str,
    reference_id: str,
    title       : str,
    content     : str,
) -> str:
    """
    contextItemKey = SHA256(source + priority + referenceId +
                             title + content[:64])[:32]
    """
    return _sha256_32(
        source.upper().strip(),
        priority.upper().strip(),
        reference_id.strip(),
        title.strip(),
        content[:64],
    )


def _compute_window_key(
    investigation_id  : str,
    conversation_id   : str,
    item_keys         : Tuple[str, ...],
) -> str:
    """
    windowKey = SHA256(investigationId + conversationId +
                       sorted(contextItemKeys))[:32]
    """
    return _sha256_32(
        investigation_id.strip(),
        conversation_id.strip(),
        "\x01".join(sorted(item_keys)),
    )


def _compute_context_fingerprint(
    window_key: str,
    item_keys : Tuple[str, ...],
) -> str:
    """
    contextFingerprint = SHA256(windowKey + sorted(contextItemKeys))[:32]
    """
    return _sha256_32(
        window_key,
        "\x01".join(sorted(item_keys)),
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_context_item(
    source          : ContextSourceEnum,
    priority        : ContextPriorityEnum,
    title           : str,
    content         : str,
    importance_score: float,
    confidence      : float,
    created_at      : str,
) -> None:
    """
    Validate ContextItem construction parameters.

    Checks
    ------
    - source is a valid ContextSourceEnum member.
    - priority is a valid ContextPriorityEnum member.
    - title is non-empty.
    - content is not None (may be empty for placeholder items).
    - importance_score in [0.0, 1.0].
    - confidence in [0.0, 1.0].
    - created_at is a non-empty string.

    Raises
    ------
    InvalidContextItemError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(source, ContextSourceEnum):
        errors.append(
            f"source must be a ContextSourceEnum member; got {source!r}."
        )
    if not isinstance(priority, ContextPriorityEnum):
        errors.append(
            f"priority must be a ContextPriorityEnum member; got {priority!r}."
        )
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if content is None:
        errors.append("content must not be None.")
    if not isinstance(importance_score, (int, float)) or not (
        0.0 <= float(importance_score) <= 1.0
    ):
        errors.append(
            f"importanceScore={importance_score!r} must be a float in [0.0, 1.0]."
        )
    if not isinstance(confidence, (int, float)) or not (
        0.0 <= float(confidence) <= 1.0
    ):
        errors.append(
            f"confidence={confidence!r} must be a float in [0.0, 1.0]."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_context_item", "errors": errors},
        )
        raise InvalidContextItemError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_context_window(
    conversation_id : str,
    created_at      : str,
) -> None:
    """
    Validate ContextWindow construction parameters.

    Checks
    ------
    - created_at is a non-empty string.

    Note: investigation_id and conversation_id may be empty (window not yet
    linked to a specific investigation or conversation).
    Note: conversation_id must be a string (may be empty).

    Raises
    ------
    InvalidContextWindowError : if any rule is violated.
    """
    errors: List[str] = []

    if conversation_id is None:
        errors.append("conversationId must not be None.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_context_window", "errors": errors},
        )
        raise InvalidContextWindowError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_context_item()
# ===========================================================================

def build_context_item(
    source          : ContextSourceEnum,
    priority        : ContextPriorityEnum,
    title           : str,
    content         : str,
    created_at      : str,
    reference_id    : str                      = "",
    importance_score: float                    = 0.5,
    confidence      : float                    = 1.0,
    metadata        : Optional[Dict[str, Any]] = None,
    validate        : bool                     = True,
) -> ContextItem:
    """
    Build an immutable ContextItem.

    contextItemKey = SHA256(source + priority + referenceId +
                             title + content[:64])[:32]
    contextItemId  = UUIDv5(_CTX_NS, contextItemKey)

    Parameters
    ----------
    source           : ContextSourceEnum — origin domain.
    priority         : ContextPriorityEnum — assembly priority tier.
    title            : short human-readable label (must be non-empty).
    content          : full text content (may be empty for placeholders).
    created_at       : ISO-8601 timestamp (caller-supplied for determinism).
    reference_id     : ID of the originating object (may be empty).
    importance_score : 0.0–1.0 importance weight (clamped; default 0.5).
    confidence       : 0.0–1.0 accuracy confidence (clamped; default 1.0).
    metadata         : arbitrary extension dict; copied, never mutated.
    validate         : if True, run validate_context_item() first.

    Returns
    -------
    ContextItem (frozen / immutable)

    Raises
    ------
    InvalidContextItemError : if validate=True and validation fails.
    """
    clamped_importance = _clamp_float(float(importance_score))
    clamped_confidence = _clamp_float(float(confidence))

    if validate:
        validate_context_item(
            source, priority, title, content,
            clamped_importance, clamped_confidence, created_at,
        )

    item_key = _compute_context_item_key(
        source.value, priority.value, reference_id, title, content,
    )
    item_id = _uuid5(item_key)

    return ContextItem(
        contextItemId   = item_id,
        contextItemKey  = item_key,
        source          = source,
        priority        = priority,
        title           = title.strip(),
        content         = content,
        referenceId     = reference_id.strip(),
        tokenEstimate   = _estimate_tokens(content),
        importanceScore = round(clamped_importance, 6),
        confidence      = round(clamped_confidence, 6),
        metadata        = dict(metadata) if metadata else {},
        createdAt       = created_at,
    )


# ===========================================================================
# Builder: build_context_window()
# ===========================================================================

def build_context_window(
    created_at      : str,
    investigation_id: str                       = "",
    conversation_id : str                       = "",
    items           : Optional[List[ContextItem]] = None,
    validate        : bool                      = True,
) -> ContextWindow:
    """
    Assemble a complete, immutable ContextWindow.

    windowKey          = SHA256(investigationId + conversationId +
                                sorted(contextItemKeys))[:32]
    windowId           = UUIDv5(_CTX_NS, windowKey)
    contextFingerprint = SHA256(windowKey + sorted(contextItemKeys))[:32]

    Items are sorted by:
      1. Priority tier ASC (CRITICAL → HIGH → NORMAL → LOW)
      2. importanceScore DESC (highest importance first within tier)
      3. contextItemId ASC (stable tie-break)

    Parameters
    ----------
    created_at       : ISO-8601 creation timestamp (caller-supplied).
    investigation_id : owning investigation ID (may be empty).
    conversation_id  : owning conversation ID (may be empty).
    items            : list of ContextItem objects to assemble.
    validate         : if True, run validate_context_window() first.

    Returns
    -------
    ContextWindow (frozen / immutable)

    Raises
    ------
    InvalidContextWindowError : if validate=True and validation fails.
    """
    if validate:
        validate_context_window(conversation_id, created_at)

    # Sort items: priority ASC, importance DESC, id ASC for full determinism
    sorted_items: Tuple[ContextItem, ...] = tuple(
        sorted(
            items or [],
            key=lambda i: (
                _PRIORITY_ORDER.get(i.priority, 99),
                -i.importanceScore,
                i.contextItemId,
            ),
        )
    )

    item_keys: Tuple[str, ...] = tuple(i.contextItemKey for i in sorted_items)

    win_key = _compute_window_key(investigation_id, conversation_id, item_keys)
    win_id  = _uuid5(win_key)
    ctx_fp  = _compute_context_fingerprint(win_key, item_keys)

    total_tokens = sum(i.tokenEstimate for i in sorted_items)

    return ContextWindow(
        windowId           = win_id,
        windowKey          = win_key,
        investigationId    = investigation_id.strip(),
        conversationId     = conversation_id.strip(),
        items              = sorted_items,
        totalTokenEstimate = total_tokens,
        contextFingerprint = ctx_fp,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_context_statistics()
# ===========================================================================

def build_context_statistics(
    windows: List[ContextWindow],
) -> ContextStatistics:
    """
    Compute ContextStatistics over a list of ContextWindow objects.

    Deterministic: canonical sort (by windowId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    windows : any list of ContextWindow objects.

    Returns
    -------
    ContextStatistics (frozen / immutable)
    """
    # Initialise per-bucket counters with every valid enum value at 0
    items_by_source: Dict[str, int] = {s.value: 0 for s in ContextSourceEnum}
    items_by_priority: Dict[str, int] = {p.value: 0 for p in ContextPriorityEnum}

    if not windows:
        return ContextStatistics(
            totalWindows      = 0,
            totalItems        = 0,
            averageTokens     = 0.0,
            averageImportance = 0.0,
            averageConfidence = 0.0,
            itemsBySource     = items_by_source,
            itemsByPriority   = items_by_priority,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(windows, key=lambda w: w.windowId)
    n = len(ordered)

    all_items: List[ContextItem] = [
        item
        for win in ordered
        for item in win.items
    ]
    n_items = len(all_items)

    token_sum = sum(w.totalTokenEstimate for w in ordered)

    for item in all_items:
        items_by_source[item.source.value] = (
            items_by_source.get(item.source.value, 0) + 1
        )
        items_by_priority[item.priority.value] = (
            items_by_priority.get(item.priority.value, 0) + 1
        )

    if n_items > 0:
        avg_importance = round(
            sum(i.importanceScore for i in all_items) / n_items, 6
        )
        avg_confidence = round(
            sum(i.confidence for i in all_items) / n_items, 6
        )
    else:
        avg_importance = 0.0
        avg_confidence = 0.0

    return ContextStatistics(
        totalWindows      = n,
        totalItems        = n_items,
        averageTokens     = round(token_sum / n, 4),
        averageImportance = avg_importance,
        averageConfidence = avg_confidence,
        itemsBySource     = items_by_source,
        itemsByPriority   = items_by_priority,
    )


# ===========================================================================
# Integration helpers — context bridges to upstream/downstream services
# ===========================================================================

def conversation_messages_to_context_items(
    messages: Any,
    created_at: str,
    priority: ContextPriorityEnum = ContextPriorityEnum.NORMAL,
) -> List[ContextItem]:
    """
    Convert ConversationMessage objects from conversation_manager_service
    into ContextItem objects for window assembly.

    Each message becomes one ContextItem with:
      - source    = CONVERSATION
      - title     = "<ROLE> message #<sequenceNumber>"
      - referenceId = messageId
      - importanceScore derived from role (SYSTEM=1.0, USER=0.8, ASSISTANT=0.7, TOOL=0.6)

    Messages are processed in sequenceNumber ASC order.

    Parameters
    ----------
    messages   : tuple/list of ConversationMessage from conversation_manager_service.
    created_at : ISO-8601 timestamp for all generated items.
    priority   : ContextPriorityEnum tier to assign (default NORMAL).

    Returns
    -------
    List[ContextItem] — one item per message, deterministic order.
    """
    _ROLE_IMPORTANCE = {
        "SYSTEM"   : 1.0,
        "USER"     : 0.8,
        "ASSISTANT": 0.7,
        "TOOL"     : 0.6,
    }

    sorted_messages = sorted(messages, key=lambda m: (m.sequenceNumber, m.messageId))
    result: List[ContextItem] = []

    for msg in sorted_messages:
        role_str = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
        importance = _ROLE_IMPORTANCE.get(role_str.upper(), 0.5)

        item = build_context_item(
            source           = ContextSourceEnum.CONVERSATION,
            priority         = priority,
            title            = f"{role_str} message #{msg.sequenceNumber}",
            content          = msg.content,
            created_at       = created_at,
            reference_id     = msg.messageId,
            importance_score = importance,
            confidence       = 1.0,
            metadata         = {"conversationId": msg.conversationId,
                                "sequenceNumber": msg.sequenceNumber},
            validate         = True,
        )
        result.append(item)

    return result


def memory_entries_to_context_items(
    memories  : Any,
    created_at: str,
    priority  : ContextPriorityEnum = ContextPriorityEnum.NORMAL,
) -> List[ContextItem]:
    """
    Convert MemoryEntry objects from session_memory_service into ContextItem
    objects for window assembly.

    Each memory entry becomes one ContextItem with:
      - source      = MEMORY
      - title       = memory.title
      - referenceId = memory.memoryId
      - importanceScore = memory.importanceScore (already 0–1)
      - confidence      = memory.confidence

    Entries are processed in importanceScore DESC, then memoryId ASC order
    so the most important memories appear first in the returned list.

    Parameters
    ----------
    memories   : tuple/list of MemoryEntry from session_memory_service.
    created_at : ISO-8601 timestamp for all generated items.
    priority   : ContextPriorityEnum tier to assign (default NORMAL).

    Returns
    -------
    List[ContextItem] — deterministic order (importance DESC, id ASC).
    """
    sorted_memories = sorted(
        memories,
        key=lambda m: (-m.importanceScore, m.memoryId),
    )
    result: List[ContextItem] = []

    for mem in sorted_memories:
        item = build_context_item(
            source           = ContextSourceEnum.MEMORY,
            priority         = priority,
            title            = mem.title,
            content          = mem.content,
            created_at       = created_at,
            reference_id     = mem.memoryId,
            importance_score = mem.importanceScore,
            confidence       = mem.confidence,
            metadata         = {"memoryType": mem.memoryType.value,
                                "conversationId": mem.conversationId},
            validate         = True,
        )
        result.append(item)

    return result


def reasoning_result_to_context_item(
    result    : Any,
    created_at: str,
    priority  : ContextPriorityEnum = ContextPriorityEnum.HIGH,
) -> ContextItem:
    """
    Convert a ReasoningResult from reasoning_service into a single ContextItem
    summarising the overall reasoning decision.

    - source         = REASONING
    - title          = "Reasoning decision"
    - content        = result.decision + explanation summary
    - referenceId    = result.reasoningId
    - importanceScore = result.overallConfidence / 100.0
    - confidence      = result.overallConfidence / 100.0

    Parameters
    ----------
    result     : ReasoningResult from reasoning_service.
    created_at : ISO-8601 timestamp.
    priority   : ContextPriorityEnum tier (default HIGH).

    Returns
    -------
    ContextItem (frozen / immutable)
    """
    confidence_norm = round(
        min(1.0, max(0.0, result.overallConfidence / 100.0)), 6
    )
    importance_norm = confidence_norm

    decision_text = result.decision or "No decision recorded."
    explanation   = ""
    if hasattr(result, "decisionExplanation") and result.decisionExplanation:
        explanation = result.decisionExplanation.summary or ""

    content = decision_text
    if explanation and explanation != decision_text:
        content = f"{decision_text}\n\n{explanation}"

    return build_context_item(
        source           = ContextSourceEnum.REASONING,
        priority         = priority,
        title            = "Reasoning decision",
        content          = content,
        created_at       = created_at,
        reference_id     = result.reasoningId,
        importance_score = importance_norm,
        confidence       = confidence_norm,
        metadata         = {
            "overallRisk"      : result.overallRisk,
            "reasoningKey"     : result.reasoningKey,
            "engineVersion"    : result.engineVersion,
        },
        validate         = True,
    )


def context_window_to_execution_prompts(
    window: ContextWindow,
) -> Tuple[str, str]:
    """
    Convert a ContextWindow into (system_prompt, user_prompt) strings
    suitable for ai_execution_service.build_execution_request().

    Rules
    -----
    - Items with source CONVERSATION or USER_INPUT contribute to user_prompt.
    - All other items contribute to system_prompt as structured context blocks.
    - Items are processed in their already-sorted window order (priority ASC,
      importance DESC, id ASC).
    - Returns ("", "") when the window has no items.

    Parameters
    ----------
    window : ContextWindow to convert.

    Returns
    -------
    (system_prompt, user_prompt) — both plain strings.
    """
    _USER_SOURCES = {ContextSourceEnum.CONVERSATION, ContextSourceEnum.USER_INPUT}

    system_parts: List[str] = []
    user_parts: List[str] = []

    for item in window.items:
        if item.source in _USER_SOURCES:
            user_parts.append(item.content)
        else:
            block = (
                f"[{item.source.value}] {item.title}\n"
                f"  priority={item.priority.value} "
                f"importance={item.importanceScore:.3f} "
                f"confidence={item.confidence:.3f}\n"
                f"  {item.content}"
            )
            system_parts.append(block)

    system_prompt = "\n\n".join(system_parts)
    user_prompt   = "\n".join(user_parts)

    return system_prompt, user_prompt


def context_window_to_copilot_context(
    window: ContextWindow,
) -> Dict[str, Any]:
    """
    Convert a ContextWindow into a flat dict suitable for injection into a
    copilot_orchestrator_service CopilotRequest's metadata or context fields.

    Returns a plain JSON-serialisable dict — no Pydantic objects.

    Parameters
    ----------
    window : ContextWindow object.

    Returns
    -------
    Dict[str, Any] — copilot-ready context dict.
    """
    source_counts: Dict[str, int] = {s.value: 0 for s in ContextSourceEnum}
    for item in window.items:
        source_counts[item.source.value] += 1

    return {
        "windowId"           : window.windowId,
        "windowKey"          : window.windowKey,
        "investigationId"    : window.investigationId,
        "conversationId"     : window.conversationId,
        "totalItems"         : len(window.items),
        "totalTokenEstimate" : window.totalTokenEstimate,
        "contextFingerprint" : window.contextFingerprint,
        "itemsBySource"      : source_counts,
        "engineVersion"      : CONTEXT_WINDOW_ENGINE_VERSION,
    }

# ===========================================================================
# A4.3.3 Part B — Context Selection
# ===========================================================================

def add_context_item(
    window  : ContextWindow,
    item    : ContextItem,
) -> ContextWindow:
    """
    Return a new ContextWindow with *item* added.

    If an item with the same contextItemKey already exists, the existing item
    is kept and the window is returned unchanged (idempotent add).  The
    returned window is fully re-sorted and its fingerprint is recomputed.

    Structured log: "context_item_added" (item key + window key only — no
    prompt contents or investigation data).

    Parameters
    ----------
    window : existing ContextWindow (immutable; never mutated).
    item   : ContextItem to add.

    Returns
    -------
    New ContextWindow (frozen / immutable).
    """
    existing_keys = {i.contextItemKey for i in window.items}
    if item.contextItemKey in existing_keys:
        _log.info(
            "context_item_add_skipped_duplicate",
            extra={
                "itemKey"  : item.contextItemKey,
                "windowKey": window.windowKey,
            },
        )
        return window

    new_items = list(window.items) + [item]
    new_window = build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = new_items,
        validate         = False,
    )

    _log.info(
        "context_item_added",
        extra={
            "itemKey"      : item.contextItemKey,
            "source"       : item.source.value,
            "priority"     : item.priority.value,
            "windowKey"    : new_window.windowKey,
            "totalItems"   : len(new_window.items),
        },
    )
    return new_window


def update_context_item(
    window  : ContextWindow,
    item    : ContextItem,
) -> ContextWindow:
    """
    Return a new ContextWindow where the item whose contextItemKey matches
    *item.contextItemKey* is replaced by *item*.

    If no matching item exists, *item* is appended (upsert semantics).
    The returned window is fully re-sorted and its fingerprint recomputed.

    Structured log: "context_item_updated" (keys only).

    Parameters
    ----------
    window : existing ContextWindow (immutable; never mutated).
    item   : replacement ContextItem.

    Returns
    -------
    New ContextWindow (frozen / immutable).
    """
    updated = [i if i.contextItemKey != item.contextItemKey else item
               for i in window.items]

    # If key was not found, append (upsert)
    found = any(i.contextItemKey == item.contextItemKey for i in window.items)
    if not found:
        updated.append(item)

    new_window = build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = updated,
        validate         = False,
    )

    _log.info(
        "context_item_updated",
        extra={
            "itemKey"      : item.contextItemKey,
            "source"       : item.source.value,
            "priority"     : item.priority.value,
            "windowKey"    : new_window.windowKey,
            "wasUpsert"    : not found,
        },
    )
    return new_window


def remove_context_item(
    window      : ContextWindow,
    item_key    : str,
) -> ContextWindow:
    """
    Return a new ContextWindow with the item whose contextItemKey equals
    *item_key* removed.

    If no matching item exists, the window is returned unchanged.
    The returned window is fully re-sorted and its fingerprint recomputed.

    Structured log: "context_item_removed" (key only).

    Parameters
    ----------
    window   : existing ContextWindow (immutable; never mutated).
    item_key : contextItemKey of the item to remove.

    Returns
    -------
    New ContextWindow (frozen / immutable).
    """
    remaining = [i for i in window.items if i.contextItemKey != item_key]
    removed   = len(window.items) - len(remaining)

    new_window = build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = remaining,
        validate         = False,
    )

    if removed > 0:
        _log.info(
            "context_item_removed",
            extra={
                "itemKey"    : item_key,
                "windowKey"  : new_window.windowKey,
                "totalItems" : len(new_window.items),
            },
        )
    return new_window


# ===========================================================================
# A4.3.3 Part B — Context Ranking
# ===========================================================================

def rank_by_priority(
    items     : List[ContextItem],
    ascending : bool = True,
) -> List[ContextItem]:
    """
    Sort *items* by priority tier.

    Ascending (default): CRITICAL first → LOW last.
    Descending: LOW first → CRITICAL last.
    Tie-break: importanceScore DESC, then contextItemId ASC (stable).

    Parameters
    ----------
    items     : list of ContextItem objects.
    ascending : True = CRITICAL first (default); False = LOW first.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        items,
        key=lambda i: (
            _PRIORITY_ORDER.get(i.priority, 99) * (1 if ascending else -1),
            -i.importanceScore,
            i.contextItemId,
        ),
    )


def rank_by_importance(
    items     : List[ContextItem],
    ascending : bool = False,
) -> List[ContextItem]:
    """
    Sort *items* by importanceScore.

    Descending (default): highest importance first.
    Ascending: lowest importance first.
    Tie-break: confidence DESC, then contextItemId ASC (stable).

    Parameters
    ----------
    items     : list of ContextItem objects.
    ascending : False = highest first (default); True = lowest first.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    sign = 1 if ascending else -1
    return sorted(
        items,
        key=lambda i: (
            sign * i.importanceScore,
            -i.confidence,
            i.contextItemId,
        ),
    )


def rank_by_confidence(
    items     : List[ContextItem],
    ascending : bool = False,
) -> List[ContextItem]:
    """
    Sort *items* by confidence score.

    Descending (default): highest confidence first.
    Ascending: lowest confidence first.
    Tie-break: importanceScore DESC, then contextItemId ASC (stable).

    Parameters
    ----------
    items     : list of ContextItem objects.
    ascending : False = highest first (default); True = lowest first.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    sign = 1 if ascending else -1
    return sorted(
        items,
        key=lambda i: (
            sign * i.confidence,
            -i.importanceScore,
            i.contextItemId,
        ),
    )


# ===========================================================================
# A4.3.3 Part B — Context Assembly
# ===========================================================================

def merge_context_windows(
    windows          : List[ContextWindow],
    created_at       : str,
    investigation_id : str = "",
    conversation_id  : str = "",
    deduplicate      : bool = True,
) -> ContextWindow:
    """
    Merge multiple ContextWindow objects into a single new ContextWindow.

    All items from all windows are collected.  When *deduplicate* is True
    (default), items with duplicate contextItemKey values are reduced to a
    single representative (the one with the highest importanceScore; ties
    broken by contextItemId ASC).  The merged window is fully re-sorted.

    investigationId and conversationId default to the values of the first
    window (by windowId ASC) unless overridden by the caller.

    Structured log: "window_merged" (window count + item count; no data).

    Parameters
    ----------
    windows          : list of ContextWindow objects to merge.
    created_at       : ISO-8601 timestamp for the new window.
    investigation_id : override investigationId (empty = use first window's).
    conversation_id  : override conversationId  (empty = use first window's).
    deduplicate      : if True, remove duplicate items (default True).

    Returns
    -------
    New ContextWindow (frozen / immutable).  Empty window if *windows* is empty.
    """
    if not windows:
        return build_context_window(
            created_at       = created_at,
            investigation_id = investigation_id,
            conversation_id  = conversation_id,
            items            = [],
            validate         = False,
        )

    # Canonical order for determinism
    ordered_windows = sorted(windows, key=lambda w: w.windowId)

    # Resolve IDs: use first window's values if caller didn't override
    inv_id  = investigation_id or ordered_windows[0].investigationId
    conv_id = conversation_id  or ordered_windows[0].conversationId

    # Collect all items
    all_items: List[ContextItem] = [
        item
        for w in ordered_windows
        for item in w.items
    ]

    if deduplicate:
        all_items = deduplicate_context_items(all_items)

    new_window = build_context_window(
        created_at       = created_at,
        investigation_id = inv_id,
        conversation_id  = conv_id,
        items            = all_items,
        validate         = False,
    )

    _log.info(
        "window_merged",
        extra={
            "sourceWindowCount" : len(ordered_windows),
            "mergedItemCount"   : len(new_window.items),
            "deduplicated"      : deduplicate,
            "windowKey"         : new_window.windowKey,
        },
    )
    return new_window


def deduplicate_context_items(
    items: List[ContextItem],
) -> List[ContextItem]:
    """
    Remove duplicate ContextItem objects, keeping the single best
    representative per contextItemKey.

    "Best" = highest importanceScore; ties broken by confidence DESC,
    then contextItemId ASC for full determinism.

    Parameters
    ----------
    items : list of ContextItem objects (may contain duplicates).

    Returns
    -------
    New list with one item per contextItemKey, order preserved by the
    chosen representative's natural sort (priority ASC, importance DESC,
    id ASC) — i.e. the same order build_context_window() would apply.
    """
    best: Dict[str, ContextItem] = {}
    for item in items:
        key = item.contextItemKey
        if key not in best:
            best[key] = item
        else:
            existing = best[key]
            # Keep the one with higher importanceScore
            if (
                item.importanceScore > existing.importanceScore
                or (
                    item.importanceScore == existing.importanceScore
                    and item.confidence > existing.confidence
                )
                or (
                    item.importanceScore == existing.importanceScore
                    and item.confidence == existing.confidence
                    and item.contextItemId < existing.contextItemId
                )
            ):
                best[key] = item

    # Return in canonical window sort order
    return sorted(
        best.values(),
        key=lambda i: (
            _PRIORITY_ORDER.get(i.priority, 99),
            -i.importanceScore,
            i.contextItemId,
        ),
    )


def build_execution_context(
    window     : ContextWindow,
    sources    : Optional[List[ContextSourceEnum]] = None,
    priorities : Optional[List[ContextPriorityEnum]] = None,
    min_importance : float = 0.0,
    min_confidence : float = 0.0,
) -> ContextWindow:
    """
    Derive an execution-ready ContextWindow by filtering the input window
    to the most relevant items.

    All four filter parameters are ANDed together.  Omitting a parameter
    (None / 0.0) disables that filter.

    Parameters
    ----------
    window         : source ContextWindow.
    sources        : if given, keep only items whose source is in this list.
    priorities     : if given, keep only items whose priority is in this list.
    min_importance : keep items with importanceScore >= this value (default 0.0).
    min_confidence : keep items with confidence >= this value (default 0.0).

    Returns
    -------
    New ContextWindow with the filtered item set (fully re-sorted).
    """
    filtered = list(window.items)

    if sources:
        src_set = set(sources)
        filtered = [i for i in filtered if i.source in src_set]

    if priorities:
        pri_set = set(priorities)
        filtered = [i for i in filtered if i.priority in pri_set]

    if min_importance > 0.0:
        filtered = [i for i in filtered if i.importanceScore >= min_importance]

    if min_confidence > 0.0:
        filtered = [i for i in filtered if i.confidence >= min_confidence]

    return build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = filtered,
        validate         = False,
    )


# ===========================================================================
# A4.3.3 Part B — Retrieval
# ===========================================================================

def retrieve_by_source(
    window : ContextWindow,
    source : ContextSourceEnum,
) -> List[ContextItem]:
    """
    Return all items in *window* whose source matches *source*.

    Order is preserved from window.items (priority ASC, importance DESC, id ASC).

    Parameters
    ----------
    window : ContextWindow to search.
    source : ContextSourceEnum to filter by.

    Returns
    -------
    List[ContextItem] — may be empty.
    """
    return [i for i in window.items if i.source == source]


def retrieve_by_priority(
    window   : ContextWindow,
    priority : ContextPriorityEnum,
) -> List[ContextItem]:
    """
    Return all items in *window* whose priority matches *priority*.

    Order is preserved from window.items.

    Parameters
    ----------
    window   : ContextWindow to search.
    priority : ContextPriorityEnum to filter by.

    Returns
    -------
    List[ContextItem] — may be empty.
    """
    return [i for i in window.items if i.priority == priority]


def retrieve_by_reference(
    window       : ContextWindow,
    reference_id : str,
) -> List[ContextItem]:
    """
    Return all items in *window* whose referenceId matches *reference_id*.

    More than one item may share a referenceId (e.g. the same finding
    projected at different priorities).  Order is preserved from window.items.

    Parameters
    ----------
    window       : ContextWindow to search.
    reference_id : referenceId string to match (case-sensitive, exact).

    Returns
    -------
    List[ContextItem] — may be empty.
    """
    return [i for i in window.items if i.referenceId == reference_id]


# ===========================================================================
# A4.3.3 Part B — Item Utilities
# ===========================================================================

def sort_context_items(
    items     : List[ContextItem],
    by        : str  = "priority",
    ascending : bool = True,
) -> List[ContextItem]:
    """
    Sort a list of ContextItem objects by a named attribute.

    Supported keys
    --------------
    "priority"        — priority tier order (CRITICAL=0 … LOW=3); tie-break: importance DESC, id ASC.
    "importance"      — importanceScore; tie-break: confidence DESC, id ASC.
    "confidence"      — confidence; tie-break: importance DESC, id ASC.
    "source"          — source.value string; tie-break: importance DESC, id ASC.
    "title"           — title string; tie-break: id ASC.
    "tokenEstimate"   — integer; tie-break: importance DESC, id ASC.
    "createdAt"       — ISO-8601 string; tie-break: id ASC.

    Parameters
    ----------
    items     : list of ContextItem objects.
    by        : sort key (see above; default "priority").
    ascending : True = ascending (default); False = descending.

    Raises
    ------
    ValueError : if *by* is not a recognised key.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    _VALID = {
        "priority", "importance", "confidence",
        "source", "title", "tokenEstimate", "createdAt",
    }
    if by not in _VALID:
        raise ValueError(
            f"sort_context_items: unknown key '{by}'. Valid: {sorted(_VALID)}"
        )

    rev = not ascending

    if by == "priority":
        return sorted(
            items,
            key=lambda i: (_PRIORITY_ORDER.get(i.priority, 99), -i.importanceScore, i.contextItemId),
            reverse=rev,
        )
    if by == "importance":
        return sorted(
            items,
            key=lambda i: (i.importanceScore, -i.confidence, i.contextItemId),
            reverse=rev,
        )
    if by == "confidence":
        return sorted(
            items,
            key=lambda i: (i.confidence, -i.importanceScore, i.contextItemId),
            reverse=rev,
        )
    if by == "source":
        return sorted(
            items,
            key=lambda i: (i.source.value, -i.importanceScore, i.contextItemId),
            reverse=rev,
        )
    if by == "title":
        return sorted(
            items,
            key=lambda i: (i.title, i.contextItemId),
            reverse=rev,
        )
    if by == "tokenEstimate":
        return sorted(
            items,
            key=lambda i: (i.tokenEstimate, -i.importanceScore, i.contextItemId),
            reverse=rev,
        )
    # createdAt
    return sorted(
        items,
        key=lambda i: (i.createdAt, i.contextItemId),
        reverse=rev,
    )


def filter_context_items(
    items           : List[ContextItem],
    source          : Optional[ContextSourceEnum]   = None,
    priority        : Optional[ContextPriorityEnum] = None,
    min_importance  : Optional[float]               = None,
    max_importance  : Optional[float]               = None,
    min_confidence  : Optional[float]               = None,
    max_confidence  : Optional[float]               = None,
    reference_id    : Optional[str]                 = None,
    title_contains  : Optional[str]                 = None,
    min_tokens      : Optional[int]                 = None,
    max_tokens      : Optional[int]                 = None,
) -> List[ContextItem]:
    """
    Filter a list of ContextItem objects by one or more criteria (all ANDed).

    Parameters
    ----------
    items          : list of ContextItem objects.
    source         : keep only items with this source.
    priority       : keep only items with this priority.
    min_importance : keep items with importanceScore >= this value.
    max_importance : keep items with importanceScore <= this value.
    min_confidence : keep items with confidence >= this value.
    max_confidence : keep items with confidence <= this value.
    reference_id   : keep only items with this exact referenceId.
    title_contains : keep only items whose title contains this substring
                     (case-insensitive).
    min_tokens     : keep items with tokenEstimate >= this value.
    max_tokens     : keep items with tokenEstimate <= this value.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[ContextItem] = []
    for item in items:
        if source          is not None and item.source   != source:
            continue
        if priority        is not None and item.priority != priority:
            continue
        if min_importance  is not None and item.importanceScore < min_importance:
            continue
        if max_importance  is not None and item.importanceScore > max_importance:
            continue
        if min_confidence  is not None and item.confidence < min_confidence:
            continue
        if max_confidence  is not None and item.confidence > max_confidence:
            continue
        if reference_id    is not None and item.referenceId != reference_id:
            continue
        if title_contains  is not None and title_contains.lower() not in item.title.lower():
            continue
        if min_tokens      is not None and item.tokenEstimate < min_tokens:
            continue
        if max_tokens      is not None and item.tokenEstimate > max_tokens:
            continue
        result.append(item)
    return result


def group_context_items(
    items    : List[ContextItem],
    group_by : str = "source",
) -> Dict[str, List[ContextItem]]:
    """
    Group ContextItem objects by a named attribute.

    Supported keys: "source", "priority".
    Each group is sorted in canonical window order (priority ASC,
    importance DESC, id ASC).

    Parameters
    ----------
    items    : list of ContextItem objects.
    group_by : "source" (default) | "priority".

    Raises
    ------
    ValueError : if *group_by* is not a recognised key.

    Returns
    -------
    Dict[str, List[ContextItem]] — each group sorted canonically.
    """
    _VALID = {"source", "priority"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_context_items: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )

    groups: Dict[str, List[ContextItem]] = {}
    for item in items:
        key = item.source.value if group_by == "source" else item.priority.value
        groups.setdefault(key, []).append(item)

    # Sort each group canonically
    return {
        k: sort_context_items(v, by="priority")
        for k, v in groups.items()
    }


def find_context_item(
    items    : List[ContextItem],
    item_key : str,
) -> Optional[ContextItem]:
    """
    Find the first ContextItem whose contextItemKey equals *item_key*.

    Parameters
    ----------
    items    : list of ContextItem objects to search.
    item_key : contextItemKey to match (exact).

    Returns
    -------
    ContextItem if found, else None.
    """
    for item in items:
        if item.contextItemKey == item_key:
            return item
    return None


# ===========================================================================
# A4.3.3 Part B — Window Utilities
# ===========================================================================

def sort_context_windows(
    windows   : List[ContextWindow],
    by        : str  = "createdAt",
    ascending : bool = True,
) -> List[ContextWindow]:
    """
    Sort a list of ContextWindow objects by a named attribute.

    Supported keys
    --------------
    "createdAt"          — ISO-8601 creation timestamp; tie-break: windowId ASC.
    "totalTokenEstimate" — total token count; tie-break: windowId ASC.
    "itemCount"          — number of items; tie-break: windowId ASC.
    "windowId"           — deterministic UUID string; no tie-break needed.
    "windowKey"          — 32-char SHA-256 key; no tie-break needed.
    "contextFingerprint" — 32-char fingerprint; no tie-break needed.

    Parameters
    ----------
    windows   : list of ContextWindow objects.
    by        : sort key (see above; default "createdAt").
    ascending : True = ascending (default); False = descending.

    Raises
    ------
    ValueError : if *by* is not a recognised key.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    _VALID = {
        "createdAt", "totalTokenEstimate", "itemCount",
        "windowId", "windowKey", "contextFingerprint",
    }
    if by not in _VALID:
        raise ValueError(
            f"sort_context_windows: unknown key '{by}'. Valid: {sorted(_VALID)}"
        )

    rev = not ascending

    _key_map = {
        "createdAt"          : lambda w: (w.createdAt,          w.windowId),
        "totalTokenEstimate" : lambda w: (w.totalTokenEstimate, w.windowId),
        "itemCount"          : lambda w: (len(w.items),         w.windowId),
        "windowId"           : lambda w: w.windowId,
        "windowKey"          : lambda w: w.windowKey,
        "contextFingerprint" : lambda w: w.contextFingerprint,
    }
    return sorted(windows, key=_key_map[by], reverse=rev)


def filter_context_windows(
    windows              : List[ContextWindow],
    investigation_id     : Optional[str] = None,
    conversation_id      : Optional[str] = None,
    min_items            : Optional[int] = None,
    max_items            : Optional[int] = None,
    min_token_estimate   : Optional[int] = None,
    max_token_estimate   : Optional[int] = None,
    has_source           : Optional[ContextSourceEnum] = None,
    has_priority         : Optional[ContextPriorityEnum] = None,
) -> List[ContextWindow]:
    """
    Filter a list of ContextWindow objects by one or more criteria (all ANDed).

    Parameters
    ----------
    windows            : list of ContextWindow objects.
    investigation_id   : keep only windows with this investigationId.
    conversation_id    : keep only windows with this conversationId.
    min_items          : keep windows with len(items) >= this value.
    max_items          : keep windows with len(items) <= this value.
    min_token_estimate : keep windows with totalTokenEstimate >= this value.
    max_token_estimate : keep windows with totalTokenEstimate <= this value.
    has_source         : keep only windows that contain at least one item
                         with this source.
    has_priority       : keep only windows that contain at least one item
                         with this priority.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[ContextWindow] = []
    for w in windows:
        if investigation_id   is not None and w.investigationId != investigation_id:
            continue
        if conversation_id    is not None and w.conversationId  != conversation_id:
            continue
        if min_items          is not None and len(w.items) < min_items:
            continue
        if max_items          is not None and len(w.items) > max_items:
            continue
        if min_token_estimate is not None and w.totalTokenEstimate < min_token_estimate:
            continue
        if max_token_estimate is not None and w.totalTokenEstimate > max_token_estimate:
            continue
        if has_source         is not None:
            if not any(i.source == has_source for i in w.items):
                continue
        if has_priority       is not None:
            if not any(i.priority == has_priority for i in w.items):
                continue
        result.append(w)
    return result


def group_context_windows(
    windows  : List[ContextWindow],
    group_by : str = "investigationId",
) -> Dict[str, List[ContextWindow]]:
    """
    Group ContextWindow objects by a string attribute.

    Supported keys: "investigationId", "conversationId".
    Each group is sorted by createdAt ASC, then windowId ASC.

    Parameters
    ----------
    windows  : list of ContextWindow objects.
    group_by : "investigationId" (default) | "conversationId".

    Raises
    ------
    ValueError : if *group_by* is not a recognised key.

    Returns
    -------
    Dict[str, List[ContextWindow]] — each group sorted chronologically.
    """
    _VALID = {"investigationId", "conversationId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_context_windows: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )

    groups: Dict[str, List[ContextWindow]] = {}
    for w in windows:
        key = w.investigationId if group_by == "investigationId" else w.conversationId
        groups.setdefault(key, []).append(w)

    return {
        k: sort_context_windows(v, by="createdAt", ascending=True)
        for k, v in groups.items()
    }


def find_context_window(
    windows    : List[ContextWindow],
    window_key : str,
) -> Optional[ContextWindow]:
    """
    Find the first ContextWindow whose windowKey equals *window_key*.

    Parameters
    ----------
    windows    : list of ContextWindow objects to search.
    window_key : windowKey to match (exact, 32-char SHA-256 key).

    Returns
    -------
    ContextWindow if found, else None.
    """
    for w in windows:
        if w.windowKey == window_key:
            return w
    return None


# ===========================================================================
# A4.3.3 Part B — Extended build_context_statistics()
#
# The original build_context_statistics() (Part A) is retained exactly.
# This section re-exports a richer variant that uses the new Part B
# operations to populate per-source and per-priority breakdowns via
# group_context_items(), making the statistics consistent with the
# ranking/retrieval layer.
# ===========================================================================

def _build_context_statistics_extended(
    windows: List[ContextWindow],
) -> ContextStatistics:
    """
    Drop-in replacement for build_context_statistics() that populates
    itemsBySource and itemsByPriority using group_context_items() so that
    the counters are always consistent with the grouping logic in Part B.

    This is the canonical implementation.  build_context_statistics() now
    delegates here.
    """
    items_by_source:   Dict[str, int] = {s.value: 0 for s in ContextSourceEnum}
    items_by_priority: Dict[str, int] = {p.value: 0 for p in ContextPriorityEnum}

    if not windows:
        return ContextStatistics(
            totalWindows      = 0,
            totalItems        = 0,
            averageTokens     = 0.0,
            averageImportance = 0.0,
            averageConfidence = 0.0,
            itemsBySource     = items_by_source,
            itemsByPriority   = items_by_priority,
        )

    ordered = sorted(windows, key=lambda w: w.windowId)
    n       = len(ordered)

    all_items: List[ContextItem] = [
        item for win in ordered for item in win.items
    ]
    n_items   = len(all_items)
    token_sum = sum(w.totalTokenEstimate for w in ordered)

    # Use group_context_items() to count by source and priority
    by_source   = group_context_items(all_items, group_by="source")
    by_priority = group_context_items(all_items, group_by="priority")

    for src_key, src_items in by_source.items():
        items_by_source[src_key] = len(src_items)

    for pri_key, pri_items in by_priority.items():
        items_by_priority[pri_key] = len(pri_items)

    if n_items > 0:
        avg_importance = round(sum(i.importanceScore for i in all_items) / n_items, 6)
        avg_confidence = round(sum(i.confidence      for i in all_items) / n_items, 6)
    else:
        avg_importance = 0.0
        avg_confidence = 0.0

    return ContextStatistics(
        totalWindows      = n,
        totalItems        = n_items,
        averageTokens     = round(token_sum / n, 4),
        averageImportance = avg_importance,
        averageConfidence = avg_confidence,
        itemsBySource     = items_by_source,
        itemsByPriority   = items_by_priority,
    )


# Patch build_context_statistics to delegate to the extended implementation
# so that callers importing the original name get the richer version.
def build_context_statistics(  # type: ignore[no-redef]
    windows: List[ContextWindow],
) -> ContextStatistics:
    """
    Compute ContextStatistics over a list of ContextWindow objects.

    Delegates to the extended implementation which uses the Part B
    group_context_items() for consistent source/priority counts.

    Parameters
    ----------
    windows : any list of ContextWindow objects.

    Returns
    -------
    ContextStatistics (frozen / immutable)
    """
    return _build_context_statistics_extended(windows)
