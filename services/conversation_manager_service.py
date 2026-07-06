"""
Conversation Manager Engine
============================
Phase A4.4.0 — Deterministic, immutable conversation and thread management.

Responsibilities
----------------
- Model conversations as ordered message collections grouped into threads.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute conversation fingerprints for cache/replay stability.
- Expose builder functions: build_message, build_thread, build_metadata,
  build_conversation, build_statistics.
- Expose validation functions: validate_message, validate_thread,
  validate_conversation.
- Integrate with ai_execution_service, prompt_assembly_service, and
  copilot_orchestrator_service as upstream/downstream context providers.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs -> same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No database. No provider. No HTTP.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import CONVERSATION_MANAGER_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("conversation_manager_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_CONV_NS = uuid.UUID("6ba7b831-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# Approximate chars-per-token ratio (conservative GPT-style estimate)
# ---------------------------------------------------------------------------
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Enumerations (immutable)
# ===========================================================================

class ConversationRole(str, Enum):
    """Role of a message author within a conversation."""
    SYSTEM    = "SYSTEM"
    USER      = "USER"
    ASSISTANT = "ASSISTANT"
    TOOL      = "TOOL"


class ConversationState(str, Enum):
    """Lifecycle state of a conversation."""
    ACTIVE    = "ACTIVE"
    PAUSED    = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED  = "ARCHIVED"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ConversationManagerError(Exception):
    """Base class for all Conversation Manager Engine errors."""


class InvalidMessageError(ConversationManagerError):
    """Raised when a message fails validation."""


class InvalidThreadError(ConversationManagerError):
    """Raised when a thread fails validation."""


class InvalidConversationError(ConversationManagerError):
    """Raised when a conversation fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ConversationMessage(BaseModel):
    """
    One immutable message within a conversation.

    Identity
    --------
    messageId  : UUIDv5(_CONV_NS, messageKey) — deterministic.
    messageKey : SHA256(conversationId + role + content[:64] +
                        str(sequenceNumber))[:32]

    Fields
    ------
    messageId        : deterministic UUID derived from messageKey.
    messageKey       : 32-char SHA-256 key.
    conversationId   : owning conversation ID.
    parentMessageId  : parent message ID (empty string = root message).
    role             : ConversationRole of the message author.
    content          : message text content.
    sequenceNumber   : 1-based ordering position within the conversation.
    tokenEstimate    : estimated token count for this message's content.
    metadata         : arbitrary key→value extension bag.
    createdAt        : ISO-8601 timestamp (caller-supplied for determinism).
    """
    messageId       : str
    messageKey      : str
    conversationId  : str
    parentMessageId : str
    role            : ConversationRole
    content         : str
    sequenceNumber  : int
    tokenEstimate   : int
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class ConversationThread(BaseModel):
    """
    An immutable thread grouping a sub-sequence of messages.

    Fields
    ------
    threadId       : UUIDv5(_CONV_NS, threadKey) — deterministic.
    threadKey      : SHA256(conversationId + rootMessageId +
                            sorted(messageIds))[:32]
    rootMessageId  : the messageId at the root of this thread.
    messageIds     : sorted tuple of message IDs belonging to this thread.
    depth          : nesting depth of this thread (0 = top-level).
    createdAt      : ISO-8601 timestamp (caller-supplied for determinism).
    """
    threadId      : str
    threadKey     : str
    rootMessageId : str
    messageIds    : Tuple[str, ...]
    depth         : int
    createdAt     : str

    class Config:
        frozen = True


class ConversationMetadata(BaseModel):
    """
    Provenance and aggregate metadata for one conversation.

    Fields
    ------
    title          : human-readable conversation title.
    summary        : optional summary of the conversation content.
    totalMessages  : count of messages in the conversation.
    totalTokens    : sum of tokenEstimate across all messages.
    lastMessageAt  : ISO-8601 timestamp of the most recent message.
    createdBy      : analyst / system identifier that started the conversation.
    tags           : sorted tuple of lowercase tag strings.
    engineVersion  : CONVERSATION_MANAGER_ENGINE_VERSION at build time.
    """
    title         : str
    summary       : str
    totalMessages : int
    totalTokens   : int
    lastMessageAt : str
    createdBy     : str
    tags          : Tuple[str, ...]
    engineVersion : str

    class Config:
        frozen = True


class Conversation(BaseModel):
    """
    The complete, immutable conversation record.

    Identity
    --------
    conversationId          : UUIDv5(_CONV_NS, conversationKey) — deterministic.
    conversationKey         : SHA256(investigationId + createdBy + title)[:32]
    conversationFingerprint : SHA256(conversationKey + sorted(messageKeys) +
                                     sorted(threadKeys))[:32]

    Fields
    ------
    conversationId          : deterministic UUID.
    conversationKey         : 32-char SHA-256 key.
    investigationId         : owning investigation ID (may be empty).
    state                   : ConversationState lifecycle state.
    messages                : tuple of ConversationMessage sorted by sequenceNumber.
    threads                 : tuple of ConversationThread.
    metadata                : ConversationMetadata provenance record.
    conversationFingerprint : deterministic content fingerprint.
    createdAt               : ISO-8601 timestamp.
    updatedAt               : ISO-8601 timestamp.
    """
    conversationId          : str
    conversationKey         : str
    investigationId         : str
    state                   : ConversationState
    messages                : Tuple[ConversationMessage, ...]
    threads                 : Tuple[ConversationThread, ...]
    metadata                : ConversationMetadata
    conversationFingerprint : str
    createdAt               : str
    updatedAt               : str

    class Config:
        frozen = True


class ConversationStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Conversation objects.

    Fields
    ------
    totalConversations   : total count.
    activeConversations  : count in ACTIVE state.
    archivedConversations: count in ARCHIVED state.
    averageMessages      : mean message count per conversation (0.0 when empty).
    averageTokens        : mean token count per conversation (0.0 when empty).
    longestConversation  : highest message count across all conversations.
    totalThreads         : sum of thread counts across all conversations.
    """
    totalConversations    : int
    activeConversations   : int
    archivedConversations : int
    averageMessages       : float
    averageTokens         : float
    longestConversation   : int
    totalThreads          : int

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
    """UUIDv5(_CONV_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_CONV_NS, key))


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


def _estimate_tokens(text: str) -> int:
    """Ceiling(len(text) / 4) — standard 4-chars-per-token estimate."""
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))


# ---------------------------------------------------------------------------
# Key derivation functions
# ---------------------------------------------------------------------------

def _compute_message_key(
    conversation_id : str,
    role            : str,
    content         : str,
    sequence_number : int,
) -> str:
    """
    messageKey = SHA256(conversationId + role + content[:64] +
                        str(sequenceNumber))[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        role.upper().strip(),
        content[:64],
        str(int(sequence_number)),
    )


def _compute_thread_key(
    conversation_id : str,
    root_message_id : str,
    message_ids     : Tuple[str, ...],
) -> str:
    """
    threadKey = SHA256(conversationId + rootMessageId +
                       sorted(messageIds))[:32]
    """
    return _sha256_32(
        conversation_id.strip(),
        root_message_id.strip(),
        "\x01".join(sorted(message_ids)),
    )


def _compute_conversation_key(
    investigation_id: str,
    created_by      : str,
    title           : str,
) -> str:
    """
    conversationKey = SHA256(investigationId + createdBy + title)[:32]
    """
    return _sha256_32(
        investigation_id.strip(),
        created_by.strip(),
        title.strip(),
    )


def _compute_conversation_fingerprint(
    conversation_key: str,
    message_keys    : Tuple[str, ...],
    thread_keys     : Tuple[str, ...],
) -> str:
    """
    conversationFingerprint = SHA256(conversationKey +
                                     sorted(messageKeys) +
                                     sorted(threadKeys))[:32]
    """
    return _sha256_32(
        conversation_key,
        "\x01".join(sorted(message_keys)),
        "\x01".join(sorted(thread_keys)),
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_message(
    conversation_id : str,
    role            : ConversationRole,
    content         : str,
    sequence_number : int,
    created_at      : str,
) -> None:
    """
    Validate ConversationMessage construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - role is a valid ConversationRole member.
    - content is a string (may be empty for tool placeholder messages).
    - sequence_number >= 1.
    - created_at is a non-empty string.

    Raises
    ------
    InvalidMessageError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not isinstance(role, ConversationRole):
        errors.append(f"role must be a ConversationRole member; got {role!r}.")
    if content is None:
        errors.append("content must not be None.")
    if not isinstance(sequence_number, int) or sequence_number < 1:
        errors.append(
            f"sequenceNumber={sequence_number!r} must be an integer >= 1."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        raise InvalidMessageError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_thread(
    conversation_id : str,
    root_message_id : str,
    message_ids     : Tuple[str, ...],
    depth           : int,
    created_at      : str,
) -> None:
    """
    Validate ConversationThread construction parameters.

    Checks
    ------
    - conversation_id is non-empty.
    - root_message_id is non-empty.
    - message_ids is a non-empty sequence.
    - root_message_id is present in message_ids.
    - depth >= 0.
    - created_at is a non-empty string.

    Raises
    ------
    InvalidThreadError : if any rule is violated.
    """
    errors: List[str] = []

    if not conversation_id or not conversation_id.strip():
        errors.append("conversationId must not be empty.")
    if not root_message_id or not root_message_id.strip():
        errors.append("rootMessageId must not be empty.")
    if not message_ids:
        errors.append("messageIds must not be empty.")
    if root_message_id and message_ids and root_message_id.strip() not in message_ids:
        errors.append(
            f"rootMessageId '{root_message_id}' must be present in messageIds."
        )
    if not isinstance(depth, int) or depth < 0:
        errors.append(f"depth={depth!r} must be an integer >= 0.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        raise InvalidThreadError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_conversation(
    investigation_id: str,
    created_by      : str,
    title           : str,
    created_at      : str,
    state           : ConversationState,
) -> None:
    """
    Validate Conversation construction parameters.

    Checks
    ------
    - created_by is non-empty.
    - title is non-empty.
    - created_at is non-empty.
    - state is a valid ConversationState member.

    Note: investigation_id may be empty (conversation not yet linked).

    Raises
    ------
    InvalidConversationError : if any rule is violated.
    """
    errors: List[str] = []

    if not created_by or not created_by.strip():
        errors.append("createdBy must not be empty.")
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")
    if not isinstance(state, ConversationState):
        errors.append(f"state must be a ConversationState member; got {state!r}.")

    if errors:
        raise InvalidConversationError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_message()
# ===========================================================================

def build_message(
    conversation_id  : str,
    role             : ConversationRole,
    content          : str,
    sequence_number  : int,
    created_at       : str,
    parent_message_id: str                      = "",
    metadata         : Optional[Dict[str, Any]] = None,
    validate         : bool                     = True,
) -> ConversationMessage:
    """
    Build an immutable ConversationMessage.

    messageKey = SHA256(conversationId + role + content[:64] +
                        str(sequenceNumber))[:32]
    messageId  = UUIDv5(_CONV_NS, messageKey)

    Parameters
    ----------
    conversation_id   : owning conversation ID.
    role              : ConversationRole of the author.
    content           : message text (may be empty for tool placeholders).
    sequence_number   : 1-based position; must be >= 1.
    created_at        : ISO-8601 timestamp (caller-supplied for determinism).
    parent_message_id : ID of the parent message ("" = root).
    metadata          : arbitrary extension dict; copied, never mutated.
    validate          : if True, run validate_message() first.

    Returns
    -------
    ConversationMessage (frozen / immutable)

    Raises
    ------
    InvalidMessageError : if validate=True and validation fails.
    """
    if validate:
        validate_message(conversation_id, role, content, sequence_number, created_at)

    msg_key = _compute_message_key(
        conversation_id, role.value, content, sequence_number
    )
    msg_id = _uuid5(msg_key)

    return ConversationMessage(
        messageId       = msg_id,
        messageKey      = msg_key,
        conversationId  = conversation_id.strip(),
        parentMessageId = parent_message_id.strip(),
        role            = role,
        content         = content,
        sequenceNumber  = int(sequence_number),
        tokenEstimate   = _estimate_tokens(content),
        metadata        = dict(metadata) if metadata else {},
        createdAt       = created_at,
    )


# ===========================================================================
# Builder: build_thread()
# ===========================================================================

def build_thread(
    conversation_id : str,
    root_message_id : str,
    message_ids     : List[str],
    created_at      : str,
    depth           : int  = 0,
    validate        : bool = True,
) -> ConversationThread:
    """
    Build an immutable ConversationThread.

    threadKey = SHA256(conversationId + rootMessageId +
                       sorted(messageIds))[:32]
    threadId  = UUIDv5(_CONV_NS, threadKey)

    Parameters
    ----------
    conversation_id : owning conversation ID.
    root_message_id : messageId at the root of this thread.
    message_ids     : all message IDs belonging to this thread.
    created_at      : ISO-8601 timestamp.
    depth           : nesting depth (0 = top-level thread).
    validate        : if True, run validate_thread() first.

    Returns
    -------
    ConversationThread (frozen / immutable)

    Raises
    ------
    InvalidThreadError : if validate=True and validation fails.
    """
    norm_ids: Tuple[str, ...] = _norm_strings(message_ids)

    if validate:
        validate_thread(
            conversation_id, root_message_id, norm_ids,
            depth, created_at,
        )

    thread_key = _compute_thread_key(conversation_id, root_message_id, norm_ids)
    thread_id  = _uuid5(thread_key)

    return ConversationThread(
        threadId      = thread_id,
        threadKey     = thread_key,
        rootMessageId = root_message_id.strip(),
        messageIds    = norm_ids,
        depth         = max(0, int(depth)),
        createdAt     = created_at,
    )


# ===========================================================================
# Builder: build_metadata()
# ===========================================================================

def build_metadata(
    title           : str,
    created_by      : str,
    messages        : Tuple[ConversationMessage, ...],
    created_at      : str,
    summary         : str                  = "",
    tags            : Optional[List[str]]  = None,
) -> ConversationMetadata:
    """
    Build a ConversationMetadata record from message totals.

    Parameters
    ----------
    title       : human-readable conversation title.
    created_by  : originating analyst / system identifier.
    messages    : the final message tuple (used to compute totals).
    created_at  : ISO-8601 fallback for lastMessageAt when messages is empty.
    summary     : optional summary text.
    tags        : classification tags (deduped + lowercase + sorted).

    Returns
    -------
    ConversationMetadata (frozen / immutable)
    """
    total_messages = len(messages)
    total_tokens   = sum(m.tokenEstimate for m in messages)

    if messages:
        # Use the createdAt of the highest-sequence message as lastMessageAt
        last_msg = max(messages, key=lambda m: (m.sequenceNumber, m.messageId))
        last_message_at = last_msg.createdAt
    else:
        last_message_at = created_at

    return ConversationMetadata(
        title         = title.strip(),
        summary       = summary,
        totalMessages = total_messages,
        totalTokens   = total_tokens,
        lastMessageAt = last_message_at,
        createdBy     = created_by.strip(),
        tags          = _norm_tags(tags),
        engineVersion = CONVERSATION_MANAGER_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_conversation()
# ===========================================================================

def build_conversation(
    created_by      : str,
    title           : str,
    created_at      : str,
    investigation_id: str                      = "",
    state           : ConversationState        = ConversationState.ACTIVE,
    messages        : Optional[List[ConversationMessage]]  = None,
    threads         : Optional[List[ConversationThread]]   = None,
    summary         : str                      = "",
    tags            : Optional[List[str]]      = None,
    validate        : bool                     = True,
) -> Conversation:
    """
    Assemble a complete, immutable Conversation.

    conversationKey         = SHA256(investigationId + createdBy + title)[:32]
    conversationId          = UUIDv5(_CONV_NS, conversationKey)
    conversationFingerprint = SHA256(conversationKey +
                                     sorted(messageKeys) +
                                     sorted(threadKeys))[:32]

    Parameters
    ----------
    created_by       : analyst / system identifier.
    title            : human-readable conversation title.
    created_at       : ISO-8601 creation timestamp.
    investigation_id : owning investigation ID (may be empty if not linked).
    state            : initial ConversationState (default ACTIVE).
    messages         : list of ConversationMessage objects.
    threads          : list of ConversationThread objects.
    summary          : optional summary text.
    tags             : classification tags.
    validate         : if True, run validate_conversation() first.

    Returns
    -------
    Conversation (frozen / immutable)

    Raises
    ------
    InvalidConversationError : if validate=True and validation fails.
    """
    if validate:
        validate_conversation(investigation_id, created_by, title, created_at, state)

    # Sort messages by sequenceNumber ASC, tie-break by messageId ASC
    sorted_messages: Tuple[ConversationMessage, ...] = tuple(
        sorted(
            messages or [],
            key=lambda m: (m.sequenceNumber, m.messageId),
        )
    )

    # Sort threads by threadId ASC for determinism
    sorted_threads: Tuple[ConversationThread, ...] = tuple(
        sorted(threads or [], key=lambda t: t.threadId)
    )

    conv_key = _compute_conversation_key(investigation_id, created_by, title)
    conv_id  = _uuid5(conv_key)

    message_keys: Tuple[str, ...] = tuple(m.messageKey for m in sorted_messages)
    thread_keys:  Tuple[str, ...] = tuple(t.threadKey  for t in sorted_threads)

    conv_fp = _compute_conversation_fingerprint(conv_key, message_keys, thread_keys)

    meta = build_metadata(
        title       = title,
        created_by  = created_by,
        messages    = sorted_messages,
        created_at  = created_at,
        summary     = summary,
        tags        = tags,
    )

    return Conversation(
        conversationId          = conv_id,
        conversationKey         = conv_key,
        investigationId         = investigation_id.strip(),
        state                   = state,
        messages                = sorted_messages,
        threads                 = sorted_threads,
        metadata                = meta,
        conversationFingerprint = conv_fp,
        createdAt               = created_at,
        updatedAt               = created_at,
    )


# ===========================================================================
# Builder: build_statistics()
# ===========================================================================

def build_statistics(
    conversations: List[Conversation],
) -> ConversationStatistics:
    """
    Compute ConversationStatistics over a list of Conversation objects.

    Deterministic: canonical sort (by conversationId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    conversations : any list of Conversation objects.

    Returns
    -------
    ConversationStatistics (frozen / immutable)
    """
    if not conversations:
        return ConversationStatistics(
            totalConversations    = 0,
            activeConversations   = 0,
            archivedConversations = 0,
            averageMessages       = 0.0,
            averageTokens         = 0.0,
            longestConversation   = 0,
            totalThreads          = 0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(conversations, key=lambda c: c.conversationId)
    n = len(ordered)

    active_count   = sum(1 for c in ordered if c.state == ConversationState.ACTIVE)
    archived_count = sum(1 for c in ordered if c.state == ConversationState.ARCHIVED)
    msg_counts     = [c.metadata.totalMessages for c in ordered]
    token_counts   = [c.metadata.totalTokens   for c in ordered]
    thread_total   = sum(len(c.threads) for c in ordered)

    return ConversationStatistics(
        totalConversations    = n,
        activeConversations   = active_count,
        archivedConversations = archived_count,
        averageMessages       = round(sum(msg_counts)   / n, 4),
        averageTokens         = round(sum(token_counts) / n, 4),
        longestConversation   = max(msg_counts),
        totalThreads          = thread_total,
    )


# ===========================================================================
# Integration helpers — context bridges to upstream/downstream services
# ===========================================================================

def messages_to_execution_prompts(
    messages: Tuple[ConversationMessage, ...],
) -> Tuple[str, str]:
    """
    Convert a message sequence into (system_prompt, user_prompt) strings
    suitable for ai_execution_service.build_execution_request().

    Rules
    -----
    - SYSTEM role messages are joined (newline-separated) to form system_prompt.
    - USER, ASSISTANT, and TOOL messages are joined as a dialogue transcript
      formatted as "<ROLE>: <content>" entries in user_prompt.
    - Messages are processed in sequenceNumber ASC order.
    - Returns ("", "") when messages is empty.

    Parameters
    ----------
    messages : tuple of ConversationMessage, ordered by sequenceNumber.

    Returns
    -------
    (system_prompt, user_prompt) — both plain strings.
    """
    sorted_msgs = sorted(messages, key=lambda m: (m.sequenceNumber, m.messageId))

    system_parts: List[str] = []
    dialogue_parts: List[str] = []

    for msg in sorted_msgs:
        if msg.role == ConversationRole.SYSTEM:
            if msg.content:
                system_parts.append(msg.content)
        else:
            prefix = msg.role.value  # "USER" | "ASSISTANT" | "TOOL"
            dialogue_parts.append(f"{prefix}: {msg.content}")

    system_prompt = "\n".join(system_parts)
    user_prompt   = "\n".join(dialogue_parts)

    return system_prompt, user_prompt


def conversation_to_prompt_sections(
    conversation: Conversation,
) -> List[Dict[str, Any]]:
    """
    Convert a Conversation into a list of section descriptors compatible
    with prompt_assembly_service.build_prompt_section().

    Each section descriptor is a plain dict with keys:
        title    : "<ROLE> Message <sequenceNumber>"
        content  : message.content
        priority : 90 for SYSTEM, 70 for USER, 50 for ASSISTANT, 30 for TOOL

    Sections are ordered by sequenceNumber ASC.

    Parameters
    ----------
    conversation : source Conversation object.

    Returns
    -------
    List of dicts; one per message.  Caller passes each to build_prompt_section().
    """
    _PRIORITY_MAP = {
        ConversationRole.SYSTEM    : 90,
        ConversationRole.USER      : 70,
        ConversationRole.ASSISTANT : 50,
        ConversationRole.TOOL      : 30,
    }

    result: List[Dict[str, Any]] = []
    sorted_msgs = sorted(
        conversation.messages,
        key=lambda m: (m.sequenceNumber, m.messageId),
    )

    for msg in sorted_msgs:
        result.append({
            "title"   : f"{msg.role.value} Message {msg.sequenceNumber}",
            "content" : msg.content,
            "priority": _PRIORITY_MAP.get(msg.role, 50),
        })

    return result


def conversation_to_copilot_context(
    conversation: Conversation,
) -> Dict[str, Any]:
    """
    Extract a context summary dict from a Conversation for use with
    copilot_orchestrator_service.build_copilot_request().

    Returns a plain dict with fields:
        conversationId          : str
        investigationId         : str
        state                   : str (ConversationState value)
        totalMessages           : int
        totalTokens             : int
        lastMessageAt           : str
        engineVersion           : str
        conversationFingerprint : str
        title                   : str
        summary                 : str

    Parameters
    ----------
    conversation : source Conversation object.

    Returns
    -------
    Dict[str, Any] — JSON-serialisable context summary.
    """
    return {
        "conversationId"          : conversation.conversationId,
        "investigationId"         : conversation.investigationId,
        "state"                   : conversation.state.value,
        "totalMessages"           : conversation.metadata.totalMessages,
        "totalTokens"             : conversation.metadata.totalTokens,
        "lastMessageAt"           : conversation.metadata.lastMessageAt,
        "engineVersion"           : conversation.metadata.engineVersion,
        "conversationFingerprint" : conversation.conversationFingerprint,
        "title"                   : conversation.metadata.title,
        "summary"                 : conversation.metadata.summary,
    }


# ===========================================================================
# Conversation Lifecycle Operations
# ===========================================================================

def add_message(
    conversation : Conversation,
    role         : ConversationRole,
    content      : str,
    updated_at   : str,
    parent_message_id : str                      = "",
    metadata          : Optional[Dict[str, Any]] = None,
) -> Conversation:
    """
    Return a new Conversation with one additional message appended.

    The new message is assigned sequenceNumber = max(existing) + 1.
    conversationFingerprint is recomputed from the updated message set.

    Parameters
    ----------
    conversation      : the source (immutable) Conversation.
    role              : ConversationRole of the new message.
    content           : message text.
    updated_at        : ISO-8601 timestamp used for the new message and updatedAt.
    parent_message_id : parent message ID (empty = root).
    metadata          : arbitrary extension dict.

    Returns
    -------
    Conversation — new immutable object with the message added.
    """
    next_seq = (
        max((m.sequenceNumber for m in conversation.messages), default=0) + 1
    )
    new_msg = build_message(
        conversation_id   = conversation.conversationId,
        role              = role,
        content           = content,
        sequence_number   = next_seq,
        created_at        = updated_at,
        parent_message_id = parent_message_id,
        metadata          = metadata,
    )
    new_msgs = list(conversation.messages) + [new_msg]
    _log.info(
        "message_added",
        extra={
            "conversationId": conversation.conversationId,
            "messageId"     : new_msg.messageId,
            "role"          : role.value,
            "sequenceNumber": next_seq,
        },
    )
    return _rebuild(conversation, messages=new_msgs, updated_at=updated_at)


def edit_message(
    conversation : Conversation,
    message_id   : str,
    new_content  : str,
    updated_at   : str,
) -> Conversation:
    """
    Return a new Conversation with one message's content replaced.

    The edited message gets a new messageKey/messageId derived from the
    updated content; all other fields are preserved.

    Parameters
    ----------
    conversation : source Conversation.
    message_id   : messageId of the message to edit.
    new_content  : replacement content string.
    updated_at   : ISO-8601 timestamp for updatedAt.

    Returns
    -------
    Conversation — new immutable object with message replaced.

    Raises
    ------
    InvalidMessageError : if message_id is not found.
    """
    target = next((m for m in conversation.messages if m.messageId == message_id), None)
    if target is None:
        raise InvalidMessageError(
            f"  - messageId '{message_id}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    replacement = build_message(
        conversation_id   = conversation.conversationId,
        role              = target.role,
        content           = new_content,
        sequence_number   = target.sequenceNumber,
        created_at        = target.createdAt,
        parent_message_id = target.parentMessageId,
        metadata          = dict(target.metadata),
    )
    new_msgs = [
        replacement if m.messageId == message_id else m
        for m in conversation.messages
    ]
    return _rebuild(conversation, messages=new_msgs, updated_at=updated_at)


def delete_message(
    conversation : Conversation,
    message_id   : str,
    updated_at   : str,
) -> Conversation:
    """
    Return a new Conversation with one message removed.

    Sequence numbers of remaining messages are NOT renumbered.

    Parameters
    ----------
    conversation : source Conversation.
    message_id   : messageId of the message to remove.
    updated_at   : ISO-8601 timestamp for updatedAt.

    Returns
    -------
    Conversation — new immutable object with message removed.

    Raises
    ------
    InvalidMessageError : if message_id is not found.
    """
    if not any(m.messageId == message_id for m in conversation.messages):
        raise InvalidMessageError(
            f"  - messageId '{message_id}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    new_msgs = [m for m in conversation.messages if m.messageId != message_id]
    return _rebuild(conversation, messages=new_msgs, updated_at=updated_at)


def move_message(
    conversation    : Conversation,
    message_id      : str,
    new_sequence    : int,
    updated_at      : str,
) -> Conversation:
    """
    Return a new Conversation with one message's sequenceNumber replaced.

    Only the target message's sequenceNumber changes; others are unchanged.

    Parameters
    ----------
    conversation : source Conversation.
    message_id   : messageId of the message to move.
    new_sequence : new sequenceNumber (must be >= 1).
    updated_at   : ISO-8601 timestamp for updatedAt.

    Returns
    -------
    Conversation — new immutable object with message moved.

    Raises
    ------
    InvalidMessageError : if message_id is not found or new_sequence < 1.
    """
    if not isinstance(new_sequence, int) or new_sequence < 1:
        raise InvalidMessageError(
            f"  - new_sequence={new_sequence!r} must be an integer >= 1."
        )
    target = next((m for m in conversation.messages if m.messageId == message_id), None)
    if target is None:
        raise InvalidMessageError(
            f"  - messageId '{message_id}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    moved = build_message(
        conversation_id   = conversation.conversationId,
        role              = target.role,
        content           = target.content,
        sequence_number   = new_sequence,
        created_at        = target.createdAt,
        parent_message_id = target.parentMessageId,
        metadata          = dict(target.metadata),
    )
    new_msgs = [
        moved if m.messageId == message_id else m
        for m in conversation.messages
    ]
    return _rebuild(conversation, messages=new_msgs, updated_at=updated_at)


# ---------------------------------------------------------------------------
# State-transition helpers
# ---------------------------------------------------------------------------

def _transition(
    conversation : Conversation,
    new_state    : ConversationState,
    updated_at   : str,
    log_event    : str,
) -> Conversation:
    """Internal: return conversation rebuilt with a new state."""
    result = _rebuild(conversation, state=new_state, updated_at=updated_at)
    _log.info(
        log_event,
        extra={
            "conversationId": conversation.conversationId,
            "fromState"     : conversation.state.value,
            "toState"       : new_state.value,
        },
    )
    return result


def archive_conversation(
    conversation : Conversation,
    updated_at   : str,
) -> Conversation:
    """
    Return a new Conversation in the ARCHIVED state.

    Logs ``conversation_archived``.
    """
    _log.info(
        "conversation_archived",
        extra={"conversationId": conversation.conversationId},
    )
    return _transition(conversation, ConversationState.ARCHIVED, updated_at, "conversation_archived")


def pause_conversation(
    conversation : Conversation,
    updated_at   : str,
) -> Conversation:
    """Return a new Conversation in the PAUSED state. Logs ``conversation_paused``."""
    return _transition(conversation, ConversationState.PAUSED, updated_at, "conversation_paused")


def resume_conversation(
    conversation : Conversation,
    updated_at   : str,
) -> Conversation:
    """Return a new Conversation in the ACTIVE state. Logs ``conversation_resumed``."""
    return _transition(conversation, ConversationState.ACTIVE, updated_at, "conversation_resumed")


def complete_conversation(
    conversation : Conversation,
    updated_at   : str,
) -> Conversation:
    """Return a new Conversation in the COMPLETED state."""
    return _transition(conversation, ConversationState.COMPLETED, updated_at, "conversation_completed")


# ===========================================================================
# Internal rebuild helper
# ===========================================================================

def _rebuild(
    conversation : Conversation,
    messages     : Optional[List[ConversationMessage]] = None,
    threads      : Optional[List[ConversationThread]]  = None,
    state        : Optional[ConversationState]         = None,
    updated_at   : Optional[str]                       = None,
) -> Conversation:
    """
    Return a new Conversation that differs from *conversation* only in the
    supplied keyword arguments.  All other fields are copied from the source.

    Used internally by lifecycle and thread operations — never mutates.
    """
    new_messages = list(messages) if messages is not None else list(conversation.messages)
    new_threads  = list(threads)  if threads  is not None else list(conversation.threads)
    new_state    = state     if state     is not None else conversation.state
    new_upd      = updated_at if updated_at is not None else conversation.updatedAt

    # Re-sort messages and threads (same rules as build_conversation)
    sorted_messages: Tuple[ConversationMessage, ...] = tuple(
        sorted(new_messages, key=lambda m: (m.sequenceNumber, m.messageId))
    )
    sorted_threads: Tuple[ConversationThread, ...] = tuple(
        sorted(new_threads, key=lambda t: t.threadId)
    )

    message_keys: Tuple[str, ...] = tuple(m.messageKey for m in sorted_messages)
    thread_keys:  Tuple[str, ...] = tuple(t.threadKey  for t in sorted_threads)

    conv_fp = _compute_conversation_fingerprint(
        conversation.conversationKey, message_keys, thread_keys
    )

    meta = build_metadata(
        title      = conversation.metadata.title,
        created_by = conversation.metadata.createdBy,
        messages   = sorted_messages,
        created_at = conversation.createdAt,
        summary    = conversation.metadata.summary,
        tags       = list(conversation.metadata.tags),
    )

    return Conversation(
        conversationId          = conversation.conversationId,
        conversationKey         = conversation.conversationKey,
        investigationId         = conversation.investigationId,
        state                   = new_state,
        messages                = sorted_messages,
        threads                 = sorted_threads,
        metadata                = meta,
        conversationFingerprint = conv_fp,
        createdAt               = conversation.createdAt,
        updatedAt               = new_upd,
    )


# ===========================================================================
# Thread Operations
# ===========================================================================

def create_thread(
    conversation    : Conversation,
    root_message_id : str,
    message_ids     : List[str],
    created_at      : str,
    updated_at      : str,
    depth           : int = 0,
) -> Conversation:
    """
    Return a new Conversation with an additional ConversationThread added.

    Parameters
    ----------
    conversation    : source Conversation.
    root_message_id : messageId at the root of the new thread.
    message_ids     : all messageIds belonging to the thread.
    created_at      : ISO-8601 timestamp for the thread's createdAt.
    updated_at      : ISO-8601 timestamp for conversation's updatedAt.
    depth           : nesting depth (0 = top-level).

    Returns
    -------
    Conversation — new immutable object with thread added.
    """
    new_thread = build_thread(
        conversation_id = conversation.conversationId,
        root_message_id = root_message_id,
        message_ids     = message_ids,
        created_at      = created_at,
        depth           = depth,
    )
    new_threads = list(conversation.threads) + [new_thread]
    return _rebuild(conversation, threads=new_threads, updated_at=updated_at)


def merge_threads(
    conversation : Conversation,
    thread_id_a  : str,
    thread_id_b  : str,
    updated_at   : str,
) -> Conversation:
    """
    Return a new Conversation where two threads are merged into one.

    The merged thread:
    - rootMessageId : the rootMessageId from thread_a.
    - messageIds    : union of both threads' messageIds (sorted).
    - depth         : min(depth_a, depth_b).
    - createdAt     : createdAt of thread_a.

    Both source threads are removed; the merged thread is added.

    Parameters
    ----------
    conversation : source Conversation.
    thread_id_a  : threadId of the first thread (becomes the root provider).
    thread_id_b  : threadId of the second thread.
    updated_at   : ISO-8601 timestamp for conversation's updatedAt.

    Returns
    -------
    Conversation — new immutable object with merged thread.

    Raises
    ------
    InvalidThreadError : if either thread_id is not found.
    """
    ta = next((t for t in conversation.threads if t.threadId == thread_id_a), None)
    tb = next((t for t in conversation.threads if t.threadId == thread_id_b), None)
    if ta is None:
        raise InvalidThreadError(
            f"  - threadId '{thread_id_a}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    if tb is None:
        raise InvalidThreadError(
            f"  - threadId '{thread_id_b}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    merged_ids = list(set(ta.messageIds) | set(tb.messageIds))
    merged = build_thread(
        conversation_id = conversation.conversationId,
        root_message_id = ta.rootMessageId,
        message_ids     = merged_ids,
        created_at      = ta.createdAt,
        depth           = min(ta.depth, tb.depth),
    )
    remaining = [t for t in conversation.threads
                 if t.threadId not in (thread_id_a, thread_id_b)]
    new_threads = remaining + [merged]
    return _rebuild(conversation, threads=new_threads, updated_at=updated_at)


def split_thread(
    conversation    : Conversation,
    thread_id       : str,
    new_root_id     : str,
    split_ids       : List[str],
    created_at      : str,
    updated_at      : str,
) -> Conversation:
    """
    Return a new Conversation where one thread is split into two.

    The original thread keeps only the messageIds NOT in split_ids.
    A new thread is created with rootMessageId=new_root_id and
    messageIds=split_ids.

    Parameters
    ----------
    conversation : source Conversation.
    thread_id    : threadId of the thread to split.
    new_root_id  : rootMessageId for the new thread.
    split_ids    : messageIds to move to the new thread.
    created_at   : ISO-8601 timestamp for the new thread's createdAt.
    updated_at   : ISO-8601 timestamp for conversation's updatedAt.

    Returns
    -------
    Conversation — new immutable object with split threads.

    Raises
    ------
    InvalidThreadError : if thread_id is not found, or if splitting leaves
                         the original thread with no messages.
    """
    source = next((t for t in conversation.threads if t.threadId == thread_id), None)
    if source is None:
        raise InvalidThreadError(
            f"  - threadId '{thread_id}' not found in conversation "
            f"'{conversation.conversationId}'."
        )
    split_set    = set(split_ids)
    remaining_ids = [mid for mid in source.messageIds if mid not in split_set]
    if not remaining_ids:
        raise InvalidThreadError(
            f"  - Splitting thread '{thread_id}' would leave the original "
            f"thread empty. Provide fewer split_ids."
        )
    updated_source = build_thread(
        conversation_id = conversation.conversationId,
        root_message_id = source.rootMessageId,
        message_ids     = remaining_ids,
        created_at      = source.createdAt,
        depth           = source.depth,
    )
    new_thread = build_thread(
        conversation_id = conversation.conversationId,
        root_message_id = new_root_id,
        message_ids     = split_ids,
        created_at      = created_at,
        depth           = source.depth,
    )
    other_threads = [t for t in conversation.threads if t.threadId != thread_id]
    new_threads   = other_threads + [updated_source, new_thread]
    return _rebuild(conversation, threads=new_threads, updated_at=updated_at)


def find_thread(
    conversation : Conversation,
    thread_id    : Optional[str] = None,
    root_message_id : Optional[str] = None,
) -> Optional[ConversationThread]:
    """
    Return the first matching ConversationThread or None.

    Lookup priority: thread_id > root_message_id.

    Parameters
    ----------
    conversation    : source Conversation.
    thread_id       : exact threadId to search for.
    root_message_id : exact rootMessageId to search for.

    Returns
    -------
    ConversationThread | None
    """
    if thread_id is not None:
        return next(
            (t for t in conversation.threads if t.threadId == thread_id), None
        )
    if root_message_id is not None:
        return next(
            (t for t in conversation.threads if t.rootMessageId == root_message_id),
            None,
        )
    return None


# ===========================================================================
# Message Utilities
# ===========================================================================

def sort_messages(
    messages  : List[ConversationMessage],
    ascending : bool = True,
) -> List[ConversationMessage]:
    """
    Return a new list of messages sorted by sequenceNumber, tie-break messageId.

    Parameters
    ----------
    messages  : list of ConversationMessage.
    ascending : True = ASC (default), False = DESC.

    Returns
    -------
    New sorted list; input not mutated.
    """
    return sorted(
        messages,
        key     = lambda m: (m.sequenceNumber, m.messageId),
        reverse = not ascending,
    )


def filter_messages(
    messages    : List[ConversationMessage],
    role        : Optional[ConversationRole] = None,
    min_tokens  : Optional[int]             = None,
    max_tokens  : Optional[int]             = None,
    conversation_id : Optional[str]         = None,
) -> List[ConversationMessage]:
    """
    Return messages matching ALL supplied predicates.

    Parameters
    ----------
    messages        : source list.
    role            : if set, keep only messages with this role.
    min_tokens      : keep only messages with tokenEstimate >= min_tokens.
    max_tokens      : keep only messages with tokenEstimate <= max_tokens.
    conversation_id : keep only messages belonging to this conversation.

    Returns
    -------
    Filtered list; input not mutated.
    """
    result = list(messages)
    if role is not None:
        result = [m for m in result if m.role == role]
    if min_tokens is not None:
        result = [m for m in result if m.tokenEstimate >= min_tokens]
    if max_tokens is not None:
        result = [m for m in result if m.tokenEstimate <= max_tokens]
    if conversation_id is not None:
        result = [m for m in result if m.conversationId == conversation_id]
    return result


def group_messages(
    messages  : List[ConversationMessage],
    group_by  : str = "role",
) -> Dict[str, List[ConversationMessage]]:
    """
    Partition messages into groups.

    Parameters
    ----------
    messages : source list.
    group_by : ``"role"`` or ``"conversationId"``.

    Returns
    -------
    Dict mapping group key (str) → sorted list of ConversationMessage.

    Raises
    ------
    ValueError : if group_by is not a supported key.
    """
    valid_keys = {"role", "conversationId"}
    if group_by not in valid_keys:
        raise ValueError(
            f"group_by must be one of {sorted(valid_keys)!r}; got {group_by!r}."
        )
    result: Dict[str, List[ConversationMessage]] = {}
    for msg in messages:
        key = msg.role.value if group_by == "role" else msg.conversationId
        result.setdefault(key, []).append(msg)
    # Sort each group by sequenceNumber ASC, tie-break messageId ASC
    for k in result:
        result[k] = sorted(result[k], key=lambda m: (m.sequenceNumber, m.messageId))
    return result


def find_message(
    messages   : List[ConversationMessage],
    message_id : Optional[str] = None,
    message_key: Optional[str] = None,
) -> Optional[ConversationMessage]:
    """
    Return the first matching ConversationMessage or None.

    Lookup priority: message_id > message_key.

    Parameters
    ----------
    messages    : source list.
    message_id  : exact messageId to search for.
    message_key : exact messageKey to search for.

    Returns
    -------
    ConversationMessage | None
    """
    if message_id is not None:
        return next((m for m in messages if m.messageId == message_id), None)
    if message_key is not None:
        return next((m for m in messages if m.messageKey == message_key), None)
    return None


# ===========================================================================
# Conversation Utilities
# ===========================================================================

def sort_conversations(
    conversations : List[Conversation],
    key           : str  = "conversationId",
    ascending     : bool = True,
) -> List[Conversation]:
    """
    Return a new sorted list of Conversation objects.

    Parameters
    ----------
    conversations : source list.
    key           : one of ``"conversationId"``, ``"createdAt"``,
                    ``"updatedAt"``, ``"totalMessages"``.
    ascending     : True = ASC (default), False = DESC.

    Returns
    -------
    New sorted list; input not mutated.

    Raises
    ------
    ValueError : if key is not supported.
    """
    _KEY_FN = {
        "conversationId" : lambda c: c.conversationId,
        "createdAt"      : lambda c: c.createdAt,
        "updatedAt"      : lambda c: c.updatedAt,
        "totalMessages"  : lambda c: c.metadata.totalMessages,
    }
    if key not in _KEY_FN:
        raise ValueError(
            f"sort key must be one of {sorted(_KEY_FN)!r}; got {key!r}."
        )
    return sorted(conversations, key=_KEY_FN[key], reverse=not ascending)


def filter_conversations(
    conversations   : List[Conversation],
    state           : Optional[ConversationState] = None,
    investigation_id: Optional[str]              = None,
    has_messages    : Optional[bool]             = None,
    has_threads     : Optional[bool]             = None,
    min_messages    : Optional[int]              = None,
    max_messages    : Optional[int]              = None,
    tag             : Optional[str]              = None,
) -> List[Conversation]:
    """
    Return conversations matching ALL supplied predicates.

    Parameters
    ----------
    conversations    : source list.
    state            : keep only conversations in this ConversationState.
    investigation_id : keep only conversations with this investigationId.
    has_messages     : True = only non-empty; False = only empty.
    has_threads      : True = has at least one thread; False = none.
    min_messages     : keep only conversations with totalMessages >= value.
    max_messages     : keep only conversations with totalMessages <= value.
    tag              : keep only conversations whose tags contain this value
                       (case-insensitive).

    Returns
    -------
    Filtered list; input not mutated.
    """
    result = list(conversations)
    if state is not None:
        result = [c for c in result if c.state == state]
    if investigation_id is not None:
        result = [c for c in result if c.investigationId == investigation_id]
    if has_messages is True:
        result = [c for c in result if c.metadata.totalMessages > 0]
    elif has_messages is False:
        result = [c for c in result if c.metadata.totalMessages == 0]
    if has_threads is True:
        result = [c for c in result if len(c.threads) > 0]
    elif has_threads is False:
        result = [c for c in result if len(c.threads) == 0]
    if min_messages is not None:
        result = [c for c in result if c.metadata.totalMessages >= min_messages]
    if max_messages is not None:
        result = [c for c in result if c.metadata.totalMessages <= max_messages]
    if tag is not None:
        norm_tag = tag.strip().lower()
        result = [c for c in result if norm_tag in c.metadata.tags]
    return result


def group_conversations(
    conversations : List[Conversation],
    group_by      : str = "state",
) -> Dict[str, List[Conversation]]:
    """
    Partition conversations into groups.

    Parameters
    ----------
    conversations : source list.
    group_by      : ``"state"``, ``"investigationId"``.

    Returns
    -------
    Dict mapping group key (str) → list of Conversation sorted by
    conversationId ASC.

    Raises
    ------
    ValueError : if group_by is not supported.
    """
    valid_keys = {"state", "investigationId"}
    if group_by not in valid_keys:
        raise ValueError(
            f"group_by must be one of {sorted(valid_keys)!r}; got {group_by!r}."
        )
    result: Dict[str, List[Conversation]] = {}
    for conv in conversations:
        key = conv.state.value if group_by == "state" else conv.investigationId
        result.setdefault(key, []).append(conv)
    for k in result:
        result[k] = sorted(result[k], key=lambda c: c.conversationId)
    return result


def find_conversation(
    conversations   : List[Conversation],
    conversation_id : Optional[str] = None,
    conversation_key: Optional[str] = None,
) -> Optional[Conversation]:
    """
    Return the first matching Conversation or None.

    Lookup priority: conversation_id > conversation_key.

    Parameters
    ----------
    conversations    : source list.
    conversation_id  : exact conversationId to search for.
    conversation_key : exact conversationKey to search for.

    Returns
    -------
    Conversation | None
    """
    if conversation_id is not None:
        return next(
            (c for c in conversations if c.conversationId == conversation_id), None
        )
    if conversation_key is not None:
        return next(
            (c for c in conversations if c.conversationKey == conversation_key), None
        )
    return None
