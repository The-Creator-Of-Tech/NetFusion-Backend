"""
Groq Streaming Engine
=====================
Phase A4.2.2 — Real-time streaming support for Groq responses using
Server-Sent Events (SSE).

Responsibilities
----------------
- Receive streamed tokens from the Groq API (SSE wire format).
- Parse ``data: {...}`` events from Groq / OpenAI streaming protocol.
- Assemble tokens into a deterministic GroqResponse via existing builders.
- Track per-stream metrics: first-token latency, total latency, throughput.
- Validate sequence numbers, duplicates, malformed JSON, and finish reasons.
- Support interrupted streams, premature EOF, and timeout errors.

This service is a PURE STREAMING TRANSPORT / ASSEMBLY LAYER.
It contains NO AI reasoning, NO prompt generation, NO investigation logic,
NO attack graph logic, NO timeline logic, NO evidence logic.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder functions return NEW objects; nothing is mutated.
- Fully deterministic: same stream → same chunks → same final response.
- No uuid4(). No random module. No unordered set iteration.
- Chunks always assembled in sequenceNumber ASC order.
- Engine version from core/constants.py — never hardcoded.
- No function-calling / tool-call support (reserved for A4.2.4).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel

from core.constants import (
    GROQ_API_ENDPOINT,
    GROQ_API_VERSION,
    GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS,
    GROQ_HTTP_DEFAULT_USER_AGENT,
    GROQ_STREAMING_ENGINE_VERSION,
)
from core.logging import get_logger
from services.groq_provider_service import (
    GroqRequest,
    GroqResponse,
    build_response,
)
from services.groq_http_client import (
    GroqHTTPConfig,
    build_headers,
    build_payload,
    _mask_api_key,
)

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("groq_streaming_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; same as groq_provider_service / groq_http_client
# ---------------------------------------------------------------------------
_STREAM_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# Valid SSE finish reasons (Groq / OpenAI compatible)
# ---------------------------------------------------------------------------
_VALID_FINISH_REASONS = frozenset({"stop", "length", "content_filter", "tool_calls", "null"})


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class GroqStreamError(Exception):
    """Base class for all Groq Streaming Engine errors."""

    def __init__(self, message: str, stream_id: str = "") -> None:
        super().__init__(message)
        self.stream_id = stream_id

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(stream_id={self.stream_id!r}, message={str(self)!r})"


class MalformedChunkError(GroqStreamError):
    """Raised when a raw SSE line cannot be parsed as valid JSON."""


class DuplicateChunkError(GroqStreamError):
    """Raised when a chunk with an already-seen sequenceNumber arrives."""


class InvalidSequenceError(GroqStreamError):
    """Raised when sequenceNumber is negative or non-integer."""


class InvalidFinishReasonError(GroqStreamError):
    """Raised when a finish_reason token contains an unrecognised value."""


class StreamInterruptedError(GroqStreamError):
    """Raised when the stream ends before a [DONE] sentinel is received."""


class StreamTimeoutError(GroqStreamError):
    """Raised when the stream exceeds the configured timeout."""


class MissingDeltaError(GroqStreamError):
    """Raised when an SSE event has no delta/choices structure."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class GroqStreamChunk(BaseModel):
    """
    One immutable token chunk received from the Groq SSE stream.

    Fields
    ------
    chunkId        : deterministic UUIDv5 derived from streamId + sequenceNumber + content.
    sequenceNumber : zero-based arrival index (used for ordering).
    content        : token text fragment (may be empty for role/control chunks).
    finishReason   : finish_reason from Groq (None for intermediate chunks).
    receivedAt     : monotonic timestamp (ms) when this chunk was processed.
    """
    chunkId        : str
    sequenceNumber : int
    content        : str
    finishReason   : Optional[str]
    receivedAt     : int  # monotonic ms

    class Config:
        frozen = True


class GroqStreamState(BaseModel):
    """
    Immutable snapshot of the current stream assembly state.

    Fields
    ------
    streamId           : deterministic UUIDv5 for this stream (derived from requestId).
    requestId          : GroqRequest.requestId that initiated this stream.
    chunks             : tuple of all GroqStreamChunk objects, ordered by sequenceNumber.
    accumulatedContent : all chunk content concatenated in sequenceNumber ASC order.
    totalChunks        : number of chunks received so far.
    completed          : True once a [DONE] or finish_reason chunk is processed.
    finishReason       : final finish_reason (None until completed).
    startedAt          : monotonic timestamp (ms) when stream started.
    completedAt        : monotonic timestamp (ms) when stream completed (0 if not yet).
    engineVersion      : GROQ_STREAMING_ENGINE_VERSION.
    """
    streamId           : str
    requestId          : str
    chunks             : Tuple[GroqStreamChunk, ...]
    accumulatedContent : str
    totalChunks        : int
    completed          : bool
    finishReason       : Optional[str]
    startedAt          : int
    completedAt        : int
    engineVersion      : str

    class Config:
        frozen = True


class GroqStreamingMetadata(BaseModel):
    """
    Immutable streaming metrics and provenance for one completed stream.

    Fields
    ------
    firstTokenLatencyMs : ms from stream start to first non-empty content chunk.
    totalLatencyMs      : ms from stream start to stream completion.
    chunkCount          : total number of content-bearing chunks processed.
    averageChunkSize    : average characters per chunk (float).
    tokensPerSecond     : estimated throughput (completion tokens / total seconds).
    interrupted         : True if stream ended without [DONE].
    warnings            : sorted tuple of non-fatal advisory strings.
    """
    firstTokenLatencyMs : int
    totalLatencyMs      : int
    chunkCount          : int
    averageChunkSize    : float
    tokensPerSecond     : float
    interrupted         : bool
    warnings            : Tuple[str, ...]

    class Config:
        frozen = True


class GroqStreamingResult(BaseModel):
    """
    Immutable final result from a completed Groq streaming interaction.

    Fields
    ------
    state    : final GroqStreamState snapshot.
    response : assembled GroqResponse (same shape as non-streaming response).
    metadata : GroqStreamingMetadata — latency and throughput metrics.
    """
    state    : GroqStreamState
    response : GroqResponse
    metadata : GroqStreamingMetadata

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5_stream(key: str) -> str:
    """UUIDv5(_STREAM_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_STREAM_NS, key))


def _mono_ms() -> int:
    """Monotonic clock in milliseconds (for latency measurement only)."""
    return int(time.monotonic() * 1000)


# ===========================================================================
# Builder: build_stream_chunk()
# ===========================================================================

def build_stream_chunk(
    stream_id      : str,
    sequence_number: int,
    content        : str,
    finish_reason  : Optional[str] = None,
) -> GroqStreamChunk:
    """
    Build an immutable GroqStreamChunk.

    chunkId is UUIDv5 derived from streamId + str(sequenceNumber) + content,
    ensuring identical chunks always produce identical chunkIds.

    Parameters
    ----------
    stream_id       : parent stream identifier.
    sequence_number : zero-based ordinal (≥ 0).
    content         : token text fragment.
    finish_reason   : finish_reason string or None.

    Returns
    -------
    GroqStreamChunk (frozen / immutable)

    Raises
    ------
    InvalidSequenceError : if sequence_number < 0.
    InvalidFinishReasonError : if finish_reason is not None and not in valid set.
    """
    if not isinstance(sequence_number, int) or sequence_number < 0:
        raise InvalidSequenceError(
            f"sequenceNumber must be a non-negative integer, got {sequence_number!r}.",
            stream_id=stream_id,
        )
    norm_fr = _normalise_finish_reason(finish_reason)
    if norm_fr is not None and norm_fr not in _VALID_FINISH_REASONS:
        raise InvalidFinishReasonError(
            f"Invalid finish_reason {finish_reason!r}. "
            f"Valid values: {sorted(_VALID_FINISH_REASONS)}.",
            stream_id=stream_id,
        )
    chunk_key = _sha256_32(stream_id, str(sequence_number), content or "")
    chunk_id  = _uuid5_stream(chunk_key)
    return GroqStreamChunk(
        chunkId        = chunk_id,
        sequenceNumber = sequence_number,
        content        = content or "",
        finishReason   = norm_fr,
        receivedAt     = _mono_ms(),
    )


def _normalise_finish_reason(reason: Optional[str]) -> Optional[str]:
    """Return None for empty / null finish reasons; strip otherwise."""
    if reason is None:
        return None
    stripped = reason.strip()
    if stripped == "" or stripped.lower() == "null":
        return None
    return stripped


# ===========================================================================
# Builder: build_stream_state()
# ===========================================================================

def build_stream_state(
    request_id   : str,
    chunks       : List[GroqStreamChunk],
    completed    : bool                = False,
    finish_reason: Optional[str]       = None,
    started_at   : int                 = 0,
    completed_at : int                 = 0,
) -> GroqStreamState:
    """
    Build an immutable GroqStreamState from a list of chunks.

    Chunks are ALWAYS sorted by sequenceNumber ASC before being stored,
    ensuring deterministic assembly even if chunks arrived out of order.

    streamId is UUIDv5 derived from the requestId so it is always
    deterministic for the same request.

    Parameters
    ----------
    request_id    : GroqRequest.requestId.
    chunks        : list of GroqStreamChunk objects (order does not matter).
    completed     : True once [DONE] or finish_reason chunk received.
    finish_reason : final finish_reason (None until completed).
    started_at    : monotonic ms when stream was initiated.
    completed_at  : monotonic ms when stream completed (0 if not done).

    Returns
    -------
    GroqStreamState (frozen / immutable)
    """
    stream_id = _uuid5_stream(_sha256_32("stream", request_id))
    sorted_chunks: Tuple[GroqStreamChunk, ...] = tuple(
        sorted(chunks, key=lambda c: c.sequenceNumber)
    )
    accumulated = "".join(c.content for c in sorted_chunks)
    return GroqStreamState(
        streamId           = stream_id,
        requestId          = request_id,
        chunks             = sorted_chunks,
        accumulatedContent = accumulated,
        totalChunks        = len(sorted_chunks),
        completed          = completed,
        finishReason       = _normalise_finish_reason(finish_reason),
        startedAt          = max(0, int(started_at)),
        completedAt        = max(0, int(completed_at)),
        engineVersion      = GROQ_STREAMING_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_streaming_metadata()
# ===========================================================================

def build_streaming_metadata(
    state       : GroqStreamState,
    interrupted : bool             = False,
    warnings    : Optional[List[str]] = None,
) -> GroqStreamingMetadata:
    """
    Build immutable GroqStreamingMetadata from a completed GroqStreamState.

    Metrics computed
    ----------------
    - firstTokenLatencyMs : ms from startedAt to first non-empty content chunk.
    - totalLatencyMs      : max(0, completedAt - startedAt).
    - chunkCount          : number of chunks with non-empty content.
    - averageChunkSize    : mean chars per non-empty chunk (0.0 if none).
    - tokensPerSecond     : estimated throughput using chars/4 tokens estimate.

    Parameters
    ----------
    state       : GroqStreamState (completed or interrupted).
    interrupted : True if stream ended without [DONE].
    warnings    : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    GroqStreamingMetadata (frozen / immutable)
    """
    content_chunks = [c for c in state.chunks if c.content]
    chunk_count    = len(content_chunks)
    total_chars    = sum(len(c.content) for c in content_chunks)

    # first-token latency: time from stream start to first content chunk
    if content_chunks and state.startedAt > 0:
        first_token_latency = max(0, content_chunks[0].receivedAt - state.startedAt)
    else:
        first_token_latency = 0

    total_latency = max(0, state.completedAt - state.startedAt) if state.completedAt > 0 else 0

    avg_chunk_size = round(total_chars / chunk_count, 4) if chunk_count > 0 else 0.0

    # tokens/sec estimate: chars / 4 = tokens, divided by total seconds
    total_seconds = total_latency / 1000.0
    if total_seconds > 0 and total_chars > 0:
        estimated_tokens = max(1, -(-total_chars // 4))  # ceiling division
        tokens_per_sec   = round(estimated_tokens / total_seconds, 4)
    else:
        tokens_per_sec = 0.0

    # warnings: dedup + sort
    warn_set: List[str] = []
    if warnings:
        seen: set = set()
        for w in warnings:
            w = w.strip()
            if w and w not in seen:
                seen.add(w)
                warn_set.append(w)
    warn_set.sort()

    return GroqStreamingMetadata(
        firstTokenLatencyMs = first_token_latency,
        totalLatencyMs      = total_latency,
        chunkCount          = chunk_count,
        averageChunkSize    = avg_chunk_size,
        tokensPerSecond     = tokens_per_sec,
        interrupted         = bool(interrupted),
        warnings            = tuple(warn_set),
    )


# ===========================================================================
# Builder: build_streaming_result()
# ===========================================================================

def build_streaming_result(
    state      : GroqStreamState,
    response   : GroqResponse,
    metadata   : GroqStreamingMetadata,
) -> GroqStreamingResult:
    """
    Build an immutable GroqStreamingResult combining state, response, and metadata.

    Parameters
    ----------
    state    : final GroqStreamState.
    response : assembled GroqResponse (built by stream_to_response()).
    metadata : GroqStreamingMetadata.

    Returns
    -------
    GroqStreamingResult (frozen / immutable)
    """
    return GroqStreamingResult(
        state    = state,
        response = response,
        metadata = metadata,
    )


# ===========================================================================
# Streaming functions
# ===========================================================================

def parse_stream_chunk(
    raw_line  : str,
    stream_id : str,
    seq_number: int,
) -> Optional[GroqStreamChunk]:
    """
    Parse one raw SSE ``data: {...}`` line into a GroqStreamChunk.

    Handles:
    - Normal delta chunks with content.
    - Role-only / empty-content chunks (returns chunk with empty content).
    - Chunks with finish_reason set.
    - ``data: [DONE]`` sentinel (returns None).

    Parameters
    ----------
    raw_line   : raw SSE line as received (e.g. ``data: {...}`` or ``data: [DONE]``).
    stream_id  : parent stream identifier (for error messages).
    seq_number : current sequence number (≥ 0).

    Returns
    -------
    GroqStreamChunk — for normal/finish chunks.
    None            — for [DONE] sentinel or blank lines.

    Raises
    ------
    MalformedChunkError      : if the line is ``data:`` prefix but not valid JSON.
    MissingDeltaError        : if the JSON has no ``choices`` array.
    InvalidFinishReasonError : if finish_reason is not a recognised value.
    InvalidSequenceError     : if seq_number is negative.
    """
    line = raw_line.strip()

    # Skip empty lines and SSE comment lines
    if not line or line.startswith(":"):
        return None

    # Only process "data: ..." lines
    if not line.startswith("data:"):
        return None

    payload_str = line[len("data:"):].strip()

    # [DONE] sentinel
    if payload_str == "[DONE]":
        return None

    # Empty payload (keep-alive or blank data line)
    if not payload_str:
        return None

    # Parse JSON
    try:
        data = json.loads(payload_str)
    except json.JSONDecodeError as exc:
        raise MalformedChunkError(
            f"Cannot parse SSE payload as JSON: {exc}. Raw: {payload_str[:200]!r}",
            stream_id=stream_id,
        )

    if not isinstance(data, dict):
        raise MalformedChunkError(
            f"SSE payload is not a JSON object. Got: {type(data).__name__}",
            stream_id=stream_id,
        )

    # Extract choices
    choices = data.get("choices")
    if choices is None or not isinstance(choices, list):
        raise MissingDeltaError(
            f"SSE event missing 'choices' array at seq={seq_number}.",
            stream_id=stream_id,
        )

    # Empty choices list is valid — some providers send it for the final chunk
    if not choices:
        return build_stream_chunk(stream_id, seq_number, "", finish_reason=None)

    choice       = choices[0]
    delta        = choice.get("delta", {}) or {}
    content      = delta.get("content") or ""
    finish_reason = choice.get("finish_reason")  # may be None for intermediate chunks

    return build_stream_chunk(
        stream_id       = stream_id,
        sequence_number = seq_number,
        content         = content,
        finish_reason   = finish_reason,
    )


def append_chunk(
    chunks     : List[GroqStreamChunk],
    new_chunk  : GroqStreamChunk,
    stream_id  : str,
) -> List[GroqStreamChunk]:
    """
    Append a new chunk to the mutable chunk list, rejecting duplicates.

    A duplicate is defined as a chunk whose sequenceNumber already exists
    in the list.  The original list is NOT mutated — a new list is returned.

    Parameters
    ----------
    chunks    : current list of GroqStreamChunk objects.
    new_chunk : candidate chunk to add.
    stream_id : stream identifier (for error context).

    Returns
    -------
    New list with new_chunk appended.

    Raises
    ------
    DuplicateChunkError : if new_chunk.sequenceNumber is already present.
    """
    seen_seqs = {c.sequenceNumber for c in chunks}
    if new_chunk.sequenceNumber in seen_seqs:
        raise DuplicateChunkError(
            f"Duplicate chunk: sequenceNumber={new_chunk.sequenceNumber} "
            f"already received in stream {stream_id!r}.",
            stream_id=stream_id,
        )
    return list(chunks) + [new_chunk]


def finalize_stream(
    chunks       : List[GroqStreamChunk],
    request_id   : str,
    finish_reason: Optional[str],
    started_at   : int,
    interrupted  : bool = False,
    warnings     : Optional[List[str]] = None,
) -> Tuple[GroqStreamState, GroqStreamingMetadata]:
    """
    Finalise a stream: build the completed GroqStreamState and metadata.

    Chunks are sorted by sequenceNumber ASC inside build_stream_state().

    Parameters
    ----------
    chunks        : all received GroqStreamChunk objects.
    request_id    : GroqRequest.requestId.
    finish_reason : final finish_reason string.
    started_at    : monotonic ms when stream started.
    interrupted   : True if [DONE] was never received.
    warnings      : advisory strings.

    Returns
    -------
    Tuple of (GroqStreamState, GroqStreamingMetadata)
    """
    completed_at = _mono_ms()
    state = build_stream_state(
        request_id    = request_id,
        chunks        = chunks,
        completed     = not interrupted,
        finish_reason = finish_reason,
        started_at    = started_at,
        completed_at  = completed_at,
    )
    meta = build_streaming_metadata(state, interrupted=interrupted, warnings=warnings)
    return state, meta


def reset_stream(request_id: str) -> Tuple[List[GroqStreamChunk], int]:
    """
    Reset streaming state for a fresh stream.

    Returns an empty chunk list and a new startedAt monotonic timestamp.
    Designed to be called at the beginning of each new stream attempt.

    Parameters
    ----------
    request_id : GroqRequest.requestId (used for logging only here).

    Returns
    -------
    Tuple of (empty_chunk_list, started_at_ms)
    """
    started_at = _mono_ms()
    _log.info(
        f"[groq_streaming] stream_reset "
        f"request_id={request_id} "
        f"started_at={started_at}"
    )
    return [], started_at


def stream_to_response(
    state     : GroqStreamState,
    request   : GroqRequest,
    created_at: str,
) -> GroqResponse:
    """
    Convert a completed GroqStreamState into a deterministic GroqResponse.

    Uses build_response() from groq_provider_service — the same builder used
    by the non-streaming path — ensuring identical GroqResponse objects for
    identical accumulated content.

    Token counts are estimated from character length (same ratio as
    groq_provider_service.estimate_tokens: ceiling(len / 4)).

    Parameters
    ----------
    state      : completed GroqStreamState with accumulatedContent.
    request    : original GroqRequest (provides requestId, model, messages).
    created_at : ISO-8601 timestamp (caller-supplied for determinism).

    Returns
    -------
    GroqResponse (frozen / immutable) — same shape as non-streaming response.

    Raises
    ------
    ValueError : if the state is not completed and has no content.
    """
    content       = state.accumulatedContent
    finish_reason = state.finishReason or "stop"

    # Estimate prompt tokens from all message content
    prompt_chars  = sum(len(m.content) for m in request.messages)
    prompt_tokens = max(0, -(-prompt_chars // 4))  # ceiling division

    # Estimate completion tokens from accumulated content
    completion_tokens = max(0, -(-len(content) // 4)) if content else 0

    total_latency = max(0, state.completedAt - state.startedAt) if state.completedAt > 0 else 0

    return build_response(
        request_id         = request.requestId,
        model              = request.model,
        content            = content,
        finish_reason      = finish_reason,
        created_at         = created_at,
        prompt_tokens      = prompt_tokens,
        completion_tokens  = completion_tokens,
        latency_ms         = total_latency,
        processing_time_ms = 0,
        warnings           = list(state.engineVersion and [] or []),
        validate           = True,
    )


# ===========================================================================
# Core async streaming function
# ===========================================================================

async def stream_async_request(
    config      : GroqHTTPConfig,
    groq_request: GroqRequest,
    created_at  : str,
) -> GroqStreamingResult:
    """
    Send a streaming GroqRequest and assemble all SSE chunks into a
    deterministic GroqStreamingResult.

    Protocol
    --------
    1. Send POST with ``stream=True`` in payload.
    2. Iterate over response lines.
    3. Parse each ``data: {...}`` line with parse_stream_chunk().
    4. Stop on ``data: [DONE]``.
    5. Assemble accumulated content into a GroqResponse via stream_to_response().

    Parameters
    ----------
    config       : GroqHTTPConfig (endpoint, API key, timeout, etc.).
    groq_request : GroqRequest — must have stream=True or it is forced here.
    created_at   : ISO-8601 timestamp string (caller-supplied for determinism).

    Returns
    -------
    GroqStreamingResult (frozen / immutable)

    Raises
    ------
    StreamInterruptedError : if stream ends before [DONE].
    StreamTimeoutError     : if stream exceeds configured timeout.
    MalformedChunkError    : if any SSE line is unparseable.
    """
    # Build stream-specific payload (force stream=True)
    import copy
    payload = build_payload(groq_request)
    payload = {**payload, "stream": True}

    headers = build_headers(config)

    chunks: List[GroqStreamChunk] = []
    started_at  = _mono_ms()
    stream_id   = _uuid5_stream(_sha256_32("stream", groq_request.requestId))
    seq_number  = 0
    finish_reason: Optional[str] = None
    done_received = False
    warnings: List[str] = []

    _log.info(
        f"[groq_streaming] stream_started "
        f"stream_id={stream_id} "
        f"request_id={groq_request.requestId} "
        f"model={groq_request.model} "
        f"api_key={_mask_api_key(config.apiKey)}"
    )

    try:
        async with httpx.AsyncClient(verify=config.verifySSL) as client:
            async with client.stream(
                "POST",
                config.endpoint,
                headers = headers,
                json    = payload,
                timeout = config.timeoutSeconds,
            ) as response:
                async for raw_line in response.aiter_lines():
                    line = raw_line.strip()
                    if not line:
                        continue

                    # [DONE] sentinel
                    if line == "data: [DONE]":
                        done_received = True
                        _log.info(
                            f"[groq_streaming] stream_done "
                            f"stream_id={stream_id} "
                            f"total_chunks={seq_number}"
                        )
                        break

                    if not line.startswith("data:"):
                        continue

                    try:
                        chunk = parse_stream_chunk(line, stream_id, seq_number)
                    except DuplicateChunkError as exc:
                        _log.warning(
                            f"[groq_streaming] duplicate_ignored "
                            f"stream_id={stream_id} "
                            f"seq={seq_number} "
                            f"error={exc}"
                        )
                        warnings.append(f"Duplicate chunk at seq={seq_number} ignored.")
                        continue
                    except MalformedChunkError as exc:
                        _log.error(
                            f"[groq_streaming] malformed_chunk "
                            f"stream_id={stream_id} "
                            f"seq={seq_number} "
                            f"error={exc}"
                        )
                        raise

                    if chunk is None:
                        # [DONE] returned from parse_stream_chunk
                        done_received = True
                        break

                    # Track first token
                    if seq_number == 0 and chunk.content:
                        _log.info(
                            f"[groq_streaming] first_token "
                            f"stream_id={stream_id} "
                            f"latency_ms={chunk.receivedAt - started_at}"
                        )

                    _log.info(
                        f"[groq_streaming] chunk_received "
                        f"stream_id={stream_id} "
                        f"seq={seq_number} "
                        f"content_len={len(chunk.content)}"
                    )

                    try:
                        chunks = append_chunk(chunks, chunk, stream_id)
                    except DuplicateChunkError as exc:
                        _log.warning(
                            f"[groq_streaming] duplicate_ignored "
                            f"stream_id={stream_id} "
                            f"seq={seq_number}"
                        )
                        warnings.append(f"Duplicate chunk at seq={seq_number} ignored.")
                        continue

                    if chunk.finishReason:
                        finish_reason = chunk.finishReason

                    seq_number += 1

    except httpx.TimeoutException as exc:
        _log.error(
            f"[groq_streaming] stream_timeout "
            f"stream_id={stream_id} "
            f"error={exc}"
        )
        raise StreamTimeoutError(
            f"Stream timed out after {config.timeoutSeconds}s: {exc}",
            stream_id=stream_id,
        )

    if not done_received and not chunks:
        _log.error(
            f"[groq_streaming] stream_interrupted "
            f"stream_id={stream_id} "
            f"chunks_received={len(chunks)}"
        )
        raise StreamInterruptedError(
            "Stream ended before [DONE] with no chunks received.",
            stream_id=stream_id,
        )

    interrupted = not done_received
    if interrupted:
        _log.warning(
            f"[groq_streaming] stream_interrupted "
            f"stream_id={stream_id} "
            f"chunks_received={len(chunks)}"
        )
        warnings.append("Stream ended without [DONE] sentinel.")

    state, meta = finalize_stream(
        chunks        = chunks,
        request_id    = groq_request.requestId,
        finish_reason = finish_reason,
        started_at    = started_at,
        interrupted   = interrupted,
        warnings      = warnings,
    )

    response = stream_to_response(state, groq_request, created_at)
    result   = build_streaming_result(state, response, meta)

    _log.info(
        f"[groq_streaming] stream_completed "
        f"stream_id={stream_id} "
        f"total_chunks={meta.chunkCount} "
        f"total_latency_ms={meta.totalLatencyMs} "
        f"first_token_ms={meta.firstTokenLatencyMs} "
        f"tokens_per_sec={meta.tokensPerSecond} "
        f"content_len={len(state.accumulatedContent)}"
    )

    return result


def stream_request(
    config      : GroqHTTPConfig,
    groq_request: GroqRequest,
    created_at  : str,
) -> GroqStreamingResult:
    """
    Synchronous wrapper around stream_async_request().

    Parameters
    ----------
    config       : GroqHTTPConfig
    groq_request : GroqRequest
    created_at   : ISO-8601 timestamp string.

    Returns
    -------
    GroqStreamingResult
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    coro = stream_async_request(config, groq_request, created_at)

    if loop is None:
        return asyncio.run(coro)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()


# ===========================================================================
# Public API surface
# ===========================================================================

__all__ = [
    # Exceptions
    "GroqStreamError",
    "MalformedChunkError",
    "DuplicateChunkError",
    "InvalidSequenceError",
    "InvalidFinishReasonError",
    "StreamInterruptedError",
    "StreamTimeoutError",
    "MissingDeltaError",
    # Models
    "GroqStreamChunk",
    "GroqStreamState",
    "GroqStreamingMetadata",
    "GroqStreamingResult",
    # Builders
    "build_stream_chunk",
    "build_stream_state",
    "build_streaming_metadata",
    "build_streaming_result",
    # Streaming functions
    "parse_stream_chunk",
    "append_chunk",
    "finalize_stream",
    "reset_stream",
    "stream_to_response",
    # HTTP functions
    "stream_request",
    "stream_async_request",
    # Version constant
    "GROQ_STREAMING_ENGINE_VERSION",
]
