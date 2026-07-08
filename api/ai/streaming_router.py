"""
AI Streaming API Router — Phase A4.8.9
======================================
REST interface for Streaming Metadata Management.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Body, Query

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.ai.streaming_models import (
    CreateStreamRequest,
    UpdateStreamRequest,
    StreamChunkRequest,
    StreamChunkResponse,
    StreamResponse,
    StreamListResponse,
    StreamStatisticsResponse,
    StreamStatusResponse,
    StreamSummaryResponse,
    BulkCreateStreamsRequest,
    BulkUpdateStreamsRequest,
    BulkDeleteStreamsRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response, build_error_response
from api.utils import exception_to_api_response, validate_pagination

from services.groq_streaming_service import (
    GroqStreamChunk,
    GroqStreamState,
    build_stream_chunk,
    build_stream_state,
    append_chunk,
    _mono_ms,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

streaming_router: APIRouter = APIRouter(
    prefix = "/streaming",
    tags   = ["Streaming"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_streaming
_STREAM_STORE = RepositoryBackedDict("streaming", "streamId", map_streaming)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _STREAM_STORE.clear()


def _all_streams() -> List[Dict[str, Any]]:
    """Return all stream states sorted deterministically by streamId ASC."""
    return sorted(_STREAM_STORE.values(), key=lambda s: s["streamId"])


def _stream_to_response(s: Dict[str, Any]) -> StreamResponse:
    """Map stored stream state dict to StreamResponse model."""
    chunks_resp = [
        StreamChunkResponse(
            chunkId        = c.chunkId,
            sequenceNumber = c.sequenceNumber,
            content        = c.content,
            finishReason   = c.finishReason,
            receivedAt     = c.receivedAt,
        )
        for c in s.get("chunks", [])
    ]
    return StreamResponse(
        streamId           = s["streamId"],
        requestId          = s["requestId"],
        streamName         = s["streamName"],
        provider           = s["provider"],
        model              = s["model"],
        status             = s["status"],
        createdAt          = s["createdAt"],
        updatedAt          = s["updatedAt"],
        userId             = s["userId"],
        projectId          = s["projectId"],
        investigationId    = s["investigationId"],
        chunkCount         = len(s.get("chunks", [])),
        totalTokens        = s.get("totalTokens", 0),
        latencyMs          = s.get("latencyMs", 0),
        accumulatedContent = s.get("accumulatedContent", ""),
        finishReason       = s.get("finishReason"),
        chunks             = chunks_resp,
    )


# ===========================================================================
# Utilities
# ===========================================================================

def find_stream(
    streams: List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """Find stream dict by field exact value (case-insensitive)."""
    target = value.lower().strip()
    for s in streams:
        v = s.get(field)
        if v is not None and str(v).lower().strip() == target:
            return s
    return None


def search_streams(
    streams: List[Dict[str, Any]],
    query  : str,
) -> List[Dict[str, Any]]:
    """Case-insensitive search across stream metadata and accumulatedContent."""
    q = query.lower().strip()
    if not q:
        return list(streams)
    res = []
    for s in streams:
        if (
            q in s.get("streamId", "").lower() or
            q in s.get("requestId", "").lower() or
            q in s.get("streamName", "").lower() or
            q in s.get("provider", "").lower() or
            q in s.get("model", "").lower() or
            q in s.get("accumulatedContent", "").lower() or
            q in s.get("userId", "").lower() or
            q in s.get("projectId", "").lower() or
            q in s.get("investigationId", "").lower()
        ):
            res.append(s)
    return res


def sort_streams(
    streams   : List[Dict[str, Any]],
    sort_by   : str = "createdAt",
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Sort stream dicts by requested field."""
    reverse = sort_order.lower() == "desc"

    def sort_key(s: Dict[str, Any]):
        if sort_by == "chunkCount":
            v = len(s.get("chunks", []))
        elif sort_by == "totalTokens":
            v = s.get("totalTokens", 0)
        elif sort_by == "latencyMs":
            v = s.get("latencyMs", 0)
        else:
            v = s.get(sort_by, "")
        
        if v is None:
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        return (0, str(v).lower())

    return sorted(streams, key=sort_key, reverse=reverse)


def filter_streams(
    streams         : List[Dict[str, Any]],
    status          : Optional[str] = None,
    provider        : Optional[str] = None,
    model           : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    minimumChunks   : Optional[int] = None,
    maximumChunks   : Optional[int] = None,
    minimumLatency  : Optional[int] = None,
    maximumLatency  : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter streams list based on standard criteria."""
    res = []
    for s in streams:
        if status is not None and s.get("status", "").lower() != status.lower().strip():
            continue
        if provider is not None and s.get("provider", "").lower() != provider.lower().strip():
            continue
        if model is not None and s.get("model", "").lower() != model.lower().strip():
            continue
        if userId is not None and s.get("userId", "").lower() != userId.lower().strip():
            continue
        if projectId is not None and s.get("projectId", "").lower() != projectId.lower().strip():
            continue
        if investigationId is not None and s.get("investigationId", "").lower() != investigationId.lower().strip():
            continue

        chunk_count = len(s.get("chunks", []))
        tokens = s.get("totalTokens", 0)
        latency = s.get("latencyMs", 0)

        if minimumTokens is not None and tokens < minimumTokens:
            continue
        if maximumTokens is not None and tokens > maximumTokens:
            continue
        if minimumChunks is not None and chunk_count < minimumChunks:
            continue
        if maximumChunks is not None and chunk_count > maximumChunks:
            continue
        if minimumLatency is not None and latency < minimumLatency:
            continue
        if maximumLatency is not None and latency > maximumLatency:
            continue

        created_at = s.get("createdAt", "")
        if createdAfter is not None and created_at <= createdAfter:
            continue
        if createdBefore is not None and created_at >= createdBefore:
            continue

        res.append(s)
    return res


def paginate_streams(
    streams  : List[Dict[str, Any]],
    page     : int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate a list of stream dicts using Pagination model."""
    safe_page = max(1, page)
    safe_page_size = max(1, page_size)
    total = len(streams)
    total_pages = math.ceil(total / safe_page_size) if total > 0 else 0
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    page_slice = streams[start:end]
    pagination = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def append_stream_chunk(
    stream: Dict[str, Any],
    chunk : GroqStreamChunk,
) -> Dict[str, Any]:
    """Append a chunk to the stream, sorting and recalculating metrics."""
    updated_chunks = append_chunk(stream["chunks"], chunk, stream["streamId"])
    sorted_chunks = sorted(updated_chunks, key=lambda c: c.sequenceNumber)
    accumulated = "".join(c.content for c in sorted_chunks)
    completion_tokens = max(0, -(-len(accumulated) // 4)) if accumulated else 0

    new_stream = dict(stream)
    new_stream["chunks"] = sorted_chunks
    new_stream["accumulatedContent"] = accumulated
    new_stream["totalTokens"] = completion_tokens
    
    if chunk.finishReason:
        new_stream["finishReason"] = chunk.finishReason
    
    return new_stream


def update_stream_chunk(
    stream       : Dict[str, Any],
    chunk_id     : str,
    content      : str,
    finish_reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a specific chunk content / finishReason in the stream."""
    chunks = list(stream["chunks"])
    found_idx = -1
    for idx, c in enumerate(chunks):
        if c.chunkId == chunk_id:
            found_idx = idx
            break
    if found_idx == -1:
        raise ValueError(f"Chunk with ID '{chunk_id}' not found.")

    old_chunk = chunks[found_idx]
    new_chunk = build_stream_chunk(
        stream_id       = stream["streamId"],
        sequence_number = old_chunk.sequenceNumber,
        content         = content,
        finish_reason   = finish_reason,
    )
    chunks[found_idx] = new_chunk

    sorted_chunks = sorted(chunks, key=lambda c: c.sequenceNumber)
    accumulated = "".join(c.content for c in sorted_chunks)
    completion_tokens = max(0, -(-len(accumulated) // 4)) if accumulated else 0

    new_stream = dict(stream)
    new_stream["chunks"] = sorted_chunks
    new_stream["accumulatedContent"] = accumulated
    new_stream["totalTokens"] = completion_tokens
    
    if new_chunk.finishReason:
        new_stream["finishReason"] = new_chunk.finishReason
        
    return new_stream


def delete_stream_chunk(
    stream  : Dict[str, Any],
    chunk_id: str,
) -> Dict[str, Any]:
    """Delete a chunk from the stream and rebuild accumulated metrics."""
    chunks = list(stream["chunks"])
    remaining = [c for c in chunks if c.chunkId != chunk_id]
    if len(remaining) == len(chunks):
        raise ValueError(f"Chunk with ID '{chunk_id}' not found.")

    sorted_chunks = sorted(remaining, key=lambda c: c.sequenceNumber)
    accumulated = "".join(c.content for c in sorted_chunks)
    completion_tokens = max(0, -(-len(accumulated) // 4)) if accumulated else 0

    new_stream = dict(stream)
    new_stream["chunks"] = sorted_chunks
    new_stream["accumulatedContent"] = accumulated
    new_stream["totalTokens"] = completion_tokens
    
    # Recalculate finishReason from remaining chunks
    fr = None
    for c in sorted_chunks:
        if c.finishReason:
            fr = c.finishReason
    new_stream["finishReason"] = fr
    
    return new_stream


def find_stream_chunk(
    stream  : Dict[str, Any],
    chunk_id: str,
) -> Optional[GroqStreamChunk]:
    """Find a chunk in the stream by its chunkId."""
    for c in stream.get("chunks", []):
        if c.chunkId == chunk_id:
            return c
    return None


def search_stream_chunks(
    stream: Dict[str, Any],
    query : str,
) -> List[GroqStreamChunk]:
    """Search chunks inside a stream by query (case-insensitive on content / chunkId)."""
    q = query.lower().strip()
    if not q:
        return list(stream.get("chunks", []))
    return [c for c in stream.get("chunks", []) if q in c.content.lower() or q in c.chunkId.lower()]


def build_stream_summary(chunks: List[GroqStreamChunk]) -> str:
    """Generate deterministic summary text for the chunks."""
    if not chunks:
        return "No chunks to summarize."
    lines = []
    for c in chunks:
        lines.append(f"Seq {c.sequenceNumber}: {c.content[:30]}")
    return "Stream summary: " + " | ".join(lines)


def calculate_stream_statistics(streams: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute statistics across all stream records."""
    total = len(streams)
    active = 0
    paused = 0
    completed = 0
    cancelled = 0
    failed = 0
    
    total_chunks = 0
    total_tokens = 0
    total_latency = 0
    
    status_counts: Dict[str, int] = {}
    provider_counts: Dict[str, int] = {}
    
    for s in streams:
        status = (s.get("status") or "active").lower().strip()
        if status == "active":
            active += 1
        elif status == "paused":
            paused += 1
        elif status == "completed":
            completed += 1
        elif status == "cancelled":
            cancelled += 1
        elif status == "failed":
            failed += 1
            
        status_counts[status] = status_counts.get(status, 0) + 1
        
        prov = (s.get("provider") or "unknown").lower().strip()
        provider_counts[prov] = provider_counts.get(prov, 0) + 1
        
        total_chunks += len(s.get("chunks", []))
        total_tokens += s.get("totalTokens", 0)
        total_latency += s.get("latencyMs", 0)
        
    avg_chunks = float(total_chunks) / total if total > 0 else 0.0
    avg_tokens = float(total_tokens) / total if total > 0 else 0.0
    avg_latency = float(total_latency) / total if total > 0 else 0.0
    
    return {
        "totalStreams": total,
        "activeStreams": active,
        "pausedStreams": paused,
        "completedStreams": completed,
        "cancelledStreams": cancelled,
        "failedStreams": failed,
        "averageChunks": round(avg_chunks, 4),
        "averageTokens": round(avg_tokens, 4),
        "averageLatency": round(avg_latency, 4),
        "statusCounts": status_counts,
        "providerCounts": provider_counts,
    }


def get_stream_status(stream: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve current stream status flags."""
    status_str = stream.get("status", "active")
    completed = status_str.lower().strip() == "completed" or stream.get("finishReason") is not None
    return {
        "streamId": stream["streamId"],
        "status": status_str,
        "chunkCount": len(stream.get("chunks", [])),
        "totalTokens": stream.get("totalTokens", 0),
        "latencyMs": stream.get("latencyMs", 0),
        "completed": completed,
    }


# ===========================================================================
# Endpoints
# ===========================================================================

@streaming_router.get(
    "",
    response_model=APIResponse,
    summary="List streams",
)
def list_streams(
    page: int = 1,
    pageSize: int = 20,
    sortBy: str = "createdAt",
    sortOrder: str = "asc",
    status: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    userId: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumTokens: Optional[int] = None,
    maximumTokens: Optional[int] = None,
    minimumChunks: Optional[int] = None,
    maximumChunks: Optional[int] = None,
    minimumLatency: Optional[int] = None,
    maximumLatency: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        streams = list(_STREAM_STORE.values())
        filtered = filter_streams(
            streams,
            status=status,
            provider=provider,
            model=model,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            minimumChunks=minimumChunks,
            maximumChunks=maximumChunks,
            minimumLatency=minimumLatency,
            maximumLatency=maximumLatency,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )
        sorted_streams = sort_streams(filtered, sortBy, sortOrder)
        paged_slice, pagination = paginate_streams(sorted_streams, page, pageSize)
        
        from api.responses import build_paginated_response
        streams_resp = [_stream_to_response(s) for s in paged_slice]
        return build_paginated_response(
            items=streams_resp,
            page=page,
            page_size=pageSize,
            total_items=len(filtered),
            message=f"{len(filtered)} stream(s) found.",
        )
    except APIErrorValidation as val_err:
        return exception_to_api_response(val_err)
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get stream statistics",
)
def get_statistics() -> APIResponse:
    try:
        streams = list(_STREAM_STORE.values())
        stats = calculate_stream_statistics(streams)
        payload = StreamStatisticsResponse(**stats)
        return build_success_response(
            data=payload.model_dump(),
            message="Statistics calculated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search streams",
)
def search_streams_endpoint(
    q: str = Query(..., min_length=1),
    page: int = 1,
    pageSize: int = 20,
    sortBy: str = "createdAt",
    sortOrder: str = "asc",
    status: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    userId: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumTokens: Optional[int] = None,
    maximumTokens: Optional[int] = None,
    minimumChunks: Optional[int] = None,
    maximumChunks: Optional[int] = None,
    minimumLatency: Optional[int] = None,
    maximumLatency: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        matched = search_streams(list(_STREAM_STORE.values()), q)
        filtered = filter_streams(
            matched,
            status=status,
            provider=provider,
            model=model,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            minimumChunks=minimumChunks,
            maximumChunks=maximumChunks,
            minimumLatency=minimumLatency,
            maximumLatency=maximumLatency,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )
        sorted_streams = sort_streams(filtered, sortBy, sortOrder)
        paged_slice, pagination = paginate_streams(sorted_streams, page, pageSize)
        
        from api.responses import build_paginated_response
        streams_resp = [_stream_to_response(s) for s in paged_slice]
        return build_paginated_response(
            items=streams_resp,
            page=page,
            page_size=pageSize,
            total_items=len(filtered),
            message=f"{len(filtered)} stream(s) matched '{q}'.",
        )
    except APIErrorValidation as val_err:
        return exception_to_api_response(val_err)
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/{streamId}",
    response_model=APIResponse,
    summary="Get a stream by ID",
)
def get_stream(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        resp = _stream_to_response(s)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream retrieved successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "",
    response_model=APIResponse,
    summary="Create a stream",
)
def create_stream(body: CreateStreamRequest) -> APIResponse:
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid stream creation request.", details=errs)
            )
            
        state = build_stream_state(body.requestId, [])
        stream_id = state.streamId
        
        if stream_id in _STREAM_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Stream for requestId '{body.requestId}' (streamId: '{stream_id}') already exists.")
            )
            
        s_dict = {
            "streamId": stream_id,
            "requestId": body.requestId,
            "streamName": body.streamName or f"Stream for Request {body.requestId}",
            "provider": body.provider,
            "model": body.model,
            "status": body.status or "active",
            "createdAt": body.createdAt,
            "updatedAt": body.createdAt,
            "userId": body.userId or "system",
            "projectId": body.projectId or "default-project",
            "investigationId": body.investigationId or "",
            "chunks": [],
            "accumulatedContent": "",
            "finishReason": None,
            "startedAt": 0,
            "completedAt": 0,
            "totalTokens": 0,
            "latencyMs": 0,
            "warnings": [],
        }
        _STREAM_STORE[stream_id] = s_dict
        
        resp = _stream_to_response(s_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.put(
    "/{streamId}",
    response_model=APIResponse,
    summary="Update stream metadata",
)
def update_stream(streamId: str, body: UpdateStreamRequest) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must specify at least one field to update.")
            )
            
        updated_dict = dict(s)
        if body.streamName is not None:
            updated_dict["streamName"] = body.streamName
        if body.status is not None:
            updated_dict["status"] = body.status
        if body.userId is not None:
            updated_dict["userId"] = body.userId
        if body.projectId is not None:
            updated_dict["projectId"] = body.projectId
        if body.investigationId is not None:
            updated_dict["investigationId"] = body.investigationId
        if body.updatedAt is not None:
            updated_dict["updatedAt"] = body.updatedAt
            
        _STREAM_STORE[streamId] = updated_dict
        resp = _stream_to_response(updated_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.delete(
    "/{streamId}",
    response_model=APIResponse,
    summary="Delete a stream",
)
def delete_stream(streamId: str) -> APIResponse:
    try:
        if streamId not in _STREAM_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        del _STREAM_STORE[streamId]
        return build_success_response(
            data=None,
            message="Stream deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/{streamId}/status",
    response_model=APIResponse,
    summary="Get stream status",
)
def get_stream_status_endpoint(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        status_dict = get_stream_status(s)
        payload = StreamStatusResponse(**status_dict)
        return build_success_response(
            data=payload.model_dump(),
            message="Stream status retrieved successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/{streamId}/summary",
    response_model=APIResponse,
    summary="Get stream summary",
)
def get_stream_summary_endpoint(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        summary_text = build_stream_summary(s.get("chunks", []))
        payload = StreamSummaryResponse(
            streamId=s["streamId"],
            requestId=s["requestId"],
            streamName=s["streamName"],
            status=s["status"],
            chunkCount=len(s.get("chunks", [])),
            totalTokens=s.get("totalTokens", 0),
            latencyMs=s.get("latencyMs", 0),
            summaryText=summary_text,
            createdAt=s["createdAt"],
            updatedAt=s["updatedAt"],
        )
        return build_success_response(
            data=payload.model_dump(),
            message="Stream summary retrieved successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.get(
    "/{streamId}/chunks",
    response_model=APIResponse,
    summary="Get stream chunks",
)
def get_stream_chunks(
    streamId: str,
    q: Optional[str] = None,
) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
        chunks = s.get("chunks", [])
        if q:
            chunks = search_stream_chunks(s, q)
            
        chunks_resp = [
            StreamChunkResponse(
                chunkId        = c.chunkId,
                sequenceNumber = c.sequenceNumber,
                content        = c.content,
                finishReason   = c.finishReason,
                receivedAt     = c.receivedAt,
            )
            for c in chunks
        ]
        return build_success_response(
            data=[c.model_dump() for c in chunks_resp],
            message=f"{len(chunks_resp)} chunk(s) retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/{streamId}/chunks",
    response_model=APIResponse,
    summary="Append a chunk to stream",
)
def append_chunk_endpoint(streamId: str, body: StreamChunkRequest) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid chunk data.", details=errs)
            )
            
        from services.groq_streaming_service import (
            DuplicateChunkError,
            InvalidSequenceError,
            InvalidFinishReasonError,
        )
        try:
            chunk = build_stream_chunk(
                stream_id       = streamId,
                sequence_number = body.sequenceNumber,
                content         = body.content,
                finish_reason   = body.finishReason,
            )
            updated_stream = append_stream_chunk(s, chunk)
        except DuplicateChunkError as exc:
            return exception_to_api_response(
                APIErrorConflict(f"Duplicate chunk sequence number: {exc}")
            )
        except (InvalidSequenceError, InvalidFinishReasonError) as exc:
            return exception_to_api_response(
                APIErrorValidation(f"Validation failed for chunk: {exc}")
            )
            
        if chunk.finishReason:
            updated_stream["status"] = "completed"
            updated_stream["finishReason"] = chunk.finishReason
            updated_stream["completedAt"] = _mono_ms()
            if updated_stream.get("startedAt", 0) > 0:
                updated_stream["latencyMs"] = max(0, updated_stream["completedAt"] - updated_stream["startedAt"])
            else:
                updated_stream["latencyMs"] = 0
                
        _STREAM_STORE[streamId] = updated_stream
        
        resp = StreamChunkResponse(
            chunkId        = chunk.chunkId,
            sequenceNumber = chunk.sequenceNumber,
            content        = chunk.content,
            finishReason   = chunk.finishReason,
            receivedAt     = chunk.receivedAt,
        )
        return build_success_response(
            data=resp.model_dump(),
            message="Chunk appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.put(
    "/{streamId}/chunks/{chunkId}",
    response_model=APIResponse,
    summary="Update a chunk",
)
def update_chunk_endpoint(
    streamId: str,
    chunkId : str,
    body    : StreamChunkRequest,
) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid chunk update data.", details=errs)
            )
            
        old_chunk = find_stream_chunk(s, chunkId)
        if not old_chunk:
            return exception_to_api_response(
                APIErrorNotFound(f"Chunk with ID '{chunkId}' not found in stream '{streamId}'.")
            )
            
        if body.sequenceNumber != old_chunk.sequenceNumber:
            for c in s["chunks"]:
                if c.chunkId != chunkId and c.sequenceNumber == body.sequenceNumber:
                    return exception_to_api_response(
                        APIErrorConflict(f"Sequence number {body.sequenceNumber} already exists in another chunk.")
                    )
                    
        try:
            updated_stream = update_stream_chunk(
                stream        = s,
                chunk_id      = chunkId,
                content       = body.content,
                finish_reason = body.finishReason,
            )
        except ValueError as exc:
            return exception_to_api_response(APIErrorNotFound(str(exc)))
        except Exception as exc:
            return exception_to_api_response(APIErrorValidation(str(exc)))
            
        _STREAM_STORE[streamId] = updated_stream
        
        updated_chunk = None
        for c in updated_stream["chunks"]:
            if c.sequenceNumber == body.sequenceNumber:
                updated_chunk = c
                break
                
        resp = StreamChunkResponse(
            chunkId        = updated_chunk.chunkId,
            sequenceNumber = updated_chunk.sequenceNumber,
            content        = updated_chunk.content,
            finishReason   = updated_chunk.finishReason,
            receivedAt     = updated_chunk.receivedAt,
        )
        return build_success_response(
            data=resp.model_dump(),
            message="Chunk updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.delete(
    "/{streamId}/chunks/{chunkId}",
    response_model=APIResponse,
    summary="Delete a chunk",
)
def delete_chunk_endpoint(streamId: str, chunkId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        old_chunk = find_stream_chunk(s, chunkId)
        if not old_chunk:
            return exception_to_api_response(
                APIErrorNotFound(f"Chunk with ID '{chunkId}' not found in stream '{streamId}'.")
            )
            
        try:
            updated_stream = delete_stream_chunk(s, chunkId)
        except ValueError as exc:
            return exception_to_api_response(APIErrorNotFound(str(exc)))
            
        _STREAM_STORE[streamId] = updated_stream
        return build_success_response(
            data=None,
            message="Chunk deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/{streamId}/start",
    response_model=APIResponse,
    summary="Start stream",
)
def start_stream(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        updated_dict = dict(s)
        updated_dict["status"] = "active"
        updated_dict["startedAt"] = _mono_ms()
        updated_dict["completedAt"] = 0
        updated_dict["latencyMs"] = 0
        
        _STREAM_STORE[streamId] = updated_dict
        resp = _stream_to_response(updated_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream started successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/{streamId}/pause",
    response_model=APIResponse,
    summary="Pause stream",
)
def pause_stream(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        updated_dict = dict(s)
        updated_dict["status"] = "paused"
        
        _STREAM_STORE[streamId] = updated_dict
        resp = _stream_to_response(updated_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream paused successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/{streamId}/resume",
    response_model=APIResponse,
    summary="Resume stream",
)
def resume_stream(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        updated_dict = dict(s)
        updated_dict["status"] = "active"
        
        _STREAM_STORE[streamId] = updated_dict
        resp = _stream_to_response(updated_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream resumed successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/{streamId}/cancel",
    response_model=APIResponse,
    summary="Cancel stream",
)
def cancel_stream(streamId: str) -> APIResponse:
    try:
        s = _STREAM_STORE.get(streamId)
        if not s:
            return exception_to_api_response(
                APIErrorNotFound(f"Stream with ID '{streamId}' not found.")
            )
            
        updated_dict = dict(s)
        updated_dict["status"] = "cancelled"
        updated_dict["completedAt"] = _mono_ms()
        if updated_dict.get("startedAt", 0) > 0:
            updated_dict["latencyMs"] = max(0, updated_dict["completedAt"] - updated_dict["startedAt"])
        else:
            updated_dict["latencyMs"] = 0
            
        _STREAM_STORE[streamId] = updated_dict
        resp = _stream_to_response(updated_dict)
        return build_success_response(
            data=resp.model_dump(),
            message="Stream cancelled successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create streams",
)
def bulk_create_streams(body: BulkCreateStreamsRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )
            
        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []
        
        for i, item in enumerate(body.streams):
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"streamId": "", "reason": "; ".join(item_errors)})
                continue
                
            try:
                state = build_stream_state(item.requestId, [])
                stream_id = state.streamId
                
                if stream_id in _STREAM_STORE:
                    failed.append({"streamId": stream_id, "reason": f"Stream '{stream_id}' already exists."})
                    continue
                    
                s_dict = {
                    "streamId": stream_id,
                    "requestId": item.requestId,
                    "streamName": item.streamName or f"Stream for Request {item.requestId}",
                    "provider": item.provider,
                    "model": item.model,
                    "status": item.status or "active",
                    "createdAt": item.createdAt,
                    "updatedAt": item.createdAt,
                    "userId": item.userId or "system",
                    "projectId": item.projectId or "default-project",
                    "investigationId": item.investigationId or "",
                    "chunks": [],
                    "accumulatedContent": "",
                    "finishReason": None,
                    "startedAt": 0,
                    "completedAt": 0,
                    "totalTokens": 0,
                    "latencyMs": 0,
                    "warnings": [],
                }
                _STREAM_STORE[stream_id] = s_dict
                succeeded.append(stream_id)
            except Exception as e:
                failed.append({"streamId": "", "reason": str(e)})
                
        payload = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(body.streams),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=payload.model_dump(),
            message=f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update streams",
)
def bulk_update_streams(body: BulkUpdateStreamsRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )
            
        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []
        
        for item in body.items:
            sid = item.streamId
            s = _STREAM_STORE.get(sid)
            if s is None:
                failed.append({"streamId": sid, "reason": f"Stream '{sid}' not found."})
                continue
                
            try:
                upd = item.update
                updated_dict = dict(s)
                if upd.streamName is not None:
                    updated_dict["streamName"] = upd.streamName
                if upd.status is not None:
                    updated_dict["status"] = upd.status
                if upd.userId is not None:
                    updated_dict["userId"] = upd.userId
                if upd.projectId is not None:
                    updated_dict["projectId"] = upd.projectId
                if upd.investigationId is not None:
                    updated_dict["investigationId"] = upd.investigationId
                if upd.updatedAt is not None:
                    updated_dict["updatedAt"] = upd.updatedAt
                    
                _STREAM_STORE[sid] = updated_dict
                succeeded.append(sid)
            except Exception as e:
                failed.append({"streamId": sid, "reason": str(e)})
                
        payload = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(body.items),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=payload.model_dump(),
            message=f"Bulk update completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@streaming_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete streams",
)
def bulk_delete_streams(body: BulkDeleteStreamsRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )
            
        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []
        
        for sid in body.streamIds:
            if sid not in _STREAM_STORE:
                failed.append({"streamId": sid, "reason": f"Stream '{sid}' not found."})
                continue
                
            try:
                _STREAM_STORE.pop(sid)
                succeeded.append(sid)
            except Exception as e:
                failed.append({"streamId": sid, "reason": str(e)})
                
        payload = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(body.streamIds),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=payload.model_dump(),
            message=f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
