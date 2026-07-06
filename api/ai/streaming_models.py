"""
AI Streaming API Models — Phase A4.8.9
=======================================
Immutable Pydantic models for AI Streaming request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateStreamRequest(BaseModel):
    """
    Request body for POST /api/v2/ai/streaming.
    """
    requestId       : str
    provider        : str
    model           : str
    createdAt       : str
    streamName      : Optional[str] = None
    userId          : Optional[str] = "system"
    projectId       : Optional[str] = "default-project"
    investigationId : Optional[str] = ""
    status          : Optional[str] = "active"

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation error strings. Empty means valid."""
        errors: List[str] = []
        if not self.requestId or not self.requestId.strip():
            errors.append("requestId must not be empty.")
        if not self.provider or not self.provider.strip():
            errors.append("provider must not be empty.")
        if not self.model or not self.model.strip():
            errors.append("model must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateStreamRequest(BaseModel):
    """
    Request body for PUT /api/v2/ai/streaming/{streamId}.
    """
    streamName      : Optional[str] = None
    status          : Optional[str] = None
    userId          : Optional[str] = None
    projectId       : Optional[str] = None
    investigationId : Optional[str] = None
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class StreamChunkRequest(BaseModel):
    """
    Request body for POST /api/v2/ai/streaming/{streamId}/chunks.
    """
    sequenceNumber : int
    content        : str
    finishReason   : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation error strings. Empty means valid."""
        errors: List[str] = []
        if self.sequenceNumber is None or self.sequenceNumber < 0:
            errors.append("sequenceNumber must be a non-negative integer.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class StreamChunkResponse(BaseModel):
    """
    Response model representing one chunk.
    """
    chunkId        : str
    sequenceNumber : int
    content        : str
    finishReason   : Optional[str] = None
    receivedAt     : int

    class Config:
        frozen = True


class StreamResponse(BaseModel):
    """
    Response model representing one stream.
    """
    streamId           : str
    requestId          : str
    streamName         : str
    provider           : str
    model              : str
    status             : str
    createdAt          : str
    updatedAt          : str
    userId             : str
    projectId          : str
    investigationId    : str
    chunkCount         : int
    totalTokens        : int
    latencyMs          : int
    accumulatedContent : str
    finishReason       : Optional[str] = None
    chunks             : List[StreamChunkResponse]

    class Config:
        frozen = True


class StreamListResponse(BaseModel):
    """
    Payload for GET /api/v2/ai/streaming (list).
    """
    streams : List[StreamResponse]
    total   : int

    class Config:
        frozen = True


class StreamStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/ai/streaming/statistics.
    """
    totalStreams      : int
    activeStreams     : int
    pausedStreams     : int
    completedStreams  : int
    cancelledStreams  : int
    failedStreams     : int
    averageChunks     : float
    averageTokens     : float
    averageLatency     : float
    statusCounts       : Dict[str, int]
    providerCounts     : Dict[str, int]

    class Config:
        frozen = True


class StreamStatusResponse(BaseModel):
    """
    Payload for GET /api/v2/ai/streaming/{streamId}/status.
    """
    streamId    : str
    status      : str
    chunkCount  : int
    totalTokens : int
    latencyMs   : int
    completed   : bool

    class Config:
        frozen = True


class StreamSummaryResponse(BaseModel):
    """
    Payload for GET /api/v2/ai/streaming/{streamId}/summary.
    """
    streamId    : str
    requestId   : str
    streamName  : str
    status      : str
    chunkCount  : int
    totalTokens : int
    latencyMs   : int
    summaryText : str
    createdAt   : str
    updatedAt   : str

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateStreamsRequest(BaseModel):
    """
    Request body for POST /api/v2/ai/streaming/bulk/create.
    """
    streams : List[CreateStreamRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.streams:
            errors.append("streams list must not be empty.")
        for i, s in enumerate(self.streams):
            sub = s.validate_request()
            for e in sub:
                errors.append(f"streams[{i}]: {e}")
        return errors


class BulkUpdateStreamsRequest(BaseModel):
    """
    Request body for PUT /api/v2/ai/streaming/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        streamId : str
        update   : UpdateStreamRequest

        class Config:
            frozen = True

    items : List[BulkUpdateItem] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.items:
            errors.append("items list must not be empty.")
        for i, item in enumerate(self.items):
            if not item.streamId or not item.streamId.strip():
                errors.append(f"items[{i}]: streamId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteStreamsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/ai/streaming/bulk/delete.
    """
    streamIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.streamIds:
            errors.append("streamIds list must not be empty.")
        for i, sid in enumerate(self.streamIds):
            if not sid or not sid.strip():
                errors.append(f"streamIds[{i}]: streamId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Summary of bulk operation results.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
