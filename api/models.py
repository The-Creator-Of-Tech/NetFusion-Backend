"""
API Models — Phase A4.7.1
==========================
Immutable Pydantic models that define the NetFusion V2 API contract.

Design rules
------------
- All models are frozen (frozen=True) — immutable after construction.
- No UUID generation inside models — callers supply all identity values.
- No timestamp generation inside models — callers supply timestamps.
- No randomness of any kind.
- No business logic — pure data containers.
- All Optional fields default to None so callers can omit them.
- Generic type parameter on APIResponse is Any so it carries any payload
  without requiring concrete type imports in orchestration code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

from core.constants import API_LAYER_VERSION


class DictAttributeWrapper(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(f"'DictAttributeWrapper' object has no attribute '{name}'")
    def __setattr__(self, name, value):
        self[name] = value


# ---------------------------------------------------------------------------
# APIResponse — generic envelope for every successful API response
# ---------------------------------------------------------------------------

class APIResponse(BaseModel):
    """
    Generic immutable response envelope.

    Every API endpoint that succeeds wraps its payload in this model so
    clients always receive a consistent top-level structure.

    Fields
    ------
    success   : True for successful responses; False when the call was
                processed but resulted in a logical error (e.g. empty
                result set that the caller must handle).
    message   : Human-readable status message.  Non-empty on error paths.
    data      : Arbitrary payload — any JSON-serialisable value.
                None when the operation produced no payload (e.g. DELETE).
    metadata  : Optional key-value bag for supplementary context
                (pagination cursors, engine versions, request IDs, etc.).
    timestamp : ISO-8601 UTC timestamp supplied by the caller.
                The API layer never generates timestamps internally.
    """
    success   : bool
    message   : str
    data      : Optional[Any]             = None
    metadata  : Optional[Dict[str, Any]]  = None
    timestamp : Optional[str]             = None

    @validator("data", pre=True, always=True)
    def wrap_data(cls, v):
        if isinstance(v, dict):
            return DictAttributeWrapper(v)
        return v

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# APIError — structured error payload
# ---------------------------------------------------------------------------

class APIError(BaseModel):
    """
    Structured error payload returned inside APIResponse.data on failure,
    or raised as an exception body via the typed error classes in errors.py.

    Fields
    ------
    errorCode : Machine-readable error code string (e.g. "NOT_FOUND",
                "VALIDATION_ERROR").  Always uppercase snake-case.
    error     : Short human-readable error title (one sentence).
    details   : Optional list of granular error detail strings — used for
                field-level validation errors or multi-cause failures.
    """
    errorCode : str
    error     : str
    details   : Optional[List[str]] = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Pagination — cursor / offset pagination metadata
# ---------------------------------------------------------------------------

class Pagination(BaseModel):
    """
    Pagination metadata attached to list responses.

    Fields
    ------
    page       : 1-based current page number.
    pageSize   : Maximum number of items per page.
    totalItems : Total number of items across all pages.
    totalPages : Computed ceiling of totalItems / pageSize.
                 Callers may also compute this themselves; it is provided
                 as a convenience field to avoid client-side maths.
    """
    page       : int
    pageSize   : int
    totalItems : int
    totalPages : int

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# HealthResponse — /system/health payload
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """
    Health-check response payload.

    Fields
    ------
    status  : One of "healthy", "degraded", or "unhealthy".
    version : API layer version string (API_LAYER_VERSION).
    uptime  : Caller-supplied uptime string (e.g. "3d 04h 12m").
              The API layer never measures uptime internally.
    """
    status  : str
    version : str = API_LAYER_VERSION
    uptime  : Optional[str] = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# VersionResponse — /system/version payload
# ---------------------------------------------------------------------------

class VersionResponse(BaseModel):
    """
    Version information response payload.

    Fields
    ------
    apiVersion     : The API layer version (API_LAYER_VERSION).
    engineVersions : Mapping of engine name → version string for every
                     service engine registered with the API layer.
                     Populated by the orchestration layer at startup;
                     the model itself does not populate it.
    """
    apiVersion     : str
    engineVersions : Dict[str, str]

    class Config:
        frozen = True
