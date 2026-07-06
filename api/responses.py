"""
API Response Builders — Phase A4.7.1
======================================
Pure deterministic helper functions that construct APIResponse objects.

Design rules
------------
- All builders return immutable APIResponse instances.
- No UUID generation — callers supply request_id / trace identifiers.
- No timestamp generation — callers supply the timestamp string.
- No randomness.
- No I/O, no service execution, no database access.
- Metadata dict is always a new copy — inputs are never mutated.

Builders
--------
build_success_response()   — wrap a successful payload in APIResponse
build_error_response()     — wrap an error in APIResponse (success=False)
build_paginated_response() — wrap a paged list payload in APIResponse
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from api.errors import APILayerError
from api.models import APIError, APIResponse, Pagination
from core.constants import API_LAYER_VERSION


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _base_metadata(
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the standard metadata dict included in every response.

    Always includes apiLayerVersion.  Caller-supplied extras are merged in;
    they take precedence over defaults if keys clash.

    Neither the input dict nor any mutable object is mutated.
    """
    base: Dict[str, Any] = {"apiLayerVersion": API_LAYER_VERSION}
    if extra:
        base = {**base, **extra}
    return base


# ---------------------------------------------------------------------------
# build_success_response()
# ---------------------------------------------------------------------------

def build_success_response(
    data      : Optional[Any]            = None,
    message   : str                      = "OK",
    timestamp : Optional[str]            = None,
    metadata  : Optional[Dict[str, Any]] = None,
) -> APIResponse:
    """
    Build a successful APIResponse envelope.

    Parameters
    ----------
    data      : Payload to carry in the response (any JSON-serialisable value).
                Pass None for operations that produce no payload (e.g. DELETE).
    message   : Human-readable success message.  Defaults to "OK".
    timestamp : ISO-8601 UTC timestamp string (caller-supplied).
                Pass None if no timestamp is available.
    metadata  : Optional additional key-value pairs to merge into the metadata
                dict alongside the standard apiLayerVersion field.

    Returns
    -------
    APIResponse (frozen / immutable)

    Examples
    --------
    >>> build_success_response(data={"reportId": "abc"}, timestamp="2026-07-03T00:00:00Z")
    APIResponse(success=True, message='OK', data={'reportId': 'abc'}, ...)
    """
    return APIResponse(
        success   = True,
        message   = message,
        data      = data,
        metadata  = _base_metadata(metadata),
        timestamp = timestamp,
    )


# ---------------------------------------------------------------------------
# build_error_response()
# ---------------------------------------------------------------------------

def build_error_response(
    error_code : str,
    error      : str,
    details    : Optional[List[str]]     = None,
    timestamp  : Optional[str]           = None,
    metadata   : Optional[Dict[str, Any]] = None,
) -> APIResponse:
    """
    Build a failed APIResponse envelope wrapping an APIError payload.

    Parameters
    ----------
    error_code : Machine-readable error code (e.g. "NOT_FOUND").
    error      : Short human-readable error title.
    details    : Optional list of granular detail strings.
    timestamp  : ISO-8601 UTC timestamp string (caller-supplied).
    metadata   : Optional additional key-value pairs.

    Returns
    -------
    APIResponse (frozen / immutable) with success=False and data=APIError.

    Examples
    --------
    >>> build_error_response("NOT_FOUND", "Report not found", timestamp="2026-07-03T00:00:00Z")
    APIResponse(success=False, message='Report not found', data=APIError(...), ...)
    """
    api_error = APIError(
        errorCode = error_code,
        error     = error,
        details   = list(details) if details else None,
    )
    return APIResponse(
        success   = False,
        message   = error,
        data      = api_error,
        metadata  = _base_metadata(metadata),
        timestamp = timestamp,
    )


def build_error_response_from_exception(
    exc       : APILayerError,
    timestamp : Optional[str]            = None,
    metadata  : Optional[Dict[str, Any]] = None,
) -> APIResponse:
    """
    Convenience overload — build an error response directly from an
    APILayerError (or any subclass).

    Parameters
    ----------
    exc       : Any APILayerError instance (APIErrorValidation, etc.).
    timestamp : ISO-8601 UTC timestamp string (caller-supplied).
    metadata  : Optional additional key-value pairs.

    Returns
    -------
    APIResponse (frozen / immutable)
    """
    return build_error_response(
        error_code = exc.error_code,
        error      = exc.message,
        details    = list(exc.details) if exc.details else None,
        timestamp  = timestamp,
        metadata   = metadata,
    )


# ---------------------------------------------------------------------------
# build_paginated_response()
# ---------------------------------------------------------------------------

def build_paginated_response(
    items      : List[Any],
    page       : int,
    page_size  : int,
    total_items: int,
    message    : str                      = "OK",
    timestamp  : Optional[str]            = None,
    metadata   : Optional[Dict[str, Any]] = None,
) -> APIResponse:
    """
    Build a successful paginated APIResponse envelope.

    The Pagination object is embedded in the response metadata under the
    key "pagination" so clients can access it without unwrapping data.
    The data field carries the items list directly.

    Parameters
    ----------
    items       : The page slice of items to return.
    page        : 1-based current page number (must be >= 1).
    page_size   : Maximum items per page (must be >= 1).
    total_items : Total items across all pages (must be >= 0).
    message     : Human-readable status message.
    timestamp   : ISO-8601 UTC timestamp (caller-supplied).
    metadata    : Optional additional key-value pairs merged into metadata.

    Returns
    -------
    APIResponse (frozen / immutable)

    Notes
    -----
    - totalPages is computed as ceil(total_items / page_size).
    - An empty result set (total_items=0) returns totalPages=0.
    - page_size=0 is guarded: totalPages defaults to 0 to avoid ZeroDivisionError.

    Examples
    --------
    >>> build_paginated_response(items=[...], page=1, page_size=20, total_items=55)
    APIResponse(success=True, data=[...], metadata={'pagination': Pagination(...)}, ...)
    """
    # Guard against division-by-zero; treat page_size < 1 as 1
    safe_page_size = max(1, page_size)
    total_pages    = math.ceil(total_items / safe_page_size) if total_items > 0 else 0

    pagination = Pagination(
        page       = max(1, page),
        pageSize   = safe_page_size,
        totalItems = max(0, total_items),
        totalPages = total_pages,
    )

    extra_meta: Dict[str, Any] = {"pagination": pagination.model_dump()}
    if metadata:
        extra_meta = {**extra_meta, **metadata}

    return APIResponse(
        success   = True,
        message   = message,
        data      = list(items),
        metadata  = _base_metadata(extra_meta),
        timestamp = timestamp,
    )
