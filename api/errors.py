"""
API Typed Exceptions — Phase A4.7.1
=====================================
Typed exception hierarchy for the NetFusion V2 API layer.

Design rules
------------
- All exceptions inherit from APILayerError (the base).
- Each subclass carries a default errorCode and HTTP status hint so the
  FastAPI exception handler (added in a later phase) can map them cleanly.
- No business logic lives here — these are pure exception containers.
- The message and details fields mirror APIError so handlers can build an
  APIError instance directly from the exception without re-parsing.

Exception hierarchy
-------------------
APILayerError
├── APIErrorValidation   (422 Unprocessable Entity)
├── APIErrorNotFound     (404 Not Found)
├── APIErrorConflict     (409 Conflict)
└── APIErrorInternal     (500 Internal Server Error)
"""

from __future__ import annotations

from typing import List, Optional


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class APILayerError(Exception):
    """
    Base class for all NetFusion API layer exceptions.

    Attributes
    ----------
    error_code  : Machine-readable error code (uppercase snake-case).
    message     : Short human-readable description of the error.
    details     : Optional list of granular detail strings.
    http_status : Suggested HTTP status code for the FastAPI handler.
                  Stored here so callers don't need to re-derive it.
    """

    error_code  : str = "API_ERROR"
    http_status : int = 500

    def __init__(
        self,
        message : str,
        details : Optional[List[str]] = None,
        error_code: Optional[str]     = None,
    ) -> None:
        super().__init__(message)
        self.message    = message
        self.details    = details or []
        # Allow per-instance override of the class-level default
        if error_code is not None:
            self.error_code = error_code

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r}, "
            f"details={self.details!r})"
        )

    def __str__(self) -> str:
        if self.details:
            detail_str = "; ".join(self.details)
            return f"[{self.error_code}] {self.message} — {detail_str}"
        return f"[{self.error_code}] {self.message}"


# ---------------------------------------------------------------------------
# APIErrorValidation — 422 Unprocessable Entity
# ---------------------------------------------------------------------------

class APIErrorValidation(APILayerError):
    """
    Raised when request data fails validation before reaching service logic.

    Typical uses
    ------------
    - Missing required fields.
    - Field value out of allowed range.
    - Enum value not recognised.
    - Cross-field constraint violation.

    HTTP mapping : 422 Unprocessable Entity
    errorCode    : "VALIDATION_ERROR"
    """

    error_code  : str = "VALIDATION_ERROR"
    http_status : int = 422

    def __init__(
        self,
        message : str                 = "Request validation failed.",
        details : Optional[List[str]] = None,
    ) -> None:
        super().__init__(message=message, details=details, error_code="VALIDATION_ERROR")


# ---------------------------------------------------------------------------
# APIErrorNotFound — 404 Not Found
# ---------------------------------------------------------------------------

class APIErrorNotFound(APILayerError):
    """
    Raised when a requested resource does not exist.

    Typical uses
    ------------
    - reportId / findingId / alertId not found in the collection.
    - Requested project has no data.

    HTTP mapping : 404 Not Found
    errorCode    : "NOT_FOUND"
    """

    error_code  : str = "NOT_FOUND"
    http_status : int = 404

    def __init__(
        self,
        message : str                 = "The requested resource was not found.",
        details : Optional[List[str]] = None,
    ) -> None:
        super().__init__(message=message, details=details, error_code="NOT_FOUND")


# ---------------------------------------------------------------------------
# APIErrorConflict — 409 Conflict
# ---------------------------------------------------------------------------

class APIErrorConflict(APILayerError):
    """
    Raised when a request conflicts with the current state of a resource.

    Typical uses
    ------------
    - Duplicate resource creation (same deterministic ID already exists).
    - Concurrent modification conflict detected by a fingerprint check.
    - State transition not allowed from the current lifecycle status.

    HTTP mapping : 409 Conflict
    errorCode    : "CONFLICT"
    """

    error_code  : str = "CONFLICT"
    http_status : int = 409

    def __init__(
        self,
        message : str                 = "The request conflicts with an existing resource.",
        details : Optional[List[str]] = None,
    ) -> None:
        super().__init__(message=message, details=details, error_code="CONFLICT")


# ---------------------------------------------------------------------------
# APIErrorInternal — 500 Internal Server Error
# ---------------------------------------------------------------------------

class APIErrorInternal(APILayerError):
    """
    Raised when an unexpected server-side error occurs that cannot be mapped
    to a more specific API error type.

    Typical uses
    ------------
    - Unhandled exception in service or repository layer.
    - Unexpected None returned from a builder that should always succeed.
    - Infrastructure failure (database unavailable, etc.).

    HTTP mapping : 500 Internal Server Error
    errorCode    : "INTERNAL_ERROR"

    Note: the exception message must never include secrets, raw stack traces,
    or internal implementation details — sanitise before raising.
    """

    error_code  : str = "INTERNAL_ERROR"
    http_status : int = 500

    def __init__(
        self,
        message : str                 = "An unexpected internal error occurred.",
        details : Optional[List[str]] = None,
    ) -> None:
        super().__init__(message=message, details=details, error_code="INTERNAL_ERROR")
