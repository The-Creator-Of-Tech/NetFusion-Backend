"""
Base Service Foundation
=======================
Defines the BaseService class which provides standard capabilities (logging, validation, 
DI, response formatting, exception mapping) to all NetFusion service layers.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from api.errors import (
    APILayerError,
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.models import APIResponse
from api.responses import build_error_response, build_success_response


class BaseService:
    """
    Base service class containing generic functionality shared across services.
    
    No domain-specific or business logic lives here.
    """

    def __init__(self, logger_name: Optional[str] = None, **dependencies) -> None:
        """
        Constructor-based dependency injection.
        Saves all keyword arguments into the self.dependencies dict.
        """
        self.dependencies = dependencies
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)

    def get_dependency(self, name: str) -> Any:
        """Retrieve a registered dependency or raise an error if not found."""
        dep = self.dependencies.get(name)
        if dep is None:
            raise RuntimeError(
                f"Required dependency '{name}' was not provided to {self.__class__.__name__}."
            )
        return dep

    def log_info(self, msg: str, *args, **kwargs) -> None:
        self.logger.info(msg, *args, **kwargs)

    def log_warn(self, msg: str, *args, **kwargs) -> None:
        self.logger.warning(msg, *args, **kwargs)

    def log_error(self, msg: str, *args, **kwargs) -> None:
        self.logger.error(msg, *args, **kwargs)

    def validate_required(self, data: Dict[str, Any], fields: List[str]) -> None:
        """Ensure all required fields exist and are not empty/None."""
        missing = [f for f in fields if not data or data.get(f) is None or data.get(f) == ""]
        if missing:
            raise APIErrorValidation(
                message="Missing required field(s).",
                details=[f"Field '{f}' is required." for f in missing],
            )

    def validate_uuid(self, val: Any, field_name: str) -> str:
        """Ensure the value is a valid UUID string and return it."""
        if not val:
            raise APIErrorValidation(
                message="Validation failed.",
                details=[f"Field '{field_name}' must not be empty."]
            )
        val_str = str(val)
        try:
            uuid.UUID(val_str)
            return val_str
        except ValueError:
            raise APIErrorValidation(
                message="Invalid UUID format.",
                details=[f"Field '{field_name}' with value '{val}' is not a valid UUID."],
            )

    def validate_type(self, val: Any, expected_type: type, field_name: str) -> None:
        """Ensure the value has the expected type."""
        if not isinstance(val, expected_type):
            raise APIErrorValidation(
                message="Invalid field type.",
                details=[
                    f"Field '{field_name}' expected type '{expected_type.__name__}', got '{type(val).__name__}'."
                ],
            )

    def build_success(
        self,
        data      : Any,
        message   : str                      = "Success",
        timestamp : Optional[str]            = None,
        metadata  : Optional[Dict[str, Any]] = None,
    ) -> APIResponse:
        """Build standard success response envelope."""
        return build_success_response(
            data      = data,
            message   = message,
            timestamp = timestamp,
            metadata  = metadata,
        )

    def build_error(
        self,
        error_code : str,
        message    : str,
        details    : Optional[List[str]]     = None,
        timestamp  : Optional[str]           = None,
    ) -> APIResponse:
        """Build standard error response envelope."""
        return build_error_response(
            error_code = error_code,
            error      = message,
            details    = details,
            timestamp  = timestamp,
        )

    def handle_exception(self, exc: Exception) -> None:
        """Map generic python exceptions to API exceptions cleanly."""
        if isinstance(exc, APILayerError):
            raise exc
        self.log_error(f"Service exception caught: {str(exc)}", exc_info=True)
        raise APIErrorInternal(f"An unexpected internal error occurred: {str(exc)}")

    def utc_now_iso(self) -> str:
        """Helper to get current time as UTC ISO string ending in Z."""
        return datetime.utcnow().isoformat() + "Z"
