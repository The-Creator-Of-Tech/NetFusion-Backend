"""
API Layer — Phase A4.7.1
========================
Public surface of the NetFusion V2 API layer.

This package defines:
  - Immutable request / response / error Pydantic models  (api/models.py)
  - Typed API exceptions                                   (api/errors.py)
  - Response builder helpers                               (api/responses.py)
  - Root APIRouter with sub-router groups and system endpoints (api/router.py)
  - Utility helpers: validation, health/version builders   (api/utils.py)

Nothing in this package executes business logic, talks to a database,
calls an AI provider, or performs I/O of any kind beyond serving the
two system endpoints (GET /health, GET /version).
"""

from api.models import (
    APIError,
    APIResponse,
    HealthResponse,
    Pagination,
    VersionResponse,
)
from api.errors import (
    APILayerError,
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.responses import (
    build_error_response,
    build_error_response_from_exception,
    build_paginated_response,
    build_success_response,
)
from api.utils import (
    build_health_response,
    build_version_response,
    exception_to_api_response,
    get_engine_version_registry,
    validate_pagination,
)
from api.router import (
    root_router,
    investigation_router,
    ai_router,
    knowledge_router,
    workflow_router,
    reports_router,
    system_router,
)
from api.investigation import asset_router

__all__ = [
    # models
    "APIError",
    "APIResponse",
    "HealthResponse",
    "Pagination",
    "VersionResponse",
    # errors
    "APILayerError",
    "APIErrorConflict",
    "APIErrorInternal",
    "APIErrorNotFound",
    "APIErrorValidation",
    # response builders
    "build_error_response",
    "build_error_response_from_exception",
    "build_paginated_response",
    "build_success_response",
    # utility helpers
    "build_health_response",
    "build_version_response",
    "exception_to_api_response",
    "get_engine_version_registry",
    "validate_pagination",
    # routers
    "root_router",
    "investigation_router",
    "ai_router",
    "knowledge_router",
    "workflow_router",
    "reports_router",
    "system_router",
    "asset_router",
]
