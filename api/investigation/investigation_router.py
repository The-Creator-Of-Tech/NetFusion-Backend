"""
Investigation Router
====================
REST interface for the Investigation service.
"""

from __future__ import annotations

from fastapi import APIRouter
from typing import Optional

from api.models import APIResponse
from api.responses import build_success_response
from api.errors import APIErrorValidation, APIErrorNotFound, APIErrorInternal
from api.utils import exception_to_api_response

from api.persistence import RepositoryBackedDict, map_investigation
from api.investigation.timeline_router import _TIMELINE_STORE
from api.investigation.asset_router import _ASSET_STORE
from api.investigation.finding_router import _FINDING_STORE

from services.investigation_service import InvestigationService
from api.investigation.investigation_models import (
    CreateInvestigationRequest,
    UpdateInvestigationRequest,
    LinkAssetRequest,
    LinkFindingRequest,
    InvestigationResponse,
    InvestigationStatisticsResponse,
)

investigation_router = APIRouter(
    prefix="/investigation",
    tags=["Investigation"],
)

_INVESTIGATION_STORE = RepositoryBackedDict("investigation", "investigationId", map_investigation)

# Instantiate the InvestigationService with the required stores
investigation_service = InvestigationService(
    investigation_store=_INVESTIGATION_STORE,
    timeline_store=_TIMELINE_STORE,
    asset_store=_ASSET_STORE,
    finding_store=_FINDING_STORE,
)

def _reset_store() -> None:
    _INVESTIGATION_STORE.clear()

@investigation_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a new investigation",
)
def create_investigation(body: CreateInvestigationRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation(message="Validation failed.", details=errors)
            )

        res = investigation_service.create_investigation(
            project_id=body.projectId,
            owner_id=body.ownerId,
            title=body.title,
            description=body.description,
            priority=body.priority,
            tags=body.tags,
            metadata=body.metadata,
        )
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Investigation created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.get(
    "/",
    response_model=APIResponse,
    summary="List all investigations",
)
def list_investigations(projectId: Optional[str] = None) -> APIResponse:
    try:
        res = investigation_service.list_investigations(project_id=projectId)
        return build_success_response(
            data=[InvestigationResponse(**i).model_dump() for i in res],
            message="Investigations retrieved successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get investigation statistics",
)
def get_statistics(projectId: Optional[str] = None) -> APIResponse:
    try:
        stats = investigation_service.get_statistics(project_id=projectId)
        return build_success_response(
            data=InvestigationStatisticsResponse(**stats).model_dump(),
            message="Statistics calculated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.get(
    "/{investigationId}",
    response_model=APIResponse,
    summary="Get investigation by ID",
)
def get_investigation(investigationId: str) -> APIResponse:
    try:
        res = investigation_service.get_investigation(investigation_id=investigationId)
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Investigation retrieved successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.put(
    "/{investigationId}",
    response_model=APIResponse,
    summary="Update investigation",
)
def update_investigation(investigationId: str, body: UpdateInvestigationRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation(message="Validation failed.", details=errors)
            )

        res = investigation_service.update_investigation(
            investigation_id=investigationId,
            title=body.title,
            description=body.description,
            priority=body.priority,
            tags=body.tags,
            metadata=body.metadata,
        )
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Investigation updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.post(
    "/{investigationId}/close",
    response_model=APIResponse,
    summary="Close an investigation",
)
def close_investigation(investigationId: str) -> APIResponse:
    try:
        res = investigation_service.close_investigation(investigation_id=investigationId)
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Investigation closed successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.delete(
    "/{investigationId}",
    response_model=APIResponse,
    summary="Delete an investigation",
)
def delete_investigation(investigationId: str) -> APIResponse:
    try:
        investigation_service.delete_investigation(investigation_id=investigationId)
        return build_success_response(
            data=None,
            message=f"Investigation '{investigationId}' deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.post(
    "/{investigationId}/link-asset",
    response_model=APIResponse,
    summary="Link asset to investigation",
)
def link_asset(investigationId: str, body: LinkAssetRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation(message="Validation failed.", details=errors)
            )

        res = investigation_service.link_asset(
            investigation_id=investigationId,
            asset_id=body.assetId,
        )
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Asset linked successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)

@investigation_router.post(
    "/{investigationId}/link-finding",
    response_model=APIResponse,
    summary="Link finding to investigation",
)
def link_finding(investigationId: str, body: LinkFindingRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation(message="Validation failed.", details=errors)
            )

        res = investigation_service.link_finding(
            investigation_id=investigationId,
            finding_id=body.findingId,
        )
        return build_success_response(
            data=InvestigationResponse(**res).model_dump(),
            message="Finding linked successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)) if not hasattr(exc, "http_status") else exc)
