"""
AI Provider Registry API Router — Phase A4.8.8
==============================================
REST interface for Provider Registry.

Prefix  : /providers
Tag     : Provider Registry
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Query

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.ai.provider_registry_models import (
    CreateProviderRequest,
    UpdateProviderRequest,
    ProviderModelRequest,
    ProviderCapabilityRequest,
    ProviderHealthResponse,
    ProviderModelResponse,
    ProviderResponse,
    ProviderListResponse,
    ProviderStatisticsResponse,
    ProviderSearchResponse,
    BulkCreateProvidersRequest,
    BulkUpdateProvidersRequest,
    BulkDeleteProvidersRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response, validate_pagination

from services.provider_registry_service import (
    ProviderDefinition,
    ProviderModel,
    ProviderCapability,
    ProviderSelection,
    build_provider_definition,
    build_provider_model,
    build_provider_capability,
    validate_provider,
    validate_model,
    ProviderValidationError,
    DuplicateProviderError,
    DuplicateModelError,
    ProviderNotFoundError,
    ModelNotFoundError,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

provider_registry_router: APIRouter = APIRouter(
    prefix = "/providers",
    tags   = ["Provider Registry"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_provider
_PROVIDER_STORE = RepositoryBackedDict("provider", "providerId", map_provider)


def _bootstrap_store() -> None:
    """Populate store with built-in standard providers and models."""
    from services.provider_registry_service import build_default_registry
    _PROVIDER_STORE.clear()
    reg = build_default_registry()
    for prov in reg.list_providers():
        models = reg.list_models(provider_name=prov.providerName)
        max_prio = max([m.priority for m in models]) if models else 50
        
        session_dict = {
            "package"      : prov,
            "models"       : {m.modelId: m for m in models},
            "status"       : "ACTIVE" if prov.enabled else "DISABLED",
            "priority"     : max_prio,
            "healthScore"  : 100.0,
            "providerType" : "local" if prov.providerName == "ollama" else "cloud",
        }
        _PROVIDER_STORE[prov.providerId] = session_dict


def _reset_store() -> None:
    """Clear the in-memory store."""
    _PROVIDER_STORE.clear()


# Initialize on import
_bootstrap_store()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _health_status(score: float) -> str:
    """Map health score to status string."""
    if score >= 80.0:
        return "HEALTHY"
    if score >= 50.0:
        return "DEGRADED"
    return "OFFLINE"


def _rebuild_provider_definition(
    prov: ProviderDefinition,
    models: List[ProviderModel],
) -> ProviderDefinition:
    """Rebuild ProviderDefinition with updated supported models."""
    supported = [m.modelName for m in models]
    default_m = prov.defaultModel
    if default_m not in supported and supported:
        default_m = supported[0]
    return build_provider_definition(
        provider_name    = prov.providerName,
        display_name     = prov.displayName,
        api_version      = prov.apiVersion,
        endpoint         = prov.endpoint,
        supported_models = supported,
        default_model    = default_m,
        created_at       = prov.createdAt,
        enabled          = prov.enabled,
    )


def _provider_to_response(s: Dict[str, Any]) -> ProviderResponse:
    """Map stored provider state to ProviderResponse."""
    prov = s["package"]
    models = list(s["models"].values())
    
    models_resp = []
    for m in models:
        models_resp.append(ProviderModelResponse(
            modelId       = m.modelId,
            modelKey      = m.modelKey,
            provider      = m.provider,
            modelName     = m.modelName,
            alias         = m.alias,
            capabilities  = {
                "streaming"        : m.capabilities.streaming,
                "toolCalling"      : m.capabilities.toolCalling,
                "jsonMode"         : m.capabilities.jsonMode,
                "vision"           : m.capabilities.vision,
                "embeddings"       : m.capabilities.embeddings,
                "maxContextTokens" : m.capabilities.maxContextTokens,
                "maxOutputTokens"  : m.capabilities.maxOutputTokens,
            },
            enabled       = m.enabled,
            priority      = m.priority,
            createdAt     = m.createdAt,
            engineVersion = m.engineVersion,
        ))
        
    status_str = s.get("status") or "ACTIVE"
    return ProviderResponse(
        providerId      = prov.providerId,
        providerKey     = prov.providerKey,
        providerName    = prov.providerName,
        displayName     = prov.displayName,
        apiVersion      = prov.apiVersion,
        endpoint        = prov.endpoint,
        supportedModels = list(prov.supportedModels),
        defaultModel    = prov.defaultModel,
        enabled         = prov.enabled,
        createdAt       = prov.createdAt,
        engineVersion   = prov.engineVersion,
        priority        = s.get("priority", 50),
        healthScore     = s.get("healthScore", 100.0),
        providerType    = s.get("providerType") or "cloud",
        status          = status_str,
        modelCount      = len(models),
        models          = models_resp,
    )


# ---------------------------------------------------------------------------
# Sort map
# ---------------------------------------------------------------------------
_SORT_KEY_MAP: Dict[str, str] = {
    "providerName" : "providerName",
    "createdAt"    : "createdAt",
    "updatedAt"    : "createdAt",
}


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_provider(
    sessions: List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """Find provider by a specific field value."""
    target = value.lower().strip()
    for s in sessions:
        prov = s["package"]
        v = None
        if field in ("providerId", "packageId"): v = prov.providerId
        elif field == "providerKey": v = prov.providerKey
        elif field == "providerName": v = prov.providerName
        
        if v is not None and str(v).lower().strip() == target:
            return s
    return None


def sort_providers(
    sessions   : List[Dict[str, Any]],
    sort_by    : str = "createdAt",
    sort_order : str = "asc",
) -> List[Dict[str, Any]]:
    """Sort providers list."""
    reverse = sort_order.lower() == "desc"
    
    def sort_key(s: Dict[str, Any]):
        prov = s["package"]
        if sort_by == "priority":
            return (0, s.get("priority", 50))
        if sort_by == "healthScore":
            return (0, s.get("healthScore", 100.0))
        if sort_by == "modelCount":
            return (0, len(s["models"]))
            
        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(prov, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())
        
    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_providers(
    sessions             : List[Dict[str, Any]],
    provider             : Optional[str] = None,
    providerType         : Optional[str] = None,
    status               : Optional[str] = None,
    supportsStreaming    : Optional[bool] = None,
    supportsTools        : Optional[bool] = None,
    supportsVision       : Optional[bool] = None,
    supportsReasoning    : Optional[bool] = None,
    minimumContextWindow : Optional[int] = None,
    maximumContextWindow : Optional[int] = None,
    minimumPriority      : Optional[int] = None,
    maximumPriority      : Optional[int] = None,
    minimumHealthScore   : Optional[float] = None,
    maximumHealthScore   : Optional[float] = None,
    createdAfter         : Optional[str] = None,
    createdBefore        : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter providers list."""
    matched = []
    for s in sessions:
        prov = s["package"]
        models = list(s["models"].values())
        
        if provider is not None and prov.providerName.lower().strip() != provider.lower().strip():
            continue
            
        if providerType is not None and s.get("providerType", "").lower().strip() != providerType.lower().strip():
            continue
            
        c_status = s.get("status") or "ACTIVE"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue
            
        if supportsStreaming is not None:
            any_stream = any(m.capabilities.streaming for m in models)
            if any_stream != supportsStreaming:
                continue
                
        if supportsTools is not None:
            any_tools = any(m.capabilities.toolCalling for m in models)
            if any_tools != supportsTools:
                continue
                
        if supportsVision is not None:
            any_vision = any(m.capabilities.vision for m in models)
            if any_vision != supportsVision:
                continue
                
        if supportsReasoning is not None:
            any_reasoning = False
            for m in models:
                m_name = m.modelName.lower()
                m_alias = (m.alias or "").lower()
                if "reason" in m_name or "opus" in m_name or "thought" in m_name or "reason" in m_alias or "opus" in m_alias or "thought" in m_alias:
                    any_reasoning = True
                    break
            if any_reasoning != supportsReasoning:
                continue
                
        if minimumContextWindow is not None:
            any_min_ctx = any(m.capabilities.maxContextTokens >= minimumContextWindow for m in models)
            if not any_min_ctx:
                continue
                
        if maximumContextWindow is not None:
            any_max_ctx = any(m.capabilities.maxContextTokens <= maximumContextWindow for m in models)
            if not any_max_ctx:
                continue
                
        prio = s.get("priority", 50)
        if minimumPriority is not None and prio < minimumPriority:
            continue
        if maximumPriority is not None and prio > maximumPriority:
            continue
            
        health = s.get("healthScore", 100.0)
        if minimumHealthScore is not None and health < minimumHealthScore:
            continue
        if maximumHealthScore is not None and health > maximumHealthScore:
            continue
            
        if createdAfter is not None and prov.createdAt <= createdAfter:
            continue
        if createdBefore is not None and prov.createdAt >= createdBefore:
            continue
            
        matched.append(s)
    return matched


def paginate_providers(
    sessions  : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate providers list."""
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(sessions)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = sessions[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def search_providers(query: str) -> List[Dict[str, Any]]:
    """Search providers matching query string."""
    q_lower = query.lower().strip()
    matched = []
    for s in _PROVIDER_STORE.values():
        prov = s["package"]
        texts = [
            prov.providerId,
            prov.providerKey,
            prov.providerName,
            prov.displayName,
            prov.apiVersion,
            prov.endpoint,
            prov.defaultModel,
            s.get("providerType") or "",
            s.get("status") or "ACTIVE",
        ]
        for m in s["models"].values():
            texts.extend([
                m.modelId,
                m.modelKey,
                m.modelName,
                m.alias or "",
            ])
        if any(q_lower in str(t).lower() for t in texts):
            matched.append(s)
    return matched


def find_provider_model(provider_id: str, model_id: str) -> Optional[ProviderModel]:
    """Find a specific model in a provider's list."""
    s = _PROVIDER_STORE.get(provider_id)
    if s is None:
        return None
    return s["models"].get(model_id)


def append_provider_model(provider_id: str, req: ProviderModelRequest) -> ProviderModel:
    """Register a new model inside a provider."""
    s = _PROVIDER_STORE.get(provider_id)
    if s is None:
        raise ProviderNotFoundError(f"Provider '{provider_id}' not found.")
        
    prov = s["package"]
    cap = build_provider_capability(
        streaming          = req.capabilities.streaming,
        tool_calling       = req.capabilities.toolCalling,
        json_mode          = req.capabilities.jsonMode,
        vision             = req.capabilities.vision,
        embeddings         = req.capabilities.embeddings,
        max_context_tokens = req.capabilities.maxContextTokens or 8192,
        max_output_tokens  = req.capabilities.maxOutputTokens or 4096,
    )
    mdl = build_provider_model(
        provider     = prov.providerName,
        model_name   = req.modelName,
        capabilities = cap,
        created_at   = req.createdAt,
        alias        = req.alias,
        enabled      = req.enabled if req.enabled is not None else True,
        priority     = req.priority if req.priority is not None else 50,
    )
    
    if mdl.modelId in s["models"]:
        raise DuplicateModelError(f"Model '{mdl.modelId}' already exists in provider.")
        
    s["models"][mdl.modelId] = mdl
    s["package"] = _rebuild_provider_definition(prov, list(s["models"].values()))
    _PROVIDER_STORE[provider_id] = s
    return mdl


def update_provider_model(provider_id: str, model_id: str, req: ProviderModelRequest) -> ProviderModel:
    """Update a registered model definition inside a provider."""
    s = _PROVIDER_STORE.get(provider_id)
    if s is None:
        raise ProviderNotFoundError(f"Provider '{provider_id}' not found.")
    if model_id not in s["models"]:
        raise ModelNotFoundError(f"Model '{model_id}' not found.")
        
    prov = s["package"]
    cap = build_provider_capability(
        streaming          = req.capabilities.streaming,
        tool_calling       = req.capabilities.toolCalling,
        json_mode          = req.capabilities.jsonMode,
        vision             = req.capabilities.vision,
        embeddings         = req.capabilities.embeddings,
        max_context_tokens = req.capabilities.maxContextTokens or 8192,
        max_output_tokens  = req.capabilities.maxOutputTokens or 4096,
    )
    mdl = build_provider_model(
        provider     = prov.providerName,
        model_name   = req.modelName,
        capabilities = cap,
        created_at   = req.createdAt,
        alias        = req.alias,
        enabled      = req.enabled if req.enabled is not None else True,
        priority     = req.priority if req.priority is not None else 50,
    )
    
    s["models"][model_id] = mdl
    s["package"] = _rebuild_provider_definition(prov, list(s["models"].values()))
    _PROVIDER_STORE[provider_id] = s
    return mdl


def delete_provider_model(provider_id: str, model_id: str) -> None:
    """Delete a registered model from a provider's list."""
    s = _PROVIDER_STORE.get(provider_id)
    if s is None:
        raise ProviderNotFoundError(f"Provider '{provider_id}' not found.")
    if model_id not in s["models"]:
        raise ModelNotFoundError(f"Model '{model_id}' not found.")
        
    s["models"].pop(model_id)
    prov = s["package"]
    s["package"] = _rebuild_provider_definition(prov, list(s["models"].values()))
    _PROVIDER_STORE[provider_id] = s


def search_provider_models(provider_id: str, query: str) -> List[ProviderModel]:
    """Search for models matching a query string in a specific provider."""
    s = _PROVIDER_STORE.get(provider_id)
    if s is None:
        return []
    q_lower = query.lower().strip()
    matched = []
    for m in s["models"].values():
        if q_lower in m.modelName.lower() or q_lower in (m.alias or "").lower():
            matched.append(m)
    return matched


def build_provider_summary(s: Dict[str, Any]) -> str:
    """Build a deterministic summary of the provider definition and state."""
    prov = s["package"]
    status_str = s.get("status") or "ACTIVE"
    models_str = ", ".join(m.modelName for m in s["models"].values())
    return (
        f"Provider Summary: Name={prov.displayName} | ID={prov.providerId} | "
        f"Type={s.get('providerType') or 'cloud'} | Status={status_str} | "
        f"HealthScore={s.get('healthScore', 100.0)} | Models=[{models_str}]"
    )


def calculate_provider_statistics() -> ProviderStatisticsResponse:
    """Calculate aggregate stats across all registered providers."""
    sessions = list(_PROVIDER_STORE.values())
    total = len(sessions)
    
    active = sum(1 for s in sessions if s.get("status") == "ACTIVE")
    disabled = total - active
    
    healthy = sum(1 for s in sessions if _health_status(s.get("healthScore", 100.0)) == "HEALTHY")
    degraded = sum(1 for s in sessions if _health_status(s.get("healthScore", 100.0)) == "DEGRADED")
    offline = sum(1 for s in sessions if _health_status(s.get("healthScore", 100.0)) == "OFFLINE")
    
    avg_health = round(sum(s.get("healthScore", 100.0) for s in sessions) / total, 4) if total > 0 else 0.0
    avg_priority = round(sum(s.get("priority", 50) for s in sessions) / total, 4) if total > 0 else 0.0
    avg_models = round(sum(len(s["models"]) for s in sessions) / total, 4) if total > 0 else 0.0
    
    type_counts = {}
    status_counts = {}
    for s in sessions:
        t = s.get("providerType") or "cloud"
        type_counts[t] = type_counts.get(t, 0) + 1
        st = s.get("status") or "ACTIVE"
        status_counts[st] = status_counts.get(st, 0) + 1
        
    return ProviderStatisticsResponse(
        totalProviders     = total,
        activeProviders    = active,
        disabledProviders  = disabled,
        healthyProviders   = healthy,
        degradedProviders  = degraded,
        offlineProviders   = offline,
        averageHealthScore = avg_health,
        averagePriority    = avg_priority,
        averageModels      = avg_models,
        providerTypeCounts = dict(sorted(type_counts.items())),
        statusCounts       = dict(sorted(status_counts.items())),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@provider_registry_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List providers",
)
def list_providers() -> APIResponse:
    try:
        sessions = sorted(_PROVIDER_STORE.values(), key=lambda s: s["package"].providerName)
        payload = ProviderListResponse(
            providers = [_provider_to_response(s) for s in sessions],
            total     = len(sessions),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sessions)} provider(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "AI provider statistics",
)
def get_provider_statistics() -> APIResponse:
    try:
        stats = calculate_provider_statistics()
        return build_success_response(
            data    = stats.model_dump(),
            message = "AI provider statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search providers",
)
def search_providers_endpoint(
    q                    : str = Query(..., min_length=1, description="Search query string."),
    sortBy               : Optional[str] = "createdAt",
    sortOrder            : Optional[str] = "asc",
    page                 : Optional[int] = 1,
    pageSize             : Optional[int] = 20,
    provider             : Optional[str] = None,
    providerType         : Optional[str] = None,
    status               : Optional[str] = None,
    supportsStreaming    : Optional[bool] = None,
    supportsTools        : Optional[bool] = None,
    supportsVision       : Optional[bool] = None,
    supportsReasoning    : Optional[bool] = None,
    minimumContextWindow : Optional[int] = None,
    maximumContextWindow : Optional[int] = None,
    minimumPriority      : Optional[int] = None,
    maximumPriority      : Optional[int] = None,
    minimumHealthScore   : Optional[float] = None,
    maximumHealthScore   : Optional[float] = None,
    createdAfter         : Optional[str] = None,
    createdBefore        : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"providerName", "createdAt", "updatedAt", "priority", "healthScore", "modelCount"}
        errs = []
        if sortBy and sortBy not in allowed_sort:
            errs.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if sortOrder and sortOrder not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        p = page or 1
        ps = pageSize or 20
        try:
            validate_pagination(p, ps)
        except APIErrorValidation as val_err:
            return exception_to_api_response(val_err)

        matched = search_providers(q)
        matched = filter_providers(
            matched,
            provider=provider,
            providerType=providerType,
            status=status,
            supportsStreaming=supportsStreaming,
            supportsTools=supportsTools,
            supportsVision=supportsVision,
            supportsReasoning=supportsReasoning,
            minimumContextWindow=minimumContextWindow,
            maximumContextWindow=maximumContextWindow,
            minimumPriority=minimumPriority,
            maximumPriority=maximumPriority,
            minimumHealthScore=minimumHealthScore,
            maximumHealthScore=maximumHealthScore,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )
        sorted_list = sort_providers(matched, sort_by=sortBy, sort_order=sortOrder)
        page_slice, pag = paginate_providers(sorted_list, p, ps)

        payload = ProviderSearchResponse(
            providers  = [_provider_to_response(w) for w in page_slice],
            total      = pag.totalItems,
            page       = pag.page,
            pageSize   = pag.pageSize,
            totalPages = pag.totalPages,
            query      = q,
            sortBy     = sortBy or "createdAt",
            sortOrder  = sortOrder or "asc",
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{pag.totalItems} provider(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.get(
    "/{providerId}",
    response_model      = APIResponse,
    summary             = "Get provider by ID",
)
def get_provider(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        return build_success_response(
            data    = _provider_to_response(s).model_dump(),
            message = "Provider retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create a provider",
    status_code         = 201,
)
def create_provider(body: CreateProviderRequest) -> APIResponse:
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errs)
            )

        try:
            prov = build_provider_definition(
                provider_name    = body.providerName,
                display_name     = body.displayName,
                api_version      = body.apiVersion,
                endpoint         = body.endpoint,
                supported_models = body.supportedModels,
                default_model    = body.defaultModel,
                created_at       = body.createdAt,
                enabled          = body.enabled if body.enabled is not None else True,
            )
        except ProviderValidationError as pve:
            return exception_to_api_response(APIErrorValidation(str(pve)))

        if prov.providerId in _PROVIDER_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Provider '{prov.providerId}' already exists.")
            )

        session_dict = {
            "package"      : prov,
            "models"       : {},
            "status"       : "ACTIVE" if prov.enabled else "DISABLED",
            "priority"     : body.priority if body.priority is not None else 50,
            "healthScore"  : body.healthScore if body.healthScore is not None else 100.0,
            "providerType" : body.providerType or "cloud",
        }
        _PROVIDER_STORE[prov.providerId] = session_dict

        return build_success_response(
            data    = _provider_to_response(session_dict).model_dump(),
            message = "Provider created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.put(
    "/{providerId}",
    response_model      = APIResponse,
    summary             = "Update provider details",
)
def update_provider(providerId: str, body: UpdateProviderRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("At least one update field must be supplied.")
            )

        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )

        prov = s["package"]
        
        # update fields inside ProviderDefinition
        disp_name = body.displayName if body.displayName is not None else prov.displayName
        api_ver   = body.apiVersion if body.apiVersion is not None else prov.apiVersion
        endpoint  = body.endpoint if body.endpoint is not None else prov.endpoint
        def_model = body.defaultModel if body.defaultModel is not None else prov.defaultModel
        enabled   = body.enabled if body.enabled is not None else prov.enabled

        try:
            updated_prov = build_provider_definition(
                provider_name    = prov.providerName,
                display_name     = disp_name,
                api_version      = api_ver,
                endpoint         = endpoint,
                supported_models = list(prov.supportedModels),
                default_model    = def_model,
                created_at       = prov.createdAt,
                enabled          = enabled,
            )
        except ProviderValidationError as pve:
            return exception_to_api_response(APIErrorValidation(str(pve)))

        s["package"] = updated_prov

        # update router state fields
        if body.priority is not None:
            s["priority"] = body.priority
        if body.healthScore is not None:
            s["healthScore"] = body.healthScore
        if body.providerType is not None:
            s["providerType"] = body.providerType
        if body.enabled is not None:
            s["status"] = "ACTIVE" if body.enabled else "DISABLED"

        _PROVIDER_STORE[providerId] = s

        return build_success_response(
            data    = _provider_to_response(s).model_dump(),
            message = "Provider updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.delete(
    "/{providerId}",
    response_model      = APIResponse,
    summary             = "Delete provider",
)
def delete_provider(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        _PROVIDER_STORE.pop(providerId)
        return build_success_response(
            data    = None,
            message = "Provider deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Models management routes
# ---------------------------------------------------------------------------

@provider_registry_router.get(
    "/{providerId}/models",
    response_model = APIResponse,
    summary        = "List provider models",
)
def list_provider_models(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        models = sorted(s["models"].values(), key=lambda m: m.modelName)
        payload = [
            {
                "modelId"       : m.modelId,
                "modelKey"      : m.modelKey,
                "provider"      : m.provider,
                "modelName"     : m.modelName,
                "alias"         : m.alias,
                "capabilities"  : {
                    "streaming"        : m.capabilities.streaming,
                    "toolCalling"      : m.capabilities.toolCalling,
                    "jsonMode"         : m.capabilities.jsonMode,
                    "vision"           : m.capabilities.vision,
                    "embeddings"       : m.capabilities.embeddings,
                    "maxContextTokens" : m.capabilities.maxContextTokens,
                    "maxOutputTokens"  : m.capabilities.maxOutputTokens,
                },
                "enabled"       : m.enabled,
                "priority"      : m.priority,
                "createdAt"     : m.createdAt,
                "engineVersion" : m.engineVersion,
            }
            for m in models
        ]
        return build_success_response(
            data    = payload,
            message = f"{len(models)} model(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.post(
    "/{providerId}/models",
    response_model = APIResponse,
    summary        = "Create provider model",
    status_code    = 201,
)
def create_provider_model(providerId: str, body: ProviderModelRequest) -> APIResponse:
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errs)
            )
            
        if providerId not in _PROVIDER_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )

        try:
            mdl = append_provider_model(providerId, body)
        except DuplicateModelError as dme:
            return exception_to_api_response(APIErrorConflict(str(dme)))
        except ProviderValidationError as pve:
            return exception_to_api_response(APIErrorValidation(str(pve)))

        payload = ProviderModelResponse(
            modelId       = mdl.modelId,
            modelKey      = mdl.modelKey,
            provider      = mdl.provider,
            modelName     = mdl.modelName,
            alias         = mdl.alias,
            capabilities  = {
                "streaming"        : mdl.capabilities.streaming,
                "toolCalling"      : mdl.capabilities.toolCalling,
                "jsonMode"         : mdl.capabilities.jsonMode,
                "vision"           : mdl.capabilities.vision,
                "embeddings"       : mdl.capabilities.embeddings,
                "maxContextTokens" : mdl.capabilities.maxContextTokens,
                "maxOutputTokens"  : mdl.capabilities.maxOutputTokens,
            },
            enabled       = mdl.enabled,
            priority      = mdl.priority,
            createdAt     = mdl.createdAt,
            engineVersion = mdl.engineVersion,
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = "Provider model created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.put(
    "/{providerId}/models/{modelId}",
    response_model = APIResponse,
    summary        = "Update provider model",
)
def update_provider_model_route(
    providerId : str,
    modelId    : str,
    body       : ProviderModelRequest,
) -> APIResponse:
    try:
        errs = body.validate_request()
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errs)
            )

        if providerId not in _PROVIDER_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )

        s = _PROVIDER_STORE[providerId]
        if modelId not in s["models"]:
            return exception_to_api_response(
                APIErrorNotFound(f"Model '{modelId}' not found.")
            )

        try:
            mdl = update_provider_model(providerId, modelId, body)
        except ProviderValidationError as pve:
            return exception_to_api_response(APIErrorValidation(str(pve)))

        payload = ProviderModelResponse(
            modelId       = mdl.modelId,
            modelKey      = mdl.modelKey,
            provider      = mdl.provider,
            modelName     = mdl.modelName,
            alias         = mdl.alias,
            capabilities  = {
                "streaming"        : mdl.capabilities.streaming,
                "toolCalling"      : mdl.capabilities.toolCalling,
                "jsonMode"         : mdl.capabilities.jsonMode,
                "vision"           : mdl.capabilities.vision,
                "embeddings"       : mdl.capabilities.embeddings,
                "maxContextTokens" : mdl.capabilities.maxContextTokens,
                "maxOutputTokens"  : mdl.capabilities.maxOutputTokens,
            },
            enabled       = mdl.enabled,
            priority      = mdl.priority,
            createdAt     = mdl.createdAt,
            engineVersion = mdl.engineVersion,
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = "Provider model updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.delete(
    "/{providerId}/models/{modelId}",
    response_model = APIResponse,
    summary        = "Delete provider model",
)
def delete_provider_model_route(providerId: str, modelId: str) -> APIResponse:
    try:
        if providerId not in _PROVIDER_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )

        s = _PROVIDER_STORE[providerId]
        if modelId not in s["models"]:
            return exception_to_api_response(
                APIErrorNotFound(f"Model '{modelId}' not found.")
            )

        delete_provider_model(providerId, modelId)
        return build_success_response(
            data    = None,
            message = "Provider model deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Health / Capabilities / Summary routes
# ---------------------------------------------------------------------------

@provider_registry_router.get(
    "/{providerId}/capabilities",
    response_model = APIResponse,
    summary        = "Get provider capabilities",
)
def get_provider_capabilities(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        models = list(s["models"].values())
        payload = {
            "streaming"        : any(m.capabilities.streaming for m in models),
            "toolCalling"      : any(m.capabilities.toolCalling for m in models),
            "jsonMode"         : any(m.capabilities.jsonMode for m in models),
            "vision"           : any(m.capabilities.vision for m in models),
            "embeddings"       : any(m.capabilities.embeddings for m in models),
            "maxContextTokens" : max([m.capabilities.maxContextTokens for m in models]) if models else 0,
            "maxOutputTokens"  : max([m.capabilities.maxOutputTokens for m in models]) if models else 0,
        }
        return build_success_response(
            data    = payload,
            message = "Provider capabilities retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.get(
    "/{providerId}/health",
    response_model = APIResponse,
    summary        = "Get provider health",
)
def get_provider_health(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        score = s.get("healthScore", 100.0)
        status_str = _health_status(score)
        payload = ProviderHealthResponse(
            providerId  = providerId,
            healthScore = score,
            status      = status_str,
            lastChecked = datetime.utcnow().isoformat() + "Z",
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Provider health: {status_str}.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.get(
    "/{providerId}/summary",
    response_model = APIResponse,
    summary        = "Get provider summary",
)
def get_provider_summary_route(providerId: str) -> APIResponse:
    try:
        s = _PROVIDER_STORE.get(providerId)
        if s is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Provider '{providerId}' not found.")
            )
        summary_text = build_provider_summary(s)
        return build_success_response(
            data    = {"summary": summary_text},
            message = "Provider summary generated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Bulk Operations routes
# ---------------------------------------------------------------------------

@provider_registry_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create providers",
    status_code    = 201,
)
def bulk_create_providers(body: BulkCreateProvidersRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.providers:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"providerId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                prov = build_provider_definition(
                    provider_name    = item.providerName,
                    display_name     = item.displayName,
                    api_version      = item.apiVersion,
                    endpoint         = item.endpoint,
                    supported_models = item.supportedModels,
                    default_model    = item.defaultModel,
                    created_at       = item.createdAt,
                    enabled          = item.enabled if item.enabled is not None else True,
                )

                if prov.providerId in _PROVIDER_STORE:
                    failed.append({"providerId": prov.providerId, "reason": f"Provider '{prov.providerId}' already exists."})
                    continue

                session_dict = {
                    "package"      : prov,
                    "models"       : {},
                    "status"       : "ACTIVE" if prov.enabled else "DISABLED",
                    "priority"     : item.priority if item.priority is not None else 50,
                    "healthScore"  : item.healthScore if item.healthScore is not None else 100.0,
                    "providerType" : item.providerType or "cloud",
                }
                _PROVIDER_STORE[prov.providerId] = session_dict
                succeeded.append(prov.providerId)
            except Exception as e:
                failed.append({"providerId": "", "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.providers),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update providers",
)
def bulk_update_providers(body: BulkUpdateProvidersRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.items:
            pid = item.providerId
            s = _PROVIDER_STORE.get(pid)
            if s is None:
                failed.append({"providerId": pid, "reason": f"Provider '{pid}' not found."})
                continue

            try:
                upd = item.update
                prov = s["package"]

                disp_name = upd.displayName if upd.displayName is not None else prov.displayName
                api_ver   = upd.apiVersion if upd.apiVersion is not None else prov.apiVersion
                endpoint  = upd.endpoint if upd.endpoint is not None else prov.endpoint
                def_model = upd.defaultModel if upd.defaultModel is not None else prov.defaultModel
                enabled   = upd.enabled if upd.enabled is not None else prov.enabled

                updated_prov = build_provider_definition(
                    provider_name    = prov.providerName,
                    display_name     = disp_name,
                    api_version      = api_ver,
                    endpoint         = endpoint,
                    supported_models = list(prov.supportedModels),
                    default_model    = def_model,
                    created_at       = prov.createdAt,
                    enabled          = enabled,
                )
                s["package"] = updated_prov

                if upd.priority is not None:
                    s["priority"] = upd.priority
                if upd.healthScore is not None:
                    s["healthScore"] = upd.healthScore
                if upd.providerType is not None:
                    s["providerType"] = upd.providerType
                if upd.enabled is not None:
                    s["status"] = "ACTIVE" if upd.enabled else "DISABLED"

                _PROVIDER_STORE[pid] = s
                succeeded.append(pid)
            except Exception as e:
                failed.append({"providerId": pid, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk update completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@provider_registry_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete providers",
)
def bulk_delete_providers(body: BulkDeleteProvidersRequest) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for pid in body.providerIds:
            if pid not in _PROVIDER_STORE:
                failed.append({"providerId": pid, "reason": f"Provider '{pid}' not found."})
                continue

            try:
                _PROVIDER_STORE.pop(pid)
                succeeded.append(pid)
            except Exception as e:
                failed.append({"providerId": pid, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.providerIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
