"""
AI Prompt Assembly API Router — Phase A4.8.5 (Part A)
=====================================================
REST interface for Prompt Assembly.

Prefix  : /prompts
Tag     : Prompt Assembly
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Query

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.ai.prompt_assembly_models import (
    CreatePromptRequest,
    UpdatePromptRequest,
    PromptSectionRequest,
    PromptSectionResponse,
    PromptResponse,
    PromptListResponse,
    PromptStatisticsResponse,
    BulkCreatePromptsRequest,
    BulkUpdatePromptsRequest,
    BulkDeletePromptsRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response, validate_pagination

from services.prompt_assembly_service import (
    PromptPackage,
    PromptSection,
    build_prompt_package,
    build_prompt_section,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

prompt_assembly_router: APIRouter = APIRouter(
    prefix = "/prompts",
    tags   = ["Prompt Assembly"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_prompt_assembly
_PROMPT_STORE = RepositoryBackedDict("promptAssembly", "promptId", map_prompt_assembly)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _PROMPT_STORE.clear()


def _section_to_response(s: PromptSection) -> PromptSectionResponse:
    """Map a service PromptSection to the API PromptSectionResponse model."""
    return PromptSectionResponse(
        sectionId     = s.sectionId,
        title         = s.title,
        priority      = s.priority,
        content       = s.content,
        tokenEstimate = s.tokenEstimate,
        metadata      = s.metadata,
    )


def _prompt_to_response(session_dict: Dict[str, Any]) -> PromptResponse:
    """Map a stored prompt package state dict to the API PromptResponse model."""
    pkg = session_dict["package"]
    return PromptResponse(
        packageId          = pkg.packageId,
        packageKey         = pkg.packageKey,
        packageFingerprint = pkg.packageFingerprint,
        systemPrompt       = pkg.systemPrompt,
        userPrompt         = pkg.userPrompt,
        sections           = [_section_to_response(s) for s in pkg.sections],
        reasoningId        = pkg.reasoningId,
        contextId          = pkg.contextId,
        investigationId    = pkg.investigationId,
        metadata           = pkg.metadata.model_dump(),
        createdAt          = pkg.createdAt,
        projectId          = session_dict.get("projectId") or "default-project",
        userId             = session_dict.get("userId") or "system",
        status             = session_dict.get("status") or "ACTIVE",
        promptName         = session_dict.get("promptName") or f"Prompt {pkg.reasoningId}",
    )


# ---------------------------------------------------------------------------
# Sort map
# ---------------------------------------------------------------------------
_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "createdAt",
}


# ---------------------------------------------------------------------------
# Prompt Section Helpers
# ---------------------------------------------------------------------------

def append_prompt_section(
    package  : PromptPackage,
    title    : str,
    content  : str,
    priority : int                      = 50,
    metadata : Optional[Dict[str, Any]] = None,
) -> PromptPackage:
    """Append a new prompt section to the package and rebuild it."""
    sec = build_prompt_section(
        title    = title,
        content  = content,
        priority = priority,
        metadata = metadata,
    )
    new_sections = list(package.sections) + [sec]
    return build_prompt_package(
        reasoning_id       = package.reasoningId,
        context_id         = package.contextId,
        investigation_id   = package.investigationId,
        system_prompt      = package.systemPrompt,
        user_prompt        = package.userPrompt,
        created_at         = package.createdAt,
        sections           = new_sections,
        max_tokens         = package.metadata.budget.maxTokens,
        reserved_tokens    = package.metadata.budget.reservedTokens,
        processing_time_ms = package.metadata.processingTimeMs,
    )


def update_prompt_section(
    package   : PromptPackage,
    section_id: str,
    priority  : Optional[int]             = None,
    content   : Optional[str]             = None,
    metadata  : Optional[Dict[str, Any]]  = None,
) -> PromptPackage:
    """Update a specific prompt section and rebuild the package."""
    new_sections = []
    found = False
    for item in package.sections:
        if item.sectionId == section_id:
            new_priority = priority if priority is not None else item.priority
            new_content = content if content is not None else item.content
            new_meta = metadata if metadata is not None else item.metadata
            
            upd_item = build_prompt_section(
                title    = item.title,
                content  = new_content,
                priority = new_priority,
                metadata = new_meta,
            )
            new_sections.append(upd_item)
            found = True
        else:
            new_sections.append(item)
    if not found:
        raise ValueError(f"Prompt section '{section_id}' not found.")
    return build_prompt_package(
        reasoning_id       = package.reasoningId,
        context_id         = package.contextId,
        investigation_id   = package.investigationId,
        system_prompt      = package.systemPrompt,
        user_prompt        = package.userPrompt,
        created_at         = package.createdAt,
        sections           = new_sections,
        max_tokens         = package.metadata.budget.maxTokens,
        reserved_tokens    = package.metadata.budget.reservedTokens,
        processing_time_ms = package.metadata.processingTimeMs,
    )


def delete_prompt_section(
    package   : PromptPackage,
    section_id: str,
) -> PromptPackage:
    """Delete a prompt section and rebuild the package."""
    remaining = [s for s in package.sections if s.sectionId != section_id]
    if len(remaining) == len(package.sections):
        raise ValueError(f"Prompt section '{section_id}' not found.")
    return build_prompt_package(
        reasoning_id       = package.reasoningId,
        context_id         = package.contextId,
        investigation_id   = package.investigationId,
        system_prompt      = package.systemPrompt,
        user_prompt        = package.userPrompt,
        created_at         = package.createdAt,
        sections           = remaining,
        max_tokens         = package.metadata.budget.maxTokens,
        reserved_tokens    = package.metadata.budget.reservedTokens,
        processing_time_ms = package.metadata.processingTimeMs,
    )


def find_prompt_section(package: PromptPackage, section_id: str) -> Optional[PromptSection]:
    """Find a section by section ID."""
    for s in package.sections:
        if s.sectionId == section_id:
            return s
    return None


def search_prompt_sections(package: PromptPackage, query: str) -> List[PromptSection]:
    """Search sections by query matching title or content."""
    q = query.lower().strip()
    return [s for s in package.sections if q in s.content.lower() or q in s.title.lower()]


def build_prompt_summary(sections: List[PromptSection]) -> str:
    """Build a summary covering all sections in the package."""
    if not sections:
        return "No prompt sections to summarize."
    lines = []
    for s in sections:
        lines.append(f"{s.title} (Priority: {s.priority}): {s.content[:50]}")
    return "Prompt Summary: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_prompt(
    prompts: List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """Find prompt by a specific field value."""
    target = value.lower().strip()
    for p in prompts:
        pkg = p["package"]
        v = None
        if field in ("promptId", "packageId"): v = pkg.packageId
        elif field == "reasoningId": v = pkg.reasoningId
        elif field == "contextId": v = pkg.contextId
        elif field == "investigationId": v = pkg.investigationId
        elif field == "projectId": v = p.get("projectId")
        elif field == "userId": v = p.get("userId")
        elif field == "status": v = p.get("status")
        
        if v is not None and str(v).lower().strip() == target:
            return p
    return None


def sort_prompts(
    prompts    : List[Dict[str, Any]],
    sort_by    : str = "createdAt",
    sort_order : str = "asc",
) -> List[Dict[str, Any]]:
    """Sort prompts list."""
    reverse = sort_order.lower() == "desc"
    
    def sort_key(p: Dict[str, Any]):
        pkg = p["package"]
        if sort_by == "sectionCount":
            return (0, len(pkg.sections))
        if sort_by == "tokenCount":
            return (0, pkg.metadata.estimatedTokens)
        if sort_by == "promptName":
            name = p.get("promptName") or f"Prompt {pkg.reasoningId}"
            return (0, name.lower())
            
        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(pkg, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())
        
    return sorted(prompts, key=sort_key, reverse=reverse)


def filter_prompts(
    prompts         : List[Dict[str, Any]],
    status          : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumSections : Optional[int] = None,
    maximumSections : Optional[int] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter prompts list."""
    result = []
    for p in prompts:
        pkg = p["package"]
        c_status = p.get("status") or "ACTIVE"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue
            
        user_id = p.get("userId") or "system"
        if userId is not None and user_id.lower().strip() != userId.lower().strip():
            continue
            
        proj_id = p.get("projectId") or "default-project"
        if projectId is not None and proj_id.lower().strip() != projectId.lower().strip():
            continue
            
        if investigationId is not None and pkg.investigationId.lower().strip() != investigationId.lower().strip():
            continue
            
        section_count = len(pkg.sections)
        if minimumSections is not None and section_count < minimumSections:
            continue
        if maximumSections is not None and section_count > maximumSections:
            continue
            
        token_count = pkg.metadata.estimatedTokens
        if minimumTokens is not None and token_count < minimumTokens:
            continue
        if maximumTokens is not None and token_count > maximumTokens:
            continue
            
        if createdAfter is not None and pkg.createdAt <= createdAfter:
            continue
        if createdBefore is not None and pkg.createdAt >= createdBefore:
            continue
            
        result.append(p)
    return result


def paginate_prompts(
    prompts   : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate prompts list."""
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(prompts)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = prompts[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def search_prompts(query: str) -> List[Dict[str, Any]]:
    """Search prompts matching query string."""
    q_lower = query.lower().strip()
    matched = []
    for p in _PROMPT_STORE.values():
        pkg = p["package"]
        texts = [
            pkg.packageId,
            pkg.packageKey,
            pkg.packageFingerprint,
            pkg.investigationId,
            pkg.reasoningId,
            pkg.contextId,
            pkg.systemPrompt,
            pkg.userPrompt,
            p.get("projectId") or "default-project",
            p.get("userId") or "system",
            p.get("status") or "ACTIVE",
            p.get("promptName") or "",
        ]
        for s in pkg.sections:
            texts.append(s.content)
            texts.append(s.title)
            texts.append(s.sectionId)
            
        if any(q_lower in str(t).lower() for t in texts):
            matched.append(p)
    return matched


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@prompt_assembly_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List prompt packages",
)
def list_prompts() -> APIResponse:
    try:
        prompts = sorted(_PROMPT_STORE.values(), key=lambda s: s["package"].packageId)
        payload = PromptListResponse(
            prompts = [_prompt_to_response(p) for p in prompts],
            total   = len(prompts),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(prompts)} prompt package(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Prompt assembly statistics",
)
def get_prompt_statistics() -> APIResponse:
    try:
        prompts = sorted(_PROMPT_STORE.values(), key=lambda s: s["package"].packageId)
        total_prompts = len(prompts)
        
        all_sections = [s for p in prompts for s in p["package"].sections]
        total_sections = len(all_sections)
        
        active = sum(1 for p in prompts if p.get("status") == "ACTIVE")
        archived = sum(1 for p in prompts if p.get("status") == "ARCHIVED")
        
        avg_sections = round(total_sections / total_prompts, 4) if total_prompts > 0 else 0.0
        
        tokens_sum = sum(p["package"].metadata.estimatedTokens for p in prompts)
        avg_tokens = round(tokens_sum / total_prompts, 4) if total_prompts > 0 else 0.0

        total_prompt_size = sum(
            len(p["package"].systemPrompt) + len(p["package"].userPrompt) + sum(len(s.content) for s in p["package"].sections)
            for p in prompts
        )
        avg_prompt_size = round(total_prompt_size / total_prompts, 4) if total_prompts > 0 else 0.0

        status_counts = {}
        for p in prompts:
            st = p.get("status") or "ACTIVE"
            status_counts[st] = status_counts.get(st, 0) + 1

        stats = PromptStatisticsResponse(
            totalPrompts       = total_prompts,
            activePrompts      = active,
            archivedPrompts    = archived,
            averageSections    = avg_sections,
            averageTokens      = avg_tokens,
            averagePromptSize  = avg_prompt_size,
            statusCounts       = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "Prompt assembly statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.get(
    "/{promptId}",
    response_model      = APIResponse,
    summary             = "Get prompt package by ID",
)
def get_prompt(promptId: str) -> APIResponse:
    try:
        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )
        return build_success_response(
            data    = _prompt_to_response(session_dict).model_dump(),
            message = "Prompt package retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create prompt package",
)
def create_prompt(body: CreatePromptRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        pkg = build_prompt_package(
            reasoning_id       = body.reasoningId,
            context_id         = body.contextId,
            investigation_id   = body.investigationId,
            system_prompt      = body.systemPrompt,
            user_prompt        = body.userPrompt,
            created_at         = body.createdAt,
            sections           = [],
            max_tokens         = body.maxTokens if body.maxTokens is not None else 8192,
            reserved_tokens    = body.reservedTokens if body.reservedTokens is not None else 1024,
            processing_time_ms = body.processingTimeMs if body.processingTimeMs is not None else 0,
        )

        if pkg.packageId in _PROMPT_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Prompt package '{pkg.packageId}' already exists.")
            )

        session_dict = {
            "package"    : pkg,
            "projectId"  : body.projectId or "default-project",
            "userId"     : body.userId or "system",
            "status"     : body.status or "ACTIVE",
            "promptName" : body.promptName or f"Prompt {body.reasoningId}",
        }
        _PROMPT_STORE[pkg.packageId] = session_dict

        return build_success_response(
            data    = _prompt_to_response(session_dict).model_dump(),
            message = "Prompt package created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.put(
    "/{promptId}",
    response_model      = APIResponse,
    summary             = "Update prompt package",
)
def update_prompt(promptId: str, body: UpdatePromptRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must contain at least one field.")
            )

        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )

        pkg = session_dict["package"]
        new_reasoning = body.reasoningId if body.reasoningId is not None else pkg.reasoningId
        new_context = body.contextId if body.contextId is not None else pkg.contextId
        new_investigation = body.investigationId if body.investigationId is not None else pkg.investigationId
        new_system = body.systemPrompt if body.systemPrompt is not None else pkg.systemPrompt
        new_user = body.userPrompt if body.userPrompt is not None else pkg.userPrompt
        new_max = body.maxTokens if body.maxTokens is not None else pkg.metadata.budget.maxTokens
        new_reserved = body.reservedTokens if body.reservedTokens is not None else pkg.metadata.budget.reservedTokens
        new_processing = body.processingTimeMs if body.processingTimeMs is not None else pkg.metadata.processingTimeMs

        new_pkg = build_prompt_package(
            reasoning_id       = new_reasoning,
            context_id         = new_context,
            investigation_id   = new_investigation,
            system_prompt      = new_system,
            user_prompt        = new_user,
            created_at         = pkg.createdAt,
            sections           = list(pkg.sections),
            max_tokens         = new_max,
            reserved_tokens    = new_reserved,
            processing_time_ms = new_processing,
        )

        proj_id = body.projectId if body.projectId is not None else session_dict.get("projectId") or "default-project"
        user_id = body.userId if body.userId is not None else session_dict.get("userId") or "system"
        status_val = body.status if body.status is not None else session_dict.get("status") or "ACTIVE"
        name_val = body.promptName if body.promptName is not None else session_dict.get("promptName") or f"Prompt {pkg.reasoningId}"

        session_dict["package"] = new_pkg
        session_dict["projectId"] = proj_id
        session_dict["userId"] = user_id
        session_dict["status"] = status_val
        session_dict["promptName"] = name_val

        _PROMPT_STORE[promptId] = session_dict

        return build_success_response(
            data    = _prompt_to_response(session_dict).model_dump(),
            message = "Prompt package updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.delete(
    "/{promptId}",
    response_model      = APIResponse,
    summary             = "Delete prompt package",
)
def delete_prompt(promptId: str) -> APIResponse:
    try:
        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )
        _PROMPT_STORE.pop(promptId)
        return build_success_response(
            data    = None,
            message = "Prompt package deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.post(
    "/{promptId}/sections",
    response_model      = APIResponse,
    summary             = "Append prompt section",
)
def append_prompt_section_route(promptId: str, body: PromptSectionRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )

        pkg = session_dict["package"]
        try:
            sec = build_prompt_section(
                title    = body.title,
                content  = body.content,
                priority = body.priority if body.priority is not None else 50,
                metadata = body.metadata,
            )

            new_sections = list(pkg.sections) + [sec]
            new_pkg = build_prompt_package(
                reasoning_id       = pkg.reasoningId,
                context_id         = pkg.contextId,
                investigation_id   = pkg.investigationId,
                system_prompt      = pkg.systemPrompt,
                user_prompt        = pkg.userPrompt,
                created_at         = pkg.createdAt,
                sections           = new_sections,
                max_tokens         = pkg.metadata.budget.maxTokens,
                reserved_tokens    = pkg.metadata.budget.reservedTokens,
                processing_time_ms = pkg.metadata.processingTimeMs,
            )

            session_dict["package"] = new_pkg
            _PROMPT_STORE[promptId] = session_dict
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = _section_to_response(sec).model_dump(),
            message = "Prompt section appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.get(
    "/{promptId}/sections",
    response_model      = APIResponse,
    summary             = "Get prompt sections",
)
def list_prompt_sections(promptId: str) -> APIResponse:
    try:
        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )

        pkg = session_dict["package"]
        resp_sections = [_section_to_response(s) for s in pkg.sections]
        return build_success_response(
            data    = [s.model_dump() for s in resp_sections],
            message = f"{len(resp_sections)} section(s) retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Routes
# ---------------------------------------------------------------------------

@prompt_assembly_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search prompt packages",
)
def search_prompts_endpoint(
    q               : str = Query(..., min_length=1, description="Search string."),
    sortBy          : Optional[str] = "createdAt",
    sortOrder       : Optional[str] = "asc",
    page            : Optional[int] = 1,
    pageSize        : Optional[int] = 20,
    status          : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumSections : Optional[int] = None,
    maximumSections : Optional[int] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "promptName", "sectionCount", "tokenCount"}
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

        matched = search_prompts(q)

        matched = filter_prompts(
            matched,
            status=status,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumSections=minimumSections,
            maximumSections=maximumSections,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_prompts = sort_prompts(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_prompts(sorted_prompts, p, ps)

        payload = {
            "prompts"    : [_prompt_to_response(w) for w in page_slice],
            "total"      : pag.totalItems,
            "page"       : pag.page,
            "pageSize"   : pag.pageSize,
            "totalPages" : pag.totalPages,
            "query"      : q,
            "sortBy"     : sortBy or "createdAt",
            "sortOrder"  : sortOrder or "asc",
        }
        return build_success_response(
            data    = payload,
            message = f"{pag.totalItems} prompt package(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create prompt packages",
    status_code    = 201,
)
def bulk_create_prompts_route(
    body: BulkCreatePromptsRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.prompts:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"promptId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                pkg = build_prompt_package(
                    reasoning_id       = item.reasoningId,
                    context_id         = item.contextId,
                    investigation_id   = item.investigationId,
                    system_prompt      = item.systemPrompt,
                    user_prompt        = item.userPrompt,
                    created_at         = item.createdAt,
                    sections           = [],
                    max_tokens         = item.maxTokens if item.maxTokens is not None else 8192,
                    reserved_tokens    = item.reservedTokens if item.reservedTokens is not None else 1024,
                    processing_time_ms = item.processingTimeMs if item.processingTimeMs is not None else 0,
                )

                if pkg.packageId in _PROMPT_STORE:
                    failed.append({"promptId": pkg.packageId, "reason": f"Prompt package '{pkg.packageId}' already exists."})
                    continue

                session_dict = {
                    "package"    : pkg,
                    "projectId"  : item.projectId or "default-project",
                    "userId"     : item.userId or "system",
                    "status"     : item.status or "ACTIVE",
                    "promptName" : item.promptName or f"Prompt {item.reasoningId}",
                }
                _PROMPT_STORE[pkg.packageId] = session_dict
                succeeded.append(pkg.packageId)
            except Exception as e:
                failed.append({"promptId": "", "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.prompts),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update prompt packages",
)
def bulk_update_prompts_route(
    body: BulkUpdatePromptsRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.items:
            prompt_id = item.promptId
            session_dict = _PROMPT_STORE.get(prompt_id)
            if session_dict is None:
                failed.append({"promptId": prompt_id, "reason": f"Prompt package '{prompt_id}' not found."})
                continue

            try:
                pkg = session_dict["package"]
                upd = item.update
                new_reasoning = upd.reasoningId if upd.reasoningId is not None else pkg.reasoningId
                new_context = upd.contextId if upd.contextId is not None else pkg.contextId
                new_investigation = upd.investigationId if upd.investigationId is not None else pkg.investigationId
                new_system = upd.systemPrompt if upd.systemPrompt is not None else pkg.systemPrompt
                new_user = upd.userPrompt if upd.userPrompt is not None else pkg.userPrompt
                new_max = upd.maxTokens if upd.maxTokens is not None else pkg.metadata.budget.maxTokens
                new_reserved = upd.reservedTokens if upd.reservedTokens is not None else pkg.metadata.budget.reservedTokens
                new_processing = upd.processingTimeMs if upd.processingTimeMs is not None else pkg.metadata.processingTimeMs

                new_pkg = build_prompt_package(
                    reasoning_id       = new_reasoning,
                    context_id         = new_context,
                    investigation_id   = new_investigation,
                    system_prompt      = new_system,
                    user_prompt        = new_user,
                    created_at         = pkg.createdAt,
                    sections           = list(pkg.sections),
                    max_tokens         = new_max,
                    reserved_tokens    = new_reserved,
                    processing_time_ms = new_processing,
                )

                proj_id = upd.projectId if upd.projectId is not None else session_dict.get("projectId") or "default-project"
                user_id = upd.userId if upd.userId is not None else session_dict.get("userId") or "system"
                status_val = upd.status if upd.status is not None else session_dict.get("status") or "ACTIVE"
                name_val = upd.promptName if upd.promptName is not None else session_dict.get("promptName") or f"Prompt {pkg.reasoningId}"

                session_dict["package"] = new_pkg
                session_dict["projectId"] = proj_id
                session_dict["userId"] = user_id
                session_dict["status"] = status_val
                session_dict["promptName"] = name_val

                _PROMPT_STORE[prompt_id] = session_dict
                succeeded.append(prompt_id)
            except Exception as e:
                failed.append({"promptId": prompt_id, "reason": str(e)})

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


@prompt_assembly_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete prompt packages",
)
def bulk_delete_prompts_route(
    body: BulkDeletePromptsRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for prompt_id in body.promptIds:
            if prompt_id not in _PROMPT_STORE:
                failed.append({"promptId": prompt_id, "reason": f"Prompt package '{prompt_id}' not found."})
                continue

            try:
                _PROMPT_STORE.pop(prompt_id)
                succeeded.append(prompt_id)
            except Exception as e:
                failed.append({"promptId": prompt_id, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.promptIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.put(
    "/{promptId}/sections/{sectionId}",
    response_model      = APIResponse,
    summary             = "Update prompt section",
)
def update_prompt_section_route(
    promptId  : str,
    sectionId : str,
    body      : PromptSectionRequest,
) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )

        pkg = session_dict["package"]
        try:
            orig_sec = find_prompt_section(pkg, sectionId)
            if orig_sec is None:
                return exception_to_api_response(APIErrorNotFound(f"Prompt section '{sectionId}' not found."))

            new_sec = build_prompt_section(
                title    = orig_sec.title,
                content  = body.content,
                priority = body.priority if body.priority is not None else orig_sec.priority,
                metadata = body.metadata,
            )

            new_pkg = update_prompt_section(
                package    = pkg,
                section_id = sectionId,
                priority   = body.priority,
                content    = body.content,
                metadata   = body.metadata,
            )
            session_dict["package"] = new_pkg
            _PROMPT_STORE[promptId] = session_dict

            updated_sec = find_prompt_section(new_pkg, new_sec.sectionId)
            if updated_sec is None:
                raise ValueError("Section not found after update.")
        except Exception as e:
            if f"Prompt section '{sectionId}' not found" in str(e):
                return exception_to_api_response(APIErrorNotFound(str(e)))
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = _section_to_response(updated_sec).model_dump(),
            message = "Prompt section updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.delete(
    "/{promptId}/sections/{sectionId}",
    response_model      = APIResponse,
    summary             = "Delete prompt section",
)
def delete_prompt_section_route(
    promptId  : str,
    sectionId : str,
) -> APIResponse:
    try:
        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )

        pkg = session_dict["package"]
        try:
            new_pkg = delete_prompt_section(pkg, sectionId)
            session_dict["package"] = new_pkg
            _PROMPT_STORE[promptId] = session_dict
        except Exception as e:
            if f"Prompt section '{sectionId}' not found" in str(e):
                return exception_to_api_response(APIErrorNotFound(str(e)))
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = None,
            message = "Prompt section deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@prompt_assembly_router.get(
    "/{promptId}/summary",
    response_model      = APIResponse,
    summary             = "Get prompt summary",
)
def get_prompt_summary(promptId: str) -> APIResponse:
    try:
        session_dict = _PROMPT_STORE.get(promptId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Prompt package '{promptId}' not found.")
            )
        pkg = session_dict["package"]
        summary_text = build_prompt_summary(list(pkg.sections))
        return build_success_response(
            data    = {"summary": summary_text},
            message = "Prompt summary generated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
