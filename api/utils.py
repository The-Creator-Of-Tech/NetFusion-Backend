"""
API Utility Helpers — Phase A4.7.1 Part B
==========================================
Pure, deterministic helper functions used by the API layer.

Contents
--------
exception_to_api_response()  — convert any APILayerError to APIResponse
validate_pagination()         — validate page / pageSize query parameters
build_health_response()       — build HealthResponse (pure transformation)
build_version_response()      — build VersionResponse with all engine versions

Design rules
------------
- No HTTP requests, no database, no AI execution, no service calls.
- No UUID generation.
- No timestamp generation — callers supply timestamps.
- No randomness.
- All functions are pure transformations; inputs are never mutated.
- Engine version aggregation is deterministic:
    keys are sorted alphabetically before building the mapping.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from api.errors import APILayerError, APIErrorValidation
from api.models import APIResponse, HealthResponse, VersionResponse
from api.responses import build_error_response_from_exception
from core.constants import (
    # API layer
    API_LAYER_VERSION,

    # Identity & Evidence
    IDENTITY_CONFIDENCE_ENGINE_VERSION,
    IDENTITY_RESOLUTION_ENGINE_VERSION,
    EVIDENCE_ENGINE_VERSION,
    HISTORY_ENGINE_VERSION,

    # Relationship
    RELATIONSHIP_ENGINE_VERSION,
    RELATIONSHIP_HISTORY_ENGINE_VERSION,

    # Attack Graph
    ATTACK_GRAPH_ENGINE_VERSION,
    ATTACK_GRAPH_QUERY_ENGINE_VERSION,
    ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,

    # Timeline
    TIMELINE_INTELLIGENCE_ENGINE_VERSION,

    # Investigation & Findings
    INVESTIGATION_ENGINE_VERSION,
    FINDING_ENGINE_VERSION,
    ALERT_ENGINE_VERSION,

    # MITRE
    MITRE_ENGINE_VERSION,
    MITRE_ATTACK_ENGINE_VERSION,

    # AI / Copilot
    AI_COPILOT_CONTEXT_ENGINE_VERSION,
    REASONING_ENGINE_VERSION,
    PROMPT_ASSEMBLY_ENGINE_VERSION,
    INVESTIGATION_NARRATIVE_ENGINE_VERSION,
    COPILOT_ORCHESTRATOR_ENGINE_VERSION,

    # Groq / Provider
    TOOL_CALLING_ENGINE_VERSION,
    GROQ_STREAMING_ENGINE_VERSION,
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
    GROQ_PROVIDER_ENGINE_VERSION,
    PROVIDER_REGISTRY_ENGINE_VERSION,
    AI_EXECUTION_ENGINE_VERSION,

    # Conversation
    CONVERSATION_MANAGER_ENGINE_VERSION,
    SESSION_MEMORY_ENGINE_VERSION,
    CONTEXT_WINDOW_ENGINE_VERSION,
    TOKEN_BUDGET_ENGINE_VERSION,
    RETRY_FAILOVER_ENGINE_VERSION,
    CHAT_RUNTIME_ENGINE_VERSION,

    # Intelligence
    CVE_INTELLIGENCE_ENGINE_VERSION,
    IOC_INTELLIGENCE_ENGINE_VERSION,
    THREAT_INTELLIGENCE_ENGINE_VERSION,
    PLAYBOOK_ENGINE_VERSION,
    RULES_ENGINE_VERSION,
    AUTOMATION_ENGINE_VERSION,
    CASE_FLOW_ENGINE_VERSION,
    REPORT_ENGINE_VERSION,
)


# ---------------------------------------------------------------------------
# Deterministic engine version registry
# ---------------------------------------------------------------------------
# All engine versions known to the API layer, keyed by a stable human-
# readable name.  Keys are sorted alphabetically so the dict serialises
# identically on every run regardless of Python version or import order.
# Add new engines here when they are introduced.

_ENGINE_VERSION_REGISTRY: Dict[str, str] = dict(sorted({
    "ai-context":                  AI_COPILOT_CONTEXT_ENGINE_VERSION,
    "ai-execution":                AI_EXECUTION_ENGINE_VERSION,
    "alert":                       ALERT_ENGINE_VERSION,
    "api-layer":                   API_LAYER_VERSION,
    "attack-graph":                ATTACK_GRAPH_ENGINE_VERSION,
    "attack-graph-intelligence":   ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,
    "attack-graph-query":          ATTACK_GRAPH_QUERY_ENGINE_VERSION,
    "automation":                  AUTOMATION_ENGINE_VERSION,
    "case-flow":                   CASE_FLOW_ENGINE_VERSION,
    "chat-runtime":                CHAT_RUNTIME_ENGINE_VERSION,
    "context-window":              CONTEXT_WINDOW_ENGINE_VERSION,
    "conversation-manager":        CONVERSATION_MANAGER_ENGINE_VERSION,
    "copilot-orchestrator":        COPILOT_ORCHESTRATOR_ENGINE_VERSION,
    "cve-intelligence":            CVE_INTELLIGENCE_ENGINE_VERSION,
    "evidence":                    EVIDENCE_ENGINE_VERSION,
    "evidence-history":            HISTORY_ENGINE_VERSION,
    "finding":                     FINDING_ENGINE_VERSION,
    "groq-http-client":            GROQ_HTTP_CLIENT_ENGINE_VERSION,
    "groq-provider":               GROQ_PROVIDER_ENGINE_VERSION,
    "groq-streaming":              GROQ_STREAMING_ENGINE_VERSION,
    "identity-confidence":         IDENTITY_CONFIDENCE_ENGINE_VERSION,
    "identity-resolution":         IDENTITY_RESOLUTION_ENGINE_VERSION,
    "ioc-intelligence":            IOC_INTELLIGENCE_ENGINE_VERSION,
    "investigation":               INVESTIGATION_ENGINE_VERSION,
    "investigation-narrative":     INVESTIGATION_NARRATIVE_ENGINE_VERSION,
    "mitre":                       MITRE_ENGINE_VERSION,
    "mitre-attack":                MITRE_ATTACK_ENGINE_VERSION,
    "playbook":                    PLAYBOOK_ENGINE_VERSION,
    "prompt-assembly":             PROMPT_ASSEMBLY_ENGINE_VERSION,
    "provider-registry":           PROVIDER_REGISTRY_ENGINE_VERSION,
    "reasoning":                   REASONING_ENGINE_VERSION,
    "relationship":                RELATIONSHIP_ENGINE_VERSION,
    "relationship-history":        RELATIONSHIP_HISTORY_ENGINE_VERSION,
    "report":                      REPORT_ENGINE_VERSION,
    "retry-failover":              RETRY_FAILOVER_ENGINE_VERSION,
    "rules":                       RULES_ENGINE_VERSION,
    "session-memory":              SESSION_MEMORY_ENGINE_VERSION,
    "threat-intelligence":         THREAT_INTELLIGENCE_ENGINE_VERSION,
    "timeline-intelligence":       TIMELINE_INTELLIGENCE_ENGINE_VERSION,
    "token-budget":                TOKEN_BUDGET_ENGINE_VERSION,
    "tool-calling":                TOOL_CALLING_ENGINE_VERSION,
}.items()))


# ---------------------------------------------------------------------------
# exception_to_api_response()
# ---------------------------------------------------------------------------

def exception_to_api_response(
    exc       : APILayerError,
    timestamp : Optional[str]            = None,
    metadata  : Optional[Dict[str, Any]] = None,
) -> APIResponse:
    """
    Convert any APILayerError (or subclass) into an APIResponse.

    This is the canonical conversion path for the FastAPI exception handler
    that will be wired in a later phase.  Keeping it here keeps the handler
    thin — it only needs to call this function and return the result.

    Parameters
    ----------
    exc       : Any APILayerError instance.
    timestamp : ISO-8601 UTC timestamp (caller-supplied; never generated here).
    metadata  : Optional extra key-value pairs to include in response metadata.

    Returns
    -------
    APIResponse (frozen / immutable) with success=False.

    Examples
    --------
    >>> exc = APIErrorNotFound("Report xyz not found")
    >>> r   = exception_to_api_response(exc, timestamp="2026-07-03T00:00:00Z")
    >>> r.success
    False
    >>> r.data.errorCode
    'NOT_FOUND'
    """
    return build_error_response_from_exception(
        exc       = exc,
        timestamp = timestamp,
        metadata  = metadata,
    )


# ---------------------------------------------------------------------------
# validate_pagination()
# ---------------------------------------------------------------------------

def validate_pagination(
    page      : int,
    page_size : int,
    max_page_size: int = 500,
) -> None:
    """
    Validate pagination query parameters.

    Rules
    -----
    - page must be an integer >= 1.
    - page_size must be an integer >= 1.
    - page_size must not exceed max_page_size (default 500).

    Parameters
    ----------
    page          : Requested page number (1-based).
    page_size     : Number of items per page.
    max_page_size : Upper bound on page_size (default 500).

    Raises
    ------
    APIErrorValidation : if any rule is violated.  All violations are
                         collected and reported together in the details list.
    """
    errors: List[str] = []

    if not isinstance(page, int) or isinstance(page, bool) or page < 1:
        errors.append(
            f"page={page!r} must be a positive integer (>= 1)."
        )
    if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size < 1:
        errors.append(
            f"pageSize={page_size!r} must be a positive integer (>= 1)."
        )
    elif page_size > max_page_size:
        errors.append(
            f"pageSize={page_size!r} exceeds the maximum allowed value of {max_page_size}."
        )

    if errors:
        raise APIErrorValidation(
            message = "Pagination parameters are invalid.",
            details = errors,
        )


# ---------------------------------------------------------------------------
# build_health_response()
# ---------------------------------------------------------------------------

def build_health_response(
    status : str            = "healthy",
    uptime : Optional[str]  = None,
) -> HealthResponse:
    """
    Build a HealthResponse (pure transformation — no I/O).

    Parameters
    ----------
    status : Health status string.  Recognised values: "healthy",
             "degraded", "unhealthy".  Any non-empty string is accepted;
             the API layer does not enforce the enum at this layer.
    uptime : Caller-supplied uptime string (e.g. "3d 04h 12m").
             Pass None if uptime is not available.

    Returns
    -------
    HealthResponse (frozen / immutable).
    The version field is always API_LAYER_VERSION (from core.constants).

    Examples
    --------
    >>> build_health_response("healthy", uptime="1d 02h")
    HealthResponse(status='healthy', version='api-layer-v1', uptime='1d 02h')
    """
    return HealthResponse(
        status  = status,
        version = API_LAYER_VERSION,
        uptime  = uptime,
    )


# ---------------------------------------------------------------------------
# build_version_response()
# ---------------------------------------------------------------------------

def build_version_response(
    extra_versions: Optional[Dict[str, str]] = None,
) -> VersionResponse:
    """
    Build a VersionResponse containing every registered engine version.

    The engineVersions dict is always constructed from
    _ENGINE_VERSION_REGISTRY (sorted alphabetically) so the output is
    deterministic regardless of call order or Python dict iteration order.

    Parameters
    ----------
    extra_versions : Optional additional engine name → version mappings to
                     merge into the response alongside the registered engines.
                     Keys in extra_versions take precedence over the registry
                     if they clash (allows runtime overrides in tests).

    Returns
    -------
    VersionResponse (frozen / immutable).

    Examples
    --------
    >>> r = build_version_response()
    >>> r.apiVersion
    'api-layer-v1'
    >>> "report" in r.engineVersions
    True
    """
    # Start from the deterministic sorted registry (copy — never mutate it)
    merged: Dict[str, str] = dict(_ENGINE_VERSION_REGISTRY)

    # Merge caller-supplied extras (sorted for determinism)
    if extra_versions:
        for k, v in sorted(extra_versions.items()):
            merged[k] = v

    return VersionResponse(
        apiVersion     = API_LAYER_VERSION,
        engineVersions = dict(sorted(merged.items())),
    )


# ---------------------------------------------------------------------------
# Re-export registry for tests and inspection
# ---------------------------------------------------------------------------

def get_engine_version_registry() -> Dict[str, str]:
    """
    Return a copy of the deterministic engine version registry.

    Returns a new dict each call — callers may mutate the result freely
    without affecting the registry.
    """
    return dict(_ENGINE_VERSION_REGISTRY)
