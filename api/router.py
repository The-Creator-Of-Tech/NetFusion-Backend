"""
API Router — Phase A4.7.1
==========================
Defines the root APIRouter and registers placeholder sub-routers for every
functional domain of the NetFusion V2 API.

Phase A — placeholder sub-routers only (no endpoints).
Phase B — system endpoints added: GET /health, GET /version.

Router layout
-------------
root_router              /api/v2
├── investigation_router /api/v2/investigation   (endpoints: Part B+)
├── ai_router            /api/v2/ai               (endpoints: Part B+)
├── knowledge_router     /api/v2/knowledge        (endpoints: Part B+)
├── workflow_router      /api/v2/workflow         (endpoints: Part B+)
├── reports_router       /api/v2/reports          (endpoints: Part B+)
└── system_router        /api/v2/system
      GET /api/v2/system/health    → HealthResponse
      GET /api/v2/system/version   → VersionResponse

How to add endpoints (Part B+)
-------------------------------
Import the appropriate sub-router and attach routes to it.
Do NOT touch include_router calls — they are locked.

    from api.router import reports_router

    @reports_router.get("/{report_id}")
    def get_report(report_id: str) -> APIResponse: ...
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from api.models import APIResponse
from api.utils import build_health_response, build_version_response
from api.investigation.alert_router import alert_router
from api.investigation.asset_router import asset_router
from api.investigation.attack_graph_router import attack_graph_router
from api.investigation.finding_router import finding_router

# ---------------------------------------------------------------------------
# Sub-routers — one per functional domain
# Each is an empty placeholder; endpoints are added in Part B and beyond.
# ---------------------------------------------------------------------------

from api.investigation.investigation_router import investigation_router

ai_router: APIRouter = APIRouter(
    prefix = "/ai",
    tags   = ["AI"],
)
"""
AI / Copilot domain router.

Planned endpoints (Part B+):
  POST   /ai/chat
  POST   /ai/reasoning
  POST   /ai/narrative
  POST   /ai/context
"""

knowledge_router: APIRouter = APIRouter(
    prefix = "/knowledge",
    tags   = ["Knowledge"],
)
"""
Threat-intelligence knowledge domain router.

Planned endpoints (Part B+):
  GET    /knowledge/mitre
  GET    /knowledge/cve
  GET    /knowledge/ioc
  GET    /knowledge/threat-actors
"""

from api.knowledge.mitre_router import mitre_router
knowledge_router.include_router(mitre_router)

from api.knowledge.cve_router import cve_router
knowledge_router.include_router(cve_router)

from api.knowledge.ioc_router import ioc_router
knowledge_router.include_router(ioc_router)

from api.knowledge.threat_router import threat_router
knowledge_router.include_router(threat_router)

from api.knowledge.campaign_router import campaign_router
knowledge_router.include_router(campaign_router)

workflow_router: APIRouter = APIRouter(
    prefix = "/workflow",
    tags   = ["Workflow"],
)

from api.workflow.playbook_router import playbook_router
workflow_router.include_router(playbook_router)

from api.workflow.rules_router import rules_router
workflow_router.include_router(rules_router)

from api.workflow.automation_router import automation_router
workflow_router.include_router(automation_router)

from api.workflow.case_flow_router import case_flow_router
workflow_router.include_router(case_flow_router)
"""
Workflow / automation domain router.

Planned endpoints (Part B+):
  GET    /workflow/cases
  POST   /workflow/cases
  GET    /workflow/playbooks
  GET    /workflow/rules
  GET    /workflow/automation
"""

reports_router: APIRouter = APIRouter(
    prefix = "/reports",
    tags   = ["Reports"],
)
"""
Report engine domain router.

Planned endpoints (Part B+):
  GET    /reports
  POST   /reports
  GET    /reports/{report_id}
  PUT    /reports/{report_id}
  DELETE /reports/{report_id}
"""

system_router: APIRouter = APIRouter(
    prefix = "/system",
    tags   = ["System"],
)
"""
System / health domain router.

Endpoints:
  GET    /system/health    → HealthResponse wrapped in APIResponse
  GET    /system/version   → VersionResponse wrapped in APIResponse
"""


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

@system_router.get(
    "/health",
    response_model        = APIResponse,
    summary               = "Health check",
    description           = (
        "Returns the current health status of the API layer.  "
        "Does not check downstream services or database connectivity — "
        "those checks are added in a later phase."
    ),
    response_description  = "API layer health status",
)
def get_health(
    uptime: Optional[str] = None,
) -> APIResponse:
    """
    GET /api/v2/system/health

    Returns a HealthResponse wrapped in the standard APIResponse envelope.

    Query parameters
    ----------------
    uptime : optional human-readable uptime string (e.g. "3d 04h 12m").
             The API layer never measures uptime itself; callers may pass
             it via this query parameter for monitoring dashboards.

    Response body (success=True)
    ----------------------------
    data.status  : "healthy"
    data.version : API_LAYER_VERSION
    data.uptime  : the supplied uptime string, or null
    """
    health = build_health_response(status="healthy", uptime=uptime)
    return APIResponse(
        success  = True,
        message  = "Service is healthy.",
        data     = health.model_dump(),
        metadata = {"apiLayerVersion": health.version},
    )


@system_router.get(
    "/version",
    response_model        = APIResponse,
    summary               = "Engine version registry",
    description           = (
        "Returns the API layer version and the version string for every "
        "registered service engine.  The engineVersions map is sorted "
        "alphabetically for deterministic output."
    ),
    response_description  = "API and engine version information",
)
def get_version() -> APIResponse:
    """
    GET /api/v2/system/version

    Returns a VersionResponse wrapped in the standard APIResponse envelope.

    Response body (success=True)
    ----------------------------
    data.apiVersion     : API_LAYER_VERSION
    data.engineVersions : sorted dict of engine name → version string
    """
    version = build_version_response()
    return APIResponse(
        success  = True,
        message  = "Version information retrieved.",
        data     = version.model_dump(),
        metadata = {"apiLayerVersion": version.apiVersion},
    )


# ---------------------------------------------------------------------------
# Setup sub-routers and their dependencies first
# ---------------------------------------------------------------------------

from api.ai.provider_registry_router import provider_registry_router
ai_router.include_router(provider_registry_router)

from api.ai.streaming_router import streaming_router
ai_router.include_router(streaming_router)

from api.ai.conversation_router import conversation_router
ai_router.include_router(conversation_router)

from api.ai.session_memory_router import session_memory_router
ai_router.include_router(session_memory_router)

from api.ai.context_window_router import context_window_router
ai_router.include_router(context_window_router)

from api.ai.prompt_assembly_router import prompt_assembly_router
ai_router.include_router(prompt_assembly_router)

from api.ai.reasoning_router import reasoning_router
ai_router.include_router(reasoning_router)

from api.ai.execution_router import execution_router
ai_router.include_router(execution_router)

from api.ai.copilot_router import copilot_router
ai_router.include_router(copilot_router)


# ---------------------------------------------------------------------------
# Root router — aggregates all sub-routers under /api/v2
# ---------------------------------------------------------------------------

root_router: APIRouter = APIRouter(prefix="/api/v2")

root_router.include_router(investigation_router)
root_router.include_router(ai_router)
root_router.include_router(knowledge_router)
root_router.include_router(workflow_router)
root_router.include_router(reports_router)
root_router.include_router(system_router)
root_router.include_router(asset_router)
root_router.include_router(attack_graph_router)
root_router.include_router(finding_router)
root_router.include_router(alert_router)

from api.investigation.timeline_router import timeline_router
root_router.include_router(timeline_router)

from api.investigation.evidence_router import evidence_router
root_router.include_router(evidence_router)

