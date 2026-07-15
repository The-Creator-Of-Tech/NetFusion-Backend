"""Workflow domain — barrel export for all four routers."""
from api.workflow.playbook_router   import playbook_router
from api.workflow.rules_router      import rules_router
from api.workflow.automation_router import automation_router
from api.workflow.case_flow_router  import case_flow_router

__all__ = [
    "playbook_router",
    "rules_router",
    "automation_router",
    "case_flow_router",
]
