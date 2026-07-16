from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from api.errors import APILayerError, APIErrorNotFound, APIErrorInternal
from api.models import APIResponse
from api.responses import build_success_response
from api.utils import exception_to_api_response
from api.persistence import WorkflowExecutionsStore, RepositoryBackedDict, map_playbook
from api.workflow.normalizers import normalize_playbook

execution_router = APIRouter(prefix="/executions", tags=["Executions"])
_EXECUTION_STORE = WorkflowExecutionsStore()
_PLAYBOOK_STORE = RepositoryBackedDict("playbook", "playbookId", map_playbook)

@execution_router.get("", response_model=APIResponse, summary="List all workflow executions")
def list_executions(
    project_id: Optional[str] = Query(None, alias="project_id"),
    playbook_id: Optional[str] = Query(None, alias="playbook_id"),
) -> APIResponse:
    try:
        if playbook_id:
            raw_pb = _PLAYBOOK_STORE.get(playbook_id)
            if not raw_pb:
                # Fallback to search
                all_pbs = [normalize_playbook(p) for p in _PLAYBOOK_STORE.values()]
                for p in all_pbs:
                    if p["playbookId"].lower() == playbook_id.strip().lower() or p["name"].lower() == playbook_id.strip().lower():
                        raw_pb = p
                        break
            if raw_pb:
                pb = normalize_playbook(raw_pb)
                executions = _EXECUTION_STORE.get_by_playbook(pb["playbookId"])
            else:
                executions = []
        else:
            executions = _EXECUTION_STORE.get_all(project_id)
            
        # Sort executions by startedAt descending
        executions = sorted(
            executions,
            key=lambda e: e.get("startedAt") or "",
            reverse=True
        )
        
        # Ensure playbookName is augmented for each execution
        for e in executions:
            if "playbookName" not in e and e.get("playbookId"):
                raw_pb = _PLAYBOOK_STORE.get(e["playbookId"])
                if raw_pb:
                    pb = normalize_playbook(raw_pb)
                    e["playbookName"] = pb["name"]
                else:
                    e["playbookName"] = "Unknown Playbook"

        return build_success_response(
            data=executions,
            message=f"Found {len(executions)} execution(s).",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))

@execution_router.get("/{executionId}", response_model=APIResponse, summary="Get details of a single execution")
def get_execution(executionId: str) -> APIResponse:
    try:
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
            
        # Augment with playbookName
        if "playbookName" not in record and record.get("playbookId"):
            raw_pb = _PLAYBOOK_STORE.get(record["playbookId"])
            if raw_pb:
                pb = normalize_playbook(raw_pb)
                record["playbookName"] = pb["name"]
            else:
                record["playbookName"] = "Unknown Playbook"
                
        return build_success_response(
            data=record,
            message="Execution retrieved successfully."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))

@execution_router.get("/{executionId}/logs", response_model=APIResponse, summary="Get logs for an execution")
def get_execution_logs(executionId: str) -> APIResponse:
    try:
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
            
        logs = record.get("logs") or []
        return build_success_response(
            data=logs,
            message="Logs retrieved successfully."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.get("/{executionId}/variables", response_model=APIResponse,
                      summary="Get runtime variables for an execution")
def get_execution_variables(executionId: str) -> APIResponse:
    """Return the variables dict accumulated during execution."""
    try:
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        # variables are stored inside metadata by update_execution_record
        meta = record.get("metadata") or record
        variables = meta.get("variables") or record.get("variables") or {}
        return build_success_response(
            data=variables,
            message="Variables retrieved successfully."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.get("/{executionId}/artifacts", response_model=APIResponse,
                      summary="Get artifacts produced during an execution")
def get_execution_artifacts(executionId: str) -> APIResponse:
    """Return the list of WorkflowArtifact dicts produced during execution."""
    try:
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        artifacts = meta.get("artifacts") or record.get("artifacts") or []
        return build_success_response(
            data=artifacts,
            message=f"Found {len(artifacts)} artifact(s)."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.get("/{executionId}/step-outputs", response_model=APIResponse,
                      summary="Get structured step outputs for an execution")
def get_execution_step_outputs(executionId: str) -> APIResponse:
    """Return stepOutputs dict — each key is a stepId, value is the structured output."""
    try:
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        step_outputs = meta.get("stepOutputs") or record.get("stepOutputs") or {}
        return build_success_response(
            data=step_outputs,
            message="Step outputs retrieved successfully."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))
