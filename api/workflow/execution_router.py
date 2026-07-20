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
        import os
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        artifacts = meta.get("artifacts") or record.get("artifacts") or []
        
        wireshark_path = r"C:\Program Files\Wireshark\Wireshark.exe"
        wireshark_supported = os.path.exists(wireshark_path)
        
        enriched_artifacts = []
        for art in artifacts:
            a = dict(art)
            if "metadata" not in a or a["metadata"] is None:
                a["metadata"] = {}
            else:
                a["metadata"] = dict(a["metadata"])

            location = a.get("location")
            if location and os.path.exists(location):
                try:
                    a["metadata"]["fileSize"] = os.path.getsize(location)
                except Exception:
                    pass

            if a.get("type", "").lower() in ["pcap", "pcapng"]:
                a["wiresharkSupported"] = wireshark_supported

            print(
                f"[ARTIFACT LIST] "
                f"artifactId={a.get('artifactId')!r} | "
                f"type={a.get('type')!r} | "
                f"name={a.get('name')!r} | "
                f"location={location!r} | "
                f"locationExists={bool(location and os.path.exists(location))} | "
                f"hasData={a.get('data') is not None}"
            )
            enriched_artifacts.append(a)

        return build_success_response(
            data=enriched_artifacts,
            message=f"Found {len(enriched_artifacts)} artifact(s)."
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.get("/{executionId}/artifacts/{artifactId}/download", summary="Download artifact file")
def download_artifact(executionId: str, artifactId: str):
    """Serve the artifact file for download.

    Resolution order (strictly per-artifact — no fallback to workflow variables):
      1. artifact.location  →  FileResponse if the file exists on disk
      2. artifact.data      →  inline Response for in-memory artifacts (e.g. JSON)
      3. 404                →  if neither is available
    """
    execution_id = executionId
    artifact_id  = artifactId
    print("=" * 80)
    print("DOWNLOAD REQUEST")
    print("execution_id =", execution_id)
    print("artifact_id  =", artifact_id)
    print("=" * 80)
    try:
        import os
        from fastapi.responses import FileResponse
        from fastapi import Response
        import json

        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        artifacts = meta.get("artifacts") or record.get("artifacts") or []

        artifact_dict = next((a for a in artifacts if a.get("artifactId") == artifactId), None)
        if not artifact_dict:
            raise APIErrorNotFound(f"Artifact '{artifactId}' not found in execution.")

        location  = artifact_dict.get("location")
        mime_type = artifact_dict.get("mimeType") or "application/octet-stream"
        name      = artifact_dict.get("name") or "artifact"
        art_type  = artifact_dict.get("type", "txt").lower()

        # ── Diagnostic logging ───────────────────────────────────────────────
        print(
            f"[ARTIFACT DOWNLOAD] "
            f"artifactId={artifactId!r} | "
            f"type={art_type!r} | "
            f"name={name!r} | "
            f"location={location!r} | "
            f"mimeType={mime_type!r} | "
            f"locationExists={bool(location and os.path.exists(location))}"
        )

        # ── Filename construction ────────────────────────────────────────────
        safe_name = "".join(c for c in name if c.isalnum() or c in "._- ").strip()
        if not safe_name:
            safe_name = "artifact"

        # Prefer the real file extension from location over the type-derived one.
        # This correctly handles .pcapng files whose artifact type is "pcap".
        if location:
            real_ext = os.path.splitext(location)[1].lower()  # e.g. ".pcapng"
        else:
            real_ext = ""

        ext_map = {
            "pcap":     ".pcap",
            "pcapng":   ".pcapng",
            "json":     ".json",
            "markdown": ".md",
            "csv":      ".csv",
            "pdf":      ".pdf",
            "txt":      ".txt",
            "xml":      ".xml",
            "report":   ".md",
        }
        fallback_ext = ext_map.get(art_type, "")
        # Use the real file extension when available, otherwise fall back to the
        # type-derived extension.
        chosen_ext = real_ext if real_ext else fallback_ext

        if chosen_ext and not safe_name.lower().endswith(chosen_ext):
            filename = f"{safe_name}{chosen_ext}"
        else:
            filename = safe_name

        # ── Resolution: location takes strict priority ───────────────────────
        if location and os.path.exists(location):
            print(
                f"[ARTIFACT DOWNLOAD] Serving file from location — "
                f"filename={filename!r} | path={location!r}"
            )
            print("artifact.name      =", artifact_dict.get("name"))
            print("artifact.type      =", artifact_dict.get("type"))
            print("artifact.location  =", artifact_dict.get("location"))
            print("download.filename  =", filename)
            print("mime_type          =", mime_type)
            return FileResponse(location, filename=filename, media_type=mime_type)

        # ── Fallback: in-memory data (e.g. NmapExecutor JSON) ───────────────
        data = artifact_dict.get("data")
        if data is not None:
            if isinstance(data, (dict, list)):
                content = json.dumps(data, indent=2)
                media   = "application/json"
            else:
                content = str(data)
                media   = mime_type

            print(
                f"[ARTIFACT DOWNLOAD] Serving inline data — "
                f"filename={filename!r} | location_missing={location!r}"
            )
            return Response(
                content=content,
                media_type=media,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        print(
            f"[ARTIFACT DOWNLOAD] ERROR — neither location nor data available "
            f"for artifactId={artifactId!r} (location={location!r})"
        )
        raise APIErrorNotFound("Artifact file not found on disk and no inline data is available.")
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.get("/{executionId}/artifacts/{artifactId}/view", summary="View artifact raw content")
def view_artifact(executionId: str, artifactId: str):
    """Serve the artifact file or data inline for rendering.

    Resolution order (strictly per-artifact — no fallback to workflow variables):
      1. artifact.location  →  FileResponse if the file exists on disk
      2. artifact.data      →  inline Response for in-memory artifacts
      3. 404
    """
    try:
        import os
        from fastapi.responses import FileResponse
        from fastapi import Response
        import json

        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        artifacts = meta.get("artifacts") or record.get("artifacts") or []

        artifact_dict = next((a for a in artifacts if a.get("artifactId") == artifactId), None)
        if not artifact_dict:
            raise APIErrorNotFound(f"Artifact '{artifactId}' not found in execution.")

        location  = artifact_dict.get("location")
        mime_type = artifact_dict.get("mimeType") or "text/plain"
        art_type  = artifact_dict.get("type", "").lower()
        name      = artifact_dict.get("name") or "artifact"

        print(
            f"[ARTIFACT VIEW] "
            f"artifactId={artifactId!r} | "
            f"type={art_type!r} | "
            f"name={name!r} | "
            f"location={location!r} | "
            f"locationExists={bool(location and os.path.exists(location))}"
        )

        if location and os.path.exists(location):
            print(f"[ARTIFACT VIEW] Serving file from location — path={location!r}")
            return FileResponse(location, media_type=mime_type)

        data = artifact_dict.get("data")
        if data is not None:
            if isinstance(data, (dict, list)):
                content = json.dumps(data, indent=2)
                media   = "application/json"
            else:
                content = str(data)
                media   = mime_type

            print(f"[ARTIFACT VIEW] Serving inline data — location_missing={location!r}")
            return Response(content=content, media_type=media)

        print(
            f"[ARTIFACT VIEW] ERROR — neither location nor data available "
            f"for artifactId={artifactId!r} (location={location!r})"
        )
        raise APIErrorNotFound("Artifact file not found on disk and no inline data is available.")
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@execution_router.post("/{executionId}/artifacts/{artifactId}/open-wireshark", summary="Open PCAP in Wireshark")
def open_in_wireshark(executionId: str, artifactId: str) -> APIResponse:
    """Open PCAP/PCAPNG in the Wireshark app."""
    try:
        import os
        import subprocess
        from api.errors import APIErrorValidation

        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        meta = record.get("metadata") or record
        artifacts = meta.get("artifacts") or record.get("artifacts") or []
        
        artifact_dict = next((a for a in artifacts if a.get("artifactId") == artifactId), None)
        if not artifact_dict:
            raise APIErrorNotFound(f"Artifact '{artifactId}' not found in execution.")
            
        art_type = artifact_dict.get("type", "").lower()
        if art_type not in ["pcap", "pcapng"]:
            raise APIErrorValidation("Artifact is not a PCAP/PCAPNG capture.")
            
        location = artifact_dict.get("location")
        if not location or not os.path.exists(location):
            raise APIErrorNotFound("PCAP capture file not found on disk.")
            
        wireshark_path = r"C:\Program Files\Wireshark\Wireshark.exe"
        if not os.path.exists(wireshark_path):
            raise APIErrorValidation("Wireshark is not installed or not found at path.")
            
        subprocess.Popen([wireshark_path, os.path.abspath(location)], close_fds=True)
        
        return build_success_response(
            data={"opened": True},
            message="Wireshark opened successfully."
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
