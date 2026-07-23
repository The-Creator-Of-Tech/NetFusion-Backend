"""
Workflow Execution Engine — Phase 2
=====================================
WorkflowExecutionContext is the single source of truth for every execution.
Typed WorkflowArtifact model tracks all produced artifacts.
StepExecutors receive the full context and return structured stepOutputs.
"""
from __future__ import annotations
import uuid
import time
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from api.persistence import WorkflowExecutionsStore, RepositoryBackedDict, map_playbook
from api.workflow.normalizers import normalize_playbook

# Persistent stores
_PLAYBOOK_STORE = RepositoryBackedDict("playbook", "playbookId", map_playbook)
_EXECUTION_STORE = WorkflowExecutionsStore()


# ---------------------------------------------------------------------------
# WorkflowArtifact model
# ---------------------------------------------------------------------------

@dataclass
class WorkflowArtifact:
    """Represents a structured artifact produced during execution."""
    artifactId: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    type: str = "json"           # json | xml | pcap | txt | markdown | csv | report
    mimeType: str = "application/json"
    producerExecutor: str = ""   # class name of the executor that created this
    stepId: str = ""
    executionId: str = ""
    createdAt: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    metadata: Dict[str, Any] = field(default_factory=dict)
    location: str = ""           # in-memory key or file path
    # actual data stored inline for in-memory artifacts
    data: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifactId": self.artifactId,
            "name": self.name,
            "type": self.type,
            "mimeType": self.mimeType,
            "producerExecutor": self.producerExecutor,
            "stepId": self.stepId,
            "executionId": self.executionId,
            "createdAt": self.createdAt,
            "metadata": self.metadata,
            "location": self.location,
            "data": self.data,
        }


# ---------------------------------------------------------------------------
# WorkflowExecutionContext — single source of truth
# ---------------------------------------------------------------------------

@dataclass
class WorkflowExecutionContext:
    """
    Shared runtime state for a workflow execution.
    Survives the lifetime of the entire execution; every executor reads/writes here.
    """
    execution_id: str
    playbook_id: str
    playbook_name: str
    steps: List[Dict[str, Any]]
    total_steps: int
    project_id: Optional[str] = None

    # --- Progress tracking ---
    completed_steps: int = 0
    failed_steps: int = 0
    current_step: Optional[str] = None
    current_step_number: Optional[int] = None
    status: str = "QUEUED"
    progress: int = 0

    # --- Variables: inter-step key-value store ---
    variables: Dict[str, Any] = field(default_factory=dict)

    # --- Artifacts: keyed by artifactId ---
    artifacts: Dict[str, WorkflowArtifact] = field(default_factory=dict)

    # --- Step outputs: keyed by stepId ---
    stepOutputs: Dict[str, Any] = field(default_factory=dict)

    # --- Execution logs ---
    logs: List[Dict[str, Any]] = field(default_factory=list)

    # --- Timeline events ---
    timelineEvents: List[Dict[str, Any]] = field(default_factory=list)

    # --- Arbitrary metadata ---
    metadata: Dict[str, Any] = field(default_factory=dict)

    # --- UI Monitor fields ---
    current_executor: Optional[str] = None
    current_action: Optional[str] = None
    returned_summary: Optional[str] = None

    # --- Timestamps ---
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: Optional[str] = None

    # ── Variable helpers ─────────────────────────────────────────────────────

    def set_variable(self, key: str, value: Any, type: Optional[str] = None) -> None:
        """Write a variable into the shared context using structured metadata."""
        if type is None:
            type = self._infer_variable_type(value)
        
        created_by = self.current_executor or "system"
        step_number = self.current_step_number or 0
        created_at = datetime.utcnow().isoformat() + "Z"

        self.variables[key] = {
            "name": key,
            "type": type,
            "value": value,
            "createdBy": created_by,
            "stepNumber": step_number,
            "createdAt": created_at
        }
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def setVariable(self, name: str, value: Any, type: Optional[str] = None) -> None:
        """CamelCase alias for set_variable."""
        self.set_variable(name, value, type)

    def get_variable(self, key: str, default: Any = None) -> Any:
        """Read a variable from the shared context. Returns raw value for backward compatibility."""
        if key not in self.variables:
            return default
        val = self.variables[key]
        if isinstance(val, dict) and "value" in val and "name" in val and "type" in val:
            return val["value"]
        return val

    def getVariable(self, name: str) -> Any:
        """CamelCase alias for get_variable."""
        return self.get_variable(name)

    def has_variable(self, key: str) -> bool:
        """Check whether a variable exists in the shared context."""
        return key in self.variables

    def hasVariable(self, name: str) -> bool:
        """CamelCase alias for has_variable."""
        return self.has_variable(name)

    def list_variables(self) -> List[Dict[str, Any]]:
        """Return all variables in their structured formats."""
        res = []
        for name, val in self.variables.items():
            if isinstance(val, dict) and "value" in val and "name" in val and "type" in val:
                res.append(val)
            else:
                # Convert legacy/flat variable on the fly
                res.append({
                    "name": name,
                    "type": self._infer_variable_type(val),
                    "value": val,
                    "createdBy": "legacy",
                    "stepNumber": 0,
                    "createdAt": self.started_at
                })
        return res

    def listVariables(self) -> List[Dict[str, Any]]:
        """CamelCase alias for list_variables."""
        return self.list_variables()

    def _infer_variable_type(self, value: Any) -> str:
        """Infer variable type from a Python value."""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, (int, float)):
            return "number"
        elif isinstance(value, list):
            return "array"
        elif isinstance(value, dict):
            return "object"
        elif isinstance(value, str):
            import os
            if (value.startswith("memory://") or 
                value.startswith("file://") or 
                (len(value) > 3 and (os.path.isabs(value) or "/" in value or "\\" in value or "." in value))):
                if os.path.exists(value) or any(value.lower().endswith(ext) for ext in [".pcap", ".pcapng", ".json", ".txt", ".csv", ".xml", ".pdf"]):
                    return "file"
            try:
                import json
                if value.strip().startswith(("{", "[")):
                    json.loads(value)
                    return "json"
            except Exception:
                pass
            return "string"
        return "json"

    # ── Artifact helpers ─────────────────────────────────────────────────────

    def add_artifact(self, artifact: WorkflowArtifact) -> WorkflowArtifact:
        """Register an artifact produced during this execution."""
        artifact.executionId = self.execution_id
        self.artifacts[artifact.artifactId] = artifact
        self.updated_at = datetime.utcnow().isoformat() + "Z"
        return artifact

    def get_artifact(self, artifact_id: str) -> Optional[WorkflowArtifact]:
        """Retrieve an artifact by its ID."""
        return self.artifacts.get(artifact_id)

    def list_artifacts(self) -> List[WorkflowArtifact]:
        """Return all artifacts produced so far, sorted by createdAt."""
        return sorted(self.artifacts.values(), key=lambda a: a.createdAt)

    # ── Step output helpers ───────────────────────────────────────────────────

    def set_step_output(self, step_id: str, output: Any) -> None:
        self.stepOutputs[step_id] = output
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def get_step_output(self, step_id: str, default: Any = None) -> Any:
        return self.stepOutputs.get(step_id, default)

    # ── Property aliases (backward compat) ───────────────────────────────────

    @property
    def executionId(self) -> str:
        return self.execution_id

    @property
    def playbookId(self) -> str:
        return self.playbook_id

    @property
    def projectId(self) -> Optional[str]:
        return self.project_id

    @property
    def currentStep(self) -> Optional[str]:
        return self.current_step

    @property
    def step_results(self) -> List[Dict[str, Any]]:
        """Legacy compat: build list from stepOutputs dict."""
        return list(self.stepOutputs.values()) if self.stepOutputs else []

    def artifacts_as_list(self) -> List[Dict[str, Any]]:
        """Serialize artifacts dict → list for persistence."""
        return [a.to_dict() for a in self.list_artifacts()]


# ---------------------------------------------------------------------------
# Backward-compat alias so existing imports of ExecutionContext still work
# ---------------------------------------------------------------------------
ExecutionContext = WorkflowExecutionContext


# ---------------------------------------------------------------------------
# update_execution_record — syncs context → DB
# ---------------------------------------------------------------------------

def update_execution_record(ctx: WorkflowExecutionContext) -> None:
    """Synchronize WorkflowExecutionContext to the database."""
    try:
        started_dt = datetime.fromisoformat(ctx.started_at.replace("Z", ""))
        duration_ms = (datetime.utcnow() - started_dt).total_seconds() * 1000.0
    except Exception:
        duration_ms = 0.0

    artifacts_list = ctx.artifacts_as_list()

    metadata = {
        # Frontend compatibility mapping
        "id": ctx.execution_id,
        "name": ctx.playbook_name,
        "type": "playbook",
        "refId": ctx.playbook_id,
        "completedAt": ctx.finished_at,
        "duration": duration_ms,

        # Core execution fields
        "executionId": ctx.execution_id,
        "playbookId": ctx.playbook_id,
        "playbookName": ctx.playbook_name,
        "status": ctx.status,
        "progress": ctx.progress,
        "logs": list(ctx.logs),
        "startedAt": ctx.started_at,
        "updatedAt": ctx.updated_at,
        "finishedAt": ctx.finished_at,
        "triggeredBy": "manual",
        "totalSteps": ctx.total_steps,
        "completedSteps": ctx.completed_steps,
        "failedSteps": ctx.failed_steps,
        "currentStep": ctx.current_step,
        "stepResults": list(ctx.stepOutputs.values()),

        # Phase 2: new runtime fields
        "variables": dict(ctx.variables),
        "artifacts": artifacts_list,
        "artifactsCount": len(artifacts_list),
        "stepOutputs": dict(ctx.stepOutputs),
        "timelineEvents": list(ctx.timelineEvents),
        "executionMetadata": dict(ctx.metadata),

        # UI Monitor fields
        "currentExecutor": ctx.current_executor,
        "currentAction": ctx.current_action,
        "returnedSummary": ctx.returned_summary,
    }

    updates = {
        "status": ctx.status,
        "progress": ctx.progress,
        "logs": list(ctx.logs),
        "finishedAt": ctx.finished_at,
        "completedSteps": ctx.completed_steps,
        "failedSteps": ctx.failed_steps,
        "currentStep": ctx.current_step,
        "stepResults": list(ctx.stepOutputs.values()),
        "metadata": metadata,
    }
    _EXECUTION_STORE.update(ctx.execution_id, updates)


# ---------------------------------------------------------------------------
# ExecutionLogger
# ---------------------------------------------------------------------------

class ExecutionLogger:
    @staticmethod
    def log(ctx: WorkflowExecutionContext, level: str, message: str) -> None:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level.lower(),
            "message": message,
        }
        ctx.logs.append(log_entry)
        update_execution_record(ctx)


# ---------------------------------------------------------------------------
# StateMachine
# ---------------------------------------------------------------------------

class StateMachine:
    @staticmethod
    def transition(ctx: WorkflowExecutionContext, to_status: str) -> None:
        valid_transitions = {
            "QUEUED": ["RUNNING", "FAILED", "ABORTED"],
            "RUNNING": ["COMPLETED", "FAILED", "ABORTED"],
            "COMPLETED": [],
            "FAILED": [],
            "ABORTED": [],
        }

        current = ctx.status
        if to_status not in valid_transitions.get(current, []):
            ExecutionLogger.log(ctx, "WARN", f"Invalid state transition from {current} to {to_status}")

        ctx.status = to_status
        if to_status in ("COMPLETED", "FAILED", "ABORTED"):
            ctx.finished_at = datetime.utcnow().isoformat() + "Z"

        ExecutionLogger.log(ctx, "INFO", f"State transitioned from {current} to {to_status}")
        update_execution_record(ctx)


# ---------------------------------------------------------------------------
# StepExecutor — updated contract: receives WorkflowExecutionContext
# ---------------------------------------------------------------------------

class StepExecutor(ABC):
    """
    Base class for all step executors.
    Every executor receives the full WorkflowExecutionContext, enabling:
    - Reading and writing shared variables
    - Creating typed artifacts
    - Creating timeline events
    - Returning structured step outputs
    """
    identifier: str = ""

    @abstractmethod
    def can_execute(self, step: Dict[str, Any]) -> bool:
        pass

    def execute(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        ctx.current_executor = self.__class__.__name__
        step_title = step.get("title") or "Step"
        ctx.current_action = f"Executing step: {step_title}"
        update_execution_record(ctx)

        self.create_timeline_event(
            ctx,
            f"Step Started: {step_title}",
            f"Step of type '{step.get('stepType')}' started."
        )

        try:
            result = self._execute_internal(step, ctx)
            success = result.get("success", False)
            summary = result.get("summary", "")

            ctx.returned_summary = summary
            ctx.current_action = f"Finished step: {step_title}"

            if success:
                self.create_timeline_event(
                    ctx,
                    f"Step Completed: {step_title}",
                    f"Step completed successfully. Summary: {summary}"
                )
            else:
                error_msg = result.get("error", "Unknown error")
                self.create_timeline_event(
                    ctx,
                    f"Step Failed: {step_title}",
                    f"Step failed. Error: {error_msg}"
                )

            update_execution_record(ctx)
            return result
        except Exception as e:
            error_msg = str(e)
            ctx.returned_summary = f"Exception: {error_msg}"
            ctx.current_action = f"Failed step: {step_title}"

            self.create_timeline_event(
                ctx,
                f"Step Failed: {step_title}",
                f"Step failed due to exception: {error_msg}"
            )

            update_execution_record(ctx)
            return {"success": False, "error": error_msg}

    @abstractmethod
    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        """
        Executors must return a structured dict. Recommended keys:
          success: bool
          summary: str
          output: dict  (structured step output stored in ctx.stepOutputs)
          error: str    (on failure)
          duration: float (ms)
        """
        pass

    def create_timeline_event(self, ctx: WorkflowExecutionContext, title: str, description: str) -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "title": title,
            "description": description,
        }
        ctx.timelineEvents.append(event)

        if ctx.project_id:
            try:
                from api.persistence import call_repository, map_timeline_event
                event_payload = {
                    "projectId": ctx.project_id,
                    "investigationId": ctx.project_id,
                    "title": title,
                    "description": description,
                    "type": "MANUAL_ACTION",
                    "createdBy": "system",
                    "updatedBy": "system",
                }
                mapped = map_timeline_event(event_payload)
                event_payload.update(mapped)
                call_repository("timelineEvent", "create", {"data": event_payload})
            except Exception as err:
                safe_err = str(err).encode('ascii', errors='replace').decode('ascii')
                print(f"Failed to log timeline event: {safe_err}")

    def setVariable(self, name: str, value: Any, type: Optional[str] = None) -> None:
        if hasattr(self, "ctx") and self.ctx:
            self.ctx.set_variable(name, value, type)

    def set_variable(self, name: str, value: Any, type: Optional[str] = None) -> None:
        if hasattr(self, "ctx") and self.ctx:
            self.ctx.set_variable(name, value, type)

    def getVariable(self, name: str) -> Any:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.get_variable(name)
        return None

    def get_variable(self, name: str) -> Any:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.get_variable(name)
        return None

    def hasVariable(self, name: str) -> bool:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.has_variable(name)
        return False

    def has_variable(self, name: str) -> bool:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.has_variable(name)
        return False

    def listVariables(self) -> List[Dict[str, Any]]:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.list_variables()
        return []

    def list_variables(self) -> List[Dict[str, Any]]:
        if hasattr(self, "ctx") and self.ctx:
            return self.ctx.list_variables()
        return []


# ---------------------------------------------------------------------------
# ManualExecutor
# ---------------------------------------------------------------------------

class ManualExecutor(StepExecutor):
    identifier = "manual"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        if "generate" in title and "report" in title:
            return False
        return step.get("stepType") == "MANUAL"

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        step_title = step.get("title") or "Manual Step"
        step_id = step.get("stepId") or step.get("id") or "manual-step"
        ExecutionLogger.log(ctx, "INFO", f"Running Manual Step: {step_title}")

        ctx.current_action = "Waiting for manual confirmation"
        update_execution_record(ctx)
        ExecutionLogger.log(ctx, "INFO", "Manual step is waiting for confirmation.")
        ExecutionLogger.log(ctx, "INFO", "Manual step completed.")

        # Structured step output
        output = {
            "confirmed": True,
            "stepTitle": step_title,
            "executedAt": datetime.utcnow().isoformat() + "Z",
        }
        ctx.set_step_output(step_id, output)

        # Write a variable so subsequent steps can check
        ctx.set_variable(f"step_{step_id}_confirmed", True)

        return {
            "success": True,
            "status": "EXECUTED",
            "summary": "Manual action completed successfully.",
            "duration": 0.0,
            "output": output,
        }


# ---------------------------------------------------------------------------
# NmapExecutor
# ---------------------------------------------------------------------------

class NmapExecutor(StepExecutor):
    identifier = "nmap"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        desc = step.get("description", "").lower()
        step_type = step.get("stepType", "")
        
        # Exclude AI summary/investigation patterns so they route to AIInvestigationExecutor
        is_ai = "ai summary" in title or "ai summary" in desc or "investigation" in title or "investigation" in desc
        if is_ai:
            return False

        return step_type == "AUTOMATED" and (
            "nmap" in title or "nmap" in desc or "scan" in title or "scan" in desc
        )

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        step_id = step.get("stepId") or step.get("id") or "nmap-step"

        # 1. Resolve Target — step.config → context variable → description IP → fallback
        target = step.get("config", {}).get("target") or step.get("target")
        if not target:
            target = ctx.get_variable("target")
        if not target:
            desc = step.get("description", "")
            ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", desc)
            target = ip_match.group(0) if ip_match else "127.0.0.1"

        # 2. Resolve Profile
        profile_raw = step.get("config", {}).get("profile") or step.get("profile") or "quick"
        profile_map = {
            "service detection": "service", "service": "service",
            "os detection": "os", "os": "os",
            "aggressive": "aggressive", "full": "full", "quick": "quick"
        }
        profile = profile_map.get(str(profile_raw).lower(), "quick")

        ExecutionLogger.log(ctx, "INFO", "Running Nmap")
        ExecutionLogger.log(ctx, "INFO", f"Target: {target}")
        ExecutionLogger.log(ctx, "INFO", f"Profile: {profile}")
        ctx.current_action = f"Running Nmap scan on {target} ({profile})"
        update_execution_record(ctx)

        from main import scan, ScanRequest
        start_time = time.time()
        scan_req = ScanRequest(target=target, profile=profile)
        scan_result = scan(scan_req)
        duration_ms = (time.time() - start_time) * 1000.0

        ports = scan_result.get("ports") or []
        services = [
            {"port": p.get("port"), "state": p.get("state"), "service": p.get("service")}
            for p in ports
        ]
        open_ports = [p.get("port") for p in ports if p.get("state") == "open"]

        ExecutionLogger.log(ctx, "INFO", f"Scan finished. Found {len(ports)} open TCP ports:")
        for p in ports:
            ExecutionLogger.log(ctx, "INFO",
                f"  {p.get('port')}/tcp | {p.get('state')} | {p.get('service')}")
        ExecutionLogger.log(ctx, "INFO", "Finished successfully.")

        # Build typed artifact
        artifact = WorkflowArtifact(
            name=f"Nmap_{target}.json",
            type="json",
            mimeType="application/json",
            producerExecutor=self.__class__.__name__,
            stepId=step_id,
            metadata={"target": target, "profile": profile, "portCount": len(ports)},
            data=scan_result,
        )
        ctx.add_artifact(artifact)

        # Write variables for subsequent executors
        ctx.setVariable("host", target, "string")
        ctx.setVariable("open_ports", open_ports, "array")
        ctx.setVariable("services", services, "array")
        ctx.setVariable("scan_results", scan_result, "json")

        # Legacy compatibility variables
        ctx.setVariable("target", target, "string")
        ctx.setVariable("last_scan_target", target, "string")
        ctx.setVariable("last_scan_ports", ports, "array")

        # Structured step output
        output = {
            "host": target,
            "ports": ports,
            "services": services,
            "openPorts": open_ports,
            "profile": profile,
            "artifactId": artifact.artifactId,
            "scannedAt": datetime.utcnow().isoformat() + "Z",
        }
        ctx.set_step_output(step_id, output)

        return {
            "success": True,
            "output": output,
            "duration": duration_ms,
            "summary": f"Nmap scan completed on target {target}. Found {len(ports)} open ports.",
        }


# ---------------------------------------------------------------------------
# PacketCaptureExecutor
# ---------------------------------------------------------------------------

class PacketCaptureExecutor(StepExecutor):
    identifier = "packet_capture"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        desc = step.get("description", "").lower()
        step_type = step.get("stepType", "")
        
        # Exclude PCAP analysis patterns so they route to PCAPAnalysisExecutor
        is_analysis = "analyze pcap" in title or "pcap analysis" in title or "analyze pcap" in desc or "pcap analysis" in desc
        if is_analysis:
            return False

        return step_type == "AUTOMATED" and (
            "capture" in title or "capture" in desc or "network capture" in title or "pcap" in title
        )

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        import os
        from services import capture_service

        step_id = step.get("stepId") or step.get("id") or "capture-step"

        # 1. Resolve Config
        config = step.get("config") or {}
        interface = config.get("interface") or "Ethernet"
        try:
            duration = int(config.get("duration") or 10)
        except (ValueError, TypeError):
            duration = 10

        capture_filter = config.get("filter") or config.get("captureFilter") or ""
        
        ExecutionLogger.log(ctx, "INFO", "Starting Packet Capture")
        ExecutionLogger.log(ctx, "INFO", f"Interface: {interface}")
        ExecutionLogger.log(ctx, "INFO", f"Duration: {duration}s")
        if capture_filter:
            ExecutionLogger.log(ctx, "INFO", f"Filter: {capture_filter}")

        ctx.current_action = f"Starting capture on {interface} for {duration}s"
        update_execution_record(ctx)

        start_time = time.time()
        
        # Start capture
        self.create_timeline_event(ctx, "Capture Started", f"Starting capture on interface {interface}")
        start_result = capture_service.start_capture(interface)
        if "error" in start_result:
            return {"success": False, "error": start_result["error"]}

        capture_id = str(uuid.uuid4())
        
        self.create_timeline_event(ctx, "Capture Running", f"Capture is actively running for {duration} seconds.")
        ctx.current_action = f"Capture running for {duration}s"
        update_execution_record(ctx)

        # Sleep for duration
        time.sleep(duration)

        # Stop capture
        ctx.current_action = "Stopping capture"
        update_execution_record(ctx)
        
        stop_result = capture_service.stop_capture()
        if "error" in stop_result:
            self.create_timeline_event(ctx, "Capture Failed", f"Failed to stop capture: {stop_result['error']}")
            return {"success": False, "error": stop_result["error"]}

        capture_file = stop_result.get("file")

        # Analyze capture
        ctx.current_action = "Analyzing PCAP"
        update_execution_record(ctx)
        
        analyze_result = capture_service.analyze_latest_capture()
        duration_ms = (time.time() - start_time) * 1000.0

        if "error" in analyze_result:
            self.create_timeline_event(ctx, "Capture Failed", f"Failed to analyze capture: {analyze_result['error']}")
            return {"success": False, "error": analyze_result["error"]}

        packet_count = analyze_result.get("total_packets", 0)
        file_size = os.path.getsize(capture_file) if capture_file and os.path.exists(capture_file) else 0

        self.create_timeline_event(ctx, "Capture Completed", f"Capture completed. Captured {packet_count} packets.")

        ExecutionLogger.log(ctx, "INFO", f"Capture finished. PCAP saved to {capture_file}.")
        ExecutionLogger.log(ctx, "INFO", f"Total packets: {packet_count}")

        import datetime as dt_mod
        today_str = dt_mod.date.today().strftime("%Y-%m-%d")
        artifact = WorkflowArtifact(
            name=f"LiveCapture_{today_str}.pcap",
            type="pcap",
            mimeType="application/vnd.tcpdump.pcap",
            producerExecutor=self.__class__.__name__,
            stepId=step_id,
            location=capture_file,
            metadata={
                "interface": interface,
                "duration": duration,
                "packetCount": packet_count,
                "captureFilter": capture_filter,
                "fileSize": file_size,
            },
        )
        ctx.add_artifact(artifact)

        # Write variables for subsequent executors
        ctx.setVariable("capture_file", capture_file, "file")
        ctx.setVariable("packet_count", packet_count, "number")
        ctx.setVariable("capture_duration", duration, "number")
        ctx.setVariable("capture_interface", interface, "string")

        # Legacy compatibility variables
        ctx.setVariable("capture_id", capture_id, "string")
        ctx.setVariable("capture_packet_count", packet_count, "number")
        ctx.setVariable("capture_status", "completed", "string")

        # Structured step output
        output = {
            "interface": interface,
            "duration": duration,
            "packetCount": packet_count,
            "captureFile": capture_file,
            "artifactId": artifact.artifactId,
            "capturedAt": datetime.utcnow().isoformat() + "Z",
        }
        ctx.set_step_output(step_id, output)

        return {
            "success": True,
            "output": output,
            "duration": duration_ms,
            "summary": f"Packet capture completed on {interface}. {packet_count} packets captured.",
        }


# ---------------------------------------------------------------------------
# PCAPAnalysisExecutor
# ---------------------------------------------------------------------------

class PCAPAnalysisExecutor(StepExecutor):
    identifier = "pcap_analysis"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        desc = step.get("description", "").lower()
        step_type = step.get("stepType", "")
        executor_id = step.get("executor") or step.get("executorType")
        if executor_id == "pcap_analysis":
            return True
        return step_type == "AUTOMATED" and (
            "analyze pcap" in title or "pcap analysis" in title or
            "analyze pcap" in desc or "pcap analysis" in desc
        )

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        import os
        from parsers import tshark_parser, packet_parser

        step_id = step.get("stepId") or step.get("id") or "pcap-analysis-step"

        # 1. Resolve Config
        config = step.get("config") or {}

        # Log the entire resolved step configuration immediately before validation
        ExecutionLogger.log(ctx, "INFO", f"Resolved step configuration: {config}")

        capture_file = (
            config.get("capture_file")
            or config.get("pcap_file")
            or config.get("pcap_file_path")
            or config.get("file_path")
            or config.get("path")
        )
        if capture_file:
            config["capture_file"] = capture_file

        ExecutionLogger.log(ctx, "INFO", "Starting PCAP Analysis")

        # 2. Variable resolution check
        if not capture_file:
            error_msg = "Missing 'capture_file' config parameter."
            ExecutionLogger.log(ctx, "ERROR", error_msg)
            return {"success": False, "error": error_msg}

        if "${" in str(capture_file):
            error_msg = f"Received unresolved variable placeholder in config: {capture_file}"
            ExecutionLogger.log(ctx, "ERROR", error_msg)
            return {"success": False, "error": error_msg}

        # Handle file URI schema and clean backslashes for Windows
        if isinstance(capture_file, str):
            if capture_file.startswith("file:///"):
                capture_file = capture_file[8:]
            elif capture_file.startswith("file://"):
                capture_file = capture_file[7:]
            capture_file = os.path.abspath(capture_file.replace('/', '\\'))

        # 3. Verify capture file exists
        ExecutionLogger.log(ctx, "INFO", f"Verifying capture file existence: {capture_file}")
        if not os.path.exists(capture_file):
            error_msg = f"Capture file does not exist: {capture_file}"
            ExecutionLogger.log(ctx, "ERROR", error_msg)
            return {"success": False, "error": error_msg}

        start_time = time.time()
        self.create_timeline_event(ctx, "PCAP Analysis Started", f"Analyzing capture file: {os.path.basename(capture_file)}")

        try:
            # 4. Execute TShark to extract structured information
            ExecutionLogger.log(ctx, "INFO", "Executing TShark to extract protocols...")
            raw_protocols = tshark_parser.extract_protocol_lines(capture_file)
            protocols_list = sorted(list(set(p.strip().upper() for p in raw_protocols if p.strip())))
            ExecutionLogger.log(ctx, "INFO", f"Protocols found: {', '.join(protocols_list)}")

            ExecutionLogger.log(ctx, "INFO", "Executing TShark to extract DNS queries...")
            raw_dns = tshark_parser.extract_dns_query_lines(capture_file)
            dns_set = set()
            for line in raw_dns:
                for part in line.replace('\t', ',').split(','):
                    part = part.strip().lower()
                    if part and part != "none":
                        dns_set.add(part)
            dns_queries_list = sorted(list(dns_set))
            ExecutionLogger.log(ctx, "INFO", f"DNS queries found: {len(dns_queries_list)}")

            ExecutionLogger.log(ctx, "INFO", "Executing TShark to extract HTTP hosts...")
            raw_http = tshark_parser.extract_http_host_lines(capture_file)
            http_set = set()
            for line in raw_http:
                for part in line.replace('\t', ',').split(','):
                    part = part.strip().lower()
                    if part and part != "none":
                        http_set.add(part)
            http_hosts_list = sorted(list(http_set))
            ExecutionLogger.log(ctx, "INFO", f"HTTP hosts found: {len(http_hosts_list)}")

            ExecutionLogger.log(ctx, "INFO", "Executing TShark to extract TLS sessions...")
            raw_tls = tshark_parser.extract_tls_session_lines(capture_file)
            tls_set = set()
            for line in raw_tls:
                for part in line.replace('\t', ',').split(','):
                    part = part.strip().lower()
                    if part and part != "none":
                        tls_set.add(part)
            tls_sessions_list = sorted(list(tls_set))
            ExecutionLogger.log(ctx, "INFO", f"TLS sessions found: {len(tls_sessions_list)}")

            ExecutionLogger.log(ctx, "INFO", "Executing TShark to parse conversations...")
            conversation_map = {}
            for line in tshark_parser.extract_conversation_lines(capture_file):
                parsed = packet_parser.parse_conversation_line(line)
                if not parsed:
                    continue
                src, dst, proto = parsed
                key = (src, dst, proto.upper())
                conversation_map[key] = conversation_map.get(key, 0) + 1

            conversations_list = []
            for (src, dst, proto), pkts in sorted(conversation_map.items(), key=lambda x: x[1], reverse=True):
                conversations_list.append({
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "packets": pkts
                })
            ExecutionLogger.log(ctx, "INFO", f"Conversations parsed: {len(conversations_list)}")

            # Format conversations as list of strings
            conversations_str_list = [
                f"{c['src']} -> {c['dst']} ({c['protocol']})"
                for c in conversations_list
            ]

            # Extract endpoints
            ExecutionLogger.log(ctx, "INFO", "Extracting unique network endpoints...")
            endpoints_set = set()
            for conv in conversations_list:
                endpoints_set.add(conv["src"])
                endpoints_set.add(conv["dst"])
            endpoints_list = sorted(list(endpoints_set))
            ExecutionLogger.log(ctx, "INFO", f"Endpoints identified: {len(endpoints_list)}")

            # Calculate capture statistics and duration
            file_size = os.path.getsize(capture_file)
            total_packets = len(raw_protocols)

            # Helper for getting capture duration
            duration = 0.0
            if total_packets > 1:
                try:
                    res_first = tshark_parser.run_tshark("-r", capture_file, "-T", "fields", "-e", "frame.time_epoch", "-c", "1")
                    res_last = tshark_parser.run_tshark("-r", capture_file, "-T", "fields", "-e", "frame.time_epoch", "-Y", f"frame.number == {total_packets}")
                    if res_first.returncode == 0 and res_last.returncode == 0:
                        first_str = res_first.stdout.strip()
                        last_str = res_last.stdout.strip()
                        if first_str and last_str:
                            duration = float(last_str) - float(first_str)
                except Exception as ex:
                    ExecutionLogger.log(ctx, "WARN", f"Failed to compute duration: {ex}")

            statistics = {
                "total_packets": total_packets,
                "file_size_bytes": file_size,
                "duration_seconds": round(duration, 3),
                "protocols_count": len(protocols_list),
                "dns_queries_count": len(dns_queries_list),
                "http_hosts_count": len(http_hosts_list),
                "tls_sessions_count": len(tls_sessions_list),
                "conversations_count": len(conversations_list),
                "endpoints_count": len(endpoints_list),
            }
            ExecutionLogger.log(ctx, "INFO", f"Compiled statistics: {statistics}")

            analysis_summary = (
                f"PCAP Analysis completed for {os.path.basename(capture_file)}. "
                f"Analyzed {total_packets} packets over {round(duration, 2)}s. "
                f"Found {len(protocols_list)} protocols ({', '.join(protocols_list[:5])}), "
                f"{len(dns_queries_list)} DNS queries, {len(http_hosts_list)} HTTP hosts, "
                f"{len(tls_sessions_list)} TLS sessions, and {len(conversations_list)} conversations."
            )
            ExecutionLogger.log(ctx, "INFO", f"Summary: {analysis_summary}")

            # 5. Store variables in Workflow Variable Registry with metadata
            ExecutionLogger.log(ctx, "INFO", "Publishing variables to Variable Registry...")
            ctx.set_variable("protocols", protocols_list, "array")
            ctx.set_variable("dns_queries", dns_queries_list, "array")
            ctx.set_variable("http_hosts", http_hosts_list, "array")
            ctx.set_variable("tls_sessions", tls_sessions_list, "array")
            ctx.set_variable("conversations", conversations_str_list, "array")
            ctx.set_variable("endpoints", endpoints_list, "array")
            ctx.set_variable("statistics", statistics, "object")
            ctx.set_variable("analysis_summary", analysis_summary, "string")

            # 6. Create Markdown report artifact
            ExecutionLogger.log(ctx, "INFO", "Creating PCAP Analysis artifact...")
            artifact_dir = os.path.dirname(capture_file)
            base_name = os.path.splitext(os.path.basename(capture_file))[0]
            artifact_path = os.path.join(artifact_dir, f"analysis_{base_name}_{uuid.uuid4().hex[:8]}.md")

            # Count protocols for markdown
            from collections import Counter
            proto_counts = dict(Counter(p.strip().upper() for p in raw_protocols if p.strip()))
            proto_summary_md = ""
            for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
                proto_summary_md += f"- **{proto}**: {count} packets\n"

            md_content = f"""# PCAP Analysis Report

## Source Capture File
- **Path**: `{capture_file}`
- **Size**: `{file_size} bytes`
- **Analyzed At**: `{datetime.utcnow().isoformat() + "Z"}`

## Extracted Statistics
- **Total Packets**: {total_packets}
- **Duration**: {round(duration, 3)} seconds
- **Unique Protocols**: {len(protocols_list)}
- **DNS Queries**: {len(dns_queries_list)}
- **HTTP Hosts**: {len(http_hosts_list)}
- **TLS Sessions**: {len(tls_sessions_list)}
- **Conversations**: {len(conversations_list)}
- **Endpoints**: {len(endpoints_list)}

## Protocol Summary
{proto_summary_md if proto_summary_md else "*No protocols identified.*"}

## DNS Summary
{chr(10).join(f"- `{query}`" for query in dns_queries_list[:50]) if dns_queries_list else "*No DNS queries identified.*"}
{f"*... and {len(dns_queries_list) - 50} more DNS queries.*" if len(dns_queries_list) > 50 else ""}

## HTTP Summary
{chr(10).join(f"- `{host}`" for host in http_hosts_list[:50]) if http_hosts_list else "*No HTTP hosts identified.*"}
{f"*... and {len(http_hosts_list) - 50} more HTTP hosts.*" if len(http_hosts_list) > 50 else ""}

## TLS Summary
{chr(10).join(f"- `{session}`" for session in tls_sessions_list[:50]) if tls_sessions_list else "*No TLS sessions identified.*"}
{f"*... and {len(tls_sessions_list) - 50} more TLS sessions.*" if len(tls_sessions_list) > 50 else ""}

## Conversation Summary
| Source | Destination | Protocol | Packets |
|---|---|---|---|
"""
            for conv in conversations_list[:50]:
                md_content += f"| {conv['src']} | {conv['dst']} | {conv['protocol']} | {conv['packets']} |\n"
            if len(conversations_list) > 50:
                md_content += f"| *... and {len(conversations_list) - 50} more* | | | |\n"
            if not conversations_list:
                md_content += "| *No conversations identified* | | | |\n"

            # Write file to disk
            with open(artifact_path, "w", encoding="utf-8") as f:
                f.write(md_content)

            artifact = WorkflowArtifact(
                name="AI_Investigation_Report.md",
                type="markdown",
                mimeType="text/markdown",
                producerExecutor=self.__class__.__name__,
                stepId=step_id,
                location=artifact_path,
                metadata={
                    "capture_file": capture_file,
                    "statistics": statistics,
                    "protocols_count": len(protocols_list),
                    "dns_queries_count": len(dns_queries_list),
                    "http_hosts_count": len(http_hosts_list),
                    "tls_sessions_count": len(tls_sessions_list),
                    "conversations_count": len(conversations_list),
                },
            )
            ctx.add_artifact(artifact)
            ExecutionLogger.log(ctx, "INFO", f"Analysis artifact created: {artifact_path}")

            # 7. Structured step output
            output = {
                "capture_file": capture_file,
                "protocols": protocols_list,
                "dns_queries": dns_queries_list,
                "http_hosts": http_hosts_list,
                "tls_sessions": tls_sessions_list,
                "conversations": conversations_list,
                "endpoints": endpoints_list,
                "statistics": statistics,
                "artifactId": artifact.artifactId,
                "analyzedAt": datetime.utcnow().isoformat() + "Z",
            }
            ctx.set_step_output(step_id, output)

            duration_ms = (time.time() - start_time) * 1000.0
            self.create_timeline_event(ctx, "PCAP Analysis Completed", f"Analysis completed successfully in {round(duration_ms / 1000.0, 2)}s.")
            ExecutionLogger.log(ctx, "INFO", "PCAP Analysis step completed successfully")

            return {
                "success": True,
                "output": output,
                "duration": duration_ms,
                "summary": analysis_summary,
            }

        except Exception as e:
            error_msg = f"PCAP Analysis failed: {e}"
            ExecutionLogger.log(ctx, "ERROR", error_msg)
            self.create_timeline_event(ctx, "PCAP Analysis Failed", error_msg)
            return {"success": False, "error": error_msg}


# ---------------------------------------------------------------------------
# AIInvestigationExecutor
# ---------------------------------------------------------------------------

class AIInvestigationExecutor(StepExecutor):
    identifier = "ai_investigation"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        desc = step.get("description", "").lower()
        step_type = step.get("stepType", "")
        executor_id = step.get("executor") or step.get("executorType")
        
        if executor_id in ("ai_investigation", "ai", "ai_summary"):
            return True
            
        return step_type == "AUTOMATED" and (
            "ai summary" in title or "ai summary" in desc or
            "investigation" in title or "investigation" in desc or
            "ai_investigation" in title or "ai_investigation" in desc or
            "ai_summary" in title or "ai_summary" in desc
        )

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        import os
        import uuid
        
        step_id = step.get("stepId") or step.get("id") or "ai-investigation-step"
        config = step.get("config") or {}
        
        ExecutionLogger.log(ctx, "INFO", "Starting AI Investigation")
        
        # 1. Load and Validate Evidence
        ExecutionLogger.log(ctx, "INFO", "Loading workflow variables")
        
        def get_evidence(var_name: str, default: Any) -> Any:
            val = config.get(var_name)
            if val is None or (isinstance(val, str) and val.startswith("${")):
                val = ctx.get_variable(var_name)
            return val if val is not None else default

        protocols = get_evidence("protocols", [])
        dns_queries = get_evidence("dns_queries", [])
        http_hosts = get_evidence("http_hosts", [])
        tls_sessions = get_evidence("tls_sessions", [])
        conversations = get_evidence("conversations", [])
        endpoints = get_evidence("endpoints", [])
        statistics = get_evidence("statistics", {})
        services = get_evidence("services", [])
        open_ports = get_evidence("open_ports", [])
        scan_results = get_evidence("scan_results", {})
        
        # Validation and type normalization
        if not isinstance(protocols, list): protocols = []
        if not isinstance(dns_queries, list): dns_queries = []
        if not isinstance(http_hosts, list): http_hosts = []
        if not isinstance(tls_sessions, list): tls_sessions = []
        if not isinstance(conversations, list): conversations = []
        if not isinstance(endpoints, list): endpoints = []
        if not isinstance(statistics, dict): statistics = {}
        if not isinstance(services, list): services = []
        if not isinstance(open_ports, list): open_ports = []
        if not isinstance(scan_results, dict): scan_results = {}
        
        # Clean lists (ensure string types, remove placeholders)
        protocols = [str(x) for x in protocols if not (isinstance(x, str) and x.startswith("${"))]
        dns_queries = [str(x) for x in dns_queries if not (isinstance(x, str) and x.startswith("${"))]
        http_hosts = [str(x) for x in http_hosts if not (isinstance(x, str) and x.startswith("${"))]
        tls_sessions = [str(x) for x in tls_sessions if not (isinstance(x, str) and x.startswith("${"))]
        conversations = [str(x) for x in conversations if not (isinstance(x, str) and x.startswith("${"))]
        endpoints = [str(x) for x in endpoints if not (isinstance(x, str) and x.startswith("${"))]
        
        clean_ports = []
        for p in open_ports:
            try:
                if not (isinstance(p, str) and p.startswith("${")):
                    clean_ports.append(int(p))
            except (ValueError, TypeError):
                pass
        open_ports = clean_ports
        
        # 2. Correlate Evidence (Rule-based)
        ExecutionLogger.log(ctx, "INFO", "Correlating evidence")
        findings = []
        recommendations = []
        risk_score = 10  # Baseline risk
        
        # Rule 1: SMB (445) exposed
        has_smb_port = 445 in open_ports or any(s.get("port") == 445 for s in services)
        has_smb_proto = any("smb" in p.lower() or "microsoft-ds" in p.lower() for p in protocols)
        if has_smb_port or has_smb_proto:
            findings.append({
                "title": "Exposed SMB Service (Port 445)",
                "severity": "Critical",
                "confidence": 95,
                "evidence": [
                    f"Port 445 is open in scan results" if has_smb_port else "",
                    f"SMB protocol detected in traffic: {protocols}" if has_smb_proto else ""
                ],
                "description": "Server Message Block (SMB) protocol is exposed to the network. This is a high-risk service frequently targeted for lateral movement, credential harvesting (e.g., via NTLM relaying), and exploit execution (e.g., EternalBlue)."
            })
            recommendations.extend([
                "Block external access to Port 445 (SMB) immediately.",
                "Ensure SMBv1 is disabled and require SMB signing on internal networks.",
                "Isolate systems exposing SMB services if they cannot be patched."
            ])
            risk_score += 40
            
        # Rule 2: MySQL/PostgreSQL exposed
        db_ports = [3306, 5432]
        exposed_dbs = []
        for p in db_ports:
            if p in open_ports or any(s.get("port") == p for s in services):
                exposed_dbs.append(p)
        db_service_names = ["mysql", "postgresql", "postgres"]
        for s in services:
            if str(s.get("service")).lower() in db_service_names:
                exposed_dbs.append(s.get("port") or "unknown")
                
        if exposed_dbs:
            findings.append({
                "title": "Exposed Database Service",
                "severity": "High",
                "confidence": 90,
                "evidence": [f"Database port/service detected: {list(set(exposed_dbs))}"],
                "description": "An unauthenticated or network-exposed database service (MySQL or PostgreSQL) was detected. Exposing databases directly to the network increases the risk of brute-force attacks, credential theft, and unauthorized data access."
            })
            recommendations.extend([
                "Restrict database ports (3306/5432) to trusted hosts or localhost only.",
                "Enforce multi-factor authentication (MFA) or strong password policies for all database accounts.",
                "Encrypt database connections using TLS/SSL."
            ])
            risk_score += 30

        # Rule 3: HTTP traffic without encryption
        has_http_proto = any(p.strip().upper() == "HTTP" for p in protocols)
        has_http_hosts = len(http_hosts) > 0
        has_http_port = 80 in open_ports or any(s.get("port") == 80 or "http" == str(s.get("service")).lower() for s in services)
        if has_http_proto or has_http_hosts or has_http_port:
            findings.append({
                "title": "Unencrypted HTTP Communication",
                "severity": "Medium",
                "confidence": 85,
                "evidence": [
                    "HTTP protocol detected in traffic." if has_http_proto else "",
                    f"HTTP hosts queried: {http_hosts[:5]}" if has_http_hosts else "",
                    "Port 80 is open/HTTP service is active." if has_http_port else ""
                ],
                "description": "Unencrypted HTTP traffic was observed in the network capture. Transmitting sensitive data over unencrypted channels makes it vulnerable to eavesdropping, sniffing, and man-in-the-middle (MitM) attacks."
            })
            recommendations.extend([
                "Enforce HTTPS/TLS (Port 443) across all web assets and client devices.",
                "Implement HTTP Strict Transport Security (HSTS) headers.",
                "Configure automatic HTTP-to-HTTPS redirection rules."
            ])
            risk_score += 15

        # Rule 4: High DNS activity
        dns_count = len(dns_queries) or statistics.get("dns_queries_count", 0)
        if dns_count > 10:
            findings.append({
                "title": "High Volume of DNS Activity",
                "severity": "Medium",
                "confidence": 80,
                "evidence": [f"Detected {dns_count} unique DNS queries (threshold: 10)."],
                "description": "An elevated volume of DNS queries was detected. This pattern is characteristic of DNS reconnaissance, subdomain brute-forcing, or potential DNS-based command and control (C2) / data exfiltration tunneling."
            })
            recommendations.extend([
                "Monitor DNS logs for suspicious patterns like DNS tunneling or rapid subdomain queries.",
                "Configure DNS rate limiting on local nameservers.",
                "Restrict DNS egress traffic to authorized enterprise nameservers only."
            ])
            risk_score += 10

        # Rule 5: Excessive conversations
        conv_count = len(conversations) or statistics.get("conversations_count", 0)
        if conv_count > 20:
            findings.append({
                "title": "Excessive Network Conversations",
                "severity": "Low",
                "confidence": 75,
                "evidence": [f"Detected {conv_count} unique conversations (threshold: 20)."],
                "description": "A large number of unique network conversations was observed. This can indicate scanning activity, peer-to-peer applications, or an overly noisy network environment."
            })
            recommendations.extend([
                "Identify host(s) generating the bulk of the conversations to ensure they are not compromised or running network scanning software.",
                "Implement network segmentation to contain noisy broadcast or scan traffic."
            ])
            risk_score += 5

        # Rule 6: Suspicious endpoint count
        endpoint_count = len(endpoints) or statistics.get("endpoints_count", 0)
        if endpoint_count > 15:
            findings.append({
                "title": "Suspiciously High Endpoint Count",
                "severity": "Low",
                "confidence": 70,
                "evidence": [f"Detected {endpoint_count} unique endpoints (threshold: 15)."],
                "description": "A high number of unique network endpoints (IP addresses) was identified. This could suggest broad network discovery, host sweeping, or a highly distributed set of connections."
            })
            recommendations.extend([
                "Verify if network endpoints are known asset inventory members.",
                "Investigate potential scanning or sweeping behavior from the source hosts."
            ])
            risk_score += 5

        for f in findings:
            f["evidence"] = [ev for ev in f["evidence"] if ev]

        # 3. Calculate Risk Score & Severity
        ExecutionLogger.log(ctx, "INFO", "Calculating risk score")
        risk_score = max(0, min(100, risk_score))
        if risk_score >= 90:
            severity = "Critical"
        elif risk_score >= 70:
            severity = "High"
        elif risk_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        # Unique recommendations (deduped but keeping order)
        seen = set()
        deduped_recommendations = []
        for r in recommendations:
            if r not in seen:
                seen.add(r)
                deduped_recommendations.append(r)
        recommendations = deduped_recommendations
        if not recommendations:
            recommendations = ["Continue monitoring network traffic for deviations from the baseline."]

        # 4. Executive Summary
        ExecutionLogger.log(ctx, "INFO", "Generating executive summary")
        
        status_bullet = "- **Investigation Status**: COMPLETED"
        risk_bullet = f"- **Overall Risk**: {severity.upper()} ({risk_score}/100)"
        
        capture_overview = f"Analyzed traffic containing {statistics.get('total_packets', 0)} packets over {statistics.get('duration_seconds', 0.0)} seconds." if statistics else "Capture statistics unavailable."
        capture_bullet = f"- **Capture Overview**: {capture_overview}"
        
        net_activity = f"Identified {len(protocols)} protocols ({', '.join(protocols[:5])}) across {len(endpoints)} unique endpoints and {len(conversations)} conversations."
        net_bullet = f"- **Network Activity**: {net_activity}"
        
        services_desc = f"Found {len(open_ports)} open TCP ports ({', '.join(map(str, open_ports[:10]))})." if open_ports else "No open services detected."
        services_bullet = f"- **Open Services**: {services_desc}"
        
        if findings:
            findings_desc = f"Triggered {len(findings)} correlation rules: " + ", ".join(f.get('title') for f in findings)
        else:
            findings_desc = "No high-risk findings detected."
        findings_bullet = f"- **Key Findings**: {findings_desc}"
        
        recs_desc = "; ".join(recommendations[:3])
        recs_bullet = f"- **Recommendations**: {recs_desc}"
        
        conclusion = "The network posture is secure." if risk_score < 40 else "Immediate remediation is recommended to secure exposed ports/protocols."
        conclusion_bullet = f"- **Conclusion**: {conclusion}"

        executive_summary = "\n".join([
            status_bullet,
            risk_bullet,
            capture_bullet,
            net_bullet,
            services_bullet,
            findings_bullet,
            recs_bullet,
            conclusion_bullet
        ])

        # IoC Candidates
        ioc_candidates = sorted(list(set(dns_queries + http_hosts + tls_sessions)))

        # 5. Publish Variables
        ExecutionLogger.log(ctx, "INFO", "Publishing variables")
        ctx.set_variable("risk_score", risk_score, "number")
        ctx.set_variable("severity", severity, "string")
        ctx.set_variable("findings", findings, "array")
        ctx.set_variable("recommendations", recommendations, "array")
        ctx.set_variable("executive_summary", executive_summary, "string")
        ctx.set_variable("ioc_candidates", ioc_candidates, "array")
        
        ai_investigation_data = {
            "risk_score": risk_score,
            "severity": severity,
            "findings": findings,
            "recommendations": recommendations,
            "executive_summary": executive_summary,
            "ioc_candidates": ioc_candidates
        }
        ctx.set_variable("ai_investigation", ai_investigation_data, "object")

        # 6. Create Artifact
        ExecutionLogger.log(ctx, "INFO", "Creating artifact")
        
        capture_file = None
        if ctx.has_variable("capture_file"):
            capture_file = ctx.get_variable("capture_file")
        if not capture_file:
            capture_file = step.get("config", {}).get("capture_file")
            
        capture_id = "default"
        if capture_file and isinstance(capture_file, str):
            capture_id = os.path.splitext(os.path.basename(capture_file))[0]
            if capture_id.startswith("file:///"):
                capture_id = capture_id[8:]
            elif capture_id.startswith("file://"):
                capture_id = capture_id[7:]
            capture_id = os.path.splitext(os.path.basename(capture_id))[0]
            
        if not capture_id or not isinstance(capture_id, str):
            capture_id = "default"

        artifact_dir = None
        if capture_file and isinstance(capture_file, str):
            try:
                cf_path = capture_file
                if cf_path.startswith("file:///"): cf_path = cf_path[8:]
                elif cf_path.startswith("file://"): cf_path = cf_path[7:]
                artifact_dir = os.path.dirname(cf_path)
            except Exception:
                pass
        if not artifact_dir or not os.path.exists(artifact_dir):
            artifact_dir = os.path.join(os.getcwd(), "Captured_packets")
        if not os.path.exists(artifact_dir):
            os.makedirs(artifact_dir, exist_ok=True)
            
        artifact_path = os.path.join(artifact_dir, f"investigation_{capture_id}.md")

        findings_md = ""
        for i, f in enumerate(findings):
            findings_md += f"### {i+1}. {f['title']} ({f['severity']})\n"
            findings_md += f"- **Confidence**: {f['confidence']}%\n"
            findings_md += f"- **Description**: {f['description']}\n"
            if f.get("evidence"):
                findings_md += "- **Evidence**:\n"
                for ev in f["evidence"]:
                    findings_md += f"  - {ev}\n"
            findings_md += "\n"
        if not findings_md:
            findings_md = "*No high-risk findings identified.*\n"

        evidence_md = ""
        if dns_queries:
            evidence_md += "### DNS Queries\n"
            evidence_md += "\n".join(f"- `{q}`" for q in dns_queries[:20]) + "\n"
            if len(dns_queries) > 20:
                evidence_md += f"- *... and {len(dns_queries) - 20} more DNS queries.*\n"
        if http_hosts:
            evidence_md += "### HTTP Hosts\n"
            evidence_md += "\n".join(f"- `{h}`" for h in http_hosts[:20]) + "\n"
            if len(http_hosts) > 20:
                evidence_md += f"- *... and {len(http_hosts) - 20} more HTTP hosts.*\n"
        if not evidence_md:
            evidence_md = "*No indicators or trace evidence collected.*\n"

        statistics_md = ""
        if statistics:
            for k, v in statistics.items():
                name_pretty = k.replace("_", " ").title()
                statistics_md += f"- **{name_pretty}**: {v}\n"
        else:
            statistics_md = "*No statistics available.*\n"

        ports_services_md = ""
        if open_ports or services:
            ports_services_md += "| Port | Service | State |\n|---|---|---|\n"
            for s in services:
                ports_services_md += f"| {s.get('port')} | {s.get('service')} | {s.get('state')} |\n"
            for p in open_ports:
                if not any(s.get("port") == p for s in services):
                    ports_services_md += f"| {p} | Unknown | open |\n"
        else:
            ports_services_md = "*No open ports or services detected.*\n"

        recommendations_md = "\n".join(f"- {r}" for r in recommendations)

        timeline_md = ""
        for event in ctx.timelineEvents:
            timeline_md += f"- **[{event.get('timestamp')}] {event.get('title')}**: {event.get('description')}\n"

        md_content = f"""# AI Investigation Report

## Executive Summary
{executive_summary}

## Risk Score & Severity
- **Risk Score**: {risk_score} / 100
- **Severity**: {severity}

## Findings
{findings_md}

## Evidence
{evidence_md}

## Network Statistics
{statistics_md}

## Open Ports & Services
{ports_services_md}

## Recommendations
{recommendations_md}

## Investigation Timeline
{timeline_md}
"""

        with open(artifact_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        artifact = WorkflowArtifact(
            name="AI_Investigation_Report.md",
            type="markdown",
            mimeType="text/markdown",
            producerExecutor=self.__class__.__name__,
            stepId=step_id,
            location=artifact_path,
            metadata={
                "capture_id": capture_id,
                "risk_score": risk_score,
                "severity": severity,
                "findings_count": len(findings)
            },
        )
        ctx.add_artifact(artifact)

        output = {
            "risk_score": risk_score,
            "severity": severity,
            "findings": findings,
            "recommendations": recommendations,
            "executive_summary": executive_summary,
            "ioc_candidates": ioc_candidates,
            "artifactId": artifact.artifactId
        }
        ctx.set_step_output(step_id, output)

        self.create_timeline_event(ctx, "AI Investigation Completed", f"AI Investigation completed with risk score {risk_score} ({severity}).")
        ExecutionLogger.log(ctx, "INFO", "Investigation completed")

        return {
            "success": True,
            "output": output,
            "summary": f"AI Investigation completed. Risk score: {risk_score} ({severity}).",
            "duration": 0.0
        }


# ---------------------------------------------------------------------------
# ReportGeneratorExecutor
# ---------------------------------------------------------------------------

class ReportGeneratorExecutor(StepExecutor):
    identifier = "report_generator"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        title = step.get("title", "").lower()
        desc = step.get("description", "").lower()
        executor_id = step.get("executor") or step.get("executorType")
        
        if executor_id in ("report_generator", "report-generator", "report_generation"):
            return True
            
        return ("generate" in title and "report" in title) or ("generate" in desc and "report" in desc)

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        self.ctx = ctx
        import os
        
        step_id = step.get("stepId") or step.get("id") or "report-generator-step"
        config = step.get("config") or {}
        
        ExecutionLogger.log(ctx, "INFO", "Starting Report Generation")
        ExecutionLogger.log(ctx, "INFO", "Loading workflow variables")
        
        # Resolve from step configuration or context
        def get_evidence(var_name: str, default: Any) -> Any:
            val = config.get(var_name)
            if val is None or (isinstance(val, str) and val.startswith("${")):
                val = ctx.get_variable(var_name)
            return val if val is not None else default

        capture_file = get_evidence("capture_file", None)
        capture_id = get_evidence("capture_id", None)
        if not capture_id or (isinstance(capture_id, str) and capture_id.startswith("${")):
            if capture_file and isinstance(capture_file, str) and not capture_file.startswith("${"):
                c_path = capture_file
                if c_path.startswith("file:///"):
                    c_path = c_path[8:]
                elif c_path.startswith("file://"):
                    c_path = c_path[7:]
                capture_id = os.path.splitext(os.path.basename(c_path))[0]
            else:
                capture_id = None
        if not capture_id or not isinstance(capture_id, str):
            capture_id = "default"

        packet_count = get_evidence("packet_count", None)
        capture_duration = get_evidence("capture_duration", None)
        capture_interface = get_evidence("capture_interface", None)

        statistics = get_evidence("statistics", {})
        protocols = get_evidence("protocols", [])
        endpoints = get_evidence("endpoints", [])
        conversations = get_evidence("conversations", [])
        dns_queries = get_evidence("dns_queries", [])
        http_hosts = get_evidence("http_hosts", [])
        tls_sessions = get_evidence("tls_sessions", [])
        analysis_summary = get_evidence("analysis_summary", "")

        host = get_evidence("host", "")
        target = get_evidence("target", "")
        services = get_evidence("services", [])
        open_ports = get_evidence("open_ports", [])
        scan_results = get_evidence("scan_results", {})

        risk_score = get_evidence("risk_score", None)
        severity = get_evidence("severity", None)
        findings = get_evidence("findings", [])
        recommendations = get_evidence("recommendations", [])
        executive_summary = get_evidence("executive_summary", "")
        ioc_candidates = get_evidence("ioc_candidates", [])
        ai_investigation = get_evidence("ai_investigation", {})

        # Graceful fallbacks and type cleanups
        def clean_str(val: Any) -> str:
            if val is None or (isinstance(val, str) and val.startswith("${")):
                return ""
            return str(val)

        def clean_list(val: Any) -> list:
            if not isinstance(val, list):
                return []
            return [x for x in val if not (isinstance(x, str) and x.startswith("${"))]

        def clean_dict(val: Any) -> dict:
            if not isinstance(val, dict):
                return {}
            return val

        capture_file = clean_str(capture_file)
        capture_interface = clean_str(capture_interface)
        analysis_summary = clean_str(analysis_summary)
        host = clean_str(host)
        target = clean_str(target)
        severity = clean_str(severity)
        executive_summary = clean_str(executive_summary)

        protocols = clean_list(protocols)
        endpoints = clean_list(endpoints)
        conversations = clean_list(conversations)
        dns_queries = clean_list(dns_queries)
        http_hosts = clean_list(http_hosts)
        tls_sessions = clean_list(tls_sessions)
        services = clean_list(services)
        open_ports = clean_list(open_ports)
        findings = clean_list(findings)
        recommendations = clean_list(recommendations)
        ioc_candidates = clean_list(ioc_candidates)

        statistics = clean_dict(statistics)
        scan_results = clean_dict(scan_results)
        ai_investigation = clean_dict(ai_investigation)

        # Normalize number fields safely
        try:
            if packet_count is not None and not (isinstance(packet_count, str) and packet_count.startswith("${")):
                packet_count = int(packet_count)
            else:
                packet_count = None
        except (ValueError, TypeError):
            packet_count = None

        try:
            if capture_duration is not None and not (isinstance(capture_duration, str) and capture_duration.startswith("${")):
                capture_duration = float(capture_duration)
            else:
                capture_duration = None
        except (ValueError, TypeError):
            capture_duration = None

        try:
            if risk_score is not None and not (isinstance(risk_score, str) and risk_score.startswith("${")):
                risk_score = float(risk_score)
            else:
                risk_score = None
        except (ValueError, TypeError):
            risk_score = None

        # Fallbacks to ai_investigation dict if direct variables were skipped
        if risk_score is None:
            if ai_investigation and "risk_score" in ai_investigation:
                try:
                    risk_score = float(ai_investigation["risk_score"])
                except (ValueError, TypeError):
                    pass
        if risk_score is None:
            risk_score = 0.0

        if not severity:
            if ai_investigation and "severity" in ai_investigation:
                severity = str(ai_investigation["severity"])
        if not severity:
            severity = "Unknown"

        if not findings:
            if ai_investigation and "findings" in ai_investigation:
                findings = ai_investigation["findings"]
        if not findings:
            findings = []

        if not recommendations:
            if ai_investigation and "recommendations" in ai_investigation:
                recommendations = ai_investigation["recommendations"]
        if not recommendations:
            recommendations = []

        if not executive_summary:
            if ai_investigation and "executive_summary" in ai_investigation:
                executive_summary = str(ai_investigation["executive_summary"])

        if not ioc_candidates:
            if ai_investigation and "ioc_candidates" in ai_investigation:
                ioc_candidates = ai_investigation["ioc_candidates"]
        if not ioc_candidates:
            # Fallback compile from evidence
            ioc_candidates = sorted(list(set(dns_queries + http_hosts + tls_sessions)))

        # Build report sections
        ExecutionLogger.log(ctx, "INFO", "Building Executive Summary")
        exec_summary_md = ""
        if executive_summary:
            lines = [l.strip() for l in executive_summary.split("\n") if l.strip()]
            formatted_lines = []
            for line in lines:
                if line.startswith("-") or line.startswith("*"):
                    formatted_lines.append(line)
                else:
                    formatted_lines.append(f"- {line}")
            exec_summary_md = "\n".join(formatted_lines)
        else:
            bullets = [
                "Investigation completed successfully",
                f"Overall Risk: {severity}",
                f"{len(open_ports)} open ports identified",
                "Recommended remediation included below"
            ]
            exec_summary_md = "\n".join(f"- {b}" for b in bullets)

        ExecutionLogger.log(ctx, "INFO", "Building Risk Assessment")

        ExecutionLogger.log(ctx, "INFO", "Building Network Statistics")
        total_packets_val = packet_count if packet_count is not None else statistics.get("total_packets", statistics.get("packet_count", "N/A"))
        protocol_count = len(protocols) if protocols else statistics.get("protocol_count", 0)
        endpoint_count = len(endpoints) if endpoints else statistics.get("endpoint_count", 0)
        dns_queries_count = len(dns_queries) if dns_queries else statistics.get("dns_queries_count", 0)
        http_hosts_count = len(http_hosts) if http_hosts else statistics.get("http_hosts_count", 0)
        tls_sessions_count = len(tls_sessions) if tls_sessions else statistics.get("tls_sessions_count", 0)
        conversations_count = len(conversations) if conversations else statistics.get("conversations_count", 0)

        # Build services table
        services_table = "| Port | Service | State |\n|---|---|---|\n"
        if services or open_ports:
            displayed_ports = set()
            for s in services:
                port = s.get("port")
                service_name = s.get("service") or "Unknown"
                state = s.get("state") or "open"
                services_table += f"| {port} | {service_name} | {state} |\n"
                displayed_ports.add(port)
            for p in open_ports:
                if p not in displayed_ports:
                    services_table += f"| {p} | Unknown | open |\n"
        else:
            services_table += "| - | No open services detected | - |\n"

        ExecutionLogger.log(ctx, "INFO", "Building Findings")
        findings_md = ""
        if findings:
            for idx, f in enumerate(findings, 1):
                title_str = f.get("title") or "Unnamed Finding"
                sev_str = f.get("severity") or "Low"
                conf_str = f.get("confidence") or "N/A"
                desc_str = f.get("description") or "No description provided."
                evidence_list = f.get("evidence") or []
                
                findings_md += f"### {title_str}\n"
                findings_md += f"- **Severity**: {sev_str}\n"
                findings_md += f"- **Confidence**: {conf_str}%\n" if conf_str != "N/A" else "- **Confidence**: N/A\n"
                findings_md += f"- **Description**: {desc_str}\n"
                if evidence_list:
                    findings_md += "- **Evidence**:\n"
                    for ev in evidence_list:
                        findings_md += f"  - {ev}\n"
                findings_md += "\n"
        else:
            findings_md = "No findings identified.\n"

        ExecutionLogger.log(ctx, "INFO", "Building Recommendations")
        recs_md = ""
        if recommendations:
            for idx, r in enumerate(recommendations, 1):
                recs_md += f"{idx}. {r}\n"
        else:
            recs_md = "1. Continue monitoring network traffic for anomalies.\n"

        # Resolve File Size
        file_size_str = "N/A"
        if capture_file and os.path.exists(capture_file):
            try:
                size_bytes = os.path.getsize(capture_file)
                if size_bytes > 1024 * 1024:
                    file_size_str = f"{size_bytes / (1024 * 1024):.2f} MB ({size_bytes} bytes)"
                else:
                    file_size_str = f"{size_bytes / 1024:.2f} KB ({size_bytes} bytes)"
            except Exception:
                pass
        if file_size_str == "N/A" and statistics and "file_size" in statistics:
            file_size_str = str(statistics["file_size"])

        # Categorize IOC Candidates
        ips = []
        domains = []
        hosts = []
        endpoints_ioc = []
        
        import re
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        for candidate in ioc_candidates:
            cand_str = str(candidate).strip()
            if not cand_str:
                continue
            if ip_pattern.match(cand_str):
                ips.append(cand_str)
            elif "." in cand_str:
                domains.append(cand_str)
            else:
                hosts.append(cand_str)
        
        for ep in endpoints:
            ep_str = str(ep).strip()
            if ep_str and ep_str not in ips and ep_str not in endpoints_ioc:
                endpoints_ioc.append(ep_str)

        ips_list = "\n".join(f"- {ip}" for ip in ips) if ips else "None identified."
        domains_list = "\n".join(f"- {d}" for d in domains) if domains else "None identified."
        hosts_list = "\n".join(f"- {h}" for h in hosts) if hosts else "None identified."
        endpoints_list = "\n".join(f"- {ep}" for ep in endpoints_ioc) if endpoints_ioc else "None identified."

        # Compile report
        report_time = datetime.utcnow().isoformat() + "Z"
        
        report_md = f"# NetFusion Investigation Report\n\n"
        report_md += f"- **Report Title**: NetFusion Investigation Report\n"
        report_md += f"- **Investigation ID**: {ctx.execution_id}\n"
        report_md += f"- **Capture ID**: {capture_id}\n"
        report_md += f"- **Report Generated Time**: {report_time}\n"
        report_md += f"- **Workflow Name**: {ctx.playbook_name}\n"
        report_md += f"- **Investigation Status**: {ctx.status}\n\n"

        report_md += f"## Executive Summary\n\n"
        report_md += f"{exec_summary_md}\n\n"

        report_md += f"## Risk Assessment\n\n"
        report_md += f"- **Risk Score**: {risk_score}\n"
        report_md += f"- **Severity**: {severity}\n"
        report_md += f"- **Total Findings**: {len(findings)}\n"
        report_md += f"- **Total Recommendations**: {len(recommendations)}\n\n"

        report_md += f"## Capture Overview\n\n"
        report_md += f"- **Packet Count**: {packet_count if packet_count is not None else 'N/A'}\n"
        report_md += f"- **Capture Duration**: {f'{capture_duration} seconds' if capture_duration is not None else 'N/A'}\n"
        report_md += f"- **Capture File**: {capture_file or 'N/A'}\n"
        report_md += f"- **Interface**: {capture_interface or 'N/A'}\n"
        report_md += f"- **File Size**: {file_size_str}\n\n"

        report_md += f"## Network Statistics\n\n"
        report_md += f"- **Total Packets**: {total_packets_val}\n"
        report_md += f"- **Protocol Count**: {protocol_count}\n"
        report_md += f"- **Endpoint Count**: {endpoint_count}\n"
        report_md += f"- **DNS Queries**: {dns_queries_count}\n"
        report_md += f"- **HTTP Hosts**: {http_hosts_count}\n"
        report_md += f"- **TLS Sessions**: {tls_sessions_count}\n"
        report_md += f"- **Conversations**: {conversations_count}\n\n"

        report_md += f"## Open Services\n\n"
        report_md += f"{services_table}\n"

        report_md += f"## Network Protocols\n\n"
        if protocols:
            report_md += "\n".join(f"- {p}" for p in protocols) + "\n\n"
        else:
            report_md += "No network protocols discovered.\n\n"

        report_md += f"## DNS Activity\n\n"
        if dns_queries:
            report_md += "\n".join(f"- {q}" for q in dns_queries) + "\n\n"
        else:
            report_md += "No DNS activity discovered.\n\n"

        report_md += f"## HTTP Hosts\n\n"
        if http_hosts:
            report_md += "\n".join(f"- {h}" for h in http_hosts) + "\n\n"
        else:
            report_md += "No HTTP hosts discovered.\n\n"

        report_md += f"## TLS Sessions\n\n"
        if tls_sessions:
            report_md += "\n".join(f"- {t}" for t in tls_sessions) + "\n\n"
        else:
            report_md += "No TLS server names discovered.\n\n"

        report_md += f"## Key Findings\n\n"
        report_md += f"{findings_md}\n"

        report_md += f"## Recommendations\n\n"
        report_md += f"{recs_md}\n"

        report_md += f"## IOC Candidates\n\n"
        report_md += f"### IP Addresses\n"
        report_md += f"{ips_list}\n\n"
        report_md += f"### Domains\n"
        report_md += f"{domains_list}\n\n"
        report_md += f"### Hosts\n"
        report_md += f"{hosts_list}\n\n"
        report_md += f"### Suspicious Endpoints\n"
        report_md += f"{endpoints_list}\n\n"

        report_md += f"## Investigation Timeline\n\n"
        report_md += "Packet Capture\n\n"
        report_md += "↓\n\n"
        report_md += "PCAP Analysis\n\n"
        report_md += "↓\n\n"
        report_md += "Nmap Scan\n\n"
        report_md += "↓\n\n"
        report_md += "AI Investigation\n\n"
        report_md += "↓\n\n"
        report_md += "Report Generated\n\n"

        report_md += f"## Conclusion\n\n"
        report_md += f"The investigation workflow has successfully run to completion. "
        report_md += f"Based on the analysis, a threat score of {risk_score} / 100 ({severity}) was determined. "
        if findings:
            report_md += f"A total of {len(findings)} key findings were identified, indicating some level of exposure or security risk. "
        else:
            report_md += "No high-risk findings were detected during the analysis. "
        report_md += f"Remediation recommendations have been compiled to guide the response team in securing the environment."

        ExecutionLogger.log(ctx, "INFO", "Writing Markdown report")
        
        artifact_dir = None
        if capture_file and isinstance(capture_file, str):
            try:
                cf_path = capture_file
                if cf_path.startswith("file:///"): cf_path = cf_path[8:]
                elif cf_path.startswith("file://"): cf_path = cf_path[7:]
                artifact_dir = os.path.dirname(cf_path)
            except Exception:
                pass
        if not artifact_dir or not os.path.exists(artifact_dir):
            artifact_dir = os.path.join(os.getcwd(), "Captured_packets")
        if not os.path.exists(artifact_dir):
            os.makedirs(artifact_dir, exist_ok=True)
            
        artifact_path = os.path.abspath(os.path.join(artifact_dir, f"report_{capture_id}.md"))
        
        with open(artifact_path, "w", encoding="utf-8") as f_out:
            f_out.write(report_md)

        ExecutionLogger.log(ctx, "INFO", "Registering artifact")
        
        artifact = WorkflowArtifact(
            name="AI_Investigation_Report.md",
            type="markdown",
            mimeType="text/markdown",
            producerExecutor=self.__class__.__name__,
            stepId=step_id,
            executionId=ctx.execution_id,
            location=artifact_path,
            metadata={
                "executor": self.__class__.__name__,
                "capture_id": capture_id,
                "report_time": report_time,
                "risk_score": risk_score,
                "severity": severity,
                "findings_count": len(findings)
            },
        )
        ctx.add_artifact(artifact)

        ExecutionLogger.log(ctx, "INFO", "Publishing report variables")
        
        ctx.set_variable("report_file", artifact_path, "file")
        ctx.set_variable("report_generated_at", report_time, "string")
        ctx.set_variable("report_summary", executive_summary or f"Investigation report generated with risk score {risk_score} ({severity}).", "string")
        ctx.set_variable("report_artifact", artifact.to_dict(), "object")

        # Structured output
        output = {
            "report_file": artifact_path,
            "report_generated_at": report_time,
            "report_summary": executive_summary or f"Investigation report generated with risk score {risk_score} ({severity}).",
            "artifactId": artifact.artifactId
        }
        ctx.set_step_output(step_id, output)
        
        ExecutionLogger.log(ctx, "INFO", "Report Generation completed successfully")
        
        return {
            "success": True,
            "output": output,
            "summary": f"Report Generation completed successfully. Created report_{capture_id}.md.",
            "duration": 0.0
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class StepExecutorRegistry:
    def __init__(self):
        self._executors_by_id: Dict[str, StepExecutor] = {}
        self._executors: List[StepExecutor] = []

    def register(self, executor: StepExecutor) -> None:
        if executor.identifier:
            self._executors_by_id[executor.identifier] = executor
        self._executors.append(executor)

    def resolve(self, step: Dict[str, Any]) -> Optional[StepExecutor]:
        title = step.get("title", "").lower()
        step_id = step.get("stepId") or step.get("id") or ""
        if ("generate" in title and "report" in title) or "generate-report" in str(step_id).lower():
            if "report_generator" in self._executors_by_id:
                return self._executors_by_id["report_generator"]

        executor_id = step.get("executor") or step.get("executorType")
        if executor_id:
            if executor_id in ("report_generator", "report-generator", "report_generation"):
                executor_id = "report_generator"
            if executor_id in self._executors_by_id:
                return self._executors_by_id[executor_id]
            else:
                return None

        # Legacy fallback
        for executor in self._executors:
            if executor.can_execute(step):
                return executor
        return None


_REGISTRY = StepExecutorRegistry()
_REGISTRY.register(ManualExecutor())
_REGISTRY.register(NmapExecutor())
_REGISTRY.register(PCAPAnalysisExecutor())
_REGISTRY.register(PacketCaptureExecutor())
_REGISTRY.register(AIInvestigationExecutor())
_REGISTRY.register(ReportGeneratorExecutor())


# ---------------------------------------------------------------------------
# StepRunner
# ---------------------------------------------------------------------------

# Variable Resolver
# ---------------------------------------------------------------------------

def resolve_variables(val: Any, ctx: WorkflowExecutionContext) -> Any:
    """
    Recursively resolve variable bindings of format ${variable_name} inside val.
    - If val equals ${variable_name} exactly, replaces with the raw stored value (preserving type).
    - If val contains ${variable_name} as a substring, replaces with stringified stored value.
    - Dicts and Lists are traversed recursively.
    """
    if isinstance(val, dict):
        return {k: resolve_variables(v, ctx) for k, v in val.items()}
    elif isinstance(val, list):
        return [resolve_variables(item, ctx) for item in val]
    elif isinstance(val, str):
        # 1. Exact match: ${variable_name} -> raw value (maintaining type)
        match = re.fullmatch(r"\$\{([^}]+)\}", val)
        if match:
            var_name = match.group(1)
            if ctx.has_variable(var_name):
                return ctx.get_variable(var_name)
            return val
        
        # 2. Substring interpolation: ...${variable_name}... -> substitute stringified
        def replace_match(m):
            var_name = m.group(1)
            if ctx.has_variable(var_name):
                resolved = ctx.get_variable(var_name)
                if isinstance(resolved, (dict, list)):
                    import json
                    return json.dumps(resolved)
                return str(resolved)
            return m.group(0)
            
        return re.sub(r"\$\{([^}]+)\}", replace_match, val)
        
    return val


# ---------------------------------------------------------------------------
# StepRunner
# ---------------------------------------------------------------------------

class StepRunner:
    @staticmethod
    def run_step(ctx: WorkflowExecutionContext, step: Dict[str, Any], index: int) -> Dict[str, Any]:
        step_id = step.get("stepId") or step.get("id") or f"step-{index + 1}"
        step_number = step.get("stepNumber") or (index + 1)
        step_title = step.get("title") or f"Step {step_number}"
        step_type = step.get("stepType") or "MANUAL"

        ctx.current_step = step_title
        ctx.current_step_number = step_number
        update_execution_record(ctx)

        ExecutionLogger.log(ctx, "INFO",
            f"[{step_number}/{ctx.total_steps}] Starting step: {step_title} (type={step_type})")

        import copy
        resolved_step = copy.deepcopy(step)
        resolved_step = resolve_variables(resolved_step, ctx)

        # Trace executor selection for each workflow step. Log every executor's can_execute() result.
        ExecutionLogger.log(ctx, "INFO", f"[TRACE] Resolving executor for step '{step_title}'")
        for exec_obj in _REGISTRY._executors:
            try:
                can_exec = exec_obj.can_execute(resolved_step)
                ExecutionLogger.log(ctx, "INFO", f"[TRACE] Executor '{exec_obj.__class__.__name__}' (identifier={exec_obj.identifier}) can_execute: {can_exec}")
            except Exception as e:
                ExecutionLogger.log(ctx, "INFO", f"[TRACE] Executor '{exec_obj.__class__.__name__}' (identifier={exec_obj.identifier}) can_execute error: {e}")

        executor = _REGISTRY.resolve(resolved_step)
        if not executor:
            error_msg = f"Unknown or missing executor: '{resolved_step.get('executor', 'unknown')}'"
            ExecutionLogger.log(ctx, "WARN", error_msg)
            
            # create timeline event manually
            event_title = f"Step Failed: {step_title}"
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "title": event_title,
                "description": error_msg,
            }
            ctx.timelineEvents.append(event)
            if ctx.project_id:
                try:
                    from api.persistence import call_repository, map_timeline_event
                    event_payload = {
                        "projectId": ctx.project_id,
                        "investigationId": ctx.project_id,
                        "title": event_title,
                        "description": error_msg,
                        "type": "MANUAL_ACTION",
                        "createdBy": "system",
                        "updatedBy": "system",
                    }
                    mapped = map_timeline_event(event_payload)
                    event_payload.update(mapped)
                    call_repository("timelineEvent", "create", {"data": event_payload})
                except Exception as err:
                    safe_err = str(err).encode('ascii', errors='replace').decode('ascii')
                    print(f"Failed to log timeline event: {safe_err}")

            step_result = {
                "stepId": step_id,
                "stepNumber": step_number,
                "title": step_title,
                "stepType": step_type,
                "status": "FAILED",
                "executedAt": datetime.utcnow().isoformat() + "Z",
                "outputs": {},
                "summary": error_msg,
                "duration": 0.0,
            }
            return step_result

        result = executor.execute(resolved_step, ctx)

        # Also store output in stepOutputs if executor didn't do it already
        if "output" in result and step_id not in ctx.stepOutputs:
            ctx.set_step_output(step_id, result["output"])

        step_result = {
            "stepId": step_id,
            "stepNumber": step_number,
            "title": step_title,
            "stepType": step_type,
            "status": "EXECUTED" if result.get("success", False) else "FAILED",
            "executedAt": datetime.utcnow().isoformat() + "Z",
            "outputs": result.get("output", {}),
            "summary": result.get("summary", ""),
            "duration": result.get("duration", 0.0),
        }

        return step_result


# ---------------------------------------------------------------------------
# WorkflowExecutionManager
# ---------------------------------------------------------------------------

class WorkflowExecutionManager:
    @staticmethod
    def create_execution(playbook_id: str) -> Optional[WorkflowExecutionContext]:
        raw_pb = _PLAYBOOK_STORE.get(playbook_id)
        if not raw_pb:
            all_pbs = [normalize_playbook(p) for p in _PLAYBOOK_STORE.values()]
            for p in all_pbs:
                if (p["playbookId"].lower() == playbook_id.strip().lower()
                        or p["name"].lower() == playbook_id.strip().lower()):
                    raw_pb = p
                    break

        if not raw_pb:
            return None

        pb = normalize_playbook(raw_pb)
        steps = pb.get("steps") or []
        execution_id = str(uuid.uuid4())

        ctx = WorkflowExecutionContext(
            execution_id=execution_id,
            playbook_id=pb["playbookId"],
            playbook_name=pb["name"],
            steps=steps,
            total_steps=len(steps),
            project_id=pb.get("projectId"),
        )

        initial_record = {
            "executionId": execution_id,
            "playbookId": pb["playbookId"],
            "status": "QUEUED",
            "progress": 0,
            "logs": [],
            "startedAt": ctx.started_at,
            "finishedAt": None,
            "triggeredBy": "manual",
            "totalSteps": ctx.total_steps,
            "completedSteps": 0,
            "failedSteps": 0,
            "currentStep": None,
            "stepResults": [],
        }
        _EXECUTION_STORE.create(initial_record)

        ExecutionLogger.log(ctx, "INFO",
            f"Execution queued for playbook '{pb['name']}' ({ctx.total_steps} step(s)).")
        return ctx

    @staticmethod
    def run_execution_background(ctx: WorkflowExecutionContext) -> None:
        try:
            # Timeline: Execution Started
            event_title = f"Execution Started: {ctx.playbook_name}"
            event_desc = f"Playbook '{ctx.playbook_name}' execution has started."
            ctx.timelineEvents.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "title": event_title,
                "description": event_desc,
            })
            if ctx.project_id:
                try:
                    from api.persistence import call_repository, map_timeline_event
                    ev = {"projectId": ctx.project_id, "investigationId": ctx.project_id,
                          "title": event_title, "description": event_desc,
                          "type": "MANUAL_ACTION", "createdBy": "system", "updatedBy": "system"}
                    ev.update(map_timeline_event(ev))
                    call_repository("timelineEvent", "create", {"data": ev})
                except Exception as err:
                    print("Failed to log timeline event:", str(err).encode('ascii', errors='replace').decode('ascii'))

            StateMachine.transition(ctx, "RUNNING")

            for i, step in enumerate(ctx.steps):
                result = StepRunner.run_step(ctx, step, i)

                if result.get("status") == "FAILED":
                    ctx.failed_steps += 1
                    ctx.set_step_output(result["stepId"], result)

                    ev_title = f"Execution Finished (FAILED): {ctx.playbook_name}"
                    ev_desc = f"Playbook '{ctx.playbook_name}' failed at step '{step.get('title')}'."
                    ctx.timelineEvents.append({
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "title": ev_title, "description": ev_desc,
                    })
                    update_execution_record(ctx)
                    StateMachine.transition(ctx, "FAILED")
                    return

                ctx.completed_steps += 1
                ctx.set_step_output(result["stepId"], result)
                ctx.progress = int(
                    (ctx.completed_steps / ctx.total_steps) * 100
                ) if ctx.total_steps > 0 else 100
                update_execution_record(ctx)

                ExecutionLogger.log(ctx, "INFO",
                    f"[{i + 1}/{ctx.total_steps}] Completed: {step.get('title')} (progress={ctx.progress}%)")

            ctx.current_step = None

            # Timeline: Execution Finished
            ev_title = f"Execution Finished (COMPLETED): {ctx.playbook_name}"
            ev_desc = (f"Playbook '{ctx.playbook_name}' finished successfully. "
                       f"All {ctx.total_steps} steps completed.")
            ctx.timelineEvents.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "title": ev_title, "description": ev_desc,
            })
            if ctx.project_id:
                try:
                    from api.persistence import call_repository, map_timeline_event
                    ev = {"projectId": ctx.project_id, "investigationId": ctx.project_id,
                          "title": ev_title, "description": ev_desc,
                          "type": "MANUAL_ACTION", "createdBy": "system", "updatedBy": "system"}
                    ev.update(map_timeline_event(ev))
                    call_repository("timelineEvent", "create", {"data": ev})
                except Exception as err:
                    print("Failed to log timeline event:", str(err).encode('ascii', errors='replace').decode('ascii'))

            update_execution_record(ctx)
            StateMachine.transition(ctx, "COMPLETED")

        except Exception as err:
            safe_err = str(err).encode('ascii', errors='replace').decode('ascii')
            print(f"Error in execution {ctx.execution_id}: {safe_err}")
            ExecutionLogger.log(ctx, "ERROR", f"Execution failed due to error: {err}")
            StateMachine.transition(ctx, "FAILED")
