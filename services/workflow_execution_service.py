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
            name=f"Nmap Scan - {target}",
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

        # Build typed artifact
        artifact = WorkflowArtifact(
            name=f"PCAP Capture - {interface}",
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
                "location": capture_file,
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
                name=f"PCAP Analysis - {os.path.basename(capture_file)}",
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
                data=md_content
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
        executor_id = step.get("executor") or step.get("executorType")
        if executor_id:
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
