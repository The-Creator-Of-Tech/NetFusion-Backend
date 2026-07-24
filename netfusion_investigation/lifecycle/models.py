"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Models

Domain entities, enums, dataclasses, and data contracts for investigation state,
links, sessions, artifacts, attachments, snapshots, replay steps, difference results,
bookmarks, and activity logging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import uuid


class Priority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvestigationStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"
    LOCKED = "LOCKED"


class ArtifactType(str, Enum):
    REPORT = "REPORT"
    EVIDENCE = "EVIDENCE"
    SCREENSHOT = "SCREENSHOT"
    PCAP = "PCAP"
    JSON = "JSON"
    CSV = "CSV"
    HTML = "HTML"
    PDF = "PDF"
    MARKDOWN = "MARKDOWN"
    ATTACHMENT = "ATTACHMENT"


class ActivityType(str, Enum):
    USER_ACTION = "USER_ACTION"
    AI_ACTION = "AI_ACTION"
    WORKFLOW_ACTION = "WORKFLOW_ACTION"
    EVIDENCE_UPDATE = "EVIDENCE_UPDATE"
    REPORT_GENERATION = "REPORT_GENERATION"
    GRAPH_CHANGE = "GRAPH_CHANGE"
    TIMELINE_EVENT = "TIMELINE_EVENT"
    COMMENT = "COMMENT"


class BookmarkType(str, Enum):
    TIMELINE_EVENT = "TIMELINE_EVENT"
    EVIDENCE = "EVIDENCE"
    GRAPH_NODE = "GRAPH_NODE"
    REASONING_STEP = "REASONING_STEP"
    REPORT = "REPORT"
    RECOMMENDATION = "RECOMMENDATION"


@dataclass
class InvestigationLinks:
    reasoning_session_ids: List[str] = field(default_factory=list)
    reasoning_trace_ids: List[str] = field(default_factory=list)
    timeline_event_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    graph_node_ids: List[str] = field(default_factory=list)
    graph_edge_ids: List[str] = field(default_factory=list)
    report_ids: List[str] = field(default_factory=list)
    workflow_ids: List[str] = field(default_factory=list)
    playbook_ids: List[str] = field(default_factory=list)
    pcap_file_ids: List[str] = field(default_factory=list)
    nmap_scan_ids: List[str] = field(default_factory=list)
    asset_ids: List[str] = field(default_factory=list)
    alert_ids: List[str] = field(default_factory=list)
    recommendation_ids: List[str] = field(default_factory=list)
    memory_keys: List[str] = field(default_factory=list)
    analyst_note_ids: List[str] = field(default_factory=list)
    ioc_values: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reasoning_session_ids": list(self.reasoning_session_ids),
            "reasoning_trace_ids": list(self.reasoning_trace_ids),
            "timeline_event_ids": list(self.timeline_event_ids),
            "evidence_ids": list(self.evidence_ids),
            "graph_node_ids": list(self.graph_node_ids),
            "graph_edge_ids": list(self.graph_edge_ids),
            "report_ids": list(self.report_ids),
            "workflow_ids": list(self.workflow_ids),
            "playbook_ids": list(self.playbook_ids),
            "pcap_file_ids": list(self.pcap_file_ids),
            "nmap_scan_ids": list(self.nmap_scan_ids),
            "asset_ids": list(self.asset_ids),
            "alert_ids": list(self.alert_ids),
            "recommendation_ids": list(self.recommendation_ids),
            "memory_keys": list(self.memory_keys),
            "analyst_note_ids": list(self.analyst_note_ids),
            "ioc_values": list(self.ioc_values),
            "cve_ids": list(self.cve_ids),
            "threat_actors": list(self.threat_actors),
            "campaigns": list(self.campaigns),
            "malware_families": list(self.malware_families),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationLinks":
        if not data:
            return cls()
        return cls(
            reasoning_session_ids=data.get("reasoning_session_ids", []),
            reasoning_trace_ids=data.get("reasoning_trace_ids", []),
            timeline_event_ids=data.get("timeline_event_ids", []),
            evidence_ids=data.get("evidence_ids", []),
            graph_node_ids=data.get("graph_node_ids", []),
            graph_edge_ids=data.get("graph_edge_ids", []),
            report_ids=data.get("report_ids", []),
            workflow_ids=data.get("workflow_ids", []),
            playbook_ids=data.get("playbook_ids", []),
            pcap_file_ids=data.get("pcap_file_ids", []),
            nmap_scan_ids=data.get("nmap_scan_ids", []),
            asset_ids=data.get("asset_ids", []),
            alert_ids=data.get("alert_ids", []),
            recommendation_ids=data.get("recommendation_ids", []),
            memory_keys=data.get("memory_keys", []),
            analyst_note_ids=data.get("analyst_note_ids", []),
            ioc_values=data.get("ioc_values", []),
            cve_ids=data.get("cve_ids", []),
            threat_actors=data.get("threat_actors", []),
            campaigns=data.get("campaigns", []),
            malware_families=data.get("malware_families", []),
        )


@dataclass
class Investigation:
    id: str
    case_id: str
    title: str = ""
    description: str = ""
    priority: Priority = Priority.MEDIUM
    severity: Severity = Severity.MEDIUM
    status: InvestigationStatus = InvestigationStatus.OPEN
    owner: str = "unassigned"
    team: str = "SOC"
    labels: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed_at: Optional[str] = None
    links: InvestigationLinks = field(default_factory=InvestigationLinks)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value if isinstance(self.priority, Enum) else self.priority,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "owner": self.owner,
            "team": self.team,
            "labels": list(self.labels),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "links": self.links.to_dict(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Investigation":
        return cls(
            id=data["id"],
            case_id=data["case_id"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            priority=Priority(data.get("priority", Priority.MEDIUM.value)),
            severity=Severity(data.get("severity", Severity.MEDIUM.value)),
            status=InvestigationStatus(data.get("status", InvestigationStatus.OPEN.value)),
            owner=data.get("owner", "unassigned"),
            team=data.get("team", "SOC"),
            labels=data.get("labels", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            closed_at=data.get("closed_at"),
            links=InvestigationLinks.from_dict(data.get("links", {})),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ReasoningSession:
    id: str
    investigation_id: str
    title: str
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    state: Dict[str, Any] = field(default_factory=dict)
    parent_session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state": dict(self.state),
            "parent_session_id": self.parent_session_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReasoningSession":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            title=data.get("title", ""),
            status=SessionStatus(data.get("status", SessionStatus.ACTIVE.value)),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            state=data.get("state", {}),
            parent_session_id=data.get("parent_session_id"),
        )


@dataclass
class Artifact:
    id: str
    investigation_id: str
    name: str
    artifact_type: ArtifactType
    file_path: Optional[str] = None
    mime_type: str = "application/octet-stream"
    checksum_sha256: str = ""
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    content: Optional[Union[str, bytes]] = None

    def to_dict(self, include_content: bool = False) -> Dict[str, Any]:
        res = {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "name": self.name,
            "artifact_type": self.artifact_type.value if isinstance(self.artifact_type, Enum) else self.artifact_type,
            "file_path": self.file_path,
            "mime_type": self.mime_type,
            "checksum_sha256": self.checksum_sha256,
            "size_bytes": self.size_bytes,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }
        if include_content and self.content is not None:
            if isinstance(self.content, bytes):
                res["content"] = self.content.decode("utf-8", errors="replace")
            else:
                res["content"] = str(self.content)
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Artifact":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            name=data.get("name", ""),
            artifact_type=ArtifactType(data.get("artifact_type", ArtifactType.ATTACHMENT.value)),
            file_path=data.get("file_path"),
            mime_type=data.get("mime_type", "application/octet-stream"),
            checksum_sha256=data.get("checksum_sha256", ""),
            size_bytes=data.get("size_bytes", 0),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            content=data.get("content"),
        )


@dataclass
class Attachment:
    id: str
    investigation_id: str
    filename: str
    file_size: int
    checksum_sha256: str
    content_type: str = "application/octet-stream"
    attached_by: str = "system"
    attached_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    storage_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "filename": self.filename,
            "file_size": self.file_size,
            "checksum_sha256": self.checksum_sha256,
            "content_type": self.content_type,
            "attached_by": self.attached_by,
            "attached_at": self.attached_at,
            "storage_path": self.storage_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attachment":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            filename=data.get("filename", ""),
            file_size=data.get("file_size", 0),
            checksum_sha256=data.get("checksum_sha256", ""),
            content_type=data.get("content_type", "application/octet-stream"),
            attached_by=data.get("attached_by", "system"),
            attached_at=data.get("attached_at", datetime.now(timezone.utc).isoformat()),
            storage_path=data.get("storage_path"),
        )


@dataclass
class InvestigationSnapshot:
    id: str
    investigation_id: str
    version: int
    label: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "system"
    state_dump: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "version": self.version,
            "label": self.label,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "state_dump": dict(self.state_dump),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationSnapshot":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            version=data.get("version", 1),
            label=data.get("label", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            created_by=data.get("created_by", "system"),
            state_dump=data.get("state_dump", {}),
        )


@dataclass
class ActivityLogEntry:
    id: str
    investigation_id: str
    activity_type: ActivityType
    actor: str
    action: str
    session_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "session_id": self.session_id,
            "activity_type": self.activity_type.value if isinstance(self.activity_type, Enum) else self.activity_type,
            "actor": self.actor,
            "action": self.action,
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActivityLogEntry":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            session_id=data.get("session_id"),
            activity_type=ActivityType(data.get("activity_type", ActivityType.USER_ACTION.value)),
            actor=data.get("actor", "system"),
            action=data.get("action", ""),
            details=data.get("details", {}),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class Bookmark:
    id: str
    investigation_id: str
    bookmark_type: BookmarkType
    target_id: str
    title: str
    notes: str = ""
    created_by: str = "analyst"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "bookmark_type": self.bookmark_type.value if isinstance(self.bookmark_type, Enum) else self.bookmark_type,
            "target_id": self.target_id,
            "title": self.title,
            "notes": self.notes,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Bookmark":
        return cls(
            id=data["id"],
            investigation_id=data["investigation_id"],
            bookmark_type=BookmarkType(data.get("bookmark_type", BookmarkType.EVIDENCE.value)),
            target_id=data.get("target_id", ""),
            title=data.get("title", ""),
            notes=data.get("notes", ""),
            created_by=data.get("created_by", "analyst"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ReplayStep:
    step_id: str
    step_number: int
    timestamp: str
    step_type: str
    description: str
    state_delta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "timestamp": self.timestamp,
            "step_type": self.step_type,
            "description": self.description,
            "state_delta": dict(self.state_delta),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReplayStep":
        return cls(
            step_id=data["step_id"],
            step_number=data.get("step_number", 0),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            step_type=data.get("step_type", "GENERAL"),
            description=data.get("description", ""),
            state_delta=data.get("state_delta", {}),
        )


@dataclass
class ReplaySession:
    replay_id: str
    investigation_id: str
    current_step_index: int = 0
    total_steps: int = 0
    status: str = "PAUSED"  # "PLAYING", "PAUSED", "COMPLETED"
    steps: List[ReplayStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "investigation_id": self.investigation_id,
            "current_step_index": self.current_step_index,
            "total_steps": len(self.steps),
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReplaySession":
        steps = [ReplayStep.from_dict(s) for s in data.get("steps", [])]
        return cls(
            replay_id=data["replay_id"],
            investigation_id=data["investigation_id"],
            current_step_index=data.get("current_step_index", 0),
            total_steps=len(steps),
            status=data.get("status", "PAUSED"),
            steps=steps,
        )


@dataclass
class TraceDifference:
    investigation_id_1: str
    investigation_id_2: str
    new_evidence: List[Dict[str, Any]] = field(default_factory=list)
    removed_evidence: List[Dict[str, Any]] = field(default_factory=list)
    changed_graph: Dict[str, Any] = field(default_factory=lambda: {
        "added_nodes": [], "removed_nodes": [], "added_edges": [], "removed_edges": []
    })
    confidence_delta: float = 0.0
    hypothesis_changes: Dict[str, Any] = field(default_factory=dict)
    recommendation_changes: Dict[str, Any] = field(default_factory=dict)
    timeline_changes: Dict[str, Any] = field(default_factory=dict)
    risk_changes: Dict[str, Any] = field(default_factory=dict)
    report_differences: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id_1": self.investigation_id_1,
            "investigation_id_2": self.investigation_id_2,
            "new_evidence": self.new_evidence,
            "removed_evidence": self.removed_evidence,
            "changed_graph": self.changed_graph,
            "confidence_delta": self.confidence_delta,
            "hypothesis_changes": self.hypothesis_changes,
            "recommendation_changes": self.recommendation_changes,
            "timeline_changes": self.timeline_changes,
            "risk_changes": self.risk_changes,
            "report_differences": self.report_differences,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceDifference":
        return cls(
            investigation_id_1=data["investigation_id_1"],
            investigation_id_2=data["investigation_id_2"],
            new_evidence=data.get("new_evidence", []),
            removed_evidence=data.get("removed_evidence", []),
            changed_graph=data.get("changed_graph", {"added_nodes": [], "removed_nodes": [], "added_edges": [], "removed_edges": []}),
            confidence_delta=data.get("confidence_delta", 0.0),
            hypothesis_changes=data.get("hypothesis_changes", {}),
            recommendation_changes=data.get("recommendation_changes", {}),
            timeline_changes=data.get("timeline_changes", {}),
            risk_changes=data.get("risk_changes", {}),
            report_differences=data.get("report_differences", {}),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
