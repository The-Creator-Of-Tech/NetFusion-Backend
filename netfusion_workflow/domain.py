"""
NetFusion Workflow Domain Objects
Enterprise dataclass representations for all 18 canonical workflow entities:
Case, Investigation, Task, Evidence, TimelineEvent, AnalystNote, Comment,
Assignment, Tag, Attachment, Recommendation, ReportReference, MITREMapping,
RiskAssessment, Approval, Bookmark, Notification, AuditRecord.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Union

from .enums import (
    ApprovalStatus,
    AuditAction,
    BusinessImpact,
    CaseLifecycle,
    EvidenceSource,
    IntegrityStatus,
    Likelihood,
    Priority,
    Severity,
    TagCategory,
    TaskStatus,
)


@dataclass
class Tag:
    """Categorized tag for assets, evidence, cases, users, threat actors, campaigns, malware, MITRE, custom."""
    name: str
    category: TagCategory = TagCategory.CUSTOM
    tag_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag_id": self.tag_id,
            "name": self.name,
            "category": self.category.value if isinstance(self.category, TagCategory) else self.category,
            "description": self.description,
            "created_at": self.created_at,
        }


@dataclass
class Comment:
    """Discussion item on tasks, evidence, notes, or investigations."""
    comment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    author: str = "system"
    content: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parent_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "comment_id": self.comment_id,
            "author": self.author,
            "content": self.content,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "parent_id": self.parent_id,
        }


@dataclass
class Attachment:
    """File or artifact attachment associated with an investigation or note."""
    attachment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    file_name: str = ""
    file_size_bytes: int = 0
    mime_type: str = "application/octet-stream"
    file_path: str = ""
    checksum_sha256: str = ""
    uploaded_by: str = ""
    uploaded_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attachment_id": self.attachment_id,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "mime_type": self.mime_type,
            "file_path": self.file_path,
            "checksum_sha256": self.checksum_sha256,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": self.uploaded_at,
        }


@dataclass
class Recommendation:
    """Actionable remediation or mitigation recommendation."""
    recommendation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    priority: Priority = Priority.MEDIUM
    status: str = "OPEN"
    action_type: str = "REMEDIATION"  # REMEDIATION, CONTAINMENT, MITIGATION
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value if isinstance(self.priority, Priority) else self.priority,
            "status": self.status,
            "action_type": self.action_type,
            "created_at": self.created_at,
        }


@dataclass
class MITREMapping:
    """Mapping to MITRE ATT&CK Framework tactics, techniques, and sub-techniques."""
    mapping_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tactic: str = ""
    tactic_id: str = ""
    technique: str = ""
    technique_id: str = ""
    sub_technique: Optional[str] = None
    sub_technique_id: Optional[str] = None
    matrix: str = "Enterprise ATT&CK"
    confidence: float = 1.0
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "sub_technique": self.sub_technique,
            "sub_technique_id": self.sub_technique_id,
            "matrix": self.matrix,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class RiskAssessment:
    """Quantitative risk scoring, confidence, business impact, likelihood, and affected systems."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    risk_score: float = 0.0  # Range: 0.0 to 100.0
    confidence: float = 100.0  # Percentage: 0.0 to 100.0
    severity: Severity = Severity.MEDIUM
    business_impact: BusinessImpact = BusinessImpact.MEDIUM
    likelihood: Likelihood = Likelihood.MEDIUM
    affected_systems: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "business_impact": self.business_impact.value if isinstance(self.business_impact, BusinessImpact) else self.business_impact,
            "likelihood": self.likelihood.value if isinstance(self.likelihood, Likelihood) else self.likelihood,
            "affected_systems": self.affected_systems,
            "recommendations": self.recommendations,
        }


@dataclass
class Assignment:
    """Analyst, reviewer, and manager assignments for cases and investigations."""
    assignment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    owner: str = ""
    assigned_analysts: List[str] = field(default_factory=list)
    reviewer: Optional[str] = None
    manager: Optional[str] = None
    assigned_at: float = field(default_factory=time.time)
    escalation_reason: Optional[str] = None
    escalated_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "owner": self.owner,
            "assigned_analysts": self.assigned_analysts,
            "reviewer": self.reviewer,
            "manager": self.manager,
            "assigned_at": self.assigned_at,
            "escalation_reason": self.escalation_reason,
            "escalated_at": self.escalated_at,
        }


@dataclass
class Approval:
    """Formal review and approval workflow for status transitions, escalations, or closures."""
    approval_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    requester: str = ""
    approver: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_action: str = ""
    comments: List[str] = field(default_factory=list)
    requested_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "requester": self.requester,
            "approver": self.approver,
            "status": self.status.value if isinstance(self.status, ApprovalStatus) else self.status,
            "requested_action": self.requested_action,
            "comments": self.comments,
            "requested_at": self.requested_at,
            "decided_at": self.decided_at,
        }


@dataclass
class Task:
    """Action item within an investigation featuring dependencies, completion tracking, and audit trail."""
    title: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    description: str = ""
    assignee: Optional[str] = None
    due_date: Optional[float] = None
    priority: Priority = Priority.MEDIUM
    status: TaskStatus = TaskStatus.TODO
    dependencies: List[str] = field(default_factory=list)  # List of Task IDs
    comments: List[Comment] = field(default_factory=list)
    completion_percentage: float = 0.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    completed_by: Optional[str] = None
    audit_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "description": self.description,
            "assignee": self.assignee,
            "due_date": self.due_date,
            "priority": self.priority.value if isinstance(self.priority, Priority) else self.priority,
            "status": self.status.value if isinstance(self.status, TaskStatus) else self.status,
            "dependencies": self.dependencies,
            "comments": [c.to_dict() for c in self.comments],
            "completion_percentage": self.completion_percentage,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "completed_by": self.completed_by,
            "audit_history": self.audit_history,
        }


@dataclass
class CustodyEntry:
    """Single append-only chain of custody entry for evidence handling."""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    actor: str = "system"
    action: str = "INGESTED"
    location: str = "STORAGE"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "location": self.location,
            "notes": self.notes,
        }


@dataclass
class Evidence:
    """Digital evidence object linked to canonical data objects, raw files, PCAPs, EVTXs, scans, or threat intel."""
    name: str
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    description: str = ""
    source: EvidenceSource = EvidenceSource.OTHER
    collector_id: Optional[str] = None
    canonical_object_ref: Optional[Any] = None
    raw_artifact: Optional[Union[str, bytes]] = None
    screenshot_path: Optional[str] = None
    pcap_ref: Optional[Dict[str, Any]] = None
    evtx_ref: Optional[Dict[str, Any]] = None
    nmap_scan_ref: Optional[Dict[str, Any]] = None
    threat_intel_ref: Optional[Dict[str, Any]] = None
    hash_sha256: str = ""
    hash_md5: str = ""
    hash_sha1: str = ""
    timestamp: float = field(default_factory=time.time)
    chain_of_custody: List[CustodyEntry] = field(default_factory=list)
    integrity_status: IntegrityStatus = IntegrityStatus.UNVERIFIED
    verified_at: Optional[float] = None
    tags: List[Tag] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "investigation_id": self.investigation_id,
            "name": self.name,
            "description": self.description,
            "source": self.source.value if isinstance(self.source, EvidenceSource) else self.source,
            "collector_id": self.collector_id,
            "canonical_object_ref": str(self.canonical_object_ref) if self.canonical_object_ref else None,
            "has_raw_artifact": self.raw_artifact is not None,
            "screenshot_path": self.screenshot_path,
            "pcap_ref": self.pcap_ref,
            "evtx_ref": self.evtx_ref,
            "nmap_scan_ref": self.nmap_scan_ref,
            "threat_intel_ref": self.threat_intel_ref,
            "hash_sha256": self.hash_sha256,
            "hash_md5": self.hash_md5,
            "hash_sha1": self.hash_sha1,
            "timestamp": self.timestamp,
            "chain_of_custody": [c.to_dict() for c in self.chain_of_custody],
            "integrity_status": self.integrity_status.value if isinstance(self.integrity_status, IntegrityStatus) else self.integrity_status,
            "verified_at": self.verified_at,
            "tags": [t.to_dict() for t in self.tags],
        }


@dataclass
class TimelineEvent:
    """Chronological event node for automated and manual investigation timeline assembly."""
    summary: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    timestamp: float = field(default_factory=time.time)
    event_type: str = "MANUAL_EVENT"  # COLLECTOR_EVENT, CANONICAL_OBJECT, NOTE, TASK, EVIDENCE, STATUS_CHANGE, AI_FINDING, MANUAL_EVENT
    source: str = "SYSTEM"
    severity: Severity = Severity.INFORMATIONAL
    actor: str = "system"
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    related_entity_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "actor": self.actor,
            "summary": self.summary,
            "description": self.description,
            "raw_data": self.raw_data,
            "tags": self.tags,
            "related_entity_id": self.related_entity_id,
        }


@dataclass
class NoteVersion:
    """Snapshot of a note version for audit history."""
    version_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version_number: int = 1
    content: str = ""
    author: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "version_number": self.version_number,
            "content": self.content,
            "author": self.author,
            "timestamp": self.timestamp,
        }


@dataclass
class AnalystNote:
    """Analyst markdown note supporting code blocks, references, mentions, and immutable versioning."""
    title: str
    content: str
    note_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    author: str = "analyst"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    ioc_references: List[str] = field(default_factory=list)
    mitre_references: List[str] = field(default_factory=list)
    evidence_references: List[str] = field(default_factory=list)
    task_references: List[str] = field(default_factory=list)
    mentions: List[str] = field(default_factory=list)
    version_history: List[NoteVersion] = field(default_factory=list)
    tags: List[Tag] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "content": self.content,
            "author": self.author,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "ioc_references": self.ioc_references,
            "mitre_references": self.mitre_references,
            "evidence_references": self.evidence_references,
            "task_references": self.task_references,
            "mentions": self.mentions,
            "version_history": [v.to_dict() for v in self.version_history],
            "tags": [t.to_dict() for t in self.tags],
        }


@dataclass
class ReportReference:
    """Reference to generated report artifacts."""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    report_type: str = "EXECUTIVE"  # EXECUTIVE, TECHNICAL, COMPLIANCE
    file_path: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "report_type": self.report_type,
            "file_path": self.file_path,
            "created_at": self.created_at,
        }


@dataclass
class Bookmark:
    """Analyst bookmark to quick-reference evidence, timeline items, or notes."""
    bookmark_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analyst: str = ""
    target_type: str = "EVIDENCE"  # EVIDENCE, TIMELINE_EVENT, NOTE, TASK
    target_id: str = ""
    title: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bookmark_id": self.bookmark_id,
            "analyst": self.analyst,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "title": self.title,
            "created_at": self.created_at,
        }


@dataclass
class Notification:
    """Notification alert sent to analysts or managers."""
    notification_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    recipient: str = ""
    title: str = ""
    message: str = ""
    read: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "notification_id": self.notification_id,
            "recipient": self.recipient,
            "title": self.title,
            "message": self.message,
            "read": self.read,
            "created_at": self.created_at,
        }


@dataclass
class AuditRecord:
    """Immutable record tracking every CRUD operation, state transition, and analyst modification."""
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: AuditAction = AuditAction.CREATE
    entity_type: str = ""
    entity_id: str = ""
    actor: str = "system"
    timestamp: float = field(default_factory=time.time)
    changes: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "action": self.action.value if isinstance(self.action, AuditAction) else self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "changes": self.changes,
            "metadata": self.metadata,
        }


@dataclass
class Investigation:
    """Primary investigation entity representing a security investigation."""
    title: str
    investigation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: Optional[str] = None
    priority: Priority = Priority.MEDIUM
    severity: Severity = Severity.MEDIUM
    status: CaseLifecycle = CaseLifecycle.NEW
    owner: str = "unassigned"
    assignee: Optional[str] = None
    created_by: str = "system"
    created_time: float = field(default_factory=time.time)
    updated_time: float = field(default_factory=time.time)
    closed_time: Optional[float] = None
    affected_assets: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    related_cases: List[str] = field(default_factory=list)
    related_investigations: List[str] = field(default_factory=list)
    summary: str = ""
    description: str = ""
    findings: List[str] = field(default_factory=list)
    root_cause: Optional[str] = None
    recommendations: List[Recommendation] = field(default_factory=list)
    final_verdict: Optional[str] = None
    tasks: List[Task] = field(default_factory=list)
    evidence_list: List[Evidence] = field(default_factory=list)
    notes: List[AnalystNote] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    tags: List[Tag] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    assignment: Optional[Assignment] = None
    mitre_mappings: List[MITREMapping] = field(default_factory=list)
    approvals: List[Approval] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "title": self.title,
            "priority": self.priority.value if isinstance(self.priority, Priority) else self.priority,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "status": self.status.value if isinstance(self.status, CaseLifecycle) else self.status,
            "owner": self.owner,
            "assignee": self.assignee,
            "created_by": self.created_by,
            "created_time": self.created_time,
            "updated_time": self.updated_time,
            "closed_time": self.closed_time,
            "affected_assets": self.affected_assets,
            "affected_users": self.affected_users,
            "related_cases": self.related_cases,
            "related_investigations": self.related_investigations,
            "summary": self.summary,
            "description": self.description,
            "findings": self.findings,
            "root_cause": self.root_cause,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "final_verdict": self.final_verdict,
            "task_count": len(self.tasks),
            "evidence_count": len(self.evidence_list),
            "note_count": len(self.notes),
            "timeline_event_count": len(self.timeline),
            "tags": [t.to_dict() for t in self.tags],
            "risk_assessment": self.risk_assessment.to_dict() if self.risk_assessment else None,
            "assignment": self.assignment.to_dict() if self.assignment else None,
            "mitre_mappings": [m.to_dict() for m in self.mitre_mappings],
        }


@dataclass
class Case:
    """Top-level incident case object containing one or more investigations."""
    title: str
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: CaseLifecycle = CaseLifecycle.NEW
    priority: Priority = Priority.MEDIUM
    severity: Severity = Severity.MEDIUM
    owner: str = "unassigned"
    created_by: str = "system"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None
    investigations: List[Investigation] = field(default_factory=list)
    tags: List[Tag] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status.value if isinstance(self.status, CaseLifecycle) else self.status,
            "priority": self.priority.value if isinstance(self.priority, Priority) else self.priority,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "owner": self.owner,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "investigation_ids": [inv.investigation_id for inv in self.investigations],
            "tags": [t.to_dict() for t in self.tags],
            "summary": self.summary,
        }
