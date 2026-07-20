"""
NetFusion Workflow Service Facade API
Production-ready WorkflowService providing end-to-end API operations for Cases,
Investigations, Evidence, Tasks, Analyst Notes, Timeline Events, Unified Search,
Audit Logging, Event Publishing, and Report Metadata Generation.
"""

import time
from typing import Any, Dict, List, Optional, Union

from .audit import AuditLogger
from .domain import (
    AnalystNote,
    Assignment,
    Case,
    Comment,
    Evidence,
    Investigation,
    MITREMapping,
    NoteVersion,
    Recommendation,
    RiskAssessment,
    Tag,
    Task,
    TimelineEvent,
)
from .enums import (
    ApprovalStatus,
    AuditAction,
    BusinessImpact,
    CaseLifecycle,
    EvidenceSource,
    Likelihood,
    Priority,
    Severity,
    TagCategory,
    TaskStatus,
)
from .evidence import EvidenceManager
from .events import (
    CaseCreated,
    EvidenceAdded,
    InvestigationClosed,
    InvestigationStarted,
    InvestigationUpdated,
    StatusChanged,
    TaskAssigned,
    TimelineUpdated,
    WorkflowEventPublisher,
)
from .exceptions import EntityNotFoundError, TaskDependencyError
from .lifecycle import LifecycleEngine
from .reporting import ReportingEngine
from .search import SearchEngine
from .timeline import TimelineEngine


class WorkflowService:
    """Enterprise API Service for NetFusion Case Management & Investigation Workflow."""

    def __init__(self, event_publisher: Optional[WorkflowEventPublisher] = None):
        self.cases: Dict[str, Case] = {}
        self.investigations: Dict[str, Investigation] = {}
        self.audit_logger = AuditLogger()
        self.search_engine = SearchEngine()
        self.event_publisher = event_publisher or WorkflowEventPublisher()

    # -------------------------------------------------------------------------
    # CASE MANAGEMENT
    # -------------------------------------------------------------------------
    def create_case(
        self,
        title: str,
        summary: str = "",
        priority: Priority = Priority.MEDIUM,
        severity: Severity = Severity.MEDIUM,
        owner: str = "unassigned",
        created_by: str = "system",
        tags: Optional[List[Tag]] = None,
    ) -> Case:
        """Creates a new top-level incident Case."""
        case = Case(
            title=title,
            summary=summary,
            priority=priority,
            severity=severity,
            owner=owner,
            created_by=created_by,
            tags=tags or [],
        )
        self.cases[case.case_id] = case
        self.search_engine.index_case(case)

        # Audit & Event
        self.audit_logger.record(
            action=AuditAction.CREATE,
            entity_type="Case",
            entity_id=case.case_id,
            actor=created_by,
            changes={"title": title, "status": case.status.value},
        )
        self.event_publisher.publish(
            CaseCreated(
                case_id=case.case_id,
                title=title,
                owner=owner,
                priority=priority.value if isinstance(priority, Priority) else str(priority),
                actor=created_by,
            )
        )
        return case

    def get_case(self, case_id: str) -> Case:
        """Retrieves a Case by ID."""
        if case_id not in self.cases:
            raise EntityNotFoundError(f"Case with ID '{case_id}' not found.")
        return self.cases[case_id]

    # -------------------------------------------------------------------------
    # INVESTIGATION MANAGEMENT
    # -------------------------------------------------------------------------
    def create_investigation(
        self,
        title: str,
        case_id: Optional[str] = None,
        priority: Priority = Priority.MEDIUM,
        severity: Severity = Severity.MEDIUM,
        owner: str = "unassigned",
        created_by: str = "system",
        summary: str = "",
        description: str = "",
        affected_assets: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
    ) -> Investigation:
        """Creates a new Investigation and links it to an optional Case."""
        investigation = Investigation(
            title=title,
            case_id=case_id,
            priority=priority,
            severity=severity,
            owner=owner,
            created_by=created_by,
            summary=summary,
            description=description,
            affected_assets=affected_assets or [],
            affected_users=affected_users or [],
            assignment=Assignment(owner=owner),
        )

        self.investigations[investigation.investigation_id] = investigation

        # Link to Case if provided
        if case_id:
            if case_id in self.cases:
                self.cases[case_id].investigations.append(investigation)
            else:
                raise EntityNotFoundError(f"Case with ID '{case_id}' not found for association.")

        # Re-index
        self.search_engine.index_investigation(investigation)

        # Audit & Events
        self.audit_logger.record(
            action=AuditAction.CREATE,
            entity_type="Investigation",
            entity_id=investigation.investigation_id,
            actor=created_by,
            changes={"title": title, "case_id": case_id, "status": investigation.status.value},
        )
        self.event_publisher.publish(
            InvestigationStarted(
                investigation_id=investigation.investigation_id,
                case_id=case_id,
                title=title,
                owner=owner,
                priority=priority.value if isinstance(priority, Priority) else str(priority),
                severity=severity.value if isinstance(severity, Severity) else str(severity),
                actor=created_by,
            )
        )

        # Automatically record initial timeline event
        self.add_timeline_event(
            investigation_id=investigation.investigation_id,
            summary=f"Investigation initialized: {title}",
            event_type="STATUS_CHANGE",
            source="WORKFLOW_ENGINE",
            severity=severity,
            actor=created_by,
        )

        return investigation

    def get_investigation(self, investigation_id: str) -> Investigation:
        """Retrieves an Investigation by ID."""
        if investigation_id not in self.investigations:
            raise EntityNotFoundError(f"Investigation with ID '{investigation_id}' not found.")
        return self.investigations[investigation_id]

    def update_investigation(
        self,
        investigation_id: str,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[Priority] = None,
        severity: Optional[Severity] = None,
        findings: Optional[List[str]] = None,
        root_cause: Optional[str] = None,
        affected_assets: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
        actor: str = "system",
    ) -> Investigation:
        """Updates attributes of an existing Investigation."""
        inv = self.get_investigation(investigation_id)
        updated_fields = []

        if title is not None:
            inv.title = title
            updated_fields.append("title")
        if summary is not None:
            inv.summary = summary
            updated_fields.append("summary")
        if description is not None:
            inv.description = description
            updated_fields.append("description")
        if priority is not None:
            inv.priority = priority
            updated_fields.append("priority")
        if severity is not None:
            inv.severity = severity
            updated_fields.append("severity")
        if findings is not None:
            inv.findings.extend(findings)
            updated_fields.append("findings")
        if root_cause is not None:
            inv.root_cause = root_cause
            updated_fields.append("root_cause")
        if affected_assets is not None:
            inv.affected_assets = list(set(inv.affected_assets + affected_assets))
            updated_fields.append("affected_assets")
        if affected_users is not None:
            inv.affected_users = list(set(inv.affected_users + affected_users))
            updated_fields.append("affected_users")

        inv.updated_time = time.time()
        self.search_engine.index_investigation(inv)

        self.audit_logger.record(
            action=AuditAction.UPDATE,
            entity_type="Investigation",
            entity_id=investigation_id,
            actor=actor,
            changes={"updated_fields": updated_fields},
        )
        self.event_publisher.publish(
            InvestigationUpdated(
                investigation_id=investigation_id,
                updated_fields=updated_fields,
                actor=actor,
            )
        )
        return inv

    def transition_lifecycle(
        self,
        investigation_id: str,
        new_status: CaseLifecycle,
        actor: str = "system",
        reason: str = "",
    ) -> Investigation:
        """Transitions an investigation to a new lifecycle state."""
        inv = self.get_investigation(investigation_id)
        old_status = inv.status

        audit_entry = LifecycleEngine.transition(inv, new_status, actor=actor, reason=reason)
        self._records = self.audit_logger._records.append(audit_entry)

        # Also transition parent case status if applicable
        if inv.case_id and inv.case_id in self.cases:
            case = self.cases[inv.case_id]
            if LifecycleEngine.is_transition_allowed(case.status, new_status):
                LifecycleEngine.transition(case, new_status, actor=actor, reason=f"Synced from investigation {investigation_id}")

        self.event_publisher.publish(
            StatusChanged(
                entity_id=investigation_id,
                entity_type="Investigation",
                old_status=old_status.value if hasattr(old_status, "value") else str(old_status),
                new_status=new_status.value if hasattr(new_status, "value") else str(new_status),
                reason=reason,
                actor=actor,
            )
        )

        self.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Lifecycle transition: {old_status.value if hasattr(old_status, 'value') else old_status} -> {new_status.value if hasattr(new_status, 'value') else new_status}",
            event_type="STATUS_CHANGE",
            source="WORKFLOW_ENGINE",
            actor=actor,
            description=reason,
        )

        return inv

    def close_investigation(
        self,
        investigation_id: str,
        final_verdict: str,
        root_cause: Optional[str] = None,
        false_positive: bool = False,
        actor: str = "system",
    ) -> Investigation:
        """Closes an investigation with a final verdict and root cause."""
        inv = self.get_investigation(investigation_id)
        inv.final_verdict = final_verdict
        if root_cause:
            inv.root_cause = root_cause

        target_status = CaseLifecycle.FALSE_POSITIVE if false_positive else CaseLifecycle.CLOSED
        self.transition_lifecycle(investigation_id, target_status, actor=actor, reason=final_verdict)

        self.event_publisher.publish(
            InvestigationClosed(
                investigation_id=investigation_id,
                final_status=target_status.value,
                final_verdict=final_verdict,
                actor=actor,
            )
        )
        return inv

    # -------------------------------------------------------------------------
    # EVIDENCE MANAGEMENT
    # -------------------------------------------------------------------------
    def add_evidence(
        self,
        investigation_id: str,
        name: str,
        description: str = "",
        source: EvidenceSource = EvidenceSource.OTHER,
        collector_id: Optional[str] = None,
        canonical_object_ref: Optional[Any] = None,
        raw_artifact: Optional[Union[str, bytes]] = None,
        screenshot_path: Optional[str] = None,
        pcap_ref: Optional[Dict[str, Any]] = None,
        evtx_ref: Optional[Dict[str, Any]] = None,
        nmap_scan_ref: Optional[Dict[str, Any]] = None,
        threat_intel_ref: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        tags: Optional[List[Tag]] = None,
    ) -> Evidence:
        """Adds digital evidence to an investigation."""
        inv = self.get_investigation(investigation_id)

        evidence = EvidenceManager.create_evidence(
            name=name,
            investigation_id=investigation_id,
            description=description,
            source=source,
            collector_id=collector_id,
            canonical_object_ref=canonical_object_ref,
            raw_artifact=raw_artifact,
            screenshot_path=screenshot_path,
            pcap_ref=pcap_ref,
            evtx_ref=evtx_ref,
            nmap_scan_ref=nmap_scan_ref,
            threat_intel_ref=threat_intel_ref,
            actor=actor,
        )
        if tags:
            evidence.tags.extend(tags)

        inv.evidence_list.append(evidence)
        self.search_engine.index_investigation(inv)

        self.audit_logger.record(
            action=AuditAction.EVIDENCE_ADDED,
            entity_type="Evidence",
            entity_id=evidence.evidence_id,
            actor=actor,
            changes={"name": name, "source": evidence.source.value, "hash_sha256": evidence.hash_sha256},
        )
        self.event_publisher.publish(
            EvidenceAdded(
                evidence_id=evidence.evidence_id,
                investigation_id=investigation_id,
                name=name,
                source=evidence.source.value if hasattr(evidence.source, "value") else str(evidence.source),
                hash_sha256=evidence.hash_sha256,
                actor=actor,
            )
        )

        self.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Evidence added: {name}",
            event_type="EVIDENCE",
            source=evidence.source.value if hasattr(evidence.source, "value") else str(evidence.source),
            severity=inv.severity,
            actor=actor,
            related_entity_id=evidence.evidence_id,
        )

        return evidence

    # -------------------------------------------------------------------------
    # TIMELINE ENGINE
    # -------------------------------------------------------------------------
    def add_timeline_event(
        self,
        investigation_id: str,
        summary: str,
        event_type: str = "MANUAL_EVENT",
        source: str = "SYSTEM",
        severity: Severity = Severity.INFORMATIONAL,
        actor: str = "system",
        description: str = "",
        raw_data: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        related_entity_id: Optional[str] = None,
    ) -> TimelineEvent:
        """Adds a timeline event to an investigation timeline."""
        inv = self.get_investigation(investigation_id)

        engine = TimelineEngine(inv.timeline)
        event = engine.create_event(
            summary=summary,
            investigation_id=investigation_id,
            event_type=event_type,
            source=source,
            severity=severity,
            actor=actor,
            description=description,
            raw_data=raw_data,
            tags=tags,
            related_entity_id=related_entity_id,
        )

        self.search_engine.index_investigation(inv)
        self.event_publisher.publish(
            TimelineUpdated(
                investigation_id=investigation_id,
                timeline_event_id=event.event_id,
                summary=summary,
                actor=actor,
            )
        )
        return event

    def get_timeline(
        self,
        investigation_id: str,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[Severity] = None,
        ascending: bool = True,
    ) -> List[TimelineEvent]:
        """Gets sorted and filtered timeline events for an investigation."""
        inv = self.get_investigation(investigation_id)
        engine = TimelineEngine(inv.timeline)
        filtered = engine.filter(event_type=event_type, source=source, severity=severity)
        engine.events = filtered
        return engine.sort(ascending=ascending)

    # -------------------------------------------------------------------------
    # TASK MANAGEMENT
    # -------------------------------------------------------------------------
    def create_task(
        self,
        investigation_id: str,
        title: str,
        description: str = "",
        assignee: Optional[str] = None,
        priority: Priority = Priority.MEDIUM,
        due_date: Optional[float] = None,
        dependencies: Optional[List[str]] = None,
        actor: str = "system",
    ) -> Task:
        """Creates a task within an investigation."""
        inv = self.get_investigation(investigation_id)

        # Validate task dependencies exist
        if dependencies:
            existing_task_ids = {t.task_id for t in inv.tasks}
            for dep_id in dependencies:
                if dep_id not in existing_task_ids:
                    raise TaskDependencyError(f"Dependency task ID '{dep_id}' does not exist in investigation.")

        task = Task(
            title=title,
            investigation_id=investigation_id,
            description=description,
            assignee=assignee,
            priority=priority,
            due_date=due_date,
            dependencies=dependencies or [],
        )

        inv.tasks.append(task)
        self.search_engine.index_investigation(inv)

        self.audit_logger.record(
            action=AuditAction.CREATE,
            entity_type="Task",
            entity_id=task.task_id,
            actor=actor,
            changes={"title": title, "assignee": assignee},
        )

        if assignee:
            self.event_publisher.publish(
                TaskAssigned(
                    task_id=task.task_id,
                    investigation_id=investigation_id,
                    assignee=assignee,
                    title=title,
                    actor=actor,
                )
            )

        return task

    def update_task_status(
        self,
        investigation_id: str,
        task_id: str,
        new_status: TaskStatus,
        completion_percentage: Optional[float] = None,
        actor: str = "system",
    ) -> Task:
        """Updates task status and checks dependency rules."""
        inv = self.get_investigation(investigation_id)
        task = next((t for t in inv.tasks if t.task_id == task_id), None)
        if not task:
            raise EntityNotFoundError(f"Task with ID '{task_id}' not found.")

        # Check dependencies prior to completing
        if new_status == TaskStatus.COMPLETED:
            for dep_id in task.dependencies:
                dep_task = next((t for t in inv.tasks if t.task_id == dep_id), None)
                if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                    raise TaskDependencyError(
                        f"Cannot complete task '{task.title}' because dependency task '{dep_task.title if dep_task else dep_id}' is incomplete."
                    )
            task.completed_at = time.time()
            task.completed_by = actor
            task.completion_percentage = 100.0
        elif completion_percentage is not None:
            task.completion_percentage = completion_percentage

        old_status = task.status
        task.status = new_status
        task.updated_at = time.time()
        task.audit_history.append({
            "timestamp": time.time(),
            "actor": actor,
            "old_status": old_status.value,
            "new_status": new_status.value,
        })

        self.audit_logger.record(
            action=AuditAction.UPDATE,
            entity_type="Task",
            entity_id=task_id,
            actor=actor,
            changes={"old_status": old_status.value, "new_status": new_status.value},
        )
        return task

    # -------------------------------------------------------------------------
    # ANALYST NOTES
    # -------------------------------------------------------------------------
    def add_note(
        self,
        investigation_id: str,
        title: str,
        content: str,
        author: str = "analyst",
        ioc_references: Optional[List[str]] = None,
        mitre_references: Optional[List[str]] = None,
        evidence_references: Optional[List[str]] = None,
        task_references: Optional[List[str]] = None,
        mentions: Optional[List[str]] = None,
        tags: Optional[List[Tag]] = None,
    ) -> AnalystNote:
        """Adds an analyst note to an investigation."""
        inv = self.get_investigation(investigation_id)

        note = AnalystNote(
            title=title,
            content=content,
            investigation_id=investigation_id,
            author=author,
            ioc_references=ioc_references or [],
            mitre_references=mitre_references or [],
            evidence_references=evidence_references or [],
            task_references=task_references or [],
            mentions=mentions or [],
            tags=tags or [],
        )

        initial_version = NoteVersion(
            version_number=1,
            content=content,
            author=author,
        )
        note.version_history.append(initial_version)

        inv.notes.append(note)
        self.search_engine.index_investigation(inv)

        self.audit_logger.record(
            action=AuditAction.NOTES_EDITED,
            entity_type="AnalystNote",
            entity_id=note.note_id,
            actor=author,
            changes={"title": title},
        )

        self.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Note added: {title}",
            event_type="NOTE",
            source="ANALYST",
            actor=author,
            related_entity_id=note.note_id,
        )

        return note

    # -------------------------------------------------------------------------
    # SEARCH & REPORTING
    # -------------------------------------------------------------------------
    def search(
        self,
        query: str,
        entity_types: Optional[List[str]] = None,
        tag: Optional[str] = None,
        ioc: Optional[str] = None,
        mitre_id: Optional[str] = None,
    ) -> Dict[str, List[Any]]:
        """Unified search across all workflow entities."""
        return self.search_engine.search(
            query=query,
            entity_types=entity_types,
            tag=tag,
            ioc=ioc,
            mitre_id=mitre_id,
        )

    def generate_report_metadata(
        self,
        investigation_id: str,
        report_type: str = "EXECUTIVE",
        author: str = "SOC Analyst",
    ) -> Dict[str, Any]:
        """Generates report-ready metadata for an investigation."""
        inv = self.get_investigation(investigation_id)
        metadata = ReportingEngine.generate_report_metadata(inv, report_type=report_type, author=author)

        self.audit_logger.record(
            action=AuditAction.REPORT_GENERATION,
            entity_type="Investigation",
            entity_id=investigation_id,
            actor=author,
            metadata={"report_type": report_type},
        )
        return metadata
