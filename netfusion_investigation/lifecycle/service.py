"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Service Layer

Service layer providing high-level business orchestration for investigations.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from netfusion_investigation.lifecycle.activity import ActivityLogger
from netfusion_investigation.lifecycle.events import (
    ArtifactAdded,
    EventBus,
    InvestigationClosed,
    InvestigationCreated,
    InvestigationUpdated,
    SnapshotCreated,
)
from netfusion_investigation.lifecycle.models import (
    ActivityType,
    Investigation,
    InvestigationLinks,
    InvestigationStatus,
    Priority,
    Severity,
)
from netfusion_investigation.lifecycle.repository import InvestigationRepository


class InvestigationService:
    """Business service orchestrating repository operations, validation, event dispatch, and audit logging."""

    def __init__(
        self,
        repository: Optional[InvestigationRepository] = None,
        event_bus: Optional[EventBus] = None,
        activity_logger: Optional[ActivityLogger] = None,
    ):
        self._repository = repository or InvestigationRepository()
        self._event_bus = event_bus or EventBus()
        self._activity_logger = activity_logger or ActivityLogger()
        self._lock = threading.RLock()

    @property
    def repository(self) -> InvestigationRepository:
        return self._repository

    @property
    def event_bus(self) -> EventBus:
        return self._event_bus

    @property
    def activity_logger(self) -> ActivityLogger:
        return self._activity_logger

    def create_investigation(
        self,
        case_id: str,
        title: str,
        description: str = "",
        priority: Union[Priority, str] = Priority.MEDIUM,
        severity: Union[Severity, str] = Severity.MEDIUM,
        owner: str = "unassigned",
        team: str = "SOC",
        labels: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Investigation:
        with self._lock:
            p_enum = priority if isinstance(priority, Priority) else Priority(priority)
            s_enum = severity if isinstance(severity, Severity) else Severity(severity)
            now = datetime.now(timezone.utc).isoformat()

            investigation = Investigation(
                id=f"inv-{uuid.uuid4().hex[:12]}",
                case_id=case_id,
                title=title,
                description=description,
                priority=p_enum,
                severity=s_enum,
                status=InvestigationStatus.OPEN,
                owner=owner,
                team=team,
                labels=labels or [],
                created_at=now,
                updated_at=now,
                closed_at=None,
                links=InvestigationLinks(),
                metadata=metadata or {},
            )

            saved = self._repository.add(investigation)

            # Audit log & Event
            self._activity_logger.log_activity(
                investigation_id=saved.id,
                activity_type=ActivityType.USER_ACTION,
                actor=owner,
                action="CREATE_INVESTIGATION",
                details={"case_id": case_id, "title": title},
            )

            self._event_bus.publish(
                InvestigationCreated(
                    event_id=f"evt-{uuid.uuid4().hex[:12]}",
                    investigation_id=saved.id,
                    payload=saved.to_dict(),
                )
            )

            return saved

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self._repository.get(investigation_id)

    def update_investigation(
        self,
        investigation_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[Union[Priority, str]] = None,
        severity: Optional[Union[Severity, str]] = None,
        status: Optional[Union[InvestigationStatus, str]] = None,
        owner: Optional[str] = None,
        team: Optional[str] = None,
        labels: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "system",
    ) -> Investigation:
        with self._lock:
            inv = self._repository.get(investigation_id)
            if not inv:
                raise ValueError(f"Investigation {investigation_id} not found")

            if inv.status == InvestigationStatus.CLOSED and status != InvestigationStatus.OPEN:
                raise ValueError("Closed investigations are immutable. Reopen before editing.")

            changes = {}
            if title is not None and title != inv.title:
                inv.title = title
                changes["title"] = title
            if description is not None and description != inv.description:
                inv.description = description
                changes["description"] = description
            if priority is not None:
                p_val = priority if isinstance(priority, Priority) else Priority(priority)
                inv.priority = p_val
                changes["priority"] = p_val.value
            if severity is not None:
                s_val = severity if isinstance(severity, Severity) else Severity(severity)
                inv.severity = s_val
                changes["severity"] = s_val.value
            if status is not None:
                st_val = status if isinstance(status, InvestigationStatus) else InvestigationStatus(status)
                inv.status = st_val
                changes["status"] = st_val.value
                if st_val == InvestigationStatus.CLOSED and not inv.closed_at:
                    inv.closed_at = datetime.now(timezone.utc).isoformat()
                    self._event_bus.publish(
                        InvestigationClosed(
                            event_id=f"evt-{uuid.uuid4().hex[:12]}",
                            investigation_id=inv.id,
                            payload={"closed_by": actor, "closed_at": inv.closed_at},
                        )
                    )
            if owner is not None and owner != inv.owner:
                inv.owner = owner
                changes["owner"] = owner
            if team is not None and team != inv.team:
                inv.team = team
                changes["team"] = team
            if labels is not None:
                inv.labels = labels
                changes["labels"] = labels
            if metadata is not None:
                inv.metadata.update(metadata)
                changes["metadata"] = metadata

            inv.updated_at = datetime.now(timezone.utc).isoformat()
            updated = self._repository.update(inv)

            self._activity_logger.log_activity(
                investigation_id=updated.id,
                activity_type=ActivityType.USER_ACTION,
                actor=actor,
                action="UPDATE_INVESTIGATION",
                details=changes,
            )

            self._event_bus.publish(
                InvestigationUpdated(
                    event_id=f"evt-{uuid.uuid4().hex[:12]}",
                    investigation_id=updated.id,
                    payload=changes,
                )
            )

            return updated

    def link_entities(
        self,
        investigation_id: str,
        reasoning_session_ids: Optional[List[str]] = None,
        reasoning_trace_ids: Optional[List[str]] = None,
        timeline_event_ids: Optional[List[str]] = None,
        evidence_ids: Optional[List[str]] = None,
        graph_node_ids: Optional[List[str]] = None,
        graph_edge_ids: Optional[List[str]] = None,
        report_ids: Optional[List[str]] = None,
        workflow_ids: Optional[List[str]] = None,
        playbook_ids: Optional[List[str]] = None,
        pcap_file_ids: Optional[List[str]] = None,
        nmap_scan_ids: Optional[List[str]] = None,
        asset_ids: Optional[List[str]] = None,
        alert_ids: Optional[List[str]] = None,
        recommendation_ids: Optional[List[str]] = None,
        memory_keys: Optional[List[str]] = None,
        analyst_note_ids: Optional[List[str]] = None,
        ioc_values: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        threat_actors: Optional[List[str]] = None,
        campaigns: Optional[List[str]] = None,
        malware_families: Optional[List[str]] = None,
        actor: str = "system",
    ) -> Investigation:
        with self._lock:
            inv = self._repository.get(investigation_id)
            if not inv:
                raise ValueError(f"Investigation {investigation_id} not found")

            links = inv.links
            link_map = [
                (reasoning_session_ids, links.reasoning_session_ids),
                (reasoning_trace_ids, links.reasoning_trace_ids),
                (timeline_event_ids, links.timeline_event_ids),
                (evidence_ids, links.evidence_ids),
                (graph_node_ids, links.graph_node_ids),
                (graph_edge_ids, links.graph_edge_ids),
                (report_ids, links.report_ids),
                (workflow_ids, links.workflow_ids),
                (playbook_ids, links.playbook_ids),
                (pcap_file_ids, links.pcap_file_ids),
                (nmap_scan_ids, links.nmap_scan_ids),
                (asset_ids, links.asset_ids),
                (alert_ids, links.alert_ids),
                (recommendation_ids, links.recommendation_ids),
                (memory_keys, links.memory_keys),
                (analyst_note_ids, links.analyst_note_ids),
                (ioc_values, links.ioc_values),
                (cve_ids, links.cve_ids),
                (threat_actors, links.threat_actors),
                (campaigns, links.campaigns),
                (malware_families, links.malware_families),
            ]

            added_count = 0
            for new_items, target_list in link_map:
                if new_items:
                    for item in new_items:
                        if item not in target_list:
                            target_list.append(item)
                            added_count += 1

            inv.updated_at = datetime.now(timezone.utc).isoformat()
            updated = self._repository.update(inv)

            self._activity_logger.log_activity(
                investigation_id=updated.id,
                activity_type=ActivityType.WORKFLOW_ACTION,
                actor=actor,
                action="LINK_ENTITIES",
                details={"added_count": added_count},
            )

            return updated

    def delete_investigation(self, investigation_id: str) -> bool:
        return self._repository.delete(investigation_id)
