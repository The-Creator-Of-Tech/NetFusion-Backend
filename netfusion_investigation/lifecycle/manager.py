"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Manager Facade

Unified entrypoint facade providing single-source-of-truth access to investigation lifecycle management.
"""

from typing import Any, Dict, List, Optional, Union

from netfusion_investigation.lifecycle.activity import ActivityLogger
from netfusion_investigation.lifecycle.artifacts import ArtifactManager
from netfusion_investigation.lifecycle.attachments import AttachmentManager
from netfusion_investigation.lifecycle.bookmarks import BookmarkManager
from netfusion_investigation.lifecycle.comparison import ComparisonEngine
from netfusion_investigation.lifecycle.events import EventBus
from netfusion_investigation.lifecycle.models import (
    ActivityType,
    Artifact,
    ArtifactType,
    Attachment,
    Bookmark,
    BookmarkType,
    Investigation,
    InvestigationSnapshot,
    InvestigationStatus,
    Priority,
    ReasoningSession,
    ReplaySession,
    ReplayStep,
    SessionStatus,
    Severity,
    TraceDifference,
)
from netfusion_investigation.lifecycle.persistence import FilePersistence
from netfusion_investigation.lifecycle.replay import ReplayEngine
from netfusion_investigation.lifecycle.reports import ReportEngine
from netfusion_investigation.lifecycle.repository import InvestigationRepository
from netfusion_investigation.lifecycle.service import InvestigationService
from netfusion_investigation.lifecycle.sessions import SessionManager
from netfusion_investigation.lifecycle.snapshots import SnapshotEngine


class InvestigationLifecycleManager:
    """Enterprise Investigation Lifecycle Manager for NetFusion."""

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        persistence: Optional[FilePersistence] = None,
        repository: Optional[InvestigationRepository] = None,
        event_bus: Optional[EventBus] = None,
    ):
        self.event_bus = event_bus or EventBus()
        self.persistence = persistence or FilePersistence(storage_dir=storage_dir)
        self.repository = repository or InvestigationRepository(persistence=self.persistence)
        self.activity_logger = ActivityLogger()
        self.service = InvestigationService(
            repository=self.repository,
            event_bus=self.event_bus,
            activity_logger=self.activity_logger,
        )
        self.session_manager = SessionManager()
        self.artifact_manager = ArtifactManager(storage_dir=storage_dir)
        self.attachment_manager = AttachmentManager(storage_dir=storage_dir)
        self.snapshot_engine = SnapshotEngine()
        self.replay_engine = ReplayEngine()
        self.comparison_engine = ComparisonEngine()
        self.bookmark_manager = BookmarkManager()
        self.report_engine = ReportEngine()

    # --- Investigation Management ---

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
        return self.service.create_investigation(
            case_id=case_id,
            title=title,
            description=description,
            priority=priority,
            severity=severity,
            owner=owner,
            team=team,
            labels=labels,
            metadata=metadata,
        )

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self.service.get_investigation(investigation_id)

    def update_investigation(self, investigation_id: str, **kwargs) -> Investigation:
        return self.service.update_investigation(investigation_id, **kwargs)

    def delete_investigation(self, investigation_id: str) -> bool:
        return self.service.delete_investigation(investigation_id)

    def link_entities(self, investigation_id: str, **kwargs) -> Investigation:
        return self.service.link_entities(investigation_id, **kwargs)

    def search_investigations(self, **kwargs) -> List[Investigation]:
        return self.repository.search(**kwargs)

    # --- Session Management ---

    def create_session(self, investigation_id: str, title: str, state: Optional[Dict[str, Any]] = None) -> ReasoningSession:
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")
        sess = self.session_manager.create_session(investigation_id, title, state)
        self.service.link_entities(investigation_id, reasoning_session_ids=[sess.id])
        return sess

    def resume_session(self, session_id: str) -> ReasoningSession:
        return self.session_manager.resume_session(session_id)

    def pause_session(self, session_id: str) -> ReasoningSession:
        return self.session_manager.pause_session(session_id)

    def archive_session(self, session_id: str) -> ReasoningSession:
        return self.session_manager.archive_session(session_id)

    def clone_session(self, session_id: str, new_title: Optional[str] = None) -> ReasoningSession:
        sess = self.session_manager.clone_session(session_id, new_title)
        self.service.link_entities(sess.investigation_id, reasoning_session_ids=[sess.id])
        return sess

    def merge_sessions(self, target_session_id: str, source_session_ids: List[str]) -> ReasoningSession:
        merged = self.session_manager.merge_sessions(target_session_id, source_session_ids)
        self.activity_logger.log_activity(
            investigation_id=merged.investigation_id,
            activity_type=ActivityType.AI_ACTION,
            actor="AI_Threat_Engine",
            action="MERGE_SESSIONS",
            details={"target_session_id": target_session_id, "merged_sources": source_session_ids},
        )
        return merged

    def lock_session(self, session_id: str) -> ReasoningSession:
        return self.session_manager.lock_session(session_id)

    def restore_session(self, session_id: str) -> ReasoningSession:
        return self.session_manager.restore_session(session_id)

    # --- Artifact & Attachment Management ---

    def store_artifact(
        self,
        investigation_id: str,
        name: str,
        artifact_type: Union[ArtifactType, str],
        content: Union[str, bytes],
        mime_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Artifact:
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")
        art = self.artifact_manager.store_artifact(
            investigation_id=investigation_id,
            name=name,
            artifact_type=artifact_type,
            content=content,
            mime_type=mime_type,
            metadata=metadata,
        )
        self.service.link_entities(investigation_id, report_ids=[art.id] if art.artifact_type == ArtifactType.REPORT else None)
        return art

    def add_attachment(
        self,
        investigation_id: str,
        filename: str,
        content: Union[str, bytes],
        content_type: str = "application/octet-stream",
        attached_by: str = "analyst",
    ) -> Attachment:
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")
        att = self.attachment_manager.add_attachment(
            investigation_id=investigation_id,
            filename=filename,
            content=content,
            content_type=content_type,
            attached_by=attached_by,
        )
        return att

    # --- Snapshots ---

    def create_snapshot(self, investigation: Union[str, Investigation], label: str = "Snapshot", created_by: str = "system") -> InvestigationSnapshot:
        if isinstance(investigation, str):
            inv = self.get_investigation(investigation)
        else:
            inv = investigation
        if not inv:
            raise ValueError(f"Investigation not found")
        snap = self.snapshot_engine.create_snapshot(inv, label=label, created_by=created_by)
        self.activity_logger.log_activity(
            investigation_id=inv.id,
            activity_type=ActivityType.USER_ACTION,
            actor=created_by,
            action="CREATE_SNAPSHOT",
            details={"snapshot_id": snap.id, "version": snap.version, "label": label},
        )
        return snap

    def restore_snapshot(self, investigation_id: str, snapshot_id_or_version: Any) -> Investigation:
        restored = self.snapshot_engine.restore_snapshot(investigation_id, snapshot_id_or_version)
        self.repository.update(restored)
        self.activity_logger.log_activity(
            investigation_id=investigation_id,
            activity_type=ActivityType.USER_ACTION,
            actor="system",
            action="RESTORE_SNAPSHOT",
            details={"snapshot_reference": str(snapshot_id_or_version)},
        )
        return restored

    # --- Replay & Comparison ---

    def initialize_replay(self, investigation: Union[str, Investigation], **kwargs) -> ReplaySession:
        if isinstance(investigation, str):
            inv = self.get_investigation(investigation)
        else:
            inv = investigation
        if not inv:
            raise ValueError(f"Investigation not found")
        return self.replay_engine.initialize_replay(inv, **kwargs)

    def compare_investigations(self, investigation_id_1: str, investigation_id_2: str, **kwargs) -> TraceDifference:
        inv1 = self.get_investigation(investigation_id_1)
        inv2 = self.get_investigation(investigation_id_2)
        if not inv1 or not inv2:
            raise ValueError("One or both investigations were not found")
        return self.comparison_engine.compare_investigations(inv1, inv2, **kwargs)

    def compare_sessions(self, session_id_1: str, session_id_2: str) -> TraceDifference:
        s1 = self.session_manager.get_session(session_id_1)
        s2 = self.session_manager.get_session(session_id_2)
        if not s1 or not s2:
            raise ValueError("One or both sessions were not found")
        return self.comparison_engine.compare_sessions(s1, s2)

    # --- Bookmarks & Activity ---

    def add_bookmark(self, investigation_id: str, bookmark_type: Union[BookmarkType, str], target_id: str, title: str, notes: str = "", created_by: str = "analyst") -> Bookmark:
        return self.bookmark_manager.add_bookmark(investigation_id, bookmark_type, target_id, title, notes, created_by)

    def get_activities(self, investigation_id: str, **kwargs) -> List[Any]:
        return self.activity_logger.get_activities(investigation_id=investigation_id, **kwargs)
