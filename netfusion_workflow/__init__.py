"""
NetFusion Investigation Workflow & Case Management Module
Enterprise management layer for security operations centers governing cases,
investigations, task management, evidence chain of custody, timeline generation,
risk assessment, audit logging, search, event publishing, and report metadata generation.
"""

from .audit import AuditLogger
from .domain import (
    AnalystNote,
    Approval,
    Assignment,
    Attachment,
    AuditRecord,
    Bookmark,
    Case,
    Comment,
    Evidence,
    Investigation,
    MITREMapping,
    Notification,
    Recommendation,
    ReportReference,
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
    IntegrityStatus,
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
    WorkflowEvent,
    WorkflowEventPublisher,
)
from .exceptions import (
    AssignmentError,
    EntityNotFoundError,
    EvidenceIntegrityError,
    InvalidLifecycleTransitionError,
    ReportMetadataError,
    SearchError,
    TaskDependencyError,
    WorkflowError,
)
from .lifecycle import LifecycleEngine
from .reporting import ReportingEngine
from .search import SearchEngine
from .service import WorkflowService
from .timeline import TimelineEngine

__all__ = [
    # Domain Objects
    "Case",
    "Investigation",
    "Task",
    "Evidence",
    "TimelineEvent",
    "AnalystNote",
    "Comment",
    "Assignment",
    "Tag",
    "Attachment",
    "Recommendation",
    "ReportReference",
    "MITREMapping",
    "RiskAssessment",
    "Approval",
    "Bookmark",
    "Notification",
    "AuditRecord",
    # Enums
    "CaseLifecycle",
    "Priority",
    "Severity",
    "TaskStatus",
    "ApprovalStatus",
    "BusinessImpact",
    "Likelihood",
    "TagCategory",
    "AuditAction",
    "EvidenceSource",
    "IntegrityStatus",
    # Engines & Managers
    "LifecycleEngine",
    "EvidenceManager",
    "TimelineEngine",
    "AuditLogger",
    "SearchEngine",
    "ReportingEngine",
    "WorkflowEventPublisher",
    "WorkflowService",
    # Events
    "WorkflowEvent",
    "CaseCreated",
    "InvestigationStarted",
    "InvestigationUpdated",
    "TaskAssigned",
    "EvidenceAdded",
    "TimelineUpdated",
    "StatusChanged",
    "InvestigationClosed",
    # Exceptions
    "WorkflowError",
    "EntityNotFoundError",
    "InvalidLifecycleTransitionError",
    "TaskDependencyError",
    "EvidenceIntegrityError",
    "AssignmentError",
    "SearchError",
    "ReportMetadataError",
]
