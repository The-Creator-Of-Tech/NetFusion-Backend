"""
NetFusion Workflow Enums
Domain enumerations governing Case Lifecycles, Priorities, Severities, Task States,
Risk Metrics, Tag Categories, and Audit Actions.
"""

from enum import Enum


class CaseLifecycle(str, Enum):
    """Lifecycle states for Cases and Investigations."""
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_FOR_INFORMATION = "WAITING_FOR_INFORMATION"
    ESCALATED = "ESCALATED"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    VALIDATION = "VALIDATION"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Priority(str, Enum):
    """Priority levels for Investigations and Tasks."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    """Severity ratings for Incidents, Findings, and Evidence."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TaskStatus(str, Enum):
    """Status states for Workflow Tasks."""
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    IN_REVIEW = "IN_REVIEW"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class ApprovalStatus(str, Enum):
    """Status states for Manager / Reviewer Approvals."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"


class BusinessImpact(str, Enum):
    """Business Impact ratings for Risk Assessment."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Likelihood(str, Enum):
    """Likelihood ratings for Risk Assessment."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TagCategory(str, Enum):
    """Entity categorization for Tagging."""
    ASSET = "ASSET"
    EVIDENCE = "EVIDENCE"
    CASE = "CASE"
    USER = "USER"
    THREAT_ACTOR = "THREAT_ACTOR"
    CAMPAIGN = "CAMPAIGN"
    MALWARE = "MALWARE"
    MITRE = "MITRE"
    CUSTOM = "CUSTOM"


class AuditAction(str, Enum):
    """Action categories for Audit Records."""
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    ASSIGN = "ASSIGN"
    STATUS_CHANGE = "STATUS_CHANGE"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    NOTES_EDITED = "NOTES_EDITED"
    TIMELINE_MODIFICATION = "TIMELINE_MODIFICATION"
    AI_RECOMMENDATION = "AI_RECOMMENDATION"
    REPORT_GENERATION = "REPORT_GENERATION"


class EvidenceSource(str, Enum):
    """Origin source of Evidence artifacts."""
    TSHARK = "TSHARK"
    NMAP = "NMAP"
    SYSMON = "SYSMON"
    THREAT_INTEL = "THREAT_INTEL"
    MANUAL = "MANUAL"
    COLLECTOR = "COLLECTOR"
    OTHER = "OTHER"


class IntegrityStatus(str, Enum):
    """Verification integrity status for Evidence checksums."""
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    CORRUPTED = "CORRUPTED"
    TAMPERED = "TAMPERED"
