"""
NetFusion Workflow Exceptions
Enterprise exception hierarchy for workflow, case lifecycle, task dependencies,
evidence integrity, assignment, search, and reporting modules.
"""


class WorkflowError(Exception):
    """Base exception for all workflow and case management errors."""
    pass


class EntityNotFoundError(WorkflowError):
    """Raised when a requested domain entity (Case, Investigation, Task, Evidence, etc.) cannot be found."""
    pass


class InvalidLifecycleTransitionError(WorkflowError):
    """Raised when an illegal case/investigation lifecycle state transition is attempted."""
    pass


class TaskDependencyError(WorkflowError):
    """Raised when task completion or execution violates task dependency rules."""
    pass


class EvidenceIntegrityError(WorkflowError):
    """Raised when evidence hash check fails or chain of custody integrity is compromised."""
    pass


class AssignmentError(WorkflowError):
    """Raised when an invalid assignment or approval workflow state is encountered."""
    pass


class SearchError(WorkflowError):
    """Raised when search query validation or execution fails."""
    pass


class ReportMetadataError(WorkflowError):
    """Raised when report metadata generation encounters structural errors or missing required fields."""
    pass
