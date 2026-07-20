"""
NetFusion Case Lifecycle State Machine
Governs state transitions across all 11 lifecycle states:
NEW, TRIAGED, IN_PROGRESS, WAITING_FOR_INFORMATION, ESCALATED,
CONTAINMENT, ERADICATION, RECOVERY, VALIDATION, CLOSED, FALSE_POSITIVE.
"""

import time
from typing import Dict, Set, Union

from .domain import Case, Investigation, AuditRecord
from .enums import AuditAction, CaseLifecycle
from .exceptions import InvalidLifecycleTransitionError

# Define allowed transitions between CaseLifecycle states
ALLOWED_TRANSITIONS: Dict[CaseLifecycle, Set[CaseLifecycle]] = {
    CaseLifecycle.NEW: {
        CaseLifecycle.TRIAGED,
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.FALSE_POSITIVE,
        CaseLifecycle.CLOSED,
    },
    CaseLifecycle.TRIAGED: {
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.WAITING_FOR_INFORMATION,
        CaseLifecycle.ESCALATED,
        CaseLifecycle.FALSE_POSITIVE,
        CaseLifecycle.CLOSED,
    },
    CaseLifecycle.IN_PROGRESS: {
        CaseLifecycle.WAITING_FOR_INFORMATION,
        CaseLifecycle.ESCALATED,
        CaseLifecycle.CONTAINMENT,
        CaseLifecycle.ERADICATION,
        CaseLifecycle.RECOVERY,
        CaseLifecycle.VALIDATION,
        CaseLifecycle.CLOSED,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.WAITING_FOR_INFORMATION: {
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.TRIAGED,
        CaseLifecycle.ESCALATED,
        CaseLifecycle.CLOSED,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.ESCALATED: {
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.CONTAINMENT,
        CaseLifecycle.ERADICATION,
        CaseLifecycle.RECOVERY,
        CaseLifecycle.VALIDATION,
        CaseLifecycle.CLOSED,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.CONTAINMENT: {
        CaseLifecycle.ERADICATION,
        CaseLifecycle.RECOVERY,
        CaseLifecycle.VALIDATION,
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.CLOSED,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.ERADICATION: {
        CaseLifecycle.RECOVERY,
        CaseLifecycle.VALIDATION,
        CaseLifecycle.CONTAINMENT,
        CaseLifecycle.CLOSED,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.RECOVERY: {
        CaseLifecycle.VALIDATION,
        CaseLifecycle.CLOSED,
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.VALIDATION: {
        CaseLifecycle.CLOSED,
        CaseLifecycle.RECOVERY,
        CaseLifecycle.IN_PROGRESS,
        CaseLifecycle.FALSE_POSITIVE,
    },
    CaseLifecycle.CLOSED: {
        CaseLifecycle.IN_PROGRESS,  # Reopening case/investigation
        CaseLifecycle.VALIDATION,
    },
    CaseLifecycle.FALSE_POSITIVE: {
        CaseLifecycle.IN_PROGRESS,  # Reopening case/investigation
        CaseLifecycle.TRIAGED,
    },
}


class LifecycleEngine:
    """Engine responsible for enforcing lifecycle rules and transitioning Cases and Investigations."""

    @staticmethod
    def is_transition_allowed(from_state: CaseLifecycle, to_state: CaseLifecycle) -> bool:
        """Checks if a transition between two lifecycle states is allowed."""
        if from_state == to_state:
            return True
        allowed = ALLOWED_TRANSITIONS.get(from_state, set())
        return to_state in allowed

    @classmethod
    def transition(
        cls,
        target: Union[Case, Investigation],
        new_status: CaseLifecycle,
        actor: str = "system",
        reason: str = "",
    ) -> AuditRecord:
        """
        Transitions a Case or Investigation to a new lifecycle state.
        Enforces validity rules and returns an AuditRecord.
        """
        old_status = target.status
        if isinstance(old_status, str):
            old_status = CaseLifecycle(old_status)
        if isinstance(new_status, str):
            new_status = CaseLifecycle(new_status)

        if not cls.is_transition_allowed(old_status, new_status):
            raise InvalidLifecycleTransitionError(
                f"Cannot transition from {old_status.value} to {new_status.value}. "
                f"Allowed target states: {[s.value for s in ALLOWED_TRANSITIONS.get(old_status, set())]}"
            )

        # Enforce closure requirements if transitioning to CLOSED
        if new_status in (CaseLifecycle.CLOSED, CaseLifecycle.FALSE_POSITIVE):
            if isinstance(target, Investigation):
                if not target.final_verdict and not target.root_cause and not reason:
                    target.final_verdict = f"Closed as {new_status.value}: {reason or 'No verdict specified.'}"
            target.closed_time if hasattr(target, "closed_time") else setattr(target, "closed_at", time.time())
            if hasattr(target, "closed_time"):
                target.closed_time = time.time()
            if hasattr(target, "closed_at"):
                target.closed_at = time.time()

        target.status = new_status
        now = time.time()
        if hasattr(target, "updated_time"):
            target.updated_time = now
        if hasattr(target, "updated_at"):
            target.updated_at = now

        entity_type = "Investigation" if isinstance(target, Investigation) else "Case"
        entity_id = target.investigation_id if isinstance(target, Investigation) else target.case_id

        audit_entry = AuditRecord(
            action=AuditAction.STATUS_CHANGE,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            timestamp=now,
            changes={
                "old_status": old_status.value,
                "new_status": new_status.value,
                "reason": reason,
            },
        )
        return audit_entry
