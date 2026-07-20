"""
ValidatorInterface and ValidationResult definitions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ValidationErrorItem:
    rule_name: str
    message: str
    entity_id: Optional[str] = None
    field_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationWarningItem:
    rule_name: str
    message: str
    entity_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    """
    Result of running validation rules on a dataset.
    """
    is_valid: bool = True
    errors: List[ValidationErrorItem] = field(default_factory=list)
    warnings: List[ValidationWarningItem] = field(default_factory=list)
    total_checked: int = 0
    rules_passed: int = 0
    rules_failed: int = 0

    def add_error(self, rule_name: str, message: str, entity_id: Optional[str] = None, field_name: Optional[str] = None) -> None:
        self.errors.append(ValidationErrorItem(rule_name=rule_name, message=message, entity_id=entity_id, field_name=field_name))
        self.is_valid = False
        self.rules_failed += 1

    def add_warning(self, rule_name: str, message: str, entity_id: Optional[str] = None) -> None:
        self.warnings.append(ValidationWarningItem(rule_name=rule_name, message=message, entity_id=entity_id))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
            "total_checked": self.total_checked,
            "rules_passed": self.rules_passed,
            "rules_failed": self.rules_failed,
        }


class ValidatorInterface(ABC):
    """
    Abstract interface for generic dataset validators.
    """

    @abstractmethod
    def validate(self, dataset: Any) -> ValidationResult:
        """Validate dataset against rules."""
        pass
