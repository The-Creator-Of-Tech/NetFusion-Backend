"""
Generic validation framework and reusable validation rules.
"""

from typing import Any, Dict, List, Optional, Set
from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface


class GenericValidationEngine(ValidatorInterface):
    """
    Generic validation engine executing a suite of dataset validation checks.
    """

    def __init__(self, check_duplicates: bool = True, check_missing_fields: bool = True, required_fields: Optional[List[str]] = None):
        self.check_duplicates = check_duplicates
        self.check_missing_fields = check_missing_fields
        self.required_fields = required_fields or ["id"]

    def validate(self, dataset: Any) -> ValidationResult:
        result = ValidationResult()

        if dataset is None:
            result.add_error("InvalidSchemaRule", "Dataset is None")
            return result

        items: List[Dict[str, Any]] = []
        if isinstance(dataset, list):
            items = dataset
        elif isinstance(dataset, dict):
            if "items" in dataset and isinstance(dataset["items"], list):
                items = dataset["items"]
            elif "records" in dataset and isinstance(dataset["records"], list):
                items = dataset["records"]
            else:
                items = [dataset]

        result.total_checked = len(items)
        seen_ids: Set[str] = set()

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                result.add_error("InvalidSchemaRule", f"Item at index {idx} is not a dictionary", entity_id=str(idx))
                continue

            # Check required fields
            if self.check_missing_fields:
                for f in self.required_fields:
                    if f not in item or item[f] is None or item[f] == "":
                        result.add_error("MissingRequiredFieldsRule", f"Missing required field '{f}'", field_name=f)

            # Check duplicate identifiers
            if self.check_duplicates:
                entity_id = item.get("id") or item.get("id_str") or item.get("uuid")
                if entity_id:
                    entity_id_str = str(entity_id)
                    if entity_id_str in seen_ids:
                        result.add_error("DuplicateIdentifierRule", f"Duplicate entity identifier detected: '{entity_id_str}'", entity_id=entity_id_str)
                    else:
                        seen_ids.add(entity_id_str)

            # Check relationships & orphan references
            refs = item.get("references") or item.get("relationships") or item.get("relates_to")
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, str) and not ref:
                        result.add_error("BrokenRelationshipRule", "Empty reference found", entity_id=item.get("id"))
                    elif isinstance(ref, dict):
                        target_id = ref.get("target_id") or ref.get("id")
                        if not target_id:
                            result.add_error("OrphanReferenceRule", "Reference target ID is missing", entity_id=item.get("id"))

        if result.is_valid:
            result.rules_passed = result.total_checked
        return result


def validate_checksum(content: Any, expected_checksum: str) -> ValidationResult:
    """
    Validation helper to verify content against expected checksum.
    """
    from netfusion_intelligence.utils.checksum import verify_checksum

    result = ValidationResult()
    result.total_checked = 1
    if not verify_checksum(content, expected_checksum):
        result.add_error("ChecksumMismatchRule", f"Checksum verification failed. Expected: '{expected_checksum}'")
    else:
        result.rules_passed = 1
    return result
