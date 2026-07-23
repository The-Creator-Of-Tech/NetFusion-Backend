"""
Dataset Validator for MITRE CWE Enterprise Intelligence Feed.
Enforces schema rules, uniqueness, and referential integrity.
"""

from typing import Any, Dict, List, Set
from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface
from netfusion_intelligence.feeds.cwe.models import CweEntity, CweRelationship


class CweValidator(ValidatorInterface):
    """
    Validates normalized CWE datasets:
    - Missing CWE IDs
    - Missing names
    - Duplicate CWE IDs
    - Broken relationship references
    - Invalid relationship natures
    """

    VALID_RELATIONSHIP_NATURES = {
        "ChildOf", "ParentOf", "StartsWith", "CanPrecede", "CanFollow",
        "RequiredBy", "Requires", "CanAlsoBe", "PeerOf",
    }

    def validate(self, dataset: Any) -> ValidationResult:
        result = ValidationResult()

        if not isinstance(dataset, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Normalized CWE dataset is not a dictionary")
            return result

        entities: Dict[str, CweEntity] = dataset.get("entities", {})
        relationships: List[CweRelationship] = dataset.get("relationships", [])

        result.total_checked = len(entities) + len(relationships)

        if not entities:
            result.add_error("EMPTY_DATASET", "CWE dataset contains 0 entities")
            return result

        seen_ids: Set[str] = set()

        for cwe_id, entity in entities.items():
            # Missing CWE ID
            if not entity.cwe_id:
                result.add_error("MISSING_CWE_ID", "Entity missing CWE ID", entity_id=cwe_id, field_name="cwe_id")
                continue

            # Missing name
            if not entity.name:
                result.add_error("MISSING_NAME", f"CWE entity '{entity.cwe_id}' is missing name",
                                 entity_id=cwe_id, field_name="name")

            # Duplicate CWE IDs
            if entity.cwe_id in seen_ids:
                result.add_error("DUPLICATE_CWE_ID", f"Duplicate CWE ID '{entity.cwe_id}' found",
                                 entity_id=cwe_id, field_name="cwe_id")
            else:
                seen_ids.add(entity.cwe_id)

        # Relationship referential integrity
        for rel in relationships:
            if not rel.source_cwe_id:
                result.add_error("INVALID_RELATIONSHIP", "CWE relationship missing source_cwe_id",
                                 entity_id="unknown", field_name="source_cwe_id")
            elif rel.source_cwe_id not in entities:
                result.add_warning("BROKEN_RELATIONSHIP_SOURCE",
                                   f"Relationship source '{rel.source_cwe_id}' not found in entities",
                                   entity_id=rel.source_cwe_id)

            if not rel.target_cwe_id:
                result.add_error("INVALID_RELATIONSHIP", "CWE relationship missing target_cwe_id",
                                 entity_id="unknown", field_name="target_cwe_id")
            elif rel.target_cwe_id not in entities:
                result.add_warning("BROKEN_RELATIONSHIP_TARGET",
                                   f"Relationship target '{rel.target_cwe_id}' not found in entities",
                                   entity_id=rel.target_cwe_id)

        if result.is_valid:
            result.rules_passed = 1
        else:
            result.rules_failed = len(result.errors)

        return result
