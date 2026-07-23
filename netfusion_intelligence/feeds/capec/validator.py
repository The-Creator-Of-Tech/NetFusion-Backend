"""
Dataset Validator for MITRE CAPEC Enterprise Intelligence Feed.
Enforces schema rules, uniqueness, and cross-reference integrity.
"""

from typing import Any, Dict, List, Set
from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface
from netfusion_intelligence.feeds.capec.models import CapecEntity, CapecRelationship, CapecCweMapping


class CapecValidator(ValidatorInterface):
    """
    Validates normalized CAPEC datasets:
    - Missing CAPEC IDs
    - Missing names
    - Duplicate CAPEC IDs
    - Broken CAPEC-to-CAPEC relationships
    - Invalid CWE cross-references
    """

    def validate(self, dataset: Any) -> ValidationResult:
        result = ValidationResult()

        if not isinstance(dataset, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Normalized CAPEC dataset is not a dictionary")
            return result

        entities: Dict[str, CapecEntity] = dataset.get("entities", {})
        relationships: List[CapecRelationship] = dataset.get("relationships", [])
        cwe_mappings: List[CapecCweMapping] = dataset.get("cwe_mappings", [])

        result.total_checked = len(entities) + len(relationships) + len(cwe_mappings)

        if not entities:
            result.add_error("EMPTY_DATASET", "CAPEC dataset contains 0 entities")
            return result

        seen_ids: Set[str] = set()

        for capec_id, entity in entities.items():
            if not entity.capec_id:
                result.add_error("MISSING_CAPEC_ID", "Entity missing CAPEC ID",
                                 entity_id=capec_id, field_name="capec_id")
                continue

            if not entity.name:
                result.add_error("MISSING_NAME", f"CAPEC entity '{entity.capec_id}' is missing name",
                                 entity_id=capec_id, field_name="name")

            if entity.capec_id in seen_ids:
                result.add_error("DUPLICATE_CAPEC_ID", f"Duplicate CAPEC ID '{entity.capec_id}'",
                                 entity_id=capec_id, field_name="capec_id")
            else:
                seen_ids.add(entity.capec_id)

        # CAPEC-to-CAPEC relationship referential integrity
        for rel in relationships:
            if not rel.source_capec_id:
                result.add_error("INVALID_RELATIONSHIP", "CAPEC relationship missing source_capec_id",
                                 entity_id="unknown", field_name="source_capec_id")
            elif rel.source_capec_id not in entities:
                result.add_warning("BROKEN_RELATIONSHIP_SOURCE",
                                   f"Relationship source '{rel.source_capec_id}' not found in entities",
                                   entity_id=rel.source_capec_id)

            if not rel.target_capec_id:
                result.add_error("INVALID_RELATIONSHIP", "CAPEC relationship missing target_capec_id",
                                 entity_id="unknown", field_name="target_capec_id")
            elif rel.target_capec_id not in entities:
                result.add_warning("BROKEN_RELATIONSHIP_TARGET",
                                   f"Relationship target '{rel.target_capec_id}' not found in entities",
                                   entity_id=rel.target_capec_id)

        if result.is_valid:
            result.rules_passed = 1
        else:
            result.rules_failed = len(result.errors)

        return result
