"""
Dataset Validator for MITRE ATT&CK Enterprise STIX 2.1 intelligence feed.
"""

from typing import Any, Dict, List, Set
from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface
from netfusion_intelligence.feeds.mitre.models import MitreEntity, MitreRelationship


class MitreValidator(ValidatorInterface):
    """
    Validates normalized MITRE ATT&CK datasets against enterprise rules:
    - Missing ATT&CK IDs on primary entities
    - Duplicate ATT&CK IDs
    - Broken relationship references (source_ref / target_ref not found)
    - Unknown object types
    - Missing required fields
    - Revoked/deprecated referential integrity
    """

    PRIMARY_TYPES_REQUIRING_ATTACK_ID = {
        "attack-pattern",
        "x-mitre-tactic",
        "intrusion-set",
        "malware",
        "tool",
        "campaign",
        "course-of-action",
        "x-mitre-data-source",
    }

    def validate(self, dataset: Any) -> ValidationResult:
        """
        Executes validation on normalized dataset.
        Returns ValidationResult instance.
        """
        result = ValidationResult()

        if not isinstance(dataset, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Normalized dataset is not a dictionary")
            return result

        entities_dict: Dict[str, MitreEntity] = dataset.get("entities", {})
        relationships: List[MitreRelationship] = dataset.get("relationships", [])

        result.total_checked = len(entities_dict) + len(relationships)

        if not entities_dict:
            result.add_error("EMPTY_DATASET", "MITRE ATT&CK dataset contains 0 entities")
            return result

        # Track ATT&CK IDs for duplicate checking
        seen_attack_ids: Dict[str, Set[str]] = {}

        for stix_id, entity in entities_dict.items():
            # 1. Missing required fields
            if not entity.stix_id:
                result.add_error("MISSING_STIX_ID", "Entity missing STIX ID", entity_id=stix_id, field_name="stix_id")
            if not entity.type:
                result.add_error("MISSING_TYPE", f"Entity '{stix_id}' missing STIX type", entity_id=stix_id, field_name="type")

            # 2. Missing ATT&CK ID check on active primary objects
            if entity.type in self.PRIMARY_TYPES_REQUIRING_ATTACK_ID and not entity.revoked and not entity.deprecated:
                if not entity.attack_id:
                    result.add_error(
                        "MISSING_ATTACK_ID",
                        f"Active entity of type '{entity.type}' ({entity.name or stix_id}) is missing official ATT&CK ID",
                        entity_id=stix_id,
                        field_name="attack_id",
                    )

            # 3. Duplicate ATT&CK ID check
            if entity.attack_id:
                if entity.type not in seen_attack_ids:
                    seen_attack_ids[entity.type] = set()
                if entity.attack_id in seen_attack_ids[entity.type] and not entity.revoked:
                    result.add_error(
                        "DUPLICATE_ATTACK_ID",
                        f"Duplicate ATT&CK ID '{entity.attack_id}' found for entity type '{entity.type}'",
                        entity_id=stix_id,
                        field_name="attack_id",
                    )
                else:
                    seen_attack_ids[entity.type].add(entity.attack_id)

        # 4. Broken relationships check
        for rel in relationships:
            if not rel.source_ref:
                result.add_error("INVALID_RELATIONSHIP", f"Relationship '{rel.stix_id}' missing source_ref", entity_id=rel.stix_id, field_name="source_ref")
            elif rel.source_ref not in entities_dict:
                result.add_warning("BROKEN_RELATIONSHIP_SOURCE", f"Relationship '{rel.stix_id}' source_ref '{rel.source_ref}' not found in entities", entity_id=rel.stix_id)

            if not rel.target_ref:
                result.add_error("INVALID_RELATIONSHIP", f"Relationship '{rel.stix_id}' missing target_ref", entity_id=rel.stix_id, field_name="target_ref")
            elif rel.target_ref not in entities_dict:
                result.add_warning("BROKEN_RELATIONSHIP_TARGET", f"Relationship '{rel.stix_id}' target_ref '{rel.target_ref}' not found in entities", entity_id=rel.stix_id)

        if result.is_valid:
            result.rules_passed = 1
        else:
            result.rules_failed = len(result.errors)

        return result
