"""
Tests for CweValidator — schema rules, uniqueness, referential integrity.
"""

import pytest

from netfusion_intelligence.feeds.cwe.validator import CweValidator
from netfusion_intelligence.feeds.cwe.models import CweEntity, CweRelationship


class TestCweValidatorValidDataset:

    def test_valid_dataset_passes(self, sample_normalized_data):
        v = CweValidator()
        result = v.validate(sample_normalized_data)
        assert result.is_valid is True
        assert result.errors == []

    def test_total_checked_includes_entities_and_relationships(self, sample_normalized_data):
        v = CweValidator()
        result = v.validate(sample_normalized_data)
        # 2 entities + 1 relationship
        assert result.total_checked == 3

    def test_rules_passed_set_on_success(self, sample_normalized_data):
        v = CweValidator()
        result = v.validate(sample_normalized_data)
        assert result.rules_passed >= 1

    def test_returns_validation_result_object(self, sample_normalized_data):
        v = CweValidator()
        result = v.validate(sample_normalized_data)
        assert hasattr(result, "is_valid")
        assert hasattr(result, "errors")
        assert hasattr(result, "warnings")


class TestCweValidatorErrors:

    def test_non_dict_input_is_error(self):
        v = CweValidator()
        result = v.validate("not a dict")
        assert result.is_valid is False
        assert any(e.rule_name == "STRUCTURAL_VALIDATION" for e in result.errors)

    def test_empty_entities_is_error(self):
        v = CweValidator()
        result = v.validate({"entities": {}, "relationships": []})
        assert result.is_valid is False
        assert any(e.rule_name == "EMPTY_DATASET" for e in result.errors)

    def test_missing_cwe_id_is_error(self):
        entity_no_id = CweEntity(cwe_id="", name="Some Weakness")
        v = CweValidator()
        result = v.validate({"entities": {"": entity_no_id}, "relationships": []})
        assert result.is_valid is False
        assert any(e.rule_name == "MISSING_CWE_ID" for e in result.errors)

    def test_missing_name_is_error(self):
        entity_no_name = CweEntity(cwe_id="CWE-999", name="")
        v = CweValidator()
        result = v.validate({"entities": {"CWE-999": entity_no_name}, "relationships": []})
        assert result.is_valid is False
        assert any(e.rule_name == "MISSING_NAME" for e in result.errors)

    def test_duplicate_cwe_id_is_error(self):
        e1 = CweEntity(cwe_id="CWE-79", name="XSS")
        e2 = CweEntity(cwe_id="CWE-79", name="XSS Duplicate")
        v = CweValidator()
        # Two entities with same CWE ID stored under different dict keys (shouldn't happen normally)
        result = v.validate({"entities": {"CWE-79": e1, "CWE-79-dup": e2}, "relationships": []})
        # The second entity has the same cwe_id attribute — should trigger duplicate check
        # We force the duplicate scenario by re-validating with patched entity
        e2_dup = CweEntity(cwe_id="CWE-79", name="XSS Dupe")
        result2 = v.validate({"entities": {"a": e1, "b": e2_dup}, "relationships": []})
        assert result2.is_valid is False
        assert any(e.rule_name == "DUPLICATE_CWE_ID" for e in result2.errors)


class TestCweValidatorRelationshipIntegrity:

    def test_relationship_with_unknown_source_is_warning(self, sample_cwe_entity):
        rel_broken = CweRelationship(
            source_cwe_id="CWE-9999",  # Not in entities
            target_cwe_id="CWE-79",
            nature="ChildOf",
        )
        v = CweValidator()
        data = {
            "entities": {"CWE-79": sample_cwe_entity},
            "relationships": [rel_broken],
        }
        result = v.validate(data)
        # Broken source → warning only (not an error)
        assert any(w.rule_name == "BROKEN_RELATIONSHIP_SOURCE" for w in result.warnings)

    def test_relationship_with_unknown_target_is_warning(self, sample_cwe_entity):
        rel_broken = CweRelationship(
            source_cwe_id="CWE-79",
            target_cwe_id="CWE-9998",  # Not in entities
            nature="ChildOf",
        )
        v = CweValidator()
        data = {
            "entities": {"CWE-79": sample_cwe_entity},
            "relationships": [rel_broken],
        }
        result = v.validate(data)
        assert any(w.rule_name == "BROKEN_RELATIONSHIP_TARGET" for w in result.warnings)

    def test_relationship_missing_source_id_is_error(self, sample_cwe_entity):
        rel_missing_src = CweRelationship(
            source_cwe_id="",
            target_cwe_id="CWE-79",
            nature="ChildOf",
        )
        v = CweValidator()
        data = {
            "entities": {"CWE-79": sample_cwe_entity},
            "relationships": [rel_missing_src],
        }
        result = v.validate(data)
        assert result.is_valid is False
        assert any(e.rule_name == "INVALID_RELATIONSHIP" for e in result.errors)

    def test_relationship_missing_target_id_is_error(self, sample_cwe_entity):
        rel_missing_tgt = CweRelationship(
            source_cwe_id="CWE-79",
            target_cwe_id="",
            nature="ChildOf",
        )
        v = CweValidator()
        data = {
            "entities": {"CWE-79": sample_cwe_entity},
            "relationships": [rel_missing_tgt],
        }
        result = v.validate(data)
        assert result.is_valid is False
        assert any(e.rule_name == "INVALID_RELATIONSHIP" for e in result.errors)

    def test_valid_intra_dataset_relationship_has_no_error(self, sample_cwe_entity, sample_cwe_entity_89):
        rel_valid = CweRelationship(
            source_cwe_id="CWE-79",
            target_cwe_id="CWE-89",
            nature="PeerOf",
        )
        v = CweValidator()
        data = {
            "entities": {"CWE-79": sample_cwe_entity, "CWE-89": sample_cwe_entity_89},
            "relationships": [rel_valid],
        }
        result = v.validate(data)
        assert result.is_valid is True
        # No broken relationship warnings for this one
        broken_src = [w for w in result.warnings if w.rule_name == "BROKEN_RELATIONSHIP_SOURCE"]
        broken_tgt = [w for w in result.warnings if w.rule_name == "BROKEN_RELATIONSHIP_TARGET"]
        assert broken_src == []
        assert broken_tgt == []
