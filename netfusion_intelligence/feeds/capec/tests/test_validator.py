"""
Tests for CapecValidator — schema rules, uniqueness, referential integrity.
"""

import pytest

from netfusion_intelligence.feeds.capec.validator import CapecValidator
from netfusion_intelligence.feeds.capec.models import CapecEntity, CapecRelationship, CapecCweMapping


class TestCapecValidatorValidDataset:

    def test_valid_dataset_passes(self, sample_normalized_data):
        v = CapecValidator()
        result = v.validate(sample_normalized_data)
        assert result.is_valid is True
        assert result.errors == []

    def test_total_checked_includes_entities_relationships_mappings(self, sample_normalized_data):
        v = CapecValidator()
        result = v.validate(sample_normalized_data)
        # 2 entities + 1 relationship + 1 cwe_mapping
        assert result.total_checked == 4

    def test_rules_passed_set_on_success(self, sample_normalized_data):
        v = CapecValidator()
        result = v.validate(sample_normalized_data)
        assert result.rules_passed >= 1

    def test_returns_validation_result_object(self, sample_normalized_data):
        v = CapecValidator()
        result = v.validate(sample_normalized_data)
        assert hasattr(result, "is_valid")
        assert hasattr(result, "errors")
        assert hasattr(result, "warnings")


class TestCapecValidatorErrors:

    def test_non_dict_input_is_error(self):
        v = CapecValidator()
        result = v.validate("not a dict")
        assert result.is_valid is False
        assert any(e.rule_name == "STRUCTURAL_VALIDATION" for e in result.errors)

    def test_empty_entities_is_error(self):
        v = CapecValidator()
        result = v.validate({"entities": {}, "relationships": [], "cwe_mappings": []})
        assert result.is_valid is False
        assert any(e.rule_name == "EMPTY_DATASET" for e in result.errors)

    def test_missing_capec_id_is_error(self):
        entity_no_id = CapecEntity(capec_id="", name="Some Attack")
        v = CapecValidator()
        result = v.validate({"entities": {"": entity_no_id}, "relationships": [], "cwe_mappings": []})
        assert result.is_valid is False
        assert any(e.rule_name == "MISSING_CAPEC_ID" for e in result.errors)

    def test_missing_name_is_error(self):
        entity_no_name = CapecEntity(capec_id="CAPEC-999", name="")
        v = CapecValidator()
        result = v.validate({"entities": {"CAPEC-999": entity_no_name}, "relationships": [], "cwe_mappings": []})
        assert result.is_valid is False
        assert any(e.rule_name == "MISSING_NAME" for e in result.errors)

    def test_duplicate_capec_id_is_error(self):
        e1 = CapecEntity(capec_id="CAPEC-66", name="SQL Injection")
        e2 = CapecEntity(capec_id="CAPEC-66", name="SQL Injection Dupe")
        v = CapecValidator()
        result = v.validate({"entities": {"a": e1, "b": e2}, "relationships": [], "cwe_mappings": []})
        assert result.is_valid is False
        assert any(e.rule_name == "DUPLICATE_CAPEC_ID" for e in result.errors)


class TestCapecValidatorRelationshipIntegrity:

    def test_relationship_with_unknown_source_is_warning(self, sample_capec_entity):
        rel_broken = CapecRelationship(
            source_capec_id="CAPEC-9999",
            target_capec_id="CAPEC-66",
            nature="ChildOf",
        )
        v = CapecValidator()
        data = {
            "entities": {"CAPEC-66": sample_capec_entity},
            "relationships": [rel_broken],
            "cwe_mappings": [],
        }
        result = v.validate(data)
        assert any(w.rule_name == "BROKEN_RELATIONSHIP_SOURCE" for w in result.warnings)

    def test_relationship_with_unknown_target_is_warning(self, sample_capec_entity):
        rel_broken = CapecRelationship(
            source_capec_id="CAPEC-66",
            target_capec_id="CAPEC-9998",
            nature="ChildOf",
        )
        v = CapecValidator()
        data = {
            "entities": {"CAPEC-66": sample_capec_entity},
            "relationships": [rel_broken],
            "cwe_mappings": [],
        }
        result = v.validate(data)
        assert any(w.rule_name == "BROKEN_RELATIONSHIP_TARGET" for w in result.warnings)

    def test_relationship_missing_source_id_is_error(self, sample_capec_entity):
        rel_missing = CapecRelationship(
            source_capec_id="",
            target_capec_id="CAPEC-66",
            nature="ChildOf",
        )
        v = CapecValidator()
        data = {
            "entities": {"CAPEC-66": sample_capec_entity},
            "relationships": [rel_missing],
            "cwe_mappings": [],
        }
        result = v.validate(data)
        assert result.is_valid is False
        assert any(e.rule_name == "INVALID_RELATIONSHIP" for e in result.errors)

    def test_relationship_missing_target_id_is_error(self, sample_capec_entity):
        rel_missing = CapecRelationship(
            source_capec_id="CAPEC-66",
            target_capec_id="",
            nature="ChildOf",
        )
        v = CapecValidator()
        data = {
            "entities": {"CAPEC-66": sample_capec_entity},
            "relationships": [rel_missing],
            "cwe_mappings": [],
        }
        result = v.validate(data)
        assert result.is_valid is False
        assert any(e.rule_name == "INVALID_RELATIONSHIP" for e in result.errors)

    def test_valid_intra_dataset_relationship_no_error(self, sample_capec_entity, sample_capec_entity_86):
        rel_valid = CapecRelationship(
            source_capec_id="CAPEC-66",
            target_capec_id="CAPEC-86",
            nature="PeerOf",
        )
        v = CapecValidator()
        data = {
            "entities": {
                "CAPEC-66": sample_capec_entity,
                "CAPEC-86": sample_capec_entity_86,
            },
            "relationships": [rel_valid],
            "cwe_mappings": [],
        }
        result = v.validate(data)
        assert result.is_valid is True
