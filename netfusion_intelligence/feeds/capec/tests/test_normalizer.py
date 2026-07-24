"""
Tests for CapecNormalizer — transformation of parsed dicts into domain models.
"""

import pytest

from netfusion_intelligence.feeds.capec.normalizer import CapecNormalizer
from netfusion_intelligence.feeds.capec.parser import CapecParser
from netfusion_intelligence.feeds.capec.models import (
    CapecEntity,
    CapecRelationship,
    CapecCweMapping,
    CapecConsequence,
    CapecDetection,
    CapecExecutionFlowStep,
    CapecMitigation,
    CapecReference,
    CapecRelatedAttackPattern,
    CapecSkillRequired,
)
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML


@pytest.fixture
def normalized():
    p = CapecParser()
    parsed = p.parse(MINIMAL_CAPEC_XML)
    n = CapecNormalizer()
    return n.normalize(parsed)


class TestCapecNormalizerOutput:

    def test_returns_dict(self, normalized):
        assert isinstance(normalized, dict)

    def test_entities_key_present(self, normalized):
        assert "entities" in normalized

    def test_relationships_key_present(self, normalized):
        assert "relationships" in normalized

    def test_cwe_mappings_key_present(self, normalized):
        assert "cwe_mappings" in normalized

    def test_catalog_version_preserved(self, normalized):
        assert normalized["catalog_version"] == "3.9"

    def test_record_count(self, normalized):
        assert normalized["record_count"] == 2

    def test_relationship_count_positive(self, normalized):
        assert normalized["relationship_count"] >= 1

    def test_cwe_mapping_count_positive(self, normalized):
        assert normalized["cwe_mapping_count"] >= 1


class TestCapecNormalizerEntities:

    def test_both_entities_present(self, normalized):
        assert "CAPEC-66" in normalized["entities"]
        assert "CAPEC-86" in normalized["entities"]

    def test_entity_is_capec_entity_instance(self, normalized):
        assert isinstance(normalized["entities"]["CAPEC-66"], CapecEntity)

    def test_entity_capec_id(self, normalized):
        assert normalized["entities"]["CAPEC-66"].capec_id == "CAPEC-66"

    def test_entity_name(self, normalized):
        assert "SQL Injection" in normalized["entities"]["CAPEC-66"].name

    def test_entity_abstraction(self, normalized):
        assert normalized["entities"]["CAPEC-66"].abstraction == "Standard"

    def test_entity_status(self, normalized):
        assert normalized["entities"]["CAPEC-66"].status == "Stable"

    def test_entity_likelihood_of_attack(self, normalized):
        assert normalized["entities"]["CAPEC-66"].likelihood_of_attack == "High"

    def test_entity_typical_severity(self, normalized):
        assert normalized["entities"]["CAPEC-66"].typical_severity == "High"

    def test_entity_description(self, normalized):
        assert normalized["entities"]["CAPEC-66"].description is not None

    def test_entity_execution_flow(self, normalized):
        flow = normalized["entities"]["CAPEC-66"].execution_flow
        assert len(flow) == 2
        assert all(isinstance(s, CapecExecutionFlowStep) for s in flow)
        assert flow[0].phase == "Explore"
        assert flow[1].phase == "Exploit"

    def test_entity_prerequisites(self, normalized):
        prereqs = normalized["entities"]["CAPEC-66"].prerequisites
        assert len(prereqs) == 1

    def test_entity_skills_required(self, normalized):
        skills = normalized["entities"]["CAPEC-66"].skills_required
        assert len(skills) == 1
        assert isinstance(skills[0], CapecSkillRequired)
        assert skills[0].level == "Low"

    def test_entity_consequences(self, normalized):
        cons = normalized["entities"]["CAPEC-66"].consequences
        assert len(cons) == 1
        assert isinstance(cons[0], CapecConsequence)
        assert "Confidentiality" in cons[0].scope

    def test_entity_mitigations(self, normalized):
        mits = normalized["entities"]["CAPEC-66"].mitigations
        assert len(mits) == 1
        assert isinstance(mits[0], CapecMitigation)
        assert mits[0].strategy == "Input Validation"

    def test_entity_detection(self, normalized):
        det = normalized["entities"]["CAPEC-66"].detection
        assert len(det) == 1
        assert isinstance(det[0], CapecDetection)
        assert det[0].method == "Web Application Firewall"

    def test_entity_related_attack_patterns(self, normalized):
        raps = normalized["entities"]["CAPEC-66"].related_attack_patterns
        assert len(raps) == 1
        assert isinstance(raps[0], CapecRelatedAttackPattern)
        assert raps[0].capec_id == "CAPEC-248"

    def test_entity_related_weaknesses(self, normalized):
        rw = normalized["entities"]["CAPEC-66"].related_weaknesses
        assert "CWE-89" in rw
        assert "CWE-20" in rw

    def test_entity_references_enriched(self, normalized):
        refs = normalized["entities"]["CAPEC-66"].references
        assert len(refs) == 1
        assert isinstance(refs[0], CapecReference)
        assert refs[0].reference_id == "REF-1"
        # External ref data should be enriched
        assert refs[0].title == "SQL Injection Prevention Cheat Sheet"

    def test_entity_example_instances(self, normalized):
        examples = normalized["entities"]["CAPEC-66"].example_instances
        assert len(examples) == 1

    def test_entity_is_frozen(self, normalized):
        entity = normalized["entities"]["CAPEC-66"]
        with pytest.raises((AttributeError, TypeError)):
            entity.name = "Modified"


class TestCapecNormalizerRelationships:

    def test_relationships_are_capec_relationship_instances(self, normalized):
        for rel in normalized["relationships"]:
            assert isinstance(rel, CapecRelationship)

    def test_capec66_childof_248(self, normalized):
        rels = normalized["relationships"]
        matching = [r for r in rels if r.source_capec_id == "CAPEC-66" and r.target_capec_id == "CAPEC-248"]
        assert len(matching) == 1
        assert matching[0].nature == "ChildOf"


class TestCapecNormalizerCweMappings:

    def test_cwe_mappings_are_capec_cwe_mapping_instances(self, normalized):
        for m in normalized["cwe_mappings"]:
            assert isinstance(m, CapecCweMapping)

    def test_capec66_mapped_to_cwe89(self, normalized):
        mappings = normalized["cwe_mappings"]
        found = [m for m in mappings if m.capec_id == "CAPEC-66" and m.cwe_id == "CWE-89"]
        assert len(found) == 1

    def test_capec66_mapped_to_cwe20(self, normalized):
        mappings = normalized["cwe_mappings"]
        found = [m for m in mappings if m.capec_id == "CAPEC-66" and m.cwe_id == "CWE-20"]
        assert len(found) == 1

    def test_capec86_mapped_to_cwe79(self, normalized):
        mappings = normalized["cwe_mappings"]
        found = [m for m in mappings if m.capec_id == "CAPEC-86" and m.cwe_id == "CWE-79"]
        assert len(found) == 1


class TestCapecNormalizerEdgeCases:

    def test_rejects_non_dict_input(self):
        n = CapecNormalizer()
        with pytest.raises(ValueError, match="dictionary"):
            n.normalize("not a dict")

    def test_empty_entities_returns_zero_count(self):
        n = CapecNormalizer()
        result = n.normalize({"attack_patterns": [], "external_references": [], "catalog_version": "3.9"})
        assert result["record_count"] == 0
        assert result["entities"] == {}
        assert result["relationships"] == []
        assert result["cwe_mappings"] == []
