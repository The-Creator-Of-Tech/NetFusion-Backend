"""
Tests for CAPEC domain models — immutability, serialization, deserialization.
"""

import pytest

from netfusion_intelligence.feeds.capec.models import (
    CapecCweMapping,
    CapecDetection,
    CapecEntity,
    CapecConsequence,
    CapecExecutionFlowStep,
    CapecMitigation,
    CapecReference,
    CapecRelatedAttackPattern,
    CapecRelationship,
    CapecSkillRequired,
)


class TestCapecEntityImmutability:

    def test_frozen_dataclass(self, sample_capec_entity):
        with pytest.raises((AttributeError, TypeError)):
            sample_capec_entity.name = "Changed"

    def test_frozen_dataclass_capec_id(self, sample_capec_entity):
        with pytest.raises((AttributeError, TypeError)):
            sample_capec_entity.capec_id = "CAPEC-999"


class TestCapecEntitySerialization:

    def test_to_dict_returns_dict(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_capec_id(self, sample_capec_entity):
        assert sample_capec_entity.to_dict()["capec_id"] == "CAPEC-66"

    def test_to_dict_name(self, sample_capec_entity):
        assert "SQL Injection" in sample_capec_entity.to_dict()["name"]

    def test_to_dict_abstraction(self, sample_capec_entity):
        assert sample_capec_entity.to_dict()["abstraction"] == "Standard"

    def test_to_dict_status(self, sample_capec_entity):
        assert sample_capec_entity.to_dict()["status"] == "Stable"

    def test_to_dict_likelihood_of_attack(self, sample_capec_entity):
        assert sample_capec_entity.to_dict()["likelihood_of_attack"] == "High"

    def test_to_dict_typical_severity(self, sample_capec_entity):
        assert sample_capec_entity.to_dict()["typical_severity"] == "High"

    def test_to_dict_execution_flow_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["execution_flow"], list)
        assert len(d["execution_flow"]) == 2

    def test_to_dict_prerequisites_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["prerequisites"], list)

    def test_to_dict_skills_required_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["skills_required"], list)

    def test_to_dict_resources_required_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["resources_required"], list)

    def test_to_dict_indicators_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["indicators"], list)

    def test_to_dict_consequences_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["consequences"], list)

    def test_to_dict_mitigations_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["mitigations"], list)

    def test_to_dict_detection_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["detection"], list)

    def test_to_dict_example_instances_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["example_instances"], list)

    def test_to_dict_related_attack_patterns_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["related_attack_patterns"], list)

    def test_to_dict_related_weaknesses_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["related_weaknesses"], list)
        assert "CWE-89" in d["related_weaknesses"]

    def test_to_dict_taxonomy_mappings_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["taxonomy_mappings"], list)

    def test_to_dict_references_is_list(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        assert isinstance(d["references"], list)

    def test_to_dict_url(self, sample_capec_entity):
        assert "66.html" in sample_capec_entity.to_dict()["url"]


class TestCapecEntityDeserialization:

    def test_round_trip(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert restored.capec_id == sample_capec_entity.capec_id
        assert restored.name == sample_capec_entity.name
        assert restored.abstraction == sample_capec_entity.abstraction
        assert restored.likelihood_of_attack == sample_capec_entity.likelihood_of_attack

    def test_round_trip_execution_flow(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.execution_flow) == 2
        assert restored.execution_flow[0].phase == "Explore"

    def test_round_trip_consequences(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.consequences) == 1
        assert "Confidentiality" in restored.consequences[0].scope

    def test_round_trip_mitigations(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.mitigations) == 1
        assert restored.mitigations[0].strategy == "Input Validation"

    def test_round_trip_detection(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.detection) == 1
        assert restored.detection[0].method == "Web Application Firewall"

    def test_round_trip_related_attack_patterns(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.related_attack_patterns) == 1
        assert restored.related_attack_patterns[0].capec_id == "CAPEC-248"

    def test_round_trip_references(self, sample_capec_entity):
        d = sample_capec_entity.to_dict()
        restored = CapecEntity.from_dict(d)
        assert len(restored.references) == 1
        assert restored.references[0].reference_id == "REF-1"


class TestCapecSubModels:

    def test_execution_flow_step_to_dict(self):
        s = CapecExecutionFlowStep(step_number=1, phase="Explore", description="Recon", techniques=("Scan",))
        d = s.to_dict()
        assert d["step_number"] == 1
        assert d["phase"] == "Explore"
        assert "Scan" in d["techniques"]

    def test_execution_flow_step_round_trip(self):
        s = CapecExecutionFlowStep(step_number=2, phase="Exploit", description="Attack", techniques=("Inject",))
        assert CapecExecutionFlowStep.from_dict(s.to_dict()) == s

    def test_skill_required_to_dict(self):
        sk = CapecSkillRequired(level="Medium", description="Requires knowledge of HTTP.")
        d = sk.to_dict()
        assert d["level"] == "Medium"
        assert "HTTP" in d["description"]

    def test_skill_required_round_trip(self):
        sk = CapecSkillRequired(level="High", description="Advanced programming skills.")
        assert CapecSkillRequired.from_dict(sk.to_dict()) == sk

    def test_consequence_to_dict(self):
        c = CapecConsequence(scope=("Integrity",), impact=("Modify Data",), note="Note", likelihood="High")
        d = c.to_dict()
        assert d["scope"] == ["Integrity"]
        assert d["note"] == "Note"

    def test_consequence_round_trip(self):
        c = CapecConsequence(scope=("Integrity",), impact=("Modify Data",))
        assert CapecConsequence.from_dict(c.to_dict()) == c

    def test_mitigation_to_dict(self):
        m = CapecMitigation(description="Use WAF.", phase=("Operation",), strategy="Filtering", effectiveness="Moderate")
        d = m.to_dict()
        assert d["strategy"] == "Filtering"
        assert "Operation" in d["phase"]

    def test_mitigation_round_trip(self):
        m = CapecMitigation(description="Patch systems.", phase=("Deployment",))
        assert CapecMitigation.from_dict(m.to_dict()) == m

    def test_detection_to_dict(self):
        det = CapecDetection(method="IDS", description="Monitor traffic.", effectiveness="High")
        d = det.to_dict()
        assert d["method"] == "IDS"
        assert d["effectiveness"] == "High"

    def test_detection_round_trip(self):
        det = CapecDetection(method="SIEM", description="Log analysis.", effectiveness="High", effectiveness_notes="Very effective.")
        assert CapecDetection.from_dict(det.to_dict()) == det

    def test_related_attack_pattern_to_dict(self):
        rap = CapecRelatedAttackPattern(capec_id="CAPEC-248", nature="ChildOf", view_id="1000")
        d = rap.to_dict()
        assert d["capec_id"] == "CAPEC-248"
        assert d["nature"] == "ChildOf"

    def test_related_attack_pattern_round_trip(self):
        rap = CapecRelatedAttackPattern(capec_id="CAPEC-66", nature="ParentOf")
        assert CapecRelatedAttackPattern.from_dict(rap.to_dict()) == rap

    def test_reference_to_dict(self):
        ref = CapecReference(
            reference_id="REF-1",
            author=("OWASP",),
            title="SQL Injection",
            url="https://owasp.org",
            publication_year="2021",
        )
        d = ref.to_dict()
        assert d["reference_id"] == "REF-1"
        assert "OWASP" in d["author"]

    def test_reference_round_trip(self):
        ref = CapecReference(
            reference_id="REF-2",
            author=("Author A", "Author B"),
            title="Security Reference",
            edition="3rd",
            url="https://example.com",
            publication_year="2022",
            publisher="Publisher X",
        )
        assert CapecReference.from_dict(ref.to_dict()) == ref

    def test_relationship_to_dict(self, sample_capec_relationship):
        d = sample_capec_relationship.to_dict()
        assert d["source_capec_id"] == "CAPEC-66"
        assert d["target_capec_id"] == "CAPEC-248"
        assert d["nature"] == "ChildOf"
        assert d["view_id"] == "1000"

    def test_cwe_mapping_to_dict(self, sample_cwe_mapping):
        d = sample_cwe_mapping.to_dict()
        assert d["capec_id"] == "CAPEC-66"
        assert d["cwe_id"] == "CWE-89"
        assert d["nature"] == "Exploits"
