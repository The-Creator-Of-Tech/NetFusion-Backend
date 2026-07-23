"""
Tests for CWE domain models — immutability, serialization, deserialization.
"""

import pytest

from netfusion_intelligence.feeds.cwe.models import (
    CweApplicablePlatform,
    CweConsequence,
    CweDetectionMethod,
    CweEntity,
    CweMitigation,
    CweModeOfIntroduction,
    CweReference,
    CweRelatedWeakness,
    CweRelationship,
    CweTaxonomyMapping,
)


class TestCweEntityImmutability:

    def test_frozen_dataclass(self, sample_cwe_entity):
        with pytest.raises((AttributeError, TypeError)):
            sample_cwe_entity.name = "Changed"

    def test_frozen_dataclass_cwe_id(self, sample_cwe_entity):
        with pytest.raises((AttributeError, TypeError)):
            sample_cwe_entity.cwe_id = "CWE-999"


class TestCweEntitySerialization:

    def test_to_dict_returns_dict(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_cwe_id(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert d["cwe_id"] == "CWE-79"

    def test_to_dict_name(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert "Improper Neutralization" in d["name"]

    def test_to_dict_abstraction(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert d["abstraction"] == "Base"

    def test_to_dict_structure(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert d["structure"] == "Simple"

    def test_to_dict_status(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert d["status"] == "Stable"

    def test_to_dict_likelihood(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert d["likelihood_of_exploit"] == "High"

    def test_to_dict_alternate_terms_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["alternate_terms"], list)
        assert "XSS" in d["alternate_terms"]

    def test_to_dict_modes_of_introduction_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["modes_of_introduction"], list)
        assert len(d["modes_of_introduction"]) == 1

    def test_to_dict_consequences_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["consequences"], list)

    def test_to_dict_mitigations_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["mitigations"], list)

    def test_to_dict_detection_methods_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["detection_methods"], list)

    def test_to_dict_related_weaknesses_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["related_weaknesses"], list)

    def test_to_dict_related_attack_patterns_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["related_attack_patterns"], list)
        assert "CAPEC-86" in d["related_attack_patterns"]

    def test_to_dict_references_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["references"], list)

    def test_to_dict_taxonomy_mappings_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["taxonomy_mappings"], list)

    def test_to_dict_affected_resources_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["affected_resources"], list)

    def test_to_dict_functional_areas_is_list(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert isinstance(d["functional_areas"], list)

    def test_to_dict_url(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        assert "79.html" in d["url"]


class TestCweEntityDeserialization:

    def test_round_trip(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert restored.cwe_id == sample_cwe_entity.cwe_id
        assert restored.name == sample_cwe_entity.name
        assert restored.abstraction == sample_cwe_entity.abstraction
        assert restored.likelihood_of_exploit == sample_cwe_entity.likelihood_of_exploit

    def test_round_trip_modes_of_introduction(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.modes_of_introduction) == 1
        assert restored.modes_of_introduction[0].phase == "Implementation"

    def test_round_trip_consequences(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.consequences) == 1
        assert "Confidentiality" in restored.consequences[0].scope

    def test_round_trip_mitigations(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.mitigations) == 1
        assert restored.mitigations[0].strategy == "Output Encoding"

    def test_round_trip_detection_methods(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.detection_methods) == 1
        assert restored.detection_methods[0].method == "Automated Static Analysis"

    def test_round_trip_related_weaknesses(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.related_weaknesses) == 1
        assert restored.related_weaknesses[0].cwe_id == "CWE-74"

    def test_round_trip_references(self, sample_cwe_entity):
        d = sample_cwe_entity.to_dict()
        restored = CweEntity.from_dict(d)
        assert len(restored.references) == 1
        assert restored.references[0].reference_id == "REF-7"


class TestCweSubModels:

    def test_cwe_consequence_to_dict(self):
        c = CweConsequence(scope=("Integrity",), impact=("Modify Data",), note="Note", likelihood="Medium")
        d = c.to_dict()
        assert d["scope"] == ["Integrity"]
        assert d["impact"] == ["Modify Data"]
        assert d["note"] == "Note"

    def test_cwe_consequence_round_trip(self):
        c = CweConsequence(scope=("Integrity",), impact=("Modify Data",))
        assert CweConsequence.from_dict(c.to_dict()) == c

    def test_cwe_mitigation_to_dict(self):
        m = CweMitigation(phase=("Architecture",), description="Use parameterized queries", strategy="Parameterization")
        d = m.to_dict()
        assert "Architecture" in d["phase"]
        assert d["strategy"] == "Parameterization"

    def test_cwe_mitigation_round_trip(self):
        m = CweMitigation(phase=("Architecture",), description="Desc", strategy="Strategy", effectiveness="High")
        assert CweMitigation.from_dict(m.to_dict()) == m

    def test_cwe_detection_method_to_dict(self):
        dm = CweDetectionMethod(method="Manual Analysis", description="Code review", effectiveness="Moderate")
        d = dm.to_dict()
        assert d["method"] == "Manual Analysis"
        assert d["effectiveness"] == "Moderate"

    def test_cwe_detection_method_round_trip(self):
        dm = CweDetectionMethod(method="Dynamic Analysis", description="Fuzzing", effectiveness="High")
        assert CweDetectionMethod.from_dict(dm.to_dict()) == dm

    def test_cwe_related_weakness_to_dict(self):
        rw = CweRelatedWeakness(cwe_id="CWE-74", nature="ChildOf", view_id="1000", ordinal="Primary")
        d = rw.to_dict()
        assert d["cwe_id"] == "CWE-74"
        assert d["nature"] == "ChildOf"

    def test_cwe_related_weakness_round_trip(self):
        rw = CweRelatedWeakness(cwe_id="CWE-74", nature="ChildOf", view_id="1000")
        assert CweRelatedWeakness.from_dict(rw.to_dict()) == rw

    def test_cwe_taxonomy_mapping_to_dict(self):
        tm = CweTaxonomyMapping(taxonomy_name="OWASP", entry_id="A01", entry_name="Broken Access Control")
        d = tm.to_dict()
        assert d["taxonomy_name"] == "OWASP"
        assert d["entry_id"] == "A01"

    def test_cwe_taxonomy_mapping_round_trip(self):
        tm = CweTaxonomyMapping(taxonomy_name="OWASP", entry_id="A01", entry_name="BAC", mapping_fit="Exact")
        assert CweTaxonomyMapping.from_dict(tm.to_dict()) == tm

    def test_cwe_reference_to_dict(self):
        ref = CweReference(
            reference_id="REF-1",
            author=("Author A",),
            title="A Book",
            url="https://example.com",
            publication_year="2020",
        )
        d = ref.to_dict()
        assert d["reference_id"] == "REF-1"
        assert "Author A" in d["author"]

    def test_cwe_reference_round_trip(self):
        ref = CweReference(
            reference_id="REF-1",
            author=("Author A",),
            title="Title",
            edition="1st",
            url="https://example.com",
            publication_year="2020",
            publisher="Publisher Inc",
        )
        assert CweReference.from_dict(ref.to_dict()) == ref

    def test_cwe_applicable_platform_to_dict(self):
        p = CweApplicablePlatform(platform_type="Language", name="C", prevalence="Often", class_="Not Language-Specific")
        d = p.to_dict()
        assert d["platform_type"] == "Language"
        assert d["name"] == "C"
        assert d["class"] == "Not Language-Specific"

    def test_cwe_applicable_platform_round_trip(self):
        p = CweApplicablePlatform(platform_type="Technology", name="Web Server", prevalence="Sometimes")
        assert CweApplicablePlatform.from_dict(p.to_dict()) == p

    def test_cwe_mode_of_introduction_to_dict(self):
        m = CweModeOfIntroduction(phase="Design", note="During architecture")
        d = m.to_dict()
        assert d["phase"] == "Design"
        assert d["note"] == "During architecture"

    def test_cwe_mode_of_introduction_round_trip(self):
        m = CweModeOfIntroduction(phase="Testing", note="During QA")
        assert CweModeOfIntroduction.from_dict(m.to_dict()) == m

    def test_cwe_relationship_to_dict(self, sample_relationship):
        d = sample_relationship.to_dict()
        assert d["source_cwe_id"] == "CWE-79"
        assert d["target_cwe_id"] == "CWE-74"
        assert d["nature"] == "ChildOf"
        assert d["view_id"] == "1000"
        assert d["ordinal"] == "Primary"
