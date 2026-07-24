"""
Tests for CweNormalizer — transformation of parsed dicts into domain models.
"""

import pytest

from netfusion_intelligence.feeds.cwe.normalizer import CweNormalizer
from netfusion_intelligence.feeds.cwe.parser import CweParser
from netfusion_intelligence.feeds.cwe.models import (
    CweEntity,
    CweRelationship,
    CweApplicablePlatform,
    CweConsequence,
    CweDetectionMethod,
    CweMitigation,
    CweModeOfIntroduction,
    CweReference,
    CweRelatedWeakness,
    CweTaxonomyMapping,
)
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML


@pytest.fixture
def normalized():
    p = CweParser()
    parsed = p.parse(MINIMAL_CWE_XML)
    n = CweNormalizer()
    return n.normalize(parsed)


class TestCweNormalizerOutput:

    def test_returns_dict(self, normalized):
        assert isinstance(normalized, dict)

    def test_entities_key_present(self, normalized):
        assert "entities" in normalized

    def test_relationships_key_present(self, normalized):
        assert "relationships" in normalized

    def test_catalog_version_preserved(self, normalized):
        assert normalized["catalog_version"] == "4.15"

    def test_record_count(self, normalized):
        assert normalized["record_count"] == 2

    def test_relationship_count_positive(self, normalized):
        # At least one relationship from CWE-79 → CWE-74 and CWE-89 → CWE-943
        assert normalized["relationship_count"] >= 1


class TestCweNormalizerEntities:

    def test_both_entities_present(self, normalized):
        entities = normalized["entities"]
        assert "CWE-79" in entities
        assert "CWE-89" in entities

    def test_entity_is_cwe_entity_instance(self, normalized):
        assert isinstance(normalized["entities"]["CWE-79"], CweEntity)

    def test_entity_cwe_id(self, normalized):
        assert normalized["entities"]["CWE-79"].cwe_id == "CWE-79"

    def test_entity_name(self, normalized):
        assert "Improper Neutralization" in normalized["entities"]["CWE-79"].name

    def test_entity_abstraction(self, normalized):
        assert normalized["entities"]["CWE-79"].abstraction == "Base"

    def test_entity_structure(self, normalized):
        assert normalized["entities"]["CWE-79"].structure == "Simple"

    def test_entity_status(self, normalized):
        assert normalized["entities"]["CWE-79"].status == "Stable"

    def test_entity_likelihood_of_exploit(self, normalized):
        assert normalized["entities"]["CWE-79"].likelihood_of_exploit == "High"

    def test_entity_description(self, normalized):
        assert normalized["entities"]["CWE-79"].description is not None

    def test_entity_modes_of_introduction(self, normalized):
        modes = normalized["entities"]["CWE-79"].modes_of_introduction
        assert len(modes) == 1
        assert isinstance(modes[0], CweModeOfIntroduction)
        assert modes[0].phase == "Implementation"

    def test_entity_applicable_platforms(self, normalized):
        platforms = normalized["entities"]["CWE-79"].applicable_platforms
        assert len(platforms) == 2
        assert all(isinstance(p, CweApplicablePlatform) for p in platforms)

    def test_entity_consequences(self, normalized):
        cons = normalized["entities"]["CWE-79"].consequences
        assert len(cons) == 1
        assert isinstance(cons[0], CweConsequence)
        assert "Confidentiality" in cons[0].scope

    def test_entity_detection_methods(self, normalized):
        dms = normalized["entities"]["CWE-79"].detection_methods
        assert len(dms) == 1
        assert isinstance(dms[0], CweDetectionMethod)
        assert dms[0].method == "Automated Static Analysis"

    def test_entity_mitigations(self, normalized):
        mits = normalized["entities"]["CWE-79"].mitigations
        assert len(mits) == 1
        assert isinstance(mits[0], CweMitigation)
        assert "Implementation" in mits[0].phase

    def test_entity_related_weaknesses(self, normalized):
        rw = normalized["entities"]["CWE-79"].related_weaknesses
        assert len(rw) == 1
        assert isinstance(rw[0], CweRelatedWeakness)
        assert rw[0].cwe_id == "CWE-74"
        assert rw[0].nature == "ChildOf"

    def test_entity_taxonomy_mappings(self, normalized):
        tm = normalized["entities"]["CWE-79"].taxonomy_mappings
        assert len(tm) == 1
        assert isinstance(tm[0], CweTaxonomyMapping)
        assert tm[0].taxonomy_name == "OWASP Top Ten 2021"

    def test_entity_references_enriched(self, normalized):
        refs = normalized["entities"]["CWE-79"].references
        assert len(refs) == 1
        assert isinstance(refs[0], CweReference)
        assert refs[0].reference_id == "REF-7"
        # External reference data should be enriched
        assert refs[0].title == "Writing Secure Code"
        assert "Michael Howard" in refs[0].author

    def test_entity_related_attack_patterns(self, normalized):
        caps = normalized["entities"]["CWE-79"].related_attack_patterns
        assert "CAPEC-86" in caps
        assert "CAPEC-198" in caps

    def test_entity_affected_resources(self, normalized):
        assert "Memory" in normalized["entities"]["CWE-79"].affected_resources

    def test_entity_functional_areas(self, normalized):
        assert "Web" in normalized["entities"]["CWE-79"].functional_areas

    def test_entity_url(self, normalized):
        assert "79.html" in normalized["entities"]["CWE-79"].url

    def test_entity_is_frozen(self, normalized):
        """CweEntity is a frozen dataclass — cannot be mutated."""
        entity = normalized["entities"]["CWE-79"]
        with pytest.raises((AttributeError, TypeError)):
            entity.name = "Modified"


class TestCweNormalizerRelationships:

    def test_relationships_are_cwe_relationship_instances(self, normalized):
        for rel in normalized["relationships"]:
            assert isinstance(rel, CweRelationship)

    def test_cwe79_childof_74_relationship_present(self, normalized):
        rels = normalized["relationships"]
        matching = [r for r in rels if r.source_cwe_id == "CWE-79" and r.target_cwe_id == "CWE-74"]
        assert len(matching) == 1
        assert matching[0].nature == "ChildOf"

    def test_cwe89_childof_943_relationship_present(self, normalized):
        rels = normalized["relationships"]
        matching = [r for r in rels if r.source_cwe_id == "CWE-89" and r.target_cwe_id == "CWE-943"]
        assert len(matching) == 1

    def test_relationship_source_and_target_are_strings(self, normalized):
        for rel in normalized["relationships"]:
            assert isinstance(rel.source_cwe_id, str)
            assert isinstance(rel.target_cwe_id, str)


class TestCweNormalizerEdgeCases:

    def test_rejects_non_dict_input(self):
        n = CweNormalizer()
        with pytest.raises(ValueError, match="dictionary"):
            n.normalize("not a dict")

    def test_empty_entities_returns_zero_count(self):
        n = CweNormalizer()
        result = n.normalize({"weaknesses": [], "external_references": [], "catalog_version": "4.15"})
        assert result["record_count"] == 0
        assert result["entities"] == {}
        assert result["relationships"] == []
