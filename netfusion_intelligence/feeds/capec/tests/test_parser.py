"""
Tests for CapecParser — full XML parsing, field extraction, edge cases.
"""

import pytest

from netfusion_intelligence.feeds.capec.parser import CapecParser
from netfusion_intelligence.feeds.capec.tests.conftest import (
    MINIMAL_CAPEC_XML,
    EMPTY_CAPEC_XML,
    INVALID_XML,
)


class TestCapecParserStructure:

    def test_parse_returns_dict(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert isinstance(result, dict)

    def test_catalog_version_extracted(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert result["catalog_version"] == "3.9"

    def test_attack_patterns_list_present(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert "attack_patterns" in result
        assert isinstance(result["attack_patterns"], list)

    def test_total_attack_patterns_count(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert result["total_attack_patterns"] == 2

    def test_external_references_present(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert "external_references" in result

    def test_categories_and_views_present(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        assert "categories" in result
        assert "views" in result

    def test_parse_string_input(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML.decode("utf-8"))
        assert result["total_attack_patterns"] == 2

    def test_empty_catalog_returns_zero_patterns(self):
        p = CapecParser()
        result = p.parse(EMPTY_CAPEC_XML)
        assert result["total_attack_patterns"] == 0
        assert result["attack_patterns"] == []

    def test_invalid_xml_raises_value_error(self):
        p = CapecParser()
        with pytest.raises(ValueError, match="Invalid CAPEC XML"):
            p.parse(INVALID_XML)


class TestCapecParserCapec66Fields:
    """Exhaustively verify every field extracted for CAPEC-66."""

    @pytest.fixture(autouse=True)
    def parse(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        self.patterns = {ap["capec_id"]: ap for ap in result["attack_patterns"]}
        self.capec66 = self.patterns["CAPEC-66"]
        self.ext_refs = {r["reference_id"]: r for r in result["external_references"]}

    def test_capec_id_prefixed(self):
        assert self.capec66["capec_id"] == "CAPEC-66"

    def test_name(self):
        assert "SQL Injection" in self.capec66["name"]

    def test_abstraction(self):
        assert self.capec66["abstraction"] == "Standard"

    def test_status(self):
        assert self.capec66["status"] == "Stable"

    def test_likelihood_of_attack(self):
        assert self.capec66["likelihood_of_attack"] == "High"

    def test_typical_severity(self):
        assert self.capec66["typical_severity"] == "High"

    def test_description_present(self):
        assert self.capec66["description"] is not None
        assert len(self.capec66["description"]) > 0

    def test_extended_description_present(self):
        assert self.capec66["extended_description"] is not None

    def test_execution_flow_extracted(self):
        flow = self.capec66["execution_flow"]
        assert len(flow) == 2
        assert flow[0]["step_number"] == 1
        assert flow[0]["phase"] == "Explore"
        assert flow[1]["phase"] == "Exploit"

    def test_execution_flow_techniques(self):
        flow = self.capec66["execution_flow"]
        assert len(flow[0]["techniques"]) >= 1

    def test_prerequisites_extracted(self):
        prereqs = self.capec66["prerequisites"]
        assert len(prereqs) == 1
        assert "SQL" in prereqs[0]

    def test_skills_required_extracted(self):
        skills = self.capec66["skills_required"]
        assert len(skills) == 1
        assert skills[0]["level"] == "Low"

    def test_resources_required_extracted(self):
        resources = self.capec66["resources_required"]
        assert len(resources) == 1
        assert "HTTP" in resources[0]

    def test_indicators_extracted(self):
        indicators = self.capec66["indicators"]
        assert len(indicators) == 1
        assert "SQL" in indicators[0]

    def test_consequences_extracted(self):
        cons = self.capec66["consequences"]
        assert len(cons) == 1
        assert "Confidentiality" in cons[0]["scope"]
        assert "Read Application Data" in cons[0]["impact"]

    def test_mitigations_extracted(self):
        mits = self.capec66["mitigations"]
        assert len(mits) == 1
        assert mits[0]["strategy"] == "Input Validation"
        assert mits[0]["effectiveness"] == "High"

    def test_detection_methods_extracted(self):
        det = self.capec66["detection"]
        assert len(det) == 1
        assert det[0]["method"] == "Web Application Firewall"
        assert det[0]["effectiveness"] == "Moderate"
        assert det[0]["effectiveness_notes"] is not None

    def test_example_instances_extracted(self):
        examples = self.capec66["example_instances"]
        assert len(examples) == 1
        assert "OR 1=1" in examples[0]

    def test_related_attack_patterns(self):
        raps = self.capec66["related_attack_patterns"]
        assert len(raps) == 1
        assert raps[0]["capec_id"] == "CAPEC-248"
        assert raps[0]["nature"] == "ChildOf"

    def test_related_weaknesses(self):
        rw = self.capec66["related_weaknesses"]
        assert "CWE-89" in rw
        assert "CWE-20" in rw

    def test_taxonomy_mappings_extracted(self):
        tm = self.capec66["taxonomy_mappings"]
        assert len(tm) == 1
        assert "ATT" in tm[0]["taxonomy_name"]
        assert tm[0]["entry_id"] == "T1190"

    def test_references_extracted(self):
        refs = self.capec66["references"]
        assert len(refs) == 1
        assert refs[0]["reference_id"] == "REF-1"

    def test_url_constructed(self):
        assert "66.html" in self.capec66["url"]

    def test_external_ref_enriched(self):
        ref = self.ext_refs.get("REF-1")
        assert ref is not None
        assert ref["title"] == "SQL Injection Prevention Cheat Sheet"
        assert "OWASP" in ref["author"]
        assert ref["publication_year"] == "2021"


class TestCapecParserCapec86Fields:

    @pytest.fixture(autouse=True)
    def parse(self):
        p = CapecParser()
        result = p.parse(MINIMAL_CAPEC_XML)
        patterns = {ap["capec_id"]: ap for ap in result["attack_patterns"]}
        self.capec86 = patterns["CAPEC-86"]

    def test_capec_id(self):
        assert self.capec86["capec_id"] == "CAPEC-86"

    def test_name(self):
        assert "XSS" in self.capec86["name"]

    def test_abstraction(self):
        assert self.capec86["abstraction"] == "Detailed"

    def test_related_weaknesses(self):
        assert "CWE-79" in self.capec86["related_weaknesses"]
