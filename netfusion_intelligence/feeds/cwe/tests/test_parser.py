"""
Tests for CweParser — full XML parsing, field extraction, edge cases.
"""

import pytest

from netfusion_intelligence.feeds.cwe.parser import CweParser
from netfusion_intelligence.feeds.cwe.tests.conftest import (
    MINIMAL_CWE_XML,
    EMPTY_CWE_XML,
    INVALID_XML,
)


class TestCweParserStructure:

    def test_parse_returns_dict(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert isinstance(result, dict)

    def test_catalog_version_extracted(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert result["catalog_version"] == "4.15"

    def test_weaknesses_list_present(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert "weaknesses" in result
        assert isinstance(result["weaknesses"], list)

    def test_total_weaknesses_count(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert result["total_weaknesses"] == 2

    def test_external_references_present(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert "external_references" in result

    def test_categories_and_views_present(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        assert "categories" in result
        assert "views" in result

    def test_parse_string_input(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML.decode("utf-8"))
        assert result["total_weaknesses"] == 2

    def test_empty_catalog_returns_zero_weaknesses(self):
        p = CweParser()
        result = p.parse(EMPTY_CWE_XML)
        assert result["total_weaknesses"] == 0
        assert result["weaknesses"] == []

    def test_invalid_xml_raises_value_error(self):
        p = CweParser()
        with pytest.raises(ValueError, match="Invalid CWE XML"):
            p.parse(INVALID_XML)


class TestCweParserCwe79Fields:
    """Exhaustively verify every field extracted for CWE-79."""

    @pytest.fixture(autouse=True)
    def parse(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        self.weaknesses = {w["cwe_id"]: w for w in result["weaknesses"]}
        self.cwe79 = self.weaknesses["CWE-79"]
        self.ext_refs = {r["reference_id"]: r for r in result["external_references"]}

    def test_cwe_id_prefixed(self):
        assert self.cwe79["cwe_id"] == "CWE-79"

    def test_name(self):
        assert "Improper Neutralization" in self.cwe79["name"]

    def test_abstraction(self):
        assert self.cwe79["abstraction"] == "Base"

    def test_structure(self):
        assert self.cwe79["structure"] == "Simple"

    def test_status(self):
        assert self.cwe79["status"] == "Stable"

    def test_description_present(self):
        assert self.cwe79["description"] is not None
        assert len(self.cwe79["description"]) > 0

    def test_extended_description_present(self):
        assert self.cwe79["extended_description"] is not None

    def test_likelihood_of_exploit(self):
        assert self.cwe79["likelihood_of_exploit"] == "High"

    def test_applicable_platforms_extracted(self):
        platforms = self.cwe79["applicable_platforms"]
        assert len(platforms) == 2
        names = [p["name"] for p in platforms]
        assert "PHP" in names
        assert "JavaScript" in names

    def test_applicable_platform_type(self):
        platforms = self.cwe79["applicable_platforms"]
        for p in platforms:
            assert p["platform_type"] == "Language"
            assert p["prevalence"] == "Often"

    def test_modes_of_introduction(self):
        modes = self.cwe79["modes_of_introduction"]
        assert len(modes) == 1
        assert modes[0]["phase"] == "Implementation"
        assert modes[0]["note"] is not None

    def test_consequences_extracted(self):
        cons = self.cwe79["consequences"]
        assert len(cons) == 1
        assert "Confidentiality" in cons[0]["scope"]
        assert "Read Application Data" in cons[0]["impact"]

    def test_detection_methods_extracted(self):
        dms = self.cwe79["detection_methods"]
        assert len(dms) == 1
        assert dms[0]["method"] == "Automated Static Analysis"
        assert dms[0]["effectiveness"] == "High"

    def test_mitigations_extracted(self):
        mits = self.cwe79["mitigations"]
        assert len(mits) == 1
        assert "Implementation" in mits[0]["phase"]
        assert mits[0]["strategy"] == "Output Encoding"

    def test_related_weaknesses(self):
        rw = self.cwe79["related_weaknesses"]
        assert len(rw) == 1
        assert rw[0]["cwe_id"] == "CWE-74"
        assert rw[0]["nature"] == "ChildOf"
        assert rw[0]["view_id"] == "1000"
        assert rw[0]["ordinal"] == "Primary"

    def test_taxonomy_mappings(self):
        tm = self.cwe79["taxonomy_mappings"]
        assert len(tm) == 1
        assert tm[0]["taxonomy_name"] == "OWASP Top Ten 2021"
        assert tm[0]["entry_id"] == "A03"
        assert tm[0]["entry_name"] == "Injection"

    def test_references_extracted(self):
        refs = self.cwe79["references"]
        assert len(refs) == 1
        assert refs[0]["reference_id"] == "REF-7"

    def test_related_attack_patterns(self):
        caps = self.cwe79["related_attack_patterns"]
        assert "CAPEC-86" in caps
        assert "CAPEC-198" in caps

    def test_affected_resources(self):
        assert "Memory" in self.cwe79["affected_resources"]

    def test_functional_areas(self):
        assert "Web" in self.cwe79["functional_areas"]

    def test_url_constructed(self):
        assert "79.html" in self.cwe79["url"]

    def test_external_ref_enriched(self):
        ref = self.ext_refs.get("REF-7")
        assert ref is not None
        assert ref["title"] == "Writing Secure Code"
        assert "Michael Howard" in ref["author"]
        assert ref["publication_year"] == "2002"
        assert ref["publisher"] == "Microsoft Press"


class TestCweParserCwe89Fields:
    """CWE-89 minimal fields."""

    @pytest.fixture(autouse=True)
    def parse(self):
        p = CweParser()
        result = p.parse(MINIMAL_CWE_XML)
        weaknesses = {w["cwe_id"]: w for w in result["weaknesses"]}
        self.cwe89 = weaknesses["CWE-89"]

    def test_cwe_id(self):
        assert self.cwe89["cwe_id"] == "CWE-89"

    def test_name_present(self):
        assert "SQL" in self.cwe89["name"]

    def test_related_weaknesses_present(self):
        assert len(self.cwe89["related_weaknesses"]) == 1
        assert self.cwe89["related_weaknesses"][0]["cwe_id"] == "CWE-943"
