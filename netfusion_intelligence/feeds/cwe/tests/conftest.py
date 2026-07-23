"""
Shared fixtures for MITRE CWE Enterprise Intelligence Pipeline tests (IL-6).
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

# ---------------------------------------------------------------------------
# Minimal valid CWE XML catalog (two weaknesses)
# ---------------------------------------------------------------------------
MINIMAL_CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog
    xmlns="http://cwe.mitre.org/cwe-7"
    Name="CWE" Version="4.15" Date="2024-02-29">
  <Weaknesses>
    <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation" 
              Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.</Description>
      <Extended_Description>Cross-site scripting (XSS) vulnerabilities occur when untrusted data is sent to a web browser.</Extended_Description>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Applicable_Platforms>
        <Language Name="PHP" Prevalence="Often"/>
        <Language Name="JavaScript" Prevalence="Often"/>
      </Applicable_Platforms>
      <Modes_Of_Introduction>
        <Introduction>
          <Phase>Implementation</Phase>
          <Note>This weakness is introduced during implementation.</Note>
        </Introduction>
      </Modes_Of_Introduction>
      <Common_Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Impact>Read Application Data</Impact>
          <Note>The attacker can read sensitive data.</Note>
        </Consequence>
      </Common_Consequences>
      <Detection_Methods>
        <Detection_Method>
          <Method>Automated Static Analysis</Method>
          <Description>Use automated tools to find XSS vulnerabilities.</Description>
          <Effectiveness>High</Effectiveness>
        </Detection_Method>
      </Detection_Methods>
      <Potential_Mitigations>
        <Mitigation>
          <Phase>Implementation</Phase>
          <Description>Use output encoding to prevent XSS.</Description>
          <Strategy>Output Encoding</Strategy>
          <Effectiveness>High</Effectiveness>
        </Mitigation>
      </Potential_Mitigations>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="OWASP Top Ten 2021">
          <Entry_ID>A03</Entry_ID>
          <Entry_Name>Injection</Entry_Name>
          <Mapping_Fit>Exact</Mapping_Fit>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
      <References>
        <Reference External_Reference_ID="REF-7"/>
      </References>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="86"/>
        <Related_Attack_Pattern CAPEC_ID="198"/>
      </Related_Attack_Patterns>
      <Affected_Resources>
        <Affected_Resource>Memory</Affected_Resource>
      </Affected_Resources>
      <Functional_Areas>
        <Functional_Area>Web</Functional_Area>
      </Functional_Areas>
    </Weakness>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command"
              Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>SQL injection vulnerabilities arise when user input is incorporated into SQL queries without proper sanitization.</Description>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="943" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
  <External_References>
    <External_Reference Reference_ID="REF-7">
      <Author>Michael Howard</Author>
      <Author>David LeBlanc</Author>
      <Title>Writing Secure Code</Title>
      <Edition>2nd Edition</Edition>
      <URL>https://www.microsoft.com/en-us/research/publication/writing-secure-code/</URL>
      <Publication_Year>2002</Publication_Year>
      <Publisher>Microsoft Press</Publisher>
    </External_Reference>
  </External_References>
</Weakness_Catalog>
"""

# ---------------------------------------------------------------------------
# Empty catalog (no weaknesses)
# ---------------------------------------------------------------------------
EMPTY_CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog
    xmlns="http://cwe.mitre.org/cwe-7"
    Name="CWE" Version="4.15" Date="2024-02-29">
  <Weaknesses/>
</Weakness_Catalog>
"""

# ---------------------------------------------------------------------------
# Invalid XML
# ---------------------------------------------------------------------------
INVALID_XML = b"<not valid xml <<<"


# ---------------------------------------------------------------------------
# Domain model fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_cwe_entity() -> CweEntity:
    """A fully populated CweEntity for unit testing."""
    return CweEntity(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation",
        abstraction="Base",
        structure="Simple",
        status="Stable",
        description="Cross-site scripting vulnerability.",
        extended_description="XSS allows attackers to inject scripts.",
        likelihood_of_exploit="High",
        background_details="Historically one of the most common vulnerabilities.",
        alternate_terms=("XSS", "Cross-Site Scripting"),
        modes_of_introduction=(
            CweModeOfIntroduction(phase="Implementation", note="During coding phase"),
        ),
        applicable_platforms=(
            CweApplicablePlatform(platform_type="Language", name="PHP", prevalence="Often"),
            CweApplicablePlatform(platform_type="Language", name="JavaScript", prevalence="Often"),
        ),
        consequences=(
            CweConsequence(
                scope=("Confidentiality",),
                impact=("Read Application Data",),
                note="Attacker reads sensitive data.",
                likelihood="High",
            ),
        ),
        detection_methods=(
            CweDetectionMethod(
                method="Automated Static Analysis",
                description="Use static analysis tools.",
                effectiveness="High",
                effectiveness_notes="Very effective for this weakness.",
            ),
        ),
        mitigations=(
            CweMitigation(
                phase=("Implementation",),
                description="Use output encoding.",
                strategy="Output Encoding",
                effectiveness="High",
                effectiveness_notes="Highly effective when applied consistently.",
            ),
        ),
        related_weaknesses=(
            CweRelatedWeakness(cwe_id="CWE-74", nature="ChildOf", view_id="1000", ordinal="Primary"),
        ),
        taxonomy_mappings=(
            CweTaxonomyMapping(
                taxonomy_name="OWASP Top Ten 2021",
                entry_id="A03",
                entry_name="Injection",
                mapping_fit="Exact",
            ),
        ),
        references=(
            CweReference(
                reference_id="REF-7",
                author=("Michael Howard", "David LeBlanc"),
                title="Writing Secure Code",
                edition="2nd Edition",
                url="https://www.microsoft.com/en-us/research/publication/writing-secure-code/",
                publication_year="2002",
                publisher="Microsoft Press",
            ),
        ),
        related_attack_patterns=("CAPEC-86", "CAPEC-198"),
        affected_resources=("Memory",),
        functional_areas=("Web",),
        mapping_notes="Used for mapping XSS weaknesses in vulnerability reports.",
        notes="This weakness has been in OWASP Top Ten for multiple years.",
        source_version="4.15",
        url="https://cwe.mitre.org/data/definitions/79.html",
    )


@pytest.fixture
def sample_cwe_entity_89() -> CweEntity:
    """A minimal CweEntity for SQL injection."""
    return CweEntity(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command",
        abstraction="Base",
        structure="Simple",
        status="Stable",
        description="SQL injection vulnerability.",
        likelihood_of_exploit="High",
        related_weaknesses=(
            CweRelatedWeakness(cwe_id="CWE-943", nature="ChildOf", view_id="1000"),
        ),
    )


@pytest.fixture
def sample_relationship() -> CweRelationship:
    return CweRelationship(
        source_cwe_id="CWE-79",
        target_cwe_id="CWE-74",
        nature="ChildOf",
        view_id="1000",
        ordinal="Primary",
    )


@pytest.fixture
def sample_normalized_data(sample_cwe_entity, sample_cwe_entity_89, sample_relationship):
    """Normalized CWE dataset dict as produced by CweNormalizer."""
    return {
        "entities": {
            "CWE-79": sample_cwe_entity,
            "CWE-89": sample_cwe_entity_89,
        },
        "relationships": [sample_relationship],
        "catalog_version": "4.15",
        "record_count": 2,
        "relationship_count": 1,
    }


@pytest.fixture
def minimal_cwe_xml() -> bytes:
    return MINIMAL_CWE_XML


@pytest.fixture
def empty_cwe_xml() -> bytes:
    return EMPTY_CWE_XML


@pytest.fixture
def invalid_xml() -> bytes:
    return INVALID_XML
