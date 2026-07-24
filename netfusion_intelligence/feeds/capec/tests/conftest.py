"""
Shared fixtures for MITRE CAPEC Enterprise Intelligence Pipeline tests (IL-6).
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

# ---------------------------------------------------------------------------
# Minimal valid CAPEC XML catalog (two attack patterns)
# ---------------------------------------------------------------------------
MINIMAL_CAPEC_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog
    xmlns="http://capec.mitre.org/capec-3"
    Name="CAPEC" Version="3.9" Date="2023-01-01">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection"
                    Abstraction="Standard" Status="Stable"
                    Likelihood_Of_Attack="High" Typical_Severity="High">
      <Description>This attack exploits a weakness in the application's interpretation of SQL queries.</Description>
      <Extended_Description>An attacker crafts SQL statements to manipulate database operations.</Extended_Description>
      <Execution_Flow>
        <Attack_Step>
          <Step>1</Step>
          <Phase>Explore</Phase>
          <Description>Identify SQL injection entry points.</Description>
          <Technique>Use automated scanners to identify entry points.</Technique>
        </Attack_Step>
        <Attack_Step>
          <Step>2</Step>
          <Phase>Exploit</Phase>
          <Description>Inject malicious SQL payload.</Description>
          <Technique>Use UNION statements to extract data.</Technique>
        </Attack_Step>
      </Execution_Flow>
      <Prerequisites>
        <Prerequisite>The target application must use SQL queries to access data.</Prerequisite>
      </Prerequisites>
      <Skills_Required>
        <Skill Level="Low">Knowledge of SQL syntax.</Skill>
      </Skills_Required>
      <Resources_Required>
        <Resource>HTTP client or web browser.</Resource>
      </Resources_Required>
      <Indicators>
        <Indicator>Unusual SQL error messages in the application output.</Indicator>
      </Indicators>
      <Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Impact>Read Application Data</Impact>
          <Note>Attackers can read sensitive data.</Note>
          <Likelihood>High</Likelihood>
        </Consequence>
      </Consequences>
      <Mitigations>
        <Mitigation Strategy="Input Validation">
          <Phase>Implementation</Phase>
          <Description>Use parameterized queries to prevent SQL injection.</Description>
          <Effectiveness>High</Effectiveness>
        </Mitigation>
      </Mitigations>
      <Detection_Methods>
        <Detection_Method>
          <Method>Web Application Firewall</Method>
          <Description>Use WAF rules to detect SQL injection attempts.</Description>
          <Effectiveness>Moderate</Effectiveness>
          <Effectiveness_Notes>Effective for known patterns.</Effectiveness_Notes>
        </Detection_Method>
      </Detection_Methods>
      <Example_Instances>
        <Example>An attacker appends ' OR 1=1 -- to a login field to bypass authentication.</Example>
      </Example_Instances>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="248" View_ID="1000"/>
      </Related_Attack_Patterns>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89"/>
        <Related_Weakness CWE_ID="20"/>
      </Related_Weaknesses>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="MITRE ATT&amp;CK">
          <Entry_ID>T1190</Entry_ID>
          <Entry_Name>Exploit Public-Facing Application</Entry_Name>
          <Mapping_Fit>Exact</Mapping_Fit>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
      <References>
        <Reference External_Reference_ID="REF-1"/>
      </References>
    </Attack_Pattern>
    <Attack_Pattern ID="86" Name="XSS via HTTP Query Strings"
                    Abstraction="Detailed" Status="Draft"
                    Likelihood_Of_Attack="High" Typical_Severity="Medium">
      <Description>This attack targets the encoding of URLs combined with HTML tags.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="79"/>
      </Related_Weaknesses>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="86" View_ID="1000"/>
      </Related_Attack_Patterns>
    </Attack_Pattern>
  </Attack_Patterns>
  <External_References>
    <External_Reference Reference_ID="REF-1">
      <Author>OWASP</Author>
      <Title>SQL Injection Prevention Cheat Sheet</Title>
      <URL>https://owasp.org/www-community/attacks/SQL_Injection</URL>
      <Publication_Year>2021</Publication_Year>
    </External_Reference>
  </External_References>
</Attack_Pattern_Catalog>
"""

# ---------------------------------------------------------------------------
# Empty catalog
# ---------------------------------------------------------------------------
EMPTY_CAPEC_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog
    xmlns="http://capec.mitre.org/capec-3"
    Name="CAPEC" Version="3.9" Date="2023-01-01">
  <Attack_Patterns/>
</Attack_Pattern_Catalog>
"""

INVALID_XML = b"<broken xml <<<"


# ---------------------------------------------------------------------------
# Domain model fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_capec_entity() -> CapecEntity:
    """Fully populated CapecEntity for CAPEC-66 SQL Injection."""
    return CapecEntity(
        capec_id="CAPEC-66",
        name="SQL Injection",
        abstraction="Standard",
        status="Stable",
        description="SQL injection attack pattern.",
        extended_description="Attacker crafts SQL statements.",
        likelihood_of_attack="High",
        typical_severity="High",
        execution_flow=(
            CapecExecutionFlowStep(
                step_number=1,
                phase="Explore",
                description="Identify SQL injection entry points.",
                techniques=("Use scanners",),
            ),
            CapecExecutionFlowStep(
                step_number=2,
                phase="Exploit",
                description="Inject malicious SQL payload.",
                techniques=("UNION extraction",),
            ),
        ),
        prerequisites=("Target uses SQL queries",),
        skills_required=(
            CapecSkillRequired(level="Low", description="Knowledge of SQL syntax"),
        ),
        resources_required=("HTTP client",),
        indicators=("SQL error messages",),
        consequences=(
            CapecConsequence(
                scope=("Confidentiality",),
                impact=("Read Application Data",),
                note="Attacker reads data.",
                likelihood="High",
            ),
        ),
        mitigations=(
            CapecMitigation(
                description="Use parameterized queries.",
                phase=("Implementation",),
                strategy="Input Validation",
                effectiveness="High",
            ),
        ),
        example_instances=("Appending ' OR 1=1 -- to a login field.",),
        related_attack_patterns=(
            CapecRelatedAttackPattern(capec_id="CAPEC-248", nature="ChildOf", view_id="1000"),
        ),
        related_weaknesses=("CWE-89", "CWE-20"),
        taxonomy_mappings=(
            {"taxonomy_name": "MITRE ATT&CK", "entry_id": "T1190", "entry_name": "Exploit Public-Facing Application"},
        ),
        references=(
            CapecReference(
                reference_id="REF-1",
                author=("OWASP",),
                title="SQL Injection Prevention Cheat Sheet",
                url="https://owasp.org/www-community/attacks/SQL_Injection",
                publication_year="2021",
            ),
        ),
        detection=(
            CapecDetection(
                method="Web Application Firewall",
                description="WAF rules detect SQL injection attempts.",
                effectiveness="Moderate",
                effectiveness_notes="Effective for known patterns.",
            ),
        ),
        notes="One of the most prevalent web attack patterns.",
        source_version="3.9",
        url="https://capec.mitre.org/data/definitions/66.html",
    )


@pytest.fixture
def sample_capec_entity_86() -> CapecEntity:
    """Minimal CapecEntity for CAPEC-86 XSS."""
    return CapecEntity(
        capec_id="CAPEC-86",
        name="XSS via HTTP Query Strings",
        abstraction="Detailed",
        status="Draft",
        description="XSS via URL-encoded HTML tags.",
        likelihood_of_attack="High",
        typical_severity="Medium",
        related_weaknesses=("CWE-79",),
        related_attack_patterns=(
            CapecRelatedAttackPattern(capec_id="CAPEC-86", nature="ChildOf", view_id="1000"),
        ),
    )


@pytest.fixture
def sample_capec_relationship() -> CapecRelationship:
    return CapecRelationship(
        source_capec_id="CAPEC-66",
        target_capec_id="CAPEC-248",
        nature="ChildOf",
        view_id="1000",
    )


@pytest.fixture
def sample_cwe_mapping() -> CapecCweMapping:
    return CapecCweMapping(capec_id="CAPEC-66", cwe_id="CWE-89", nature="Exploits")


@pytest.fixture
def sample_normalized_data(sample_capec_entity, sample_capec_entity_86, sample_capec_relationship, sample_cwe_mapping):
    """Normalized CAPEC dataset dict as produced by CapecNormalizer."""
    return {
        "entities": {
            "CAPEC-66": sample_capec_entity,
            "CAPEC-86": sample_capec_entity_86,
        },
        "relationships": [sample_capec_relationship],
        "cwe_mappings": [sample_cwe_mapping],
        "catalog_version": "3.9",
        "record_count": 2,
        "relationship_count": 1,
        "cwe_mapping_count": 1,
    }


@pytest.fixture
def minimal_capec_xml() -> bytes:
    return MINIMAL_CAPEC_XML


@pytest.fixture
def empty_capec_xml() -> bytes:
    return EMPTY_CAPEC_XML


@pytest.fixture
def invalid_xml() -> bytes:
    return INVALID_XML
