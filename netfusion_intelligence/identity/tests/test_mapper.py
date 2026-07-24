"""
Tests for generic IdentityMapper in NetFusion CIIL.
"""

from netfusion_intelligence.identity.mapper import FeedMappingConfig, IdentityMapper
from netfusion_intelligence.identity.models import CanonicalEntityType


def test_generic_mapper_mapping_raw_feed_object():
    mapper = IdentityMapper()

    raw_feed_item = {
        "stix_id": "attack-pattern--92a4729f-3d02-45e0-8260-ebde451e06d9",
        "attack_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "details": "Adversaries may abuse command and script interpreters",
        "other_names": ["cmd.exe", "powershell"],
        "cve_refs": ["CVE-2023-1234"],
        "labels": ["execution", "windows"],
        "platform": "Windows",
    }

    config = FeedMappingConfig(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name_field="technique_name",
        description_field="details",
        aliases_field="other_names",
        tags_field="labels",
        external_id_mappings=[
            {"source": "MITRE", "field": "attack_id", "type": "ATTACK_ID"},
            {"source": "STIX", "field": "stix_id", "type": "STIX_ID"},
            {"source": "NVD", "field": "cve_refs", "type": "CVE_ID"},
        ],
        metadata_fields=["platform"],
    )

    entity, provenance = mapper.map_raw_object(
        raw_data=raw_feed_item,
        config=config,
        feed_source="MITRE_STIX",
        dataset_version="14.1",
    )

    assert entity.entity_type == CanonicalEntityType.ATTACK_TECHNIQUE.value
    assert entity.display_name == "Command and Scripting Interpreter"
    assert "cmd.exe" in entity.aliases
    assert "powershell" in entity.aliases
    assert "execution" in entity.tags
    assert entity.metadata.get("platform") == "Windows"

    assert len(entity.external_identifiers) == 3
    sources = {ext.source: ext.identifier for ext in entity.external_identifiers}
    assert sources["MITRE"] == "T1059"
    assert sources["STIX"] == "attack-pattern--92a4729f-3d02-45e0-8260-ebde451e06d9"
    assert sources["NVD"] == "CVE-2023-1234"

    assert provenance.feed == "MITRE_STIX"
    assert provenance.dataset_version == "14.1"
