"""
Tests for IdentityService facade layer in NetFusion CIIL.
"""

from netfusion_intelligence.identity.models import CanonicalEntityType, ExternalIdentifier
from netfusion_intelligence.identity.service import IdentityService


def test_service_full_lifecycle():
    service = IdentityService()

    # 1. Resolve entity
    ext = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    ent = service.resolve_entity(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command and Scripting Interpreter",
        external_identifiers=[ext],
        aliases=["T1059"],
        feed_source="MITRE",
    )

    assert ent.canonical_uuid is not None

    # 2. Find by UUID
    by_uuid = service.find_by_uuid(ent.canonical_uuid)
    assert by_uuid is not None
    assert by_uuid.display_name == "Command and Scripting Interpreter"

    # 3. Find by external ID
    by_ext = service.find_by_external_id(source="MITRE", identifier="T1059")
    assert len(by_ext) == 1
    assert by_ext[0].canonical_uuid == ent.canonical_uuid

    # 4. Search
    search_res = service.search(query="Command")
    assert len(search_res) == 1
    assert search_res[0].canonical_uuid == ent.canonical_uuid

    # 5. Provenance
    prov = service.get_provenance(ent.canonical_uuid)
    assert len(prov) == 1
    assert prov[0].feed == "MITRE"

    # 6. Statistics
    stats = service.get_statistics()
    assert stats.total_canonical_entities == 1
    assert "MITRE" in stats.sources
