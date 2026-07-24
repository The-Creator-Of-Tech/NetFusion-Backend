"""
Tests for IdentityResolver duplicate detection and intelligent merging.
"""

import pytest
import uuid

from netfusion_intelligence.identity.models import CanonicalEntityType, ExternalIdentifier
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver


@pytest.fixture
def repo():
    return IdentityRepository(":memory:")


@pytest.fixture
def resolver(repo):
    return IdentityResolver(repo)


def test_resolver_creates_new_entity_when_no_match(resolver, repo):
    ext = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    entity = resolver.resolve(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command and Scripting Interpreter",
        external_identifiers=[ext],
        aliases=["T1059"],
        feed_source="MITRE",
    )

    assert entity.canonical_uuid is not None
    assert entity.display_name == "Command and Scripting Interpreter"
    assert entity.active is True
    assert repo.count_entities() == 1


def test_resolver_prevents_duplicate_and_merges_data(resolver, repo):
    ext1 = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    ent1 = resolver.resolve(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command Interpreter",
        external_identifiers=[ext1],
        aliases=["T1059"],
        feed_source="MITRE",
    )

    # Second incoming item from a different feed (e.g. STIX) with the same T1059 external ID
    ext2 = ExternalIdentifier(source="STIX", identifier="T1059", identifier_type="ATTACK_ID")
    ext_vt = ExternalIdentifier(source="VirusTotal", identifier="vt-rule-1059", identifier_type="RULE_ID")
    ent2 = resolver.resolve(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command Interpreter Technique",
        external_identifiers=[ext2, ext_vt],
        aliases=["CmdLineExec"],
        feed_source="VirusTotal",
    )

    # Should match existing entity ent1, NOT create a second entity
    assert ent2.canonical_uuid == ent1.canonical_uuid
    assert repo.count_entities() == 1
    assert resolver.duplicate_prevented_count == 1

    # Should merge external identifiers, aliases, and tags
    fetched = repo.get_entity(ent1.canonical_uuid)
    assert "CmdLineExec" in fetched.aliases
    assert len(fetched.external_identifiers) == 3


def test_resolver_merge_two_existing_entities(resolver, repo):
    # Create entity A from feed 1
    extA = ExternalIdentifier(source="FeedA", identifier="ID-100", identifier_type="CUSTOM")
    entA = resolver.resolve(
        entity_type=CanonicalEntityType.MALWARE.value,
        display_name="Emotet Malware",
        external_identifiers=[extA],
        aliases=["Emotet"],
        feed_source="FeedA",
    )

    # Create entity B from feed 2 with different identifier initially
    extB = ExternalIdentifier(source="FeedB", identifier="ID-200", identifier_type="CUSTOM")
    entB = resolver.resolve(
        entity_type=CanonicalEntityType.MALWARE.value,
        display_name="Geodo Botnet",
        external_identifiers=[extB],
        aliases=["Geodo"],
        feed_source="FeedB",
    )

    assert repo.count_entities() == 2

    # Now manually merge B into A
    merged = resolver.merge_entities(
        primary_uuid=entA.canonical_uuid,
        secondary_uuid=entB.canonical_uuid,
        reason="Discovered Geodo is alias of Emotet",
    )

    assert merged.canonical_uuid == entA.canonical_uuid
    assert "Geodo" in merged.aliases
    assert "Emotet" in merged.aliases

    # entB should now be inactive and status MERGED
    fetchedB = repo.get_entity(entB.canonical_uuid)
    assert fetchedB.status == "MERGED"
    assert fetchedB.active is False

    # Check merge history
    history = repo.get_merge_history(entA.canonical_uuid)
    assert len(history) == 1
    assert history[0].merged_canonical_uuid == entB.canonical_uuid
