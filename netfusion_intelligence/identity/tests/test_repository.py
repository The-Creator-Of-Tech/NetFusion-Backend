"""
Tests for IdentityRepository in NetFusion CIIL.
"""

from datetime import datetime, timezone
import pytest
import uuid

from netfusion_intelligence.identity.models import (
    CanonicalEntity,
    CanonicalEntityType,
    EntityMergeRecord,
    EntityProvenance,
    ExternalIdentifier,
)
from netfusion_intelligence.identity.relationship import CanonicalRelationship
from netfusion_intelligence.identity.repository import IdentityRepository


@pytest.fixture
def repo():
    return IdentityRepository(":memory:")


def test_repository_save_and_get_entity(repo):
    u_val = str(uuid.uuid4())
    ext = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    prov = EntityProvenance.create(
        canonical_uuid=u_val,
        feed="MITRE",
        dataset_version="14.1",
        original_object_id="attack-pattern--1",
    )

    entity = CanonicalEntity(
        canonical_uuid=u_val,
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command Interpreter",
        aliases=("T1059", "cmd.exe"),
        tags=("execution", "os"),
        external_identifiers=(ext,),
    )

    repo.save_entity(entity, provenance=prov)

    fetched = repo.get_entity(u_val)
    assert fetched is not None
    assert fetched.canonical_uuid == u_val
    assert fetched.display_name == "Command Interpreter"
    assert "T1059" in fetched.aliases
    assert len(fetched.external_identifiers) == 1
    assert fetched.external_identifiers[0].identifier == "T1059"

    # Verify Provenance retrieval
    prov_list = repo.get_provenance(u_val)
    assert len(prov_list) == 1
    assert prov_list[0].feed == "MITRE"


def test_repository_find_by_external_id_and_search(repo):
    u_val = str(uuid.uuid4())
    ext = ExternalIdentifier(source="NVD", identifier="CVE-2025-9999", identifier_type="CVE_ID")

    entity = CanonicalEntity(
        canonical_uuid=u_val,
        entity_type=CanonicalEntityType.CVE.value,
        display_name="Critical Buffer Overflow",
        description="Remote code execution via buffer overflow",
        external_identifiers=(ext,),
    )
    repo.save_entity(entity)

    # Search by external ID
    found = repo.find_by_external_id(source="NVD", identifier="CVE-2025-9999")
    assert len(found) == 1
    assert found[0].canonical_uuid == u_val

    # Search by query keyword
    searched = repo.search(query="Buffer Overflow")
    assert len(searched) == 1
    assert searched[0].canonical_uuid == u_val


def test_repository_relationship_and_merge_history(repo):
    u1 = str(uuid.uuid4())
    u2 = str(uuid.uuid4())

    rel = CanonicalRelationship.create(
        source_canonical_uuid=u1,
        target_canonical_uuid=u2,
        relationship_type="EXPLOITS",
        originating_source="ThreatFeedA",
    )
    repo.save_relationship(rel)

    rels = repo.get_relationships(u1, direction="source")
    assert len(rels) == 1
    assert rels[0].target_canonical_uuid == u2
    assert rels[0].relationship_type == "EXPLOITS"

    merge_rec = EntityMergeRecord.create(
        target_canonical_uuid=u1,
        merged_canonical_uuid=u2,
        reason="Duplicate identity resolution",
    )
    repo.save_merge_record(merge_rec)

    history = repo.get_merge_history(u1)
    assert len(history) == 1
    assert history[0].merged_canonical_uuid == u2
