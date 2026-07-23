"""
Tests for Canonical Entity Models in NetFusion CIIL.
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


def test_canonical_entity_immutability():
    u_val = str(uuid.uuid4())
    ext = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    
    entity = CanonicalEntity(
        canonical_uuid=u_val,
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command and Scripting Interpreter",
        aliases=("T1059", "ExecScript"),
        external_identifiers=(ext,),
    )

    assert entity.canonical_uuid == u_val
    assert entity.display_name == "Command and Scripting Interpreter"
    assert "T1059" in entity.aliases

    # Immutability checks: dataclass frozen
    with pytest.raises(Exception):
        entity.display_name = "New Name"

    # Modifying UUID should fail in with_updated
    with pytest.raises(ValueError, match="Canonical UUID is immutable"):
        entity.with_updated(canonical_uuid=str(uuid.uuid4()))

    # Updating other fields returns new instance
    updated = entity.with_updated(display_name="Updated Name", confidence=0.9)
    assert updated.canonical_uuid == entity.canonical_uuid
    assert updated.display_name == "Updated Name"
    assert updated.confidence == 0.9
    assert entity.display_name == "Command and Scripting Interpreter"


def test_external_identifier_validation_and_serialization():
    with pytest.raises(ValueError):
        ExternalIdentifier(source="", identifier="T1059", identifier_type="ATTACK_ID")

    ext = ExternalIdentifier(
        source="NVD",
        identifier="CVE-2025-12345",
        identifier_type="CVE_ID",
        confidence=0.95,
        first_seen=datetime.now(timezone.utc),
    )

    d = ext.to_dict()
    assert d["source"] == "NVD"
    assert d["identifier"] == "CVE-2025-12345"

    reconstructed = ExternalIdentifier.from_dict(d)
    assert reconstructed.source == ext.source
    assert reconstructed.identifier == ext.identifier
    assert reconstructed.confidence == 0.95


def test_provenance_and_merge_record_creation():
    u_val = str(uuid.uuid4())
    prov = EntityProvenance.create(
        canonical_uuid=u_val,
        feed="MITRE_ATTACK",
        dataset_version="v14.1",
        original_object_id="attack-pattern--12345",
    )
    assert prov.canonical_uuid == u_val
    assert prov.feed == "MITRE_ATTACK"
    assert prov.verification_status == "VERIFIED"

    merge_rec = EntityMergeRecord.create(
        target_canonical_uuid=u_val,
        merged_canonical_uuid=str(uuid.uuid4()),
        reason="Duplicate entity match on T1059",
    )
    assert merge_rec.target_canonical_uuid == u_val
    assert "T1059" in merge_rec.reason
