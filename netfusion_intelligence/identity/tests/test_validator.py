"""
Tests for IdentityValidator in NetFusion CIIL.
"""

import uuid
from netfusion_intelligence.identity.models import CanonicalEntity, ExternalIdentifier
from netfusion_intelligence.identity.relationship import CanonicalRelationship
from netfusion_intelligence.identity.validator import IdentityValidator


def test_validator_valid_and_invalid_entity():
    val = IdentityValidator()

    valid_ent = CanonicalEntity(
        canonical_uuid=str(uuid.uuid4()),
        entity_type="ATTACK_TECHNIQUE",
        display_name="Phishing",
        external_identifiers=(
            ExternalIdentifier(source="MITRE", identifier="T1566", identifier_type="ATTACK_ID"),
        ),
    )
    rep1 = val.validate_entity(valid_ent)
    assert rep1.is_valid is True
    assert len(rep1.errors) == 0

    invalid_ent = CanonicalEntity(
        canonical_uuid="invalid-uuid-string",
        entity_type="ATTACK_TECHNIQUE",
        display_name="Phishing",
    )
    rep2 = val.validate_entity(invalid_ent)
    assert rep2.is_valid is False
    assert any("Invalid UUID format" in err for err in rep2.errors)


def test_validator_dataset_validation():
    val = IdentityValidator()
    u1 = str(uuid.uuid4())
    u2 = str(uuid.uuid4())

    ent1 = CanonicalEntity(canonical_uuid=u1, entity_type="CVE", display_name="CVE-2025-100")
    ent2 = CanonicalEntity(canonical_uuid=u2, entity_type="EXPLOIT", display_name="Exploit-100")

    rel = CanonicalRelationship.create(
        source_canonical_uuid=u1,
        target_canonical_uuid=u2,
        relationship_type="EXPLOITS",
        originating_source="NVD",
    )

    rep = val.validate_dataset(entities=[ent1, ent2], relationships=[rel])
    assert rep.is_valid is True

    # Test broken relationship target
    rel_broken = CanonicalRelationship.create(
        source_canonical_uuid=u1,
        target_canonical_uuid=str(uuid.uuid4()), # Non-existent UUID
        relationship_type="EXPLOITS",
        originating_source="NVD",
    )
    rep_broken = val.validate_dataset(entities=[ent1, ent2], relationships=[rel_broken])
    assert rep_broken.is_valid is False
    assert any("Broken relationship" in err for err in rep_broken.errors)
