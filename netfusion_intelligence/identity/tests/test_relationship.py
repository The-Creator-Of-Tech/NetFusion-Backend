"""
Tests for CanonicalRelationship and RelationshipEngine in NetFusion CIIL.
"""

import uuid
from netfusion_intelligence.identity.relationship import CanonicalRelationship, RelationshipEngine


def test_relationship_engine_multi_source_deduplication():
    engine = RelationshipEngine()

    u_source = str(uuid.uuid4())
    u_target = str(uuid.uuid4())

    # Source 1 provides relationship
    rel1 = engine.link_relationship(
        source_canonical_uuid=u_source,
        target_canonical_uuid=u_target,
        relationship_type="USES",
        originating_source="MITRE",
        confidence=0.8,
    )

    assert rel1.relationship_type == "USES"
    assert rel1.originating_sources == ("MITRE",)
    assert len(engine.list_all()) == 1

    # Source 2 provides SAME relationship (source, target, type) with higher confidence
    rel2 = engine.link_relationship(
        source_canonical_uuid=u_source,
        target_canonical_uuid=u_target,
        relationship_type="USES",
        originating_source="ThreatFox",
        confidence=0.95,
    )

    # Should update existing relationship link without creating duplicate
    assert len(engine.list_all()) == 1
    assert rel2.relationship_id == rel1.relationship_id
    assert rel2.confidence == 0.95
    assert set(rel2.originating_sources) == {"MITRE", "ThreatFox"}


def test_relationship_query_by_direction():
    engine = RelationshipEngine()

    u1 = str(uuid.uuid4())
    u2 = str(uuid.uuid4())
    u3 = str(uuid.uuid4())

    engine.link_relationship(source_canonical_uuid=u1, target_canonical_uuid=u2, relationship_type="USES", originating_source="FeedA")
    engine.link_relationship(source_canonical_uuid=u3, target_canonical_uuid=u1, relationship_type="TARGETS", originating_source="FeedB")

    # Direction = source
    src_rels = engine.find_relationships(u1, direction="source")
    assert len(src_rels) == 1
    assert src_rels[0].target_canonical_uuid == u2

    # Direction = target
    tgt_rels = engine.find_relationships(u1, direction="target")
    assert len(tgt_rels) == 1
    assert tgt_rels[0].source_canonical_uuid == u3

    # Direction = both
    both_rels = engine.find_relationships(u1, direction="both")
    assert len(both_rels) == 2
