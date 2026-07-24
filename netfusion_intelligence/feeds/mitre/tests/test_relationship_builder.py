"""
Unit tests for MitreRelationshipBuilder.
"""

from netfusion_intelligence.feeds.mitre.normalizer import MitreNormalizer
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.relationship_builder import MitreRelationshipBuilder
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_build_relationships_from_normalized_data():
    parsed = MitreParser().parse(SAMPLE_STIX_BUNDLE)
    norm = MitreNormalizer().normalize(parsed)

    builder = MitreRelationshipBuilder()
    rels = builder.build_relationships(norm)

    assert len(rels) == 4
    rel_types = {r.relationship_type for r in rels}
    assert "uses" in rel_types
    assert "mitigates" in rel_types
    assert "subtechnique-of" in rel_types
