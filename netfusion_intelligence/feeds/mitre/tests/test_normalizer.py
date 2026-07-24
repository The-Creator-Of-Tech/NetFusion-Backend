"""
Unit tests for MitreNormalizer.
"""

from netfusion_intelligence.feeds.mitre.normalizer import MitreNormalizer
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_normalize_stix_bundle():
    parser = MitreParser()
    normalizer = MitreNormalizer()

    parsed = parser.parse(SAMPLE_STIX_BUNDLE)
    norm = normalizer.normalize(parsed)

    assert norm["record_count"] == 13
    assert len(norm["entities"]) == 9
    assert len(norm["relationships"]) == 4

    # Verify T1059 technique mapping
    t1059 = norm["entities"]["attack-pattern--t1059-uuid"]
    assert t1059.attack_id == "T1059"
    assert t1059.name == "Command and Scripting Interpreter"
    assert "execution" in t1059.tactics
    assert "Windows" in t1059.platforms
    assert not t1059.is_subtechnique

    # Verify T1059.001 sub-technique mapping
    t1059_001 = norm["entities"]["attack-pattern--t1059-001-uuid"]
    assert t1059_001.attack_id == "T1059.001"
    assert t1059_001.is_subtechnique
    assert t1059_001.parent_technique_id == "T1059"

    # Verify APT28 Group mapping
    apt28 = norm["entities"]["intrusion-set--apt28-uuid"]
    assert apt28.attack_id == "G0007"
    assert "Fancy Bear" in apt28.aliases

    # Verify enriched relationship
    rel = norm["relationships"][0]
    assert rel.source_ref == "intrusion-set--apt28-uuid"
    assert rel.source_attack_id == "G0007"
    assert rel.target_attack_id == "S0002"
    assert rel.relationship_type == "uses"
