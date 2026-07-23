"""
Tests for IdentityStatisticsTracker in NetFusion CIIL.
"""

from netfusion_intelligence.identity.models import CanonicalEntityType, ExternalIdentifier
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver
from netfusion_intelligence.identity.statistics import IdentityStatisticsTracker


def test_statistics_generation():
    repo = IdentityRepository(":memory:")
    resolver = IdentityResolver(repo)
    tracker = IdentityStatisticsTracker(repo)

    # 1. Resolve first entity
    ext1 = ExternalIdentifier(source="MITRE", identifier="T1059", identifier_type="ATTACK_ID")
    resolver.resolve(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command Interpreter",
        external_identifiers=[ext1],
        feed_source="MITRE",
    )

    # 2. Resolve duplicate entity
    ext2 = ExternalIdentifier(source="NVD", identifier="T1059", identifier_type="ATTACK_ID")
    resolver.resolve(
        entity_type=CanonicalEntityType.ATTACK_TECHNIQUE.value,
        display_name="Command Interpreter Dup",
        external_identifiers=[ext2],
        feed_source="NVD",
    )

    stats = tracker.generate_statistics(duplicate_prevented_count=resolver.duplicate_prevented_count)

    assert stats.total_canonical_entities == 1
    assert stats.active_entities == 1
    assert stats.duplicate_prevented_count == 1
    assert stats.deduplication_rate == 0.5  # 1 prevented out of 2 resolution attempts
    assert "MITRE" in stats.sources
    assert "NVD" in stats.sources
    assert stats.entity_types_breakdown.get(CanonicalEntityType.ATTACK_TECHNIQUE.value) == 1
