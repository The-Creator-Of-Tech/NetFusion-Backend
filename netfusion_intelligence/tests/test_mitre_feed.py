"""
End-to-End Integration test for MITRE ATT&CK Enterprise Intelligence Feed within IL-1 framework.
"""

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.mitre.feed import MitreAttackFeed
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE
from netfusion_intelligence.models.import_result import ImportStatus


def test_mitre_feed_full_lifecycle_execution():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)

    feed = MitreAttackFeed(repository=repo, offline_data=SAMPLE_STIX_BUNDLE)
    engine.register_feed(feed)

    # Trigger full synchronization pipeline
    result = engine.sync_feed("mitre_attack_enterprise")

    assert result.status == ImportStatus.COMPLETED
    assert result.records_processed == 9
    assert result.records_inserted == 9
    assert result.relationship_count == 4
    assert result.validation_passed is True

    # Check active dataset version
    active = repo.get_active_dataset_version("mitre_attack_enterprise")
    assert active is not None
    assert active.status.value == "ACTIVE"

    # Query techniques from engine repository
    tech = repo.get_mitre_object("T1059")
    assert tech is not None
    assert tech["name"] == "Command and Scripting Interpreter"

    # Query statistics
    stats = repo.get_mitre_statistics_for_version()
    assert stats["total_objects"] == 9
    assert stats["total_relationships"] == 4
