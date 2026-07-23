"""
Unit tests for MitreUpdater.
"""

from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.feeds.mitre.updater import MitreUpdater


def test_updater_version_comparison_and_rollback():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    updater = MitreUpdater(repo)
    feed_id = "mitre_attack_enterprise"

    # Initial state: no active version
    cmp_res = updater.compare_versions(feed_id, "checksum-abc")
    assert cmp_res["update_required"] is True

    # Save active dataset version
    v1 = DatasetVersion(
        feed_id=feed_id,
        version_id="v1.0",
        checksum="checksum-abc",
        status=DatasetStatus.ACTIVE,
        validation_status=ValidationStatus.PASSED,
    )
    repo.save_dataset_version(v1)

    # Same checksum comparison -> no update required
    cmp_res2 = updater.compare_versions(feed_id, "checksum-abc")
    assert cmp_res2["update_required"] is False

    # New checksum comparison -> update required
    cmp_res3 = updater.compare_versions(feed_id, "checksum-xyz")
    assert cmp_res3["update_required"] is True

    # Save second version v2.0
    v2 = DatasetVersion(
        feed_id=feed_id,
        version_id="v2.0",
        checksum="checksum-xyz",
        status=DatasetStatus.STORED,
        validation_status=ValidationStatus.PASSED,
    )
    repo.save_dataset_version(v2)

    # Activate v2.0
    updater.activate_dataset(feed_id, v2)
    active = repo.get_active_dataset_version(feed_id)
    assert active.version_id == "v2.0"

    # Rollback to v1.0
    rolled = updater.rollback_dataset(feed_id, target_version_id="v1.0")
    assert rolled.version_id == "v1.0"
    active_after = repo.get_active_dataset_version(feed_id)
    assert active_after.version_id == "v1.0"
