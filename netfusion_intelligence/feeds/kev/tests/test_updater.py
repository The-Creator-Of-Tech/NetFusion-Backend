"""
Tests for CisaKevUpdater dataset version management and rollback.
"""

from netfusion_intelligence.feeds.kev.updater import CisaKevUpdater
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_updater_activation_and_rollback():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    updater = CisaKevUpdater(repo)

    # Register dataset version 1
    v1 = DatasetVersion(
        feed_id="cisa_kev_1.0",
        version_id="v1.0.0",
        status=DatasetStatus.CREATED,
    )
    repo.save_dataset_version(v1)

    # Activate dataset version 1
    success = updater.activate_dataset("cisa_kev_1.0", v1)
    assert success is True
    active = repo.get_active_dataset_version("cisa_kev_1.0")
    assert active is not None
    assert active.version_id == "v1.0.0"

    # Register & activate dataset version 2
    v2 = DatasetVersion(
        feed_id="cisa_kev_1.0",
        version_id="v2.0.0",
        status=DatasetStatus.CREATED,
    )
    repo.save_dataset_version(v2)
    updater.activate_dataset("cisa_kev_1.0", v2)

    active2 = repo.get_active_dataset_version("cisa_kev_1.0")
    assert active2.version_id == "v2.0.0"

    # Rollback to version 1
    updater.rollback_dataset("cisa_kev_1.0", target_version_id="v1.0.0")
    active_rolled = repo.get_active_dataset_version("cisa_kev_1.0")
    assert active_rolled.version_id == "v1.0.0"
