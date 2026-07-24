"""
Unit tests for NVD Updater & Rollback Manager (updater.py).
"""

from netfusion_intelligence.feeds.nvd.updater import NvdUpdater
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_updater_activation_and_rollback():
    sql_repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    updater = NvdUpdater(sql_repo)

    v1 = DatasetVersion(feed_id="nvd_cve_2.0", version_id="v1.0")
    v2 = DatasetVersion(feed_id="nvd_cve_2.0", version_id="v2.0")

    sql_repo.save_dataset_version(v1)
    sql_repo.save_dataset_version(v2)

    assert updater.activate_dataset("nvd_cve_2.0", v1) is True
    active = sql_repo.get_active_dataset_version("nvd_cve_2.0")
    assert active.version_id == "v1.0"

    assert updater.activate_dataset("nvd_cve_2.0", v2) is True
    active2 = sql_repo.get_active_dataset_version("nvd_cve_2.0")
    assert active2.version_id == "v2.0"

    assert updater.rollback_dataset("nvd_cve_2.0", target_version_id="v1.0") is True
    active_rolled = sql_repo.get_active_dataset_version("nvd_cve_2.0")
    assert active_rolled.version_id == "v1.0"
