"""
Tests for CapecUpdater — version comparison, activation, and rollback.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.capec.updater import CapecUpdater
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def updater(repo):
    return CapecUpdater(repo)


def _make_version(feed_id, version_id, checksum="abc123", status=DatasetStatus.ACTIVE):
    return DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum=checksum,
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version="3.9",
        status=status,
        validation_status=ValidationStatus.PASSED,
    )


class TestCapecUpdaterCompareVersions:

    def test_no_active_version_requires_update(self, updater):
        result = updater.compare_versions("newchecksum")
        assert result["update_required"] is True
        assert result["active_version_id"] is None

    def test_same_checksum_no_update_needed(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v001", checksum="abc123")
        repo.save_dataset_version(dv)
        repo.set_active_dataset_version("mitre_capec_xml", "v001")
        result = updater.compare_versions("abc123")
        assert result["update_required"] is False
        assert result["active_version_id"] == "v001"

    def test_checksum_case_insensitive(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v001", checksum="ABC123")
        repo.save_dataset_version(dv)
        repo.set_active_dataset_version("mitre_capec_xml", "v001")
        result = updater.compare_versions("abc123")
        assert result["update_required"] is False

    def test_different_checksum_requires_update(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v001", checksum="oldchecksum")
        repo.save_dataset_version(dv)
        repo.set_active_dataset_version("mitre_capec_xml", "v001")
        result = updater.compare_versions("newchecksum")
        assert result["update_required"] is True
        assert result["active_version_id"] == "v001"


class TestCapecUpdaterActivateDataset:

    def test_activate_sets_active_version(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v002", status=DatasetStatus.CREATED)
        repo.save_dataset_version(dv)
        result = updater.activate_dataset(dv)
        assert result is True
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active is not None
        assert active.version_id == "v002"

    def test_activate_deactivates_previous_version(self, updater, repo):
        dv1 = _make_version("mitre_capec_xml", "v001")
        dv2 = _make_version("mitre_capec_xml", "v002", status=DatasetStatus.CREATED)
        repo.save_dataset_version(dv1)
        repo.set_active_dataset_version("mitre_capec_xml", "v001")
        repo.save_dataset_version(dv2)
        updater.activate_dataset(dv2)
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == "v002"


class TestCapecUpdaterRollback:

    def test_rollback_no_versions_returns_none(self, updater):
        result = updater.rollback_dataset()
        assert result is None

    def test_rollback_to_specific_version(self, updater, repo):
        dv1 = _make_version("mitre_capec_xml", "v001")
        dv2 = _make_version("mitre_capec_xml", "v002")
        repo.save_dataset_version(dv1)
        repo.save_dataset_version(dv2)
        repo.set_active_dataset_version("mitre_capec_xml", "v002")
        result = updater.rollback_dataset(target_version_id="v001")
        assert result is not None
        assert result.version_id == "v001"
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == "v001"

    def test_rollback_unknown_version_raises(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v001")
        repo.save_dataset_version(dv)
        with pytest.raises(ValueError, match="not found"):
            updater.rollback_dataset(target_version_id="nonexistent")

    def test_rollback_no_previous_version_raises(self, updater, repo):
        dv = _make_version("mitre_capec_xml", "v001")
        repo.save_dataset_version(dv)
        repo.set_active_dataset_version("mitre_capec_xml", "v001")
        with pytest.raises(ValueError, match="No previous"):
            updater.rollback_dataset()
