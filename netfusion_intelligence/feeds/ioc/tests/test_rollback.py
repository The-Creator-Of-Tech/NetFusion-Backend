"""Tests for IL-7 IocUpdater — version activation, comparison, and rollback."""

import pytest
from datetime import datetime, timezone
from netfusion_intelligence.feeds.ioc.updater import IocUpdater
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def make_version(version_id, checksum="abc123", status=DatasetStatus.STORED):
    return DatasetVersion(
        feed_id="netfusion_ioc_v1",
        version_id=version_id,
        checksum=checksum,
        imported_at=datetime.now(timezone.utc).isoformat(),
        status=status,
        validation_status=ValidationStatus.PASSED,
    )


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository("sqlite:///:memory:")


@pytest.fixture
def updater(repo):
    return IocUpdater(repo)


class TestIocUpdater:

    def test_compare_versions_no_active(self, updater):
        result = updater.compare_versions("newchecksum")
        assert result["update_required"] is True
        assert result["active_version_id"] is None

    def test_compare_versions_same_checksum(self, updater, repo):
        v = make_version("v1", checksum="same_hash", status=DatasetStatus.ACTIVE)
        repo.save_dataset_version(v)
        repo.set_active_dataset_version("netfusion_ioc_v1", "v1")
        result = updater.compare_versions("same_hash")
        assert result["update_required"] is False

    def test_compare_versions_different_checksum(self, updater, repo):
        v = make_version("v1", checksum="old_hash", status=DatasetStatus.ACTIVE)
        repo.save_dataset_version(v)
        repo.set_active_dataset_version("netfusion_ioc_v1", "v1")
        result = updater.compare_versions("new_hash")
        assert result["update_required"] is True

    def test_activate_dataset(self, updater, repo):
        v = make_version("v2")
        repo.save_dataset_version(v)
        success = updater.activate_dataset(v)
        assert success is True
        active = repo.get_active_dataset_version("netfusion_ioc_v1")
        assert active.version_id == "v2"

    def test_rollback_to_previous(self, updater, repo):
        v1 = make_version("v1", status=DatasetStatus.ACTIVE)
        v2 = make_version("v2", status=DatasetStatus.STORED)
        repo.save_dataset_version(v1)
        repo.save_dataset_version(v2)
        repo.set_active_dataset_version("netfusion_ioc_v1", "v2")
        rolled = updater.rollback_dataset()
        assert rolled is not None

    def test_rollback_to_specific_version(self, updater, repo):
        v1 = make_version("v1", status=DatasetStatus.STORED)
        v2 = make_version("v2", status=DatasetStatus.ACTIVE)
        repo.save_dataset_version(v1)
        repo.save_dataset_version(v2)
        repo.set_active_dataset_version("netfusion_ioc_v1", "v2")
        rolled = updater.rollback_dataset(target_version_id="v1")
        assert rolled.version_id == "v1"

    def test_rollback_nonexistent_raises(self, updater, repo):
        v = make_version("v1")
        repo.save_dataset_version(v)
        with pytest.raises(ValueError, match="not found for rollback"):
            updater.rollback_dataset(target_version_id="nonexistent-ver")

    def test_rollback_no_versions_returns_none(self, updater):
        result = updater.rollback_dataset()
        assert result is None
