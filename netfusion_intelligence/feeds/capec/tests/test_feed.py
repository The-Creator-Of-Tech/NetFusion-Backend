"""
Tests for CapecFeed — full pipeline integration: download → parse → normalize → validate → store → relationships → activate.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.capec.feed import CapecFeed
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML, INVALID_XML


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def feed_offline(repo):
    return CapecFeed(repository=repo, offline_data=MINIMAL_CAPEC_XML)


@pytest.fixture
def feed_no_repo():
    return CapecFeed(offline_data=MINIMAL_CAPEC_XML)


@pytest.fixture
def dataset_version():
    return DatasetVersion(
        feed_id="mitre_capec_xml",
        version_id="capec-test-v001",
        checksum="abc",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version="3.9",
        status=DatasetStatus.CREATED,
        validation_status=ValidationStatus.PASSED,
    )


class TestCapecFeedMetadata:

    def test_feed_id(self, feed_offline):
        assert feed_offline.feed_id == "mitre_capec_xml"

    def test_feed_name(self, feed_offline):
        assert "CAPEC" in feed_offline.feed_name

    def test_manifest_is_not_none(self, feed_offline):
        assert feed_offline.manifest is not None

    def test_manifest_entity_types(self, feed_offline):
        assert "CAPEC" in feed_offline.manifest.entity_types

    def test_manifest_dependencies(self, feed_offline):
        assert "mitre_cwe_xml" in feed_offline.manifest.dependencies

    def test_trust_profile_present(self, feed_offline):
        assert feed_offline.trust_profile is not None
        assert feed_offline.trust_profile.publisher == "MITRE Corporation"

    def test_config_enabled(self, feed_offline):
        assert feed_offline.config.enabled is True


class TestCapecFeedFetchRawData:

    def test_fetch_returns_bytes(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_fetch_contains_xml(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        assert b"Attack_Pattern_Catalog" in raw


class TestCapecFeedVerifyChecksum:

    def test_verify_no_expected_checksum_passes(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        assert feed_offline.verify_checksum(raw) is True

    def test_verify_correct_checksum_passes(self, feed_offline):
        import hashlib
        raw = feed_offline.fetch_raw_data()
        checksum = hashlib.sha256(raw).hexdigest()
        feed_offline.expected_checksum = checksum
        assert feed_offline.verify_checksum(raw) is True

    def test_verify_wrong_checksum_fails(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        feed_offline.expected_checksum = "deadbeef" * 8
        assert feed_offline.verify_checksum(raw) is False


class TestCapecFeedParse:

    def test_parse_returns_dict(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert isinstance(parsed, dict)
        assert "attack_patterns" in parsed

    def test_parse_catalog_version(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert parsed["catalog_version"] == "3.9"

    def test_parse_total_patterns(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert parsed["total_attack_patterns"] == 2

    def test_parse_invalid_xml_raises(self, repo):
        feed = CapecFeed(repository=repo, offline_data=INVALID_XML)
        with pytest.raises(Exception):
            feed.parse(feed.fetch_raw_data())


class TestCapecFeedNormalize:

    def test_normalize_returns_dict_with_entities(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        assert "entities" in normalized
        assert len(normalized["entities"]) == 2

    def test_normalize_contains_cwe_mappings(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        assert "cwe_mappings" in normalized
        assert len(normalized["cwe_mappings"]) >= 1

    def test_normalize_stores_last_normalized_data(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        feed_offline.normalize(parsed)
        assert feed_offline._last_normalized_data is not None


class TestCapecFeedValidate:

    def test_validate_valid_dataset_passes(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        result = feed_offline.validate(normalized)
        assert result.is_valid is True

    def test_validate_returns_validation_result(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        result = feed_offline.validate(normalized)
        assert hasattr(result, "is_valid")
        assert hasattr(result, "errors")


class TestCapecFeedStore:

    def test_store_returns_import_result(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        result = feed_offline.store(dataset_version, normalized)
        assert isinstance(result, ImportResult)

    def test_store_records_processed_count(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        result = feed_offline.store(dataset_version, normalized)
        assert result.records_processed == 2

    def test_store_cwe_mappings_persisted(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        feed_offline.store(dataset_version, normalized)
        # Verify CWE-89 is mapped to CAPEC-66 in the database
        capecs = repo.list_capec_by_cwe("CWE-89", version_id=dataset_version.version_id)
        assert any(c["capec_id"] == "CAPEC-66" for c in capecs)

    def test_store_without_repo_graceful(self, feed_no_repo, dataset_version):
        raw = feed_no_repo.fetch_raw_data()
        parsed = feed_no_repo.parse(raw)
        normalized = feed_no_repo.normalize(parsed)
        result = feed_no_repo.store(dataset_version, normalized)
        assert result.records_processed == 2


class TestCapecFeedBuildRelationships:

    def test_build_relationships_returns_int(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        feed_offline.store(dataset_version, normalized)
        count = feed_offline.build_relationships(dataset_version)
        assert isinstance(count, int)
        assert count >= 0

    def test_build_relationships_without_repo(self, feed_no_repo, dataset_version):
        raw = feed_no_repo.fetch_raw_data()
        parsed = feed_no_repo.parse(raw)
        normalized = feed_no_repo.normalize(parsed)
        feed_no_repo.store(dataset_version, normalized)
        count = feed_no_repo.build_relationships(dataset_version)
        assert count >= 0


class TestCapecFeedActivateRollback:

    def test_on_activate_sets_active_version(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        feed_offline.on_activate(dataset_version)
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active is not None
        assert active.version_id == dataset_version.version_id

    def test_on_rollback_with_two_versions(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        repo.set_active_dataset_version("mitre_capec_xml", dataset_version.version_id)
        dv2 = DatasetVersion(
            feed_id="mitre_capec_xml",
            version_id="capec-test-v002",
            checksum="def456",
            imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_version="3.10",
            status=DatasetStatus.CREATED,
            validation_status=ValidationStatus.PASSED,
        )
        repo.save_dataset_version(dv2)
        repo.set_active_dataset_version("mitre_capec_xml", dv2.version_id)
        feed_offline.on_rollback(dataset_version)
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active is not None


class TestCapecFeedFullPipeline:

    def test_full_pipeline_produces_stored_entities(self, repo, dataset_version):
        repo.save_dataset_version(dataset_version)
        feed = CapecFeed(repository=repo, offline_data=MINIMAL_CAPEC_XML)

        raw = feed.fetch_raw_data()
        assert feed.verify_checksum(raw)
        parsed = feed.parse(raw)
        normalized = feed.normalize(parsed)
        validation = feed.validate(normalized)
        assert validation.is_valid
        result = feed.store(dataset_version, normalized)
        assert result.records_processed == 2
        rel_count = feed.build_relationships(dataset_version)
        assert rel_count >= 0
        feed.on_activate(dataset_version)

        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == dataset_version.version_id

        pattern = repo.get_capec_attack_pattern("CAPEC-66")
        assert pattern is not None
        assert pattern["name"] is not None
        assert isinstance(pattern["execution_flow"], list)
        assert isinstance(pattern["mitigations"], list)
        assert isinstance(pattern["detection"], list)
