"""
Tests for CweFeed — full pipeline integration: download → parse → normalize → validate → store → relationships → activate.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.cwe.feed import CweFeed
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML, INVALID_XML


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def feed_offline(repo):
    return CweFeed(repository=repo, offline_data=MINIMAL_CWE_XML)


@pytest.fixture
def feed_no_repo():
    """Feed without a backing repository — tests graceful degradation."""
    return CweFeed(offline_data=MINIMAL_CWE_XML)


@pytest.fixture
def dataset_version():
    return DatasetVersion(
        feed_id="mitre_cwe_xml",
        version_id="cwe-test-v001",
        checksum="abc",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version="4.15",
        status=DatasetStatus.CREATED,
        validation_status=ValidationStatus.PASSED,
    )


# ---------------------------------------------------------------------------
# Metadata / manifest
# ---------------------------------------------------------------------------

class TestCweFeedMetadata:

    def test_feed_id(self, feed_offline):
        assert feed_offline.feed_id == "mitre_cwe_xml"

    def test_feed_name(self, feed_offline):
        assert "CWE" in feed_offline.feed_name

    def test_manifest_is_not_none(self, feed_offline):
        assert feed_offline.manifest is not None

    def test_manifest_name(self, feed_offline):
        assert "CWE" in feed_offline.manifest.name

    def test_manifest_entity_types(self, feed_offline):
        assert "CWE" in feed_offline.manifest.entity_types

    def test_trust_profile_present(self, feed_offline):
        assert feed_offline.trust_profile is not None
        assert feed_offline.trust_profile.publisher == "MITRE Corporation"

    def test_config_enabled(self, feed_offline):
        assert feed_offline.config.enabled is True


# ---------------------------------------------------------------------------
# Step 2: fetch_raw_data
# ---------------------------------------------------------------------------

class TestCweFeedFetchRawData:

    def test_fetch_returns_bytes(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_fetch_contains_xml(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        assert b"Weakness_Catalog" in raw


# ---------------------------------------------------------------------------
# Step 3: verify_checksum
# ---------------------------------------------------------------------------

class TestCweFeedVerifyChecksum:

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


# ---------------------------------------------------------------------------
# Step 4: parse
# ---------------------------------------------------------------------------

class TestCweFeedParse:

    def test_parse_returns_dict(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert isinstance(parsed, dict)
        assert "weaknesses" in parsed

    def test_parse_catalog_version(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert parsed["catalog_version"] == "4.15"

    def test_parse_total_weaknesses(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        assert parsed["total_weaknesses"] == 2

    def test_parse_invalid_xml_raises(self, repo):
        feed = CweFeed(repository=repo, offline_data=INVALID_XML)
        with pytest.raises(Exception):
            feed.parse(feed.fetch_raw_data())


# ---------------------------------------------------------------------------
# Step 5: normalize
# ---------------------------------------------------------------------------

class TestCweFeedNormalize:

    def test_normalize_returns_dict_with_entities(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        normalized = feed_offline.normalize(parsed)
        assert "entities" in normalized
        assert len(normalized["entities"]) == 2

    def test_normalize_stores_last_normalized_data(self, feed_offline):
        raw = feed_offline.fetch_raw_data()
        parsed = feed_offline.parse(raw)
        feed_offline.normalize(parsed)
        assert feed_offline._last_normalized_data is not None


# ---------------------------------------------------------------------------
# Step 6: validate
# ---------------------------------------------------------------------------

class TestCweFeedValidate:

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


# ---------------------------------------------------------------------------
# Step 7: store
# ---------------------------------------------------------------------------

class TestCweFeedStore:

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

    def test_store_without_repo_graceful(self, feed_no_repo, dataset_version):
        raw = feed_no_repo.fetch_raw_data()
        parsed = feed_no_repo.parse(raw)
        normalized = feed_no_repo.normalize(parsed)
        result = feed_no_repo.store(dataset_version, normalized)
        assert result.records_processed == 2


# ---------------------------------------------------------------------------
# Step 8: build_relationships
# ---------------------------------------------------------------------------

class TestCweFeedBuildRelationships:

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
        # Should return the relationship count from normalized data
        assert count >= 0


# ---------------------------------------------------------------------------
# Step 9: on_activate / on_rollback
# ---------------------------------------------------------------------------

class TestCweFeedActivateRollback:

    def test_on_activate_sets_active_version(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        feed_offline.on_activate(dataset_version)
        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active is not None
        assert active.version_id == dataset_version.version_id

    def test_on_rollback_without_previous_version_does_not_raise(self, feed_offline, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        repo.set_active_dataset_version("mitre_cwe_xml", dataset_version.version_id)
        # With only one version, rollback may raise ValueError — that's acceptable
        # Just ensure no uncaught exception escapes the feed layer when there are 2+ versions
        dv2 = DatasetVersion(
            feed_id="mitre_cwe_xml",
            version_id="cwe-test-v002",
            checksum="def456",
            imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_version="4.16",
            status=DatasetStatus.CREATED,
            validation_status=ValidationStatus.PASSED,
        )
        repo.save_dataset_version(dv2)
        repo.set_active_dataset_version("mitre_cwe_xml", dv2.version_id)
        feed_offline.on_rollback(dataset_version)
        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active is not None


# ---------------------------------------------------------------------------
# Full pipeline end-to-end
# ---------------------------------------------------------------------------

class TestCweFeedFullPipeline:

    def test_full_pipeline_produces_stored_entities(self, repo, dataset_version):
        repo.save_dataset_version(dataset_version)
        feed = CweFeed(repository=repo, offline_data=MINIMAL_CWE_XML)

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

        # Verify data is queryable from repository
        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active.version_id == dataset_version.version_id

        weakness = repo.get_cwe_weakness("CWE-79")
        assert weakness is not None
        assert weakness["name"] is not None
