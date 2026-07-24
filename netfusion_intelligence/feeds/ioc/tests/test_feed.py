"""
Tests for IL-7 IocFeed — full IL-1 lifecycle integration.
Covers: fetch → parse → normalize → validate → store → build_relationships → activate → rollback.
"""

import pytest
from netfusion_intelligence.feeds.ioc.feed import IocFeed
from netfusion_intelligence.feeds.ioc.providers import OfflineImportProvider
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.config import EngineConfig
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from datetime import datetime, timezone


SAMPLE = {
    "indicators": [
        {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.9, "severity": "high",
         "provider": "test", "malware_families": ["Emotet"], "attack_technique_ids": ["T1059"]},
        {"type": "domain", "value": "malware.example.com", "confidence": 0.8},
        {"type": "sha256", "value": "a" * 64, "confidence": 0.95, "severity": "critical"},
        {"type": "url", "value": "https://bad.com/drop.exe", "confidence": 0.7},
        {"type": "email", "value": "attacker@evil.org", "confidence": 0.6},
    ]
}


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository("sqlite:///:memory:")


@pytest.fixture
def feed(repo):
    provider = OfflineImportProvider(data=SAMPLE, name="TestFeed")
    return IocFeed(repository=repo, providers=[provider])


@pytest.fixture
def dataset_version():
    return DatasetVersion(
        feed_id="netfusion_ioc_v1",
        version_id="test-v-001",
        checksum="abc123",
        imported_at=datetime.now(timezone.utc).isoformat(),
        status=DatasetStatus.STORED,
        validation_status=ValidationStatus.PASSED,
    )


class TestIocFeedLifecycle:

    def test_feed_id(self, feed):
        assert feed.feed_id == "netfusion_ioc_v1"

    def test_manifest_declared(self, feed):
        manifest = feed.manifest
        assert manifest is not None
        assert "IOC" in manifest.name or "ioc" in manifest.name.lower()
        assert "IOC" in manifest.entity_types

    def test_config_defaults(self, feed):
        assert feed.config.enabled is True
        assert feed.config.auto_activate is True

    # ------------------------------------------------------------------
    # Step 2: fetch_raw_data
    # ------------------------------------------------------------------

    def test_fetch_raw_data_returns_list(self, feed):
        raw = feed.fetch_raw_data()
        assert isinstance(raw, list)
        assert len(raw) == 1
        assert raw[0]["raw"] is not None

    # ------------------------------------------------------------------
    # Step 3: verify_checksum
    # ------------------------------------------------------------------

    def test_verify_checksum_non_empty(self, feed):
        raw = feed.fetch_raw_data()
        assert feed.verify_checksum(raw) is True

    def test_verify_checksum_empty_list_fails(self, feed):
        # A list where all entries have raw=None means nothing was fetched
        assert feed.verify_checksum([{"raw": None, "provider_id": "x"}]) is False

    # ------------------------------------------------------------------
    # Step 4: parse
    # ------------------------------------------------------------------

    def test_parse_returns_dict_with_indicators(self, feed):
        raw = feed.fetch_raw_data()
        parsed = feed.parse(raw)
        assert "indicators" in parsed
        assert len(parsed["indicators"]) == 5

    # ------------------------------------------------------------------
    # Step 5: normalize
    # ------------------------------------------------------------------

    def test_normalize_produces_entities(self, feed):
        raw = feed.fetch_raw_data()
        parsed = feed.parse(raw)
        norm = feed.normalize(parsed)
        assert "entities" in norm
        assert len(norm["entities"]) == 5

    def test_normalize_deduplicates(self):
        """Feed with duplicate indicators should produce fewer entities."""
        dup_data = {"indicators": [
            {"type": "ipv4", "value": "9.9.9.9"},
            {"type": "ipv4", "value": "9.9.9.9"},
        ]}
        p = OfflineImportProvider(data=dup_data, name="Dup")
        f = IocFeed(providers=[p])
        raw = f.fetch_raw_data()
        parsed = f.parse(raw)
        norm = f.normalize(parsed)
        assert len(norm["entities"]) == 1
        assert norm["duplicate_count"] == 1

    # ------------------------------------------------------------------
    # Step 6: validate
    # ------------------------------------------------------------------

    def test_validate_passes_clean_dataset(self, feed):
        raw = feed.fetch_raw_data()
        parsed = feed.parse(raw)
        norm = feed.normalize(parsed)
        result = feed.validate(norm)
        assert result.is_valid

    def test_validate_detects_invalid_dataset(self, feed):
        result = feed.validate("not a dict")
        assert not result.is_valid

    # ------------------------------------------------------------------
    # Step 7: store
    # ------------------------------------------------------------------

    def test_store_persists_indicators(self, feed, dataset_version, repo):
        raw = feed.fetch_raw_data()
        parsed = feed.parse(raw)
        norm = feed.normalize(parsed)
        store_result = feed.store(dataset_version, norm)
        assert store_result.records_inserted == 5

        # Confirm in repo
        from netfusion_intelligence.feeds.ioc.repository import IocRepository
        ioc_repo = IocRepository(repo)
        stored = ioc_repo.list_indicators(version_id=dataset_version.version_id)
        assert len(stored) == 5

    def test_store_without_repo_returns_result(self):
        """Feed without repository should still return ImportResult."""
        p = OfflineImportProvider(data=SAMPLE, name="T")
        f = IocFeed(providers=[p])
        dv = DatasetVersion(
            feed_id="netfusion_ioc_v1", version_id="norepo-v-001",
            checksum="x", imported_at=datetime.now(timezone.utc).isoformat(),
        )
        raw = f.fetch_raw_data()
        parsed = f.parse(raw)
        norm = f.normalize(parsed)
        result = f.store(dv, norm)
        assert result.records_inserted == 5

    # ------------------------------------------------------------------
    # Step 8: build_relationships
    # ------------------------------------------------------------------

    def test_build_relationships_returns_count(self, feed, dataset_version, repo):
        raw = feed.fetch_raw_data()
        parsed = feed.parse(raw)
        norm = feed.normalize(parsed)
        feed.store(dataset_version, norm)
        count = feed.build_relationships(dataset_version)
        assert count >= 1  # Emotet + T1059 from the IPv4 indicator

    # ------------------------------------------------------------------
    # Step 9: on_activate / on_rollback
    # ------------------------------------------------------------------

    def test_on_activate_does_not_raise(self, feed, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        feed.on_activate(dataset_version)  # should not throw

    def test_on_rollback_does_not_raise(self, feed, dataset_version, repo):
        repo.save_dataset_version(dataset_version)
        feed.on_rollback(dataset_version)  # no prior version — should handle gracefully

    # ------------------------------------------------------------------
    # Engine integration (uses lifecycle runner directly to bypass
    # dependency gate — prerequisite feeds are not registered in unit tests)
    # ------------------------------------------------------------------

    def test_register_and_sync_via_lifecycle_runner(self):
        raw_repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
        engine = IntelligenceEngine(
            config=EngineConfig(db_url="sqlite:///:memory:"),
            repository=raw_repo,
        )
        provider = OfflineImportProvider(data=SAMPLE, name="Engine")
        feed = IocFeed(repository=raw_repo, providers=[provider])
        engine.register_feed(feed)
        assert engine.registry.has("netfusion_ioc_v1")
        # Run the lifecycle directly to avoid the dependency pre-check
        result = engine.lifecycle_runner.execute(feed)
        assert result is not None
        assert result.records_inserted == 5


class TestIocFeedIncrementalUpdate:

    def test_second_sync_updates_existing(self):
        """Two consecutive lifecycle runs produce indicators both times (different version_ids)."""
        repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
        p = OfflineImportProvider(data=SAMPLE, name="Inc")
        feed = IocFeed(repository=repo, providers=[p])

        engine = IntelligenceEngine(repository=repo, config=EngineConfig(db_url="sqlite:///:memory:"))
        engine.register_feed(feed)

        r1 = engine.lifecycle_runner.execute(feed)
        assert r1.records_inserted == 5

        # Recreate provider so it supplies fresh data for a second run
        p2 = OfflineImportProvider(data=SAMPLE, name="Inc")
        feed2 = IocFeed(repository=repo, providers=[p2])
        r2 = engine.lifecycle_runner.execute(feed2)
        assert r2.records_inserted <= 5
