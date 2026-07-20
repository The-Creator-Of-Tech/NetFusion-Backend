"""
Unit tests for Feed Manifest model and plugin exposure.
"""

import pytest
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.interfaces.validator import ValidationResult


class DummyManifestFeed(FeedInterface):
    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id="dummy_manifest_feed", feed_name="Dummy Manifest Feed", description="Test")

    @property
    def manifest(self) -> FeedManifest:
        return FeedManifest(
            name="Dummy Manifest Feed",
            description="Test Feed",
            vendor="CustomVendor",
            version="2.0.0",
            supports_incremental_updates=True,
            supports_delta_updates=True,
            entity_types=["threat_actor", "cve"],
            relationship_types=["targets", "exploits"],
            dependencies=["parent_feed"],
        )

    @property
    def config(self) -> FeedConfig:
        return FeedConfig()

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        pass

    def fetch_raw_data(self): return "data"
    def verify_checksum(self, raw_data): return True
    def parse(self, raw_data): return [{"id": 1}]
    def normalize(self, parsed_data): return parsed_data
    def validate(self, normalized_data): return ValidationResult(is_valid=True)
    def store(self, dataset_version, normalized_data): return ImportResult(records_inserted=1)
    def build_relationships(self, dataset_version): return 2
    def on_activate(self, dataset_version): pass
    def on_rollback(self, dataset_version): pass


class DefaultManifestFeed(FeedInterface):
    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id="default_manifest_feed", feed_name="Default Manifest Feed", description="Default")

    @property
    def config(self) -> FeedConfig:
        return FeedConfig()

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        pass

    def fetch_raw_data(self): return "data"
    def verify_checksum(self, raw_data): return True
    def parse(self, raw_data): return [{"id": 1}]
    def normalize(self, parsed_data): return parsed_data
    def validate(self, normalized_data): return ValidationResult(is_valid=True)
    def store(self, dataset_version, normalized_data): return ImportResult(records_inserted=1)
    def build_relationships(self, dataset_version): return 0
    def on_activate(self, dataset_version): pass
    def on_rollback(self, dataset_version): pass


def test_feed_manifest_dataclass():
    manifest = FeedManifest(
        name="Test Feed",
        description="Test Description",
        vendor="TestVendor",
        version="1.2.3",
        feed_type="cve_feed",
        supports_incremental_updates=True,
        entity_types=["cve"],
        relationship_types=["affects"],
        dependencies=["nvd_feed"],
    )
    d = manifest.to_dict()
    assert d["name"] == "Test Feed"
    assert d["vendor"] == "TestVendor"
    assert d["supports_incremental_updates"] is True
    assert d["entity_types"] == ["cve"]
    assert d["dependencies"] == ["nvd_feed"]

    restored = FeedManifest.from_dict(d)
    assert restored.name == manifest.name
    assert restored.dependencies == manifest.dependencies


def test_custom_feed_manifest_exposure():
    feed = DummyManifestFeed()
    manifest = feed.manifest
    assert manifest.name == "Dummy Manifest Feed"
    assert manifest.vendor == "CustomVendor"
    assert manifest.version == "2.0.0"
    assert manifest.supports_incremental_updates is True
    assert manifest.entity_types == ["threat_actor", "cve"]
    assert manifest.dependencies == ["parent_feed"]


def test_default_feed_manifest_fallback():
    feed = DefaultManifestFeed()
    manifest = feed.manifest
    assert manifest.name == "Default Manifest Feed"
    assert manifest.description == "Default"
    assert manifest.vendor == "NetFusion"
    assert manifest.supports_full_sync is True
    assert manifest.dependencies == []
