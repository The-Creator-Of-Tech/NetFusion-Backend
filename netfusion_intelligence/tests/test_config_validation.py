"""
Unit tests for Feed Configuration Validation.
"""

import pytest
from netfusion_intelligence.core.config_validator import (
    ConfigurationValidationError,
    validate_cron_expression,
    validate_feed_configuration,
)
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.exceptions import FeedRegistrationError
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.models.import_result import ImportResult


class ConfigTestFeed(FeedInterface):
    def __init__(self, feed_id="config_test_feed", config=None, manifest=None):
        self._id = feed_id
        self._config = config or FeedConfig()
        self._manifest = manifest or FeedManifest(name=feed_id, description="Test")

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id=self._id, feed_name=self._id, description="Test")

    @property
    def manifest(self) -> FeedManifest:
        return self._manifest

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config

    def fetch_raw_data(self): return "data"
    def verify_checksum(self, raw_data): return True
    def parse(self, raw_data): return [{"id": 1}]
    def normalize(self, parsed_data): return parsed_data
    def validate(self, normalized_data): return ValidationResult(is_valid=True)
    def store(self, dataset_version, normalized_data): return ImportResult(records_inserted=1)
    def build_relationships(self, dataset_version): return 0
    def on_activate(self, dataset_version): pass
    def on_rollback(self, dataset_version): pass


def test_cron_expression_validator():
    assert validate_cron_expression("0 * * * *") is True
    assert validate_cron_expression("*/5 * * * *") is True
    assert validate_cron_expression("0 12 * * 1-5") is True
    assert validate_cron_expression("@hourly") is True
    assert validate_cron_expression("invalid_cron_str") is False
    assert validate_cron_expression("99 99 99 99 99") is False


def test_valid_feed_config():
    feed = ConfigTestFeed()
    validate_feed_configuration(feed)


def test_invalid_schedule_fails_registration():
    feed = ConfigTestFeed(config=FeedConfig(schedule="not_a_cron"))
    with pytest.raises(ConfigurationValidationError):
        validate_feed_configuration(feed)


def test_invalid_retry_policy_fails_registration():
    feed = ConfigTestFeed(config=FeedConfig(retry_count=-1))
    with pytest.raises(ConfigurationValidationError):
        validate_feed_configuration(feed)

    feed_delay = ConfigTestFeed(config=FeedConfig(retry_delay=-0.5))
    with pytest.raises(ConfigurationValidationError):
        validate_feed_configuration(feed_delay)


def test_invalid_timeout_fails_registration():
    feed = ConfigTestFeed(config=FeedConfig(timeout=0.0))
    with pytest.raises(ConfigurationValidationError):
        validate_feed_configuration(feed)


def test_duplicate_feed_id_fails_registration():
    engine = IntelligenceEngine()
    feed1 = ConfigTestFeed("duplicate_feed")
    feed2 = ConfigTestFeed("duplicate_feed")

    engine.register_feed(feed1)
    # Registration of different instance with same ID should fail
    with pytest.raises(FeedRegistrationError):
        validate_feed_configuration(feed2, existing_feed_ids=["duplicate_feed"])


def test_capability_mismatch_fails_registration():
    # Manifest says checksum verification is UNSUPPORTED
    manifest = FeedManifest(name="no_checksum", description="No CS", supports_checksum_verification=False)
    # Config demands checksum verification
    config = FeedConfig(checksum_required=True)
    feed = ConfigTestFeed("checksum_mismatch", config=config, manifest=manifest)

    with pytest.raises(ConfigurationValidationError) as exc_info:
        validate_feed_configuration(feed)
    assert "checksum verification" in str(exc_info.value)
