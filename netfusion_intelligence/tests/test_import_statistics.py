"""
Unit tests for 13 Import Statistics metrics and permanent history logging.
"""

import pytest
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult


class StatsTestFeed(FeedInterface):
    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id="stats_test_feed", feed_name="Stats Feed", description="Test")

    @property
    def config(self) -> FeedConfig:
        return FeedConfig()

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        pass

    def fetch_raw_data(self):
        return "raw_test_data_string_for_bytes_count"

    def verify_checksum(self, raw_data):
        return True

    def parse(self, raw_data):
        return [{"id": 101}, {"id": 102}, {"id": 103}]

    def normalize(self, parsed_data):
        return parsed_data

    def validate(self, normalized_data):
        return ValidationResult(is_valid=True, total_checked=3)

    def store(self, dataset_version, normalized_data):
        res = ImportResult()
        res.records_inserted = 2
        res.records_updated = 1
        res.records_deleted = 0
        res.duplicate_records = 0
        return res

    def build_relationships(self, dataset_version):
        return 4

    def on_activate(self, dataset_version):
        pass

    def on_rollback(self, dataset_version):
        pass


def test_import_statistics_recording_and_persistence():
    engine = IntelligenceEngine()
    feed = StatsTestFeed()
    engine.register_feed(feed)

    res = engine.sync_feed("stats_test_feed")

    # Verify all 13 metrics
    assert res.records_downloaded == 3
    assert res.records_parsed == 3
    assert res.records_processed == 3
    assert res.records_inserted == 2
    assert res.records_updated == 1
    assert res.records_deleted == 0
    assert res.duplicate_records == 0
    assert res.validation_errors == 0
    assert res.relationship_count == 4
    assert res.execution_time > 0.0
    assert res.download_size > 0
    assert res.checksum is not None
    assert res.trigger == "manual"

    # Query import history from repository
    history = engine.get_import_history(feed_id="stats_test_feed")
    assert len(history) >= 1
    h = history[0]
    assert h.records_inserted == 2
    assert h.relationship_count == 4
    assert h.checksum == res.checksum
    assert h.trigger == "manual"
