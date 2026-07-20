"""
Unit tests for Structured Metrics service and Framework Health Dashboard.
"""

import pytest
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult


class DashboardTestFeed(FeedInterface):
    def __init__(self, feed_id="dash_feed"):
        self._id = feed_id

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id=self._id, feed_name=self._id, description="Dash")

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


def test_metrics_service():
    engine = IntelligenceEngine()
    feed = DashboardTestFeed("metrics_feed")
    engine.register_feed(feed)

    engine.sync_feed("metrics_feed")

    metrics = engine.get_metrics()
    assert metrics.successful_imports >= 1
    assert metrics.failed_imports == 0
    assert metrics.average_import_duration > 0.0
    assert metrics.active_feeds == 1
    assert metrics.disabled_feeds == 0


def test_health_dashboard_summary():
    engine = IntelligenceEngine()
    feed = DashboardTestFeed("dash_feed")
    engine.register_feed(feed)

    engine.sync_feed("dash_feed")

    summary = engine.get_health()
    assert summary.total_feeds == 1
    assert summary.healthy_feeds == 1
    assert summary.scheduler_status == "STOPPED"
    assert summary.overall_framework_health == "HEALTHY"

    # Check feed health record details
    fh = summary.feed_healths[0]
    assert fh.feed_id == "dash_feed"
    assert fh.last_success_at is not None
    assert fh.average_execution_time > 0.0
    assert fh.validation_health == "PASSED"
    assert fh.dependency_health == "HEALTHY"
