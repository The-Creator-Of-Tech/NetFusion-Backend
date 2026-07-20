"""
Unit tests for Domain Event Audit Log persistence.
"""

import pytest
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult


class AuditTestFeed(FeedInterface):
    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id="audit_test_feed", feed_name="Audit Feed", description="Test")

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


def test_event_audit_logging():
    engine = IntelligenceEngine()
    feed = AuditTestFeed()
    
    # 1. FeedRegistered event
    engine.register_feed(feed)

    # 2. FeedStarted, ValidationPassed, FeedCompleted events
    engine.sync_feed("audit_test_feed")

    # Fetch audit logs
    audit_logs = engine.get_audit_logs(feed_id="audit_test_feed")
    assert len(audit_logs) >= 3

    event_types = [log.event_type for log in audit_logs]
    assert "FeedRegistered" in event_types
    assert "FeedStarted" in event_types
    assert "FeedCompleted" in event_types
    assert "ValidationPassed" in event_types

    # Test filtering by event_type
    completed_logs = engine.get_audit_logs(event_type="FeedCompleted")
    assert len(completed_logs) >= 1
    assert completed_logs[0].event_type == "FeedCompleted"
