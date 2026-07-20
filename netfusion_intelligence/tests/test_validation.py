"""
Unit tests for Generic Validation Engine and validation constraints.
"""

import pytest
from netfusion_intelligence.core.exceptions import SchedulerError, ValidationError
from netfusion_intelligence.models.dataset import DatasetStatus, ValidationStatus
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed
from netfusion_intelligence.utils.validation import GenericValidationEngine, validate_checksum


def test_validation_rules_duplicate_and_missing():
    validator = GenericValidationEngine(required_fields=["id", "name"])
    dataset = [
        {"id": "1", "name": "Item 1"},
        {"id": "1", "name": "Item 1 Duplicate"},
        {"id": "2"},  # Missing name
    ]

    res = validator.validate(dataset)
    assert res.is_valid is False
    assert len(res.errors) >= 2
    rule_names = [e.rule_name for e in res.errors]
    assert "DuplicateIdentifierRule" in rule_names
    assert "MissingRequiredFieldsRule" in rule_names


def test_validation_failure_prevents_dataset_activation(engine):
    feed = SampleGenericIntelligenceFeed("bad_validation_feed")
    feed.should_fail_validation = True
    feed.config.retry_count = 0
    engine.register_feed(feed)

    with pytest.raises((ValidationError, SchedulerError)):
        engine.sync_feed("bad_validation_feed")

    versions = engine.get_dataset_versions("bad_validation_feed")
    assert len(versions) == 1
    assert versions[0].status == DatasetStatus.FAILED
    assert versions[0].validation_status == ValidationStatus.FAILED
