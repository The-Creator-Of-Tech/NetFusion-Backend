"""
Pytest configuration and fixture feed plugins for netfusion_intelligence tests.
"""

from typing import Any, Dict, List, Optional
import pytest

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.events import EventBus
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult, ImportStatus
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.utils.checksum import compute_checksum
from netfusion_intelligence.utils.validation import GenericValidationEngine


class SampleGenericIntelligenceFeed(FeedInterface):
    """
    Generic intelligence feed implementation used for framework verification tests.
    """

    def __init__(self, feed_id: str = "sample_intel_feed", auto_activate: bool = True):
        self._metadata = FeedMetadata(
            feed_id=feed_id,
            feed_name=f"Sample Intelligence Feed ({feed_id})",
            description="Generic threat intelligence feed plugin for testing",
        )
        self._config = FeedConfig(enabled=True, auto_activate=auto_activate)
        self.raw_data_payload = [{"id": "INTEL-001", "name": "Threat Alpha", "severity": "HIGH"}]
        self.should_fail_validation = False
        self.should_fail_download = False
        self.stored_datasets: Dict[str, Any] = {}
        self.activated_versions: List[str] = []
        self.rolled_back_versions: List[str] = []

    @property
    def metadata(self) -> FeedMetadata:
        return self._metadata

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config

    def fetch_raw_data(self) -> Any:
        if self.should_fail_download:
            raise RuntimeError("Network timeout downloading feed")
        return self.raw_data_payload

    def verify_checksum(self, raw_data: Any) -> bool:
        return True

    def parse(self, raw_data: Any) -> Any:
        return raw_data

    def normalize(self, parsed_data: Any) -> Any:
        return parsed_data

    def validate(self, normalized_data: Any) -> ValidationResult:
        if self.should_fail_validation:
            res = ValidationResult()
            res.add_error("TestRule", "Simulated validation failure")
            return res
        validator = GenericValidationEngine(required_fields=["id", "name"])
        return validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        self.stored_datasets[dataset_version.version_id] = normalized_data
        return ImportResult(
            import_id=str(__import__("uuid").uuid4()),
            feed_id=self.feed_id,
            version_id=dataset_version.version_id,
            status=ImportStatus.STORING,
            records_processed=len(normalized_data) if isinstance(normalized_data, list) else 1,
            records_inserted=len(normalized_data) if isinstance(normalized_data, list) else 1,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        return 2

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        self.activated_versions.append(dataset_version.version_id)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        self.rolled_back_versions.append(dataset_version.version_id)


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def engine(repo, event_bus):
    return IntelligenceEngine(repository=repo, event_bus=event_bus)


@pytest.fixture
def sample_feed():
    return SampleGenericIntelligenceFeed()
