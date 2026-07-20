"""
Unit tests for Feed Dependency Graph, Cycle Detection, and Topological Sorting.
"""

import pytest
from netfusion_intelligence.core.dependency import (
    DependencyCycleError,
    FeedDependencyGraph,
)
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.exceptions import SchedulerError
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.models.import_result import ImportResult


class MockDepFeed(FeedInterface):
    def __init__(self, feed_id: str, deps: list = None):
        self._id = feed_id
        self._deps = deps or []
        self._config = FeedConfig()

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(feed_id=self._id, feed_name=self._id, description="Dep test")

    @property
    def manifest(self) -> FeedManifest:
        return FeedManifest(name=self._id, description="Dep test", dependencies=self._deps)

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


def test_dependency_graph_topological_sort():
    # MITRE depends on nothing
    mitre = MockDepFeed("mitre")
    # CWE depends on nothing
    cwe = MockDepFeed("cwe")
    # CAPEC depends on CWE
    capec = MockDepFeed("capec", deps=["cwe"])
    # NVD depends on nothing
    nvd = MockDepFeed("nvd")
    # KEV depends on NVD
    kev = MockDepFeed("kev", deps=["nvd"])
    # EPSS depends on NVD
    epss = MockDepFeed("epss", deps=["nvd"])

    graph = FeedDependencyGraph([mitre, capec, cwe, kev, epss, nvd])
    order = graph.get_topological_order()

    assert order.index("cwe") < order.index("capec")
    assert order.index("nvd") < order.index("kev")
    assert order.index("nvd") < order.index("epss")


def test_dependency_cycle_detection():
    feed_a = MockDepFeed("feed_a", deps=["feed_b"])
    feed_b = MockDepFeed("feed_b", deps=["feed_c"])
    feed_c = MockDepFeed("feed_c", deps=["feed_a"])

    graph = FeedDependencyGraph([feed_a, feed_b, feed_c])
    cycles = graph.detect_cycles()
    assert len(cycles) > 0

    with pytest.raises(DependencyCycleError):
        graph.get_topological_order()


def test_prerequisite_validation_and_execution():
    nvd = MockDepFeed("nvd")
    kev = MockDepFeed("kev", deps=["nvd"])

    engine = IntelligenceEngine()
    engine.register_feed(nvd)
    engine.register_feed(kev)

    # Attempt to sync KEV before NVD has synced (NVD is registered but has no health record yet)
    # Both are registered so validate_prerequisites succeeds
    res = engine.sync_feed("nvd")
    assert res.status.value == "COMPLETED"

    res_kev = engine.sync_feed("kev")
    assert res_kev.status.value == "COMPLETED"


def test_prerequisite_missing_feed_fails():
    kev = MockDepFeed("kev", deps=["unregistered_nvd"])
    engine = IntelligenceEngine()
    engine.register_feed(kev)

    with pytest.raises(SchedulerError) as exc_info:
        engine.sync_feed("kev")
    assert "Prerequisite failure" in str(exc_info.value)
