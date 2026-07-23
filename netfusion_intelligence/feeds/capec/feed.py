"""
Main Feed Plugin Implementation for MITRE CAPEC Enterprise Intelligence Source (IL-6).
Fully implements FeedInterface and integrates into the IL-1 Lifecycle Engine.
"""

from typing import Any, Dict, Optional, Union

from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.security.trust_model import TrustLevel, TrustProfile

from netfusion_intelligence.feeds.capec.manifest import get_capec_manifest
from netfusion_intelligence.feeds.capec.downloader import DEFAULT_CAPEC_URL, CapecDownloader
from netfusion_intelligence.feeds.capec.verifier import CapecVerifier
from netfusion_intelligence.feeds.capec.parser import CapecParser
from netfusion_intelligence.feeds.capec.normalizer import CapecNormalizer
from netfusion_intelligence.feeds.capec.validator import CapecValidator
from netfusion_intelligence.feeds.capec.repository import CapecRepository
from netfusion_intelligence.feeds.capec.updater import CapecUpdater
from netfusion_intelligence.feeds.capec.statistics import CapecStatistics


class CapecFeed(FeedInterface):
    """
    Official NetFusion MITRE CAPEC Enterprise Intelligence Feed Plugin.
    Implements standard IL-1 FeedInterface: download → verify → parse → normalize → validate → store → relationships → activate.
    """

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        url: Optional[str] = None,
        offline_data: Optional[Union[bytes, str]] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 2 * * 0",
            timeout=300.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )
        self.url = url or DEFAULT_CAPEC_URL
        self.offline_data = offline_data

        # Pipeline components
        self.downloader = CapecDownloader(
            url=self.url,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
            offline_data=self.offline_data,
        )
        self.verifier = CapecVerifier()
        self.parser = CapecParser()
        self.normalizer = CapecNormalizer()
        self.validator = CapecValidator()
        self.statistics_engine = CapecStatistics()

        # In-memory state for current pipeline run
        self._last_normalized_data: Optional[Dict[str, Any]] = None
        self._last_raw_data: Optional[bytes] = None

        # Trust Profile
        self.trust_profile = TrustProfile(
            publisher="MITRE Corporation",
            organization="MITRE CAPEC",
            official_url=self.url,
            expected_domain="capec.mitre.org",
            trust_level=TrustLevel.HIGH,
        )

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id="mitre_capec_xml",
            feed_name="MITRE CAPEC Enterprise Intelligence",
            description="Official MITRE Common Attack Pattern Enumeration and Classification (CAPEC) XML intelligence pipeline.",
            version="1.0.0",
            author="MITRE / NetFusion Architecture",
            tags=["mitre", "capec", "attack_pattern", "il6", "knowledge_graph"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_capec_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    def fetch_raw_data(self) -> Any:
        """Step 2: Fetch raw CAPEC XML bytes."""
        raw = self.downloader.download()
        self._last_raw_data = raw
        return raw

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Verify payload integrity."""
        expected = getattr(self, "expected_checksum", None)
        return self.verifier.verify_checksum(raw_data, expected_checksum=expected)

    def parse(self, raw_data: Any) -> Any:
        """Step 4: Parse raw XML into structured catalog dict."""
        return self.parser.parse(raw_data)

    def normalize(self, parsed_data: Any) -> Any:
        """Step 5: Normalize parsed data into CapecEntity domain models."""
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized CAPEC dataset."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """Step 7: Persist normalized CAPEC entities into the repository."""
        self._last_normalized_data = normalized_data
        inserted = 0
        updated = 0
        duplicates = 0

        if self._repository:
            repo = CapecRepository(self._repository)
            entities = list(normalized_data.get("entities", {}).values())
            res = repo.store_attack_patterns(dataset_version.version_id, entities)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)

            # Store CWE cross-reference mappings
            cwe_mappings = normalized_data.get("cwe_mappings", [])
            repo.store_cwe_mappings(dataset_version.version_id, cwe_mappings)
        else:
            inserted = len(normalized_data.get("entities", {}))

        return ImportResult(
            import_id="",
            feed_id=self.feed_id,
            version_id=dataset_version.version_id,
            records_processed=len(normalized_data.get("entities", {})),
            records_inserted=inserted,
            records_updated=updated,
            duplicate_records=duplicates,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """Step 8: Store CAPEC-to-CAPEC relationships in the knowledge graph."""
        norm_data = self._last_normalized_data or {}
        relationships = norm_data.get("relationships", [])

        if self._repository:
            repo = CapecRepository(self._repository)
            count = repo.store_relationships(dataset_version.version_id, relationships)
            return count

        return len(relationships)

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Activate dataset."""
        if self._repository:
            updater = CapecUpdater(self._repository)
            updater.activate_dataset(dataset_version)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback to a previous dataset version."""
        if self._repository:
            updater = CapecUpdater(self._repository)
            updater.rollback_dataset(target_version_id=dataset_version.version_id)
