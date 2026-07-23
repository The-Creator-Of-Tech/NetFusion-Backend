"""
IL-7 IOC Enterprise Intelligence Feed.
Main FeedInterface implementation integrating all pipeline components
into the standard 13-step IL-1 lifecycle.

Supports: MISP, OpenCTI, STIX 2.1, TAXII, CSV, JSON, YAML, offline imports.
Every IOC becomes a first-class Canonical IOC Entity within CIIL.
"""

from typing import Any, Dict, List, Optional, Union

from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.security.trust_model import TrustLevel, TrustProfile

from netfusion_intelligence.feeds.ioc.manifest import get_ioc_manifest
from netfusion_intelligence.feeds.ioc.downloader import IocDownloader
from netfusion_intelligence.feeds.ioc.verifier import IocVerifier
from netfusion_intelligence.feeds.ioc.parser import IocParser
from netfusion_intelligence.feeds.ioc.normalizer import IocNormalizer
from netfusion_intelligence.feeds.ioc.validator import IocValidator
from netfusion_intelligence.feeds.ioc.correlation import IocCorrelationEngine
from netfusion_intelligence.feeds.ioc.reputation import IocReputationEngine
from netfusion_intelligence.feeds.ioc.confidence import IocConfidenceEngine
from netfusion_intelligence.feeds.ioc.repository import IocRepository
from netfusion_intelligence.feeds.ioc.updater import IocUpdater
from netfusion_intelligence.feeds.ioc.statistics import IocStatistics
from netfusion_intelligence.feeds.ioc.providers import IocProviderInterface


class IocFeed(FeedInterface):
    """
    NetFusion IL-7 IOC Enterprise Intelligence Feed.

    Pipeline:
      fetch_raw_data  → downloader (all providers)
      parse           → parser (MISP/STIX/OpenCTI/CSV/JSON/YAML)
      normalize       → normalizer (type-specific value normalization + dedup)
      validate        → validator (format + cross-ref rules)
      store           → IocRepository → ioc_indicator, ioc_source, ioc_reputation tables
      build_relations → correlation engine → ioc_relationship table
      on_activate     → IocUpdater.activate_dataset()
    """

    FEED_ID = "netfusion_ioc_v1"

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        providers: Optional[List[IocProviderInterface]] = None,
        offline_data: Optional[Any] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 */6 * * *",
            timeout=600.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )

        # Pipeline components
        self.downloader = IocDownloader(
            providers=providers or [],
            offline_data=offline_data,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
        )
        self.verifier = IocVerifier()
        self.parser = IocParser()
        self.normalizer = IocNormalizer()
        self.validator = IocValidator()
        self.correlation_engine = IocCorrelationEngine()
        self.reputation_engine = IocReputationEngine()
        self.confidence_engine = IocConfidenceEngine()
        self.statistics_engine = IocStatistics()

        # In-flight state
        self._last_normalized_data: Optional[Dict[str, Any]] = None
        self._last_raw_payloads: Optional[List[Dict[str, Any]]] = None

        # Trust Profile (generic multi-source feed)
        self.trust_profile = TrustProfile(
            publisher="NetFusion IOC Pipeline",
            organization="NetFusion",
            official_url="https://localhost/ioc",
            expected_domain="localhost",
            trust_level=TrustLevel.HIGH,
        )

    def add_provider(self, provider: IocProviderInterface) -> None:
        """Register a new IOC provider after construction."""
        self.downloader.add_provider(provider)

    # ------------------------------------------------------------------
    # FeedInterface properties
    # ------------------------------------------------------------------

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id=self.FEED_ID,
            feed_name="NetFusion IOC Enterprise Intelligence",
            description=(
                "Production-grade IOC pipeline ingesting indicators from MISP, OpenCTI, "
                "STIX 2.1, TAXII, CSV, JSON, YAML, and offline imports. "
                "Full CIIL canonical entity integration with correlation, reputation, and sightings."
            ),
            version="1.0.0",
            author="NetFusion Intelligence Architecture",
            tags=["ioc", "threat_intel", "il7", "indicators"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_ioc_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    # ------------------------------------------------------------------
    # IL-1 Lifecycle Steps
    # ------------------------------------------------------------------

    def fetch_raw_data(self) -> Any:
        """
        Step 2: Secure Download.
        Fetches raw data from all registered providers.
        Returns a list of provider payloads for the parser.
        """
        payloads = self.downloader.download()
        self._last_raw_payloads = payloads
        return payloads

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Integrity verification (structural sanity check for multi-provider list)."""
        if isinstance(raw_data, list):
            # At least one payload must be non-empty
            return any(p.get("raw") is not None for p in raw_data)
        return self.verifier.verify_structure(raw_data)

    def parse(self, raw_data: Any) -> Any:
        """
        Step 4: Parse.
        Dispatches each provider payload to the appropriate sub-parser.
        Returns a merged dict of all raw indicator dicts.
        """
        if isinstance(raw_data, list):
            return self.parser.parse_all(raw_data)
        # Fallback: single payload
        return self.parser.parse({
            "raw": raw_data, "provider_type": "json",
            "provider_id": "default", "default_confidence": 0.5, "default_tlp": "TLP:WHITE",
        })

    def normalize(self, parsed_data: Any) -> Any:
        """
        Step 5: Normalize.
        Converts raw parsed indicator dicts to IocEntity domain models.
        Applies full type-specific normalization and deduplication.
        """
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized IOC dataset."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """
        Step 7: Store.
        Persists IocEntity objects and their reputation records.
        """
        self._last_normalized_data = normalized_data
        entities = normalized_data.get("entities", {})
        entity_list = list(entities.values())

        inserted = updated = duplicates = 0

        if self._repository:
            repo = IocRepository(self._repository)

            # Store indicators
            res = repo.store_indicators(dataset_version.version_id, entity_list)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)

            # Compute and store initial reputation records
            reputations = list(
                self.reputation_engine.bulk_compute(entities).values()
            )
            repo.store_reputations(dataset_version.version_id, reputations)
        else:
            inserted = len(entity_list)

        return ImportResult(
            import_id="",
            feed_id=self.FEED_ID,
            version_id=dataset_version.version_id,
            records_processed=len(entity_list),
            records_inserted=inserted,
            records_updated=updated,
            duplicate_records=duplicates,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """
        Step 8: Relationship Build.
        Runs the correlation engine to derive IOC-to-IOC and
        IOC-to-entity relationships.
        """
        norm_data = self._last_normalized_data or {}
        entities = norm_data.get("entities", {})
        relationships = self.correlation_engine.build_relationships(entities)

        if self._repository:
            repo = IocRepository(self._repository)
            count = repo.store_relationships(dataset_version.version_id, relationships)
            return count

        return len(relationships)

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Activate Dataset."""
        if self._repository:
            updater = IocUpdater(self._repository)
            updater.activate_dataset(dataset_version)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback to previous dataset version."""
        if self._repository:
            updater = IocUpdater(self._repository)
            try:
                updater.rollback_dataset(target_version_id=dataset_version.version_id)
            except ValueError:
                pass
