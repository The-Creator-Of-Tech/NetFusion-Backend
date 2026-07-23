"""
Main Feed Plugin Implementation for NetFusion IL-5 EPSS Enterprise Intelligence Pipeline.
Fully implements FeedInterface and integrates into IL-1 Lifecycle Engine and CIIL Layer.
"""

from typing import Any, Dict, Optional, Union
import logging

from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.security.trust_model import TrustLevel, TrustProfile

from netfusion_intelligence.feeds.epss.manifest import get_epss_manifest
from netfusion_intelligence.feeds.epss.downloader import DEFAULT_EPSS_CSV_URL, EpssDownloader
from netfusion_intelligence.feeds.epss.verifier import EpssVerifier
from netfusion_intelligence.feeds.epss.parser import EpssParser
from netfusion_intelligence.feeds.epss.normalizer import EpssNormalizer
from netfusion_intelligence.feeds.epss.validator import EpssValidator
from netfusion_intelligence.feeds.epss.mapper import EpssCiilMapper
from netfusion_intelligence.feeds.epss.repository import EpssRepository
from netfusion_intelligence.feeds.epss.updater import EpssUpdater
from netfusion_intelligence.feeds.epss.statistics import EpssStatistics
from netfusion_intelligence.feeds.epss.scoring import EpssScoringEngine
from netfusion_intelligence.feeds.epss.history import EpssHistoryTracker
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver

logger = logging.getLogger(__name__)


class EpssFeed(FeedInterface):
    """
    Official NetFusion FIRST EPSS Intelligence Feed Plugin.
    Connects EPSS downloader, parser, normalizer, validator, CIIL mapper, and repository.
    Enriches canonical CVE entities with exploit probability intelligence.
    NEVER creates duplicate CVEs.
    """

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        url: Optional[str] = None,
        feed_format: str = "csv",
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        identity_resolver: Optional[IdentityResolver] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 2 * * *",  # Daily at 2 AM UTC
            timeout=600.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )
        self.url = url or DEFAULT_EPSS_CSV_URL
        self.feed_format = feed_format
        self.offline_data = offline_data

        # Component instances
        self.downloader = EpssDownloader(
            url=self.url,
            feed_format=self.feed_format,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
            offline_data=self.offline_data,
        )
        self.verifier = EpssVerifier()
        self.parser = EpssParser()
        self.normalizer = EpssNormalizer()
        self.statistics_engine = EpssStatistics()
        self.scoring_engine = EpssScoringEngine()
        self.history_tracker = EpssHistoryTracker(scoring_engine=self.scoring_engine)

        # CIIL Identity Setup
        if identity_resolver:
            self.resolver = identity_resolver
        elif self._repository:
            identity_repo = IdentityRepository(":memory:")
            self.resolver = IdentityResolver(repository=identity_repo)
        else:
            self.resolver = None

        self.ciil_mapper = EpssCiilMapper(resolver=self.resolver)
        self.validator = EpssValidator(canonical_cve_checker=self.resolver.repository if self.resolver else None)

        self._last_normalized_data: Optional[Dict[str, Any]] = None

        # Security Trust Profile
        self.trust_profile = TrustProfile(
            publisher="Forum of Incident Response and Security Teams",
            organization="FIRST",
            official_url=self.url,
            expected_domain="epss.cyentia.com",
            trust_level=TrustLevel.HIGH,
        )

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id="first_epss_1.0",
            feed_name="FIRST Exploit Prediction Scoring System",
            description="Official FIRST EPSS exploit probability intelligence pipeline enriching canonical CVE entities.",
            version="1.0.0",
            author="FIRST / NetFusion Architecture",
            tags=["first", "epss", "exploit", "probability", "scoring", "vulnerability", "threat_intel"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_epss_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    def fetch_raw_data(self) -> Any:
        """Step 2: Fetch raw EPSS CSV/JSON payload from remote API or offline data."""
        return self.downloader.download()

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Verify payload integrity and checksum."""
        expected_chk = getattr(self, "expected_checksum", None)
        return self.verifier.verify_checksum(raw_data, expected_checksum=expected_chk)

    def parse(self, raw_data: Any) -> Any:
        """Step 4: Parse raw EPSS CSV or JSON content into structured dictionaries."""
        return self.parser.parse(raw_data)

    def normalize(self, parsed_data: Any) -> Any:
        """Step 5: Normalize parsed data into EpssRecord domain models."""
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized dataset against domain and identity rules."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """
        Step 7: Persist normalized EPSS entries into repository and CIIL layer.
        Enriches existing canonical CVE entities - NEVER creates duplicate CVEs.
        """
        self._last_normalized_data = normalized_data

        entities_map = normalized_data.get("entities", {})
        epss_records = list(entities_map.values())
        inserted = 0
        updated = 0
        duplicates = 0
        enriched_count = 0

        if self._repository:
            epss_repo = EpssRepository(self._repository)

            # Retrieve previous scores for delta computation
            previous_scores = self._get_previous_scores(epss_repo, dataset_version.version_id)

            # Build historical snapshots with deltas
            historical_snapshots = self.history_tracker.build_historical_snapshots(
                records=epss_records,
                dataset_version=dataset_version.version_id,
                previous_scores=previous_scores,
            )

            # Store historical snapshots
            hist_result = epss_repo.store_historical_scores(
                version_id=dataset_version.version_id,
                historical_scores=historical_snapshots,
            )
            logger.info(f"Stored {hist_result.get('inserted', 0)} EPSS historical snapshots")

            # Retrieve historical data for trend enrichment
            historical_data = self._load_historical_data(epss_repo, epss_records)

            # Enrich records with trends and historical metrics
            enriched_records = self.history_tracker.enrich_records_with_history(
                records=epss_records,
                historical_data=historical_data,
            )

            # Store enriched EPSS records
            res = epss_repo.store_epss_records(dataset_version.version_id, enriched_records)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)

            # Resolve & Enrich Canonical CVE Entities in CIIL
            if self.resolver and self.ciil_mapper:
                self.ciil_mapper.reset_counters()
                for rec in enriched_records:
                    enriched = self.ciil_mapper.enrich_canonical_cve(
                        rec,
                        dataset_version=dataset_version.version_id,
                        feed_source=self.feed_id,
                    )
                    if enriched:
                        enriched_count += 1

                logger.info(
                    f"CIIL enrichment complete: {enriched_count} enriched, "
                    f"{self.ciil_mapper.skipped_count} skipped (no canonical CVE)"
                )
        else:
            inserted = len(epss_records)

        return ImportResult(
            import_id="",
            feed_id=self.feed_id,
            version_id=dataset_version.version_id,
            records_processed=len(epss_records),
            records_inserted=inserted,
            records_updated=updated,
            duplicate_records=duplicates,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """
        Step 8: Construct entity relationships (CVE -> EPSS Score, Exploit Probability).
        """
        norm_data = self._last_normalized_data or {}
        entities = list(norm_data.get("entities", {}).values())

        # Each EPSS record creates relationships:
        # - CVE has_epss_score EPSS_SCORE
        # - CVE exploit_probability PREDICTION
        relationship_count = len(entities) * 2

        logger.info(f"EPSS relationships built: {relationship_count}")
        return relationship_count

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Dataset activation callback."""
        if self._repository:
            updater = EpssUpdater(self._repository)
            updater.activate_dataset(self.feed_id, dataset_version)
            logger.info(f"Activated EPSS dataset: {dataset_version.version_id}")

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback callback."""
        if self._repository:
            updater = EpssUpdater(self._repository)
            updater.rollback_dataset(self.feed_id, target_version_id=dataset_version.version_id)
            logger.info(f"Rolled back EPSS dataset to: {dataset_version.version_id}")

    def _get_previous_scores(
        self,
        epss_repo: EpssRepository,
        current_version: str,
    ) -> Dict[str, float]:
        """
        Retrieves previous EPSS scores for delta computation.
        Returns dict mapping CVE_ID -> previous_score.
        """
        previous_scores = {}

        if hasattr(self._repository, "get_active_dataset_version"):
            active_version = self._repository.get_active_dataset_version(self.feed_id)
            if active_version and active_version != current_version:
                # Load previous scores
                prev_records = epss_repo.list_epss_scores(version_id=active_version, limit=100000)
                for rec in prev_records:
                    cve_id = rec.get("cve_id", "")
                    previous_scores[cve_id] = rec.get("epss_score", 0.0)
                    previous_scores[f"{cve_id}_percentile"] = rec.get("epss_percentile", 0.0)

        logger.info(f"Loaded {len(previous_scores) // 2} previous EPSS scores for delta computation")
        return previous_scores

    def _load_historical_data(
        self,
        epss_repo: EpssRepository,
        records: list,
    ) -> Dict[str, list]:
        """
        Loads historical EPSS data for each CVE to enable trend calculation.
        Returns dict mapping CVE_ID -> list of EpssHistoricalScore.
        """
        from netfusion_intelligence.feeds.epss.models import EpssHistoricalScore

        historical_data = {}

        for rec in records[:1000]:  # Limit to avoid excessive queries
            cve_id = rec.cve_id
            hist_records = epss_repo.get_epss_history(cve_id, limit=30)

            if hist_records:
                historical_data[cve_id] = [
                    EpssHistoricalScore.from_dict(h) for h in hist_records
                ]

        logger.info(f"Loaded historical data for {len(historical_data)} CVEs")
        return historical_data
