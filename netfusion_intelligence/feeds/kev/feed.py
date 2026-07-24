"""
Main Feed Plugin Implementation for NetFusion IL-4 CISA KEV Enterprise Intelligence Pipeline.
Fully implements FeedInterface and integrates into IL-1 Lifecycle Engine and CIIL Layer.
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

from netfusion_intelligence.feeds.kev.manifest import get_kev_manifest
from netfusion_intelligence.feeds.kev.downloader import DEFAULT_CISA_KEV_JSON_URL, CisaKevDownloader
from netfusion_intelligence.feeds.kev.verifier import CisaKevVerifier
from netfusion_intelligence.feeds.kev.parser import CisaKevParser
from netfusion_intelligence.feeds.kev.normalizer import CisaKevNormalizer
from netfusion_intelligence.feeds.kev.validator import CisaKevValidator
from netfusion_intelligence.feeds.kev.mapper import CisaKevCiilMapper
from netfusion_intelligence.feeds.kev.repository import CisaKevRepository
from netfusion_intelligence.feeds.kev.updater import CisaKevUpdater
from netfusion_intelligence.feeds.kev.statistics import CisaKevStatistics
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver


class CisaKevFeed(FeedInterface):
    """
    Official NetFusion CISA Known Exploited Vulnerabilities (KEV) Intelligence Feed Plugin.
    Connects KEV downloader, parser, normalizer, validator, CIIL mapper, and repository.
    """

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        url: Optional[str] = None,
        feed_format: str = "json",
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        identity_resolver: Optional[IdentityResolver] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 */6 * * *",
            timeout=300.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )
        self.url = url or DEFAULT_CISA_KEV_JSON_URL
        self.feed_format = feed_format
        self.offline_data = offline_data

        # Component instances
        self.downloader = CisaKevDownloader(
            url=self.url,
            feed_format=self.feed_format,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
            offline_data=self.offline_data,
        )
        self.verifier = CisaKevVerifier()
        self.parser = CisaKevParser()
        self.normalizer = CisaKevNormalizer()
        self.statistics_engine = CisaKevStatistics()

        # CIIL Identity Setup
        if identity_resolver:
            self.resolver = identity_resolver
        elif self._repository:
            identity_repo = IdentityRepository(":memory:")
            self.resolver = IdentityResolver(repository=identity_repo)
        else:
            self.resolver = None

        self.ciil_mapper = CisaKevCiilMapper(resolver=self.resolver)
        self.validator = CisaKevValidator(canonical_cve_checker=self.resolver.repository if self.resolver else None)

        self._last_normalized_data: Optional[Dict[str, Any]] = None

        # Security Trust Profile
        self.trust_profile = TrustProfile(
            publisher="Cybersecurity and Infrastructure Security Agency",
            organization="CISA / DHS",
            official_url=self.url,
            expected_domain="www.cisa.gov",
            trust_level=TrustLevel.HIGH,
        )

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id="cisa_kev_1.0",
            feed_name="CISA Known Exploited Vulnerabilities Catalog",
            description="Official CISA Known Exploited Vulnerabilities (KEV) catalog intelligence pipeline.",
            version="1.0.0",
            author="CISA / NetFusion Architecture",
            tags=["cisa", "kev", "vulnerability", "exploitation", "ransomware", "threat_intel"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_kev_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    def fetch_raw_data(self) -> Any:
        """Step 2: Fetch raw CISA KEV JSON/CSV payload from remote API or offline data."""
        return self.downloader.download()

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Verify payload integrity and checksum."""
        expected_chk = getattr(self, "expected_checksum", None)
        return self.verifier.verify_checksum(raw_data, expected_checksum=expected_chk)

    def parse(self, raw_data: Any) -> Any:
        """Step 4: Parse raw CISA KEV JSON or CSV content into structured dictionaries."""
        return self.parser.parse(raw_data)

    def normalize(self, parsed_data: Any) -> Any:
        """Step 5: Normalize parsed data into KevRecord domain models."""
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized dataset against domain and identity rules."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """Step 7: Persist normalized KEV entries into repository and CIIL layer."""
        self._last_normalized_data = normalized_data

        entities_map = normalized_data.get("entities", {})
        kev_records = list(entities_map.values())
        inserted = 0
        updated = 0
        duplicates = 0
        enriched_count = 0

        if self._repository:
            kev_repo = CisaKevRepository(self._repository)
            res = kev_repo.store_kev_records(dataset_version.version_id, kev_records)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)

            # Resolve & Enrich Canonical CVE Entities in CIIL
            if self.resolver and self.ciil_mapper:
                for rec in kev_records:
                    enriched = self.ciil_mapper.enrich_canonical_cve(
                        rec,
                        dataset_version=dataset_version.version_id,
                        feed_source=self.feed_id,
                    )
                    if enriched:
                        enriched_count += 1
        else:
            inserted = len(kev_records)

        return ImportResult(
            import_id="",
            feed_id=self.feed_id,
            version_id=dataset_version.version_id,
            records_processed=len(kev_records),
            records_inserted=inserted,
            records_updated=updated,
            duplicate_records=duplicates,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """Step 8: Construct entity relationships (CVE -> Known Exploited, Ransomware, Product)."""
        norm_data = self._last_normalized_data or {}
        entities = list(norm_data.get("entities", {}).values())

        relationship_count = 0
        for rec in entities:
            relationship_count += len(rec.cwes) + len(rec.reference_urls) + 1
        return relationship_count

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Dataset activation callback."""
        if self._repository:
            updater = CisaKevUpdater(self._repository)
            updater.activate_dataset(self.feed_id, dataset_version)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback callback."""
        if self._repository:
            updater = CisaKevUpdater(self._repository)
            updater.rollback_dataset(self.feed_id, target_version_id=dataset_version.version_id)
