"""
Main Feed Plugin Implementation for NetFusion IL-3 NVD Enterprise CVE Intelligence Pipeline.
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

from netfusion_intelligence.feeds.nvd.manifest import get_nvd_manifest
from netfusion_intelligence.feeds.nvd.downloader import DEFAULT_NVD_API_URL, NvdDownloader
from netfusion_intelligence.feeds.nvd.verifier import NvdVerifier
from netfusion_intelligence.feeds.nvd.parser import NvdParser
from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.validator import NvdValidator
from netfusion_intelligence.feeds.nvd.mapper import NvdCiilMapper
from netfusion_intelligence.feeds.nvd.repository import NvdRepository
from netfusion_intelligence.feeds.nvd.updater import NvdUpdater
from netfusion_intelligence.feeds.nvd.statistics import NvdStatistics
from netfusion_intelligence.identity.registry import IdentityRegistry
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver


class NvdCveFeed(FeedInterface):
    """
    Official NetFusion NVD Enterprise CVE JSON 2.0 Intelligence Feed Plugin.
    Connects NVD downloader, parser, normalizer, validator, CIIL mapper, and repository.
    """

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 * * * *",
            timeout=300.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )
        self.url = url or DEFAULT_NVD_API_URL
        self.api_key = api_key
        self.offline_data = offline_data

        # Component instances
        self.downloader = NvdDownloader(
            url=self.url,
            api_key=self.api_key,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
            offline_data=self.offline_data,
        )
        self.verifier = NvdVerifier()
        self.parser = NvdParser()
        self.normalizer = NvdNormalizer()
        self.validator = NvdValidator()
        self.statistics_engine = NvdStatistics()

        # CIIL Identity Setup
        if self._repository:
            identity_repo = IdentityRepository(":memory:")
            self.resolver = IdentityResolver(repository=identity_repo)
        else:
            self.resolver = None

        self.ciil_mapper = NvdCiilMapper(resolver=self.resolver)

        # Temporary in-memory cache during single-run execution
        self._last_normalized_data: Optional[Dict[str, Any]] = None

        # Trust Profile for Security Framework
        self.trust_profile = TrustProfile(
            publisher="National Vulnerability Database",
            organization="NIST",
            official_url=self.url,
            expected_domain="services.nvd.nist.gov",
            trust_level=TrustLevel.HIGH,
        )

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id="nvd_cve_2.0",
            feed_name="NVD Enterprise CVE JSON 2.0 API",
            description="Official Enterprise National Vulnerability Database CVE JSON 2.0 intelligence pipeline.",
            version="2.0.0",
            author="NIST / NetFusion Architecture",
            tags=["nvd", "cve", "vulnerability", "cvss", "cpe", "cwe", "threat_intel"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_nvd_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    def fetch_raw_data(self) -> Any:
        """Step 2: Fetch raw NVD JSON payload from remote API or offline file."""
        return self.downloader.download()

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Verify payload integrity/checksum."""
        expected_chk = getattr(self, "expected_checksum", None)
        return self.verifier.verify_checksum(raw_data, expected_checksum=expected_chk)

    def parse(self, raw_data: Any) -> Any:
        """Step 4: Parse raw NVD JSON content into structured dictionaries."""
        return self.parser.parse(raw_data)

    def normalize(self, parsed_data: Any) -> Any:
        """Step 5: Normalize parsed JSON into NvdCve domain models."""
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized dataset against structural and domain rules."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """Step 7: Persist normalized NVD CVEs into repository and CIIL layer."""
        self._last_normalized_data = normalized_data

        cve_entities = list(normalized_data.get("entities", {}).values())
        inserted = 0
        updated = 0
        duplicates = 0

        # Persist into NVD Repository
        if self._repository:
            nvd_repo = NvdRepository(self._repository)
            res = nvd_repo.store_cves(dataset_version.version_id, cve_entities)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)

            # Resolve each CVE into CIIL Canonical Entity
            if not self.resolver:
                identity_repo = IdentityRepository(":memory:")
                self.resolver = IdentityResolver(repository=identity_repo)
                self.ciil_mapper.resolver = self.resolver

            for cve in cve_entities:
                self.ciil_mapper.resolve_cve_entity(cve, dataset_version=dataset_version.version_id)
        else:
            inserted = len(cve_entities)

        return ImportResult(
            import_id="",
            feed_id=self.feed_id,
            version_id=dataset_version.version_id,
            records_processed=len(cve_entities),
            records_inserted=inserted,
            records_updated=updated,
            duplicate_records=duplicates,
        )

    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """Step 8: Construct entity relationships (CVE -> CWE, CVE -> Vendor/Product)."""
        norm_data = self._last_normalized_data or {}
        cve_entities = list(norm_data.get("entities", {}).values())

        relationship_count = 0
        for cve in cve_entities:
            relationship_count += len(cve.cwes) + len(cve.cpe_matches)

        return relationship_count

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Activate dataset version callback."""
        if self._repository:
            updater = NvdUpdater(self._repository)
            updater.activate_dataset(self.feed_id, dataset_version)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback callback."""
        if self._repository:
            updater = NvdUpdater(self._repository)
            updater.rollback_dataset(self.feed_id, target_version_id=dataset_version.version_id)
