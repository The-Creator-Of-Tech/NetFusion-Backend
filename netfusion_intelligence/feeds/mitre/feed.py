"""
Main Feed Plugin Implementation for MITRE ATT&CK Enterprise STIX 2.1 Intelligence Source.
Fully implements FeedInterface and integrates into IL-1 Lifecycle Engine.
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

from netfusion_intelligence.feeds.mitre.manifest import get_mitre_manifest
from netfusion_intelligence.feeds.mitre.downloader import DEFAULT_MITRE_ATTACK_URL, MitreDownloader
from netfusion_intelligence.feeds.mitre.verifier import MitreVerifier
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.normalizer import MitreNormalizer
from netfusion_intelligence.feeds.mitre.validator import MitreValidator
from netfusion_intelligence.feeds.mitre.relationship_builder import MitreRelationshipBuilder
from netfusion_intelligence.feeds.mitre.repository import MitreRepository
from netfusion_intelligence.feeds.mitre.updater import MitreUpdater
from netfusion_intelligence.feeds.mitre.statistics import MitreStatistics


class MitreAttackFeed(FeedInterface):
    """
    Official NetFusion MITRE ATT&CK Enterprise STIX 2.1 Intelligence Feed Plugin.
    Implements standard IL-1 FeedInterface and connects downloader, parser, normalizer,
    validator, relationship builder, and repository layers.
    """

    def __init__(
        self,
        repository: Optional[IntelligenceRepositoryInterface] = None,
        config: Optional[FeedConfig] = None,
        url: Optional[str] = None,
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    ):
        self._repository = repository
        self._config = config or FeedConfig(
            enabled=True,
            schedule="0 0 * * *",
            timeout=600.0,
            retry_count=3,
            checksum_required=False,
            auto_activate=True,
        )
        self.url = url or DEFAULT_MITRE_ATTACK_URL
        self.offline_data = offline_data

        # Component instances
        self.downloader = MitreDownloader(
            url=self.url,
            timeout=self._config.timeout,
            verify_tls=self._config.verify_ssl,
            offline_data=self.offline_data,
        )
        self.verifier = MitreVerifier()
        self.parser = MitreParser()
        self.normalizer = MitreNormalizer()
        self.validator = MitreValidator()
        self.relationship_builder = MitreRelationshipBuilder()
        self.statistics_engine = MitreStatistics()

        # Temporary in-memory cache during single-run execution
        self._last_normalized_data: Optional[Dict[str, Any]] = None

        # Trust Profile for Security Framework
        self.trust_profile = TrustProfile(
            publisher="MITRE Corporation",
            organization="MITRE ATT&CK",
            official_url=self.url,
            expected_domain="raw.githubusercontent.com",
            trust_level=TrustLevel.HIGH,
        )

    @property
    def metadata(self) -> FeedMetadata:
        return FeedMetadata(
            feed_id="mitre_attack_enterprise",
            feed_name="MITRE ATT&CK Enterprise STIX 2.1",
            description="Official Enterprise MITRE ATT&CK STIX 2.1 threat intelligence dataset pipeline.",
            version="2.1.0",
            author="MITRE / NetFusion Architecture",
            tags=["mitre", "attack", "enterprise", "stix2.1", "threat_intel"],
        )

    @property
    def manifest(self) -> FeedManifest:
        return get_mitre_manifest()

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config
        self.downloader.timeout = new_config.timeout
        self.downloader.verify_tls = new_config.verify_ssl

    def fetch_raw_data(self) -> Any:
        """Step 2: Fetch raw STIX 2.1 bundle string."""
        return self.downloader.download()

    def verify_checksum(self, raw_data: Any) -> bool:
        """Step 3: Verify payload integrity/checksum."""
        expected_chk = getattr(self, "expected_checksum", None)
        return self.verifier.verify_checksum(raw_data, expected_checksum=expected_chk)

    def parse(self, raw_data: Any) -> Any:
        """Step 4: Parse STIX JSON bundle."""
        return self.parser.parse(raw_data)

    def normalize(self, parsed_data: Any) -> Any:
        """Step 5: Normalize parsed objects into domain models."""
        normalized = self.normalizer.normalize(parsed_data)
        self._last_normalized_data = normalized
        return normalized

    def validate(self, normalized_data: Any) -> ValidationResult:
        """Step 6: Validate normalized dataset."""
        return self.validator.validate(normalized_data)

    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """Step 7: Persist normalized entities into repository."""
        self._last_normalized_data = normalized_data
        
        inserted = 0
        updated = 0
        duplicates = 0

        if self._repository:
            mitre_repo = MitreRepository(self._repository)
            entities = list(normalized_data.get("entities", {}).values())
            res = mitre_repo.store_entities(dataset_version.version_id, entities)
            inserted = res.get("inserted", 0)
            updated = res.get("updated", 0)
            duplicates = res.get("duplicates", 0)
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
        """Step 8: Construct entity graph relationships."""
        norm_data = self._last_normalized_data or {}
        relationships = self.relationship_builder.build_relationships(norm_data)

        if self._repository:
            mitre_repo = MitreRepository(self._repository)
            count = mitre_repo.store_relationships(dataset_version.version_id, relationships)
            return count

        return len(relationships)

    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """Step 9: Activate dataset callback."""
        if self._repository:
            updater = MitreUpdater(self._repository)
            updater.activate_dataset(self.feed_id, dataset_version)

    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """Rollback callback."""
        if self._repository:
            updater = MitreUpdater(self._repository)
            updater.rollback_dataset(self.feed_id, target_version_id=dataset_version.version_id)
