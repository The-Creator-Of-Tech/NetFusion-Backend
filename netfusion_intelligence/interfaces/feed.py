"""
FeedInterface definition.
Every intelligence source plugin MUST implement this interface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.manifest import FeedManifest
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.import_result import ImportResult


class FeedInterface(ABC):
    """
    Abstract Base Class for all NetFusion Intelligence feeds.
    Strictly plugin-oriented; no switch statements or feed-specific engine logic.
    """

    @property
    @abstractmethod
    def metadata(self) -> FeedMetadata:
        """Returns metadata for this feed."""
        pass

    @property
    def manifest(self) -> FeedManifest:
        """Returns manifest for this feed. Default fallback constructs FeedManifest from metadata."""
        meta = self.metadata
        return FeedManifest(
            name=meta.feed_name if meta else "Unknown Feed",
            description=meta.description if meta else "",
            version=meta.version if meta else "1.0.0",
        )

    @property
    def feed_id(self) -> str:
        """Unique identifier of the feed."""
        return self.metadata.feed_id

    @property
    def feed_name(self) -> str:
        """Human readable feed name."""
        return self.metadata.feed_name

    @property
    def description(self) -> str:
        """Feed description."""
        return self.metadata.description

    @property
    @abstractmethod
    def config(self) -> FeedConfig:
        """Returns current configuration for this feed."""
        pass

    @config.setter
    @abstractmethod
    def config(self, new_config: FeedConfig) -> None:
        """Updates current configuration for this feed."""
        pass

    @abstractmethod
    def fetch_raw_data(self) -> Any:
        """
        Step 2: Download
        Fetch raw bytes, JSON, XML, or STIX string from remote or local source.
        """
        pass

    @abstractmethod
    def verify_checksum(self, raw_data: Any) -> bool:
        """
        Step 3: Verify
        Verify integrity/checksum of raw fetched data.
        """
        pass

    @abstractmethod
    def parse(self, raw_data: Any) -> Any:
        """
        Step 4: Parse
        Parse raw content into structured internal Python objects/dicts.
        """
        pass

    @abstractmethod
    def normalize(self, parsed_data: Any) -> Any:
        """
        Step 5: Normalize
        Convert parsed objects into standardized domain objects.
        """
        pass

    @abstractmethod
    def validate(self, normalized_data: Any) -> Any:
        """
        Step 6: Validate
        Validate normalized dataset against structural and domain rules.
        Must return a ValidationResult object.
        """
        pass

    @abstractmethod
    def store(self, dataset_version: DatasetVersion, normalized_data: Any) -> ImportResult:
        """
        Step 7: Store
        Persist normalized data for this specific dataset_version.
        """
        pass

    @abstractmethod
    def build_relationships(self, dataset_version: DatasetVersion) -> int:
        """
        Step 8: Relationship Build
        Construct graph/entity relationships for the newly stored dataset version.
        Returns the number of relationships created.
        """
        pass

    @abstractmethod
    def on_activate(self, dataset_version: DatasetVersion) -> None:
        """
        Step 9: Activate Dataset Callback
        Executed when dataset version becomes the active version.
        """
        pass

    @abstractmethod
    def on_rollback(self, dataset_version: DatasetVersion) -> None:
        """
        Rollback Callback
        Executed when dataset version is rolled back or deactivated.
        """
        pass
