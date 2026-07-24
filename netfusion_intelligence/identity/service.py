"""
Identity Service Layer for NetFusion CIIL.
Provides facade methods for entity resolution, merging, external lookup, relationship management, provenance, and statistics.
"""

from typing import Any, Dict, List, Optional

from netfusion_intelligence.identity.events import IdentityEventPublisher
from netfusion_intelligence.identity.mapper import FeedMappingConfig, IdentityMapper
from netfusion_intelligence.identity.models import (
    CanonicalEntity,
    EntityProvenance,
    ExternalIdentifier,
)
from netfusion_intelligence.identity.registry import IdentityRegistry
from netfusion_intelligence.identity.relationship import CanonicalRelationship, RelationshipEngine
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver
from netfusion_intelligence.identity.statistics import IdentityStatistics, IdentityStatisticsTracker
from netfusion_intelligence.identity.validator import IdentityValidator, ValidationReport


class IdentityService:
    """
    Unified Service Layer for NetFusion Canonical Intelligence Identity Layer (CIIL).
    """

    def __init__(
        self,
        repository: Optional[IdentityRepository] = None,
        event_publisher: Optional[IdentityEventPublisher] = None,
    ):
        self.repository = repository or IdentityRepository(":memory:")
        self.event_publisher = event_publisher or IdentityEventPublisher()
        self.registry = IdentityRegistry()
        self.validator = IdentityValidator()
        self.mapper = IdentityMapper()
        self.relationship_engine = RelationshipEngine()
        self.resolver = IdentityResolver(
            repository=self.repository,
            event_publisher=self.event_publisher,
        )
        self.statistics_tracker = IdentityStatisticsTracker(repository=self.repository)

    def resolve_entity(
        self,
        entity_type: str,
        display_name: str,
        external_identifiers: List[ExternalIdentifier],
        aliases: Optional[List[str]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        feed_source: str = "UNKNOWN",
        dataset_version: str = "1.0",
        original_object_id: Optional[str] = None,
        confidence: float = 1.0,
    ) -> CanonicalEntity:
        """
        Resolves an incoming feed entity into a CanonicalEntity.
        Performs duplicate detection and merging.
        """
        return self.resolver.resolve(
            entity_type=entity_type,
            display_name=display_name,
            external_identifiers=external_identifiers,
            aliases=aliases,
            description=description,
            tags=tags,
            metadata=metadata,
            feed_source=feed_source,
            dataset_version=dataset_version,
            original_object_id=original_object_id,
            confidence=confidence,
        )

    def map_and_resolve(
        self,
        raw_data: Dict[str, Any],
        mapping_config: FeedMappingConfig,
        feed_source: str,
        dataset_version: str = "1.0",
    ) -> CanonicalEntity:
        """
        Maps raw feed object using FeedMappingConfig and resolves into a CanonicalEntity.
        """
        mapped_entity, _ = self.mapper.map_raw_object(
            raw_data=raw_data,
            config=mapping_config,
            feed_source=feed_source,
            dataset_version=dataset_version,
        )
        return self.resolve_entity(
            entity_type=mapped_entity.entity_type,
            display_name=mapped_entity.display_name,
            external_identifiers=list(mapped_entity.external_identifiers),
            aliases=list(mapped_entity.aliases),
            description=mapped_entity.description,
            tags=list(mapped_entity.tags),
            metadata=mapped_entity.metadata,
            feed_source=feed_source,
            dataset_version=dataset_version,
            original_object_id=str(raw_data.get("id", raw_data.get("uuid", ""))),
            confidence=mapped_entity.confidence,
        )

    def merge_entity(
        self,
        primary_uuid: str,
        secondary_uuid: str,
        reason: str = "Manual merge requested",
    ) -> CanonicalEntity:
        """
        Merges secondary canonical entity into primary canonical entity.
        """
        return self.resolver.merge_entities(
            primary_uuid=primary_uuid,
            secondary_uuid=secondary_uuid,
            reason=reason,
            merged_by="IdentityService",
        )

    def find_by_uuid(self, canonical_uuid: str) -> Optional[CanonicalEntity]:
        """
        Look up canonical entity by UUID.
        """
        return self.repository.get_entity(canonical_uuid)

    def find_by_external_id(self, source: str, identifier: str) -> List[CanonicalEntity]:
        """
        Look up canonical entities by external identifier (source + ID).
        """
        return self.repository.find_by_external_id(source=source, identifier=identifier)

    def search(
        self,
        query: Optional[str] = None,
        entity_type: Optional[str] = None,
        feed_source: Optional[str] = None,
        limit: int = 100,
    ) -> List[CanonicalEntity]:
        """
        Search canonical entities by query string, entity type, or feed source.
        """
        return self.repository.search(
            query=query,
            entity_type=entity_type,
            feed_source=feed_source,
            limit=limit,
        )

    def list_sources(self) -> List[str]:
        """
        List all distinct intelligence sources registered in CIIL.
        """
        return self.repository.list_sources()

    def list_aliases(self, canonical_uuid: str) -> List[str]:
        """
        List aliases for a given canonical entity.
        """
        return self.repository.list_aliases(canonical_uuid)

    def link_relationship(
        self,
        source_canonical_uuid: str,
        target_canonical_uuid: str,
        relationship_type: str,
        originating_source: str,
        confidence: float = 1.0,
        version: str = "1.0",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CanonicalRelationship:
        """
        Establishes a canonical relationship between two entities.
        """
        rel = self.relationship_engine.link_relationship(
            source_canonical_uuid=source_canonical_uuid,
            target_canonical_uuid=target_canonical_uuid,
            relationship_type=relationship_type,
            originating_source=originating_source,
            confidence=confidence,
            version=version,
            metadata=metadata,
        )
        self.repository.save_relationship(rel)
        return rel

    def list_relationships(
        self,
        canonical_uuid: str,
        direction: str = "both",
        relationship_type: Optional[str] = None,
    ) -> List[CanonicalRelationship]:
        """
        Retrieves relationships associated with a canonical entity.
        """
        return self.repository.get_relationships(
            canonical_uuid=canonical_uuid,
            direction=direction,
            relationship_type=relationship_type,
        )

    def get_provenance(self, canonical_uuid: str) -> List[EntityProvenance]:
        """
        Retrieves complete provenance audit log for a canonical entity.
        """
        return self.repository.get_provenance(canonical_uuid)

    def get_merge_history(self, canonical_uuid: str):
        """
        Retrieves merge history for a canonical entity.
        """
        return self.repository.get_merge_history(canonical_uuid)

    def get_statistics(self) -> IdentityStatistics:
        """
        Retrieves identity statistics.
        """
        return self.statistics_tracker.generate_statistics(
            duplicate_prevented_count=self.resolver.duplicate_prevented_count
        )

    def validate_entity(self, entity: CanonicalEntity) -> ValidationReport:
        """
        Validates entity structure.
        """
        return self.validator.validate_entity(entity)
