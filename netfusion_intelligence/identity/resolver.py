"""
Identity Resolution Engine for NetFusion CIIL.
Handles duplicate detection, identity merging, UUID generation, provenance preservation, and audit logging.
Contains NO feed-specific logic.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from netfusion_intelligence.identity.events import (
    CanonicalEntityCreated,
    CanonicalEntityMerged,
    ExternalIdentifierAdded,
    IdentityEventPublisher,
    IdentityResolved,
)
from netfusion_intelligence.identity.models import (
    CanonicalEntity,
    EntityMergeRecord,
    EntityProvenance,
    ExternalIdentifier,
)
from netfusion_intelligence.identity.repository import IdentityRepository


class IdentityResolver:
    """
    Generic Identity Resolution Engine for NetFusion CIIL.
    """

    def __init__(
        self,
        repository: IdentityRepository,
        event_publisher: Optional[IdentityEventPublisher] = None,
    ):
        self.repository = repository
        self.event_publisher = event_publisher or IdentityEventPublisher()
        self._duplicate_prevented_count: int = 0

    @property
    def duplicate_prevented_count(self) -> int:
        return self._duplicate_prevented_count

    def resolve(
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
        Resolves an incoming entity input against existing canonical entities.
        If a match exists, merges into existing canonical entity.
        If no match exists, creates a new canonical entity with a fresh UUID.
        """
        alias_list = aliases or []
        tag_list = tags or []
        meta_dict = metadata or {}

        # 1. Search for matching existing canonical entities
        matched_entities = self._find_matches(
            entity_type=entity_type,
            external_identifiers=external_identifiers,
            aliases=alias_list,
        )

        if not matched_entities:
            # Create brand new CanonicalEntity
            new_uuid = str(uuid.uuid4())
            new_entity = CanonicalEntity(
                canonical_uuid=new_uuid,
                entity_type=entity_type,
                display_name=display_name,
                aliases=tuple(sorted(set(alias_list))),
                description=description,
                created=datetime.now(timezone.utc),
                modified=datetime.now(timezone.utc),
                confidence=confidence,
                status="ACTIVE",
                active=True,
                source_count=1,
                tags=tuple(sorted(set(tag_list))),
                metadata=meta_dict,
                external_identifiers=tuple(external_identifiers),
            )

            provenance = EntityProvenance.create(
                canonical_uuid=new_uuid,
                feed=feed_source,
                dataset_version=dataset_version,
                original_object_id=original_object_id or new_uuid,
            )

            self.repository.save_entity(new_entity, provenance=provenance)

            self.event_publisher.publish(CanonicalEntityCreated(
                canonical_uuid=new_uuid,
                entity_type=entity_type,
                display_name=display_name,
            ))
            for ext in external_identifiers:
                self.event_publisher.publish(ExternalIdentifierAdded(
                    canonical_uuid=new_uuid,
                    source=ext.source,
                    identifier=ext.identifier,
                    identifier_type=ext.identifier_type,
                ))
            self.event_publisher.publish(IdentityResolved(
                canonical_uuid=new_uuid,
                is_new=True,
                source=feed_source,
                identifier=external_identifiers[0].identifier if external_identifiers else new_uuid,
            ))

            return new_entity

        # 2. Existing match found!
        self._duplicate_prevented_count += 1
        primary = matched_entities[0]

        # If multiple canonical entities match, merge secondary entities into primary first
        if len(matched_entities) > 1:
            for secondary in matched_entities[1:]:
                if secondary.canonical_uuid != primary.canonical_uuid:
                    primary = self.merge_entities(
                        primary_uuid=primary.canonical_uuid,
                        secondary_uuid=secondary.canonical_uuid,
                        reason=f"Identity resolution auto-merge on incoming {feed_source} feed",
                        merged_by="IdentityResolver",
                    )

        # Merge incoming data into primary canonical entity
        updated_entity = self._merge_incoming_data(
            target=primary,
            display_name=display_name,
            description=description,
            incoming_ext_ids=external_identifiers,
            incoming_aliases=alias_list,
            incoming_tags=tag_list,
            incoming_metadata=meta_dict,
            feed_source=feed_source,
        )

        provenance = EntityProvenance.create(
            canonical_uuid=updated_entity.canonical_uuid,
            feed=feed_source,
            dataset_version=dataset_version,
            original_object_id=original_object_id or updated_entity.canonical_uuid,
        )

        self.repository.save_entity(updated_entity, provenance=provenance)

        self.event_publisher.publish(IdentityResolved(
            canonical_uuid=updated_entity.canonical_uuid,
            is_new=False,
            source=feed_source,
            identifier=external_identifiers[0].identifier if external_identifiers else updated_entity.canonical_uuid,
        ))

        return updated_entity

    def merge_entities(
        self,
        primary_uuid: str,
        secondary_uuid: str,
        reason: str = "Manual/System merge",
        merged_by: str = "IdentityResolver",
    ) -> CanonicalEntity:
        """
        Intelligently merges secondary CanonicalEntity into primary CanonicalEntity.
        Primary retains its UUID. Secondary is marked MERGED and deactivated.
        All attributes, external IDs, aliases, relationships, and provenance are merged.
        """
        if primary_uuid == secondary_uuid:
            primary = self.repository.get_entity(primary_uuid)
            if not primary:
                raise ValueError(f"Entity not found: {primary_uuid}")
            return primary

        primary = self.repository.get_entity(primary_uuid)
        secondary = self.repository.get_entity(secondary_uuid)

        if not primary:
            raise ValueError(f"Primary entity not found: {primary_uuid}")
        if not secondary:
            raise ValueError(f"Secondary entity not found: {secondary_uuid}")

        # Combine aliases
        all_aliases = sorted(set(primary.aliases).union(set(secondary.aliases)))
        if secondary.display_name != primary.display_name and secondary.display_name not in all_aliases:
            all_aliases.append(secondary.display_name)

        # Combine descriptions
        desc = primary.description
        if not desc and secondary.description:
            desc = secondary.description
        elif desc and secondary.description and secondary.description not in desc:
            desc = f"{desc}\n\n[Merged Description]: {secondary.description}"

        # Combine tags
        all_tags = sorted(set(primary.tags).union(set(secondary.tags)))

        # Combine metadata
        merged_meta = dict(secondary.metadata)
        merged_meta.update(primary.metadata)

        # Combine external identifiers
        ext_dict: Dict[Tuple[str, str, str], ExternalIdentifier] = {}
        for ext in list(primary.external_identifiers) + list(secondary.external_identifiers):
            key = (ext.source.lower(), ext.identifier.lower(), ext.identifier_type.lower())
            if key not in ext_dict:
                ext_dict[key] = ext
            else:
                # Keep highest confidence and updated links
                existing = ext_dict[key]
                conf = max(existing.confidence, ext.confidence)
                url = existing.url or ext.url
                ver = existing.version or ext.version
                fs = min(filter(None, [existing.first_seen, ext.first_seen]), default=None)
                ls = max(filter(None, [existing.last_seen, ext.last_seen]), default=None)
                ext_dict[key] = ExternalIdentifier(
                    source=existing.source,
                    identifier=existing.identifier,
                    identifier_type=existing.identifier_type,
                    url=url,
                    version=ver,
                    confidence=conf,
                    first_seen=fs,
                    last_seen=ls,
                )

        # Update primary entity
        updated_primary = primary.with_updated(
            aliases=tuple(all_aliases),
            description=desc,
            tags=tuple(all_tags),
            metadata=merged_meta,
            external_identifiers=tuple(ext_dict.values()),
            source_count=primary.source_count + secondary.source_count,
        )

        # Update secondary entity state to MERGED
        updated_secondary = secondary.with_updated(
            status="MERGED",
            active=False,
        )

        # Transfer provenance from secondary to primary
        transferred_prov = self.repository.transfer_provenance(secondary_uuid, primary_uuid)

        # Record merge history
        merge_record = EntityMergeRecord.create(
            target_canonical_uuid=primary_uuid,
            merged_canonical_uuid=secondary_uuid,
            reason=reason,
            provenance_transferred=transferred_prov,
            merged_by=merged_by,
        )

        # Save both entities and merge record
        self.repository.save_entity(updated_primary)
        self.repository.save_entity(updated_secondary)
        self.repository.save_merge_record(merge_record)

        self.event_publisher.publish(CanonicalEntityMerged(
            target_canonical_uuid=primary_uuid,
            merged_canonical_uuid=secondary_uuid,
            reason=reason,
        ))

        return updated_primary

    def _find_matches(
        self,
        entity_type: str,
        external_identifiers: List[ExternalIdentifier],
        aliases: List[str],
    ) -> List[CanonicalEntity]:
        """
        Finds matching active canonical entities by external identifiers or aliases.
        """
        matched_map: Dict[str, CanonicalEntity] = {}

        # Match by external identifiers
        for ext in external_identifiers:
            found = self.repository.find_by_external_id(ext.source, ext.identifier)
            for f in found:
                if f.active and f.canonical_uuid not in matched_map:
                    matched_map[f.canonical_uuid] = f

        # Match by identifier value across sources if specific match not found
        if not matched_map:
            for ext in external_identifiers:
                found = self.repository.find_by_identifier_value(ext.identifier)
                for f in found:
                    if f.active and f.canonical_uuid not in matched_map and f.entity_type.upper() == entity_type.upper():
                        matched_map[f.canonical_uuid] = f

        # Match by alias and entity_type if still not found
        if not matched_map:
            for al in aliases:
                found = self.repository.find_by_alias(al)
                for f in found:
                    if f.active and f.canonical_uuid not in matched_map and f.entity_type.upper() == entity_type.upper():
                        matched_map[f.canonical_uuid] = f

        return list(matched_map.values())

    def _merge_incoming_data(
        self,
        target: CanonicalEntity,
        display_name: str,
        description: Optional[str],
        incoming_ext_ids: List[ExternalIdentifier],
        incoming_aliases: List[str],
        incoming_tags: List[str],
        incoming_metadata: Dict[str, Any],
        feed_source: str,
    ) -> CanonicalEntity:

        # Merge external identifiers
        ext_map: Dict[Tuple[str, str, str], ExternalIdentifier] = {
            (e.source.lower(), e.identifier.lower(), e.identifier_type.lower()): e
            for e in target.external_identifiers
        }

        for ext in incoming_ext_ids:
            key = (ext.source.lower(), ext.identifier.lower(), ext.identifier_type.lower())
            if key not in ext_map:
                ext_map[key] = ext
                self.event_publisher.publish(ExternalIdentifierAdded(
                    canonical_uuid=target.canonical_uuid,
                    source=ext.source,
                    identifier=ext.identifier,
                    identifier_type=ext.identifier_type,
                ))

        # Merge aliases
        all_aliases = set(target.aliases)
        for al in incoming_aliases:
            if al and al != target.display_name:
                all_aliases.add(al)
        if display_name != target.display_name:
            all_aliases.add(display_name)

        # Merge description
        desc = target.description
        if not desc and description:
            desc = description

        # Merge tags
        all_tags = set(target.tags).union(set(incoming_tags))

        # Merge metadata
        merged_meta = dict(target.metadata)
        if incoming_metadata:
            merged_meta.update(incoming_metadata)

        return target.with_updated(
            aliases=tuple(sorted(all_aliases)),
            description=desc,
            tags=tuple(sorted(all_tags)),
            metadata=merged_meta,
            external_identifiers=tuple(ext_map.values()),
        )
