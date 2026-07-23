"""
Generic Identity Mapper for NetFusion CIIL.
Maps raw feed dictionary objects into Canonical Entities and External Identifiers dynamically.
Contains NO feed-specific logic.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from netfusion_intelligence.identity.models import CanonicalEntity, ExternalIdentifier, EntityProvenance


@dataclass
class FeedMappingConfig:
    """
    Generic mapping definition for transforming feed items into canonical structure.
    """
    entity_type: str
    display_name_field: str
    description_field: Optional[str] = None
    aliases_field: Optional[str] = None
    tags_field: Optional[str] = None
    external_id_mappings: List[Dict[str, str]] = field(default_factory=list)
    # Each entry in external_id_mappings: {"source": "MITRE", "field": "external_id", "type": "ATTACK_ID"}
    metadata_fields: List[str] = field(default_factory=list)
    custom_transform: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None


class IdentityMapper:
    """
    Generic Mapper converting arbitrary dict structures into Canonical Entities.
    """

    def map_raw_object(
        self,
        raw_data: Dict[str, Any],
        config: FeedMappingConfig,
        feed_source: str,
        dataset_version: str = "1.0",
        canonical_uuid: Optional[str] = None,
    ) -> Tuple[CanonicalEntity, EntityProvenance]:
        """
        Maps a raw input dictionary using a generic FeedMappingConfig into a CanonicalEntity and EntityProvenance.
        """
        if config.custom_transform:
            data = config.custom_transform(raw_data)
        else:
            data = raw_data

        display_name = str(data.get(config.display_name_field, "Unnamed Entity")).strip()
        if not display_name:
            display_name = "Unnamed Entity"

        description = str(data.get(config.description_field, "")) if config.description_field and data.get(config.description_field) else None

        aliases_raw = data.get(config.aliases_field, []) if config.aliases_field else []
        if isinstance(aliases_raw, str):
            aliases = [aliases_raw]
        elif isinstance(aliases_raw, (list, set, tuple)):
            aliases = [str(a) for a in aliases_raw if a]
        else:
            aliases = []

        tags_raw = data.get(config.tags_field, []) if config.tags_field else []
        if isinstance(tags_raw, str):
            tags = [tags_raw]
        elif isinstance(tags_raw, (list, set, tuple)):
            tags = [str(t) for t in tags_raw if t]
        else:
            tags = []

        # Extract external identifiers
        ext_identifiers: List[ExternalIdentifier] = []
        for mapping in config.external_id_mappings:
            source = mapping.get("source", feed_source)
            field_name = mapping.get("field")
            id_type = mapping.get("type", "CUSTOM")
            url = mapping.get("url")

            if field_name and data.get(field_name):
                val = data.get(field_name)
                if isinstance(val, list):
                    for item in val:
                        ext_identifiers.append(
                            ExternalIdentifier(
                                source=source,
                                identifier=str(item),
                                identifier_type=id_type,
                                url=url,
                            )
                        )
                else:
                    ext_identifiers.append(
                        ExternalIdentifier(
                            source=source,
                            identifier=str(val),
                            identifier_type=id_type,
                            url=url,
                        )
                    )

        # Extract metadata
        meta: Dict[str, Any] = {}
        for mf in config.metadata_fields:
            if mf in data:
                meta[mf] = data[mf]

        uuid_val = canonical_uuid or str(uuid.uuid4())

        entity = CanonicalEntity(
            canonical_uuid=uuid_val,
            entity_type=config.entity_type,
            display_name=display_name,
            aliases=tuple(aliases),
            description=description,
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            confidence=float(data.get("confidence", 1.0)),
            status=str(data.get("status", "ACTIVE")),
            active=bool(data.get("active", True)),
            tags=tuple(tags),
            metadata=meta,
            external_identifiers=tuple(ext_identifiers),
        )

        provenance = EntityProvenance.create(
            canonical_uuid=uuid_val,
            feed=feed_source,
            dataset_version=dataset_version,
            original_object_id=str(data.get("id", data.get("uuid", uuid_val))),
        )

        return entity, provenance
