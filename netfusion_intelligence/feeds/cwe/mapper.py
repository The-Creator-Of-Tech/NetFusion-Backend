"""
CIIL Mapper for CWE entities.
Maps CweEntity instances to CanonicalEntity records for the Canonical Intelligence Identity Layer.
"""

from typing import Any, Dict, Optional
from netfusion_intelligence.feeds.cwe.models import CweEntity
from netfusion_intelligence.identity.models import CanonicalEntity, CanonicalEntityType, EntityProvenance, ExternalIdentifier


class CweMapper:
    """
    Maps normalized CweEntity objects to NetFusion CanonicalEntity (CIIL) records.
    Ensures every CWE weakness has a canonical UUID, external identifier, and provenance.
    Never duplicates entities — relies on canonical ID resolution.
    """

    FEED_ID = "mitre_cwe_xml"
    SOURCE = "MITRE CWE"

    def map_to_canonical(
        self,
        entity: CweEntity,
        dataset_version: str,
        existing_canonical_id: Optional[str] = None,
    ) -> CanonicalEntity:
        """
        Maps a CweEntity to a CanonicalEntity.
        If an existing canonical UUID is supplied (entity already known to CIIL), it is reused.
        """
        provenance = EntityProvenance.create(
            feed_id=self.FEED_ID,
            source=self.SOURCE,
            source_id=entity.cwe_id,
            dataset_version=dataset_version,
        )
        external_id = ExternalIdentifier(
            identifier_type="CWE_ID",
            identifier_value=entity.cwe_id,
            source=self.SOURCE,
        )

        properties = self._build_properties(entity)

        return CanonicalEntity(
            canonical_uuid=existing_canonical_id or "",  # CIIL registry assigns UUID on first creation
            entity_type=CanonicalEntityType.CWE.value,
            primary_identifier=entity.cwe_id,
            display_name=entity.name,
            description=entity.description or "",
            external_identifiers=(external_id,),
            provenance=(provenance,),
            properties=properties,
            tags=self._build_tags(entity),
        )

    @staticmethod
    def _build_properties(entity: CweEntity) -> Dict[str, Any]:
        return {
            "cwe_id": entity.cwe_id,
            "name": entity.name,
            "abstraction": entity.abstraction,
            "structure": entity.structure,
            "status": entity.status,
            "description": entity.description,
            "extended_description": entity.extended_description,
            "likelihood_of_exploit": entity.likelihood_of_exploit,
            "background_details": entity.background_details,
            "alternate_terms": list(entity.alternate_terms),
            "modes_of_introduction": [m.to_dict() for m in entity.modes_of_introduction],
            "applicable_platforms": [p.to_dict() for p in entity.applicable_platforms],
            "consequences": [c.to_dict() for c in entity.consequences],
            "detection_methods": [d.to_dict() for d in entity.detection_methods],
            "mitigations": [m.to_dict() for m in entity.mitigations],
            "related_weaknesses": [r.to_dict() for r in entity.related_weaknesses],
            "taxonomy_mappings": [t.to_dict() for t in entity.taxonomy_mappings],
            "references": [r.to_dict() for r in entity.references],
            "related_attack_patterns": list(entity.related_attack_patterns),
            "affected_resources": list(entity.affected_resources),
            "functional_areas": list(entity.functional_areas),
            "mapping_notes": entity.mapping_notes,
            "notes": entity.notes,
            "source_version": entity.source_version,
            "url": entity.url,
        }

    @staticmethod
    def _build_tags(entity: CweEntity) -> tuple:
        tags = ["cwe", "weakness"]
        if entity.abstraction:
            tags.append(f"abstraction:{entity.abstraction.lower()}")
        if entity.status:
            tags.append(f"status:{entity.status.lower()}")
        if entity.likelihood_of_exploit:
            tags.append(f"exploit_likelihood:{entity.likelihood_of_exploit.lower()}")
        return tuple(tags)
