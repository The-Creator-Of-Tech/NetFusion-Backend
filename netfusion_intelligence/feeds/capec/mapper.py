"""
CIIL Mapper for CAPEC entities.
Maps CapecEntity instances to CanonicalEntity records for the Canonical Intelligence Identity Layer.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.feeds.capec.models import CapecEntity
from netfusion_intelligence.identity.models import CanonicalEntity, CanonicalEntityType, EntityProvenance, ExternalIdentifier


class CapecMapper:
    """
    Maps normalized CapecEntity objects to NetFusion CanonicalEntity (CIIL) records.
    Ensures every CAPEC pattern has a canonical UUID, external identifier, and provenance.
    """

    FEED_ID = "mitre_capec_xml"
    SOURCE = "MITRE CAPEC"

    def map_to_canonical(
        self,
        entity: CapecEntity,
        dataset_version: str,
        existing_canonical_id: Optional[str] = None,
    ) -> CanonicalEntity:
        """
        Maps a CapecEntity to a CanonicalEntity.
        """
        provenance = EntityProvenance.create(
            feed_id=self.FEED_ID,
            source=self.SOURCE,
            source_id=entity.capec_id,
            dataset_version=dataset_version,
        )
        external_id = ExternalIdentifier(
            identifier_type="CAPEC_ID",
            identifier_value=entity.capec_id,
            source=self.SOURCE,
        )

        properties = self._build_properties(entity)

        return CanonicalEntity(
            canonical_uuid=existing_canonical_id or "",
            entity_type=CanonicalEntityType.CAPEC.value,
            primary_identifier=entity.capec_id,
            display_name=entity.name,
            description=entity.description or "",
            external_identifiers=(external_id,),
            provenance=(provenance,),
            properties=properties,
            tags=self._build_tags(entity),
        )

    @staticmethod
    def _build_properties(entity: CapecEntity) -> Dict[str, Any]:
        # Extract ATT&CK technique IDs from taxonomy_mappings
        attack_technique_ids: List[str] = []
        for tm in entity.taxonomy_mappings:
            if isinstance(tm, dict):
                tax_name = (tm.get("taxonomy_name") or "").lower()
                if "mitre" in tax_name and "att" in tax_name:
                    entry_id = tm.get("entry_id")
                    if entry_id:
                        attack_technique_ids.append(entry_id)

        return {
            "capec_id": entity.capec_id,
            "name": entity.name,
            "abstraction": entity.abstraction,
            "status": entity.status,
            "description": entity.description,
            "extended_description": entity.extended_description,
            "likelihood_of_attack": entity.likelihood_of_attack,
            "typical_severity": entity.typical_severity,
            "execution_flow": [s.to_dict() for s in entity.execution_flow],
            "prerequisites": list(entity.prerequisites),
            "skills_required": [s.to_dict() for s in entity.skills_required],
            "resources_required": list(entity.resources_required),
            "indicators": list(entity.indicators),
            "consequences": [c.to_dict() for c in entity.consequences],
            "mitigations": [m.to_dict() for m in entity.mitigations],
            "detection": [d.to_dict() for d in entity.detection],
            "example_instances": list(entity.example_instances),
            "related_attack_patterns": [r.to_dict() for r in entity.related_attack_patterns],
            "related_weaknesses": list(entity.related_weaknesses),
            "taxonomy_mappings": list(entity.taxonomy_mappings),
            "attack_technique_ids": attack_technique_ids,
            "references": [r.to_dict() for r in entity.references],
            "notes": entity.notes,
            "source_version": entity.source_version,
            "url": entity.url,
        }

    @staticmethod
    def _build_tags(entity: CapecEntity) -> tuple:
        tags = ["capec", "attack_pattern"]
        if entity.abstraction:
            tags.append(f"abstraction:{entity.abstraction.lower()}")
        if entity.status:
            tags.append(f"status:{entity.status.lower()}")
        if entity.likelihood_of_attack:
            tags.append(f"likelihood:{entity.likelihood_of_attack.lower()}")
        if entity.typical_severity:
            tags.append(f"severity:{entity.typical_severity.lower()}")
        return tuple(tags)
