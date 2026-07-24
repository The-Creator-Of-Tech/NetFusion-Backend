"""
Normalizer for MITRE ATT&CK Enterprise STIX 2.1 parsed objects.
Converts parsed STIX objects into immutable NetFusion MitreEntity and MitreRelationship collections.
"""

from typing import Any, Dict, List, Union
from netfusion_intelligence.feeds.mitre.mapper import MitreMapper
from netfusion_intelligence.feeds.mitre.models import MitreEntity, MitreRelationship


class MitreNormalizer:
    """
    Normalizes parsed STIX 2.1 objects into immutable domain models.
    Preserves all official STIX properties and links relationships to object types & ATT&CK IDs.
    """

    def __init__(self, mapper: Optional[MitreMapper] = None):
        self.mapper = mapper or MitreMapper()

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms parsed STIX bundle data into normalized domain model collections.
        """
        if not isinstance(parsed_data, dict):
            raise ValueError("Parsed data must be a dictionary")

        objects = parsed_data.get("objects", [])
        
        entities_by_stix_id: Dict[str, MitreEntity] = {}
        entities_by_type: Dict[str, List[MitreEntity]] = {}
        raw_relationships: List[MitreRelationship] = []

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            stix_type = obj.get("type")
            if stix_type == "relationship":
                rel = self.mapper.map_stix_relationship(obj)
                raw_relationships.append(rel)
            else:
                entity = self.mapper.map_stix_object(obj)
                entities_by_stix_id[entity.stix_id] = entity
                if entity.type not in entities_by_type:
                    entities_by_type[entity.type] = []
                entities_by_type[entity.type].append(entity)

        # Enrich relationships with source/target ATT&CK IDs and types
        enriched_relationships: List[MitreRelationship] = []
        for rel in raw_relationships:
            src_entity = entities_by_stix_id.get(rel.source_ref)
            tgt_entity = entities_by_stix_id.get(rel.target_ref)

            src_attack_id = src_entity.attack_id if src_entity else None
            src_type = src_entity.type if src_entity else None
            tgt_attack_id = tgt_entity.attack_id if tgt_entity else None
            tgt_type = tgt_entity.type if tgt_entity else None

            enriched_rel = MitreRelationship(
                stix_id=rel.stix_id,
                source_ref=rel.source_ref,
                target_ref=rel.target_ref,
                relationship_type=rel.relationship_type,
                source_attack_id=src_attack_id,
                source_type=src_type,
                target_attack_id=tgt_attack_id,
                target_type=tgt_type,
                description=rel.description,
                confidence=rel.confidence,
                created=rel.created,
                modified=rel.modified,
                external_references=rel.external_references,
                revoked=rel.revoked,
            )
            enriched_relationships.append(enriched_rel)

        return {
            "items": list(entities_by_stix_id.values()),
            "entities": entities_by_stix_id,
            "entities_by_type": entities_by_type,
            "relationships": enriched_relationships,
            "tactics": entities_by_type.get("x-mitre-tactic", []),
            "techniques": entities_by_type.get("attack-pattern", []),
            "groups": entities_by_type.get("intrusion-set", []),
            "software": entities_by_type.get("malware", []) + entities_by_type.get("tool", []),
            "campaigns": entities_by_type.get("campaign", []),
            "mitigations": entities_by_type.get("course-of-action", []),
            "data_sources": entities_by_type.get("x-mitre-data-source", []),
            "data_components": entities_by_type.get("x-mitre-data-component", []),
            "assets": entities_by_type.get("x-mitre-asset", []),
            "record_count": len(entities_by_stix_id) + len(enriched_relationships),
        }

