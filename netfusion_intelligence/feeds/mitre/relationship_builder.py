"""
Relationship Builder for MITRE ATT&CK STIX 2.1 intelligence feed.
Constructs graph relationships ONLY from STIX relationship objects.
Never infers relationships or relies on string matching.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.mitre.models import MitreEntity, MitreRelationship


class MitreRelationshipBuilder:
    """
    Extracts and builds graph relationships strictly from official STIX relationship objects.
    Enforces preserve rule: source_ref, target_ref, relationship_type, description, confidence, created, modified.
    """

    def build_relationships(self, normalized_data: Dict[str, Any]) -> List[MitreRelationship]:
        """
        Extracts verified STIX relationships from normalized dataset.
        Returns list of MitreRelationship objects.
        """
        if not isinstance(normalized_data, dict):
            return []

        relationships: List[MitreRelationship] = normalized_data.get("relationships", [])
        entities: Dict[str, MitreEntity] = normalized_data.get("entities", {})

        verified_relationships: List[MitreRelationship] = []

        for rel in relationships:
            if not isinstance(rel, MitreRelationship):
                continue
            
            # Resolve source and target entities if available
            src_entity = entities.get(rel.source_ref)
            tgt_entity = entities.get(rel.target_ref)

            verified_rel = MitreRelationship(
                stix_id=rel.stix_id,
                source_ref=rel.source_ref,
                target_ref=rel.target_ref,
                relationship_type=rel.relationship_type,
                source_attack_id=src_entity.attack_id if src_entity else rel.source_attack_id,
                source_type=src_entity.type if src_entity else rel.source_type,
                target_attack_id=tgt_entity.attack_id if tgt_entity else rel.target_attack_id,
                target_type=tgt_entity.type if tgt_entity else rel.target_type,
                description=rel.description,
                confidence=rel.confidence,
                created=rel.created,
                modified=rel.modified,
                external_references=rel.external_references,
                revoked=rel.revoked,
            )
            verified_relationships.append(verified_rel)

        return verified_relationships
