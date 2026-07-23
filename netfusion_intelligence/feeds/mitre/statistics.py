"""
Statistics Engine for MITRE ATT&CK STIX 2.1 intelligence dataset.
Computes fine-grained object counts, tactic distributions, and relationship metrics.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.mitre.models import MitreEntity, MitreRelationship


class MitreStatistics:
    """
    Computes statistical metrics for normalized MITRE ATT&CK datasets.
    """

    @staticmethod
    def calculate_statistics(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes structured statistics from a normalized dataset dictionary.
        """
        if not isinstance(normalized_data, dict):
            return {}

        entities: Dict[str, MitreEntity] = normalized_data.get("entities", {})
        relationships: List[MitreRelationship] = normalized_data.get("relationships", [])

        by_type: Dict[str, int] = {}
        by_tactic: Dict[str, int] = {}
        by_platform: Dict[str, int] = {}
        by_relationship_type: Dict[str, int] = {}

        techniques_cnt = 0
        subtechniques_cnt = 0
        revoked_cnt = 0
        deprecated_cnt = 0

        for ent in entities.values():
            e_type = ent.type
            by_type[e_type] = by_type.get(e_type, 0) + 1

            if ent.revoked:
                revoked_cnt += 1
            if ent.deprecated:
                deprecated_cnt += 1

            if e_type == "attack-pattern":
                if ent.is_subtechnique:
                    subtechniques_cnt += 1
                else:
                    techniques_cnt += 1

            for tac in ent.tactics:
                by_tactic[tac] = by_tactic.get(tac, 0) + 1

            for plt in ent.platforms:
                by_platform[plt] = by_platform.get(plt, 0) + 1

        for rel in relationships:
            rel_type = rel.relationship_type
            by_relationship_type[rel_type] = by_relationship_type.get(rel_type, 0) + 1

        return {
            "total_entities": len(entities),
            "total_relationships": len(relationships),
            "techniques_count": techniques_cnt,
            "subtechniques_count": subtechniques_cnt,
            "tactics_count": by_type.get("x-mitre-tactic", 0),
            "groups_count": by_type.get("intrusion-set", 0),
            "malware_count": by_type.get("malware", 0),
            "tools_count": by_type.get("tool", 0),
            "campaigns_count": by_type.get("campaign", 0),
            "mitigations_count": by_type.get("course-of-action", 0),
            "data_sources_count": by_type.get("x-mitre-data-source", 0),
            "data_components_count": by_type.get("x-mitre-data-component", 0),
            "assets_count": by_type.get("x-mitre-asset", 0),
            "revoked_count": revoked_cnt,
            "deprecated_count": deprecated_cnt,
            "entity_counts_by_type": by_type,
            "tactic_distribution": by_tactic,
            "platform_distribution": by_platform,
            "relationship_distribution": by_relationship_type,
        }
