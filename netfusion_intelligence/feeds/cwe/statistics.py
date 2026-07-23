"""
Statistics Engine for MITRE CWE intelligence dataset.
Computes comprehensive coverage, distribution, and quality metrics.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.cwe.models import CweEntity, CweRelationship


class CweStatistics:
    """
    Computes statistical metrics for normalized CWE datasets.
    """

    @staticmethod
    def calculate_statistics(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes structured statistics from a normalized CWE dataset dictionary.
        """
        if not isinstance(normalized_data, dict):
            return {}

        entities: Dict[str, CweEntity] = normalized_data.get("entities", {})
        relationships: List[CweRelationship] = normalized_data.get("relationships", [])

        by_abstraction: Dict[str, int] = {}
        by_structure: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_likelihood: Dict[str, int] = {}
        by_relationship_nature: Dict[str, int] = {}

        has_mitigation = 0
        has_detection = 0
        has_capec_ref = 0
        has_platform = 0
        total_mitigations = 0
        total_detection_methods = 0
        total_consequences = 0

        most_common: List[Dict[str, Any]] = []

        for ent in entities.values():
            abstraction = ent.abstraction or "Unknown"
            by_abstraction[abstraction] = by_abstraction.get(abstraction, 0) + 1

            structure = ent.structure or "Unknown"
            by_structure[structure] = by_structure.get(structure, 0) + 1

            status = ent.status or "Unknown"
            by_status[status] = by_status.get(status, 0) + 1

            likelihood = ent.likelihood_of_exploit or "Unknown"
            by_likelihood[likelihood] = by_likelihood.get(likelihood, 0) + 1

            if ent.mitigations:
                has_mitigation += 1
                total_mitigations += len(ent.mitigations)

            if ent.detection_methods:
                has_detection += 1
                total_detection_methods += len(ent.detection_methods)

            if ent.related_attack_patterns:
                has_capec_ref += 1

            if ent.applicable_platforms:
                has_platform += 1

            total_consequences += len(ent.consequences)

        for rel in relationships:
            nature = rel.nature or "Unknown"
            by_relationship_nature[nature] = by_relationship_nature.get(nature, 0) + 1

        # Most common weaknesses by related_weaknesses count
        sorted_entities = sorted(
            entities.values(),
            key=lambda e: len(e.related_weaknesses),
            reverse=True,
        )
        most_common = [
            {"cwe_id": e.cwe_id, "name": e.name, "related_count": len(e.related_weaknesses)}
            for e in sorted_entities[:10]
        ]

        total = len(entities)
        return {
            "total_weaknesses": total,
            "total_relationships": len(relationships),
            "by_abstraction": by_abstraction,
            "by_structure": by_structure,
            "by_status": by_status,
            "by_likelihood_of_exploit": by_likelihood,
            "by_relationship_nature": by_relationship_nature,
            "weaknesses_with_mitigations": has_mitigation,
            "weaknesses_with_detection_methods": has_detection,
            "weaknesses_with_capec_references": has_capec_ref,
            "weaknesses_with_platform_data": has_platform,
            "total_mitigations": total_mitigations,
            "total_detection_methods": total_detection_methods,
            "total_consequences": total_consequences,
            "mitigation_coverage_pct": round(has_mitigation / total * 100, 2) if total else 0.0,
            "detection_coverage_pct": round(has_detection / total * 100, 2) if total else 0.0,
            "capec_coverage_pct": round(has_capec_ref / total * 100, 2) if total else 0.0,
            "most_connected_weaknesses": most_common,
        }
