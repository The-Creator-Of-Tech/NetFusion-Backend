"""
Statistics Engine for MITRE CAPEC intelligence dataset.
Computes comprehensive coverage, distribution, and quality metrics.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.capec.models import CapecEntity, CapecRelationship, CapecCweMapping


class CapecStatistics:
    """
    Computes statistical metrics for normalized CAPEC datasets.
    """

    @staticmethod
    def calculate_statistics(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes structured statistics from a normalized CAPEC dataset dictionary.
        """
        if not isinstance(normalized_data, dict):
            return {}

        entities: Dict[str, CapecEntity] = normalized_data.get("entities", {})
        relationships: List[CapecRelationship] = normalized_data.get("relationships", [])
        cwe_mappings: List[CapecCweMapping] = normalized_data.get("cwe_mappings", [])

        by_abstraction: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_likelihood: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_relationship_nature: Dict[str, int] = {}

        has_execution_flow = 0
        has_mitigation = 0
        has_detection = 0
        has_cwe_ref = 0
        has_attack_ref = 0
        has_prerequisites = 0
        total_execution_steps = 0
        total_mitigations = 0

        for ent in entities.values():
            abstraction = ent.abstraction or "Unknown"
            by_abstraction[abstraction] = by_abstraction.get(abstraction, 0) + 1

            status = ent.status or "Unknown"
            by_status[status] = by_status.get(status, 0) + 1

            likelihood = ent.likelihood_of_attack or "Unknown"
            by_likelihood[likelihood] = by_likelihood.get(likelihood, 0) + 1

            severity = ent.typical_severity or "Unknown"
            by_severity[severity] = by_severity.get(severity, 0) + 1

            if ent.execution_flow:
                has_execution_flow += 1
                total_execution_steps += len(ent.execution_flow)

            if ent.mitigations:
                has_mitigation += 1
                total_mitigations += len(ent.mitigations)

            if ent.detection:
                has_detection += 1

            if ent.related_weaknesses:
                has_cwe_ref += 1

            if ent.prerequisites:
                has_prerequisites += 1

            # Check for ATT&CK taxonomy mappings
            for tm in ent.taxonomy_mappings:
                if isinstance(tm, dict):
                    tax_name = (tm.get("taxonomy_name") or "").lower()
                    if "mitre" in tax_name and "att" in tax_name:
                        has_attack_ref += 1
                        break

        for rel in relationships:
            nature = rel.nature or "Unknown"
            by_relationship_nature[nature] = by_relationship_nature.get(nature, 0) + 1

        # Most common by CWE reference count
        sorted_entities = sorted(
            entities.values(),
            key=lambda e: len(e.related_weaknesses),
            reverse=True,
        )
        most_common_by_cwe = [
            {"capec_id": e.capec_id, "name": e.name, "cwe_count": len(e.related_weaknesses)}
            for e in sorted_entities[:10]
        ]

        total = len(entities)
        return {
            "total_attack_patterns": total,
            "total_relationships": len(relationships),
            "total_cwe_mappings": len(cwe_mappings),
            "by_abstraction": by_abstraction,
            "by_status": by_status,
            "by_likelihood_of_attack": by_likelihood,
            "by_typical_severity": by_severity,
            "by_relationship_nature": by_relationship_nature,
            "patterns_with_execution_flow": has_execution_flow,
            "patterns_with_mitigations": has_mitigation,
            "patterns_with_detection": has_detection,
            "patterns_with_cwe_references": has_cwe_ref,
            "patterns_with_attack_references": has_attack_ref,
            "patterns_with_prerequisites": has_prerequisites,
            "total_execution_steps": total_execution_steps,
            "total_mitigations": total_mitigations,
            "execution_flow_coverage_pct": round(has_execution_flow / total * 100, 2) if total else 0.0,
            "mitigation_coverage_pct": round(has_mitigation / total * 100, 2) if total else 0.0,
            "cwe_coverage_pct": round(has_cwe_ref / total * 100, 2) if total else 0.0,
            "attack_coverage_pct": round(has_attack_ref / total * 100, 2) if total else 0.0,
            "most_referenced_attack_patterns": most_common_by_cwe,
        }
