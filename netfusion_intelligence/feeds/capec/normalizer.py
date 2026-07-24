"""
Normalizer for MITRE CAPEC XML parsed data.
Converts raw parser dicts into immutable CapecEntity domain models.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.capec.models import (
    CapecCweMapping,
    CapecDetection,
    CapecEntity,
    CapecConsequence,
    CapecExecutionFlowStep,
    CapecMitigation,
    CapecReference,
    CapecRelatedAttackPattern,
    CapecRelationship,
    CapecSkillRequired,
)


class CapecNormalizer:
    """
    Normalizes parsed CAPEC catalog data into immutable CapecEntity domain models.
    Builds CAPEC-to-CAPEC and CAPEC-to-CWE relationship graphs.
    """

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms parsed CAPEC catalog dict into normalized domain model collections.

        Returns:
            {
              "entities": {capec_id: CapecEntity},
              "relationships": [CapecRelationship, ...],
              "cwe_mappings": [CapecCweMapping, ...],
              "catalog_version": str,
              "record_count": int,
            }
        """
        if not isinstance(parsed_data, dict):
            raise ValueError("Parsed CAPEC data must be a dictionary")

        catalog_version = parsed_data.get("catalog_version", "unknown")
        patterns_raw: List[Dict[str, Any]] = parsed_data.get("attack_patterns", [])
        ext_refs_index = self._build_ref_index(parsed_data.get("external_references", []))

        entities: Dict[str, CapecEntity] = {}
        relationships: List[CapecRelationship] = []
        cwe_mappings: List[CapecCweMapping] = []

        for raw in patterns_raw:
            entity = self._map_attack_pattern(raw, ext_refs_index)
            entities[entity.capec_id] = entity

        # Build CAPEC-to-CAPEC and CAPEC-to-CWE relationships
        for entity in entities.values():
            for rap in entity.related_attack_patterns:
                relationships.append(
                    CapecRelationship(
                        source_capec_id=entity.capec_id,
                        target_capec_id=rap.capec_id,
                        nature=rap.nature or "Related",
                        view_id=rap.view_id,
                    )
                )
            for cwe_id in entity.related_weaknesses:
                cwe_mappings.append(
                    CapecCweMapping(
                        capec_id=entity.capec_id,
                        cwe_id=cwe_id,
                        nature="Exploits",
                    )
                )

        return {
            "entities": entities,
            "relationships": relationships,
            "cwe_mappings": cwe_mappings,
            "catalog_version": catalog_version,
            "record_count": len(entities),
            "relationship_count": len(relationships),
            "cwe_mapping_count": len(cwe_mappings),
        }

    @staticmethod
    def _build_ref_index(ext_refs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        return {r.get("reference_id", ""): r for r in ext_refs if r.get("reference_id")}

    @staticmethod
    def _map_attack_pattern(raw: Dict[str, Any], ref_index: Dict[str, Dict[str, Any]]) -> CapecEntity:
        # Execution flow
        execution_flow = tuple(
            CapecExecutionFlowStep(
                step_number=s.get("step_number"),
                phase=s.get("phase"),
                description=s.get("description"),
                techniques=tuple(s.get("techniques", [])),
            )
            for s in raw.get("execution_flow", [])
        )

        # Skills required
        skills_required = tuple(
            CapecSkillRequired(level=s.get("level"), description=s.get("description"))
            for s in raw.get("skills_required", [])
        )

        # Consequences
        consequences = tuple(
            CapecConsequence(
                scope=tuple(c.get("scope", [])),
                impact=tuple(c.get("impact", [])),
                note=c.get("note"),
                likelihood=c.get("likelihood"),
            )
            for c in raw.get("consequences", [])
        )

        # Mitigations
        mitigations = tuple(
            CapecMitigation(
                description=m.get("description"),
                phase=tuple(m.get("phase", [])),
                strategy=m.get("strategy"),
                effectiveness=m.get("effectiveness"),
            )
            for m in raw.get("mitigations", [])
        )

        # Detection
        detection = tuple(
            CapecDetection(
                method=d.get("method"),
                description=d.get("description"),
                effectiveness=d.get("effectiveness"),
                effectiveness_notes=d.get("effectiveness_notes"),
            )
            for d in raw.get("detection", [])
        )

        # Related attack patterns
        related_attack_patterns = tuple(
            CapecRelatedAttackPattern(
                capec_id=r.get("capec_id", ""),
                nature=r.get("nature"),
                view_id=r.get("view_id"),
            )
            for r in raw.get("related_attack_patterns", [])
        )

        # References — enrich with full external ref data
        references_raw = raw.get("references", [])
        enriched_refs = []
        for ref in references_raw:
            ref_id = ref.get("reference_id")
            full_ref = ref_index.get(ref_id, {}) if ref_id else {}
            enriched_refs.append(
                CapecReference(
                    reference_id=ref_id,
                    author=tuple(full_ref.get("author", [])),
                    title=full_ref.get("title"),
                    edition=full_ref.get("edition"),
                    url=full_ref.get("url"),
                    publication_year=full_ref.get("publication_year"),
                    publisher=full_ref.get("publisher"),
                )
            )

        return CapecEntity(
            capec_id=raw.get("capec_id", ""),
            name=raw.get("name", ""),
            abstraction=raw.get("abstraction"),
            status=raw.get("status"),
            description=raw.get("description"),
            extended_description=raw.get("extended_description"),
            likelihood_of_attack=raw.get("likelihood_of_attack") or None,
            typical_severity=raw.get("typical_severity") or None,
            execution_flow=execution_flow,
            prerequisites=tuple(raw.get("prerequisites", [])),
            skills_required=skills_required,
            resources_required=tuple(raw.get("resources_required", [])),
            indicators=tuple(raw.get("indicators", [])),
            consequences=consequences,
            mitigations=mitigations,
            example_instances=tuple(raw.get("example_instances", [])),
            related_attack_patterns=related_attack_patterns,
            related_weaknesses=tuple(raw.get("related_weaknesses", [])),
            taxonomy_mappings=tuple(raw.get("taxonomy_mappings", [])),
            references=tuple(enriched_refs),
            detection=detection,
            notes=raw.get("notes"),
            source_version=raw.get("source_version"),
            url=raw.get("url"),
        )
