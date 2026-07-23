"""
Normalizer for MITRE CWE XML parsed data.
Converts raw parser dicts into immutable CweEntity domain models.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.cwe.models import (
    CweApplicablePlatform,
    CweConsequence,
    CweDetectionMethod,
    CweEntity,
    CweMitigation,
    CweModeOfIntroduction,
    CweReference,
    CweRelatedWeakness,
    CweRelationship,
    CweTaxonomyMapping,
)


class CweNormalizer:
    """
    Normalizes parsed CWE catalog data into immutable CweEntity domain models.
    Builds the CweRelationship graph from related_weaknesses in each entity.
    """

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms parsed CWE catalog dict into normalized domain model collections.

        Returns:
            {
              "entities": {cwe_id: CweEntity},
              "relationships": [CweRelationship, ...],
              "catalog_version": str,
              "record_count": int,
            }
        """
        if not isinstance(parsed_data, dict):
            raise ValueError("Parsed CWE data must be a dictionary")

        catalog_version = parsed_data.get("catalog_version", "unknown")
        weaknesses_raw: List[Dict[str, Any]] = parsed_data.get("weaknesses", [])
        ext_refs_index = self._build_ref_index(parsed_data.get("external_references", []))

        entities: Dict[str, CweEntity] = {}
        relationships: List[CweRelationship] = []

        for raw in weaknesses_raw:
            entity = self._map_weakness(raw, ext_refs_index)
            entities[entity.cwe_id] = entity

        # Build CWE-to-CWE relationships
        for entity in entities.values():
            for rw in entity.related_weaknesses:
                relationships.append(
                    CweRelationship(
                        source_cwe_id=entity.cwe_id,
                        target_cwe_id=rw.cwe_id,
                        nature=rw.nature or "Related",
                        view_id=rw.view_id,
                        ordinal=rw.ordinal,
                    )
                )

        return {
            "entities": entities,
            "relationships": relationships,
            "catalog_version": catalog_version,
            "record_count": len(entities),
            "relationship_count": len(relationships),
        }

    @staticmethod
    def _build_ref_index(ext_refs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Indexes external references by reference_id for O(1) lookup."""
        return {r.get("reference_id", ""): r for r in ext_refs if r.get("reference_id")}

    @staticmethod
    def _map_weakness(raw: Dict[str, Any], ref_index: Dict[str, Dict[str, Any]]) -> CweEntity:
        # Modes of introduction
        modes = tuple(
            CweModeOfIntroduction(phase=m.get("phase"), note=m.get("note"))
            for m in raw.get("modes_of_introduction", [])
        )

        # Applicable platforms
        platforms = tuple(
            CweApplicablePlatform(
                platform_type=p.get("platform_type"),
                name=p.get("name"),
                prevalence=p.get("prevalence"),
                class_=p.get("class"),
            )
            for p in raw.get("applicable_platforms", [])
        )

        # Consequences
        consequences = tuple(
            CweConsequence(
                scope=tuple(c.get("scope", [])),
                impact=tuple(c.get("impact", [])),
                note=c.get("note"),
                likelihood=c.get("likelihood"),
            )
            for c in raw.get("consequences", [])
        )

        # Detection methods
        detection_methods = tuple(
            CweDetectionMethod(
                method=dm.get("method"),
                description=dm.get("description"),
                effectiveness=dm.get("effectiveness"),
                effectiveness_notes=dm.get("effectiveness_notes"),
            )
            for dm in raw.get("detection_methods", [])
        )

        # Mitigations
        mitigations = tuple(
            CweMitigation(
                phase=tuple(m.get("phase", [])),
                description=m.get("description"),
                strategy=m.get("strategy"),
                effectiveness=m.get("effectiveness"),
                effectiveness_notes=m.get("effectiveness_notes"),
            )
            for m in raw.get("mitigations", [])
        )

        # Related weaknesses
        related_weaknesses = tuple(
            CweRelatedWeakness(
                cwe_id=rw.get("cwe_id", ""),
                nature=rw.get("nature"),
                view_id=rw.get("view_id"),
                ordinal=rw.get("ordinal"),
            )
            for rw in raw.get("related_weaknesses", [])
        )

        # Taxonomy mappings
        taxonomy_mappings = tuple(
            CweTaxonomyMapping(
                taxonomy_name=tm.get("taxonomy_name"),
                entry_id=tm.get("entry_id"),
                entry_name=tm.get("entry_name"),
                mapping_fit=tm.get("mapping_fit"),
            )
            for tm in raw.get("taxonomy_mappings", [])
        )

        # References — enrich with external ref data
        references_raw = raw.get("references", [])
        enriched_refs = []
        for ref in references_raw:
            ref_id = ref.get("reference_id")
            full_ref = ref_index.get(ref_id, {}) if ref_id else {}
            enriched_refs.append(
                CweReference(
                    reference_id=ref_id,
                    author=tuple(full_ref.get("author", [])),
                    title=full_ref.get("title"),
                    edition=full_ref.get("edition"),
                    url=full_ref.get("url"),
                    publication_year=full_ref.get("publication_year"),
                    publisher=full_ref.get("publisher"),
                )
            )

        return CweEntity(
            cwe_id=raw.get("cwe_id", ""),
            name=raw.get("name", ""),
            abstraction=raw.get("abstraction"),
            structure=raw.get("structure"),
            status=raw.get("status"),
            description=raw.get("description"),
            extended_description=raw.get("extended_description"),
            likelihood_of_exploit=raw.get("likelihood_of_exploit"),
            background_details=raw.get("background_details"),
            alternate_terms=tuple(raw.get("alternate_terms", [])),
            modes_of_introduction=modes,
            applicable_platforms=platforms,
            consequences=consequences,
            detection_methods=detection_methods,
            mitigations=mitigations,
            related_weaknesses=related_weaknesses,
            taxonomy_mappings=taxonomy_mappings,
            references=tuple(enriched_refs),
            related_attack_patterns=tuple(raw.get("related_attack_patterns", [])),
            affected_resources=tuple(raw.get("affected_resources", [])),
            functional_areas=tuple(raw.get("functional_areas", [])),
            mapping_notes=raw.get("mapping_notes"),
            notes=raw.get("notes"),
            source_version=raw.get("source_version"),
            url=raw.get("url"),
        )
