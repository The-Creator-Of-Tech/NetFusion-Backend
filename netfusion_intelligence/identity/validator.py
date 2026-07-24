"""
Identity Validator for NetFusion CIIL.
Validates canonical entities, external identifiers, relationships, provenance integrity, and mappings.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import uuid

from netfusion_intelligence.identity.models import CanonicalEntity, EntityProvenance, ExternalIdentifier
from netfusion_intelligence.identity.relationship import CanonicalRelationship


@dataclass
class ValidationReport:
    """Report detailing validation findings."""
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }


class IdentityValidator:
    """
    Validates canonical entities, identifiers, relationships, and provenance for structural and domain integrity.
    """

    def validate_entity(self, entity: CanonicalEntity) -> ValidationReport:
        report = ValidationReport()

        # Check UUID format
        try:
            uuid.UUID(entity.canonical_uuid)
        except Exception:
            report.add_error(f"Invalid UUID format: {entity.canonical_uuid}")

        if not entity.entity_type:
            report.add_error("Entity type cannot be empty")
        if not entity.display_name:
            report.add_error("Display name cannot be empty")

        if not (0.0 <= entity.confidence <= 1.0):
            report.add_error(f"Confidence value {entity.confidence} must be between 0.0 and 1.0")

        # Validate external identifiers
        seen_ext: Set[tuple] = set()
        for ext in entity.external_identifiers:
            ext_report = self.validate_external_identifier(ext)
            if not ext_report.is_valid:
                for err in ext_report.errors:
                    report.add_error(f"ExternalIdentifier error: {err}")

            key = (ext.source.lower(), ext.identifier.lower(), ext.identifier_type.lower())
            if key in seen_ext:
                report.add_warning(f"Duplicate external identifier in entity: {ext.source}:{ext.identifier}")
            seen_ext.add(key)

        return report

    def validate_external_identifier(self, ext: ExternalIdentifier) -> ValidationReport:
        report = ValidationReport()
        if not ext.source or not ext.source.strip():
            report.add_error("External identifier source cannot be empty")
        if not ext.identifier or not ext.identifier.strip():
            report.add_error("External identifier value cannot be empty")
        if not ext.identifier_type or not ext.identifier_type.strip():
            report.add_error("External identifier type cannot be empty")
        if not (0.0 <= ext.confidence <= 1.0):
            report.add_error(f"External identifier confidence {ext.confidence} must be between 0.0 and 1.0")
        return report

    def validate_relationship(
        self,
        relationship: CanonicalRelationship,
        known_uuids: Optional[Set[str]] = None,
    ) -> ValidationReport:
        report = ValidationReport()

        try:
            uuid.UUID(relationship.relationship_id)
        except Exception:
            report.add_error(f"Invalid relationship ID format: {relationship.relationship_id}")

        if not relationship.source_canonical_uuid:
            report.add_error("Source canonical UUID cannot be empty")
        if not relationship.target_canonical_uuid:
            report.add_error("Target canonical UUID cannot be empty")

        if relationship.source_canonical_uuid == relationship.target_canonical_uuid:
            report.add_warning(f"Self-referential relationship detected for UUID: {relationship.source_canonical_uuid}")

        if known_uuids:
            if relationship.source_canonical_uuid not in known_uuids:
                report.add_error(f"Broken relationship: source UUID {relationship.source_canonical_uuid} does not exist")
            if relationship.target_canonical_uuid not in known_uuids:
                report.add_error(f"Broken relationship: target UUID {relationship.target_canonical_uuid} does not exist")

        if not relationship.relationship_type:
            report.add_error("Relationship type cannot be empty")
        if not relationship.originating_source:
            report.add_error("Originating source cannot be empty")

        return report

    def validate_provenance(self, provenance: EntityProvenance, known_uuids: Optional[Set[str]] = None) -> ValidationReport:
        report = ValidationReport()

        if not provenance.provenance_id:
            report.add_error("Provenance ID cannot be empty")
        if not provenance.canonical_uuid:
            report.add_error("Provenance canonical UUID cannot be empty")
        if known_uuids and provenance.canonical_uuid not in known_uuids:
            report.add_error(f"Broken provenance: canonical UUID {provenance.canonical_uuid} does not exist")
        if not provenance.feed:
            report.add_error("Provenance feed cannot be empty")
        if not provenance.dataset_version:
            report.add_error("Provenance dataset version cannot be empty")
        if not provenance.original_object_id:
            report.add_error("Provenance original_object_id cannot be empty")

        return report

    def validate_dataset(
        self,
        entities: List[CanonicalEntity],
        relationships: Optional[List[CanonicalRelationship]] = None,
    ) -> ValidationReport:
        """
        Validates an entire collection of entities and relationships for duplicate UUIDs and broken links.
        """
        report = ValidationReport()
        seen_uuids: Set[str] = set()

        for ent in entities:
            if ent.canonical_uuid in seen_uuids:
                report.add_error(f"Duplicate canonical UUID detected in dataset: {ent.canonical_uuid}")
            seen_uuids.add(ent.canonical_uuid)

            ent_rep = self.validate_entity(ent)
            if not ent_rep.is_valid:
                for err in ent_rep.errors:
                    report.add_error(f"Entity [{ent.canonical_uuid}] error: {err}")

        if relationships:
            for rel in relationships:
                rel_rep = self.validate_relationship(rel, known_uuids=seen_uuids)
                if not rel_rep.is_valid:
                    for err in rel_rep.errors:
                        report.add_error(f"Relationship [{rel.relationship_id}] error: {err}")

        return report
