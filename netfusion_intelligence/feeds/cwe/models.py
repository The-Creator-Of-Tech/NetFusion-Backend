"""
Domain models for MITRE CWE (Common Weakness Enumeration) entities.
Immutable dataclasses capturing every available CWE XML field.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CweConsequence:
    scope: Tuple[str, ...] = field(default_factory=tuple)
    impact: Tuple[str, ...] = field(default_factory=tuple)
    note: Optional[str] = None
    likelihood: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": list(self.scope),
            "impact": list(self.impact),
            "note": self.note,
            "likelihood": self.likelihood,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweConsequence":
        return cls(
            scope=tuple(d.get("scope", [])),
            impact=tuple(d.get("impact", [])),
            note=d.get("note"),
            likelihood=d.get("likelihood"),
        )


@dataclass(frozen=True)
class CweMitigation:
    phase: Tuple[str, ...] = field(default_factory=tuple)
    description: Optional[str] = None
    strategy: Optional[str] = None
    effectiveness: Optional[str] = None
    effectiveness_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": list(self.phase),
            "description": self.description,
            "strategy": self.strategy,
            "effectiveness": self.effectiveness,
            "effectiveness_notes": self.effectiveness_notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweMitigation":
        return cls(
            phase=tuple(d.get("phase", [])),
            description=d.get("description"),
            strategy=d.get("strategy"),
            effectiveness=d.get("effectiveness"),
            effectiveness_notes=d.get("effectiveness_notes"),
        )


@dataclass(frozen=True)
class CweDetectionMethod:
    method: Optional[str] = None
    description: Optional[str] = None
    effectiveness: Optional[str] = None
    effectiveness_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "description": self.description,
            "effectiveness": self.effectiveness,
            "effectiveness_notes": self.effectiveness_notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweDetectionMethod":
        return cls(
            method=d.get("method"),
            description=d.get("description"),
            effectiveness=d.get("effectiveness"),
            effectiveness_notes=d.get("effectiveness_notes"),
        )


@dataclass(frozen=True)
class CweRelatedWeakness:
    cwe_id: str
    nature: Optional[str] = None
    view_id: Optional[str] = None
    ordinal: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "nature": self.nature,
            "view_id": self.view_id,
            "ordinal": self.ordinal,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweRelatedWeakness":
        return cls(
            cwe_id=d.get("cwe_id", ""),
            nature=d.get("nature"),
            view_id=d.get("view_id"),
            ordinal=d.get("ordinal"),
        )


@dataclass(frozen=True)
class CweTaxonomyMapping:
    taxonomy_name: Optional[str] = None
    entry_id: Optional[str] = None
    entry_name: Optional[str] = None
    mapping_fit: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "taxonomy_name": self.taxonomy_name,
            "entry_id": self.entry_id,
            "entry_name": self.entry_name,
            "mapping_fit": self.mapping_fit,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweTaxonomyMapping":
        return cls(
            taxonomy_name=d.get("taxonomy_name"),
            entry_id=d.get("entry_id"),
            entry_name=d.get("entry_name"),
            mapping_fit=d.get("mapping_fit"),
        )


@dataclass(frozen=True)
class CweReference:
    reference_id: Optional[str] = None
    author: Tuple[str, ...] = field(default_factory=tuple)
    title: Optional[str] = None
    edition: Optional[str] = None
    url: Optional[str] = None
    publication_year: Optional[str] = None
    publisher: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "author": list(self.author),
            "title": self.title,
            "edition": self.edition,
            "url": self.url,
            "publication_year": self.publication_year,
            "publisher": self.publisher,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweReference":
        return cls(
            reference_id=d.get("reference_id"),
            author=tuple(d.get("author", [])),
            title=d.get("title"),
            edition=d.get("edition"),
            url=d.get("url"),
            publication_year=d.get("publication_year"),
            publisher=d.get("publisher"),
        )


@dataclass(frozen=True)
class CweApplicablePlatform:
    platform_type: Optional[str] = None
    name: Optional[str] = None
    prevalence: Optional[str] = None
    class_: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform_type": self.platform_type,
            "name": self.name,
            "prevalence": self.prevalence,
            "class": self.class_,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweApplicablePlatform":
        return cls(
            platform_type=d.get("platform_type"),
            name=d.get("name"),
            prevalence=d.get("prevalence"),
            class_=d.get("class"),
        )


@dataclass(frozen=True)
class CweModeOfIntroduction:
    phase: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"phase": self.phase, "note": self.note}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweModeOfIntroduction":
        return cls(phase=d.get("phase"), note=d.get("note"))


@dataclass(frozen=True)
class CweEntity:
    """
    Complete CWE weakness entity capturing every available field from the MITRE CWE XML.
    """
    cwe_id: str
    name: str
    abstraction: Optional[str] = None
    structure: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    extended_description: Optional[str] = None
    likelihood_of_exploit: Optional[str] = None
    background_details: Optional[str] = None
    alternate_terms: Tuple[str, ...] = field(default_factory=tuple)
    modes_of_introduction: Tuple[CweModeOfIntroduction, ...] = field(default_factory=tuple)
    applicable_platforms: Tuple[CweApplicablePlatform, ...] = field(default_factory=tuple)
    consequences: Tuple[CweConsequence, ...] = field(default_factory=tuple)
    detection_methods: Tuple[CweDetectionMethod, ...] = field(default_factory=tuple)
    mitigations: Tuple[CweMitigation, ...] = field(default_factory=tuple)
    related_weaknesses: Tuple[CweRelatedWeakness, ...] = field(default_factory=tuple)
    taxonomy_mappings: Tuple[CweTaxonomyMapping, ...] = field(default_factory=tuple)
    references: Tuple[CweReference, ...] = field(default_factory=tuple)
    related_attack_patterns: Tuple[str, ...] = field(default_factory=tuple)  # CAPEC IDs
    affected_resources: Tuple[str, ...] = field(default_factory=tuple)
    functional_areas: Tuple[str, ...] = field(default_factory=tuple)
    mapping_notes: Optional[str] = None
    notes: Optional[str] = None
    source_version: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "abstraction": self.abstraction,
            "structure": self.structure,
            "status": self.status,
            "description": self.description,
            "extended_description": self.extended_description,
            "likelihood_of_exploit": self.likelihood_of_exploit,
            "background_details": self.background_details,
            "alternate_terms": list(self.alternate_terms),
            "modes_of_introduction": [m.to_dict() for m in self.modes_of_introduction],
            "applicable_platforms": [p.to_dict() for p in self.applicable_platforms],
            "consequences": [c.to_dict() for c in self.consequences],
            "detection_methods": [d.to_dict() for d in self.detection_methods],
            "mitigations": [m.to_dict() for m in self.mitigations],
            "related_weaknesses": [r.to_dict() for r in self.related_weaknesses],
            "taxonomy_mappings": [t.to_dict() for t in self.taxonomy_mappings],
            "references": [r.to_dict() for r in self.references],
            "related_attack_patterns": list(self.related_attack_patterns),
            "affected_resources": list(self.affected_resources),
            "functional_areas": list(self.functional_areas),
            "mapping_notes": self.mapping_notes,
            "notes": self.notes,
            "source_version": self.source_version,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CweEntity":
        return cls(
            cwe_id=d.get("cwe_id", ""),
            name=d.get("name", ""),
            abstraction=d.get("abstraction"),
            structure=d.get("structure"),
            status=d.get("status"),
            description=d.get("description"),
            extended_description=d.get("extended_description"),
            likelihood_of_exploit=d.get("likelihood_of_exploit"),
            background_details=d.get("background_details"),
            alternate_terms=tuple(d.get("alternate_terms", [])),
            modes_of_introduction=tuple(CweModeOfIntroduction.from_dict(m) for m in d.get("modes_of_introduction", [])),
            applicable_platforms=tuple(CweApplicablePlatform.from_dict(p) for p in d.get("applicable_platforms", [])),
            consequences=tuple(CweConsequence.from_dict(c) for c in d.get("consequences", [])),
            detection_methods=tuple(CweDetectionMethod.from_dict(dm) for dm in d.get("detection_methods", [])),
            mitigations=tuple(CweMitigation.from_dict(m) for m in d.get("mitigations", [])),
            related_weaknesses=tuple(CweRelatedWeakness.from_dict(r) for r in d.get("related_weaknesses", [])),
            taxonomy_mappings=tuple(CweTaxonomyMapping.from_dict(t) for t in d.get("taxonomy_mappings", [])),
            references=tuple(CweReference.from_dict(r) for r in d.get("references", [])),
            related_attack_patterns=tuple(d.get("related_attack_patterns", [])),
            affected_resources=tuple(d.get("affected_resources", [])),
            functional_areas=tuple(d.get("functional_areas", [])),
            mapping_notes=d.get("mapping_notes"),
            notes=d.get("notes"),
            source_version=d.get("source_version"),
            url=d.get("url"),
        )


@dataclass(frozen=True)
class CweRelationship:
    """Normalized CWE-to-CWE relationship for graph construction."""
    source_cwe_id: str
    target_cwe_id: str
    nature: str
    view_id: Optional[str] = None
    ordinal: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_cwe_id": self.source_cwe_id,
            "target_cwe_id": self.target_cwe_id,
            "nature": self.nature,
            "view_id": self.view_id,
            "ordinal": self.ordinal,
        }
