"""
Domain models for MITRE CAPEC (Common Attack Pattern Enumeration and Classification) entities.
Immutable dataclasses capturing every available CAPEC XML field.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CapecExecutionFlowStep:
    step_number: Optional[int] = None
    phase: Optional[str] = None
    description: Optional[str] = None
    techniques: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "phase": self.phase,
            "description": self.description,
            "techniques": list(self.techniques),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapecExecutionFlowStep":
        return cls(
            step_number=d.get("step_number"),
            phase=d.get("phase"),
            description=d.get("description"),
            techniques=tuple(d.get("techniques", [])),
        )


@dataclass(frozen=True)
class CapecSkillRequired:
    level: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "description": self.description}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapecSkillRequired":
        return cls(level=d.get("level"), description=d.get("description"))


@dataclass(frozen=True)
class CapecConsequence:
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
    def from_dict(cls, d: Dict[str, Any]) -> "CapecConsequence":
        return cls(
            scope=tuple(d.get("scope", [])),
            impact=tuple(d.get("impact", [])),
            note=d.get("note"),
            likelihood=d.get("likelihood"),
        )


@dataclass(frozen=True)
class CapecMitigation:
    description: Optional[str] = None
    phase: Tuple[str, ...] = field(default_factory=tuple)
    strategy: Optional[str] = None
    effectiveness: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "phase": list(self.phase),
            "strategy": self.strategy,
            "effectiveness": self.effectiveness,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapecMitigation":
        return cls(
            description=d.get("description"),
            phase=tuple(d.get("phase", [])),
            strategy=d.get("strategy"),
            effectiveness=d.get("effectiveness"),
        )


@dataclass(frozen=True)
class CapecDetection:
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
    def from_dict(cls, d: Dict[str, Any]) -> "CapecDetection":
        return cls(
            method=d.get("method"),
            description=d.get("description"),
            effectiveness=d.get("effectiveness"),
            effectiveness_notes=d.get("effectiveness_notes"),
        )


@dataclass(frozen=True)
class CapecRelatedAttackPattern:
    capec_id: str
    nature: Optional[str] = None
    view_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"capec_id": self.capec_id, "nature": self.nature, "view_id": self.view_id}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapecRelatedAttackPattern":
        return cls(capec_id=d.get("capec_id", ""), nature=d.get("nature"), view_id=d.get("view_id"))


@dataclass(frozen=True)
class CapecReference:
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
    def from_dict(cls, d: Dict[str, Any]) -> "CapecReference":
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
class CapecEntity:
    """
    Complete CAPEC attack pattern entity capturing every available field from the MITRE CAPEC XML.
    """
    capec_id: str
    name: str
    abstraction: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    extended_description: Optional[str] = None
    likelihood_of_attack: Optional[str] = None
    typical_severity: Optional[str] = None
    execution_flow: Tuple[CapecExecutionFlowStep, ...] = field(default_factory=tuple)
    prerequisites: Tuple[str, ...] = field(default_factory=tuple)
    skills_required: Tuple[CapecSkillRequired, ...] = field(default_factory=tuple)
    resources_required: Tuple[str, ...] = field(default_factory=tuple)
    indicators: Tuple[str, ...] = field(default_factory=tuple)
    consequences: Tuple[CapecConsequence, ...] = field(default_factory=tuple)
    mitigations: Tuple[CapecMitigation, ...] = field(default_factory=tuple)
    example_instances: Tuple[str, ...] = field(default_factory=tuple)
    related_attack_patterns: Tuple[CapecRelatedAttackPattern, ...] = field(default_factory=tuple)
    related_weaknesses: Tuple[str, ...] = field(default_factory=tuple)  # CWE IDs
    taxonomy_mappings: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    references: Tuple[CapecReference, ...] = field(default_factory=tuple)
    detection: Tuple[CapecDetection, ...] = field(default_factory=tuple)
    notes: Optional[str] = None
    source_version: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        # Extract ATT&CK technique IDs from taxonomy_mappings (mirrors CapecMapper logic)
        attack_technique_ids: List[str] = []
        for tm in self.taxonomy_mappings:
            if isinstance(tm, dict):
                tax_name = (tm.get("taxonomy_name") or "").lower()
                if "mitre" in tax_name and "att" in tax_name:
                    entry_id = tm.get("entry_id")
                    if entry_id:
                        attack_technique_ids.append(entry_id)

        return {
            "capec_id": self.capec_id,
            "name": self.name,
            "abstraction": self.abstraction,
            "status": self.status,
            "description": self.description,
            "extended_description": self.extended_description,
            "likelihood_of_attack": self.likelihood_of_attack,
            "typical_severity": self.typical_severity,
            "execution_flow": [s.to_dict() for s in self.execution_flow],
            "prerequisites": list(self.prerequisites),
            "skills_required": [s.to_dict() for s in self.skills_required],
            "resources_required": list(self.resources_required),
            "indicators": list(self.indicators),
            "consequences": [c.to_dict() for c in self.consequences],
            "mitigations": [m.to_dict() for m in self.mitigations],
            "example_instances": list(self.example_instances),
            "related_attack_patterns": [r.to_dict() for r in self.related_attack_patterns],
            "related_weaknesses": list(self.related_weaknesses),
            "taxonomy_mappings": list(self.taxonomy_mappings),
            "attack_technique_ids": attack_technique_ids,
            "references": [r.to_dict() for r in self.references],
            "detection": [d.to_dict() for d in self.detection],
            "notes": self.notes,
            "source_version": self.source_version,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapecEntity":
        return cls(
            capec_id=d.get("capec_id", ""),
            name=d.get("name", ""),
            abstraction=d.get("abstraction"),
            status=d.get("status"),
            description=d.get("description"),
            extended_description=d.get("extended_description"),
            likelihood_of_attack=d.get("likelihood_of_attack"),
            typical_severity=d.get("typical_severity"),
            execution_flow=tuple(CapecExecutionFlowStep.from_dict(s) for s in d.get("execution_flow", [])),
            prerequisites=tuple(d.get("prerequisites", [])),
            skills_required=tuple(CapecSkillRequired.from_dict(s) for s in d.get("skills_required", [])),
            resources_required=tuple(d.get("resources_required", [])),
            indicators=tuple(d.get("indicators", [])),
            consequences=tuple(CapecConsequence.from_dict(c) for c in d.get("consequences", [])),
            mitigations=tuple(CapecMitigation.from_dict(m) for m in d.get("mitigations", [])),
            example_instances=tuple(d.get("example_instances", [])),
            related_attack_patterns=tuple(CapecRelatedAttackPattern.from_dict(r) for r in d.get("related_attack_patterns", [])),
            related_weaknesses=tuple(d.get("related_weaknesses", [])),
            taxonomy_mappings=tuple(d.get("taxonomy_mappings", [])),
            references=tuple(CapecReference.from_dict(r) for r in d.get("references", [])),
            detection=tuple(CapecDetection.from_dict(det) for det in d.get("detection", [])),
            notes=d.get("notes"),
            source_version=d.get("source_version"),
            url=d.get("url"),
        )


@dataclass(frozen=True)
class CapecRelationship:
    """Normalized CAPEC-to-CAPEC relationship for graph construction."""
    source_capec_id: str
    target_capec_id: str
    nature: str
    view_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_capec_id": self.source_capec_id,
            "target_capec_id": self.target_capec_id,
            "nature": self.nature,
            "view_id": self.view_id,
        }


@dataclass(frozen=True)
class CapecCweMapping:
    """Cross-reference between a CAPEC attack pattern and a CWE weakness."""
    capec_id: str
    cwe_id: str
    nature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"capec_id": self.capec_id, "cwe_id": self.cwe_id, "nature": self.nature}
