"""
Domain models for MITRE ATT&CK Enterprise STIX 2.1 entities and relationships.
Provides immutable dataclasses for normalized NetFusion intelligence objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ExternalReference:
    source_name: str
    description: Optional[str] = None
    external_id: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "description": self.description,
            "external_id": self.external_id,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalReference":
        return cls(
            source_name=data.get("source_name", ""),
            description=data.get("description"),
            external_id=data.get("external_id"),
            url=data.get("url"),
        )


@dataclass(frozen=True)
class MitreEntity:
    stix_id: str
    type: str
    attack_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    tactics: Tuple[str, ...] = field(default_factory=tuple)
    platforms: Tuple[str, ...] = field(default_factory=tuple)
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    kill_chain_phases: Tuple[Dict[str, str], ...] = field(default_factory=tuple)
    permissions_required: Tuple[str, ...] = field(default_factory=tuple)
    system_requirements: Tuple[str, ...] = field(default_factory=tuple)
    detection: Optional[str] = None
    contributors: Tuple[str, ...] = field(default_factory=tuple)
    external_references: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    url: Optional[str] = None
    version: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    revoked: bool = False
    deprecated: bool = False
    raw_stix: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stix_id": self.stix_id,
            "type": self.type,
            "attack_id": self.attack_id,
            "name": self.name,
            "description": self.description,
            "is_subtechnique": self.is_subtechnique,
            "parent_technique_id": self.parent_technique_id,
            "tactics": list(self.tactics),
            "platforms": list(self.platforms),
            "aliases": list(self.aliases),
            "kill_chain_phases": list(self.kill_chain_phases),
            "permissions_required": list(self.permissions_required),
            "system_requirements": list(self.system_requirements),
            "detection": self.detection,
            "contributors": list(self.contributors),
            "external_references": list(self.external_references),
            "url": self.url,
            "version": self.version,
            "created": self.created,
            "modified": self.modified,
            "revoked": self.revoked,
            "deprecated": self.deprecated,
        }


@dataclass(frozen=True)
class MitreRelationship:
    stix_id: str
    source_ref: str
    target_ref: str
    relationship_type: str
    source_attack_id: Optional[str] = None
    source_type: Optional[str] = None
    target_attack_id: Optional[str] = None
    target_type: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[int] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    external_references: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stix_id": self.stix_id,
            "source_ref": self.source_ref,
            "source_attack_id": self.source_attack_id,
            "source_type": self.source_type,
            "target_ref": self.target_ref,
            "target_attack_id": self.target_attack_id,
            "target_type": self.target_type,
            "relationship_type": self.relationship_type,
            "description": self.description,
            "confidence": self.confidence,
            "created": self.created,
            "modified": self.modified,
            "external_references": list(self.external_references),
            "revoked": self.revoked,
        }
