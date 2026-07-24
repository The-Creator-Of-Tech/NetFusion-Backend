"""
Identity Registry for NetFusion CIIL.
Maintains entity types, generic mapping configurations, and identifier schemas dynamically.
NO feed-specific logic is hardcoded here.
"""

from typing import Any, Callable, Dict, List, Optional, Set
from netfusion_intelligence.identity.models import CanonicalEntityType


class IdentityRegistry:
    """
    Generic registry for entity types, mapping strategies, and identifier patterns.
    """

    def __init__(self):
        self._supported_entity_types: Set[str] = {e.value for e in CanonicalEntityType}
        self._mapping_strategies: Dict[str, Callable[[Any], Dict[str, Any]]] = {}
        self._identifier_types: Set[str] = {
            "ATTACK_ID", "STIX_ID", "CVE_ID", "CWE_ID", "CAPEC_ID",
            "SHA256", "MD5", "SHA1", "DOMAIN", "URL", "IP", "EMAIL",
            "UUID", "CUSTOM", "VIRUSTOTAL_ID", "OPENCTI_ID", "MISP_UUID",
            "THREATFOX_ID", "ABUSEIPDB_ID", "MALWAREBAZAAR_ID"
        }

    def register_entity_type(self, entity_type: str) -> None:
        """Dynamically registers a custom entity type."""
        if not entity_type:
            raise ValueError("entity_type cannot be empty")
        self._supported_entity_types.add(entity_type.upper())

    def is_registered_entity_type(self, entity_type: str) -> bool:
        return entity_type.upper() in self._supported_entity_types

    def list_entity_types(self) -> List[str]:
        return sorted(list(self._supported_entity_types))

    def register_identifier_type(self, identifier_type: str) -> None:
        """Registers a custom identifier type string."""
        if not identifier_type:
            raise ValueError("identifier_type cannot be empty")
        self._identifier_types.add(identifier_type.upper())

    def is_registered_identifier_type(self, identifier_type: str) -> bool:
        return identifier_type.upper() in self._identifier_types

    def list_identifier_types(self) -> List[str]:
        return sorted(list(self._identifier_types))

    def register_mapping_strategy(self, feed_name: str, strategy_fn: Callable[[Any], Dict[str, Any]]) -> None:
        """Registers a generic mapper strategy for a given feed name."""
        if not feed_name:
            raise ValueError("feed_name cannot be empty")
        self._mapping_strategies[feed_name.lower()] = strategy_fn

    def get_mapping_strategy(self, feed_name: str) -> Optional[Callable[[Any], Dict[str, Any]]]:
        return self._mapping_strategies.get(feed_name.lower())
