"""
Tests for IdentityRegistry in NetFusion CIIL.
"""

from netfusion_intelligence.identity.models import CanonicalEntityType
from netfusion_intelligence.identity.registry import IdentityRegistry


def test_registry_entity_and_identifier_type_management():
    reg = IdentityRegistry()

    assert reg.is_registered_entity_type("ATTACK_TECHNIQUE")
    assert reg.is_registered_entity_type("CVE")

    # Register custom entity type
    reg.register_entity_type("CUSTOM_THREAT_CONTAINER")
    assert reg.is_registered_entity_type("CUSTOM_THREAT_CONTAINER")
    assert "CUSTOM_THREAT_CONTAINER" in reg.list_entity_types()

    # Register custom identifier type
    reg.register_identifier_type("SHODAN_HOST_ID")
    assert reg.is_registered_identifier_type("SHODAN_HOST_ID")
    assert "SHODAN_HOST_ID" in reg.list_identifier_types()


def test_registry_mapping_strategy_registration():
    reg = IdentityRegistry()

    def dummy_strategy(obj):
        return {"mapped": True}

    reg.register_mapping_strategy("custom_feed", dummy_strategy)
    strat = reg.get_mapping_strategy("CUSTOM_FEED")
    assert strat is not None
    assert strat({})["mapped"] is True
