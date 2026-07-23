"""
Tests for identity domain events in NetFusion CIIL.
"""

from netfusion_intelligence.identity.events import (
    CanonicalEntityCreated,
    CanonicalEntityMerged,
    ExternalIdentifierAdded,
    IdentityEventPublisher,
)


def test_event_publisher_pub_sub():
    publisher = IdentityEventPublisher()
    received_events = []

    def handler(event):
        received_events.append(event)

    publisher.subscribe(handler)

    ev1 = CanonicalEntityCreated(canonical_uuid="u-123", entity_type="CVE", display_name="Test CVE")
    ev2 = ExternalIdentifierAdded(canonical_uuid="u-123", source="NVD", identifier="CVE-2025-1", identifier_type="CVE_ID")

    publisher.publish(ev1)
    publisher.publish(ev2)

    assert len(received_events) == 2
    assert received_events[0].canonical_uuid == "u-123"
    assert received_events[1].identifier == "CVE-2025-1"
    assert len(publisher.get_history()) == 2
