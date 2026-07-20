import pytest
from netfusion_canonical import CanonicalValidator, DeadLetterQueue
from netfusion_collectors.threat_intelligence.canonical import (
    IOCObserved,
    ThreatIntelMatched,
    ThreatActorObserved,
    CampaignObserved,
    MalwareObserved,
    ExploitObserved,
    RelationshipObserved,
    ConfidenceObserved,
    RiskObserved,
    MITREMappingObserved,
)


def test_all_canonical_objects_pass_validator():
    objects = [
        IOCObserved(ioc_value="1.1.1.1", ioc_type="IPv4"),
        ThreatIntelMatched(ioc_value="1.1.1.1", threat_name="Test Threat"),
        ThreatActorObserved(actor_name="APT28"),
        CampaignObserved(campaign_name="Operation Solar"),
        MalwareObserved(malware_name="AgentTesla"),
        ExploitObserved(exploit_id="EXPLOIT-CVE-2021-44228"),
        RelationshipObserved(source_id="A", target_id="B"),
        ConfidenceObserved(target_object_id="obj-123", score=90.0),
        RiskObserved(target_entity="1.1.1.1", risk_score=85.0),
        MITREMappingObserved(technique_id="T1059"),
    ]

    dlq = DeadLetterQueue()

    for obj in objects:
        valid, errors = CanonicalValidator.validate(obj)
        assert valid is True, f"Object {obj.__class__.__name__} failed validation: {errors}"

        # Test seal assignment
        assert obj.checksum is not None
        assert len(obj.checksum) == 64  # SHA-256 length


def test_dlq_rejection_for_invalid_object():
    dlq = DeadLetterQueue()
    invalid_obj = IOCObserved(ioc_value="1.1.1.1")
    invalid_obj.object_id = ""  # Corrupt object_id to force validation failure

    valid, errors = CanonicalValidator.validate(invalid_obj)
    assert valid is False
    assert len(errors) > 0

    if not valid:
        dlq.enqueue(
            raw_payload=invalid_obj.to_dict(),
            errors=errors,
            collector_id="ThreatIntelCollector",
            execution_id="exec-123",
        )

    assert len(dlq.messages) == 1
    msg = dlq.messages[0]
    assert msg.collector_id == "ThreatIntelCollector"
