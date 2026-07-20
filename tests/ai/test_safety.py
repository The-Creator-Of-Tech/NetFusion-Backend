"""
Tests for NetFusion SafetyEngine and claim verification.
"""

import pytest

from netfusion_ai import SafetyEngine, ContextBuilder, SafetyViolationError, ClaimType


def test_safety_engine_classification():
    safety = SafetyEngine(strict_mode=False)
    cb = ContextBuilder()

    context = cb.build_context(
        canonical_objects=[{"value": "192.168.1.50"}],
        evidence=[{"checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
    )

    sample_text = (
        "Observed evidence log confirms activity from 192.168.1.50.\n"
        "We infer lateral movement occurred.\n"
        "We suspect the adversary used mimikatz hypothesis.\n"
        "Recommend isolating host immediately."
    )

    facts, inferences, hypotheses, recs = safety.verify_and_classify(sample_text, context)

    assert len(facts) >= 1
    assert len(inferences) >= 1
    assert len(hypotheses) >= 1
    assert len(recs) >= 1

    assert facts[0].claim_type == ClaimType.FACT
    assert recs[0].claim_type == ClaimType.RECOMMENDATION


def test_safety_engine_strict_mode_violation():
    safety = SafetyEngine(strict_mode=True)
    cb = ContextBuilder()

    context = cb.build_context()  # Empty context

    text_with_fabricated_ip = "Observed attack from ungrounded IP 203.0.113.99"

    with pytest.raises(SafetyViolationError):
        safety.verify_and_classify(text_with_fabricated_ip, context)
