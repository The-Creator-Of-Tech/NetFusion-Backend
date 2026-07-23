"""
Unit tests for MitreValidator.
"""

from netfusion_intelligence.feeds.mitre.normalizer import MitreNormalizer
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.validator import MitreValidator
from netfusion_intelligence.feeds.mitre.models import MitreEntity, MitreRelationship
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_validator_valid_dataset():
    parsed = MitreParser().parse(SAMPLE_STIX_BUNDLE)
    norm = MitreNormalizer().normalize(parsed)
    val = MitreValidator().validate(norm)

    assert val.is_valid
    assert len(val.errors) == 0


def test_validator_missing_attack_id_error():
    validator = MitreValidator()

    bad_entity = MitreEntity(
        stix_id="attack-pattern--bad-uuid",
        type="attack-pattern",
        name="Bad Technique",
        attack_id=None,  # Missing ATT&CK ID on active technique!
    )
    dataset = {
        "entities": {"attack-pattern--bad-uuid": bad_entity},
        "relationships": [],
    }

    val = validator.validate(dataset)
    assert not val.is_valid
    assert any(e.rule_name == "MISSING_ATTACK_ID" for e in val.errors)


def test_validator_duplicate_attack_id_error():
    validator = MitreValidator()

    e1 = MitreEntity(stix_id="ap1", type="attack-pattern", attack_id="T1001", name="T1")
    e2 = MitreEntity(stix_id="ap2", type="attack-pattern", attack_id="T1001", name="T2")

    dataset = {
        "entities": {"ap1": e1, "ap2": e2},
        "relationships": [],
    }

    val = validator.validate(dataset)
    assert not val.is_valid
    assert any(e.rule_name == "DUPLICATE_ATTACK_ID" for e in val.errors)
