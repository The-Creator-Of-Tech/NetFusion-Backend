"""
Tests for CisaKevValidator.
"""

from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.feeds.kev.normalizer import CisaKevNormalizer
from netfusion_intelligence.feeds.kev.parser import CisaKevParser
from netfusion_intelligence.feeds.kev.validator import CisaKevValidator
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON


def test_validator_valid():
    parser = CisaKevParser()
    parsed = parser.parse(SAMPLE_CISA_KEV_JSON)
    normalized = CisaKevNormalizer().normalize(parsed)

    validator = CisaKevValidator()
    result = validator.validate(normalized)
    assert result.is_valid is True
    assert result.rules_failed == 0


def test_validator_invalid_cve():
    normalized = {
        "catalog_version": "1.0",
        "entities": {
            "INVALID": KevRecord(cve_id="INVALID")
        }
    }
    validator = CisaKevValidator()
    result = validator.validate(normalized)
    assert result.is_valid is False
    assert any(err.rule_name == "MALFORMED_CVE_ID" for err in result.errors)


def test_validator_orphan_rejection():
    normalized = {
        "catalog_version": "1.0",
        "entities": {
            "CVE-2021-99999": KevRecord(cve_id="CVE-2021-99999")
        }
    }
    # Dummy canonical checker returning False (CVE does not exist in CIIL)
    validator = CisaKevValidator(canonical_cve_checker=lambda cve: False)
    result = validator.validate(normalized)
    assert result.is_valid is False
    assert any(err.rule_name == "ORPHAN_KEV_ENTRY" for err in result.errors)
