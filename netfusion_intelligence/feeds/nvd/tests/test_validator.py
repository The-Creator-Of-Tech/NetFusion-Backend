"""
Unit tests for NVD Validator (validator.py).
"""

from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_CVE_2024_1234
from netfusion_intelligence.feeds.nvd.validator import NvdValidator


def test_validator_valid_dataset():
    normalizer = NvdNormalizer()
    validator = NvdValidator()

    cve = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)
    norm = {"count": 1, "entities": {cve.cve_id: cve}}

    result = validator.validate(norm)
    assert result.is_valid is True
    assert len(result.errors) == 0


def test_validator_invalid_score():
    normalizer = NvdNormalizer()
    validator = NvdValidator()

    cve = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)
    # Set invalid CVSS score
    bad_cve = cve.from_dict({**cve.to_dict(), "cvss_score": 15.0})

    norm = {"count": 1, "entities": {bad_cve.cve_id: bad_cve}}
    result = validator.validate(norm)

    assert result.is_valid is False
    assert any("out of valid range" in e.message for e in result.errors)
