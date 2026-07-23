"""Tests for IL-7 IocValidator — format and cross-reference rules."""

import pytest
from netfusion_intelligence.feeds.ioc.validator import IocValidator
from netfusion_intelligence.feeds.ioc.normalizer import IocNormalizer


def _normalized(indicators):
    norm = IocNormalizer()
    return norm.normalize({"indicators": indicators, "provider_metas": []})


class TestIocValidator:

    def setup_method(self):
        self.val = IocValidator()

    def test_valid_ipv4_passes(self):
        ds = _normalized([{"type": "ipv4", "value": "8.8.8.8", "confidence": 0.9}])
        result = self.val.validate(ds)
        assert result.is_valid
        assert result.errors == []

    def test_valid_domain_passes(self):
        ds = _normalized([{"type": "domain", "value": "evil.com"}])
        result = self.val.validate(ds)
        assert result.is_valid

    def test_valid_sha256_passes(self):
        ds = _normalized([{"type": "sha256", "value": "a" * 64}])
        result = self.val.validate(ds)
        assert result.is_valid

    def test_valid_url_passes(self):
        ds = _normalized([{"type": "url", "value": "https://malware.com/drop.exe"}])
        result = self.val.validate(ds)
        assert result.is_valid

    def test_valid_email_passes(self):
        ds = _normalized([{"type": "email", "value": "bad@evil.com"}])
        result = self.val.validate(ds)
        assert result.is_valid

    def test_non_dict_input_fails(self):
        result = self.val.validate("not a dict")
        assert not result.is_valid
        assert any("not a dict" in e.message.lower() for e in result.errors)

    def test_empty_dataset_is_valid(self):
        result = self.val.validate({"entities": {}})
        assert result.is_valid

    def test_confidence_out_of_range_raises_error(self):
        """Confidence outside [0,1] after normalizer clamps — inject manually."""
        import uuid
        from netfusion_intelligence.feeds.ioc.models import IocEntity
        bad_entity = IocEntity(
            ioc_id=str(uuid.uuid4()),
            ioc_type="ipv4",
            value="1.2.3.4",
            confidence=1.5,   # invalid
        )
        fp = "fake_fp"
        ds = {"entities": {fp: bad_entity}}
        result = self.val.validate(ds)
        assert not result.is_valid
        assert any("CONFIDENCE" in e.rule_name for e in result.errors)

    def test_invalid_attack_id_generates_warning(self):
        import uuid
        from netfusion_intelligence.feeds.ioc.models import IocEntity
        ent = IocEntity(
            ioc_id=str(uuid.uuid4()),
            ioc_type="ipv4",
            value="9.9.9.9",
            confidence=0.5,
            attack_technique_ids=("BADID",),
        )
        ds = {"entities": {"fp1": ent}}
        result = self.val.validate(ds)
        assert result.is_valid   # warnings don't fail validation
        assert any("ATTACK" in w.rule_name for w in result.warnings)

    def test_invalid_capec_id_warning(self):
        import uuid
        from netfusion_intelligence.feeds.ioc.models import IocEntity
        ent = IocEntity(
            ioc_id=str(uuid.uuid4()), ioc_type="domain", value="test.com",
            confidence=0.5, capec_ids=("NOT-CAPEC",),
        )
        ds = {"entities": {"fp2": ent}}
        result = self.val.validate(ds)
        assert any("CAPEC" in w.rule_name for w in result.warnings)

    def test_invalid_cve_id_warning(self):
        import uuid
        from netfusion_intelligence.feeds.ioc.models import IocEntity
        ent = IocEntity(
            ioc_id=str(uuid.uuid4()), ioc_type="domain", value="x.com",
            confidence=0.5, cve_ids=("CVE-BADFORMAT",),
        )
        ds = {"entities": {"fp3": ent}}
        result = self.val.validate(ds)
        assert any("CVE" in w.rule_name for w in result.warnings)

    def test_total_checked_reflects_entity_count(self):
        ds = _normalized([
            {"type": "ipv4", "value": "1.1.1.1"},
            {"type": "domain", "value": "a.com"},
            {"type": "sha256", "value": "b" * 64},
        ])
        result = self.val.validate(ds)
        assert result.total_checked == 3
