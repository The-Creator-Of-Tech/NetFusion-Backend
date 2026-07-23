"""Tests for IL-7 IocNormalizer — value normalization and deduplication."""

import pytest
from netfusion_intelligence.feeds.ioc.normalizer import IocNormalizer
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocType


class TestIocNormalizer:

    def setup_method(self):
        self.norm = IocNormalizer()

    def _make_parsed(self, indicators):
        return {"indicators": indicators, "provider_metas": []}

    # ------------------------------------------------------------------
    # IPv4 normalization
    # ------------------------------------------------------------------

    def test_ipv4_normalized(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "  1.2.3.4  ", "confidence": 0.9}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "1.2.3.4"
        assert ent.ioc_type == "ipv4"

    def test_ipv4_with_port_stripped(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "10.0.0.1:8080"}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "10.0.0.1"

    def test_invalid_ipv4_rejected(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "999.999.999.999"}
        ]))
        assert len(result["entities"]) == 0

    # ------------------------------------------------------------------
    # Domain normalization
    # ------------------------------------------------------------------

    def test_domain_lowercased(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "domain", "value": "EVIL.EXAMPLE.COM"}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "evil.example.com"

    def test_domain_strips_protocol(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "domain", "value": "http://evil.com/path"}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "evil.com"

    def test_domain_strips_trailing_dot(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "domain", "value": "malicious.com."}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "malicious.com"

    # ------------------------------------------------------------------
    # Hash normalization
    # ------------------------------------------------------------------

    def test_sha256_uppercased(self):
        h = "a" * 64
        result = self.norm.normalize(self._make_parsed([
            {"type": "sha256", "value": h.lower()}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == h.upper()

    def test_invalid_hash_length_rejected(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "sha256", "value": "abc123"}  # too short
        ]))
        assert len(result["entities"]) == 0

    def test_md5_valid(self):
        h = "b" * 32
        result = self.norm.normalize(self._make_parsed([
            {"type": "md5", "value": h}
        ]))
        assert len(result["entities"]) == 1

    # ------------------------------------------------------------------
    # Email normalization
    # ------------------------------------------------------------------

    def test_email_lowercased(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "email", "value": "ATTACKER@EVIL.COM"}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value == "attacker@evil.com"

    def test_invalid_email_rejected(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "email", "value": "notanemail"}
        ]))
        assert len(result["entities"]) == 0

    # ------------------------------------------------------------------
    # URL normalization
    # ------------------------------------------------------------------

    def test_url_scheme_lowercased(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "url", "value": "HTTP://EVIL.COM/Path?q=1"}
        ]))
        ent = list(result["entities"].values())[0]
        assert ent.value.startswith("http://evil.com")

    # ------------------------------------------------------------------
    # Registry key normalization
    # ------------------------------------------------------------------

    def test_registry_key_hive_expanded(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "registry_key", "value": r"HKLM\SOFTWARE\Run"}
        ]))
        ent = list(result["entities"].values())[0]
        assert "HKEY_LOCAL_MACHINE" in ent.value

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def test_duplicates_deduplicated(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.7},
            {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.9},
        ]))
        # Only one entity after deduplication
        assert len(result["entities"]) == 1
        assert result["duplicate_count"] == 1

    def test_case_insensitive_dedup_domain(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "domain", "value": "Evil.COM"},
            {"type": "domain", "value": "evil.com"},
        ]))
        assert len(result["entities"]) == 1

    def test_different_types_not_deduped(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "1.2.3.4"},
            {"type": "domain", "value": "evil.com"},
        ]))
        assert len(result["entities"]) == 2

    # ------------------------------------------------------------------
    # Attribution fields propagated
    # ------------------------------------------------------------------

    def test_malware_families_propagated(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "5.5.5.5",
             "malware_families": ["Emotet", "TrickBot"]}
        ]))
        ent = list(result["entities"].values())[0]
        assert "Emotet" in ent.malware_families

    def test_attack_ids_propagated(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "domain", "value": "c2.evil.com",
             "attack_technique_ids": ["T1059", "T1071.001"]}
        ]))
        ent = list(result["entities"].values())[0]
        assert "T1059" in ent.attack_technique_ids

    # ------------------------------------------------------------------
    # Missing or invalid entries
    # ------------------------------------------------------------------

    def test_missing_value_skipped(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": ""},
        ]))
        assert len(result["entities"]) == 0

    def test_missing_type_skipped(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "", "value": "1.2.3.4"},
        ]))
        assert len(result["entities"]) == 0

    def test_invalid_type_skipped(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "not_a_real_type", "value": "something"},
        ]))
        assert len(result["entities"]) == 0

    def test_empty_indicators_list(self):
        result = self.norm.normalize({"indicators": [], "provider_metas": []})
        assert result["record_count"] == 0
        assert result["entities"] == {}

    # ------------------------------------------------------------------
    # Record count accuracy
    # ------------------------------------------------------------------

    def test_record_count_matches_entities(self):
        result = self.norm.normalize(self._make_parsed([
            {"type": "ipv4", "value": "1.1.1.1"},
            {"type": "domain", "value": "test.com"},
            {"type": "sha256", "value": "c" * 64},
        ]))
        assert result["record_count"] == len(result["entities"])
        assert result["record_count"] == 3
