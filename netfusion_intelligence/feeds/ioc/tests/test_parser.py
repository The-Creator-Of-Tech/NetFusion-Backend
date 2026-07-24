"""Tests for IL-7 IocParser — all provider format paths."""

import json
import pytest
from netfusion_intelligence.feeds.ioc.parser import IocParser


class TestIocParser:

    def setup_method(self):
        self.parser = IocParser()

    # ------------------------------------------------------------------
    # Generic JSON
    # ------------------------------------------------------------------

    def test_parse_json_list(self):
        payload = {
            "raw": [
                {"type": "ipv4", "value": "10.0.0.1", "confidence": 0.9},
                {"type": "domain", "value": "bad.com"},
            ],
            "provider_type": "json",
            "provider_id": "test",
            "default_confidence": 0.5,
            "default_tlp": "TLP:WHITE",
        }
        result = self.parser.parse(payload)
        assert result["provider_meta"]["provider_id"] == "test"
        assert len(result["indicators"]) == 2
        assert result["indicators"][0]["type"] == "ipv4"

    def test_parse_json_dict_envelope(self):
        payload = {
            "raw": {"indicators": [{"type": "sha256", "value": "a" * 64}]},
            "provider_type": "json",
            "provider_id": "test",
            "default_confidence": 0.5,
            "default_tlp": "TLP:WHITE",
        }
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["type"] == "sha256"

    def test_parse_json_bytes(self):
        raw = json.dumps([{"type": "email", "value": "x@y.com"}]).encode()
        payload = {"raw": raw, "provider_type": "json", "provider_id": "t",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 1

    def test_parse_empty_raw_returns_empty(self):
        payload = {"raw": None, "provider_type": "json", "provider_id": "t",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert result["indicators"] == []

    # ------------------------------------------------------------------
    # MISP
    # ------------------------------------------------------------------

    def test_parse_misp_attributes(self):
        misp_data = {
            "response": {
                "Attribute": [
                    {"type": "ip-src", "value": "1.2.3.4", "id": "100",
                     "Tag": [{"name": "malware:AgentTesla"}]},
                    {"type": "domain", "value": "evil.com", "id": "101"},
                    {"type": "sha256", "value": "b" * 64, "id": "102"},
                    {"type": "unknown-type", "value": "x"},    # should be skipped
                ]
            }
        }
        payload = {"raw": misp_data, "provider_type": "misp", "provider_id": "misp",
                   "default_confidence": 0.8, "default_tlp": "TLP:AMBER"}
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 3
        ip_ind = next(i for i in result["indicators"] if i["type"] == "ipv4")
        assert ip_ind["tags"] == ["malware:AgentTesla"]
        assert ip_ind["confidence"] == 0.8

    def test_parse_misp_empty_attributes(self):
        misp_data = {"response": {"Attribute": []}}
        payload = {"raw": misp_data, "provider_type": "misp", "provider_id": "misp",
                   "default_confidence": 0.7, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert result["indicators"] == []

    # ------------------------------------------------------------------
    # STIX 2.1
    # ------------------------------------------------------------------

    def test_parse_stix_indicator(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--abc",
                    "pattern": "[ipv4-addr:value = '5.5.5.5']",
                    "confidence": 80,
                    "labels": ["malicious-activity"],
                    "valid_from": "2024-01-01T00:00:00Z",
                },
                {
                    "type": "malware",   # non-indicator, should be ignored
                    "id": "malware--xyz",
                    "name": "TestMalware",
                },
            ],
        }
        payload = {"raw": bundle, "provider_type": "stix", "provider_id": "stix",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["type"] == "ipv4"
        assert result["indicators"][0]["value"] == "5.5.5.5"
        assert abs(result["indicators"][0]["confidence"] - 0.8) < 0.01

    def test_parse_stix_hash_pattern(self):
        bundle = {
            "objects": [{
                "type": "indicator",
                "id": "indicator--h1",
                "pattern": "[file:hashes.'SHA-256' = '" + "c" * 64 + "']",
                "confidence": 90,
            }]
        }
        payload = {"raw": bundle, "provider_type": "stix", "provider_id": "stix",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert result["indicators"][0]["type"] == "sha256"

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def test_parse_csv_with_headers(self):
        csv_data = b"type,value,confidence,severity\nipv4,192.168.1.1,0.9,high\ndomain,bad.net,0.7,medium\n"
        payload = {"raw": csv_data, "provider_type": "csv", "provider_id": "csv",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 2
        assert result["indicators"][0]["type"] == "ipv4"
        assert result["indicators"][0]["value"] == "192.168.1.1"

    def test_parse_csv_type_inference(self):
        csv_data = b"value\n8.8.8.8\ngoogle.com\n" + b"a" * 64 + b"\n"
        payload = {"raw": csv_data, "provider_type": "csv", "provider_id": "csv",
                   "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}
        result = self.parser.parse(payload)
        assert len(result["indicators"]) == 3
        types = {i["type"] for i in result["indicators"]}
        assert "ipv4" in types
        assert "domain" in types
        assert "sha256" in types

    # ------------------------------------------------------------------
    # parse_all aggregation
    # ------------------------------------------------------------------

    def test_parse_all_merges_providers(self):
        payloads = [
            {"raw": [{"type": "ipv4", "value": "1.1.1.1"}], "provider_type": "json",
             "provider_id": "p1", "default_confidence": 0.5, "default_tlp": "TLP:WHITE"},
            {"raw": [{"type": "domain", "value": "test.com"}], "provider_type": "json",
             "provider_id": "p2", "default_confidence": 0.6, "default_tlp": "TLP:WHITE"},
        ]
        result = self.parser.parse_all(payloads)
        assert result["total_raw"] == 2
        assert len(result["indicators"]) == 2
        assert len(result["provider_metas"]) == 2

    # ------------------------------------------------------------------
    # Type inference
    # ------------------------------------------------------------------

    def test_infer_type_ipv4(self):
        assert self.parser._infer_type("192.168.0.1") == "ipv4"

    def test_infer_type_ipv6(self):
        assert self.parser._infer_type("2001:db8::1") == "ipv6"

    def test_infer_type_sha256(self):
        assert self.parser._infer_type("a" * 64) == "sha256"

    def test_infer_type_md5(self):
        assert self.parser._infer_type("b" * 32) == "md5"

    def test_infer_type_sha1(self):
        assert self.parser._infer_type("c" * 40) == "sha1"

    def test_infer_type_email(self):
        assert self.parser._infer_type("user@domain.com") == "email"

    def test_infer_type_url(self):
        assert self.parser._infer_type("https://malicious.com/path") == "url"

    def test_infer_type_domain(self):
        assert self.parser._infer_type("evil.example.com") == "domain"

    def test_infer_type_registry(self):
        t = self.parser._infer_type(r"HKEY_LOCAL_MACHINE\SOFTWARE\Run")
        assert t == "registry_key"

    def test_infer_type_unknown_returns_none(self):
        assert self.parser._infer_type("not-an-indicator") is None
