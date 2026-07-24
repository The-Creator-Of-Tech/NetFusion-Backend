"""
Tests for CapecVerifier — checksum computation, verification, and XML structure validation.
"""

import hashlib
import pytest

from netfusion_intelligence.feeds.capec.verifier import CapecVerifier
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML, INVALID_XML


class TestCapecVerifierChecksum:

    def test_compute_sha256_returns_hex_string(self):
        v = CapecVerifier()
        result = v.compute_sha256(MINIMAL_CAPEC_XML)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_compute_sha256_correct_value(self):
        v = CapecVerifier()
        expected = hashlib.sha256(MINIMAL_CAPEC_XML).hexdigest()
        assert v.compute_sha256(MINIMAL_CAPEC_XML) == expected

    def test_compute_sha256_string_input(self):
        v = CapecVerifier()
        xml_str = MINIMAL_CAPEC_XML.decode("utf-8")
        result = v.compute_sha256(xml_str)
        expected = hashlib.sha256(MINIMAL_CAPEC_XML).hexdigest()
        assert result == expected

    def test_verify_checksum_no_expected_always_passes(self):
        v = CapecVerifier()
        assert v.verify_checksum(MINIMAL_CAPEC_XML, expected_checksum=None) is True

    def test_verify_checksum_matches(self):
        v = CapecVerifier()
        checksum = v.compute_sha256(MINIMAL_CAPEC_XML)
        assert v.verify_checksum(MINIMAL_CAPEC_XML, expected_checksum=checksum) is True

    def test_verify_checksum_case_insensitive(self):
        v = CapecVerifier()
        checksum = v.compute_sha256(MINIMAL_CAPEC_XML).upper()
        assert v.verify_checksum(MINIMAL_CAPEC_XML, expected_checksum=checksum) is True

    def test_verify_checksum_mismatch_fails(self):
        v = CapecVerifier()
        assert v.verify_checksum(MINIMAL_CAPEC_XML, expected_checksum="deadbeef" * 8) is False

    def test_verify_checksum_empty_string_passes(self):
        v = CapecVerifier()
        assert v.verify_checksum(MINIMAL_CAPEC_XML, expected_checksum="") is True


class TestCapecVerifierStructure:

    def test_valid_xml_passes_structure_check(self):
        v = CapecVerifier()
        assert v.verify_xml_structure(MINIMAL_CAPEC_XML) is True

    def test_invalid_xml_fails_structure_check(self):
        v = CapecVerifier()
        assert v.verify_xml_structure(INVALID_XML) is False

    def test_empty_data_fails_structure_check(self):
        v = CapecVerifier()
        assert v.verify_xml_structure(b"") is False

    def test_xml_declaration_detected(self):
        v = CapecVerifier()
        assert v.verify_xml_structure(b"<?xml version='1.0'?><root/>") is True

    def test_attack_pattern_catalog_root_detected(self):
        v = CapecVerifier()
        assert v.verify_xml_structure(b"<Attack_Pattern_Catalog xmlns='...'/>") is True
