"""
Tests for CweVerifier — checksum computation, verification, and XML structure validation.
"""

import hashlib
import pytest

from netfusion_intelligence.feeds.cwe.verifier import CweVerifier
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML, INVALID_XML


class TestCweVerifierChecksum:

    def test_compute_sha256_returns_hex_string(self):
        v = CweVerifier()
        result = v.compute_sha256(MINIMAL_CWE_XML)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest length

    def test_compute_sha256_correct_value(self):
        v = CweVerifier()
        expected = hashlib.sha256(MINIMAL_CWE_XML).hexdigest()
        assert v.compute_sha256(MINIMAL_CWE_XML) == expected

    def test_compute_sha256_string_input(self):
        v = CweVerifier()
        xml_str = MINIMAL_CWE_XML.decode("utf-8")
        result = v.compute_sha256(xml_str)
        # String should be encoded to bytes before hashing
        expected = hashlib.sha256(MINIMAL_CWE_XML).hexdigest()
        assert result == expected

    def test_verify_checksum_no_expected_always_passes(self):
        v = CweVerifier()
        assert v.verify_checksum(MINIMAL_CWE_XML, expected_checksum=None) is True

    def test_verify_checksum_matches(self):
        v = CweVerifier()
        checksum = v.compute_sha256(MINIMAL_CWE_XML)
        assert v.verify_checksum(MINIMAL_CWE_XML, expected_checksum=checksum) is True

    def test_verify_checksum_case_insensitive(self):
        v = CweVerifier()
        checksum = v.compute_sha256(MINIMAL_CWE_XML).upper()
        assert v.verify_checksum(MINIMAL_CWE_XML, expected_checksum=checksum) is True

    def test_verify_checksum_mismatch_fails(self):
        v = CweVerifier()
        assert v.verify_checksum(MINIMAL_CWE_XML, expected_checksum="deadbeef" * 8) is False

    def test_verify_checksum_empty_string_expected_passes(self):
        """Empty string is falsy — treated as no checksum."""
        v = CweVerifier()
        assert v.verify_checksum(MINIMAL_CWE_XML, expected_checksum="") is True


class TestCweVerifierStructure:

    def test_valid_xml_passes_structure_check(self):
        v = CweVerifier()
        assert v.verify_xml_structure(MINIMAL_CWE_XML) is True

    def test_invalid_xml_fails_structure_check(self):
        v = CweVerifier()
        assert v.verify_xml_structure(INVALID_XML) is False

    def test_empty_data_fails_structure_check(self):
        v = CweVerifier()
        assert v.verify_xml_structure(b"") is False

    def test_xml_declaration_detected(self):
        v = CweVerifier()
        assert v.verify_xml_structure(b"<?xml version='1.0'?><root/>") is True

    def test_weakness_catalog_root_detected(self):
        v = CweVerifier()
        assert v.verify_xml_structure(b"<Weakness_Catalog xmlns='...'/>") is True
