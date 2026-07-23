"""
Unit tests for MitreParser.
"""

import json
import pytest
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_parse_valid_stix_bundle():
    parser = MitreParser()
    res = parser.parse(SAMPLE_STIX_BUNDLE)

    assert res["spec_version"] == "2.1"
    assert res["bundle_id"] == "bundle--11111111-2222-3333-4444-555555555555"
    assert len(res["tactics"]) == 1
    assert len(res["techniques"]) == 2
    assert len(res["groups"]) == 1
    assert len(res["software"]) == 2
    assert len(res["malware"]) == 1
    assert len(res["tools"]) == 1
    assert len(res["campaigns"]) == 1
    assert len(res["mitigations"]) == 1
    assert len(res["data_sources"]) == 1
    assert len(res["relationships"]) == 4


def test_parse_invalid_type_raises():
    parser = MitreParser()
    with pytest.raises(ValueError, match="Expected STIX bundle"):
        parser.parse({"type": "attack-pattern", "objects": []})


def test_parse_invalid_json_raises():
    parser = MitreParser()
    with pytest.raises(ValueError, match="Invalid JSON"):
        parser.parse("not json")
