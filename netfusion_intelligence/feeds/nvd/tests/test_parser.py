"""
Unit tests for NVD Parser (parser.py).
"""

from netfusion_intelligence.feeds.nvd.parser import NvdParser
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE


def test_parser_dict_payload():
    parser = NvdParser()
    res = parser.parse(SAMPLE_NVD_JSON_RESPONSE)

    assert res["format"] == "NVD_CVE"
    assert res["total_results"] == 2
    assert len(res["items"]) == 2
    assert res["items"][0]["id"] == "CVE-2024-1234"


def test_parser_json_string():
    import json
    parser = NvdParser()
    raw_str = json.dumps(SAMPLE_NVD_JSON_RESPONSE)
    res = parser.parse(raw_str)

    assert res["total_results"] == 2
    assert len(res["items"]) == 2
