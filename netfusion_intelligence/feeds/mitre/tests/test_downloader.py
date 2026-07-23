"""
Unit tests for MitreDownloader.
"""

import json
from netfusion_intelligence.feeds.mitre.downloader import MitreDownloader
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_downloader_with_offline_dict():
    downloader = MitreDownloader(offline_data=SAMPLE_STIX_BUNDLE)
    data = downloader.download()
    assert isinstance(data, str)
    parsed = json.loads(data)
    assert parsed["type"] == "bundle"
    assert len(parsed["objects"]) == 13


def test_downloader_with_offline_str():
    raw_str = json.dumps(SAMPLE_STIX_BUNDLE)
    downloader = MitreDownloader(offline_data=raw_str)
    data = downloader.download()
    assert data == raw_str


def test_downloader_with_offline_bytes():
    raw_bytes = json.dumps(SAMPLE_STIX_BUNDLE).encode("utf-8")
    downloader = MitreDownloader(offline_data=raw_bytes)
    data = downloader.download()
    assert json.loads(data)["type"] == "bundle"
