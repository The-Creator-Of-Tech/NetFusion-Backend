"""
Unit tests for NVD Downloader (downloader.py).
"""

from netfusion_intelligence.feeds.nvd.downloader import NvdDownloader
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE


def test_offline_downloader():
    downloader = NvdDownloader(offline_data=SAMPLE_NVD_JSON_RESPONSE)
    data = downloader.download()
    assert data == SAMPLE_NVD_JSON_RESPONSE


def test_downloader_init():
    downloader = NvdDownloader(url="https://services.nvd.nist.gov/rest/json/cves/2.0", api_key="test-key")
    assert downloader.url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert downloader.api_key == "test-key"
