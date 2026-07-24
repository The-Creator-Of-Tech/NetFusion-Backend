"""
Tests for CisaKevDownloader.
"""

from netfusion_intelligence.feeds.kev.downloader import CisaKevDownloader
from netfusion_intelligence.feeds.kev.tests.sample_kev import SAMPLE_CISA_KEV_JSON, SAMPLE_CISA_KEV_CSV


def test_downloader_offline_dict():
    dl = CisaKevDownloader(offline_data=SAMPLE_CISA_KEV_JSON)
    data = dl.download()
    assert isinstance(data, dict)
    assert data["count"] == 3


def test_downloader_offline_csv():
    dl = CisaKevDownloader(feed_format="csv", offline_data=SAMPLE_CISA_KEV_CSV)
    data = dl.download()
    assert isinstance(data, str)
    assert "CVE-2021-44228" in data
