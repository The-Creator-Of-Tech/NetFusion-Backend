"""Tests for IL-7 IocDownloader."""

import pytest
from netfusion_intelligence.feeds.ioc.downloader import IocDownloader
from netfusion_intelligence.feeds.ioc.providers import OfflineImportProvider, JsonProvider


class TestIocDownloader:

    def test_offline_data_bypass(self):
        dl = IocDownloader(offline_data={"indicators": [{"type": "ipv4", "value": "1.1.1.1"}]})
        result = dl.download()
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["provider_type"] == "manual"

    def test_offline_provider(self):
        provider = OfflineImportProvider(
            data={"indicators": [{"type": "domain", "value": "test.com"}]},
            name="UnitTest",
        )
        dl = IocDownloader(providers=[provider])
        result = dl.download()
        assert len(result) == 1
        assert result[0]["provider_id"] == "offline_unittest"
        assert result[0]["raw"] is not None
        assert "provider" not in result[0]   # provider object stripped — not JSON serializable

    def test_no_providers_returns_empty_payload(self):
        dl = IocDownloader()
        result = dl.download()
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["raw"] == []

    def test_add_provider(self):
        dl = IocDownloader()
        p = OfflineImportProvider(data=[], name="Late")
        dl.add_provider(p)
        result = dl.download()
        assert len(result) == 1

    def test_provider_error_is_non_fatal(self):
        """A provider that raises must not abort the entire download."""
        class FailingProvider(OfflineImportProvider):
            def fetch(self):
                raise RuntimeError("network failure")

        good = OfflineImportProvider(data={"indicators": []}, name="Good")
        bad = FailingProvider(data=None, name="Bad")
        dl = IocDownloader(providers=[good, bad])
        result = dl.download()
        assert len(result) == 2
        assert result[1].get("error") is not None
    def test_multiple_providers_aggregated(self):
        p1 = OfflineImportProvider(data={"indicators": [{"type": "ipv4", "value": "10.0.0.1"}]}, name="P1")
        p2 = OfflineImportProvider(data={"indicators": [{"type": "domain", "value": "bad.com"}]}, name="P2")
        dl = IocDownloader(providers=[p1, p2])
        result = dl.download()
        assert len(result) == 2
