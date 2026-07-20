import pytest
import asyncio
from unittest.mock import patch, MagicMock
from netfusion_collectors.threat_intelligence.providers import (
    IOCInput,
    ThreatProviderFactory,
    AbuseIPDBProvider,
    VirusTotalProvider,
    AlienVaultOTXProvider,
    URLHausProvider,
    MISPProvider,
    OpenCTIProvider,
)
from netfusion_collectors.threat_intelligence.config import (
    AbuseIPDBConfig,
    VirusTotalConfig,
    AlienVaultOTXConfig,
    URLhausConfig,
    MISPConfig,
    OpenCTIConfig,
)


def test_provider_factory_registration():
    registered = ThreatProviderFactory.list_registered()
    assert "abuseipdb" in registered
    assert "virustotal" in registered
    assert "alienvault_otx" in registered
    assert "urlhaus" in registered
    assert "misp" in registered
    assert "opencti" in registered


def test_abuseipdb_mock_lookup():
    async def _test():
        cfg = AbuseIPDBConfig(api_key="test_key")
        provider = AbuseIPDBProvider(name="abuseipdb", config=cfg)

        mock_resp = {
            "data": {
                "ipAddress": "1.1.1.1",
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "US",
                "usageType": "Data Center",
            }
        }

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            import json
            mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_resp).encode("utf-8")
            mock_url.return_value = mock_cm

            res = await provider.lookup_ioc(IOCInput(value="1.1.1.1", type="IPv4"))

            assert res.is_threat is True
            assert res.confidence == 85.0
            assert res.metadata["total_reports"] == 42

    asyncio.run(_test())


def test_virustotal_mock_lookup():
    async def _test():
        cfg = VirusTotalConfig(api_key="test_key")
        provider = VirusTotalProvider(name="virustotal", config=cfg)

        mock_resp = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 3, "harmless": 50, "undetected": 5},
                    "categories": {"Kaspersky": "malware", "Sophos": "trojan"},
                }
            }
        }

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            import json
            mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_resp).encode("utf-8")
            mock_url.return_value = mock_cm

            res = await provider.lookup_ioc(IOCInput(value="badsite.com", type="Domain"))

            assert res.is_threat is True
            assert res.metadata["malicious"] == 12
            assert "malware" in res.categories

    asyncio.run(_test())


def test_alienvault_otx_mock_lookup():
    async def _test():
        cfg = AlienVaultOTXConfig(api_key="test_key")
        provider = AlienVaultOTXProvider(name="alienvault_otx", config=cfg)

        mock_resp = {
            "pulse_info": {
                "pulses": [
                    {"name": "Pulse 1", "tags": ["ransomware", "apt29"], "adversary": "Cozy Bear"},
                    {"name": "Pulse 2", "tags": ["c2"], "adversary": None},
                ]
            }
        }

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            import json
            mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_resp).encode("utf-8")
            mock_url.return_value = mock_cm

            res = await provider.lookup_ioc(IOCInput(value="2.2.2.2", type="IPv4"))

            assert res.is_threat is True
            assert res.metadata["pulse_count"] == 2
            assert "Cozy Bear" in res.metadata["adversaries"]

    asyncio.run(_test())


def test_urlhaus_mock_lookup():
    async def _test():
        cfg = URLhausConfig()
        provider = URLHausProvider(name="urlhaus", config=cfg)

        mock_resp = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Emotet", "payload_delivery"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/100/",
        }

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            mock_cm.__enter__.return_value.read.return_value = str(mock_resp).replace("'", '"').encode("utf-8")
            mock_url.return_value = mock_cm

            res = await provider.lookup_ioc(IOCInput(value="http://malware.link/exe", type="URL"))

            assert res.is_threat is True
            assert "Emotet" in res.categories

    asyncio.run(_test())
