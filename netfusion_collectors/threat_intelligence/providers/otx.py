import time
import urllib.request
import urllib.parse
import json
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class AlienVaultOTXProvider(BaseThreatProvider):
    """
    AlienVault OTX (Open Threat Exchange) Provider.
    Enriches IPs, Domains, Hashes, and URLs with pulse threat intelligence.
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", "https://otx.alienvault.com/api/v1") or "https://otx.alienvault.com/api/v1"

    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        start_time = time.time()
        self.total_lookups += 1

        if not self.api_key:
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name="AlienVault OTX API Key Unconfigured",
                metadata={"status": "NO_API_KEY"},
            )

        type_map = {
            "ipv4": f"indicators/IPv4/{ioc.value}/general",
            "ipv6": f"indicators/IPv6/{ioc.value}/general",
            "ip": f"indicators/IPv4/{ioc.value}/general",
            "domain": f"indicators/domain/{ioc.value}/general",
            "filehash": f"indicators/file/{ioc.value}/general",
            "hash": f"indicators/file/{ioc.value}/general",
            "cve": f"indicators/cve/{ioc.value}/general",
        }

        endpoint = type_map.get(ioc.type.lower())
        if not endpoint:
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name=f"Unsupported IOC Type '{ioc.type}' for AlienVault OTX",
            )

        def _do_request():
            url = f"{self.base_url}/{endpoint}"
            req = urllib.request.Request(url, headers={"X-OTX-API-KEY": self.api_key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            pulse_info = raw_res.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)

            is_threat = pulse_count > 0
            confidence = min(100.0, pulse_count * 20.0)
            severity = (
                Severity.CRITICAL if pulse_count >= 10 else
                Severity.HIGH if pulse_count >= 5 else
                Severity.MEDIUM if pulse_count >= 1 else
                Severity.INFORMATIONAL
            )

            tags = set()
            adversaries = set()
            for pulse in pulses:
                tags.update(pulse.get("tags", []))
                if pulse.get("adversary"):
                    adversaries.add(pulse.get("adversary"))

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=confidence,
                severity=severity,
                threat_name=f"AlienVault OTX ({pulse_count} Threat Pulses)" if is_threat else "No OTX Pulses Matched",
                categories=list(tags),
                raw_data=raw_res,
                references=[f"https://otx.alienvault.com/indicator/{ioc.type.lower()}/{ioc.value}"],
                metadata={"pulse_count": pulse_count, "adversaries": list(adversaries)},
            )
        except Exception as e:
            self.failure_count += 1
            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                error_message=self._mask_secret(str(e)),
            )


ThreatProviderFactory.register("alienvault_otx", AlienVaultOTXProvider)
ThreatProviderFactory.register("otx", AlienVaultOTXProvider)
