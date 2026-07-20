import time
import urllib.request
import urllib.parse
import json
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class VirusTotalProvider(BaseThreatProvider):
    """
    VirusTotal v3 API Threat Intelligence Provider.
    Supports IPs, Domains, URLs, and File Hashes (MD5, SHA1, SHA256).
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", "https://www.virustotal.com/api/v3") or "https://www.virustotal.com/api/v3"

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
                threat_name="VirusTotal API Key Unconfigured",
                metadata={"status": "NO_API_KEY"},
            )

        ioc_type_lower = ioc.type.lower()
        endpoint_map = {
            "ipv4": f"ip_addresses/{ioc.value}",
            "ipv6": f"ip_addresses/{ioc.value}",
            "ip": f"ip_addresses/{ioc.value}",
            "domain": f"domains/{ioc.value}",
            "filehash": f"files/{ioc.value}",
            "hash": f"files/{ioc.value}",
        }

        endpoint = endpoint_map.get(ioc_type_lower)
        if not endpoint:
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name=f"Unsupported IOC Type '{ioc.type}' for VirusTotal",
            )

        def _do_request():
            url = f"{self.base_url}/{endpoint}"
            req = urllib.request.Request(url, headers={"x-apikey": self.api_key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            attributes = raw_res.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total = malicious + suspicious + harmless + undetected
            positives = malicious + suspicious
            confidence = (positives / total * 100.0) if total > 0 else 0.0

            is_threat = positives > 0
            severity = (
                Severity.CRITICAL if positives >= 10 else
                Severity.HIGH if positives >= 5 else
                Severity.MEDIUM if positives >= 1 else
                Severity.INFORMATIONAL
            )

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=round(confidence, 2),
                severity=severity,
                threat_name=f"VirusTotal Matched ({positives}/{total} detections)" if is_threat else "Clean VirusTotal Record",
                categories=list(attributes.get("categories", {}).values()) if isinstance(attributes.get("categories"), dict) else [],
                raw_data=attributes,
                references=[f"https://www.virustotal.com/gui/search/{ioc.value}"],
                metadata={"malicious": malicious, "suspicious": suspicious, "total": total},
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


ThreatProviderFactory.register("virustotal", VirusTotalProvider)
