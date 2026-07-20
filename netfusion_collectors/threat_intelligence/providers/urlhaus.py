import time
import urllib.request
import urllib.parse
import json
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class URLHausProvider(BaseThreatProvider):
    """
    URLhaus API Threat Intelligence Provider (abuse.ch).
    Enriches URLs, Domains, and Hostnames with malware distribution data.
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", "https://urlhaus-api.abuse.ch/v1") or "https://urlhaus-api.abuse.ch/v1"

    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        start_time = time.time()
        self.total_lookups += 1

        ioc_type_lower = ioc.type.lower()
        if ioc_type_lower in ("url", "urls"):
            endpoint = "url"
            param_key = "url"
        elif ioc_type_lower in ("domain", "host", "hostname", "ipv4", "ip"):
            endpoint = "host"
            param_key = "host"
        elif ioc_type_lower in ("filehash", "hash", "md5", "sha256"):
            endpoint = "payload"
            param_key = "hash"
        else:
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name=f"Unsupported IOC Type '{ioc.type}' for URLhaus",
            )

        def _do_request():
            url = f"{self.base_url}/{endpoint}/"
            data_encoded = urllib.parse.urlencode({param_key: ioc.value}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            query_status = raw_res.get("query_status", "no_results")
            is_threat = query_status in ("ok", "found", "active", "online")

            url_status = raw_res.get("url_status", "unknown")
            threat_type = raw_res.get("threat", "malware_download")
            tags = raw_res.get("tags", []) or []

            confidence = 90.0 if is_threat else 0.0
            severity = Severity.HIGH if is_threat else Severity.INFORMATIONAL

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=confidence,
                severity=severity,
                threat_name=f"URLhaus Malicious ({threat_type})" if is_threat else "Clean URLhaus Record",
                categories=tags if isinstance(tags, list) else [tags],
                raw_data=raw_res,
                references=[raw_res.get("urlhaus_reference", f"https://urlhaus.abuse.ch/browse/")],
                metadata={"query_status": query_status, "url_status": url_status},
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


ThreatProviderFactory.register("urlhaus", URLHausProvider)
