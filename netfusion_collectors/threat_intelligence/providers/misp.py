import time
import urllib.request
import json
import ssl
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class MISPProvider(BaseThreatProvider):
    """
    MISP (Malware Information Sharing Platform) REST API Provider.
    Enriches attributes, events, and indicators from private/community MISP instances.
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", None)
        self.verify_cert = getattr(config, "verify_cert", True)

    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        start_time = time.time()
        self.total_lookups += 1

        if not self.base_url or not self.api_key:
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name="MISP Base URL or API Key Unconfigured",
                metadata={"status": "UNCONFIGURED"},
            )

        def _do_request():
            url = f"{self.base_url.rstrip('/')}/attributes/restSearch"
            payload = json.dumps({"value": ioc.value, "returnFormat": "json"}).encode("utf-8")
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            context = None
            if not self.verify_cert:
                context = ssl._create_unverified_context()

            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10, context=context) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            response_data = raw_res.get("response", {})
            attributes = response_data.get("Attribute", [])
            match_count = len(attributes)

            is_threat = match_count > 0
            confidence = min(100.0, match_count * 25.0)
            severity = Severity.HIGH if match_count >= 3 else (Severity.MEDIUM if is_threat else Severity.INFORMATIONAL)

            categories = list({attr.get("category", "General") for attr in attributes})

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=confidence,
                severity=severity,
                threat_name=f"MISP Attribute Matched ({match_count} events)" if is_threat else "No MISP Attributes Found",
                categories=categories,
                raw_data=raw_res,
                references=[f"{self.base_url}/attributes/index/searchvalue:{ioc.value}"],
                metadata={"match_count": match_count},
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


ThreatProviderFactory.register("misp", MISPProvider)
