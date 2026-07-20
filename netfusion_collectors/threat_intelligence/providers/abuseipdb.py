import time
import urllib.request
import urllib.parse
import json
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class AbuseIPDBProvider(BaseThreatProvider):
    """
    AbuseIPDB Threat Intelligence Provider.
    Enriches IP addresses with abuse confidence scores, report counts, and categories.
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", "https://api.abuseipdb.com/api/v2") or "https://api.abuseipdb.com/api/v2"

    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        start_time = time.time()
        self.total_lookups += 1

        if ioc.type.lower() not in ("ipv4", "ipv6", "ip"):
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name="Unsupported IOC Type for AbuseIPDB",
            )

        if not self.api_key:
            # Mock / Demo fallback if key is unconfigured
            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency
            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=False,
                confidence=0.0,
                threat_name="AbuseIPDB API Key Unconfigured",
                metadata={"status": "NO_API_KEY"},
            )

        def _do_request():
            params = urllib.parse.urlencode({"ipAddress": ioc.value, "maxAgeInDays": getattr(self.config, "max_age_days", 90)})
            url = f"{self.base_url}/check?{params}"
            req = urllib.request.Request(url, headers={"Key": self.api_key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            data = raw_res.get("data", {})
            abuse_score = float(data.get("abuseConfidenceScore", 0))
            is_threat = abuse_score > 20
            severity = (
                Severity.CRITICAL if abuse_score >= 80 else
                Severity.HIGH if abuse_score >= 50 else
                Severity.MEDIUM if abuse_score >= 20 else
                Severity.INFORMATIONAL
            )
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=abuse_score,
                severity=severity,
                threat_name=f"AbuseIPDB Malicious IP (Score: {abuse_score}%)" if is_threat else "Clean IP",
                categories=data.get("usageType", "").split() if data.get("usageType") else ["IP Reputation"],
                raw_data=data,
                references=[f"https://www.abuseipdb.com/check/{ioc.value}"],
                metadata={"total_reports": reports, "country_code": country, "domain": data.get("domain")},
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


ThreatProviderFactory.register("abuseipdb", AbuseIPDBProvider)
