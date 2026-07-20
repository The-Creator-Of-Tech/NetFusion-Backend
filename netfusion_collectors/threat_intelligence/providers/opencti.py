import time
import urllib.request
import json
import asyncio
from typing import Any, Dict
from netfusion_canonical.value_objects import Severity
from .base import BaseThreatProvider, IOCInput, ProviderResponse, ThreatProviderFactory


class OpenCTIProvider(BaseThreatProvider):
    """
    OpenCTI GraphQL Threat Intelligence Provider.
    Queries OpenCTI instance for Indicators, Observables, Threat Actors, and Malware.
    """

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.base_url = getattr(config, "base_url", None)

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
                threat_name="OpenCTI Base URL or API Token Unconfigured",
                metadata={"status": "UNCONFIGURED"},
            )

        query = """
        query StixObservables($search: String) {
            stixObservables(search: $search) {
                edges {
                    node {
                        id
                        entity_type
                        observable_value
                        x_opencti_score
                        created_at
                        objectLabel {
                            value
                        }
                    }
                }
            }
        }
        """

        def _do_request():
            url = f"{self.base_url.rstrip('/')}/graphql"
            payload = json.dumps({"query": query, "variables": {"search": ioc.value}}).encode("utf-8")
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            raw_res = await asyncio.to_thread(_do_request)
            data = raw_res.get("data", {})
            edges = data.get("stixObservables", {}).get("edges", [])
            match_count = len(edges)

            is_threat = match_count > 0
            score = 0.0
            labels = []
            if is_threat:
                node = edges[0].get("node", {})
                score = float(node.get("x_opencti_score", 50.0))
                lbl_nodes = node.get("objectLabel", [])
                if isinstance(lbl_nodes, list):
                    labels = [l.get("value") for l in lbl_nodes if isinstance(l, dict) and "value" in l]

            severity = (
                Severity.CRITICAL if score >= 80 else
                Severity.HIGH if score >= 50 else
                Severity.MEDIUM if is_threat else
                Severity.INFORMATIONAL
            )

            latency = (time.time() - start_time) * 1000
            self.total_latency_ms += latency

            return ProviderResponse(
                provider_name=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                is_threat=is_threat,
                confidence=score if is_threat else 0.0,
                severity=severity,
                threat_name=f"OpenCTI Observable Matched (Score: {score})" if is_threat else "No OpenCTI Observable Matched",
                categories=labels,
                raw_data=raw_res,
                references=[f"{self.base_url}/dashboard/search/{ioc.value}"],
                metadata={"match_count": match_count, "score": score},
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


ThreatProviderFactory.register("opencti", OpenCTIProvider)
