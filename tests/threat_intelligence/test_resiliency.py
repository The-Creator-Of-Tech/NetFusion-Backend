import pytest
import asyncio
from unittest.mock import patch, MagicMock
from netfusion_collectors.threat_intelligence.config import ThreatIntelConfig, RetryPolicyConfig
from netfusion_collectors.threat_intelligence.cache import ThreatIntelCache
from netfusion_collectors.threat_intelligence.runner import ThreatIntelRunner
from netfusion_collectors.threat_intelligence.providers import (
    IOCInput,
    BaseThreatProvider,
    ProviderResponse,
)


class FailingProvider(BaseThreatProvider):
    def __init__(self, name: str, config: any):
        super().__init__(name, config)
        self.attempts = 0

    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        self.attempts += 1
        if self.attempts < 3:
            raise RuntimeError("HTTP 429 Rate Limit Exceeded")
        return ProviderResponse(
            provider_name=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_threat=True,
            confidence=90.0,
        )


def test_retry_and_recovery(temp_cache_dir):
    async def _test():
        config = ThreatIntelConfig(
            cache_dir=temp_cache_dir,
            retry_policy=RetryPolicyConfig(max_retries=3, backoff_factor=0.1),
        )
        cache = ThreatIntelCache(db_path=f"{temp_cache_dir}/res.db")
        runner = ThreatIntelRunner(config=config, cache=cache)

        failing_prov = FailingProvider(name="failing_prov", config=config.abuseipdb)
        runner.providers = [failing_prov]

        resps = await runner.lookup_single(IOCInput(value="8.8.8.8", type="IPv4"))

        assert len(resps) == 1
        assert resps[0].is_threat is True
        assert resps[0].confidence == 90.0
        assert failing_prov.attempts == 3

    asyncio.run(_test())
