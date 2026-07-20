import asyncio
import time
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk import CollectorContext
from .config import ThreatIntelConfig
from .cache import ThreatIntelCache
from .metrics import ThreatIntelMetrics
from .providers import (
    BaseThreatProvider,
    IOCInput,
    ProviderResponse,
    ThreatProviderFactory,
)


class ThreatIntelRunner:
    """
    Asynchronous Execution Runner for Threat Intelligence Collector.
    Manages batching, concurrency semaphores, caching, rate limiting, retries, and provider aggregation.
    """

    def __init__(
        self,
        config: ThreatIntelConfig,
        cache: ThreatIntelCache,
        metrics: Optional[ThreatIntelMetrics] = None,
    ):
        self.config: ThreatIntelConfig = config
        self.cache: ThreatIntelCache = cache
        self.metrics: Optional[ThreatIntelMetrics] = metrics
        self.semaphore = asyncio.Semaphore(config.concurrent_lookups)
        self.providers: List[BaseThreatProvider] = self._init_providers()

    def _init_providers(self) -> List[BaseThreatProvider]:
        provider_configs = [
            ("abuseipdb", self.config.abuseipdb),
            ("virustotal", self.config.virustotal),
            ("alienvault_otx", self.config.alienvault_otx),
            ("urlhaus", self.config.urlhaus),
            ("misp", self.config.misp),
            ("opencti", self.config.opencti),
        ]

        active_providers = []
        for name, cfg in provider_configs:
            if cfg.enabled:
                try:
                    p_inst = ThreatProviderFactory.create_provider(name, cfg)
                    active_providers.append(p_inst)
                except Exception:
                    pass
        return active_providers

    async def lookup_single(self, ioc: IOCInput) -> List[ProviderResponse]:
        """Lookup a single IOC across all enabled providers with caching and retry policy."""
        responses: List[ProviderResponse] = []

        async with self.semaphore:
            for provider in self.providers:
                if not provider.enabled:
                    continue

                # 1. Cache lookup
                cached_data = self.cache.get(provider.name, ioc.type, ioc.value)
                if cached_data is not None:
                    if self.metrics:
                        self.metrics.record_cache_hit()
                    try:
                        resp = ProviderResponse(**cached_data)
                        responses.append(resp)
                        continue
                    except Exception:
                        pass

                if self.metrics:
                    self.metrics.record_cache_miss()
                    self.metrics.record_lookup(1)

                # 2. Provider API call with Retries
                resp = await self._execute_with_retry(provider, ioc)
                responses.append(resp)

                # 3. Save to cache
                if not resp.error_message:
                    is_neg = not resp.is_threat
                    resp_dict = resp.__dict__
                    self.cache.set(
                        provider=provider.name,
                        ioc_type=ioc.type,
                        ioc_value=ioc.value,
                        value=resp_dict,
                        is_negative=is_neg,
                    )
                else:
                    if self.metrics:
                        self.metrics.record_failure()

        return responses

    async def _execute_with_retry(
        self,
        provider: BaseThreatProvider,
        ioc: IOCInput,
    ) -> ProviderResponse:
        retries = self.config.retry_policy.max_retries
        backoff = self.config.retry_policy.backoff_factor

        for attempt in range(retries + 1):
            try:
                resp = await provider.lookup_ioc(ioc)
                if not resp.error_message:
                    if resp.is_threat and self.metrics:
                        self.metrics.record_threat_match()
                    return resp

                if attempt < retries:
                    await asyncio.sleep(backoff * (2 ** attempt))
            except Exception as e:
                if attempt == retries:
                    return ProviderResponse(
                        provider_name=provider.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        is_threat=False,
                        error_message=str(e),
                    )
                await asyncio.sleep(backoff * (2 ** attempt))

        return ProviderResponse(
            provider_name=provider.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_threat=False,
            error_message="Max retries exceeded",
        )

    async def run_batch(self, iocs: List[IOCInput]) -> List[ProviderResponse]:
        """Execute concurrent batch lookups across all IOCs."""
        all_results: List[ProviderResponse] = []
        chunks = [iocs[i : i + self.config.batch_size] for i in range(0, len(iocs), self.config.batch_size)]

        for chunk in chunks:
            tasks = [self.lookup_single(ioc) for ioc in chunk]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=False)
            for res_list in chunk_results:
                all_results.extend(res_list)

        return all_results

    def execute_sync(self, iocs: List[IOCInput]) -> List[ProviderResponse]:
        """Synchronous wrapper for async runner execution."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # Nested loop handling or create new task
            import nest_asyncio  # if available
            try:
                nest_asyncio.apply()
                return loop.run_until_complete(self.run_batch(iocs))
            except Exception:
                # Fallback run in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(self.run_batch(iocs)))
                    return future.result()
        else:
            return loop.run_until_complete(self.run_batch(iocs))
