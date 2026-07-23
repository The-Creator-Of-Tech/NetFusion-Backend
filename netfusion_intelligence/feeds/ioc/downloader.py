"""
IL-7 IOC Downloader.
Orchestrates provider-based data acquisition for the IOC pipeline.
Supports all registered providers: MISP, OpenCTI, STIX, TAXII, CSV, JSON, YAML, offline.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.feeds.ioc.providers import IocProviderInterface


class IocDownloader:
    """
    Executes secure data acquisition from one or more IOC providers.
    Each provider fetches its native format; the downloader aggregates
    the raw payloads into a list of (provider, raw_data) pairs.
    """

    def __init__(
        self,
        providers: Optional[List[IocProviderInterface]] = None,
        offline_data: Optional[Any] = None,
        timeout: float = 600.0,
        verify_tls: bool = True,
    ):
        self._providers = providers or []
        self._offline_data = offline_data
        self.timeout = timeout
        self.verify_tls = verify_tls

    def add_provider(self, provider: IocProviderInterface) -> None:
        """Register an additional provider."""
        self._providers.append(provider)

    def download(self) -> List[Dict[str, Any]]:
        """
        Fetches data from all registered providers.
        Returns a list of payloads: [{"provider": IocProviderInterface, "raw": Any}, ...]
        If offline_data is set directly (bypass), wraps it as a single manual provider payload.
        """
        if self._offline_data is not None:
            return [{"raw": self._offline_data, "provider_id": "offline", "provider_type": "manual",
                     "provider_name": "Offline", "default_confidence": 0.5, "default_tlp": "TLP:WHITE"}]

        results: List[Dict[str, Any]] = []
        for provider in self._providers:
            try:
                raw = provider.fetch()
                results.append({
                    # NOTE: "provider" key intentionally omitted — IocProviderInterface is not
                    # JSON-serializable and the IL-1 checksum utility serializes raw_data.
                    "raw": raw,
                    "provider_id": provider.provider_id,
                    "provider_type": provider.provider_type,
                    "provider_name": provider.provider_name,
                    "default_confidence": provider.default_confidence,
                    "default_tlp": provider.default_tlp,
                })
            except Exception as exc:
                # Non-fatal: log and continue; one provider failure must not abort the pipeline
                results.append({
                    "raw": None,
                    "provider_id": provider.provider_id,
                    "provider_type": provider.provider_type,
                    "provider_name": provider.provider_name,
                    "error": str(exc),
                })

        # If no providers registered, return empty
        return results or [{"provider": None, "raw": [], "provider_id": "empty", "provider_type": "manual"}]
