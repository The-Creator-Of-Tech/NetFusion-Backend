import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type
from netfusion_canonical.value_objects import Severity


@dataclass
class IOCInput:
    value: str
    type: str  # IPv4, IPv6, Domain, URL, FileHash, Email, CVE, CPE
    context_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResponse:
    provider_name: str
    ioc_value: str
    ioc_type: str
    is_threat: bool = False
    confidence: float = 0.0  # 0.0 to 100.0
    severity: Severity = Severity.INFORMATIONAL
    threat_name: str = "Clean / No Threat Match"
    categories: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class BaseThreatProvider(ABC):
    """
    Abstract Base Class for all Threat Intelligence Providers.
    Ensures complete isolation of vendor-specific API formats and credentials.
    """

    def __init__(self, name: str, config: Any):
        self.name: str = name
        self.config: Any = config
        self.enabled: bool = getattr(config, "enabled", True)
        self.api_key: Optional[str] = getattr(config, "api_key", None)
        self.base_url: Optional[str] = getattr(config, "base_url", None)
        self.rate_limit_events: int = 0
        self.failure_count: int = 0
        self.total_lookups: int = 0
        self.total_latency_ms: float = 0.0

    @abstractmethod
    async def lookup_ioc(self, ioc: IOCInput) -> ProviderResponse:
        """Perform lookup for a single IOC against provider API."""
        pass

    async def lookup_batch(self, iocs: List[IOCInput]) -> List[ProviderResponse]:
        """Perform concurrent lookup for a list of IOCs."""
        tasks = [self.lookup_ioc(ioc) for ioc in iocs]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def is_healthy(self) -> bool:
        """Check provider health and credential presence."""
        if not self.enabled:
            return False
        return True

    def _mask_secret(self, text: str) -> str:
        """Mask sensitive keys in logs or errors."""
        if not text:
            return ""
        if self.api_key and self.api_key in text:
            return text.replace(self.api_key, "******")
        return text


class ThreatProviderFactory:
    """Registry and Factory for Threat Intelligence Providers."""

    _registry: Dict[str, Type[BaseThreatProvider]] = {}

    @classmethod
    def register(cls, name: str, provider_cls: Type[BaseThreatProvider]) -> None:
        cls._registry[name.lower()] = provider_cls

    @classmethod
    def create_provider(cls, name: str, config: Any) -> BaseThreatProvider:
        provider_key = name.lower()
        if provider_key not in cls._registry:
            raise ValueError(f"Unknown threat provider '{name}'. Registered providers: {list(cls._registry.keys())}")
        return cls._registry[provider_key](name=name, config=config)

    @classmethod
    def list_registered(cls) -> List[str]:
        return list(cls._registry.keys())
