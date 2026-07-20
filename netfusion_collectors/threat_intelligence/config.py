from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from netfusion_collector_sdk.config import CollectorConfig


class IOCType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    URL = "URL"
    FILE_HASH = "FileHash"
    EMAIL = "Email"
    CVE = "CVE"
    CPE = "CPE"


class RetryPolicyConfig(BaseModel):
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_factor: float = Field(default=1.5, ge=0.1, le=60.0)
    retry_statuses: List[int] = Field(default_factory=lambda: [429, 500, 502, 503, 504])


class RateLimitConfig(BaseModel):
    requests_per_minute: int = Field(default=60, ge=1, le=10000)
    burst_limit: int = Field(default=10, ge=1, le=1000)


class BaseProviderConfig(BaseModel):
    enabled: bool = Field(default=True)
    api_key: Optional[str] = Field(default=None)
    oauth_token: Optional[str] = Field(default=None)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    base_url: Optional[str] = Field(default=None)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    cache_ttl: int = Field(default=86400)  # 24 hours


class AbuseIPDBConfig(BaseProviderConfig):
    base_url: str = "https://api.abuseipdb.com/api/v2"
    max_age_days: int = Field(default=90, ge=1, le=365)


class VirusTotalConfig(BaseProviderConfig):
    base_url: str = "https://www.virustotal.com/api/v3"


class AlienVaultOTXConfig(BaseProviderConfig):
    base_url: str = "https://otx.alienvault.com/api/v1"


class URLhausConfig(BaseProviderConfig):
    base_url: str = "https://urlhaus-api.abuse.ch/v1"


class MISPConfig(BaseProviderConfig):
    base_url: Optional[str] = Field(default=None, description="URL of MISP instance e.g. https://misp.local")
    verify_cert: bool = Field(default=True)


class OpenCTIConfig(BaseProviderConfig):
    base_url: Optional[str] = Field(default=None, description="URL of OpenCTI GraphQL server")


class ThreatIntelConfig(CollectorConfig):
    # General Settings
    api_timeout: float = Field(default=10.0, ge=0.1, le=300.0)
    retry_policy: RetryPolicyConfig = Field(default_factory=RetryPolicyConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    cache_ttl: int = Field(default=86400, ge=0)
    proxy_support: Optional[Union[str, Dict[str, str]]] = Field(default=None)
    tls_verification: bool = Field(default=True)
    batch_size: int = Field(default=50, ge=1, le=1000)
    concurrent_lookups: int = Field(default=10, ge=1, le=100)
    cache_dir: str = Field(default="./cache/threat_intel")

    # Inputs
    iocs: List[Dict[str, Any]] = Field(default_factory=list, description="List of IOCs to enrich: [{'value': '1.1.1.1', 'type': 'IPv4'}]")
    enrich_investigation_context: bool = Field(default=True)

    # Provider Configurations
    abuseipdb: AbuseIPDBConfig = Field(default_factory=AbuseIPDBConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    alienvault_otx: AlienVaultOTXConfig = Field(default_factory=AlienVaultOTXConfig)
    urlhaus: URLhausConfig = Field(default_factory=URLhausConfig)
    misp: MISPConfig = Field(default_factory=MISPConfig)
    opencti: OpenCTIConfig = Field(default_factory=OpenCTIConfig)
