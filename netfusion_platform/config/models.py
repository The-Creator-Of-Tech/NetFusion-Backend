"""
NetFusion Platform Configuration Models
Enterprise dataclasses defining strongly typed configuration structures for the entire platform.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    uri: str = "sqlite:///dev.db"
    pool_size: int = 10
    max_overflow: int = 20
    timeout_seconds: int = 30


@dataclass
class EventBusConfig:
    """Event bus channel configuration."""
    backend: str = "memory"  # memory, redis
    capacity: int = 10000
    retry_attempts: int = 3
    dead_letter_queue_enabled: bool = True


@dataclass
class CollectorGlobalConfig:
    """Collectors global toggle and individual configs."""
    sysmon_enabled: bool = True
    nmap_enabled: bool = True
    tshark_enabled: bool = True
    threat_intel_enabled: bool = True
    max_concurrent_collectors: int = 10
    default_timeout_seconds: int = 300


@dataclass
class AIGlobalConfig:
    """AI engine settings and provider configs."""
    default_provider: str = "mock"  # mock, openai, anthropic, gemini, groq, azure_openai, ollama
    model_name: str = "mock-gpt-4"
    max_token_budget: int = 4000
    temperature: float = 0.2
    safety_enabled: bool = True
    providers: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class SecurityConfig:
    """Security, Authentication, and Secret management configuration."""
    jwt_secret: str = "netfusion-dev-secret-key-change-in-production-123456"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60
    api_key_header: str = "X-API-Key"
    rbac_enabled: bool = True
    mask_secrets_in_logs: bool = True


@dataclass
class FeatureFlags:
    """Platform-wide dynamic feature flags."""
    enable_ai: bool = True
    enable_sysmon: bool = True
    enable_nmap: bool = True
    enable_tshark: bool = True
    enable_threat_intel: bool = True
    strict_validation: bool = True
    hot_reload: bool = True
    circuit_breaker_enabled: bool = True
    backpressure_enabled: bool = True


@dataclass
class PlatformConfig:
    """Master platform configuration dataclass."""
    environment: str = "development"  # development, staging, production
    debug: bool = False
    log_level: str = "INFO"
    app_name: str = "NetFusion Investigation Platform"
    version: str = "1.0.0"
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    event_bus: EventBusConfig = field(default_factory=EventBusConfig)
    collectors: CollectorGlobalConfig = field(default_factory=CollectorGlobalConfig)
    ai: AIGlobalConfig = field(default_factory=AIGlobalConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    features: FeatureFlags = field(default_factory=FeatureFlags)
