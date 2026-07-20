"""
NetFusion Centralized Configuration Manager
Handles environment variables, YAML, JSON, secrets, feature flags, validation, and hot-reload.
"""

import json
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List

from netfusion_platform.config.models import (
    PlatformConfig,
    DatabaseConfig,
    EventBusConfig,
    CollectorGlobalConfig,
    AIGlobalConfig,
    SecurityConfig,
    FeatureFlags,
)
from netfusion_platform.config.validation import ensure_valid_config

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """Centralized configuration manager supporting Env, YAML, JSON, secrets, and hot reload."""

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._current_config: PlatformConfig = PlatformConfig()
        self._reload_callbacks: List[Callable[[PlatformConfig], None]] = []
        self.load()

    @property
    def config(self) -> PlatformConfig:
        """Access current active PlatformConfig instance."""
        return self._current_config

    def register_reload_callback(self, callback: Callable[[PlatformConfig], None]) -> None:
        """Register callback function invoked when configuration hot-reloads."""
        self._reload_callbacks.append(callback)

    def load(self) -> PlatformConfig:
        """Load configuration hierarchy: Defaults -> File (JSON/YAML) -> Environment Variables."""
        cfg_dict: Dict[str, Any] = {}

        # 1. Load from file if specified or present in default paths
        file_to_load = self._find_config_file()
        if file_to_load and os.path.exists(file_to_load):
            cfg_dict = self._load_file(file_to_load)

        # 2. Build configuration object
        new_config = self._build_config_from_dict(cfg_dict)

        # 3. Apply Environment Variable Overrides
        self._apply_env_overrides(new_config)

        # 4. Validate Configuration
        ensure_valid_config(new_config)

        self._current_config = new_config
        return self._current_config

    def reload(self) -> PlatformConfig:
        """Perform hot-reload of configuration and notify registered callbacks."""
        logger.info("Hot-reloading platform configuration...")
        old_config = self._current_config
        new_config = self.load()
        
        for callback in self._reload_callbacks:
            try:
                callback(new_config)
            except Exception as e:
                logger.error("Error executing reload callback: %s", e)
                
        logger.info("Platform configuration reloaded successfully.")
        return new_config

    def update_feature_flags(self, **flags) -> None:
        """Dynamically update feature flags at runtime."""
        for flag_name, flag_val in flags.items():
            if hasattr(self._current_config.features, flag_name):
                setattr(self._current_config.features, flag_name, bool(flag_val))
                logger.info("Updated feature flag %s = %s", flag_name, flag_val)
            else:
                logger.warning("Unknown feature flag '%s'", flag_name)

    def _find_config_file(self) -> Optional[str]:
        if self._config_path:
            return self._config_path
        
        for candidate in ["netfusion.yaml", "netfusion.yml", "netfusion.json", "config/netfusion.yaml"]:
            if os.path.exists(candidate):
                return candidate
        return None

    def _load_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {}

        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
                return yaml.safe_load(content) or {}
            except ImportError:
                logger.warning("PyYAML not installed, trying basic JSON parse for YAML file")
                return json.loads(content)
        elif path.suffix.lower() == ".json":
            return json.loads(content)
        return {}

    def _build_config_from_dict(self, d: Dict[str, Any]) -> PlatformConfig:
        db_d = d.get("database", {})
        db = DatabaseConfig(
            uri=db_d.get("uri", "sqlite:///dev.db"),
            pool_size=int(db_d.get("pool_size", 10)),
            max_overflow=int(db_d.get("max_overflow", 20)),
            timeout_seconds=int(db_d.get("timeout_seconds", 30)),
        )

        bus_d = d.get("event_bus", {})
        bus = EventBusConfig(
            backend=bus_d.get("backend", "memory"),
            capacity=int(bus_d.get("capacity", 10000)),
            retry_attempts=int(bus_d.get("retry_attempts", 3)),
            dead_letter_queue_enabled=bool(bus_d.get("dead_letter_queue_enabled", True)),
        )

        coll_d = d.get("collectors", {})
        collectors = CollectorGlobalConfig(
            sysmon_enabled=bool(coll_d.get("sysmon_enabled", True)),
            nmap_enabled=bool(coll_d.get("nmap_enabled", True)),
            tshark_enabled=bool(coll_d.get("tshark_enabled", True)),
            threat_intel_enabled=bool(coll_d.get("threat_intel_enabled", True)),
            max_concurrent_collectors=int(coll_d.get("max_concurrent_collectors", 10)),
            default_timeout_seconds=int(coll_d.get("default_timeout_seconds", 300)),
        )

        ai_d = d.get("ai", {})
        ai = AIGlobalConfig(
            default_provider=ai_d.get("default_provider", "mock"),
            model_name=ai_d.get("model_name", "mock-gpt-4"),
            max_token_budget=int(ai_d.get("max_token_budget", 4000)),
            temperature=float(ai_d.get("temperature", 0.2)),
            safety_enabled=bool(ai_d.get("safety_enabled", True)),
            providers=ai_d.get("providers", {}),
        )

        sec_d = d.get("security", {})
        sec = SecurityConfig(
            jwt_secret=sec_d.get("jwt_secret", "netfusion-dev-secret-key-change-in-production-123456"),
            jwt_algorithm=sec_d.get("jwt_algorithm", "HS256"),
            jwt_expiration_minutes=int(sec_d.get("jwt_expiration_minutes", 60)),
            api_key_header=sec_d.get("api_key_header", "X-API-Key"),
            rbac_enabled=bool(sec_d.get("rbac_enabled", True)),
            mask_secrets_in_logs=bool(sec_d.get("mask_secrets_in_logs", True)),
        )

        feat_d = d.get("features", {})
        features = FeatureFlags(
            enable_ai=bool(feat_d.get("enable_ai", True)),
            enable_sysmon=bool(feat_d.get("enable_sysmon", True)),
            enable_nmap=bool(feat_d.get("enable_nmap", True)),
            enable_tshark=bool(feat_d.get("enable_tshark", True)),
            enable_threat_intel=bool(feat_d.get("enable_threat_intel", True)),
            strict_validation=bool(feat_d.get("strict_validation", True)),
            hot_reload=bool(feat_d.get("hot_reload", True)),
            circuit_breaker_enabled=bool(feat_d.get("circuit_breaker_enabled", True)),
            backpressure_enabled=bool(feat_d.get("backpressure_enabled", True)),
        )

        return PlatformConfig(
            environment=d.get("environment", "development"),
            debug=bool(d.get("debug", False)),
            log_level=d.get("log_level", "INFO"),
            app_name=d.get("app_name", "NetFusion Investigation Platform"),
            version=d.get("version", "1.0.0"),
            database=db,
            event_bus=bus,
            collectors=collectors,
            ai=ai,
            security=sec,
            features=features,
        )

    def _apply_env_overrides(self, config: PlatformConfig) -> None:
        """Apply environment variables starting with NETFUSION_."""
        if "NETFUSION_ENV" in os.environ:
            config.environment = os.environ["NETFUSION_ENV"]
        if "NETFUSION_LOG_LEVEL" in os.environ:
            config.log_level = os.environ["NETFUSION_LOG_LEVEL"]
        if "NETFUSION_DEBUG" in os.environ:
            config.debug = os.environ["NETFUSION_DEBUG"].lower() in ("true", "1", "yes")
        if "NETFUSION_JWT_SECRET" in os.environ:
            config.security.jwt_secret = os.environ["NETFUSION_JWT_SECRET"]
        if "NETFUSION_DB_URI" in os.environ:
            config.database.uri = os.environ["NETFUSION_DB_URI"]
        if "NETFUSION_AI_PROVIDER" in os.environ:
            config.ai.default_provider = os.environ["NETFUSION_AI_PROVIDER"]
