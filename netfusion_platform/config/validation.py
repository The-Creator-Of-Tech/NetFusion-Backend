"""
NetFusion Platform Configuration Validation Module
Performs schema and semantic validation on configuration structures.
"""

from typing import List, Tuple, Any, Dict
from netfusion_platform.config.models import PlatformConfig


class ConfigurationValidationError(ValueError):
    """Raised when configuration validation fails."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"Configuration validation failed with {len(errors)} error(s):\n" + "\n".join(f"- {e}" for e in errors))


def validate_platform_config(config: PlatformConfig) -> Tuple[bool, List[str]]:
    """
    Validates a PlatformConfig instance.
    Returns (is_valid, list_of_error_messages).
    """
    errors: List[str] = []

    # Environment check
    valid_envs = {"development", "staging", "production", "test"}
    if config.environment.lower() not in valid_envs:
        errors.append(f"Invalid environment '{config.environment}'. Must be one of {valid_envs}")

    # Log level check
    valid_log_levels = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if config.log_level.upper() not in valid_log_levels:
        errors.append(f"Invalid log_level '{config.log_level}'. Must be one of {valid_log_levels}")

    # Database validation
    if config.database.pool_size < 1:
        errors.append(f"database.pool_size must be >= 1, got {config.database.pool_size}")
    if config.database.timeout_seconds < 1:
        errors.append(f"database.timeout_seconds must be >= 1, got {config.database.timeout_seconds}")

    # Event bus validation
    if config.event_bus.capacity < 100:
        errors.append(f"event_bus.capacity must be >= 100, got {config.event_bus.capacity}")

    # AI Config validation
    if not (0.0 <= config.ai.temperature <= 2.0):
        errors.append(f"ai.temperature must be between 0.0 and 2.0, got {config.ai.temperature}")
    if config.ai.max_token_budget < 256:
        errors.append(f"ai.max_token_budget must be >= 256, got {config.ai.max_token_budget}")

    # Security validation
    if config.security.jwt_expiration_minutes < 1:
        errors.append(f"security.jwt_expiration_minutes must be >= 1, got {config.security.jwt_expiration_minutes}")
    if config.environment == "production" and config.security.jwt_secret == "default-netfusion-jwt-secret-key-change-in-production":
        # Warning/error for production default secret
        errors.append("security.jwt_secret must be changed from default in production environment")

    return len(errors) == 0, errors


def ensure_valid_config(config: PlatformConfig) -> None:
    """Raises ConfigurationValidationError if config is invalid."""
    is_valid, errors = validate_platform_config(config)
    if not is_valid:
        raise ConfigurationValidationError(errors)
