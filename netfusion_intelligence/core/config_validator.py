"""
Configuration Validator for intelligence feeds.
Validates schedule expressions, retry policies, timeouts, duplicate IDs, and capability alignment.
"""

import re
from typing import List, Optional
from netfusion_intelligence.core.exceptions import FeedRegistrationError
from netfusion_intelligence.interfaces.feed import FeedInterface


class ConfigurationValidationError(FeedRegistrationError):
    """Raised when feed configuration fails validation before registration."""
    pass


CRON_REGEX = re.compile(
    r"^(\*|([0-5]?\d)(-[0-5]?\d)?(,\s*[0-5]?\d(-[0-5]?\d)?)*)(\/\d+)?\s+"
    r"(\*|([01]?\d|2[0-3])(-([01]?\d|2[0-3]))?(,\s*([01]?\d|2[0-3])(-([01]?\d|2[0-3]))?)*)(\/\d+)?\s+"
    r"(\*|([1-9]|[12]\d|3[01])(-([1-9]|[12]\d|3[01]))?(,\s*([1-9]|[12]\d|3[01])(-([1-9]|[12]\d|3[01]))?)*)(\/\d+)?\s+"
    r"(\*|([1-9]|1[0-2])(-([1-9]|1[0-2]))?(,\s*([1-9]|1[0-2])(-([1-9]|1[0-2]))?)*)(\/\d+)?\s+"
    r"(\*|[0-6](-[0-6])?(,\s*[0-6](-[0-6])?)*)(\/\d+)?$"
)


def validate_cron_expression(schedule: str) -> bool:
    """Validates 5-part cron syntax or standard presets."""
    if not schedule or not schedule.strip():
        return False
    s = schedule.strip()
    if s.startswith("@"):  # e.g., @hourly, @daily, @weekly
        return s in {"@hourly", "@daily", "@weekly", "@monthly", "@yearly"}
    # Split tokens
    parts = s.split()
    if len(parts) != 5:
        return False
    return bool(CRON_REGEX.match(s))


def validate_feed_configuration(feed: FeedInterface, existing_feed_ids: Optional[List[str]] = None) -> None:
    """
    Validates a feed instance and its configuration before registration.
    Throws ConfigurationValidationError if invalid.
    """
    if not isinstance(feed, FeedInterface):
        raise ConfigurationValidationError("Provided object does not implement FeedInterface")

    feed_id = feed.feed_id
    if not feed_id or not feed_id.strip():
        raise ConfigurationValidationError("Feed ID cannot be empty or blank")

    if existing_feed_ids and feed_id in existing_feed_ids:
        raise ConfigurationValidationError(f"Duplicate Feed ID '{feed_id}' is already registered")

    config = feed.config
    if not config:
        raise ConfigurationValidationError(f"Feed '{feed_id}' has missing configuration")

    # 1. Validate Schedule
    if config.schedule and not validate_cron_expression(config.schedule):
        raise ConfigurationValidationError(f"Feed '{feed_id}' has invalid schedule format: '{config.schedule}'")

    # 2. Validate Retry Policy
    if config.retry_count < 0:
        raise ConfigurationValidationError(f"Feed '{feed_id}' has invalid retry_count ({config.retry_count}); must be >= 0")
    if config.retry_delay < 0:
        raise ConfigurationValidationError(f"Feed '{feed_id}' has invalid retry_delay ({config.retry_delay}); must be >= 0")

    # 3. Validate Timeout
    if config.timeout <= 0:
        raise ConfigurationValidationError(f"Feed '{feed_id}' has invalid timeout ({config.timeout}); must be > 0")

    # 4. Capability Alignment Validation
    manifest = feed.manifest
    if manifest:
        if config.checksum_required and not manifest.supports_checksum_verification:
            raise ConfigurationValidationError(
                f"Feed '{feed_id}' configuration requires checksum verification, but manifest states it is unsupported"
            )
