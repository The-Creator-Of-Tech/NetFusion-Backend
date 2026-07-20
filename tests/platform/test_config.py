"""
Integration tests for NetFusion Configuration Management.
"""

import pytest
from netfusion_platform.config import (
    ConfigurationManager,
    PlatformConfig,
    validate_platform_config,
    ensure_valid_config,
    ConfigurationValidationError,
)


def test_configuration_manager_default():
    cm = ConfigurationManager()
    cfg = cm.config
    assert cfg.environment in ("development", "staging", "production", "test")
    assert cfg.database.pool_size >= 1
    assert cfg.features.enable_ai is True


def test_configuration_validation():
    cfg = PlatformConfig(environment="invalid_env")
    is_valid, errors = validate_platform_config(cfg)
    assert not is_valid
    assert len(errors) > 0

    with pytest.raises(ConfigurationValidationError):
        ensure_valid_config(cfg)


def test_hot_reload():
    cm = ConfigurationManager()
    reloaded_count = 0

    def callback(new_cfg):
        nonlocal reloaded_count
        reloaded_count += 1

    cm.register_reload_callback(callback)
    cm.reload()
    assert reloaded_count == 1
