import os
from typing import Any, Dict, Optional, Type
from pydantic import BaseModel, Field, ConfigDict


class CollectorConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    collector_id: Optional[str] = None
    timeout: int = Field(default=300, ge=1, le=86400)
    temporary_storage: str = Field(default="/tmp/netfusion")


class ConfigurationManager:
    """
    Cascading configuration resolver.
    Precedence (highest to lowest):
    1. Invocation Overrides
    2. Environment Vars (`NETFUSION_COLLECTOR_*`)
    3. Profiles / Defaults
    """

    @staticmethod
    def resolve(
        config_class: Type[CollectorConfig],
        invocation_overrides: Optional[Dict[str, Any]] = None,
        profile_defaults: Optional[Dict[str, Any]] = None,
    ) -> CollectorConfig:
        merged: Dict[str, Any] = {}

        if profile_defaults:
            merged.update(profile_defaults)

        # Environment variable overrides
        for key, val in os.environ.items():
            if key.startswith("NETFUSION_COLLECTOR_"):
                param_key = key[len("NETFUSION_COLLECTOR_") :].lower()
                merged[param_key] = val

        if invocation_overrides:
            merged.update({k: v for k, v in invocation_overrides.items() if v is not None})

        return config_class(**merged)
