"""
NetFusion Base AI Provider Abstraction
Defines the abstract base provider contract, configuration, request/response models,
and health checking interfaces for interchangeable LLM adapters.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time

from netfusion_ai.enums import AIProviderType


@dataclass
class ProviderConfig:
    """Configuration settings for an AI Provider."""
    provider_type: AIProviderType = AIProviderType.MOCK
    api_key: str = ""
    api_base: str = ""
    model_name: str = ""
    api_version: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout_seconds: float = 30.0
    retry_count: int = 3
    additional_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMRequest:
    """Standardized prompt and system instruction request."""
    system_prompt: str = ""
    user_prompt: str = ""
    messages: List[Dict[str, str]] = field(default_factory=list)
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stop_sequences: List[str] = field(default_factory=list)
    json_mode: bool = False


@dataclass
class LLMResponse:
    """Standardized response output from an AI Provider."""
    content: str
    provider_name: str
    model_name: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_seconds: float = 0.0
    finish_reason: str = "stop"
    raw_response: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


class BaseAIProvider(ABC):
    """Abstract Base Class for all NetFusion AI Providers."""

    def __init__(self, config: ProviderConfig):
        self.config = config

    @property
    @abstractmethod
    def provider_type(self) -> AIProviderType:
        """Returns the provider enumeration type."""
        pass

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        """Generates text output synchronously for an LLMRequest."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Checks provider endpoint connectivity and status."""
        pass
