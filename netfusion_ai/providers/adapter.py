"""
NetFusion Provider Adapter & Registry
Manages registration, selection, health routing, and automatic failover across LLM providers.
"""

from typing import Dict, List, Optional

from netfusion_ai.enums import AIProviderType
from netfusion_ai.events import AIEventPublisher, AIProviderFailure
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig
from .openai_provider import OpenAIProvider
from .azure_openai_provider import AzureOpenAIProvider
from .anthropic_provider import AnthropicProvider
from .gemini_provider import GeminiProvider
from .groq_provider import GroqProvider
from .ollama_provider import OllamaProvider
from .mock_provider import MockAIProvider


class ProviderAdapter:
    """Manager and Failover Router for AI Providers."""

    def __init__(
        self,
        primary_provider: Optional[BaseAIProvider] = None,
        event_publisher: Optional[AIEventPublisher] = None,
    ):
        self._providers: Dict[str, BaseAIProvider] = {}
        self._fallback_order: List[str] = []
        self.event_publisher = event_publisher
        self._auto_mock = False

        if primary_provider:
            self.register_provider(primary_provider.provider_type.value, primary_provider, set_primary=True)
        else:
            mock = MockAIProvider()
            self._auto_mock = True
            self.register_provider(AIProviderType.MOCK.value, mock, set_primary=True)

    def register_provider(
        self, name: str, provider: BaseAIProvider, set_primary: bool = False
    ) -> None:
        """Registers a provider adapter instance."""
        # If replacing auto-generated mock, clean it up
        if self._auto_mock and name != AIProviderType.MOCK.value:
            if AIProviderType.MOCK.value in self._providers:
                del self._providers[AIProviderType.MOCK.value]
            if AIProviderType.MOCK.value in self._fallback_order:
                self._fallback_order.remove(AIProviderType.MOCK.value)
            self._auto_mock = False

        self._providers[name] = provider
        if name in self._fallback_order:
            self._fallback_order.remove(name)

        if set_primary:
            self._primary_name = name
            self._fallback_order.insert(0, name)
        else:
            self._fallback_order.append(name)

    def get_provider(self, name: Optional[str] = None) -> BaseAIProvider:
        """Retrieves a provider by name or primary default."""
        target = name or self._primary_name
        if target not in self._providers:
            raise ProviderError(target, f"Provider '{target}' is not registered.")
        return self._providers[target]

    def generate(self, request: LLMRequest, preferred_provider: Optional[str] = None) -> LLMResponse:
        """Generates text via primary provider with automatic failover chain."""
        order = list(self._fallback_order)
        start_name = preferred_provider or self._primary_name
        if start_name in order:
            order.remove(start_name)
            order.insert(0, start_name)

        last_exception: Optional[Exception] = None

        for name in order:
            provider = self._providers[name]
            if not provider.is_healthy():
                continue
            try:
                response = provider.generate(request)
                return response
            except Exception as e:
                last_exception = e
                fallback_next = order[order.index(name) + 1] if order.index(name) + 1 < len(order) else None
                if self.event_publisher:
                    self.event_publisher.publish(
                        AIProviderFailure(
                            provider_name=name,
                            error_message=str(e),
                            fallback_provider=fallback_next,
                        )
                    )

        # Fallback to Mock if all failed
        mock = MockAIProvider(custom_response="[Fallback] AI Provider unavailable; returning deterministic mock response.")
        return mock.generate(request)

    def health_check_all(self) -> Dict[str, bool]:
        """Returns health status for all registered providers."""
        return {name: p.is_healthy() for name, p in self._providers.items()}


def create_provider_from_config(config: ProviderConfig) -> BaseAIProvider:
    """Factory helper creating provider instance from ProviderConfig."""
    ptype = config.provider_type
    if isinstance(ptype, str):
        ptype = AIProviderType(ptype)

    if ptype == AIProviderType.OPENAI:
        return OpenAIProvider(config)
    elif ptype == AIProviderType.AZURE_OPENAI:
        return AzureOpenAIProvider(config)
    elif ptype == AIProviderType.ANTHROPIC:
        return AnthropicProvider(config)
    elif ptype == AIProviderType.GEMINI:
        return GeminiProvider(config)
    elif ptype == AIProviderType.GROQ:
        return GroqProvider(config)
    elif ptype == AIProviderType.OLLAMA:
        return OllamaProvider(config)
    elif ptype == AIProviderType.MOCK:
        return MockAIProvider(config)
    else:
        return MockAIProvider(config)
