"""
Tests for NetFusion AI Provider Abstraction and Adapters.
"""

import pytest
from unittest.mock import MagicMock, patch

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from netfusion_ai.providers import (
    BaseAIProvider,
    ProviderConfig,
    LLMRequest,
    LLMResponse,
    OpenAIProvider,
    AzureOpenAIProvider,
    AnthropicProvider,
    GeminiProvider,
    GroqProvider,
    OllamaProvider,
    MockAIProvider,
    ProviderAdapter,
    create_provider_from_config,
)


def test_mock_provider_generation():
    config = ProviderConfig(provider_type=AIProviderType.MOCK)
    mock_p = MockAIProvider(config, custom_response="Custom mock answer")

    req = LLMRequest(user_prompt="Analyze incident")
    resp = mock_p.generate(req)

    assert resp.content == "Custom mock answer"
    assert resp.provider_name == "mock"
    assert resp.prompt_tokens > 0
    assert mock_p.is_healthy() is True


def test_provider_factory():
    cfg_openai = ProviderConfig(provider_type=AIProviderType.OPENAI, api_key="sk-test")
    p = create_provider_from_config(cfg_openai)
    assert isinstance(p, OpenAIProvider)

    cfg_ollama = ProviderConfig(provider_type=AIProviderType.OLLAMA)
    p2 = create_provider_from_config(cfg_ollama)
    assert isinstance(p2, OllamaProvider)


def test_provider_adapter_failover():
    primary = MockAIProvider(healthy=False)
    fallback = MockAIProvider(custom_response="Fallback Success", healthy=True)

    adapter = ProviderAdapter()
    adapter.register_provider("primary_mock", primary, set_primary=True)
    adapter.register_provider("fallback_mock", fallback)

    req = LLMRequest(user_prompt="Test query")
    res = adapter.generate(req)

    assert res.content == "Fallback Success"


def test_openai_provider_mock_http():
    cfg = ProviderConfig(provider_type=AIProviderType.OPENAI, api_key="test-key")
    provider = OpenAIProvider(cfg)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "GPT-4o response"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate(LLMRequest(user_prompt="Hello"))
        assert res.content == "GPT-4o response"
        assert res.total_tokens == 15
