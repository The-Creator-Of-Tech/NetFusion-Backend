"""
NetFusion Azure OpenAI Provider Adapter
Implements BaseAIProvider for Azure OpenAI Service deployment endpoints.
"""

import time
import requests
from typing import Any, Dict

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class AzureOpenAIProvider(BaseAIProvider):
    """Azure OpenAI Service provider adapter."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.config.model_name = self.config.model_name or "gpt-4o"
        self.config.api_version = self.config.api_version or "2024-02-15-preview"

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.AZURE_OPENAI

    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        base = self.config.api_base.rstrip('/')
        deployment = self.config.model_name
        url = f"{base}/openai/deployments/{deployment}/chat/completions?api-version={self.config.api_version}"
        headers = {
            "api-key": self.config.api_key,
            "Content-Type": "application/json",
        }

        messages = list(request.messages)
        if not messages:
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            if request.user_prompt:
                messages.append({"role": "user", "content": request.user_prompt})

        payload: Dict[str, Any] = {
            "messages": messages,
            "max_tokens": request.max_tokens or self.config.max_tokens,
            "temperature": request.temperature if request.temperature is not None else self.config.temperature,
        }
        if request.stop_sequences:
            payload["stop"] = request.stop_sequences

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            latency = time.time() - start_time

            choice = data.get("choices", [{}])[0]
            content = choice.get("message", {}).get("content", "")
            usage = data.get("usage", {})

            return LLMResponse(
                content=content,
                provider_name=self.provider_type.value,
                model_name=self.config.model_name,
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                latency_seconds=latency,
                finish_reason=choice.get("finish_reason", "stop"),
                raw_response=data,
            )
        except Exception as e:
            raise ProviderError("AzureOpenAI", f"API invocation failed: {str(e)}", e) from e

    def is_healthy(self) -> bool:
        if not self.config.api_key or not self.config.api_base:
            return False
        try:
            base = self.config.api_base.rstrip('/')
            url = f"{base}/openai/deployments?api-version={self.config.api_version}"
            headers = {"api-key": self.config.api_key}
            resp = requests.get(url, headers=headers, timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False
