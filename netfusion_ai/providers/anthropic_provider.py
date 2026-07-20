"""
NetFusion Anthropic Provider Adapter
Implements BaseAIProvider for Anthropic Claude API.
"""

import time
import requests
from typing import Any, Dict

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API provider adapter."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.config.model_name = self.config.model_name or "claude-3-5-sonnet-20241022"
        self.config.api_base = self.config.api_base or "https://api.anthropic.com/v1"
        self.config.api_version = self.config.api_version or "2023-06-01"

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.ANTHROPIC

    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        url = f"{self.config.api_base.rstrip('/')}/messages"
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": self.config.api_version,
            "Content-Type": "application/json",
        }

        messages = []
        if request.messages:
            for m in request.messages:
                if m.get("role") != "system":
                    messages.append({"role": m["role"], "content": m["content"]})
        else:
            if request.user_prompt:
                messages.append({"role": "user", "content": request.user_prompt})

        payload: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "max_tokens": request.max_tokens or self.config.max_tokens,
            "temperature": request.temperature if request.temperature is not None else self.config.temperature,
        }
        if request.system_prompt:
            payload["system"] = request.system_prompt
        if request.stop_sequences:
            payload["stop_sequences"] = request.stop_sequences

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            latency = time.time() - start_time

            content_blocks = data.get("content", [])
            content = "".join([block.get("text", "") for block in content_blocks if block.get("type") == "text"])
            usage = data.get("usage", {})

            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)

            return LLMResponse(
                content=content,
                provider_name=self.provider_type.value,
                model_name=self.config.model_name,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                latency_seconds=latency,
                finish_reason=data.get("stop_reason", "end_turn"),
                raw_response=data,
            )
        except Exception as e:
            raise ProviderError("Anthropic", f"API invocation failed: {str(e)}", e) from e

    def is_healthy(self) -> bool:
        return bool(self.config.api_key)
