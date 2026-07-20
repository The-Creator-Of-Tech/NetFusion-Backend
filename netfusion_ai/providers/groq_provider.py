"""
NetFusion Groq Provider Adapter
Implements BaseAIProvider for Groq LLaMA/Mixtral acceleration API.
"""

import time
import requests
from typing import Any, Dict

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class GroqProvider(BaseAIProvider):
    """Groq Cloud API provider adapter."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.config.model_name = self.config.model_name or "llama-3.3-70b-versatile"
        self.config.api_base = self.config.api_base or "https://api.groq.com/openai/v1"

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.GROQ

    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        url = f"{self.config.api_base.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        messages = list(request.messages)
        if not messages:
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            if request.user_prompt:
                messages.append({"role": "user", "content": request.user_prompt})

        payload: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "max_tokens": request.max_tokens or self.config.max_tokens,
            "temperature": request.temperature if request.temperature is not None else self.config.temperature,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}

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
            raise ProviderError("Groq", f"API invocation failed: {str(e)}", e) from e

    def is_healthy(self) -> bool:
        if not self.config.api_key:
            return False
        try:
            url = f"{self.config.api_base.rstrip('/')}/models"
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            resp = requests.get(url, headers=headers, timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False
