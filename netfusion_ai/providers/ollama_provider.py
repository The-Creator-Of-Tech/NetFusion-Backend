"""
NetFusion Local LLM / Ollama Provider Adapter
Implements BaseAIProvider for local Ollama HTTP REST endpoints.
"""

import time
import requests
from typing import Any, Dict

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class OllamaProvider(BaseAIProvider):
    """Local Ollama LLM provider adapter."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.config.model_name = self.config.model_name or "llama3"
        self.config.api_base = self.config.api_base or "http://localhost:11434"

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.OLLAMA

    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        url = f"{self.config.api_base.rstrip('/')}/api/chat"

        messages = list(request.messages)
        if not messages:
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            if request.user_prompt:
                messages.append({"role": "user", "content": request.user_prompt})

        payload: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature if request.temperature is not None else self.config.temperature,
                "num_predict": request.max_tokens or self.config.max_tokens,
            }
        }
        if request.json_mode:
            payload["format"] = "json"

        try:
            resp = requests.post(url, json=payload, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            latency = time.time() - start_time

            content = data.get("message", {}).get("content", "")
            prompt_tokens = data.get("prompt_eval_count", 0)
            completion_tokens = data.get("eval_count", 0)

            return LLMResponse(
                content=content,
                provider_name=self.provider_type.value,
                model_name=self.config.model_name,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                latency_seconds=latency,
                finish_reason="stop" if data.get("done") else "length",
                raw_response=data,
            )
        except Exception as e:
            raise ProviderError("Ollama", f"API invocation failed: {str(e)}", e) from e

    def is_healthy(self) -> bool:
        try:
            url = f"{self.config.api_base.rstrip('/')}/api/tags"
            resp = requests.get(url, timeout=3.0)
            return resp.status_code == 200
        except Exception:
            return False
