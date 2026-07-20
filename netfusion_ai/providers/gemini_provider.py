"""
NetFusion Google Gemini Provider Adapter
Implements BaseAIProvider for Google Gemini REST API.
"""

import time
import requests
from typing import Any, Dict

from netfusion_ai.enums import AIProviderType
from netfusion_ai.exceptions import ProviderError
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class GeminiProvider(BaseAIProvider):
    """Google Gemini API provider adapter."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.config.model_name = self.config.model_name or "gemini-1.5-pro"
        self.config.api_base = self.config.api_base or "https://generativelanguage.googleapis.com/v1beta"

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.GEMINI

    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        model = self.config.model_name
        url = f"{self.config.api_base.rstrip('/')}/models/{model}:generateContent?key={self.config.api_key}"

        contents = []
        if request.messages:
            for m in request.messages:
                role = "user" if m.get("role") == "user" else "model"
                contents.append({"role": role, "parts": [{"text": m.get("content", "")}]})
        else:
            prompt_text = ""
            if request.system_prompt:
                prompt_text += f"{request.system_prompt}\n\n"
            if request.user_prompt:
                prompt_text += request.user_prompt
            contents.append({"role": "user", "parts": [{"text": prompt_text}]})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": request.temperature if request.temperature is not None else self.config.temperature,
                "maxOutputTokens": request.max_tokens or self.config.max_tokens,
            }
        }
        if request.system_prompt and request.messages:
            payload["systemInstruction"] = {"parts": [{"text": request.system_prompt}]}

        try:
            resp = requests.post(url, json=payload, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            latency = time.time() - start_time

            candidates = data.get("candidates", [{}])
            parts = candidates[0].get("content", {}).get("parts", [{}]) if candidates else [{}]
            content = parts[0].get("text", "") if parts else ""
            usage = data.get("usageMetadata", {})

            return LLMResponse(
                content=content,
                provider_name=self.provider_type.value,
                model_name=self.config.model_name,
                prompt_tokens=usage.get("promptTokenCount", 0),
                completion_tokens=usage.get("candidatesTokenCount", 0),
                total_tokens=usage.get("totalTokenCount", 0),
                latency_seconds=latency,
                finish_reason=candidates[0].get("finishReason", "STOP") if candidates else "STOP",
                raw_response=data,
            )
        except Exception as e:
            raise ProviderError("Gemini", f"API invocation failed: {str(e)}", e) from e

    def is_healthy(self) -> bool:
        if not self.config.api_key:
            return False
        try:
            url = f"{self.config.api_base.rstrip('/')}/models?key={self.config.api_key}"
            resp = requests.get(url, timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False
