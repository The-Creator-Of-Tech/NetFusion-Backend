"""
NetFusion Mock AI Provider
Implements BaseAIProvider for deterministic testing, offline execution, and fallback handling.
"""

import json
import time
from typing import Any, Dict, Optional

from netfusion_ai.enums import AIProviderType
from .base import BaseAIProvider, LLMRequest, LLMResponse, ProviderConfig


class MockAIProvider(BaseAIProvider):
    """Deterministic Mock AI Provider for testing."""

    def __init__(
        self,
        config: Optional[ProviderConfig] = None,
        custom_response: Optional[str] = None,
        healthy: bool = True,
    ):
        config = config or ProviderConfig(provider_type=AIProviderType.MOCK, model_name="mock-analyst-v1")
        super().__init__(config)
        self.custom_response = custom_response
        self._healthy = healthy
        self.call_count = 0
        self.last_request: Optional[LLMRequest] = None

    @property
    def provider_type(self) -> AIProviderType:
        return AIProviderType.MOCK

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.call_count += 1
        self.last_request = request
        start_time = time.time()

        if self.custom_response:
            content = self.custom_response
        elif request.json_mode:
            content = json.dumps({
                "summary": "Mock investigation summary analyzing input context.",
                "confidence_score": 0.85,
                "findings": ["Observed suspicious activity", "Correlated timeline events"],
                "mitre_tactics": ["Initial Access", "Execution"],
                "risk_rating": "HIGH",
            })
        else:
            content = (
                "Mock Analysis Result:\n"
                f"Processed prompt length: {len(request.user_prompt or '')} chars.\n"
                "Key Finding: Incident exhibits potential privilege escalation and internal discovery."
            )

        latency = time.time() - start_time
        prompt_tokens = len((request.user_prompt or "").split()) + len((request.system_prompt or "").split())
        completion_tokens = len(content.split())

        return LLMResponse(
            content=content,
            provider_name=self.provider_type.value,
            model_name=self.config.model_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_seconds=latency,
            finish_reason="stop",
            raw_response={"mock": True, "call_count": self.call_count},
        )

    def is_healthy(self) -> bool:
        return self._healthy

    def set_healthy(self, healthy: bool) -> None:
        self._healthy = healthy
