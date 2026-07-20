"""
NetFusion Memory Manager
Maintains investigation-scoped memory buffers:
- Conversation History
- Investigation Context
- Prompt Cache
- AI Responses
- Provider Metadata
Ensures isolation between different investigation scopes.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time

from netfusion_ai.domain import ConversationTurn, AnalysisResult
from netfusion_ai.context_builder import InvestigationContextContainer
from netfusion_ai.exceptions import MemoryError


@dataclass
class InvestigationMemoryScope:
    """Isolated memory storage container for a single investigation."""
    investigation_id: str
    context_container: Optional[InvestigationContextContainer] = None
    conversation_history: List[ConversationTurn] = field(default_factory=list)
    prompt_cache: Dict[str, str] = field(default_factory=dict)
    ai_responses: List[AnalysisResult] = field(default_factory=list)
    provider_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


class MemoryManager:
    """Investigation-scoped Memory Manager."""

    def __init__(self, max_history_turns: int = 50):
        self.max_history_turns = max_history_turns
        self._scopes: Dict[str, InvestigationMemoryScope] = {}

    def get_or_create_scope(self, investigation_id: str) -> InvestigationMemoryScope:
        """Retrieves existing memory scope or initializes a new isolated scope."""
        if not investigation_id:
            raise MemoryError("Investigation ID must be non-empty for memory scoping.")
        if investigation_id not in self._scopes:
            self._scopes[investigation_id] = InvestigationMemoryScope(investigation_id=investigation_id)
        return self._scopes[investigation_id]

    def set_context(self, investigation_id: str, context: InvestigationContextContainer) -> None:
        """Updates active investigation context container in memory scope."""
        scope = self.get_or_create_scope(investigation_id)
        scope.context_container = context

    def get_context(self, investigation_id: str) -> Optional[InvestigationContextContainer]:
        """Retrieves investigation context container from memory scope."""
        scope = self.get_or_create_scope(investigation_id)
        return scope.context_container

    def add_turn(self, investigation_id: str, turn: ConversationTurn) -> None:
        """Appends interactive analyst copilot conversation turn."""
        scope = self.get_or_create_scope(investigation_id)
        scope.conversation_history.append(turn)
        if len(scope.conversation_history) > self.max_history_turns:
            scope.conversation_history = scope.conversation_history[-self.max_history_turns:]

    def cache_prompt(self, investigation_id: str, key: str, rendered_prompt: str) -> None:
        """Caches rendered prompt in investigation scope."""
        scope = self.get_or_create_scope(investigation_id)
        scope.prompt_cache[key] = rendered_prompt

    def get_cached_prompt(self, investigation_id: str, key: str) -> Optional[str]:
        """Retrieves cached rendered prompt."""
        scope = self.get_or_create_scope(investigation_id)
        return scope.prompt_cache.get(key)

    def record_response(self, investigation_id: str, result: AnalysisResult) -> None:
        """Records AI AnalysisResult in memory scope."""
        scope = self.get_or_create_scope(investigation_id)
        scope.ai_responses.append(result)

    def get_responses(self, investigation_id: str) -> List[AnalysisResult]:
        """Retrieves list of past AI AnalysisResults for an investigation."""
        scope = self.get_or_create_scope(investigation_id)
        return scope.ai_responses

    def update_provider_metadata(self, investigation_id: str, meta: Dict[str, Any]) -> None:
        """Updates provider usage and latency metadata."""
        scope = self.get_or_create_scope(investigation_id)
        scope.provider_metadata.update(meta)

    def clear_scope(self, investigation_id: str) -> None:
        """Wipes memory scope for a closed or purged investigation."""
        if investigation_id in self._scopes:
            del self._scopes[investigation_id]
