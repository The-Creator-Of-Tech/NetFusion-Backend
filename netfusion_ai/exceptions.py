"""
NetFusion AI Investigation Assistant Exceptions
Exception hierarchy governing provider failures, context overflows, prompt rendering,
reasoning errors, safety violations, and memory constraints.
"""


class AIError(Exception):
    """Base exception for all AI Investigation Assistant errors."""
    pass


class ProviderError(AIError):
    """Raised when an AI Provider API call or connection fails."""
    def __init__(self, provider_name: str, message: str, raw_error: Exception = None):
        super().__init__(f"[{provider_name}] {message}")
        self.provider_name = provider_name
        self.raw_error = raw_error


class ContextOverflowError(AIError):
    """Raised when investigation context exceeds provider token / size limits."""
    def __init__(self, current_tokens: int, max_tokens: int):
        super().__init__(f"Context token limit exceeded: {current_tokens} > {max_tokens}")
        self.current_tokens = current_tokens
        self.max_tokens = max_tokens


class PromptTemplateError(AIError):
    """Raised when rendering a prompt template fails or variables are missing."""
    pass


class SafetyViolationError(AIError):
    """Raised when AI output violates non-fabrication or attribution principles."""
    pass


class ReasoningError(AIError):
    """Raised when reasoning pipeline fails to form valid analytical conclusions."""
    pass


class MemoryError(AIError):
    """Raised when memory manager fails to retrieve or scope investigation history."""
    pass
