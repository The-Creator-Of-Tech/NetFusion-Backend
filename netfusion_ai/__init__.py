"""
NetFusion Production-Ready AI Investigation Assistant Package
SOC analyst copilot consuming structured investigation data and generating explainable, non-fabricating analytical outputs.
"""

from .assistant import AIAssistant
from .analysis_engine import AIAnalysisEngine
from .prompt_builder import PromptBuilder
from .context_builder import ContextBuilder, ContextConfig, InvestigationContextContainer
from .recommendation_engine import RecommendationEngine
from .hypothesis_engine import HypothesisEngine
from .risk_engine import RiskEngine
from .explanation_engine import ExplanationEngine
from .report_engine import ReportEngine
from .mitre_reasoner import MITREReasoner
from .confidence_engine import ConfidenceEngine
from .evidence_selector import EvidenceSelector
from .memory_manager import MemoryManager, InvestigationMemoryScope
from .health import AIHealthChecker, AIHealthStatus
from .safety_engine import SafetyEngine

from .enums import (
    AIProviderType,
    AnalysisCategory,
    PromptTemplateType,
    RecommendationCategory,
    TacticalPhase,
    ConfidenceLevel,
    ClaimType,
)
from .exceptions import (
    AIError,
    ProviderError,
    ContextOverflowError,
    PromptTemplateError,
    SafetyViolationError,
    ReasoningError,
    MemoryError,
)
from .domain import (
    EvidenceReference,
    Explanation,
    Claim,
    Hypothesis,
    RecommendationItem,
    MITREInference,
    ConfidenceMetadata,
    RiskScore,
    AIReport,
    AnalysisResult,
    ConversationTurn,
)
from .events import (
    AIEvent,
    AIAnalysisStarted,
    AIAnalysisCompleted,
    AIRecommendationGenerated,
    AIHypothesisGenerated,
    AIReportGenerated,
    AIProviderFailure,
    AIEventPublisher,
)
from .providers import (
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

__all__ = [
    # Core Architecture
    "AIAssistant",
    "AIAnalysisEngine",
    "PromptBuilder",
    "ContextBuilder",
    "ContextConfig",
    "InvestigationContextContainer",
    "RecommendationEngine",
    "HypothesisEngine",
    "RiskEngine",
    "ExplanationEngine",
    "ReportEngine",
    "MITREReasoner",
    "ConfidenceEngine",
    "EvidenceSelector",
    "MemoryManager",
    "InvestigationMemoryScope",
    "AIHealthChecker",
    "AIHealthStatus",
    "SafetyEngine",
    # Enums
    "AIProviderType",
    "AnalysisCategory",
    "PromptTemplateType",
    "RecommendationCategory",
    "TacticalPhase",
    "ConfidenceLevel",
    "ClaimType",
    # Exceptions
    "AIError",
    "ProviderError",
    "ContextOverflowError",
    "PromptTemplateError",
    "SafetyViolationError",
    "ReasoningError",
    "MemoryError",
    # Domain Objects
    "EvidenceReference",
    "Explanation",
    "Claim",
    "Hypothesis",
    "RecommendationItem",
    "MITREInference",
    "ConfidenceMetadata",
    "RiskScore",
    "AIReport",
    "AnalysisResult",
    "ConversationTurn",
    # Events
    "AIEvent",
    "AIAnalysisStarted",
    "AIAnalysisCompleted",
    "AIRecommendationGenerated",
    "AIHypothesisGenerated",
    "AIReportGenerated",
    "AIProviderFailure",
    "AIEventPublisher",
    # Providers
    "BaseAIProvider",
    "ProviderConfig",
    "LLMRequest",
    "LLMResponse",
    "OpenAIProvider",
    "AzureOpenAIProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "GroqProvider",
    "OllamaProvider",
    "MockAIProvider",
    "ProviderAdapter",
    "create_provider_from_config",
]
