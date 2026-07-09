/**
 * AI Application Layer — Phase A5.4.2
 * ======================================
 * Barrel export for all AI orchestrators.
 *
 * Architecture:
 *   Router → AI Orchestrators (this) → AI Service Layer → Repository → Prisma → PostgreSQL
 *
 * Orchestrators:
 *  - AIOrchestrator       — master coordinator (full conversation workflow)
 *  - ConversationOrchestrator — turn-by-turn conversation lifecycle
 *  - PromptOrchestrator   — prompt building, context compression, token/cost estimation
 *  - ReasoningOrchestrator — multi-step reasoning, confidence aggregation, retry
 *  - StreamingOrchestrator — stream lifecycle, chunk aggregation, progress, cancel/resume
 */

export {
  AIOrchestrator,
  aiOrchestrator,
  // Input types
  StartConversationInput,
  ContinueConversationInput,
  CloseConversationInput,
  SummarizeConversationInput,
  LoadMemoryInput,
  SaveMemoryInput,
  BuildContextInput,
  RunPromptInput,
  RunReasoningInput,
  ExecuteAIInput,
  StreamResponseInput,
  CancelExecutionInput,
  // Result types
  ConversationResult,
  ContinueConversationResult,
} from './AIOrchestrator';

export {
  ConversationOrchestrator,
  conversationOrchestrator,
  ConversationTurnInput,
  ConversationTurnResult,
  ConversationHistoryResult,
  PruneContextInput,
} from './ConversationOrchestrator';

export {
  PromptOrchestrator,
  promptOrchestrator,
  BuildPromptInput,
  BuildPromptResult,
  CompressContextInput,
  CompressContextResult,
  OptimizePromptInput,
  TokenEstimateResult,
  CostEstimateResult,
} from './PromptOrchestrator';

export {
  ReasoningOrchestrator,
  reasoningOrchestrator,
  RunReasoningWorkflowInput,
  ReasoningWorkflowResult,
  ReasoningStepDefinition,
  StepExecutionResult,
} from './ReasoningOrchestrator';

export {
  StreamingOrchestrator,
  streamingOrchestrator,
  StartStreamInput,
  IngestChunksInput,
  StreamLifecycleResult,
  CancelStreamInput,
  ResumeStreamInput,
} from './StreamingOrchestrator';
