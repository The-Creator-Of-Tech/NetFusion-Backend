/**
 * Application Layer — Phase A5.4.1
 * ==================================
 * Barrel export for the entire Application / Orchestration Layer.
 *
 * Architecture:
 *   Router → Application Layer (this) → Service Layer → Repository → Prisma → PostgreSQL
 *
 * Rules:
 *   - Orchestrators NEVER access repositories directly
 *   - Orchestrators only call Service Layer singletons
 *   - All cross-service operations go through an OperationContext
 */

// ── Base ──────────────────────────────────────────────────────────────────────
export {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationError,
  OrchestrationValidationError,
  OrchestrationNotFoundError,
  WorkflowState,
  RetryOptions,
} from './base/BaseApplicationService';

// ── Events ────────────────────────────────────────────────────────────────────
export {
  APP_EVENTS,
  AppEventName,
  ApplicationEventPublisher,
  appEventPublisher,
  // typed event interfaces
  AppEventBase,
  InvestigationStartedEvent,
  InvestigationClosedEvent,
  InvestigationArchivedEvent,
  ScanStartedEvent,
  ScanCompletedEvent,
  CaptureStartedEvent,
  CaptureCompletedEvent,
  ReportGeneratedEvent,
  EvidenceImportedEvent,
  FindingCorrelatedEvent,
  AlertEscalatedEvent,
  // AI event interfaces (A5.4.2)
  AIConversationStartedEvent,
  AIConversationContinuedEvent,
  AIConversationClosedEvent,
  AIConversationSummarizedEvent,
  AIMemoryLoadedEvent,
  AIMemorySavedEvent,
  AIContextBuiltEvent,
  AIPromptBuiltEvent,
  AIReasoningStartedEvent,
  AIReasoningCompletedEvent,
  AIExecutionStartedEvent,
  AIExecutionCompletedEvent,
  AIExecutionCancelledEvent,
  AIStreamingStartedEvent,
  AIStreamingFinishedEvent,
  AIProviderSelectedEvent,
} from './events/ApplicationEvents';

// ── Orchestrators ─────────────────────────────────────────────────────────────
export {
  InvestigationOrchestrator,
  investigationOrchestrator,
} from './investigation/InvestigationOrchestrator';

export {
  ScanOrchestrator,
  scanOrchestrator,
} from './investigation/ScanOrchestrator';

export {
  CaptureOrchestrator,
  captureOrchestrator,
} from './investigation/CaptureOrchestrator';

export {
  ReportOrchestrator,
  reportOrchestrator,
} from './investigation/ReportOrchestrator';

// ── AI Orchestrators (A5.4.2) ─────────────────────────────────────────────────
export {
  AIOrchestrator,
  aiOrchestrator,
  ConversationOrchestrator,
  conversationOrchestrator,
  PromptOrchestrator,
  promptOrchestrator,
  ReasoningOrchestrator,
  reasoningOrchestrator,
  StreamingOrchestrator,
  streamingOrchestrator,
} from './ai';

// ── Knowledge Orchestrators (A5.4.3) ──────────────────────────────────────────
export {
  KnowledgeOrchestrator,
  knowledgeOrchestrator,
  MitreOrchestrator,
  mitreOrchestrator,
  CveOrchestrator,
  cveOrchestrator,
  IocOrchestrator,
  iocOrchestrator,
  ThreatOrchestrator,
  threatOrchestrator,
  CorrelationOrchestrator,
  correlationOrchestrator,
} from './knowledge';

// ── Workflow Orchestrators (A5.4.4) ───────────────────────────────────────────
export {
  WorkflowOrchestrator,
  workflowOrchestrator,
  PlaybookOrchestrator,
  playbookOrchestrator,
  RuleOrchestrator,
  ruleOrchestrator,
  AutomationOrchestrator,
  automationOrchestrator,
  CaseFlowOrchestrator,
  caseFlowOrchestrator,
  ExecutionOrchestrator,
  executionOrchestrator,
} from './workflow';

// ── Shared Orchestrators (A5.4.5) ─────────────────────────────────────────────
export {
  NotificationOrchestrator,
  notificationOrchestrator,
  ActivityOrchestrator,
  activityOrchestrator,
  AttachmentOrchestrator,
  attachmentOrchestrator,
  CommentOrchestrator,
  commentOrchestrator,
  TagOrchestrator,
  tagOrchestrator,
  FavoriteOrchestrator,
  favoriteOrchestrator,
  ApiKeyOrchestrator,
  apiKeyOrchestrator,
  SettingsOrchestrator,
  settingsOrchestrator,
  SharedOrchestrator,
  sharedOrchestrator,
} from './shared';

// ── Platform Orchestrators (A5.4.6) ───────────────────────────────────────────
export {
  PlatformOrchestrator,
  platformOrchestrator,
  InvestigationPipeline,
  investigationPipeline,
  CorrelationPipeline,
  correlationPipeline,
  ResponsePipeline,
  responsePipeline,
  ReportingPipeline,
  reportingPipeline,
  MaintenancePipeline,
  maintenancePipeline,
} from './platform';
