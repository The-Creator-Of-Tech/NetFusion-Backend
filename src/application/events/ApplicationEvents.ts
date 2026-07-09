/**
 * ApplicationEvents.ts — Phase A5.4.1
 * ======================================
 * Standardised application-level event definitions and typed publisher helpers
 * for the Investigation Orchestration Layer.
 *
 * All events are published through the existing EventPublisher singleton.
 * Naming convention: <Domain><Action>  (PascalCase, past tense where possible)
 */

import { eventPublisher } from '../../services/base/EventPublisher';

// ─────────────────────────────────────────────────────────────────────────────
// Event name constants
// ─────────────────────────────────────────────────────────────────────────────

export const APP_EVENTS = {
  // Investigation lifecycle
  INVESTIGATION_STARTED:      'InvestigationStarted',
  INVESTIGATION_UPDATED:      'InvestigationUpdated',
  INVESTIGATION_CLOSED:       'InvestigationClosed',
  INVESTIGATION_ARCHIVED:     'InvestigationArchived',
  INVESTIGATION_DELETED:      'InvestigationDeleted',
  INVESTIGATION_STATS:        'InvestigationStatsGenerated',
  INVESTIGATION_SUMMARY:      'InvestigationSummaryGenerated',
  ASSET_LINKED:               'AssetLinkedToInvestigation',
  FINDING_LINKED:             'FindingLinkedToInvestigation',
  EVIDENCE_LINKED:            'EvidenceLinkedToInvestigation',

  // Scan workflows
  SCAN_STARTED:               'ScanStarted',
  SCAN_COMPLETED:             'ScanCompleted',
  SCAN_CANCELLED:             'ScanCancelled',
  SCAN_FAILED:                'ScanFailed',
  RESCAN_STARTED:             'RescanStarted',

  // Capture workflows
  CAPTURE_STARTED:            'CaptureStarted',
  CAPTURE_STOPPED:            'CaptureStopped',
  CAPTURE_PAUSED:             'CapturePaused',
  CAPTURE_RESUMED:            'CaptureResumed',
  CAPTURE_ANALYSED:           'CaptureAnalysed',
  CAPTURE_SAVED:              'CaptureSaved',
  CAPTURE_IMPORTED:           'CaptureImported',
  CAPTURE_EXPORTED:           'CaptureExported',
  CAPTURE_COMPLETED:          'CaptureCompleted',

  // Report workflows
  REPORT_GENERATED:           'ReportGenerated',
  EXECUTIVE_REPORT_GENERATED: 'ExecutiveReportGenerated',
  TECHNICAL_REPORT_GENERATED: 'TechnicalReportGenerated',
  REPORT_PUBLISHED:           'ReportPublished',
  REPORT_ARCHIVED:            'ReportArchived',
  REPORT_EXPORTED:            'ReportExported',

  // Cross-domain
  EVIDENCE_IMPORTED:          'EvidenceImported',
  FINDING_CORRELATED:         'FindingCorrelated',
  ALERT_ESCALATED:            'AlertEscalated',

  // AI Orchestration — conversation lifecycle
  AI_CONVERSATION_STARTED:    'AIConversationStarted',
  AI_CONVERSATION_CONTINUED:  'AIConversationContinued',
  AI_CONVERSATION_CLOSED:     'AIConversationClosed',
  AI_CONVERSATION_SUMMARIZED: 'AIConversationSummarized',

  // AI Orchestration — memory & context
  AI_MEMORY_LOADED:           'AIMemoryLoaded',
  AI_MEMORY_SAVED:            'AIMemorySaved',
  AI_CONTEXT_BUILT:           'AIContextBuilt',

  // AI Orchestration — prompt
  AI_PROMPT_BUILT:            'AIPromptBuilt',
  AI_PROMPT_OPTIMIZED:        'AIPromptOptimized',

  // AI Orchestration — reasoning
  AI_REASONING_STARTED:       'AIReasoningStarted',
  AI_REASONING_COMPLETED:     'AIReasoningCompleted',
  AI_REASONING_FAILED:        'AIReasoningFailed',

  // AI Orchestration — execution
  AI_EXECUTION_STARTED:       'AIExecutionStarted',
  AI_EXECUTION_COMPLETED:     'AIExecutionCompleted',
  AI_EXECUTION_CANCELLED:     'AIExecutionCancelled',
  AI_EXECUTION_FAILED:        'AIExecutionFailed',

  // AI Orchestration — streaming
  AI_STREAMING_STARTED:       'AIStreamingStarted',
  AI_STREAMING_FINISHED:      'AIStreamingFinished',
  AI_STREAMING_CANCELLED:     'AIStreamingCancelled',

  // AI Orchestration — provider
  AI_PROVIDER_SELECTED:       'AIProviderSelected',

  // Knowledge Orchestration (A5.4.3)
  FINDING_CORRELATED_FULL:        'FindingCorrelatedFull',
  ASSET_CORRELATED:               'AssetCorrelated',
  INVESTIGATION_KNOWLEDGE_BUILT:  'InvestigationKnowledgeBuilt',
  THREAT_CONTEXT_BUILT:           'ThreatContextBuilt',
  THREAT_SUMMARY_GENERATED:       'ThreatSummaryGenerated',
  RECOMMENDATIONS_GENERATED:      'RecommendationsGenerated',

  MITRE_MAPPED:                   'MitreMapped',
  CVE_CORRELATED:                 'CVECorrelated',
  CVE_RISK_CALCULATED:            'CVERiskCalculated',

  IOC_ENRICHED_FULL:              'IOCEnrichedFull',
  IOC_CORRELATED:                 'IOCCorrelated',
  IOC_REPUTATION_LOOKED_UP:       'IOCReputationLookedUp',

  THREAT_ACTOR_IDENTIFIED:        'ThreatActorIdentified',
  CAMPAIGN_MATCHED:               'CampaignMatched',
  THREAT_SCORE_CALCULATED:        'ThreatScoreCalculated',

  KNOWLEDGE_GRAPH_UPDATED:        'KnowledgeGraphUpdated',

  // ── Workflow Orchestration (A5.4.4) ──────────────────────────────────────
  // Master workflow
  WORKFLOW_STARTED:               'WorkflowStarted',
  WORKFLOW_PAUSED:                'WorkflowPaused',
  WORKFLOW_RESUMED:               'WorkflowResumed',
  WORKFLOW_COMPLETED:             'WorkflowCompleted',

  // Playbook lifecycle
  PLAYBOOK_STARTED:               'PlaybookStarted',
  PLAYBOOK_COMPLETED:             'PlaybookCompleted',
  PLAYBOOK_ABORTED:               'PlaybookAborted',
  PLAYBOOK_CLONED:                'PlaybookCloned',

  // Automation lifecycle
  AUTOMATION_TRIGGERED:           'AutomationTriggered',
  AUTOMATION_STARTED:             'AutomationStarted',
  AUTOMATION_COMPLETED:           'AutomationCompleted',
  AUTOMATION_CANCELLED:           'AutomationCancelled',
  AUTOMATION_SCHEDULED:           'AutomationScheduled',

  // Rule evaluation
  RULE_MATCHED:                   'RuleMatched',
  RULE_FAILED:                    'RuleFailed',
  RULE_CONFLICT_RESOLVED:         'RuleConflictResolved',

  // Case management
  CASE_CREATED:                   'CaseCreated',
  CASE_ASSIGNED:                  'CaseAssigned',
  CASE_STARTED:                   'CaseStarted',
  CASE_RESOLVED:                  'CaseResolved',
  CASE_CLOSED:                    'CaseClosed',
  CASE_REOPENED:                  'CaseReopened',

  // Execution tracking
  EXECUTION_TRACKED:              'ExecutionTracked',
  EXECUTION_SUCCEEDED:            'ExecutionSucceeded',
  EXECUTION_FAILED:               'ExecutionFailed',

  // Shared Orchestration events
  NOTIFICATION_SENT:              'NotificationSent',
  NOTIFICATION_BROADCAST:         'NotificationBroadcast',
  NOTIFICATION_MARKED_READ:       'NotificationMarkedRead',
  ACTIVITY_LOGGED:                'ActivityLogged',
  ATTACHMENT_UPLOADED:            'AttachmentUploaded',
  ATTACHMENT_DELETED:             'AttachmentDeleted',
  COMMENT_CREATED:                'CommentCreated',
  COMMENT_UPDATED:                'CommentUpdated',
  COMMENT_DELETED:                'CommentDeleted',
  TAG_CREATED:                    'TagCreated',
  TAG_ASSIGNED:                   'TagAssigned',
  TAG_REMOVED:                    'TagRemoved',
  FAVORITE_ADDED:                 'FavoriteAdded',
  FAVORITE_REMOVED:               'FavoriteRemoved',
  FAVORITE_TOGGLED:               'FavoriteToggled',
  API_KEY_CREATED:                'ApiKeyCreated',
  API_KEY_REVOKED:                'ApiKeyRevoked',
  SETTINGS_UPDATED:               'SettingsUpdated',

  // Platform-level Orchestration events (A5.4.6)
  PLATFORM_INITIALIZED:            'PlatformInitialized',
  INVESTIGATION_PIPELINE_STARTED:  'InvestigationPipelineStarted',
  INVESTIGATION_PIPELINE_COMPLETED: 'InvestigationPipelineCompleted',
  CORRELATION_PIPELINE_STARTED:    'CorrelationPipelineStarted',
  CORRELATION_COMPLETED:           'CorrelationCompleted',
  RESPONSE_PIPELINE_STARTED:       'ResponsePipelineStarted',
  RESPONSE_COMPLETED:              'ResponseCompleted',
  REPORTING_COMPLETED:             'ReportingCompleted',
  MAINTENANCE_COMPLETED:           'MaintenanceCompleted',
  PLATFORM_HEALTH_VERIFIED:        'PlatformHealthVerified',
} as const;

export type AppEventName = (typeof APP_EVENTS)[keyof typeof APP_EVENTS];

// ─────────────────────────────────────────────────────────────────────────────
// Typed event payload interfaces
// ─────────────────────────────────────────────────────────────────────────────

export interface AppEventBase {
  correlationId: string;
  timestamp: Date;
  actor: string;
}

export interface InvestigationStartedEvent extends AppEventBase {
  investigationId: string;
  projectId: string;
  title: string;
}

export interface InvestigationClosedEvent extends AppEventBase {
  investigationId: string;
  projectId: string;
  title: string;
  closedAt: Date;
}

export interface InvestigationArchivedEvent extends AppEventBase {
  investigationId: string;
  projectId: string;
}

export interface ScanStartedEvent extends AppEventBase {
  scanId: string;
  investigationId: string;
  projectId: string;
  target: string;
  scanType: string;
}

export interface ScanCompletedEvent extends AppEventBase {
  scanId: string;
  investigationId: string;
  projectId: string;
  assetCount: number;
  findingCount: number;
  alertCount: number;
  durationMs: number;
}

export interface CaptureStartedEvent extends AppEventBase {
  captureId: string;
  investigationId: string;
  projectId: string;
  interface?: string;
}

export interface CaptureCompletedEvent extends AppEventBase {
  captureId: string;
  investigationId: string;
  projectId: string;
  packetCount: number;
  durationMs: number;
}

export interface ReportGeneratedEvent extends AppEventBase {
  reportId: string;
  investigationId: string;
  projectId: string;
  reportType: string;
}

export interface EvidenceImportedEvent extends AppEventBase {
  evidenceId: string;
  investigationId: string;
  projectId: string;
  sourceType: string;
}

export interface FindingCorrelatedEvent extends AppEventBase {
  findingId: string;
  investigationId: string;
  correlatedWith: string[];
}

export interface AlertEscalatedEvent extends AppEventBase {
  alertId: string;
  investigationId: string;
  fromSeverity: string;
  toSeverity: string;
}

// ── AI Orchestration event interfaces ────────────────────────────────────────

export interface AIConversationStartedEvent extends AppEventBase {
  conversationId: string;
  projectId: string;
  title: string;
  memoryId?: string;
  contextId?: string;
}

export interface AIConversationContinuedEvent extends AppEventBase {
  conversationId: string;
  projectId: string;
  messageId: string;
  executionId?: string;
}

export interface AIConversationClosedEvent extends AppEventBase {
  conversationId: string;
  projectId: string;
  closedAt: Date;
}

export interface AIConversationSummarizedEvent extends AppEventBase {
  conversationId: string;
  projectId: string;
  summaryLength: number;
}

export interface AIMemoryLoadedEvent extends AppEventBase {
  memoryId: string;
  conversationId: string;
  entryCount: number;
}

export interface AIMemorySavedEvent extends AppEventBase {
  memoryId: string;
  conversationId: string;
  entryCount: number;
}

export interface AIContextBuiltEvent extends AppEventBase {
  contextId: string;
  conversationId: string;
  entryCount: number;
  tokenEstimate: number;
}

export interface AIPromptBuiltEvent extends AppEventBase {
  promptId: string;
  conversationId: string;
  estimatedTokens: number;
  withinBudget: boolean;
}

export interface AIReasoningStartedEvent extends AppEventBase {
  reasoningId: string;
  projectId: string;
  investigationId: string;
}

export interface AIReasoningCompletedEvent extends AppEventBase {
  reasoningId: string;
  projectId: string;
  investigationId: string;
  overallConfidence: number;
  overallRisk: number;
  stepCount: number;
  decision: string;
}

export interface AIExecutionStartedEvent extends AppEventBase {
  executionId: string;
  providerId: string;
  providerName: string;
  projectId?: string;
}

export interface AIExecutionCompletedEvent extends AppEventBase {
  executionId: string;
  providerId: string;
  projectId?: string;
  totalTokens: number;
  estimatedCost: number;
  latencyMs: number;
}

export interface AIExecutionCancelledEvent extends AppEventBase {
  executionId: string;
  projectId?: string;
}

export interface AIStreamingStartedEvent extends AppEventBase {
  streamingId: string;
  executionId?: string;
  projectId?: string;
}

export interface AIStreamingFinishedEvent extends AppEventBase {
  streamingId: string;
  executionId?: string;
  projectId?: string;
  chunkCount: number;
  totalLength: number;
}

export interface AIProviderSelectedEvent extends AppEventBase {
  providerId: string;
  providerName: string;
  strategy: string;
  healthScore: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed publish helpers
// ─────────────────────────────────────────────────────────────────────────────

export class ApplicationEventPublisher {
  private static instance: ApplicationEventPublisher;

  private constructor() {}

  static getInstance(): ApplicationEventPublisher {
    if (!ApplicationEventPublisher.instance) {
      ApplicationEventPublisher.instance = new ApplicationEventPublisher();
    }
    return ApplicationEventPublisher.instance;
  }

  async publish(name: AppEventName, payload: Record<string, any>): Promise<void> {
    await eventPublisher.publish(name, { ...payload, _appEvent: true });
  }

  // ── Convenience typed publishers ──────────────────────────────────────────

  async investigationStarted(p: InvestigationStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_STARTED, p);
  }

  async investigationClosed(p: InvestigationClosedEvent): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_CLOSED, p);
  }

  async investigationArchived(p: InvestigationArchivedEvent): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_ARCHIVED, p);
  }

  async scanStarted(p: ScanStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.SCAN_STARTED, p);
  }

  async scanCompleted(p: ScanCompletedEvent): Promise<void> {
    await this.publish(APP_EVENTS.SCAN_COMPLETED, p);
  }

  async captureStarted(p: CaptureStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.CAPTURE_STARTED, p);
  }

  async captureCompleted(p: CaptureCompletedEvent): Promise<void> {
    await this.publish(APP_EVENTS.CAPTURE_COMPLETED, p);
  }

  async reportGenerated(p: ReportGeneratedEvent): Promise<void> {
    await this.publish(APP_EVENTS.REPORT_GENERATED, p);
  }

  async evidenceImported(p: EvidenceImportedEvent): Promise<void> {
    await this.publish(APP_EVENTS.EVIDENCE_IMPORTED, p);
  }

  async findingCorrelated(p: FindingCorrelatedEvent): Promise<void> {
    await this.publish(APP_EVENTS.FINDING_CORRELATED, p);
  }

  async alertEscalated(p: AlertEscalatedEvent): Promise<void> {
    await this.publish(APP_EVENTS.ALERT_ESCALATED, p);
  }

  // ── AI Orchestration typed publishers ────────────────────────────────────

  async aiConversationStarted(p: AIConversationStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_CONVERSATION_STARTED, p);
  }

  async aiConversationContinued(p: AIConversationContinuedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_CONVERSATION_CONTINUED, p);
  }

  async aiConversationClosed(p: AIConversationClosedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_CONVERSATION_CLOSED, p);
  }

  async aiConversationSummarized(p: AIConversationSummarizedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_CONVERSATION_SUMMARIZED, p);
  }

  async aiMemoryLoaded(p: AIMemoryLoadedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_MEMORY_LOADED, p);
  }

  async aiMemorySaved(p: AIMemorySavedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_MEMORY_SAVED, p);
  }

  async aiContextBuilt(p: AIContextBuiltEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_CONTEXT_BUILT, p);
  }

  async aiPromptBuilt(p: AIPromptBuiltEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_PROMPT_BUILT, p);
  }

  async aiReasoningStarted(p: AIReasoningStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_REASONING_STARTED, p);
  }

  async aiReasoningCompleted(p: AIReasoningCompletedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_REASONING_COMPLETED, p);
  }

  async aiExecutionStarted(p: AIExecutionStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_EXECUTION_STARTED, p);
  }

  async aiExecutionCompleted(p: AIExecutionCompletedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_EXECUTION_COMPLETED, p);
  }

  async aiExecutionCancelled(p: AIExecutionCancelledEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_EXECUTION_CANCELLED, p);
  }

  async aiStreamingStarted(p: AIStreamingStartedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_STREAMING_STARTED, p);
  }

  async aiStreamingFinished(p: AIStreamingFinishedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_STREAMING_FINISHED, p);
  }

  async aiProviderSelected(p: AIProviderSelectedEvent): Promise<void> {
    await this.publish(APP_EVENTS.AI_PROVIDER_SELECTED, p);
  }

  // ── Knowledge Orchestration typed publishers (A5.4.3) ─────────────────────

  async findingCorrelatedFull(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.FINDING_CORRELATED_FULL, p);
  }

  async assetCorrelated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.ASSET_CORRELATED, p);
  }

  async investigationKnowledgeBuilt(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_KNOWLEDGE_BUILT, p);
  }

  async threatContextBuilt(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.THREAT_CONTEXT_BUILT, p);
  }

  async threatSummaryGenerated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.THREAT_SUMMARY_GENERATED, p);
  }

  async recommendationsGenerated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RECOMMENDATIONS_GENERATED, p);
  }

  async mitreMapped(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.MITRE_MAPPED, p);
  }

  async cveCorrelated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CVE_CORRELATED, p);
  }

  async cveRiskCalculated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CVE_RISK_CALCULATED, p);
  }

  async iocEnrichedFull(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.IOC_ENRICHED_FULL, p);
  }

  async iocCorrelated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.IOC_CORRELATED, p);
  }

  async iocReputationLookedUp(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.IOC_REPUTATION_LOOKED_UP, p);
  }

  async threatActorIdentified(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.THREAT_ACTOR_IDENTIFIED, p);
  }

  async campaignMatched(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CAMPAIGN_MATCHED, p);
  }

  async threatScoreCalculated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.THREAT_SCORE_CALCULATED, p);
  }

  async knowledgeGraphUpdated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.KNOWLEDGE_GRAPH_UPDATED, p);
  }

  // ── Workflow Orchestration typed publishers (A5.4.4) ──────────────────────

  async workflowStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.WORKFLOW_STARTED, p);
  }

  async workflowPaused(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.WORKFLOW_PAUSED, p);
  }

  async workflowResumed(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.WORKFLOW_RESUMED, p);
  }

  async workflowCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.WORKFLOW_COMPLETED, p);
  }

  async playbookStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLAYBOOK_STARTED, p);
  }

  async playbookCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLAYBOOK_COMPLETED, p);
  }

  async playbookAborted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLAYBOOK_ABORTED, p);
  }

  async playbookCloned(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLAYBOOK_CLONED, p);
  }

  async automationTriggered(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.AUTOMATION_TRIGGERED, p);
  }

  async automationStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.AUTOMATION_STARTED, p);
  }

  async automationCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.AUTOMATION_COMPLETED, p);
  }

  async automationCancelled(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.AUTOMATION_CANCELLED, p);
  }

  async automationScheduled(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.AUTOMATION_SCHEDULED, p);
  }

  async ruleMatched(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RULE_MATCHED, p);
  }

  async ruleFailed(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RULE_FAILED, p);
  }

  async ruleConflictResolved(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RULE_CONFLICT_RESOLVED, p);
  }

  async caseCreated(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_CREATED, p);
  }

  async caseAssigned(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_ASSIGNED, p);
  }

  async caseStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_STARTED, p);
  }

  async caseResolved(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_RESOLVED, p);
  }

  async caseClosed(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_CLOSED, p);
  }

  async caseReopened(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CASE_REOPENED, p);
  }

  async executionTracked(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.EXECUTION_TRACKED, p);
  }

  async executionSucceeded(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.EXECUTION_SUCCEEDED, p);
  }

  async executionFailed(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.EXECUTION_FAILED, p);
  }

  // ── Platform Orchestration convenience publishers ──────────────────────────

  async platformInitialized(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLATFORM_INITIALIZED, p);
  }

  async investigationPipelineStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_PIPELINE_STARTED, p);
  }

  async investigationPipelineCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, p);
  }

  async correlationPipelineStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CORRELATION_PIPELINE_STARTED, p);
  }

  async correlationCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.CORRELATION_COMPLETED, p);
  }

  async responsePipelineStarted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RESPONSE_PIPELINE_STARTED, p);
  }

  async responseCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.RESPONSE_COMPLETED, p);
  }

  async reportingCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.REPORTING_COMPLETED, p);
  }

  async maintenanceCompleted(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.MAINTENANCE_COMPLETED, p);
  }

  async platformHealthVerified(p: AppEventBase & Record<string, any>): Promise<void> {
    await this.publish(APP_EVENTS.PLATFORM_HEALTH_VERIFIED, p);
  }
}

export const appEventPublisher = ApplicationEventPublisher.getInstance();
