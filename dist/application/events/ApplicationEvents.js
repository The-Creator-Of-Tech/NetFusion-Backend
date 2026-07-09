"use strict";
/**
 * ApplicationEvents.ts — Phase A5.4.1
 * ======================================
 * Standardised application-level event definitions and typed publisher helpers
 * for the Investigation Orchestration Layer.
 *
 * All events are published through the existing EventPublisher singleton.
 * Naming convention: <Domain><Action>  (PascalCase, past tense where possible)
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.appEventPublisher = exports.ApplicationEventPublisher = exports.APP_EVENTS = void 0;
const EventPublisher_1 = require("../../services/base/EventPublisher");
// ─────────────────────────────────────────────────────────────────────────────
// Event name constants
// ─────────────────────────────────────────────────────────────────────────────
exports.APP_EVENTS = {
    // Investigation lifecycle
    INVESTIGATION_STARTED: 'InvestigationStarted',
    INVESTIGATION_UPDATED: 'InvestigationUpdated',
    INVESTIGATION_CLOSED: 'InvestigationClosed',
    INVESTIGATION_ARCHIVED: 'InvestigationArchived',
    INVESTIGATION_DELETED: 'InvestigationDeleted',
    INVESTIGATION_STATS: 'InvestigationStatsGenerated',
    INVESTIGATION_SUMMARY: 'InvestigationSummaryGenerated',
    ASSET_LINKED: 'AssetLinkedToInvestigation',
    FINDING_LINKED: 'FindingLinkedToInvestigation',
    EVIDENCE_LINKED: 'EvidenceLinkedToInvestigation',
    // Scan workflows
    SCAN_STARTED: 'ScanStarted',
    SCAN_COMPLETED: 'ScanCompleted',
    SCAN_CANCELLED: 'ScanCancelled',
    SCAN_FAILED: 'ScanFailed',
    RESCAN_STARTED: 'RescanStarted',
    // Capture workflows
    CAPTURE_STARTED: 'CaptureStarted',
    CAPTURE_STOPPED: 'CaptureStopped',
    CAPTURE_PAUSED: 'CapturePaused',
    CAPTURE_RESUMED: 'CaptureResumed',
    CAPTURE_ANALYSED: 'CaptureAnalysed',
    CAPTURE_SAVED: 'CaptureSaved',
    CAPTURE_IMPORTED: 'CaptureImported',
    CAPTURE_EXPORTED: 'CaptureExported',
    CAPTURE_COMPLETED: 'CaptureCompleted',
    // Report workflows
    REPORT_GENERATED: 'ReportGenerated',
    EXECUTIVE_REPORT_GENERATED: 'ExecutiveReportGenerated',
    TECHNICAL_REPORT_GENERATED: 'TechnicalReportGenerated',
    REPORT_PUBLISHED: 'ReportPublished',
    REPORT_ARCHIVED: 'ReportArchived',
    REPORT_EXPORTED: 'ReportExported',
    // Cross-domain
    EVIDENCE_IMPORTED: 'EvidenceImported',
    FINDING_CORRELATED: 'FindingCorrelated',
    ALERT_ESCALATED: 'AlertEscalated',
    // AI Orchestration — conversation lifecycle
    AI_CONVERSATION_STARTED: 'AIConversationStarted',
    AI_CONVERSATION_CONTINUED: 'AIConversationContinued',
    AI_CONVERSATION_CLOSED: 'AIConversationClosed',
    AI_CONVERSATION_SUMMARIZED: 'AIConversationSummarized',
    // AI Orchestration — memory & context
    AI_MEMORY_LOADED: 'AIMemoryLoaded',
    AI_MEMORY_SAVED: 'AIMemorySaved',
    AI_CONTEXT_BUILT: 'AIContextBuilt',
    // AI Orchestration — prompt
    AI_PROMPT_BUILT: 'AIPromptBuilt',
    AI_PROMPT_OPTIMIZED: 'AIPromptOptimized',
    // AI Orchestration — reasoning
    AI_REASONING_STARTED: 'AIReasoningStarted',
    AI_REASONING_COMPLETED: 'AIReasoningCompleted',
    AI_REASONING_FAILED: 'AIReasoningFailed',
    // AI Orchestration — execution
    AI_EXECUTION_STARTED: 'AIExecutionStarted',
    AI_EXECUTION_COMPLETED: 'AIExecutionCompleted',
    AI_EXECUTION_CANCELLED: 'AIExecutionCancelled',
    AI_EXECUTION_FAILED: 'AIExecutionFailed',
    // AI Orchestration — streaming
    AI_STREAMING_STARTED: 'AIStreamingStarted',
    AI_STREAMING_FINISHED: 'AIStreamingFinished',
    AI_STREAMING_CANCELLED: 'AIStreamingCancelled',
    // AI Orchestration — provider
    AI_PROVIDER_SELECTED: 'AIProviderSelected',
    // Knowledge Orchestration (A5.4.3)
    FINDING_CORRELATED_FULL: 'FindingCorrelatedFull',
    ASSET_CORRELATED: 'AssetCorrelated',
    INVESTIGATION_KNOWLEDGE_BUILT: 'InvestigationKnowledgeBuilt',
    THREAT_CONTEXT_BUILT: 'ThreatContextBuilt',
    THREAT_SUMMARY_GENERATED: 'ThreatSummaryGenerated',
    RECOMMENDATIONS_GENERATED: 'RecommendationsGenerated',
    MITRE_MAPPED: 'MitreMapped',
    CVE_CORRELATED: 'CVECorrelated',
    CVE_RISK_CALCULATED: 'CVERiskCalculated',
    IOC_ENRICHED_FULL: 'IOCEnrichedFull',
    IOC_CORRELATED: 'IOCCorrelated',
    IOC_REPUTATION_LOOKED_UP: 'IOCReputationLookedUp',
    THREAT_ACTOR_IDENTIFIED: 'ThreatActorIdentified',
    CAMPAIGN_MATCHED: 'CampaignMatched',
    THREAT_SCORE_CALCULATED: 'ThreatScoreCalculated',
    KNOWLEDGE_GRAPH_UPDATED: 'KnowledgeGraphUpdated',
    // ── Workflow Orchestration (A5.4.4) ──────────────────────────────────────
    // Master workflow
    WORKFLOW_STARTED: 'WorkflowStarted',
    WORKFLOW_PAUSED: 'WorkflowPaused',
    WORKFLOW_RESUMED: 'WorkflowResumed',
    WORKFLOW_COMPLETED: 'WorkflowCompleted',
    // Playbook lifecycle
    PLAYBOOK_STARTED: 'PlaybookStarted',
    PLAYBOOK_COMPLETED: 'PlaybookCompleted',
    PLAYBOOK_ABORTED: 'PlaybookAborted',
    PLAYBOOK_CLONED: 'PlaybookCloned',
    // Automation lifecycle
    AUTOMATION_TRIGGERED: 'AutomationTriggered',
    AUTOMATION_STARTED: 'AutomationStarted',
    AUTOMATION_COMPLETED: 'AutomationCompleted',
    AUTOMATION_CANCELLED: 'AutomationCancelled',
    AUTOMATION_SCHEDULED: 'AutomationScheduled',
    // Rule evaluation
    RULE_MATCHED: 'RuleMatched',
    RULE_FAILED: 'RuleFailed',
    RULE_CONFLICT_RESOLVED: 'RuleConflictResolved',
    // Case management
    CASE_CREATED: 'CaseCreated',
    CASE_ASSIGNED: 'CaseAssigned',
    CASE_STARTED: 'CaseStarted',
    CASE_RESOLVED: 'CaseResolved',
    CASE_CLOSED: 'CaseClosed',
    CASE_REOPENED: 'CaseReopened',
    // Execution tracking
    EXECUTION_TRACKED: 'ExecutionTracked',
    EXECUTION_SUCCEEDED: 'ExecutionSucceeded',
    EXECUTION_FAILED: 'ExecutionFailed',
    // Shared Orchestration events
    NOTIFICATION_SENT: 'NotificationSent',
    NOTIFICATION_BROADCAST: 'NotificationBroadcast',
    NOTIFICATION_MARKED_READ: 'NotificationMarkedRead',
    ACTIVITY_LOGGED: 'ActivityLogged',
    ATTACHMENT_UPLOADED: 'AttachmentUploaded',
    ATTACHMENT_DELETED: 'AttachmentDeleted',
    COMMENT_CREATED: 'CommentCreated',
    COMMENT_UPDATED: 'CommentUpdated',
    COMMENT_DELETED: 'CommentDeleted',
    TAG_CREATED: 'TagCreated',
    TAG_ASSIGNED: 'TagAssigned',
    TAG_REMOVED: 'TagRemoved',
    FAVORITE_ADDED: 'FavoriteAdded',
    FAVORITE_REMOVED: 'FavoriteRemoved',
    FAVORITE_TOGGLED: 'FavoriteToggled',
    API_KEY_CREATED: 'ApiKeyCreated',
    API_KEY_REVOKED: 'ApiKeyRevoked',
    SETTINGS_UPDATED: 'SettingsUpdated',
    // Platform-level Orchestration events (A5.4.6)
    PLATFORM_INITIALIZED: 'PlatformInitialized',
    INVESTIGATION_PIPELINE_STARTED: 'InvestigationPipelineStarted',
    INVESTIGATION_PIPELINE_COMPLETED: 'InvestigationPipelineCompleted',
    CORRELATION_PIPELINE_STARTED: 'CorrelationPipelineStarted',
    CORRELATION_COMPLETED: 'CorrelationCompleted',
    RESPONSE_PIPELINE_STARTED: 'ResponsePipelineStarted',
    RESPONSE_COMPLETED: 'ResponseCompleted',
    REPORTING_COMPLETED: 'ReportingCompleted',
    MAINTENANCE_COMPLETED: 'MaintenanceCompleted',
    PLATFORM_HEALTH_VERIFIED: 'PlatformHealthVerified',
};
// ─────────────────────────────────────────────────────────────────────────────
// Typed publish helpers
// ─────────────────────────────────────────────────────────────────────────────
class ApplicationEventPublisher {
    constructor() { }
    static getInstance() {
        if (!ApplicationEventPublisher.instance) {
            ApplicationEventPublisher.instance = new ApplicationEventPublisher();
        }
        return ApplicationEventPublisher.instance;
    }
    async publish(name, payload) {
        await EventPublisher_1.eventPublisher.publish(name, { ...payload, _appEvent: true });
    }
    // ── Convenience typed publishers ──────────────────────────────────────────
    async investigationStarted(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_STARTED, p);
    }
    async investigationClosed(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_CLOSED, p);
    }
    async investigationArchived(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_ARCHIVED, p);
    }
    async scanStarted(p) {
        await this.publish(exports.APP_EVENTS.SCAN_STARTED, p);
    }
    async scanCompleted(p) {
        await this.publish(exports.APP_EVENTS.SCAN_COMPLETED, p);
    }
    async captureStarted(p) {
        await this.publish(exports.APP_EVENTS.CAPTURE_STARTED, p);
    }
    async captureCompleted(p) {
        await this.publish(exports.APP_EVENTS.CAPTURE_COMPLETED, p);
    }
    async reportGenerated(p) {
        await this.publish(exports.APP_EVENTS.REPORT_GENERATED, p);
    }
    async evidenceImported(p) {
        await this.publish(exports.APP_EVENTS.EVIDENCE_IMPORTED, p);
    }
    async findingCorrelated(p) {
        await this.publish(exports.APP_EVENTS.FINDING_CORRELATED, p);
    }
    async alertEscalated(p) {
        await this.publish(exports.APP_EVENTS.ALERT_ESCALATED, p);
    }
    // ── AI Orchestration typed publishers ────────────────────────────────────
    async aiConversationStarted(p) {
        await this.publish(exports.APP_EVENTS.AI_CONVERSATION_STARTED, p);
    }
    async aiConversationContinued(p) {
        await this.publish(exports.APP_EVENTS.AI_CONVERSATION_CONTINUED, p);
    }
    async aiConversationClosed(p) {
        await this.publish(exports.APP_EVENTS.AI_CONVERSATION_CLOSED, p);
    }
    async aiConversationSummarized(p) {
        await this.publish(exports.APP_EVENTS.AI_CONVERSATION_SUMMARIZED, p);
    }
    async aiMemoryLoaded(p) {
        await this.publish(exports.APP_EVENTS.AI_MEMORY_LOADED, p);
    }
    async aiMemorySaved(p) {
        await this.publish(exports.APP_EVENTS.AI_MEMORY_SAVED, p);
    }
    async aiContextBuilt(p) {
        await this.publish(exports.APP_EVENTS.AI_CONTEXT_BUILT, p);
    }
    async aiPromptBuilt(p) {
        await this.publish(exports.APP_EVENTS.AI_PROMPT_BUILT, p);
    }
    async aiReasoningStarted(p) {
        await this.publish(exports.APP_EVENTS.AI_REASONING_STARTED, p);
    }
    async aiReasoningCompleted(p) {
        await this.publish(exports.APP_EVENTS.AI_REASONING_COMPLETED, p);
    }
    async aiExecutionStarted(p) {
        await this.publish(exports.APP_EVENTS.AI_EXECUTION_STARTED, p);
    }
    async aiExecutionCompleted(p) {
        await this.publish(exports.APP_EVENTS.AI_EXECUTION_COMPLETED, p);
    }
    async aiExecutionCancelled(p) {
        await this.publish(exports.APP_EVENTS.AI_EXECUTION_CANCELLED, p);
    }
    async aiStreamingStarted(p) {
        await this.publish(exports.APP_EVENTS.AI_STREAMING_STARTED, p);
    }
    async aiStreamingFinished(p) {
        await this.publish(exports.APP_EVENTS.AI_STREAMING_FINISHED, p);
    }
    async aiProviderSelected(p) {
        await this.publish(exports.APP_EVENTS.AI_PROVIDER_SELECTED, p);
    }
    // ── Knowledge Orchestration typed publishers (A5.4.3) ─────────────────────
    async findingCorrelatedFull(p) {
        await this.publish(exports.APP_EVENTS.FINDING_CORRELATED_FULL, p);
    }
    async assetCorrelated(p) {
        await this.publish(exports.APP_EVENTS.ASSET_CORRELATED, p);
    }
    async investigationKnowledgeBuilt(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_KNOWLEDGE_BUILT, p);
    }
    async threatContextBuilt(p) {
        await this.publish(exports.APP_EVENTS.THREAT_CONTEXT_BUILT, p);
    }
    async threatSummaryGenerated(p) {
        await this.publish(exports.APP_EVENTS.THREAT_SUMMARY_GENERATED, p);
    }
    async recommendationsGenerated(p) {
        await this.publish(exports.APP_EVENTS.RECOMMENDATIONS_GENERATED, p);
    }
    async mitreMapped(p) {
        await this.publish(exports.APP_EVENTS.MITRE_MAPPED, p);
    }
    async cveCorrelated(p) {
        await this.publish(exports.APP_EVENTS.CVE_CORRELATED, p);
    }
    async cveRiskCalculated(p) {
        await this.publish(exports.APP_EVENTS.CVE_RISK_CALCULATED, p);
    }
    async iocEnrichedFull(p) {
        await this.publish(exports.APP_EVENTS.IOC_ENRICHED_FULL, p);
    }
    async iocCorrelated(p) {
        await this.publish(exports.APP_EVENTS.IOC_CORRELATED, p);
    }
    async iocReputationLookedUp(p) {
        await this.publish(exports.APP_EVENTS.IOC_REPUTATION_LOOKED_UP, p);
    }
    async threatActorIdentified(p) {
        await this.publish(exports.APP_EVENTS.THREAT_ACTOR_IDENTIFIED, p);
    }
    async campaignMatched(p) {
        await this.publish(exports.APP_EVENTS.CAMPAIGN_MATCHED, p);
    }
    async threatScoreCalculated(p) {
        await this.publish(exports.APP_EVENTS.THREAT_SCORE_CALCULATED, p);
    }
    async knowledgeGraphUpdated(p) {
        await this.publish(exports.APP_EVENTS.KNOWLEDGE_GRAPH_UPDATED, p);
    }
    // ── Workflow Orchestration typed publishers (A5.4.4) ──────────────────────
    async workflowStarted(p) {
        await this.publish(exports.APP_EVENTS.WORKFLOW_STARTED, p);
    }
    async workflowPaused(p) {
        await this.publish(exports.APP_EVENTS.WORKFLOW_PAUSED, p);
    }
    async workflowResumed(p) {
        await this.publish(exports.APP_EVENTS.WORKFLOW_RESUMED, p);
    }
    async workflowCompleted(p) {
        await this.publish(exports.APP_EVENTS.WORKFLOW_COMPLETED, p);
    }
    async playbookStarted(p) {
        await this.publish(exports.APP_EVENTS.PLAYBOOK_STARTED, p);
    }
    async playbookCompleted(p) {
        await this.publish(exports.APP_EVENTS.PLAYBOOK_COMPLETED, p);
    }
    async playbookAborted(p) {
        await this.publish(exports.APP_EVENTS.PLAYBOOK_ABORTED, p);
    }
    async playbookCloned(p) {
        await this.publish(exports.APP_EVENTS.PLAYBOOK_CLONED, p);
    }
    async automationTriggered(p) {
        await this.publish(exports.APP_EVENTS.AUTOMATION_TRIGGERED, p);
    }
    async automationStarted(p) {
        await this.publish(exports.APP_EVENTS.AUTOMATION_STARTED, p);
    }
    async automationCompleted(p) {
        await this.publish(exports.APP_EVENTS.AUTOMATION_COMPLETED, p);
    }
    async automationCancelled(p) {
        await this.publish(exports.APP_EVENTS.AUTOMATION_CANCELLED, p);
    }
    async automationScheduled(p) {
        await this.publish(exports.APP_EVENTS.AUTOMATION_SCHEDULED, p);
    }
    async ruleMatched(p) {
        await this.publish(exports.APP_EVENTS.RULE_MATCHED, p);
    }
    async ruleFailed(p) {
        await this.publish(exports.APP_EVENTS.RULE_FAILED, p);
    }
    async ruleConflictResolved(p) {
        await this.publish(exports.APP_EVENTS.RULE_CONFLICT_RESOLVED, p);
    }
    async caseCreated(p) {
        await this.publish(exports.APP_EVENTS.CASE_CREATED, p);
    }
    async caseAssigned(p) {
        await this.publish(exports.APP_EVENTS.CASE_ASSIGNED, p);
    }
    async caseStarted(p) {
        await this.publish(exports.APP_EVENTS.CASE_STARTED, p);
    }
    async caseResolved(p) {
        await this.publish(exports.APP_EVENTS.CASE_RESOLVED, p);
    }
    async caseClosed(p) {
        await this.publish(exports.APP_EVENTS.CASE_CLOSED, p);
    }
    async caseReopened(p) {
        await this.publish(exports.APP_EVENTS.CASE_REOPENED, p);
    }
    async executionTracked(p) {
        await this.publish(exports.APP_EVENTS.EXECUTION_TRACKED, p);
    }
    async executionSucceeded(p) {
        await this.publish(exports.APP_EVENTS.EXECUTION_SUCCEEDED, p);
    }
    async executionFailed(p) {
        await this.publish(exports.APP_EVENTS.EXECUTION_FAILED, p);
    }
    // ── Platform Orchestration convenience publishers ──────────────────────────
    async platformInitialized(p) {
        await this.publish(exports.APP_EVENTS.PLATFORM_INITIALIZED, p);
    }
    async investigationPipelineStarted(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_PIPELINE_STARTED, p);
    }
    async investigationPipelineCompleted(p) {
        await this.publish(exports.APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, p);
    }
    async correlationPipelineStarted(p) {
        await this.publish(exports.APP_EVENTS.CORRELATION_PIPELINE_STARTED, p);
    }
    async correlationCompleted(p) {
        await this.publish(exports.APP_EVENTS.CORRELATION_COMPLETED, p);
    }
    async responsePipelineStarted(p) {
        await this.publish(exports.APP_EVENTS.RESPONSE_PIPELINE_STARTED, p);
    }
    async responseCompleted(p) {
        await this.publish(exports.APP_EVENTS.RESPONSE_COMPLETED, p);
    }
    async reportingCompleted(p) {
        await this.publish(exports.APP_EVENTS.REPORTING_COMPLETED, p);
    }
    async maintenanceCompleted(p) {
        await this.publish(exports.APP_EVENTS.MAINTENANCE_COMPLETED, p);
    }
    async platformHealthVerified(p) {
        await this.publish(exports.APP_EVENTS.PLATFORM_HEALTH_VERIFIED, p);
    }
}
exports.ApplicationEventPublisher = ApplicationEventPublisher;
exports.appEventPublisher = ApplicationEventPublisher.getInstance();
