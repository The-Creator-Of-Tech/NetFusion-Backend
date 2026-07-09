"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionOrchestrator = exports.caseFlowOrchestrator = exports.CaseFlowOrchestrator = exports.automationOrchestrator = exports.AutomationOrchestrator = exports.ruleOrchestrator = exports.RuleOrchestrator = exports.playbookOrchestrator = exports.PlaybookOrchestrator = exports.workflowOrchestrator = exports.WorkflowOrchestrator = exports.correlationOrchestrator = exports.CorrelationOrchestrator = exports.threatOrchestrator = exports.ThreatOrchestrator = exports.iocOrchestrator = exports.IocOrchestrator = exports.cveOrchestrator = exports.CveOrchestrator = exports.mitreOrchestrator = exports.MitreOrchestrator = exports.knowledgeOrchestrator = exports.KnowledgeOrchestrator = exports.streamingOrchestrator = exports.StreamingOrchestrator = exports.reasoningOrchestrator = exports.ReasoningOrchestrator = exports.promptOrchestrator = exports.PromptOrchestrator = exports.conversationOrchestrator = exports.ConversationOrchestrator = exports.aiOrchestrator = exports.AIOrchestrator = exports.reportOrchestrator = exports.ReportOrchestrator = exports.captureOrchestrator = exports.CaptureOrchestrator = exports.scanOrchestrator = exports.ScanOrchestrator = exports.investigationOrchestrator = exports.InvestigationOrchestrator = exports.appEventPublisher = exports.ApplicationEventPublisher = exports.APP_EVENTS = exports.OrchestrationNotFoundError = exports.OrchestrationValidationError = exports.OrchestrationError = exports.CompensatingRegistry = exports.createOperationContext = exports.BaseApplicationService = void 0;
exports.maintenancePipeline = exports.MaintenancePipeline = exports.reportingPipeline = exports.ReportingPipeline = exports.responsePipeline = exports.ResponsePipeline = exports.correlationPipeline = exports.CorrelationPipeline = exports.investigationPipeline = exports.InvestigationPipeline = exports.platformOrchestrator = exports.PlatformOrchestrator = exports.sharedOrchestrator = exports.SharedOrchestrator = exports.settingsOrchestrator = exports.SettingsOrchestrator = exports.apiKeyOrchestrator = exports.ApiKeyOrchestrator = exports.favoriteOrchestrator = exports.FavoriteOrchestrator = exports.tagOrchestrator = exports.TagOrchestrator = exports.commentOrchestrator = exports.CommentOrchestrator = exports.attachmentOrchestrator = exports.AttachmentOrchestrator = exports.activityOrchestrator = exports.ActivityOrchestrator = exports.notificationOrchestrator = exports.NotificationOrchestrator = exports.executionOrchestrator = void 0;
// ── Base ──────────────────────────────────────────────────────────────────────
var BaseApplicationService_1 = require("./base/BaseApplicationService");
Object.defineProperty(exports, "BaseApplicationService", { enumerable: true, get: function () { return BaseApplicationService_1.BaseApplicationService; } });
Object.defineProperty(exports, "createOperationContext", { enumerable: true, get: function () { return BaseApplicationService_1.createOperationContext; } });
Object.defineProperty(exports, "CompensatingRegistry", { enumerable: true, get: function () { return BaseApplicationService_1.CompensatingRegistry; } });
Object.defineProperty(exports, "OrchestrationError", { enumerable: true, get: function () { return BaseApplicationService_1.OrchestrationError; } });
Object.defineProperty(exports, "OrchestrationValidationError", { enumerable: true, get: function () { return BaseApplicationService_1.OrchestrationValidationError; } });
Object.defineProperty(exports, "OrchestrationNotFoundError", { enumerable: true, get: function () { return BaseApplicationService_1.OrchestrationNotFoundError; } });
// ── Events ────────────────────────────────────────────────────────────────────
var ApplicationEvents_1 = require("./events/ApplicationEvents");
Object.defineProperty(exports, "APP_EVENTS", { enumerable: true, get: function () { return ApplicationEvents_1.APP_EVENTS; } });
Object.defineProperty(exports, "ApplicationEventPublisher", { enumerable: true, get: function () { return ApplicationEvents_1.ApplicationEventPublisher; } });
Object.defineProperty(exports, "appEventPublisher", { enumerable: true, get: function () { return ApplicationEvents_1.appEventPublisher; } });
// ── Orchestrators ─────────────────────────────────────────────────────────────
var InvestigationOrchestrator_1 = require("./investigation/InvestigationOrchestrator");
Object.defineProperty(exports, "InvestigationOrchestrator", { enumerable: true, get: function () { return InvestigationOrchestrator_1.InvestigationOrchestrator; } });
Object.defineProperty(exports, "investigationOrchestrator", { enumerable: true, get: function () { return InvestigationOrchestrator_1.investigationOrchestrator; } });
var ScanOrchestrator_1 = require("./investigation/ScanOrchestrator");
Object.defineProperty(exports, "ScanOrchestrator", { enumerable: true, get: function () { return ScanOrchestrator_1.ScanOrchestrator; } });
Object.defineProperty(exports, "scanOrchestrator", { enumerable: true, get: function () { return ScanOrchestrator_1.scanOrchestrator; } });
var CaptureOrchestrator_1 = require("./investigation/CaptureOrchestrator");
Object.defineProperty(exports, "CaptureOrchestrator", { enumerable: true, get: function () { return CaptureOrchestrator_1.CaptureOrchestrator; } });
Object.defineProperty(exports, "captureOrchestrator", { enumerable: true, get: function () { return CaptureOrchestrator_1.captureOrchestrator; } });
var ReportOrchestrator_1 = require("./investigation/ReportOrchestrator");
Object.defineProperty(exports, "ReportOrchestrator", { enumerable: true, get: function () { return ReportOrchestrator_1.ReportOrchestrator; } });
Object.defineProperty(exports, "reportOrchestrator", { enumerable: true, get: function () { return ReportOrchestrator_1.reportOrchestrator; } });
// ── AI Orchestrators (A5.4.2) ─────────────────────────────────────────────────
var ai_1 = require("./ai");
Object.defineProperty(exports, "AIOrchestrator", { enumerable: true, get: function () { return ai_1.AIOrchestrator; } });
Object.defineProperty(exports, "aiOrchestrator", { enumerable: true, get: function () { return ai_1.aiOrchestrator; } });
Object.defineProperty(exports, "ConversationOrchestrator", { enumerable: true, get: function () { return ai_1.ConversationOrchestrator; } });
Object.defineProperty(exports, "conversationOrchestrator", { enumerable: true, get: function () { return ai_1.conversationOrchestrator; } });
Object.defineProperty(exports, "PromptOrchestrator", { enumerable: true, get: function () { return ai_1.PromptOrchestrator; } });
Object.defineProperty(exports, "promptOrchestrator", { enumerable: true, get: function () { return ai_1.promptOrchestrator; } });
Object.defineProperty(exports, "ReasoningOrchestrator", { enumerable: true, get: function () { return ai_1.ReasoningOrchestrator; } });
Object.defineProperty(exports, "reasoningOrchestrator", { enumerable: true, get: function () { return ai_1.reasoningOrchestrator; } });
Object.defineProperty(exports, "StreamingOrchestrator", { enumerable: true, get: function () { return ai_1.StreamingOrchestrator; } });
Object.defineProperty(exports, "streamingOrchestrator", { enumerable: true, get: function () { return ai_1.streamingOrchestrator; } });
// ── Knowledge Orchestrators (A5.4.3) ──────────────────────────────────────────
var knowledge_1 = require("./knowledge");
Object.defineProperty(exports, "KnowledgeOrchestrator", { enumerable: true, get: function () { return knowledge_1.KnowledgeOrchestrator; } });
Object.defineProperty(exports, "knowledgeOrchestrator", { enumerable: true, get: function () { return knowledge_1.knowledgeOrchestrator; } });
Object.defineProperty(exports, "MitreOrchestrator", { enumerable: true, get: function () { return knowledge_1.MitreOrchestrator; } });
Object.defineProperty(exports, "mitreOrchestrator", { enumerable: true, get: function () { return knowledge_1.mitreOrchestrator; } });
Object.defineProperty(exports, "CveOrchestrator", { enumerable: true, get: function () { return knowledge_1.CveOrchestrator; } });
Object.defineProperty(exports, "cveOrchestrator", { enumerable: true, get: function () { return knowledge_1.cveOrchestrator; } });
Object.defineProperty(exports, "IocOrchestrator", { enumerable: true, get: function () { return knowledge_1.IocOrchestrator; } });
Object.defineProperty(exports, "iocOrchestrator", { enumerable: true, get: function () { return knowledge_1.iocOrchestrator; } });
Object.defineProperty(exports, "ThreatOrchestrator", { enumerable: true, get: function () { return knowledge_1.ThreatOrchestrator; } });
Object.defineProperty(exports, "threatOrchestrator", { enumerable: true, get: function () { return knowledge_1.threatOrchestrator; } });
Object.defineProperty(exports, "CorrelationOrchestrator", { enumerable: true, get: function () { return knowledge_1.CorrelationOrchestrator; } });
Object.defineProperty(exports, "correlationOrchestrator", { enumerable: true, get: function () { return knowledge_1.correlationOrchestrator; } });
// ── Workflow Orchestrators (A5.4.4) ───────────────────────────────────────────
var workflow_1 = require("./workflow");
Object.defineProperty(exports, "WorkflowOrchestrator", { enumerable: true, get: function () { return workflow_1.WorkflowOrchestrator; } });
Object.defineProperty(exports, "workflowOrchestrator", { enumerable: true, get: function () { return workflow_1.workflowOrchestrator; } });
Object.defineProperty(exports, "PlaybookOrchestrator", { enumerable: true, get: function () { return workflow_1.PlaybookOrchestrator; } });
Object.defineProperty(exports, "playbookOrchestrator", { enumerable: true, get: function () { return workflow_1.playbookOrchestrator; } });
Object.defineProperty(exports, "RuleOrchestrator", { enumerable: true, get: function () { return workflow_1.RuleOrchestrator; } });
Object.defineProperty(exports, "ruleOrchestrator", { enumerable: true, get: function () { return workflow_1.ruleOrchestrator; } });
Object.defineProperty(exports, "AutomationOrchestrator", { enumerable: true, get: function () { return workflow_1.AutomationOrchestrator; } });
Object.defineProperty(exports, "automationOrchestrator", { enumerable: true, get: function () { return workflow_1.automationOrchestrator; } });
Object.defineProperty(exports, "CaseFlowOrchestrator", { enumerable: true, get: function () { return workflow_1.CaseFlowOrchestrator; } });
Object.defineProperty(exports, "caseFlowOrchestrator", { enumerable: true, get: function () { return workflow_1.caseFlowOrchestrator; } });
Object.defineProperty(exports, "ExecutionOrchestrator", { enumerable: true, get: function () { return workflow_1.ExecutionOrchestrator; } });
Object.defineProperty(exports, "executionOrchestrator", { enumerable: true, get: function () { return workflow_1.executionOrchestrator; } });
// ── Shared Orchestrators (A5.4.5) ─────────────────────────────────────────────
var shared_1 = require("./shared");
Object.defineProperty(exports, "NotificationOrchestrator", { enumerable: true, get: function () { return shared_1.NotificationOrchestrator; } });
Object.defineProperty(exports, "notificationOrchestrator", { enumerable: true, get: function () { return shared_1.notificationOrchestrator; } });
Object.defineProperty(exports, "ActivityOrchestrator", { enumerable: true, get: function () { return shared_1.ActivityOrchestrator; } });
Object.defineProperty(exports, "activityOrchestrator", { enumerable: true, get: function () { return shared_1.activityOrchestrator; } });
Object.defineProperty(exports, "AttachmentOrchestrator", { enumerable: true, get: function () { return shared_1.AttachmentOrchestrator; } });
Object.defineProperty(exports, "attachmentOrchestrator", { enumerable: true, get: function () { return shared_1.attachmentOrchestrator; } });
Object.defineProperty(exports, "CommentOrchestrator", { enumerable: true, get: function () { return shared_1.CommentOrchestrator; } });
Object.defineProperty(exports, "commentOrchestrator", { enumerable: true, get: function () { return shared_1.commentOrchestrator; } });
Object.defineProperty(exports, "TagOrchestrator", { enumerable: true, get: function () { return shared_1.TagOrchestrator; } });
Object.defineProperty(exports, "tagOrchestrator", { enumerable: true, get: function () { return shared_1.tagOrchestrator; } });
Object.defineProperty(exports, "FavoriteOrchestrator", { enumerable: true, get: function () { return shared_1.FavoriteOrchestrator; } });
Object.defineProperty(exports, "favoriteOrchestrator", { enumerable: true, get: function () { return shared_1.favoriteOrchestrator; } });
Object.defineProperty(exports, "ApiKeyOrchestrator", { enumerable: true, get: function () { return shared_1.ApiKeyOrchestrator; } });
Object.defineProperty(exports, "apiKeyOrchestrator", { enumerable: true, get: function () { return shared_1.apiKeyOrchestrator; } });
Object.defineProperty(exports, "SettingsOrchestrator", { enumerable: true, get: function () { return shared_1.SettingsOrchestrator; } });
Object.defineProperty(exports, "settingsOrchestrator", { enumerable: true, get: function () { return shared_1.settingsOrchestrator; } });
Object.defineProperty(exports, "SharedOrchestrator", { enumerable: true, get: function () { return shared_1.SharedOrchestrator; } });
Object.defineProperty(exports, "sharedOrchestrator", { enumerable: true, get: function () { return shared_1.sharedOrchestrator; } });
// ── Platform Orchestrators (A5.4.6) ───────────────────────────────────────────
var platform_1 = require("./platform");
Object.defineProperty(exports, "PlatformOrchestrator", { enumerable: true, get: function () { return platform_1.PlatformOrchestrator; } });
Object.defineProperty(exports, "platformOrchestrator", { enumerable: true, get: function () { return platform_1.platformOrchestrator; } });
Object.defineProperty(exports, "InvestigationPipeline", { enumerable: true, get: function () { return platform_1.InvestigationPipeline; } });
Object.defineProperty(exports, "investigationPipeline", { enumerable: true, get: function () { return platform_1.investigationPipeline; } });
Object.defineProperty(exports, "CorrelationPipeline", { enumerable: true, get: function () { return platform_1.CorrelationPipeline; } });
Object.defineProperty(exports, "correlationPipeline", { enumerable: true, get: function () { return platform_1.correlationPipeline; } });
Object.defineProperty(exports, "ResponsePipeline", { enumerable: true, get: function () { return platform_1.ResponsePipeline; } });
Object.defineProperty(exports, "responsePipeline", { enumerable: true, get: function () { return platform_1.responsePipeline; } });
Object.defineProperty(exports, "ReportingPipeline", { enumerable: true, get: function () { return platform_1.ReportingPipeline; } });
Object.defineProperty(exports, "reportingPipeline", { enumerable: true, get: function () { return platform_1.reportingPipeline; } });
Object.defineProperty(exports, "MaintenancePipeline", { enumerable: true, get: function () { return platform_1.MaintenancePipeline; } });
Object.defineProperty(exports, "maintenancePipeline", { enumerable: true, get: function () { return platform_1.maintenancePipeline; } });
