"use strict";
/**
 * ThreatOrchestrator.ts — Phase A5.4.3
 * ========================================
 * Orchestrates threat actor and campaign identification, technique/IOC/CVE association,
 * and threat scoring workflows.
 *
 * Responsibilities
 * ----------------
 * - Identify threat actors by name, severity, status
 * - Identify and match campaigns
 * - Associate MITRE techniques with threat actors
 * - Associate IOCs with threat actors
 * - Associate CVEs with threat actors (via relationships)
 * - Calculate threat scores for actors and campaigns
 * - Publish ThreatActorIdentified / CampaignMatched / ThreatScoreCalculated events
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.threatOrchestrator = exports.ThreatOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const knowledge_1 = require("../../services/knowledge");
// ─────────────────────────────────────────────────────────────────────────────
// ThreatOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ThreatOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ThreatOrchestrator');
    }
    // ── identifyThreatActor ───────────────────────────────────────────────────
    /**
     * Identify threat actors by name, alias, or severity.
     * Publishes ThreatActorIdentified when actors are found.
     */
    async identifyThreatActor(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Identifying threat actors: name=${input.name ?? 'N/A'} severity=${input.severity ?? 'N/A'}`);
        let actors = [];
        if (input.name) {
            actors = await knowledge_1.threatService.findByActor(input.name);
        }
        else if (input.severity) {
            actors = await knowledge_1.threatService.findByThreatLevel(input.severity);
        }
        else if (input.threatActorId) {
            this.validateUuid(input.threatActorId, 'threatActorId', ctx);
            // Get score to verify existence
            const score = await knowledge_1.threatService.calculateThreatScore(input.threatActorId);
            actors = score >= 0 ? [{ id: input.threatActorId, score }] : [];
        }
        else {
            throw new BaseApplicationService_1.OrchestrationValidationError('At least one of name, severity, or threatActorId must be provided.', ctx.correlationId);
        }
        if (actors.length > 0) {
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.THREAT_ACTOR_IDENTIFIED, ctx, {
                actorCount: actors.length,
                identifiedBy: input.name ? 'name' : input.severity ? 'severity' : 'id',
            });
        }
        this.logTiming(ctx, 'identifyThreatActor');
        return {
            actors,
            totalFound: actors.length,
            correlationId: ctx.correlationId,
        };
    }
    // ── identifyCampaign ──────────────────────────────────────────────────────
    /**
     * Identify campaigns associated with a threat actor.
     * Publishes CampaignMatched when campaigns are found.
     */
    async identifyCampaign(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.threatActorId, 'threatActorId', ctx);
        this.logInfo(ctx, `Identifying campaigns for threat actor: ${input.threatActorId}`);
        const campaigns = await knowledge_1.threatService.getCampaigns(input.threatActorId);
        if (campaigns.length > 0) {
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAMPAIGN_MATCHED, ctx, {
                threatActorId: input.threatActorId,
                campaignCount: campaigns.length,
                campaignIds: campaigns.map((c) => c.id),
            });
        }
        this.logTiming(ctx, 'identifyCampaign');
        return { campaigns, correlationId: ctx.correlationId };
    }
    // ── associateTechniques ───────────────────────────────────────────────────
    /**
     * Link MITRE techniques to a threat actor.
     */
    async associateTechniques(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.threatActorId, 'threatActorId', ctx);
        if (!input.techniqueIds || input.techniqueIds.length === 0) {
            throw new BaseApplicationService_1.OrchestrationValidationError('techniqueIds must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Associating ${input.techniqueIds.length} technique(s) with ThreatActor ${input.threatActorId}`);
        await knowledge_1.threatService.linkTechniques(input.threatActorId, input.techniqueIds, input.actor);
        this.logTiming(ctx, 'associateTechniques');
        return {
            threatActorId: input.threatActorId,
            techniqueIds: input.techniqueIds,
            correlationId: ctx.correlationId,
        };
    }
    // ── associateIOCs ─────────────────────────────────────────────────────────
    /**
     * Link IOCs to a threat actor.
     */
    async associateIOCs(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.threatActorId, 'threatActorId', ctx);
        if (!input.iocIds || input.iocIds.length === 0) {
            throw new BaseApplicationService_1.OrchestrationValidationError('iocIds must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Associating ${input.iocIds.length} IOC(s) with ThreatActor ${input.threatActorId}`);
        await knowledge_1.threatService.linkIocs(input.threatActorId, input.iocIds, input.actor);
        this.logTiming(ctx, 'associateIOCs');
        return {
            threatActorId: input.threatActorId,
            iocIds: input.iocIds,
            correlationId: ctx.correlationId,
        };
    }
    // ── associateCVEs ─────────────────────────────────────────────────────────
    /**
     * Associate CVEs with a threat actor via ThreatRelationship records.
     */
    async associateCVEs(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.threatActorId, 'threatActorId', ctx);
        if (!input.cveIds || input.cveIds.length === 0) {
            throw new BaseApplicationService_1.OrchestrationValidationError('cveIds must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Associating ${input.cveIds.length} CVE(s) with ThreatActor ${input.threatActorId}`);
        const failed = [];
        let linkedCount = 0;
        for (const cveId of input.cveIds) {
            try {
                this.validateUuid(cveId, 'cveId', ctx);
                await knowledge_1.threatService.addRelationship({
                    threatId: input.threatActorId,
                    cveId,
                    targetType: 'CVE',
                    relationType: 'EXPLOITS',
                    confidence: 75,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                linkedCount++;
            }
            catch (e) {
                failed.push(cveId);
            }
        }
        this.logTiming(ctx, 'associateCVEs');
        return {
            threatActorId: input.threatActorId,
            linkedCount,
            failed,
            correlationId: ctx.correlationId,
        };
    }
    // ── calculateThreatScore ──────────────────────────────────────────────────
    /**
     * Calculate threat score (0–100) for a threat actor.
     * Publishes ThreatScoreCalculated.
     */
    async calculateThreatScore(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.threatActorId, 'threatActorId', ctx);
        this.logInfo(ctx, `Calculating threat score for: ${input.threatActorId}`);
        const score = await knowledge_1.threatService.calculateThreatScore(input.threatActorId);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.THREAT_SCORE_CALCULATED, ctx, {
            threatActorId: input.threatActorId,
            score,
        });
        this.logTiming(ctx, 'calculateThreatScore');
        return { threatActorId: input.threatActorId, score, correlationId: ctx.correlationId };
    }
    // ── getTechniques ─────────────────────────────────────────────────────────
    async getTechniques(threatActorId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(threatActorId, 'threatActorId', ctx);
        return knowledge_1.threatService.getTechniques(threatActorId);
    }
    // ── getAssociatedIOCs ─────────────────────────────────────────────────────
    async getAssociatedIOCs(threatActorId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(threatActorId, 'threatActorId', ctx);
        return knowledge_1.threatService.getAssociatedIocs(threatActorId);
    }
    // ── getAssociatedCVEs ─────────────────────────────────────────────────────
    async getAssociatedCVEs(threatActorId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(threatActorId, 'threatActorId', ctx);
        return knowledge_1.threatService.getAssociatedCves(threatActorId);
    }
    // ── getStatistics ─────────────────────────────────────────────────────────
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return knowledge_1.threatService.getStatistics();
    }
}
exports.ThreatOrchestrator = ThreatOrchestrator;
exports.threatOrchestrator = new ThreatOrchestrator();
