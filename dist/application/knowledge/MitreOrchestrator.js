"use strict";
/**
 * MitreOrchestrator.ts — Phase A5.4.3
 * ======================================
 * Orchestrates MITRE ATT&CK correlations and technique workflows.
 *
 * Responsibilities
 * ----------------
 * - Map findings/IOCs/CVEs to MITRE techniques and tactics
 * - Find mitigations and detections for techniques
 * - Find related techniques (siblings, sub-techniques, parent)
 * - Aggregate tactic-level risk
 * - Publish knowledge-graph events
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.mitreOrchestrator = exports.MitreOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const knowledge_1 = require("../../services/knowledge");
// ─────────────────────────────────────────────────────────────────────────────
// MitreOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class MitreOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('MitreOrchestrator');
    }
    // ── mapTechnique ──────────────────────────────────────────────────────────
    /**
     * Fully map a MITRE technique: fetch details, mitigations, related techniques.
     * Publishes MitreMapped.
     */
    async mapTechnique(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Mapping MITRE technique: ${input.mitreId}`);
        const technique = await knowledge_1.mitreService.findByMitreId(input.mitreId);
        if (!technique) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('MitreTechnique', input.mitreId, ctx.correlationId);
        }
        const [mitigations, subTechniques, detectionRules] = await Promise.all([
            knowledge_1.mitreService.findMitigations(technique.id),
            knowledge_1.mitreService.findSubTechniques(input.mitreId),
            knowledge_1.mitreService.findDetectionRules(technique.id),
        ]);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MITRE_MAPPED, ctx, {
            techniqueId: technique.id,
            mitreId: technique.mitreId,
            mitigationCount: mitigations.length,
            detectionCount: detectionRules.length,
        });
        this.logTiming(ctx, 'mapTechnique');
        return {
            techniqueId: technique.id,
            mitreId: technique.mitreId,
            name: technique.name,
            severity: String(technique.severity),
            tactic: technique.tacticId ?? null,
            mitigations,
            relatedTechniques: subTechniques,
            correlationId: ctx.correlationId,
        };
    }
    // ── mapTactic ─────────────────────────────────────────────────────────────
    /**
     * Map a tactic: retrieve all its techniques and aggregate risk score.
     */
    async mapTactic(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.tacticId, 'tacticId', ctx);
        this.logInfo(ctx, `Mapping MITRE tactic: ${input.tacticId}`);
        const [techniques, risk] = await Promise.all([
            knowledge_1.mitreService.findByTactic(input.tacticId),
            knowledge_1.mitreService.aggregateTacticRisk(input.tacticId),
        ]);
        this.logTiming(ctx, 'mapTactic');
        return {
            tacticId: input.tacticId,
            techniques,
            aggregateRisk: risk,
            correlationId: ctx.correlationId,
        };
    }
    // ── findMitigations ───────────────────────────────────────────────────────
    /**
     * Retrieve all mitigations for a technique (by UUID).
     */
    async findMitigations(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.techniqueId, 'techniqueId', ctx);
        this.logInfo(ctx, `Finding mitigations for technique: ${input.techniqueId}`);
        const mitigations = await knowledge_1.mitreService.findMitigations(input.techniqueId);
        this.logTiming(ctx, 'findMitigations');
        return mitigations;
    }
    // ── findDetections ────────────────────────────────────────────────────────
    /**
     * Retrieve detection rules targeting a technique (by UUID).
     */
    async findDetections(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.techniqueId, 'techniqueId', ctx);
        this.logInfo(ctx, `Finding detections for technique: ${input.techniqueId}`);
        const rules = await knowledge_1.mitreService.findDetectionRules(input.techniqueId);
        this.logTiming(ctx, 'findDetections');
        return rules;
    }
    // ── findRelatedTechniques ─────────────────────────────────────────────────
    /**
     * Find related techniques: sub-techniques and optionally sibling parent.
     */
    async findRelatedTechniques(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Finding related techniques for: ${input.mitreId}`);
        const [subTechniques, parent] = await Promise.all([
            knowledge_1.mitreService.findSubTechniques(input.mitreId),
            knowledge_1.mitreService.findParentTechnique(input.mitreId),
        ]);
        this.logTiming(ctx, 'findRelatedTechniques');
        return {
            subTechniques,
            parent,
            correlationId: ctx.correlationId,
        };
    }
    // ── correlateToCve ────────────────────────────────────────────────────────
    /**
     * Find MITRE techniques correlated to a specific CVE.
     */
    async correlateToCve(cveId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(cveId, 'cveId', ctx);
        this.logInfo(ctx, `Correlating techniques to CVE: ${cveId}`);
        const techniques = await knowledge_1.mitreService.correlateToCve(cveId);
        this.logTiming(ctx, 'correlateToCve');
        return techniques;
    }
    // ── correlateToThreatActor ────────────────────────────────────────────────
    /**
     * Find MITRE techniques correlated to a ThreatActor.
     */
    async correlateToThreatActor(threatActorId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(threatActorId, 'threatActorId', ctx);
        this.logInfo(ctx, `Correlating techniques to ThreatActor: ${threatActorId}`);
        const techniques = await knowledge_1.mitreService.correlateToThreatActor(threatActorId);
        this.logTiming(ctx, 'correlateToThreatActor');
        return techniques;
    }
    // ── getStatistics ─────────────────────────────────────────────────────────
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return knowledge_1.mitreService.getStatistics();
    }
}
exports.MitreOrchestrator = MitreOrchestrator;
exports.mitreOrchestrator = new MitreOrchestrator();
