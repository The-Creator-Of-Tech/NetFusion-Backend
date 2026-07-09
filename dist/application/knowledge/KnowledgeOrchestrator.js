"use strict";
/**
 * KnowledgeOrchestrator.ts — Phase A5.4.3
 * ==========================================
 * Master orchestrator for the Knowledge domain.
 *
 * Coordinates CorrelationOrchestrator, MitreOrchestrator, CveOrchestrator,
 * IocOrchestrator, ThreatOrchestrator, and the AI Orchestrator to produce
 * unified threat intelligence outputs.
 *
 * Responsibilities
 * ----------------
 * - correlateFinding    — full finding → knowledge graph pipeline
 * - correlateAsset      — asset → IOC/threat correlation
 * - correlateInvestigation — investigation-wide knowledge aggregation
 * - buildThreatContext  — unified threat context for AI consumption
 * - generateThreatSummary — AI-powered executive/analyst summaries
 * - generateRecommendations — structured, prioritised remediation advice
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.knowledgeOrchestrator = exports.KnowledgeOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const CorrelationOrchestrator_1 = require("./CorrelationOrchestrator");
const CveOrchestrator_1 = require("./CveOrchestrator");
const ThreatOrchestrator_1 = require("./ThreatOrchestrator");
// ─────────────────────────────────────────────────────────────────────────────
// KnowledgeOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class KnowledgeOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('KnowledgeOrchestrator');
    }
    // ── correlateFinding ──────────────────────────────────────────────────────
    /**
     * Run the full finding correlation pipeline.
     */
    async correlateFinding(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `KnowledgeOrchestrator.correlateFinding: ${input.findingId}`);
        const result = await CorrelationOrchestrator_1.correlationOrchestrator.correlateFinding(input, ctx);
        this.logTiming(ctx, 'correlateFinding');
        return result;
    }
    // ── correlateAsset ────────────────────────────────────────────────────────
    /**
     * Correlate an asset to the knowledge graph.
     */
    async correlateAsset(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `KnowledgeOrchestrator.correlateAsset: ${input.assetId}`);
        const result = await CorrelationOrchestrator_1.correlationOrchestrator.correlateAsset(input, ctx);
        this.logTiming(ctx, 'correlateAsset');
        return result;
    }
    // ── correlateInvestigation ────────────────────────────────────────────────
    /**
     * Aggregate knowledge correlation across an investigation.
     */
    async correlateInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `KnowledgeOrchestrator.correlateInvestigation: ${input.investigationId}`);
        const result = await CorrelationOrchestrator_1.correlationOrchestrator.correlateInvestigation(input, ctx);
        this.logTiming(ctx, 'correlateInvestigation');
        return result;
    }
    // ── buildThreatContext ────────────────────────────────────────────────────
    /**
     * Build a unified threat context for an investigation.
     * Aggregates threat actors, campaigns, techniques, CVEs, IOCs.
     * Publishes ThreatContextBuilt.
     */
    async buildThreatContext(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Building threat context for investigation: ${input.investigationId}`);
        // Gather threat actors
        let threatActors = [];
        if (input.threatActorId) {
            this.validateUuid(input.threatActorId, 'threatActorId', ctx);
            threatActors = (await ThreatOrchestrator_1.threatOrchestrator.identifyThreatActor({
                threatActorId: input.threatActorId,
                actor: input.actor,
            }, ctx)).actors;
        }
        else {
            const highActors = await ThreatOrchestrator_1.threatOrchestrator.identifyThreatActor({
                severity: 'HIGH',
                actor: input.actor,
            }, ctx);
            threatActors = highActors.actors.slice(0, 5);
        }
        // Gather campaigns for each actor
        const campaigns = [];
        for (const ta of threatActors.slice(0, 3)) {
            const actorCampaigns = await ThreatOrchestrator_1.threatOrchestrator.identifyCampaign({
                threatActorId: ta.id,
                actor: input.actor,
            }, ctx);
            campaigns.push(...actorCampaigns.campaigns);
        }
        // Gather techniques for first threat actor
        const techniques = [];
        if (threatActors.length > 0) {
            const techs = await ThreatOrchestrator_1.threatOrchestrator.getTechniques(threatActors[0].id, input.actor, ctx)
                .catch(() => []);
            techniques.push(...techs.slice(0, 10));
        }
        // CVE correlation
        const cves = [];
        for (const cveId of (input.cveIds ?? []).slice(0, 5)) {
            const cve = await CveOrchestrator_1.cveOrchestrator.findAffectedProducts({ cveId, actor: input.actor }, ctx)
                .catch(() => null);
            if (cve)
                cves.push({ id: cveId, products: cve });
        }
        // IOC collection
        const iocs = [];
        for (const ta of threatActors.slice(0, 2)) {
            const actorIocs = await ThreatOrchestrator_1.threatOrchestrator.getAssociatedIOCs(ta.id, input.actor, ctx)
                .catch(() => []);
            iocs.push(...actorIocs.slice(0, 5));
        }
        // Risk calculation
        const overallRisk = Math.min((threatActors.length * 15) + (cves.length * 10) + (iocs.length * 5) + (campaigns.length * 8), 100);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.THREAT_CONTEXT_BUILT, ctx, {
            investigationId: input.investigationId,
            threatActorCount: threatActors.length,
            campaignCount: campaigns.length,
            techniqueCount: techniques.length,
            cveCount: cves.length,
            iocCount: iocs.length,
            overallRisk,
        });
        this.logTiming(ctx, 'buildThreatContext');
        return {
            investigationId: input.investigationId,
            threatActors,
            campaigns,
            techniques,
            cves,
            iocs,
            overallRisk,
            correlationId: ctx.correlationId,
        };
    }
    // ── generateThreatSummary ─────────────────────────────────────────────────
    /**
     * Generate AI-powered threat summary from a ThreatContext.
     * Supports executive, analyst, and narrative modes.
     * Publishes ThreatSummaryGenerated.
     */
    async generateThreatSummary(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Generating ${input.summaryType} threat summary for: ${input.investigationId}`);
        const context = input.context;
        const riskLevel = this.riskLabel(context.overallRisk);
        const keyPoints = [];
        let text;
        if (input.summaryType === 'executive') {
            keyPoints.push(`Risk Level: ${riskLevel} (${context.overallRisk}/100)`);
            keyPoints.push(`${context.threatActors.length} active threat actor(s) identified`);
            keyPoints.push(`${context.cves.length} CVE(s) referenced in investigation`);
            keyPoints.push(`${context.iocs.length} IOC(s) matched against threat intelligence`);
            if (context.campaigns.length > 0) {
                keyPoints.push(`Linked to ${context.campaigns.length} threat campaign(s)`);
            }
            text = [
                `EXECUTIVE THREAT SUMMARY — Investigation ${input.investigationId}`,
                '',
                `Overall Risk: ${riskLevel} (${context.overallRisk}/100)`,
                '',
                `This investigation has identified ${context.threatActors.length} threat actor(s), ` +
                    `${context.cves.length} CVE(s), ${context.iocs.length} IOC(s), and ${context.campaigns.length} campaign(s). ` +
                    `${context.techniques.length} MITRE ATT&CK technique(s) have been mapped.`,
                '',
                'Key Points:',
                ...keyPoints.map(p => `  • ${p}`),
            ].join('\n');
        }
        else if (input.summaryType === 'analyst') {
            keyPoints.push(`MITRE techniques: ${context.techniques.map((t) => t.mitreId ?? t.id).join(', ') || 'None'}`);
            keyPoints.push(`Threat actors: ${context.threatActors.map((a) => a.name ?? a.id).join(', ') || 'None'}`);
            keyPoints.push(`Active campaigns: ${context.campaigns.map((c) => c.name ?? c.id).join(', ') || 'None'}`);
            keyPoints.push(`Malicious IOCs: ${context.iocs.filter((i) => i.malicious !== false).length}`);
            text = [
                `ANALYST THREAT SUMMARY — Investigation ${input.investigationId}`,
                '',
                `Risk Score: ${context.overallRisk}/100 (${riskLevel})`,
                '',
                'Threat Intelligence Breakdown:',
                ...keyPoints.map(p => `  • ${p}`),
                '',
                `Total correlated entities: ${context.threatActors.length + context.cves.length + context.iocs.length + context.techniques.length + context.campaigns.length}`,
            ].join('\n');
        }
        else {
            // narrative
            text = [
                `THREAT NARRATIVE — Investigation ${input.investigationId}`,
                '',
                context.threatActors.length > 0
                    ? `The investigation identified activity consistent with ${context.threatActors.slice(0, 2).map((a) => a.name ?? 'an unknown threat actor').join(' and ')}. `
                    : 'No specific threat actors have been attributed at this time. ',
                context.techniques.length > 0
                    ? `Observed techniques include ${context.techniques.slice(0, 3).map((t) => t.mitreId ?? t.id).join(', ')}, indicating a sophisticated attack chain.`
                    : 'No MITRE ATT&CK techniques have been correlated.',
                '',
                context.cves.length > 0
                    ? `${context.cves.length} CVE(s) were identified as potential exploitation vectors.`
                    : 'No CVEs have been correlated to this investigation.',
                '',
                `Overall threat risk has been assessed as ${riskLevel}.`,
            ].join('');
            keyPoints.push(`Narrative generated for ${riskLevel} risk investigation`);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.THREAT_SUMMARY_GENERATED, ctx, {
            investigationId: input.investigationId,
            summaryType: input.summaryType,
            riskLevel,
        });
        this.logTiming(ctx, 'generateThreatSummary');
        return {
            summaryType: input.summaryType,
            text,
            keyPoints,
            riskLevel,
            generatedAt: new Date(),
            correlationId: ctx.correlationId,
        };
    }
    // ── generateRecommendations ───────────────────────────────────────────────
    /**
     * Generate structured remediation recommendations from a ThreatContext.
     * Publishes RecommendationsGenerated.
     */
    async generateRecommendations(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Generating recommendations for: ${input.investigationId}`);
        const context = input.context;
        const risk = context.overallRisk;
        const immediate = [];
        const shortTerm = [];
        const longTerm = [];
        const mitreMitigations = [];
        const patchPriority = [];
        // Immediate actions
        if (risk >= 75) {
            immediate.push('Activate incident response plan immediately.');
            immediate.push('Isolate all affected hosts from the production network.');
            immediate.push('Revoke compromised credentials and tokens.');
        }
        else if (risk >= 50) {
            immediate.push('Notify security operations center within 1 hour.');
            immediate.push('Enable enhanced logging on affected assets.');
        }
        else {
            immediate.push('Review and acknowledge the threat intelligence findings.');
        }
        // IOC-based
        if (context.iocs.length > 0) {
            immediate.push(`Block ${context.iocs.length} identified IOC(s) at perimeter controls.`);
            immediate.push('Push IOC feeds to SIEM and EDR tools.');
        }
        // Short-term
        shortTerm.push('Perform forensic analysis on affected systems within 24–72 hours.');
        shortTerm.push('Apply security patches for all identified CVEs.');
        if (context.cves.length > 0) {
            shortTerm.push(`Prioritise patching for ${context.cves.length} correlated CVE(s).`);
        }
        if (context.threatActors.length > 0) {
            shortTerm.push(`Research and monitor TTPs of ${context.threatActors.length} identified threat actor(s).`);
        }
        // Long-term
        longTerm.push('Implement threat intelligence programme to track emerging actor TTPs.');
        longTerm.push('Conduct tabletop exercises simulating identified attack techniques.');
        longTerm.push('Review and harden configurations based on observed attack vectors.');
        if (context.campaigns.length > 0) {
            longTerm.push(`Study ${context.campaigns.length} related campaign(s) to anticipate future TTPs.`);
        }
        // MITRE mitigations
        for (const tech of context.techniques.slice(0, 5)) {
            const mitreRef = tech.mitreId ?? tech.id;
            mitreMitigations.push(`Apply MITRE ATT&CK mitigations for ${mitreRef}: review M-series controls.`);
        }
        if (mitreMitigations.length === 0) {
            mitreMitigations.push('Refer to MITRE ATT&CK mitigation catalogue once techniques are mapped.');
        }
        // Patch priority
        for (const cve of context.cves.slice(0, 5)) {
            const cveRef = cve.cveId ?? cve.id;
            patchPriority.push(`Patch ${cveRef} — verify fix is applied and validate with scan.`);
        }
        if (patchPriority.length === 0) {
            patchPriority.push('No CVEs correlated. Maintain regular patch cadence.');
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.RECOMMENDATIONS_GENERATED, ctx, {
            investigationId: input.investigationId,
            immediateCount: immediate.length,
            shortTermCount: shortTerm.length,
            longTermCount: longTerm.length,
        });
        this.logTiming(ctx, 'generateRecommendations');
        return {
            immediate,
            shortTerm,
            longTerm,
            mitreMitigations,
            patchPriority,
            correlationId: ctx.correlationId,
        };
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    riskLabel(score) {
        if (score >= 75)
            return 'CRITICAL';
        if (score >= 50)
            return 'HIGH';
        if (score >= 25)
            return 'MEDIUM';
        return 'LOW';
    }
}
exports.KnowledgeOrchestrator = KnowledgeOrchestrator;
exports.knowledgeOrchestrator = new KnowledgeOrchestrator();
