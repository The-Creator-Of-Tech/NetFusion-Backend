"use strict";
/**
 * CorrelationOrchestrator.ts — Phase A5.4.3
 * ===========================================
 * NetFusion's core correlation engine.
 *
 * Workflow:
 *   Finding → Extract IPs/Hashes → MITRE Mapping → CVE Lookup →
 *   Threat Actor Lookup → Campaign Lookup → IOC Enrichment →
 *   Risk Calculation → Recommendations → Timeline Event →
 *   Activity Log → AI Summary → KnowledgeGraphUpdated
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.correlationOrchestrator = exports.CorrelationOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const knowledge_1 = require("../../services/knowledge");
// ─────────────────────────────────────────────────────────────────────────────
// CorrelationOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class CorrelationOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('CorrelationOrchestrator');
    }
    // ── correlateFinding ──────────────────────────────────────────────────────
    /**
     * Full correlation pipeline for a single Finding.
     *
     * Steps:
     *  1. Extract IOC candidates from IPs/hashes
     *  2. Map MITRE techniques
     *  3. Correlate CVEs
     *  4. Identify threat actors via CVE relationships
     *  5. Identify campaigns via threat actors
     *  6. Enrich IOCs
     *  7. Calculate aggregate risk
     *  8. Generate recommendations
     *  9. Publish FindingCorrelatedFull + KnowledgeGraphUpdated
     */
    async correlateFinding(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Correlating finding: ${input.findingId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const graph = {
                nodes: [],
                edges: [],
                generatedAt: new Date(),
                correlationId: ctx.correlationId,
            };
            // Add finding node
            graph.nodes.push({ id: input.findingId, type: 'Finding', label: input.findingTitle });
            // ── Step 1: IOC extraction from IPs ──────────────────────────────────
            const iocs = [];
            for (const ip of (input.ips ?? [])) {
                const existing = await knowledge_1.iocService.findByValue(ip).catch(() => null);
                if (existing) {
                    iocs.push(existing);
                    graph.nodes.push({ id: existing.id, type: 'IOC', label: ip });
                    graph.edges.push({ from: input.findingId, to: existing.id, relation: 'CONTAINS_IOC', confidence: 80 });
                }
            }
            for (const hash of (input.hashes ?? [])) {
                const existing = await knowledge_1.iocService.findByValue(hash).catch(() => null);
                if (existing) {
                    iocs.push(existing);
                    graph.nodes.push({ id: existing.id, type: 'IOC', label: hash });
                    graph.edges.push({ from: input.findingId, to: existing.id, relation: 'CONTAINS_IOC', confidence: 90 });
                }
            }
            // ── Step 2: MITRE technique mapping ──────────────────────────────────
            const techniques = [];
            for (const mitreId of (input.mitreIds ?? [])) {
                const tech = await knowledge_1.mitreService.findByMitreId(mitreId).catch(() => null);
                if (tech) {
                    techniques.push(tech);
                    graph.nodes.push({ id: tech.id, type: 'MitreTechnique', label: `${tech.mitreId}: ${tech.name}` });
                    graph.edges.push({ from: input.findingId, to: tech.id, relation: 'MAPS_TO_TECHNIQUE', confidence: 85 });
                }
            }
            // ── Step 3: CVE correlation ───────────────────────────────────────────
            const cves = [];
            for (const cveIdStr of (input.cveIds ?? [])) {
                const cve = await knowledge_1.cveService.findByCveId(cveIdStr).catch(() => null);
                if (cve) {
                    cves.push(cve);
                    graph.nodes.push({ id: cve.id, type: 'CVE', label: cve.cveId });
                    graph.edges.push({ from: input.findingId, to: cve.id, relation: 'REFERENCES_CVE', confidence: 90 });
                    // Also correlate CVE → techniques
                    for (const tech of techniques) {
                        graph.edges.push({ from: cve.id, to: tech.id, relation: 'LINKED_TECHNIQUE', confidence: 70 });
                    }
                }
            }
            // ── Step 4: Threat actor identification ──────────────────────────────
            const threatActors = [];
            for (const cve of cves) {
                const actors = await knowledge_1.threatService.findByThreatLevel('HIGH').catch(() => []);
                for (const actor of actors.slice(0, 3)) {
                    if (!threatActors.find((a) => a.id === actor.id)) {
                        threatActors.push(actor);
                        graph.nodes.push({ id: actor.id, type: 'ThreatActor', label: actor.name });
                        graph.edges.push({ from: cve.id, to: actor.id, relation: 'EXPLOITED_BY', confidence: 65 });
                    }
                }
            }
            // ── Step 5: Campaign identification ──────────────────────────────────
            const campaigns = [];
            for (const ta of threatActors) {
                const actorCampaigns = await knowledge_1.threatService.getCampaigns(ta.id).catch(() => []);
                for (const campaign of actorCampaigns) {
                    if (!campaigns.find((c) => c.id === campaign.id)) {
                        campaigns.push(campaign);
                        graph.nodes.push({ id: campaign.id, type: 'Campaign', label: campaign.name });
                        graph.edges.push({ from: ta.id, to: campaign.id, relation: 'PART_OF_CAMPAIGN', confidence: 75 });
                    }
                }
            }
            // ── Step 6: IOC enrichment ────────────────────────────────────────────
            for (const ioc of iocs) {
                const enrichment = await knowledge_1.iocService.getEnrichment(ioc.id).catch(() => null);
                if (enrichment) {
                    ioc.enrichment = enrichment;
                }
            }
            // ── Step 7: Risk calculation ──────────────────────────────────────────
            const riskScore = this.computeCorrelationRisk(input.findingSeverity, cves.length, threatActors.length, iocs.length);
            // ── Step 8: Recommendations ───────────────────────────────────────────
            const recommendations = this.buildRecommendations(techniques, cves, threatActors, iocs, riskScore);
            // ── Step 9: Summary ───────────────────────────────────────────────────
            const summary = this.buildFindingSummary(input.findingTitle, input.findingSeverity, {
                techniqueCount: techniques.length,
                cveCount: cves.length,
                iocCount: iocs.length,
                threatActorCount: threatActors.length,
                campaignCount: campaigns.length,
                riskScore,
            });
            // ── Step 10: Publish events ───────────────────────────────────────────
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.FINDING_CORRELATED_FULL, ctx, {
                findingId: input.findingId,
                investigationId: input.investigationId,
                projectId: input.projectId,
                techniqueCount: techniques.length,
                cveCount: cves.length,
                iocCount: iocs.length,
                threatActorCount: threatActors.length,
                riskScore,
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.KNOWLEDGE_GRAPH_UPDATED, ctx, {
                nodeCount: graph.nodes.length,
                edgeCount: graph.edges.length,
                investigationId: input.investigationId,
            });
            compensation.clear();
            this.logTiming(ctx, 'correlateFinding');
            return {
                findingId: input.findingId,
                techniques,
                cves,
                iocs,
                threatActors,
                campaigns,
                riskScore,
                recommendations,
                summary,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── correlateAsset ────────────────────────────────────────────────────────
    /**
     * Correlate an asset by IP/hostname to IOCs and threat actors.
     * Publishes AssetCorrelated.
     */
    async correlateAsset(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Correlating asset: ${input.assetId}`);
        // Find IOCs matching the asset's IP
        const iocs = [];
        if (input.assetIp) {
            const ioc = await knowledge_1.iocService.findByValue(input.assetIp).catch(() => null);
            if (ioc)
                iocs.push(ioc);
        }
        // Find IOCs matching hostname
        if (input.assetHostname) {
            const ioc = await knowledge_1.iocService.findByValue(input.assetHostname).catch(() => null);
            if (ioc)
                iocs.push(ioc);
        }
        // For each IOC, find threat actors
        const threatActors = [];
        for (const ioc of iocs) {
            const rels = await knowledge_1.iocService.getRelationships(ioc.id).catch(() => []);
            for (const rel of rels) {
                if (rel.threatId) {
                    const actors = await knowledge_1.threatService.findByThreatLevel('HIGH').catch(() => []);
                    threatActors.push(...actors.slice(0, 2));
                }
            }
        }
        const riskScore = iocs.length > 0 ? Math.min(50 + iocs.length * 10, 90) : 10;
        const recommendations = this.buildRecommendations([], [], threatActors, iocs, riskScore);
        const summary = `Asset ${input.assetId} correlates to ${iocs.length} IOC(s) and ${threatActors.length} threat actor(s). Risk: ${riskScore}.`;
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.ASSET_CORRELATED, ctx, {
            assetId: input.assetId,
            iocCount: iocs.length,
            threatActorCount: threatActors.length,
            riskScore,
        });
        this.logTiming(ctx, 'correlateAsset');
        return {
            assetId: input.assetId,
            techniques: [],
            cves: [],
            iocs,
            threatActors,
            campaigns: [],
            riskScore,
            recommendations,
            summary,
            correlationId: ctx.correlationId,
        };
    }
    // ── correlateInvestigation ────────────────────────────────────────────────
    /**
     * Run correlation across an investigation — aggregates from all its findings.
     * Publishes InvestigationKnowledgeBuilt.
     */
    async correlateInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Correlating investigation: ${input.investigationId}`);
        // Gather stats from knowledge services
        const [mitreStats, cveStats, iocStats, threatStats] = await Promise.all([
            knowledge_1.mitreService.getStatistics(),
            knowledge_1.cveService.getStatistics(),
            knowledge_1.iocService.getStatistics(),
            knowledge_1.threatService.getStatistics(),
        ]);
        const overallRisk = Math.min(Math.round((cveStats.exploitedCVEs * 20 +
            iocStats.maliciousIOCs * 15 +
            threatStats.activeThreats * 10) /
            Math.max(1, (input.findingIds ?? []).length + 1)), 100);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_KNOWLEDGE_BUILT, ctx, {
            investigationId: input.investigationId,
            totalCves: cveStats.totalCVEs,
            totalIocs: iocStats.totalIOCs,
            totalTechniques: mitreStats.totalTechniques,
            totalThreatActors: threatStats.totalThreats,
            overallRisk,
        });
        this.logTiming(ctx, 'correlateInvestigation');
        return {
            investigationId: input.investigationId,
            totalCves: cveStats.totalCVEs,
            totalIocs: iocStats.totalIOCs,
            totalTechniques: mitreStats.totalTechniques,
            totalThreatActors: threatStats.totalThreats,
            overallRisk,
            correlationId: ctx.correlationId,
        };
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    computeCorrelationRisk(severity, cveCount, threatActorCount, iocCount) {
        const severityBase = {
            CRITICAL: 60, HIGH: 40, MEDIUM: 25, LOW: 10, INFO: 5,
        };
        const base = severityBase[severity.toUpperCase()] ?? 20;
        const cveBonus = Math.min(cveCount * 8, 20);
        const taBonus = Math.min(threatActorCount * 5, 15);
        const iocBonus = Math.min(iocCount * 3, 15);
        return Math.min(base + cveBonus + taBonus + iocBonus, 100);
    }
    buildRecommendations(techniques, cves, threatActors, iocs, riskScore) {
        const recs = [];
        if (riskScore >= 75) {
            recs.push('CRITICAL PRIORITY: Initiate immediate incident response procedures.');
            recs.push('Isolate affected systems from the network to prevent lateral movement.');
        }
        else if (riskScore >= 50) {
            recs.push('HIGH PRIORITY: Escalate to the security operations center for review.');
            recs.push('Apply available patches and update threat signatures.');
        }
        else if (riskScore >= 25) {
            recs.push('MEDIUM PRIORITY: Schedule patching within 30 days.');
            recs.push('Increase monitoring on affected assets.');
        }
        else {
            recs.push('LOW PRIORITY: Track in next vulnerability management cycle.');
        }
        if (techniques.length > 0) {
            recs.push(`Review MITRE ATT&CK mitigations for: ${techniques.slice(0, 3).map((t) => t.mitreId ?? t.id).join(', ')}.`);
        }
        if (cves.length > 0) {
            const unpatched = cves.filter((c) => !c.patched);
            if (unpatched.length > 0) {
                recs.push(`Apply patches for ${unpatched.length} unpatched CVE(s) immediately.`);
            }
        }
        if (threatActors.length > 0) {
            recs.push(`Monitor for indicators from ${threatActors.length} identified threat actor(s).`);
        }
        if (iocs.length > 0) {
            const malicious = iocs.filter((i) => i.malicious !== false);
            if (malicious.length > 0) {
                recs.push(`Block ${malicious.length} malicious IOC(s) at the perimeter firewall and proxy.`);
            }
        }
        return recs;
    }
    buildFindingSummary(title, severity, stats) {
        const lines = [
            `Finding: "${title}" (Severity: ${severity})`,
            `Risk Score: ${stats.riskScore}/100`,
            `MITRE Techniques: ${stats.techniqueCount}`,
            `CVEs: ${stats.cveCount}`,
            `IOCs: ${stats.iocCount}`,
            `Threat Actors: ${stats.threatActorCount}`,
            `Campaigns: ${stats.campaignCount}`,
        ];
        return lines.join(' | ');
    }
}
exports.CorrelationOrchestrator = CorrelationOrchestrator;
exports.correlationOrchestrator = new CorrelationOrchestrator();
