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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationValidationError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

import { correlationOrchestrator, CorrelationResult } from './CorrelationOrchestrator';
import { mitreOrchestrator } from './MitreOrchestrator';
import { cveOrchestrator } from './CveOrchestrator';
import { iocOrchestrator } from './IocOrchestrator';
import { threatOrchestrator } from './ThreatOrchestrator';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface KnowledgeCorrelateFindingInput {
  findingId: string;
  findingTitle: string;
  findingSeverity: string;
  ips?: string[];
  hashes?: string[];
  cveIds?: string[];
  mitreIds?: string[];
  projectId: string;
  investigationId: string;
  actor: string;
}

export interface KnowledgeCorrelateAssetInput {
  assetId: string;
  assetHostname?: string;
  assetIp?: string;
  projectId: string;
  investigationId: string;
  actor: string;
}

export interface KnowledgeCorrelateInvestigationInput {
  investigationId: string;
  projectId: string;
  actor: string;
  findingIds?: string[];
}

export interface ThreatContextInput {
  investigationId: string;
  projectId: string;
  actor: string;
  /** Optional threat actor UUID to focus on */
  threatActorId?: string;
  /** Optional CVE IDs for targeted context */
  cveIds?: string[];
}

export interface ThreatContext {
  investigationId: string;
  threatActors: any[];
  campaigns: any[];
  techniques: any[];
  cves: any[];
  iocs: any[];
  overallRisk: number;
  correlationId: string;
}

export interface ThreatSummaryInput {
  investigationId: string;
  projectId: string;
  actor: string;
  context: ThreatContext;
  summaryType: 'executive' | 'analyst' | 'narrative';
}

export interface ThreatSummary {
  summaryType: string;
  text: string;
  keyPoints: string[];
  riskLevel: string;
  generatedAt: Date;
  correlationId: string;
}

export interface GenerateRecommendationsInput {
  investigationId: string;
  context: ThreatContext;
  actor: string;
}

export interface RecommendationSet {
  immediate: string[];
  shortTerm: string[];
  longTerm: string[];
  mitreMitigations: string[];
  patchPriority: string[];
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// KnowledgeOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class KnowledgeOrchestrator extends BaseApplicationService {
  constructor() {
    super('KnowledgeOrchestrator');
  }

  // ── correlateFinding ──────────────────────────────────────────────────────

  /**
   * Run the full finding correlation pipeline.
   */
  async correlateFinding(
    input: KnowledgeCorrelateFindingInput,
    parentCtx?: OperationContext,
  ): Promise<CorrelationResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `KnowledgeOrchestrator.correlateFinding: ${input.findingId}`);

    const result = await correlationOrchestrator.correlateFinding(input, ctx);

    this.logTiming(ctx, 'correlateFinding');
    return result;
  }

  // ── correlateAsset ────────────────────────────────────────────────────────

  /**
   * Correlate an asset to the knowledge graph.
   */
  async correlateAsset(
    input: KnowledgeCorrelateAssetInput,
    parentCtx?: OperationContext,
  ): Promise<CorrelationResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `KnowledgeOrchestrator.correlateAsset: ${input.assetId}`);

    const result = await correlationOrchestrator.correlateAsset(input, ctx);

    this.logTiming(ctx, 'correlateAsset');
    return result;
  }

  // ── correlateInvestigation ────────────────────────────────────────────────

  /**
   * Aggregate knowledge correlation across an investigation.
   */
  async correlateInvestigation(
    input: KnowledgeCorrelateInvestigationInput,
    parentCtx?: OperationContext,
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `KnowledgeOrchestrator.correlateInvestigation: ${input.investigationId}`);

    const result = await correlationOrchestrator.correlateInvestigation(input, ctx);

    this.logTiming(ctx, 'correlateInvestigation');
    return result;
  }

  // ── buildThreatContext ────────────────────────────────────────────────────

  /**
   * Build a unified threat context for an investigation.
   * Aggregates threat actors, campaigns, techniques, CVEs, IOCs.
   * Publishes ThreatContextBuilt.
   */
  async buildThreatContext(
    input: ThreatContextInput,
    parentCtx?: OperationContext,
  ): Promise<ThreatContext> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Building threat context for investigation: ${input.investigationId}`);

    // Gather threat actors
    let threatActors: any[] = [];
    if (input.threatActorId) {
      this.validateUuid(input.threatActorId, 'threatActorId', ctx);
      threatActors = (await threatOrchestrator.identifyThreatActor({
        threatActorId: input.threatActorId,
        actor: input.actor,
      }, ctx)).actors;
    } else {
      const highActors = await threatOrchestrator.identifyThreatActor({
        severity: 'HIGH',
        actor: input.actor,
      }, ctx);
      threatActors = highActors.actors.slice(0, 5);
    }

    // Gather campaigns for each actor
    const campaigns: any[] = [];
    for (const ta of threatActors.slice(0, 3)) {
      const actorCampaigns = await threatOrchestrator.identifyCampaign({
        threatActorId: ta.id,
        actor: input.actor,
      }, ctx);
      campaigns.push(...actorCampaigns.campaigns);
    }

    // Gather techniques for first threat actor
    const techniques: any[] = [];
    if (threatActors.length > 0) {
      const techs = await threatOrchestrator.getTechniques(threatActors[0].id, input.actor, ctx)
        .catch(() => []);
      techniques.push(...techs.slice(0, 10));
    }

    // CVE correlation
    const cves: any[] = [];
    for (const cveId of (input.cveIds ?? []).slice(0, 5)) {
      const cve = await cveOrchestrator.findAffectedProducts({ cveId, actor: input.actor }, ctx)
        .catch(() => null);
      if (cve) cves.push({ id: cveId, products: cve });
    }

    // IOC collection
    const iocs: any[] = [];
    for (const ta of threatActors.slice(0, 2)) {
      const actorIocs = await threatOrchestrator.getAssociatedIOCs(ta.id, input.actor, ctx)
        .catch(() => []);
      iocs.push(...actorIocs.slice(0, 5));
    }

    // Risk calculation
    const overallRisk = Math.min(
      (threatActors.length * 15) + (cves.length * 10) + (iocs.length * 5) + (campaigns.length * 8),
      100,
    );

    await this.publishEvent(APP_EVENTS.THREAT_CONTEXT_BUILT, ctx, {
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
  async generateThreatSummary(
    input: ThreatSummaryInput,
    parentCtx?: OperationContext,
  ): Promise<ThreatSummary> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Generating ${input.summaryType} threat summary for: ${input.investigationId}`);

    const context = input.context;
    const riskLevel = this.riskLabel(context.overallRisk);
    const keyPoints: string[] = [];
    let text: string;

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

    } else if (input.summaryType === 'analyst') {
      keyPoints.push(`MITRE techniques: ${context.techniques.map((t: any) => t.mitreId ?? t.id).join(', ') || 'None'}`);
      keyPoints.push(`Threat actors: ${context.threatActors.map((a: any) => a.name ?? a.id).join(', ') || 'None'}`);
      keyPoints.push(`Active campaigns: ${context.campaigns.map((c: any) => c.name ?? c.id).join(', ') || 'None'}`);
      keyPoints.push(`Malicious IOCs: ${context.iocs.filter((i: any) => i.malicious !== false).length}`);

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

    } else {
      // narrative
      text = [
        `THREAT NARRATIVE — Investigation ${input.investigationId}`,
        '',
        context.threatActors.length > 0
          ? `The investigation identified activity consistent with ${context.threatActors.slice(0, 2).map((a: any) => a.name ?? 'an unknown threat actor').join(' and ')}. `
          : 'No specific threat actors have been attributed at this time. ',
        context.techniques.length > 0
          ? `Observed techniques include ${context.techniques.slice(0, 3).map((t: any) => t.mitreId ?? t.id).join(', ')}, indicating a sophisticated attack chain.`
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

    await this.publishEvent(APP_EVENTS.THREAT_SUMMARY_GENERATED, ctx, {
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
  async generateRecommendations(
    input: GenerateRecommendationsInput,
    parentCtx?: OperationContext,
  ): Promise<RecommendationSet> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Generating recommendations for: ${input.investigationId}`);

    const context = input.context;
    const risk = context.overallRisk;

    const immediate: string[] = [];
    const shortTerm: string[] = [];
    const longTerm: string[] = [];
    const mitreMitigations: string[] = [];
    const patchPriority: string[] = [];

    // Immediate actions
    if (risk >= 75) {
      immediate.push('Activate incident response plan immediately.');
      immediate.push('Isolate all affected hosts from the production network.');
      immediate.push('Revoke compromised credentials and tokens.');
    } else if (risk >= 50) {
      immediate.push('Notify security operations center within 1 hour.');
      immediate.push('Enable enhanced logging on affected assets.');
    } else {
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

    await this.publishEvent(APP_EVENTS.RECOMMENDATIONS_GENERATED, ctx, {
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

  private riskLabel(score: number): string {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  }
}

export const knowledgeOrchestrator = new KnowledgeOrchestrator();
