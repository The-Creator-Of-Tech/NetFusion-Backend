/**
 * CorrelationPipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles correlation capabilities by coordinating AI, Knowledge, and Investigation domains:
 * Finding → IOC Extraction → MITRE Mapping → CVE Correlation → Threat Actor → Campaign → AI Summary → Recommendations
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Orchestrators
import { correlationOrchestrator, CorrelateFindingInput } from '../knowledge/CorrelationOrchestrator';
import { aiOrchestrator } from '../ai/AIOrchestrator';

// Services
import { attackGraphService, findingService, alertService } from '../../services/investigation';
import prisma from '../../lib/prisma';

export class CorrelationPipeline extends BaseApplicationService {
  constructor() {
    super('CorrelationPipeline');
  }

  async correlateFinding(
    input: CorrelateFindingInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Correlating finding ${input.findingId} within CorrelationPipeline`);

    await this.publishEvent(APP_EVENTS.CORRELATION_PIPELINE_STARTED, ctx, {
      findingId: input.findingId,
      investigationId: input.investigationId,
    });

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Core Correlation Orchestration (Extracts IOC, Mitre techniques, CVEs, Threat Actors, Campaigns)
      const coreRes = await correlationOrchestrator.correlateFinding(input, ctx);

      // 2. AI Reasoning / Summary
      const aiRes = await aiOrchestrator.runReasoning({
        projectId: input.projectId,
        investigationId: input.investigationId,
        actor: input.actor,
        steps: [
          {
            stage: 'FindingCorrelation',
            inputSummary: `Finding: ${input.findingTitle}, Severity: ${input.findingSeverity}`,
            outputSummary: `Risk Score: ${coreRes.riskScore}, Techniques Identified: ${coreRes.techniques.length}`,
            confidence: 0.95,
            findingIds: [input.findingId],
          }
        ],
        decision: `Identified potential threat vector mapping with calculated risk score ${coreRes.riskScore}`,
      }, ctx);

      // 3. Build recommendations
      const recommendations = await this.generateRecommendations(input.investigationId, input.actor, ctx);

      // 4. Update the threat graph node if nodes exist
      try {
        await attackGraphService.rebuildGraph(input.investigationId, input.actor);
      } catch (_) { /* best effort */ }

      const result = {
        findingId: input.findingId,
        techniques: coreRes.techniques,
        cves: coreRes.cves,
        iocs: coreRes.iocs,
        threatActors: coreRes.threatActors,
        campaigns: coreRes.campaigns,
        riskScore: coreRes.riskScore,
        aiSummary: aiRes.decision,
        recommendations,
        correlationId: ctx.correlationId,
      };

      await this.publishEvent(APP_EVENTS.CORRELATION_COMPLETED, ctx, {
        findingId: input.findingId,
        investigationId: input.investigationId,
        riskScore: coreRes.riskScore,
      });

      return result;
    });
  }

  async correlateInvestigation(
    investigationId: string,
    projectId: string,
    actor: string,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId, investigationId });
    this.logInfo(ctx, `Correlating all findings in investigation ${investigationId}`);
    
    // Find all findings
    const findings = await prisma.finding.findMany({ where: { investigationId } });
    const results: any[] = [];

    for (const f of findings) {
      const res = await correlationOrchestrator.correlateFinding({
        findingId: f.id,
        findingTitle: f.title,
        findingSeverity: f.severity,
        projectId,
        investigationId,
        actor,
      }, ctx);
      results.push(res);
    }

    // Aggregates risk
    const overallRisk = await this.generateRiskAssessment(investigationId, actor, ctx);

    return {
      investigationId,
      findingsCount: findings.length,
      overallRisk,
      correlations: results,
      correlationId: ctx.correlationId,
    };
  }

  async generateRiskAssessment(
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext
  ): Promise<number> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    this.logInfo(ctx, `Generating risk assessment for investigation ${investigationId}`);

    const alerts = await alertService.getOpenAlerts(investigationId);
    let score = 10; // base risk
    
    for (const alert of alerts) {
      if (alert.severity === 'CRITICAL') score += 25;
      else if (alert.severity === 'HIGH') score += 15;
      else if (alert.severity === 'MEDIUM') score += 8;
      else score += 3;
    }

    return Math.min(score, 100);
  }

  async generateRecommendations(
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext
  ): Promise<string[]> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    const alerts = await alertService.getOpenAlerts(investigationId);
    const recs: string[] = [];

    if (alerts.length > 0) {
      recs.push(`Remediate ${alerts.length} unresolved alerts immediately.`);
    }
    
    const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH');
    if (criticalAlerts.length > 0) {
      recs.push(`EXECUTE containments: isolate hosts related to ${criticalAlerts.length} high priority alerts.`);
    } else {
      recs.push('Monitor baseline security profiles and updates.');
    }

    return recs;
  }

  async buildThreatGraph(
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    this.logInfo(ctx, `Building threat graph for investigation ${investigationId}`);
    return attackGraphService.rebuildGraph(investigationId, actor);
  }
}

export const correlationPipeline = new CorrelationPipeline();
