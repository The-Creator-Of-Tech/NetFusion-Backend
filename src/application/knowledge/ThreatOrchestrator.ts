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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  OrchestrationNotFoundError,
  OrchestrationValidationError,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { threatService } from '../../services/knowledge';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface IdentifyThreatActorInput {
  /** Search by name or alias */
  name?: string;
  /** Search by severity level */
  severity?: string;
  /** ThreatActor UUID for direct lookup */
  threatActorId?: string;
  actor: string;
}

export interface IdentifyCampaignInput {
  /** ThreatActor UUID to find campaigns for */
  threatActorId: string;
  actor: string;
}

export interface AssociateTechniquesInput {
  threatActorId: string;
  techniqueIds: string[];
  actor: string;
}

export interface AssociateIOCsInput {
  threatActorId: string;
  iocIds: string[];
  actor: string;
}

export interface AssociateCVEsInput {
  threatActorId: string;
  /** One or more CVE UUIDs to link via ThreatRelationship */
  cveIds: string[];
  actor: string;
}

export interface CalculateThreatScoreInput {
  threatActorId: string;
  actor: string;
}

export interface ThreatActorResult {
  actors: any[];
  totalFound: number;
  correlationId: string;
}

export interface ThreatScoreResult {
  threatActorId: string;
  score: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ThreatOrchestrator extends BaseApplicationService {
  constructor() {
    super('ThreatOrchestrator');
  }

  // ── identifyThreatActor ───────────────────────────────────────────────────

  /**
   * Identify threat actors by name, alias, or severity.
   * Publishes ThreatActorIdentified when actors are found.
   */
  async identifyThreatActor(
    input: IdentifyThreatActorInput,
    parentCtx?: OperationContext,
  ): Promise<ThreatActorResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Identifying threat actors: name=${input.name ?? 'N/A'} severity=${input.severity ?? 'N/A'}`);

    let actors: any[] = [];

    if (input.name) {
      actors = await threatService.findByActor(input.name);
    } else if (input.severity) {
      actors = await threatService.findByThreatLevel(input.severity as any);
    } else if (input.threatActorId) {
      this.validateUuid(input.threatActorId, 'threatActorId', ctx);
      // Get score to verify existence
      const score = await threatService.calculateThreatScore(input.threatActorId);
      actors = score >= 0 ? [{ id: input.threatActorId, score }] : [];
    } else {
      throw new OrchestrationValidationError(
        'At least one of name, severity, or threatActorId must be provided.',
        ctx.correlationId,
      );
    }

    if (actors.length > 0) {
      await this.publishEvent(APP_EVENTS.THREAT_ACTOR_IDENTIFIED, ctx, {
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
  async identifyCampaign(
    input: IdentifyCampaignInput,
    parentCtx?: OperationContext,
  ): Promise<{ campaigns: any[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.threatActorId, 'threatActorId', ctx);
    this.logInfo(ctx, `Identifying campaigns for threat actor: ${input.threatActorId}`);

    const campaigns = await threatService.getCampaigns(input.threatActorId);

    if (campaigns.length > 0) {
      await this.publishEvent(APP_EVENTS.CAMPAIGN_MATCHED, ctx, {
        threatActorId: input.threatActorId,
        campaignCount: campaigns.length,
        campaignIds: campaigns.map((c: any) => c.id),
      });
    }

    this.logTiming(ctx, 'identifyCampaign');

    return { campaigns, correlationId: ctx.correlationId };
  }

  // ── associateTechniques ───────────────────────────────────────────────────

  /**
   * Link MITRE techniques to a threat actor.
   */
  async associateTechniques(
    input: AssociateTechniquesInput,
    parentCtx?: OperationContext,
  ): Promise<{ threatActorId: string; techniqueIds: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.threatActorId, 'threatActorId', ctx);

    if (!input.techniqueIds || input.techniqueIds.length === 0) {
      throw new OrchestrationValidationError('techniqueIds must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Associating ${input.techniqueIds.length} technique(s) with ThreatActor ${input.threatActorId}`);

    await threatService.linkTechniques(input.threatActorId, input.techniqueIds, input.actor);

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
  async associateIOCs(
    input: AssociateIOCsInput,
    parentCtx?: OperationContext,
  ): Promise<{ threatActorId: string; iocIds: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.threatActorId, 'threatActorId', ctx);

    if (!input.iocIds || input.iocIds.length === 0) {
      throw new OrchestrationValidationError('iocIds must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Associating ${input.iocIds.length} IOC(s) with ThreatActor ${input.threatActorId}`);

    await threatService.linkIocs(input.threatActorId, input.iocIds, input.actor);

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
  async associateCVEs(
    input: AssociateCVEsInput,
    parentCtx?: OperationContext,
  ): Promise<{ threatActorId: string; linkedCount: number; failed: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.threatActorId, 'threatActorId', ctx);

    if (!input.cveIds || input.cveIds.length === 0) {
      throw new OrchestrationValidationError('cveIds must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Associating ${input.cveIds.length} CVE(s) with ThreatActor ${input.threatActorId}`);

    const failed: string[] = [];
    let linkedCount = 0;

    for (const cveId of input.cveIds) {
      try {
        this.validateUuid(cveId, 'cveId', ctx);
        await threatService.addRelationship({
          threatId: input.threatActorId,
          cveId,
          targetType: 'CVE',
          relationType: 'EXPLOITS',
          confidence: 75,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
        linkedCount++;
      } catch (e: any) {
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
  async calculateThreatScore(
    input: CalculateThreatScoreInput,
    parentCtx?: OperationContext,
  ): Promise<ThreatScoreResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.threatActorId, 'threatActorId', ctx);
    this.logInfo(ctx, `Calculating threat score for: ${input.threatActorId}`);

    const score = await threatService.calculateThreatScore(input.threatActorId);

    await this.publishEvent(APP_EVENTS.THREAT_SCORE_CALCULATED, ctx, {
      threatActorId: input.threatActorId,
      score,
    });

    this.logTiming(ctx, 'calculateThreatScore');

    return { threatActorId: input.threatActorId, score, correlationId: ctx.correlationId };
  }

  // ── getTechniques ─────────────────────────────────────────────────────────

  async getTechniques(threatActorId: string, actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(threatActorId, 'threatActorId', ctx);
    return threatService.getTechniques(threatActorId);
  }

  // ── getAssociatedIOCs ─────────────────────────────────────────────────────

  async getAssociatedIOCs(threatActorId: string, actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(threatActorId, 'threatActorId', ctx);
    return threatService.getAssociatedIocs(threatActorId);
  }

  // ── getAssociatedCVEs ─────────────────────────────────────────────────────

  async getAssociatedCVEs(threatActorId: string, actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(threatActorId, 'threatActorId', ctx);
    return threatService.getAssociatedCves(threatActorId);
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return threatService.getStatistics();
  }
}

export const threatOrchestrator = new ThreatOrchestrator();
