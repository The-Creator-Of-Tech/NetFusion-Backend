/**
 * IocOrchestrator.ts — Phase A5.4.3
 * =====================================
 * Orchestrates IOC enrichment, correlation, confidence scoring, and reputation lookups.
 *
 * Responsibilities
 * ----------------
 * - Enrich IOCs with reputation data and categories
 * - Correlate IOCs to CVEs, threat actors, MITRE techniques
 * - Calculate IOC confidence score
 * - Perform reputation lookup (score-based)
 * - Find related threats
 * - Publish IOCEnrichedFull / IOCCorrelated events
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
import { iocService } from '../../services/knowledge';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface EnrichIOCInput {
  iocId: string;
  actor: string;
  reputationScore: number;
  malicious: boolean;
  categories?: string[];
  firstSeen?: string;
  lastSeen?: string;
  provider?: string;
}

export interface CorrelateIOCInput {
  iocId: string;
  actor: string;
  /** Optional CVE UUID to link */
  cveId?: string;
  /** Optional ThreatActor UUID to link */
  threatId?: string;
}

export interface CalculateConfidenceInput {
  iocId: string;
  actor: string;
}

export interface LookupReputationInput {
  iocId: string;
  actor: string;
}

export interface FindRelatedThreatsInput {
  iocId: string;
  actor: string;
}

export interface IOCEnrichmentResult {
  iocId: string;
  enrichment: any;
  threatScore: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// IocOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class IocOrchestrator extends BaseApplicationService {
  constructor() {
    super('IocOrchestrator');
  }

  // ── enrichIOC ─────────────────────────────────────────────────────────────

  /**
   * Enrich an IOC with reputation data.
   * Publishes IOCEnrichedFull.
   */
  async enrichIOC(
    input: EnrichIOCInput,
    parentCtx?: OperationContext,
  ): Promise<IOCEnrichmentResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.iocId, 'iocId', ctx);

    if (typeof input.reputationScore !== 'number' || input.reputationScore < 0 || input.reputationScore > 100) {
      throw new OrchestrationValidationError(
        `reputationScore must be 0–100, got: ${input.reputationScore}`,
        ctx.correlationId,
      );
    }

    this.logInfo(ctx, `Enriching IOC: ${input.iocId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const enrichment = await iocService.enrichIoc(
        input.iocId,
        {
          reputationScore: input.reputationScore,
          malicious: input.malicious,
          categories: input.categories ?? [],
          firstSeen: input.firstSeen,
          lastSeen: input.lastSeen,
          provider: input.provider ?? 'NetFusion',
          createdBy: input.actor,
          updatedBy: input.actor,
        },
      );

      const threatScore = await iocService.calculateThreatScore(input.iocId);

      await this.publishEvent(APP_EVENTS.IOC_ENRICHED_FULL, ctx, {
        iocId: input.iocId,
        reputationScore: input.reputationScore,
        malicious: input.malicious,
        threatScore,
      });

      compensation.clear();
      this.logTiming(ctx, 'enrichIOC');

      return {
        iocId: input.iocId,
        enrichment,
        threatScore,
        correlationId: ctx.correlationId,
      };
    });
  }

  // ── correlateIOC ──────────────────────────────────────────────────────────

  /**
   * Correlate an IOC to a CVE or ThreatActor by adding a relationship.
   * Publishes IOCCorrelated.
   */
  async correlateIOC(
    input: CorrelateIOCInput,
    parentCtx?: OperationContext,
  ): Promise<{ iocId: string; relationship: any; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.iocId, 'iocId', ctx);

    if (!input.cveId && !input.threatId) {
      throw new OrchestrationValidationError(
        'At least one of cveId or threatId must be provided.',
        ctx.correlationId,
      );
    }

    this.logInfo(ctx, `Correlating IOC ${input.iocId} to CVE/Threat`);

    const targetType = input.cveId ? 'CVE' : 'THREAT_ACTOR';
    const targetId = (input.cveId ?? input.threatId)!;

    const relationship = await iocService.addRelationship(
      input.iocId,
      {
        targetId,
        targetType,
        relationType: 'ASSOCIATED_WITH',
        confidence: 75,
        cveId: input.cveId,
        threatId: input.threatId,
        createdBy: input.actor,
        updatedBy: input.actor,
      },
    );

    await this.publishEvent(APP_EVENTS.IOC_CORRELATED, ctx, {
      iocId: input.iocId,
      targetType,
      targetId,
    });

    this.logTiming(ctx, 'correlateIOC');

    return { iocId: input.iocId, relationship, correlationId: ctx.correlationId };
  }

  // ── calculateConfidence ───────────────────────────────────────────────────

  /**
   * Calculate composite confidence/threat score for an IOC (0–100).
   */
  async calculateConfidence(
    input: CalculateConfidenceInput,
    parentCtx?: OperationContext,
  ): Promise<{ iocId: string; score: number; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.iocId, 'iocId', ctx);
    this.logInfo(ctx, `Calculating confidence for IOC: ${input.iocId}`);

    const score = await iocService.calculateThreatScore(input.iocId);

    this.logTiming(ctx, 'calculateConfidence');

    return { iocId: input.iocId, score, correlationId: ctx.correlationId };
  }

  // ── lookupReputation ──────────────────────────────────────────────────────

  /**
   * Return existing enrichment (reputation) data for an IOC.
   * Publishes IOCReputationLookedUp.
   */
  async lookupReputation(
    input: LookupReputationInput,
    parentCtx?: OperationContext,
  ): Promise<{ iocId: string; enrichment: any | null; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.iocId, 'iocId', ctx);
    this.logInfo(ctx, `Looking up reputation for IOC: ${input.iocId}`);

    const enrichment = await iocService.getEnrichment(input.iocId);

    await this.publishEvent(APP_EVENTS.IOC_REPUTATION_LOOKED_UP, ctx, {
      iocId: input.iocId,
      found: enrichment !== null,
      reputationScore: enrichment?.reputationScore ?? null,
    });

    this.logTiming(ctx, 'lookupReputation');

    return { iocId: input.iocId, enrichment, correlationId: ctx.correlationId };
  }

  // ── findRelatedThreats ────────────────────────────────────────────────────

  /**
   * Find threat actors linked to an IOC.
   */
  async findRelatedThreats(
    input: FindRelatedThreatsInput,
    parentCtx?: OperationContext,
  ): Promise<{ iocId: string; relationships: any[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.iocId, 'iocId', ctx);
    this.logInfo(ctx, `Finding related threats for IOC: ${input.iocId}`);

    const relationships = await iocService.getRelationships(input.iocId);

    this.logTiming(ctx, 'findRelatedThreats');

    return { iocId: input.iocId, relationships, correlationId: ctx.correlationId };
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return iocService.getStatistics();
  }
}

export const iocOrchestrator = new IocOrchestrator();
