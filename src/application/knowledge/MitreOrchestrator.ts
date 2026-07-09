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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  OrchestrationNotFoundError,
  OrchestrationValidationError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { mitreService } from '../../services/knowledge';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface MapTechniqueInput {
  mitreId: string;
  actor: string;
  contextId?: string;
}

export interface MapTacticInput {
  tacticId: string;
  actor: string;
}

export interface FindMitigationsInput {
  techniqueId: string;
  actor: string;
}

export interface FindDetectionsInput {
  techniqueId: string;
  actor: string;
}

export interface FindRelatedTechniquesInput {
  mitreId: string;
  actor: string;
  /** Include sibling techniques (same tactic) */
  includeSiblings?: boolean;
}

export interface TechniqueMappingResult {
  techniqueId: string;
  mitreId: string;
  name: string;
  severity: string;
  tactic: string | null;
  mitigations: any[];
  relatedTechniques: any[];
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// MitreOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class MitreOrchestrator extends BaseApplicationService {
  constructor() {
    super('MitreOrchestrator');
  }

  // ── mapTechnique ──────────────────────────────────────────────────────────

  /**
   * Fully map a MITRE technique: fetch details, mitigations, related techniques.
   * Publishes MitreMapped.
   */
  async mapTechnique(
    input: MapTechniqueInput,
    parentCtx?: OperationContext,
  ): Promise<TechniqueMappingResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Mapping MITRE technique: ${input.mitreId}`);

    const technique = await mitreService.findByMitreId(input.mitreId);
    if (!technique) {
      throw new OrchestrationNotFoundError('MitreTechnique', input.mitreId, ctx.correlationId);
    }

    const [mitigations, subTechniques, detectionRules] = await Promise.all([
      mitreService.findMitigations(technique.id),
      mitreService.findSubTechniques(input.mitreId),
      mitreService.findDetectionRules(technique.id),
    ]);

    await this.publishEvent(APP_EVENTS.MITRE_MAPPED, ctx, {
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
  async mapTactic(
    input: MapTacticInput,
    parentCtx?: OperationContext,
  ): Promise<{ tacticId: string; techniques: any[]; aggregateRisk: number; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.tacticId, 'tacticId', ctx);
    this.logInfo(ctx, `Mapping MITRE tactic: ${input.tacticId}`);

    const [techniques, risk] = await Promise.all([
      mitreService.findByTactic(input.tacticId),
      mitreService.aggregateTacticRisk(input.tacticId),
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
  async findMitigations(
    input: FindMitigationsInput,
    parentCtx?: OperationContext,
  ): Promise<any[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.techniqueId, 'techniqueId', ctx);
    this.logInfo(ctx, `Finding mitigations for technique: ${input.techniqueId}`);

    const mitigations = await mitreService.findMitigations(input.techniqueId);

    this.logTiming(ctx, 'findMitigations');
    return mitigations;
  }

  // ── findDetections ────────────────────────────────────────────────────────

  /**
   * Retrieve detection rules targeting a technique (by UUID).
   */
  async findDetections(
    input: FindDetectionsInput,
    parentCtx?: OperationContext,
  ): Promise<any[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.techniqueId, 'techniqueId', ctx);
    this.logInfo(ctx, `Finding detections for technique: ${input.techniqueId}`);

    const rules = await mitreService.findDetectionRules(input.techniqueId);

    this.logTiming(ctx, 'findDetections');
    return rules;
  }

  // ── findRelatedTechniques ─────────────────────────────────────────────────

  /**
   * Find related techniques: sub-techniques and optionally sibling parent.
   */
  async findRelatedTechniques(
    input: FindRelatedTechniquesInput,
    parentCtx?: OperationContext,
  ): Promise<{ subTechniques: any[]; parent: any | null; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Finding related techniques for: ${input.mitreId}`);

    const [subTechniques, parent] = await Promise.all([
      mitreService.findSubTechniques(input.mitreId),
      mitreService.findParentTechnique(input.mitreId),
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
  async correlateToCve(
    cveId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<any[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(cveId, 'cveId', ctx);
    this.logInfo(ctx, `Correlating techniques to CVE: ${cveId}`);

    const techniques = await mitreService.correlateToCve(cveId);
    this.logTiming(ctx, 'correlateToCve');
    return techniques;
  }

  // ── correlateToThreatActor ────────────────────────────────────────────────

  /**
   * Find MITRE techniques correlated to a ThreatActor.
   */
  async correlateToThreatActor(
    threatActorId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<any[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(threatActorId, 'threatActorId', ctx);
    this.logInfo(ctx, `Correlating techniques to ThreatActor: ${threatActorId}`);

    const techniques = await mitreService.correlateToThreatActor(threatActorId);
    this.logTiming(ctx, 'correlateToThreatActor');
    return techniques;
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return mitreService.getStatistics();
  }
}

export const mitreOrchestrator = new MitreOrchestrator();
