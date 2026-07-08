/**
 * PlaybookService — Phase A5.3.6
 * ================================
 * Business logic for Playbook lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for Playbooks and PlaybookSteps
 * - Category, author, priority, and status lookups
 * - Playbook execution simulation & step orchestration
 * - Confidence & risk scoring
 * - Statistics and bulk operations
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { playbookRepository } from '../../repositories/workflow';
import prisma from '../../lib/prisma';
import {
  Playbook,
  PlaybookStep,
  PlaybookStatus,
  RuleSeverity,
  Prisma,
} from '@prisma/client';

// ── Valid status transitions ──────────────────────────────────────────────────
const STATUS_TRANSITIONS: Record<string, string[]> = {
  DRAFT:    ['ACTIVE', 'ARCHIVED'],
  ACTIVE:   ['DRAFT', 'ARCHIVED'],
  ARCHIVED: ['DRAFT'],
};

// ── Severity score map ────────────────────────────────────────────────────────
const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 100,
  HIGH:     75,
  MEDIUM:   50,
  LOW:      25,
};

export class PlaybookService extends BaseService {
  constructor(private readonly playbookRepo = playbookRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  /**
   * Create a new playbook. Validates required fields and publishes PlaybookCreated.
   */
  async createPlaybook(
    data: Prisma.PlaybookUncheckedCreateInput,
    tx?: any,
  ): Promise<Playbook> {
    this.validateRequired(data as any, ['name', 'severity', 'createdBy', 'updatedBy']);
    if (!data.projectId) {
      throw new Error('Validation failed: projectId is required.');
    }

    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validSeverities.includes(String(data.severity).toUpperCase())) {
      throw new Error(`Validation failed: severity "${data.severity}" is not valid.`);
    }

    if (data.confidence !== undefined) {
      const conf = Number(data.confidence);
      if (isNaN(conf) || conf < 0 || conf > 100) {
        throw new Error(`Validation failed: confidence must be between 0 and 100.`);
      }
    }

    const runInTx = async (transaction: any) => {
      const playbook = await this.playbookRepo.create(data, transaction);
      await eventPublisher.publish('PlaybookCreated', { playbook });
      return playbook;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  /**
   * Update a playbook by UUID. Validates status transitions. Publishes PlaybookUpdated.
   */
  async updatePlaybook(
    id: string,
    data: Prisma.PlaybookUncheckedUpdateInput,
    tx?: any,
  ): Promise<Playbook> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }

      if (data.status && data.status !== existing.status) {
        const allowed = STATUS_TRANSITIONS[existing.status] ?? [];
        if (!allowed.includes(String(data.status))) {
          throw new Error(
            `Invalid status transition from "${existing.status}" to "${data.status}".`,
          );
        }
      }

      if (data.confidence !== undefined) {
        const conf = Number(data.confidence);
        if (isNaN(conf) || conf < 0 || conf > 100) {
          throw new Error(`Validation failed: confidence must be between 0 and 100.`);
        }
      }

      const updated = await this.playbookRepo.update(id, data, transaction);
      await eventPublisher.publish('PlaybookUpdated', { playbook: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  /**
   * Soft-delete a playbook by UUID. Publishes PlaybookDeleted.
   */
  async deletePlaybook(id: string, actor: string, tx?: any): Promise<Playbook> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }
      const deleted = await this.playbookRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('PlaybookDeleted', { playbook: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  /** Find playbooks by project UUID. */
  async findByProject(projectId: string, tx?: any): Promise<Playbook[]> {
    this.validateUuid(projectId, 'projectId');
    return this.playbookRepo.findByProject(projectId, tx);
  }

  /** Find playbooks by investigation UUID. */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Playbook[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.playbookRepo.findByInvestigation(investigationId, tx);
  }

  /** Find playbooks by category (non-empty). */
  async findByCategory(category: string, tx?: any): Promise<Playbook[]> {
    if (!category || !category.trim()) {
      throw new Error('Validation failed: category must not be empty.');
    }
    return this.playbookRepo.findByCategory(category.trim(), tx);
  }

  /** Find playbooks by author (non-empty). */
  async findByAuthor(author: string, tx?: any): Promise<Playbook[]> {
    if (!author || !author.trim()) {
      throw new Error('Validation failed: author must not be empty.');
    }
    return this.playbookRepo.findByAuthor(author.trim(), tx);
  }

  /** Find playbooks by numeric priority (must be >= 1). */
  async findByPriority(priority: number, tx?: any): Promise<Playbook[]> {
    if (!Number.isInteger(priority) || priority < 1) {
      throw new Error(`Validation failed: priority must be a positive integer.`);
    }
    return this.playbookRepo.findByPriority(priority, tx);
  }

  /** Find all enabled playbooks. */
  async findEnabled(tx?: any): Promise<Playbook[]> {
    return this.playbookRepo.findEnabled(tx);
  }

  /** Find all disabled playbooks. */
  async findDisabled(tx?: any): Promise<Playbook[]> {
    return this.playbookRepo.findDisabled(tx);
  }

  /** Find all DRAFT playbooks. */
  async findDrafts(tx?: any): Promise<Playbook[]> {
    return this.playbookRepo.findDrafts(tx);
  }

  /** Find all ARCHIVED playbooks. */
  async findArchived(tx?: any): Promise<Playbook[]> {
    return this.playbookRepo.findArchived(tx);
  }

  /** Find a playbook with all its steps included. */
  async findWithSteps(id: string, tx?: any): Promise<any> {
    this.validateUuid(id, 'playbookId');
    const result = await this.playbookRepo.findWithSteps(id, tx);
    if (!result) throw new Error(`Playbook "${id}" not found.`);
    return result;
  }

  /** Search playbook steps by keyword (title/description). */
  async searchSteps(query: string, tx?: any): Promise<PlaybookStep[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.playbookRepo.searchSteps(query.trim(), tx);
  }

  /** Find a single playbook step by UUID. */
  async findStep(stepId: string, tx?: any): Promise<PlaybookStep | null> {
    this.validateUuid(stepId, 'stepId');
    return this.playbookRepo.findStep(stepId, tx);
  }

  // ── Execution / Orchestration ───────────────────────────────────────────────

  /**
   * Execute a playbook — transitions status to ACTIVE if DRAFT, publishes
   * PlaybookExecutionStarted. Returns the updated playbook and its steps.
   */
  async executePlaybook(
    id: string,
    actor: string,
    tx?: any,
  ): Promise<{ playbook: Playbook; steps: PlaybookStep[] }> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }
      if (existing.status === 'ARCHIVED') {
        throw new Error(`Cannot execute archived playbook "${id}".`);
      }

      let playbook = existing;
      if (existing.status === 'DRAFT') {
        playbook = await this.playbookRepo.update(
          id,
          { status: 'ACTIVE' as PlaybookStatus, updatedBy: actor },
          transaction,
        );
      }

      const steps = await this.playbookRepo.findWithSteps(id, transaction);
      await eventPublisher.publish('PlaybookExecutionStarted', {
        playbook,
        actor,
        stepCount: steps?.steps?.length ?? 0,
      });

      return { playbook, steps: steps?.steps ?? [] };
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Enable a playbook (set enabled = true). Publishes PlaybookEnabled.
   */
  async enablePlaybook(id: string, actor: string, tx?: any): Promise<Playbook> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }
      const updated = await this.playbookRepo.update(
        id,
        { enabled: true, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('PlaybookEnabled', { playbook: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Disable a playbook (set enabled = false). Publishes PlaybookDisabled.
   */
  async disablePlaybook(id: string, actor: string, tx?: any): Promise<Playbook> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }
      const updated = await this.playbookRepo.update(
        id,
        { enabled: false, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('PlaybookDisabled', { playbook: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Archive a playbook (status → ARCHIVED). Publishes PlaybookArchived.
   */
  async archivePlaybook(id: string, actor: string, tx?: any): Promise<Playbook> {
    this.validateUuid(id, 'playbookId');

    const runInTx = async (transaction: any) => {
      const existing = await this.playbookRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Playbook "${id}" not found.`);
      }
      const updated = await this.playbookRepo.update(
        id,
        { status: 'ARCHIVED' as PlaybookStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('PlaybookArchived', { playbook: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Scoring ─────────────────────────────────────────────────────────────────

  /**
   * Calculate a risk score (0–100) for a playbook based on severity,
   * step count, and enabled status.
   */
  async calculateRiskScore(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'playbookId');
    const playbook = await this.playbookRepo.findById(id, tx);
    if (!playbook || playbook.deletedAt) {
      throw new Error(`Playbook "${id}" not found.`);
    }

    const severityScore = SEVERITY_SCORE[String(playbook.severity ?? 'MEDIUM')] ?? 50;
    const withSteps = await this.playbookRepo.findWithSteps(id, tx);
    const stepBonus = Math.min((withSteps?.steps?.length ?? 0) * 2, 20);
    const enabledBonus = playbook.enabled ? 10 : 0;

    return Math.min(severityScore + stepBonus + enabledBonus, 100);
  }

  /**
   * Pure scoring utility: score a list of playbook IDs (0–100).
   */
  scorePlaybooks(ids: string[]): number {
    if (!ids || ids.length === 0) return 0;
    return Math.min(ids.length * 10, 100);
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  /**
   * Compute aggregate statistics across all non-deleted playbooks.
   */
  async getStatistics(tx?: any): Promise<{
    totalPlaybooks: number;
    enabledPlaybooks: number;
    disabledPlaybooks: number;
    draftPlaybooks: number;
    activePlaybooks: number;
    archivedPlaybooks: number;
    averagePriority: number;
    severityCounts: Record<string, number>;
  }> {
    const stats = await this.playbookRepo.calculateStatistics(tx);
    const client = tx || prisma;

    const all = await client.playbook.findMany({ where: { deletedAt: null } });

    const severityCounts: Record<string, number> = {};
    let prioritySum = 0;
    for (const p of all) {
      const sev = String(p.severity ?? 'MEDIUM');
      severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
      prioritySum += p.priority ?? 1;
    }

    return {
      totalPlaybooks: stats.total,
      enabledPlaybooks: stats.enabled,
      disabledPlaybooks: stats.disabled,
      draftPlaybooks: stats.draft,
      activePlaybooks: stats.active,
      archivedPlaybooks: stats.archived,
      averagePriority: all.length > 0 ? Math.round((prioritySum / all.length) * 10) / 10 : 0,
      severityCounts,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  /**
   * Bulk-create playbooks. Returns succeeded IDs and failed entries.
   */
  async bulkCreatePlaybooks(
    items: Prisma.PlaybookUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { name: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { name: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const p = await this.createPlaybook({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(p.id);
      } catch (e: any) {
        failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('PlaybooksBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete playbooks by IDs.
   */
  async bulkDeletePlaybooks(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deletePlaybook(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('PlaybooksBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const playbookService = new PlaybookService();
