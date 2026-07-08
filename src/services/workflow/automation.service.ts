/**
 * AutomationService — Phase A5.3.6
 * ===================================
 * Business logic for Automation lifecycle and execution management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for Automations, AutomationSteps, and AutomationExecutions
 * - Trigger-based lookups, enable/disable, and category queries
 * - Execution lifecycle (start, complete, fail)
 * - Step orchestration and execution logging
 * - Scoring and statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { automationRepository } from '../../repositories/workflow';
import prisma from '../../lib/prisma';
import {
  Automation,
  AutomationExecution,
  AutomationStep,
  AutomationStatus,
  AutomationTriggerType,
  AutomationExecutionStatus,
  Prisma,
} from '@prisma/client';

// ── Severity score map ────────────────────────────────────────────────────────
const PRIORITY_SCORE: Record<number, number> = {};
const priorityToScore = (priority: number): number => {
  if (priority <= 10)  return 90;
  if (priority <= 50)  return 70;
  if (priority <= 100) return 50;
  return 30;
};

// ── Valid trigger types ───────────────────────────────────────────────────────
export const VALID_TRIGGERS: AutomationTriggerType[] = [
  'FINDING_CREATED',
  'ALERT_CREATED',
  'RULE_MATCHED',
  'PLAYBOOK_SELECTED',
  'TIMELINE_EVENT',
  'MANUAL',
];

export class AutomationService extends BaseService {
  constructor(private readonly automationRepo = automationRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  /**
   * Create a new automation. Validates required fields and publishes AutomationCreated.
   */
  async createAutomation(
    data: Prisma.AutomationUncheckedCreateInput,
    tx?: any,
  ): Promise<Automation> {
    this.validateRequired(data as any, ['name', 'trigger', 'createdBy', 'updatedBy']);
    if (!data.projectId) {
      throw new Error('Validation failed: projectId is required.');
    }

    if (!VALID_TRIGGERS.includes(String(data.trigger) as AutomationTriggerType)) {
      throw new Error(`Validation failed: trigger "${data.trigger}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const automation = await this.automationRepo.create(data, transaction);
      await eventPublisher.publish('AutomationCreated', { automation });
      return automation;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  /**
   * Update an automation by UUID. Validates trigger if provided. Publishes AutomationUpdated.
   */
  async updateAutomation(
    id: string,
    data: Prisma.AutomationUncheckedUpdateInput,
    tx?: any,
  ): Promise<Automation> {
    this.validateUuid(id, 'automationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.automationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Automation "${id}" not found.`);
      }

      if (data.trigger !== undefined) {
        if (!VALID_TRIGGERS.includes(String(data.trigger) as AutomationTriggerType)) {
          throw new Error(`Validation failed: trigger "${data.trigger}" is not valid.`);
        }
      }

      const updated = await this.automationRepo.update(id, data, transaction);
      await eventPublisher.publish('AutomationUpdated', { automation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  /**
   * Soft-delete an automation by UUID. Publishes AutomationDeleted.
   */
  async deleteAutomation(id: string, actor: string, tx?: any): Promise<Automation> {
    this.validateUuid(id, 'automationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.automationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Automation "${id}" not found.`);
      }
      const deleted = await this.automationRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('AutomationDeleted', { automation: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  /** Find automations by project UUID. */
  async findByProject(projectId: string, tx?: any): Promise<Automation[]> {
    this.validateUuid(projectId, 'projectId');
    return this.automationRepo.findByProject(projectId, tx);
  }

  /** Find automations by investigation UUID. */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Automation[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.automationRepo.findByInvestigation(investigationId, tx);
  }

  /** Find automations by playbook UUID. */
  async findByPlaybook(playbookId: string, tx?: any): Promise<Automation[]> {
    this.validateUuid(playbookId, 'playbookId');
    return this.automationRepo.findByPlaybook(playbookId, tx);
  }

  /** Find automations by rule UUID. */
  async findByRule(ruleId: string, tx?: any): Promise<Automation[]> {
    this.validateUuid(ruleId, 'ruleId');
    return this.automationRepo.findByRule(ruleId, tx);
  }

  /** Find automations by trigger type. */
  async findByTrigger(trigger: AutomationTriggerType, tx?: any): Promise<Automation[]> {
    if (!VALID_TRIGGERS.includes(trigger)) {
      throw new Error(`Validation failed: trigger "${trigger}" is not valid.`);
    }
    return this.automationRepo.findByTrigger(trigger, tx);
  }

  /** Find all enabled automations. */
  async findEnabled(tx?: any): Promise<Automation[]> {
    return this.automationRepo.findEnabled(tx);
  }

  /** Find all disabled automations. */
  async findDisabled(tx?: any): Promise<Automation[]> {
    return this.automationRepo.findDisabled(tx);
  }

  /** Find executions for an automation UUID. */
  async findExecutions(automationId: string, tx?: any): Promise<AutomationExecution[]> {
    this.validateUuid(automationId, 'automationId');
    return this.automationRepo.findExecutions(automationId, tx);
  }

  /** Find steps for an automation UUID. */
  async findSteps(automationId: string, tx?: any): Promise<AutomationStep[]> {
    this.validateUuid(automationId, 'automationId');
    return this.automationRepo.findSteps(automationId, tx);
  }

  /** Search automation steps by keyword. */
  async searchSteps(query: string, tx?: any): Promise<AutomationStep[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.automationRepo.searchSteps(query.trim(), tx);
  }

  // ── Enable / Disable ────────────────────────────────────────────────────────

  /**
   * Enable an automation. Publishes AutomationEnabled.
   */
  async enableAutomation(id: string, actor: string, tx?: any): Promise<Automation> {
    this.validateUuid(id, 'automationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.automationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Automation "${id}" not found.`);
      }
      const updated = await this.automationRepo.update(
        id,
        { enabled: true, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('AutomationEnabled', { automation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Disable an automation. Publishes AutomationDisabled.
   */
  async disableAutomation(id: string, actor: string, tx?: any): Promise<Automation> {
    this.validateUuid(id, 'automationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.automationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Automation "${id}" not found.`);
      }
      const updated = await this.automationRepo.update(
        id,
        { enabled: false, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('AutomationDisabled', { automation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Execution Lifecycle ─────────────────────────────────────────────────────

  /**
   * Start a new execution for an automation. Publishes AutomationExecutionStarted.
   */
  async startExecution(
    automationId: string,
    actor: string,
    tx?: any,
  ): Promise<AutomationExecution> {
    this.validateUuid(automationId, 'automationId');

    const runInTx = async (transaction: any) => {
      const automation = await this.automationRepo.findById(automationId, transaction);
      if (!automation || automation.deletedAt) {
        throw new Error(`Automation "${automationId}" not found.`);
      }
      if (!automation.enabled) {
        throw new Error(`Cannot start execution for disabled automation "${automationId}".`);
      }

      const client = transaction || prisma;
      const execution = await client.automationExecution.create({
        data: {
          automationId,
          status: 'ACTIVE' as AutomationExecutionStatus,
          startedAt: new Date(),
          createdBy: actor,
          updatedBy: actor,
        },
      });

      await eventPublisher.publish('AutomationExecutionStarted', { execution, automationId });
      return execution;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Complete an execution. Publishes AutomationExecutionCompleted.
   */
  async completeExecution(
    executionId: string,
    stepResults: Record<string, any>[],
    actor: string,
    tx?: any,
  ): Promise<AutomationExecution> {
    this.validateUuid(executionId, 'executionId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.automationExecution.findFirst({
        where: { id: executionId, deletedAt: null },
      });
      if (!existing) {
        throw new Error(`AutomationExecution "${executionId}" not found.`);
      }

      const updated = await client.automationExecution.update({
        where: { id: executionId },
        data: {
          status: 'COMPLETED' as AutomationExecutionStatus,
          completedAt: new Date(),
          stepResults: stepResults as any,
          updatedBy: actor,
        },
      });

      await eventPublisher.publish('AutomationExecutionCompleted', { execution: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Fail an execution. Publishes AutomationExecutionFailed.
   */
  async failExecution(
    executionId: string,
    reason: string,
    actor: string,
    tx?: any,
  ): Promise<AutomationExecution> {
    this.validateUuid(executionId, 'executionId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.automationExecution.findFirst({
        where: { id: executionId, deletedAt: null },
      });
      if (!existing) {
        throw new Error(`AutomationExecution "${executionId}" not found.`);
      }

      const updated = await client.automationExecution.update({
        where: { id: executionId },
        data: {
          status: 'FAILED' as AutomationExecutionStatus,
          completedAt: new Date(),
          stepResults: [{ error: reason }] as any,
          updatedBy: actor,
        },
      });

      await eventPublisher.publish('AutomationExecutionFailed', { execution: updated, reason });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Scoring ─────────────────────────────────────────────────────────────────

  /**
   * Calculate a score (0–100) for an automation based on priority and enabled state.
   */
  async calculateScore(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'automationId');
    const automation = await this.automationRepo.findById(id, tx);
    if (!automation || automation.deletedAt) {
      throw new Error(`Automation "${id}" not found.`);
    }

    const priorityScore = priorityToScore(automation.priority ?? 100);
    const steps = await this.automationRepo.findSteps(id, tx);
    const stepBonus = Math.min(steps.length * 2, 10);
    const enabledBonus = automation.enabled ? 5 : 0;

    return Math.min(priorityScore + stepBonus + enabledBonus, 100);
  }

  /**
   * Pure scoring utility: score a list of automation IDs (0–100).
   */
  scoreAutomations(ids: string[]): number {
    if (!ids || ids.length === 0) return 0;
    return Math.min(ids.length * 10, 100);
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  /**
   * Compute aggregate statistics across all non-deleted automations.
   */
  async getStatistics(tx?: any): Promise<{
    totalAutomations: number;
    enabledAutomations: number;
    disabledAutomations: number;
    triggerCounts: Record<string, number>;
    averagePriority: number;
    totalExecutions: number;
  }> {
    const stats = await this.automationRepo.calculateStatistics(tx);
    const client = tx || prisma;

    const all = await client.automation.findMany({ where: { deletedAt: null } });
    const prioritySum = all.reduce((s: number, a: Automation) => s + (a.priority ?? 100), 0);
    const totalExecutions = await client.automationExecution.count({ where: { deletedAt: null } });

    return {
      totalAutomations: stats.total,
      enabledAutomations: stats.enabled,
      disabledAutomations: stats.disabled,
      triggerCounts: stats.triggerCounts as Record<string, number>,
      averagePriority: all.length > 0 ? Math.round((prioritySum / all.length) * 10) / 10 : 0,
      totalExecutions,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  /**
   * Bulk-create automations. Returns succeeded IDs and failed entries.
   */
  async bulkCreateAutomations(
    items: Prisma.AutomationUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { name: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { name: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const a = await this.createAutomation({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(a.id);
      } catch (e: any) {
        failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('AutomationsBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete automations by IDs.
   */
  async bulkDeleteAutomations(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteAutomation(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('AutomationsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const automationService = new AutomationService();
