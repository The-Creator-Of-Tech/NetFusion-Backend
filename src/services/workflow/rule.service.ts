/**
 * RuleService — Phase A5.3.6
 * ============================
 * Business logic for detection Rule lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for Rules, RuleConditions, and RuleActions
 * - Category, severity, and status lookups
 * - Rule evaluation (condition matching)
 * - Action execution logging
 * - Scoring and statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { ruleRepository } from '../../repositories/workflow';
import prisma from '../../lib/prisma';
import {
  Rule,
  RuleCondition,
  RuleAction,
  RuleSeverity,
  RuleStatus,
  Prisma,
} from '@prisma/client';

// ── Severity score map ────────────────────────────────────────────────────────
const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 100,
  HIGH:     75,
  MEDIUM:   50,
  LOW:      25,
};

// ── Valid rule operators ──────────────────────────────────────────────────────
export const VALID_OPERATORS = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'contains', 'startsWith', 'endsWith', 'in', 'notIn'];

export class RuleService extends BaseService {
  constructor(private readonly ruleRepo = ruleRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  /**
   * Create a new rule. Validates required fields and publishes RuleCreated.
   */
  async createRule(
    data: Prisma.RuleUncheckedCreateInput,
    tx?: any,
  ): Promise<Rule> {
    this.validateRequired(data as any, ['name', 'severity', 'createdBy', 'updatedBy']);
    if (!data.projectId) {
      throw new Error('Validation failed: projectId is required.');
    }

    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validSeverities.includes(String(data.severity).toUpperCase())) {
      throw new Error(`Validation failed: severity "${data.severity}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const rule = await this.ruleRepo.create(data, transaction);
      await eventPublisher.publish('RuleCreated', { rule });
      return rule;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  /**
   * Update a rule by UUID. Publishes RuleUpdated.
   */
  async updateRule(
    id: string,
    data: Prisma.RuleUncheckedUpdateInput,
    tx?: any,
  ): Promise<Rule> {
    this.validateUuid(id, 'ruleId');

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${id}" not found.`);
      }

      if (data.severity !== undefined) {
        const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        if (!validSeverities.includes(String(data.severity).toUpperCase())) {
          throw new Error(`Validation failed: severity "${data.severity}" is not valid.`);
        }
      }

      const updated = await this.ruleRepo.update(id, data, transaction);
      await eventPublisher.publish('RuleUpdated', { rule: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  /**
   * Soft-delete a rule by UUID. Publishes RuleDeleted.
   */
  async deleteRule(id: string, actor: string, tx?: any): Promise<Rule> {
    this.validateUuid(id, 'ruleId');

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${id}" not found.`);
      }
      const deleted = await this.ruleRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('RuleDeleted', { rule: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  /** Find rules by project UUID. */
  async findByProject(projectId: string, tx?: any): Promise<Rule[]> {
    this.validateUuid(projectId, 'projectId');
    return this.ruleRepo.findByProject(projectId, tx);
  }

  /** Find rules by investigation UUID. */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Rule[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.ruleRepo.findByInvestigation(investigationId, tx);
  }

  /** Find rules by category (non-empty). */
  async findByCategory(category: string, tx?: any): Promise<Rule[]> {
    if (!category || !category.trim()) {
      throw new Error('Validation failed: category must not be empty.');
    }
    return this.ruleRepo.findByCategory(category.trim(), tx);
  }

  /** Find rules by severity. */
  async findBySeverity(severity: RuleSeverity, tx?: any): Promise<Rule[]> {
    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validSeverities.includes(String(severity).toUpperCase())) {
      throw new Error(`Validation failed: severity "${severity}" is not valid.`);
    }
    return this.ruleRepo.findBySeverity(severity, tx);
  }

  /** Find all enabled rules. */
  async findEnabled(tx?: any): Promise<Rule[]> {
    return this.ruleRepo.findEnabled(tx);
  }

  /** Find all disabled rules. */
  async findDisabled(tx?: any): Promise<Rule[]> {
    return this.ruleRepo.findDisabled(tx);
  }

  /** Find conditions for a rule UUID. */
  async findConditions(ruleId: string, tx?: any): Promise<RuleCondition[]> {
    this.validateUuid(ruleId, 'ruleId');
    return this.ruleRepo.findConditions(ruleId, tx);
  }

  /** Find actions for a rule UUID. */
  async findActions(ruleId: string, tx?: any): Promise<RuleAction[]> {
    this.validateUuid(ruleId, 'ruleId');
    return this.ruleRepo.findActions(ruleId, tx);
  }

  /** Search conditions by keyword. */
  async searchConditions(query: string, tx?: any): Promise<RuleCondition[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.ruleRepo.searchConditions(query.trim(), tx);
  }

  /** Search actions by keyword. */
  async searchActions(query: string, tx?: any): Promise<RuleAction[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.ruleRepo.searchActions(query.trim(), tx);
  }

  /** Find a single condition by UUID. */
  async findCondition(conditionId: string, tx?: any): Promise<RuleCondition | null> {
    this.validateUuid(conditionId, 'conditionId');
    return this.ruleRepo.findCondition(conditionId, tx);
  }

  /** Find a single action by UUID. */
  async findAction(actionId: string, tx?: any): Promise<RuleAction | null> {
    this.validateUuid(actionId, 'actionId');
    return this.ruleRepo.findAction(actionId, tx);
  }

  // ── Condition & Action Management ───────────────────────────────────────────

  /**
   * Add a condition to an existing rule. Publishes RuleConditionAdded.
   */
  async addCondition(
    ruleId: string,
    data: { field: string; operator: string; value: string; createdBy: string; updatedBy: string },
    tx?: any,
  ): Promise<RuleCondition> {
    this.validateUuid(ruleId, 'ruleId');

    if (!data.field || !data.field.trim()) {
      throw new Error('Validation failed: field must not be empty.');
    }
    if (!data.operator || !data.operator.trim()) {
      throw new Error('Validation failed: operator must not be empty.');
    }
    if (!data.value || !data.value.trim()) {
      throw new Error('Validation failed: value must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(ruleId, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${ruleId}" not found.`);
      }
      const client = transaction || prisma;
      const condition = await client.ruleCondition.create({
        data: { ruleId, ...data },
      });
      await eventPublisher.publish('RuleConditionAdded', { condition, ruleId });
      return condition;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Add an action to an existing rule. Publishes RuleActionAdded.
   */
  async addAction(
    ruleId: string,
    data: { actionType: string; parameters?: Record<string, any>; createdBy: string; updatedBy: string },
    tx?: any,
  ): Promise<RuleAction> {
    this.validateUuid(ruleId, 'ruleId');

    if (!data.actionType || !data.actionType.trim()) {
      throw new Error('Validation failed: actionType must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(ruleId, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${ruleId}" not found.`);
      }
      const client = transaction || prisma;
      const action = await client.ruleAction.create({
        data: { ruleId, ...data, parameters: data.parameters ?? {} },
      });
      await eventPublisher.publish('RuleActionAdded', { action, ruleId });
      return action;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Rule Evaluation ─────────────────────────────────────────────────────────

  /**
   * Evaluate a rule against a data record.
   * Returns true if all conditions match (AND logic). Publishes RuleEvaluated.
   */
  async evaluateRule(
    ruleId: string,
    record: Record<string, any>,
    tx?: any,
  ): Promise<{ matched: boolean; conditionResults: { conditionId: string; field: string; matched: boolean }[] }> {
    this.validateUuid(ruleId, 'ruleId');

    const rule = await this.ruleRepo.findById(ruleId, tx);
    if (!rule || rule.deletedAt) {
      throw new Error(`Rule "${ruleId}" not found.`);
    }
    if (!rule.enabled) {
      return { matched: false, conditionResults: [] };
    }

    const conditions = await this.ruleRepo.findConditions(ruleId, tx);
    const conditionResults = conditions.map((c) => {
      const fieldValue = record[c.field];
      let matched = false;

      switch (c.operator) {
        case 'eq':         matched = String(fieldValue) === c.value; break;
        case 'neq':        matched = String(fieldValue) !== c.value; break;
        case 'gt':         matched = Number(fieldValue) > Number(c.value); break;
        case 'gte':        matched = Number(fieldValue) >= Number(c.value); break;
        case 'lt':         matched = Number(fieldValue) < Number(c.value); break;
        case 'lte':        matched = Number(fieldValue) <= Number(c.value); break;
        case 'contains':   matched = String(fieldValue).includes(c.value); break;
        case 'startsWith': matched = String(fieldValue).startsWith(c.value); break;
        case 'endsWith':   matched = String(fieldValue).endsWith(c.value); break;
        default:           matched = false;
      }

      return { conditionId: c.id, field: c.field, matched };
    });

    const matched = conditionResults.length > 0 && conditionResults.every((r) => r.matched);
    await eventPublisher.publish('RuleEvaluated', { ruleId, matched, conditionResults });
    return { matched, conditionResults };
  }

  /**
   * Enable a rule. Publishes RuleEnabled.
   */
  async enableRule(id: string, actor: string, tx?: any): Promise<Rule> {
    this.validateUuid(id, 'ruleId');

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${id}" not found.`);
      }
      const updated = await this.ruleRepo.update(id, { enabled: true, updatedBy: actor }, transaction);
      await eventPublisher.publish('RuleEnabled', { rule: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Disable a rule. Publishes RuleDisabled.
   */
  async disableRule(id: string, actor: string, tx?: any): Promise<Rule> {
    this.validateUuid(id, 'ruleId');

    const runInTx = async (transaction: any) => {
      const existing = await this.ruleRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Rule "${id}" not found.`);
      }
      const updated = await this.ruleRepo.update(id, { enabled: false, updatedBy: actor }, transaction);
      await eventPublisher.publish('RuleDisabled', { rule: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Scoring ─────────────────────────────────────────────────────────────────

  /**
   * Calculate a risk score (0–100) for a rule based on severity and condition count.
   */
  async calculateRiskScore(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'ruleId');
    const rule = await this.ruleRepo.findById(id, tx);
    if (!rule || rule.deletedAt) {
      throw new Error(`Rule "${id}" not found.`);
    }

    const severityScore = SEVERITY_SCORE[String(rule.severity ?? 'MEDIUM')] ?? 50;
    const conditions = await this.ruleRepo.findConditions(id, tx);
    const conditionBonus = Math.min(conditions.length * 5, 20);
    const enabledBonus = rule.enabled ? 5 : 0;

    return Math.min(severityScore + conditionBonus + enabledBonus, 100);
  }

  /**
   * Pure scoring utility: score a list of rule IDs (0–100).
   */
  scoreRules(ids: string[]): number {
    if (!ids || ids.length === 0) return 0;
    return Math.min(ids.length * 10, 100);
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  /**
   * Compute aggregate statistics across all non-deleted rules.
   */
  async getStatistics(tx?: any): Promise<{
    totalRules: number;
    enabledRules: number;
    disabledRules: number;
    severityCounts: Record<string, number>;
    averagePriority: number;
  }> {
    const stats = await this.ruleRepo.calculateStatistics(tx);
    const client = tx || prisma;

    const all = await client.rule.findMany({ where: { deletedAt: null } });
    const prioritySum = all.reduce((s: number, r: Rule) => s + (r.priority ?? 100), 0);

    return {
      totalRules: stats.total,
      enabledRules: stats.enabled,
      disabledRules: stats.disabled,
      severityCounts: stats.severityCounts as Record<string, number>,
      averagePriority: all.length > 0 ? Math.round((prioritySum / all.length) * 10) / 10 : 0,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  /**
   * Bulk-create rules. Returns succeeded IDs and failed entries.
   */
  async bulkCreateRules(
    items: Prisma.RuleUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { name: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { name: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const r = await this.createRule({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(r.id);
      } catch (e: any) {
        failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('RulesBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete rules by IDs.
   */
  async bulkDeleteRules(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteRule(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('RulesBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const ruleService = new RuleService();
