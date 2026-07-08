import { BaseRepository } from '../base/BaseRepository';
import { Rule, RuleCondition, RuleAction, RuleSeverity, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class RuleRepository extends BaseRepository<Rule, Prisma.RuleUncheckedCreateInput, Prisma.RuleUncheckedUpdateInput> {
  constructor() {
    super('rule');
  }

  /**
   * Finds rules by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds rules by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds rules by category where not deleted.
   */
  async findByCategory(category: string, tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { category, deletedAt: null } }, tx);
  }

  /**
   * Finds rules by severity where not deleted.
   */
  async findBySeverity(severity: RuleSeverity, tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { severity, deletedAt: null } }, tx);
  }

  /**
   * Finds enabled rules where not deleted.
   */
  async findEnabled(tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
  }

  /**
   * Finds disabled rules where not deleted.
   */
  async findDisabled(tx?: any): Promise<Rule[]> {
    return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
  }

  /**
   * Finds conditions associated with a specific rule ID where not deleted.
   */
  async findConditions(ruleId: string, tx?: any): Promise<RuleCondition[]> {
    const client = tx || prisma;
    return client.ruleCondition.findMany({
      where: { ruleId, deletedAt: null },
    });
  }

  /**
   * Finds actions associated with a specific rule ID where not deleted.
   */
  async findActions(ruleId: string, tx?: any): Promise<RuleAction[]> {
    const client = tx || prisma;
    return client.ruleAction.findMany({
      where: { ruleId, deletedAt: null },
    });
  }

  /**
   * Searches rule conditions for a query string case-insensitively in field or value where not deleted.
   */
  async searchConditions(query: string, tx?: any): Promise<RuleCondition[]> {
    const client = tx || prisma;
    return client.ruleCondition.findMany({
      where: {
        deletedAt: null,
        OR: [
          { field: { contains: query, mode: 'insensitive' } },
          { value: { contains: query, mode: 'insensitive' } },
        ],
      },
    });
  }

  /**
   * Searches rule actions for a query string case-insensitively in actionType where not deleted.
   */
  async searchActions(query: string, tx?: any): Promise<RuleAction[]> {
    const client = tx || prisma;
    return client.ruleAction.findMany({
      where: {
        actionType: { contains: query, mode: 'insensitive' },
        deletedAt: null,
      },
    });
  }

  /**
   * Finds a rule condition by ID where not deleted.
   */
  async findCondition(conditionId: string, tx?: any): Promise<RuleCondition | null> {
    const client = tx || prisma;
    return client.ruleCondition.findFirst({
      where: { id: conditionId, deletedAt: null },
    });
  }

  /**
   * Finds a rule action by ID where not deleted.
   */
  async findAction(actionId: string, tx?: any): Promise<RuleAction | null> {
    const client = tx || prisma;
    return client.ruleAction.findFirst({
      where: { id: actionId, deletedAt: null },
    });
  }

  /**
   * Computes statistics for rules.
   */
  async calculateStatistics(tx?: any): Promise<{
    total: number;
    enabled: number;
    disabled: number;
    severityCounts: Record<RuleSeverity, number>;
  }> {
    const rules = await this.findMany({ filter: { deletedAt: null } }, tx);
    const severityCounts: Record<RuleSeverity, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };
    for (const r of rules) {
      severityCounts[r.severity] = (severityCounts[r.severity] || 0) + 1;
    }
    return {
      total: rules.length,
      enabled: rules.filter((r) => r.enabled).length,
      disabled: rules.filter((r) => !r.enabled).length,
      severityCounts,
    };
  }
}
