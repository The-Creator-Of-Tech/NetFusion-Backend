import { BaseRepository } from '../base/BaseRepository';
import { Automation, AutomationExecution, AutomationStep, AutomationTriggerType, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class AutomationRepository extends BaseRepository<Automation, Prisma.AutomationUncheckedCreateInput, Prisma.AutomationUncheckedUpdateInput> {
  constructor() {
    super('automation');
  }

  /**
   * Finds automations by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds automations by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds automations by playbook ID where not deleted.
   */
  async findByPlaybook(playbookId: string, tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { playbookId, deletedAt: null } }, tx);
  }

  /**
   * Finds automations by rule ID where not deleted.
   */
  async findByRule(ruleId: string, tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { ruleId, deletedAt: null } }, tx);
  }

  /**
   * Finds automations by trigger type where not deleted.
   */
  async findByTrigger(trigger: AutomationTriggerType, tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { trigger, deletedAt: null } }, tx);
  }

  /**
   * Finds enabled automations where not deleted.
   */
  async findEnabled(tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
  }

  /**
   * Finds disabled automations where not deleted.
   */
  async findDisabled(tx?: any): Promise<Automation[]> {
    return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
  }

  /**
   * Finds executions associated with a specific automation ID where not deleted.
   */
  async findExecutions(automationId: string, tx?: any): Promise<AutomationExecution[]> {
    const client = tx || prisma;
    return client.automationExecution.findMany({
      where: { automationId, deletedAt: null },
      orderBy: { startedAt: 'desc' },
    });
  }

  /**
   * Finds steps associated with a specific automation ID where not deleted.
   */
  async findSteps(automationId: string, tx?: any): Promise<AutomationStep[]> {
    const client = tx || prisma;
    return client.automationStep.findMany({
      where: { automationId, deletedAt: null },
      orderBy: { stepNumber: 'asc' },
    });
  }

  /**
   * Searches automation steps for a query string case-insensitively in name or description where not deleted.
   */
  async searchSteps(query: string, tx?: any): Promise<AutomationStep[]> {
    const client = tx || prisma;
    return client.automationStep.findMany({
      where: {
        deletedAt: null,
        OR: [
          { name: { contains: query, mode: 'insensitive' } },
          { description: { contains: query, mode: 'insensitive' } },
        ],
      },
      orderBy: { stepNumber: 'asc' },
    });
  }

  /**
   * Computes statistics for automations.
   */
  async calculateStatistics(tx?: any): Promise<{
    total: number;
    enabled: number;
    disabled: number;
    triggerCounts: Record<AutomationTriggerType, number>;
  }> {
    const automations = await this.findMany({ filter: { deletedAt: null } }, tx);
    const triggerCounts: Record<AutomationTriggerType, number> = {
      FINDING_CREATED: 0,
      ALERT_CREATED: 0,
      RULE_MATCHED: 0,
      PLAYBOOK_SELECTED: 0,
      TIMELINE_EVENT: 0,
      MANUAL: 0,
    };
    for (const a of automations) {
      triggerCounts[a.trigger] = (triggerCounts[a.trigger] || 0) + 1;
    }
    return {
      total: automations.length,
      enabled: automations.filter((a) => a.enabled).length,
      disabled: automations.filter((a) => !a.enabled).length,
      triggerCounts,
    };
  }
}
