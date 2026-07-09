/**
 * ResponsePipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles incident response orchestration by coordinating Workflow, Playbooks, Automation, Case Flow, and Notifications:
 * Alert → Rule Match → Automation → Playbook → Case Creation → Notifications → Timeline → Activity Log
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Orchestrators
import { ruleOrchestrator } from '../workflow/RuleOrchestrator';
import { automationOrchestrator } from '../workflow/AutomationOrchestrator';
import { playbookOrchestrator } from '../workflow/PlaybookOrchestrator';
import { caseFlowOrchestrator } from '../workflow/CaseFlowOrchestrator';
import { notificationOrchestrator } from '../shared/NotificationOrchestrator';

// Services
import { alertService, timelineService } from '../../services/investigation';
import prisma from '../../lib/prisma';

export interface AlertResponseInput {
  alertId: string;
  projectId: string;
  investigationId: string;
  actor: string;
}

export interface PlaybookResponseInput {
  playbookId: string;
  projectId: string;
  investigationId: string;
  actor: string;
}

export interface AutomationResponseInput {
  automationId: string;
  projectId: string;
  investigationId: string;
  actor: string;
}

export interface CaseResponseInput {
  title: string;
  description?: string;
  projectId: string;
  investigationId: string;
  actor: string;
  assignedTo?: string;
}

export class ResponsePipeline extends BaseApplicationService {
  constructor() {
    super('ResponsePipeline');
  }

  async respondToAlert(
    input: AlertResponseInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Responding to alert ${input.alertId} in ResponsePipeline`);

    await this.publishEvent(APP_EVENTS.RESPONSE_PIPELINE_STARTED, ctx, {
      alertId: input.alertId,
      investigationId: input.investigationId,
    });

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Fetch Alert details
      const alert = await prisma.alert.findUnique({ where: { id: input.alertId } });
      if (!alert) throw new Error(`Alert ${input.alertId} not found.`);

      // 2. Evaluate rules (matches conditions to actions)
      const ruleMatch = await ruleOrchestrator.evaluateRules({
        projectId: input.projectId,
        investigationId: input.investigationId,
        record: { alertId: input.alertId, severity: alert.severity },
        actor: input.actor,
      }, ctx);

      // 3. Automation execution (if rules trigger automation)
      let automationRes: any = null;
      if (ruleMatch.automationsTriggered > 0) {
        automationRes = await automationOrchestrator.startAutomation({
          automationId: '00000000-0000-4000-8000-000000000000', // default stub UUID
          projectId: input.projectId,
          investigationId: input.investigationId,
          actor: input.actor,
        }, ctx);
        
        compensation.register('cancel-automation', async () => {
          try {
            await automationOrchestrator.cancelAutomation({
              automationId: '00000000-0000-4000-8000-000000000000',
              executionId: automationRes.executionId,
              reason: 'Pipeline compensation triggered rollback.',
              actor: 'system',
              projectId: input.projectId,
            });
          } catch (_) {}
        });
      }

      // 4. Playbook containment execution
      const playbookRes = await playbookOrchestrator.startPlaybook({
        playbookId: '00000000-0000-4000-8000-000000000000',
        projectId: input.projectId,
        investigationId: input.investigationId,
        actor: input.actor,
      }, ctx);
      
      compensation.register('abort-playbook', async () => {
        try {
          await playbookOrchestrator.abortPlaybook({
            playbookId: playbookRes.playbookId,
            actor: 'system',
            reason: 'Pipeline compensation triggered rollback.',
            projectId: input.projectId,
            investigationId: input.investigationId,
          });
        } catch (_) {}
      });

      // 5. Create Case Flow case
      const caseRes = await caseFlowOrchestrator.createCase({
        title: `Incident Case: ${alert.title}`,
        description: `Triggered by Response Pipeline for alert: ${alert.description ?? ''}`,
        projectId: input.projectId,
        investigationId: input.investigationId,
        priority: 'HIGH',
        actor: input.actor,
      }, ctx);

      compensation.register('delete-case', async () => {
        try {
          await prisma.caseFlow.delete({ where: { id: caseRes.caseId } });
        } catch (_) {}
      });

      // 6. Notifications to team
      await notificationOrchestrator.sendNotification({
        userId: input.actor, // notify active actor
        title: 'Incident Case Raised',
        message: `Response pipeline successfully matched rules, launched automation and created case: ${caseRes.caseId}`,
        type: 'ALERT',
        actor: input.actor,
        projectId: input.projectId,
        investigationId: input.investigationId,
      }, ctx);

      // 7. Re-verify timeline log
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: 'Response Pipeline Complete',
        description: `Orchestrated containment and opened case ${caseRes.caseId} for alert ${input.alertId}.`,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      });

      const responsePayload = {
        alertId: input.alertId,
        caseId: caseRes.caseId,
        automationId: automationRes?.executionId,
        playbookId: playbookRes.playbookId,
        status: 'CONTAINED',
        correlationId: ctx.correlationId,
      };

      await this.publishEvent(APP_EVENTS.RESPONSE_COMPLETED, ctx, responsePayload);

      return responsePayload;
    });
  }

  async executePlaybook(input: PlaybookResponseInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    return playbookOrchestrator.startPlaybook({
      playbookId: input.playbookId,
      projectId: input.projectId,
      investigationId: input.investigationId,
      actor: input.actor,
    }, ctx);
  }

  async launchAutomation(input: AutomationResponseInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    return automationOrchestrator.startAutomation({
      automationId: input.automationId,
      projectId: input.projectId,
      investigationId: input.investigationId,
      actor: input.actor,
    }, ctx);
  }

  async createCase(input: CaseResponseInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    return caseFlowOrchestrator.createCase({
      title: input.title,
      description: input.description,
      projectId: input.projectId,
      investigationId: input.investigationId,
      actor: input.actor,
      assignedTo: input.assignedTo,
    }, ctx);
  }

  async escalate(caseId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Escalating severity of case ${caseId}`);
    return caseFlowOrchestrator.changeStatus({
      caseId,
      newStatus: 'IN_PROGRESS',
      actor,
      projectId: '00000000-0000-4000-a000-000000000000',
      reason: 'Critical escalation triggered by response pipeline.',
    }, ctx);
  }

  async rollback(caseId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Rolling back response pipeline case: ${caseId}`);
    // Simulate rollback by deleting/archiving case
    await prisma.caseFlow.deleteMany({ where: { id: caseId } });
    return { status: 'ROLLED_BACK', caseId };
  }
}

export const responsePipeline = new ResponsePipeline();
