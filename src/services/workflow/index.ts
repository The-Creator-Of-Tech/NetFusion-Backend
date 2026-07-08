/**
 * Workflow Domain Services — Phase A5.3.6
 * ==========================================
 * Barrel export for all workflow domain service singletons and classes.
 */

export { PlaybookService, playbookService } from './playbook.service';
export { RuleService, ruleService, VALID_OPERATORS } from './rule.service';
export { AutomationService, automationService, VALID_TRIGGERS } from './automation.service';
export { CaseFlowService, caseFlowService, VALID_PRIORITIES, VALID_STATUSES } from './case-flow.service';
