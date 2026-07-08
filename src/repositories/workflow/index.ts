import { PlaybookRepository } from './playbook.repository';
import { RuleRepository } from './rule.repository';
import { AutomationRepository } from './automation.repository';
import { CaseFlowRepository } from './case-flow.repository';

export {
  PlaybookRepository,
  RuleRepository,
  AutomationRepository,
  CaseFlowRepository,
};

export const playbookRepository = new PlaybookRepository();
export const ruleRepository = new RuleRepository();
export const automationRepository = new AutomationRepository();
export const caseFlowRepository = new CaseFlowRepository();
