-- CreateEnum
CREATE TYPE "PlaybookStatus" AS ENUM ('DRAFT', 'ACTIVE', 'DEPRECATED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "RuleStatus" AS ENUM ('DRAFT', 'ACTIVE', 'DISABLED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "AutomationStatus" AS ENUM ('DRAFT', 'ACTIVE', 'DISABLED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "AutomationExecutionStatus" AS ENUM ('PENDING', 'ACTIVE', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "CaseStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'ON_HOLD', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "CaseExecutionStatus" AS ENUM ('PENDING', 'ACTIVE', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "RuleSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "CasePriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AutomationTriggerType" AS ENUM ('FINDING_CREATED', 'ALERT_CREATED', 'RULE_MATCHED', 'PLAYBOOK_SELECTED', 'TIMELINE_EVENT', 'MANUAL');

-- CreateEnum
CREATE TYPE "StepType" AS ENUM ('MANUAL', 'AUTOMATED', 'VERIFICATION', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CREATED', 'ASSIGNED', 'INVESTIGATED', 'RECOVERED', 'CLOSED', 'CREATE_ALERT', 'CREATE_TIMELINE_EVENT', 'START_PLAYBOOK', 'UPDATE_FINDING', 'UPDATE_ALERT', 'TAG_INVESTIGATION');

-- CreateTable
CREATE TABLE "playbooks" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "severity" "RuleSeverity" NOT NULL,
    "status" "PlaybookStatus" NOT NULL DEFAULT 'DRAFT',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 1,
    "category" TEXT,
    "author" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "playbooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_steps" (
    "id" UUID NOT NULL,
    "playbookId" UUID NOT NULL,
    "stepNumber" INTEGER NOT NULL,
    "stepKey" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "stepType" "StepType" NOT NULL,
    "expectedOutcome" TEXT,
    "relatedTechniques" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "relatedCVEs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "relatedIOCs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "playbook_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rules" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "severity" "RuleSeverity" NOT NULL,
    "status" "RuleStatus" NOT NULL DEFAULT 'DRAFT',
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "category" TEXT,
    "author" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rule_conditions" (
    "id" UUID NOT NULL,
    "ruleId" UUID NOT NULL,
    "field" TEXT NOT NULL,
    "operator" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "rule_conditions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rule_actions" (
    "id" UUID NOT NULL,
    "ruleId" UUID NOT NULL,
    "actionType" TEXT NOT NULL,
    "parameters" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "rule_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "automations" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID,
    "playbookId" UUID,
    "ruleId" UUID,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" "AutomationStatus" NOT NULL DEFAULT 'DRAFT',
    "trigger" "AutomationTriggerType" NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "category" TEXT,
    "author" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "automations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "automation_steps" (
    "id" UUID NOT NULL,
    "automationId" UUID NOT NULL,
    "stepNumber" INTEGER NOT NULL,
    "stepKey" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "action" "StepType" NOT NULL,
    "parameters" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "automation_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "automation_executions" (
    "id" UUID NOT NULL,
    "automationId" UUID NOT NULL,
    "status" "AutomationExecutionStatus" NOT NULL DEFAULT 'PENDING',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "stepResults" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "automation_executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_flows" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "playbookId" UUID,
    "automationId" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" "CaseStatus" NOT NULL DEFAULT 'OPEN',
    "priority" "CasePriority" NOT NULL DEFAULT 'MEDIUM',
    "findingIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "alertIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "evidenceIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "playbookIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "assignedTo" TEXT,
    "owner" TEXT,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "case_flows_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_flow_steps" (
    "id" UUID NOT NULL,
    "caseFlowId" UUID NOT NULL,
    "stepNumber" INTEGER NOT NULL,
    "stepKey" TEXT NOT NULL,
    "stepType" "StepType" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "assignedTo" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "case_flow_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_flow_executions" (
    "id" UUID NOT NULL,
    "caseFlowId" UUID NOT NULL,
    "status" "CaseExecutionStatus" NOT NULL DEFAULT 'PENDING',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "stepResults" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "case_flow_executions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "playbooks_projectId_idx" ON "playbooks"("projectId");

-- CreateIndex
CREATE INDEX "playbooks_investigationId_idx" ON "playbooks"("investigationId");

-- CreateIndex
CREATE INDEX "playbooks_status_idx" ON "playbooks"("status");

-- CreateIndex
CREATE INDEX "playbooks_priority_idx" ON "playbooks"("priority");

-- CreateIndex
CREATE INDEX "playbooks_createdAt_idx" ON "playbooks"("createdAt");

-- CreateIndex
CREATE INDEX "playbooks_updatedAt_idx" ON "playbooks"("updatedAt");

-- CreateIndex
CREATE INDEX "playbook_steps_playbookId_idx" ON "playbook_steps"("playbookId");

-- CreateIndex
CREATE INDEX "playbook_steps_createdAt_idx" ON "playbook_steps"("createdAt");

-- CreateIndex
CREATE INDEX "playbook_steps_updatedAt_idx" ON "playbook_steps"("updatedAt");

-- CreateIndex
CREATE INDEX "rules_projectId_idx" ON "rules"("projectId");

-- CreateIndex
CREATE INDEX "rules_investigationId_idx" ON "rules"("investigationId");

-- CreateIndex
CREATE INDEX "rules_status_idx" ON "rules"("status");

-- CreateIndex
CREATE INDEX "rules_priority_idx" ON "rules"("priority");

-- CreateIndex
CREATE INDEX "rules_createdAt_idx" ON "rules"("createdAt");

-- CreateIndex
CREATE INDEX "rules_updatedAt_idx" ON "rules"("updatedAt");

-- CreateIndex
CREATE INDEX "rule_conditions_ruleId_idx" ON "rule_conditions"("ruleId");

-- CreateIndex
CREATE INDEX "rule_conditions_createdAt_idx" ON "rule_conditions"("createdAt");

-- CreateIndex
CREATE INDEX "rule_conditions_updatedAt_idx" ON "rule_conditions"("updatedAt");

-- CreateIndex
CREATE INDEX "rule_actions_ruleId_idx" ON "rule_actions"("ruleId");

-- CreateIndex
CREATE INDEX "rule_actions_createdAt_idx" ON "rule_actions"("createdAt");

-- CreateIndex
CREATE INDEX "rule_actions_updatedAt_idx" ON "rule_actions"("updatedAt");

-- CreateIndex
CREATE INDEX "automations_projectId_idx" ON "automations"("projectId");

-- CreateIndex
CREATE INDEX "automations_investigationId_idx" ON "automations"("investigationId");

-- CreateIndex
CREATE INDEX "automations_playbookId_idx" ON "automations"("playbookId");

-- CreateIndex
CREATE INDEX "automations_ruleId_idx" ON "automations"("ruleId");

-- CreateIndex
CREATE INDEX "automations_status_idx" ON "automations"("status");

-- CreateIndex
CREATE INDEX "automations_priority_idx" ON "automations"("priority");

-- CreateIndex
CREATE INDEX "automations_createdAt_idx" ON "automations"("createdAt");

-- CreateIndex
CREATE INDEX "automations_updatedAt_idx" ON "automations"("updatedAt");

-- CreateIndex
CREATE INDEX "automation_steps_automationId_idx" ON "automation_steps"("automationId");

-- CreateIndex
CREATE INDEX "automation_steps_createdAt_idx" ON "automation_steps"("createdAt");

-- CreateIndex
CREATE INDEX "automation_steps_updatedAt_idx" ON "automation_steps"("updatedAt");

-- CreateIndex
CREATE INDEX "automation_executions_automationId_idx" ON "automation_executions"("automationId");

-- CreateIndex
CREATE INDEX "automation_executions_status_idx" ON "automation_executions"("status");

-- CreateIndex
CREATE INDEX "automation_executions_createdAt_idx" ON "automation_executions"("createdAt");

-- CreateIndex
CREATE INDEX "automation_executions_updatedAt_idx" ON "automation_executions"("updatedAt");

-- CreateIndex
CREATE INDEX "case_flows_projectId_idx" ON "case_flows"("projectId");

-- CreateIndex
CREATE INDEX "case_flows_investigationId_idx" ON "case_flows"("investigationId");

-- CreateIndex
CREATE INDEX "case_flows_playbookId_idx" ON "case_flows"("playbookId");

-- CreateIndex
CREATE INDEX "case_flows_automationId_idx" ON "case_flows"("automationId");

-- CreateIndex
CREATE INDEX "case_flows_status_idx" ON "case_flows"("status");

-- CreateIndex
CREATE INDEX "case_flows_priority_idx" ON "case_flows"("priority");

-- CreateIndex
CREATE INDEX "case_flows_createdAt_idx" ON "case_flows"("createdAt");

-- CreateIndex
CREATE INDEX "case_flows_updatedAt_idx" ON "case_flows"("updatedAt");

-- CreateIndex
CREATE INDEX "case_flow_steps_caseFlowId_idx" ON "case_flow_steps"("caseFlowId");

-- CreateIndex
CREATE INDEX "case_flow_steps_createdAt_idx" ON "case_flow_steps"("createdAt");

-- CreateIndex
CREATE INDEX "case_flow_steps_updatedAt_idx" ON "case_flow_steps"("updatedAt");

-- CreateIndex
CREATE INDEX "case_flow_executions_caseFlowId_idx" ON "case_flow_executions"("caseFlowId");

-- CreateIndex
CREATE INDEX "case_flow_executions_status_idx" ON "case_flow_executions"("status");

-- CreateIndex
CREATE INDEX "case_flow_executions_createdAt_idx" ON "case_flow_executions"("createdAt");

-- CreateIndex
CREATE INDEX "case_flow_executions_updatedAt_idx" ON "case_flow_executions"("updatedAt");

-- AddForeignKey
ALTER TABLE "playbooks" ADD CONSTRAINT "playbooks_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbooks" ADD CONSTRAINT "playbooks_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_steps" ADD CONSTRAINT "playbook_steps_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "playbooks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rules" ADD CONSTRAINT "rules_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rules" ADD CONSTRAINT "rules_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rule_conditions" ADD CONSTRAINT "rule_conditions_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rule_actions" ADD CONSTRAINT "rule_actions_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automations" ADD CONSTRAINT "automations_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automations" ADD CONSTRAINT "automations_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automations" ADD CONSTRAINT "automations_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "playbooks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automations" ADD CONSTRAINT "automations_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automation_steps" ADD CONSTRAINT "automation_steps_automationId_fkey" FOREIGN KEY ("automationId") REFERENCES "automations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automation_executions" ADD CONSTRAINT "automation_executions_automationId_fkey" FOREIGN KEY ("automationId") REFERENCES "automations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flows" ADD CONSTRAINT "case_flows_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flows" ADD CONSTRAINT "case_flows_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flows" ADD CONSTRAINT "case_flows_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "playbooks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flows" ADD CONSTRAINT "case_flows_automationId_fkey" FOREIGN KEY ("automationId") REFERENCES "automations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flow_steps" ADD CONSTRAINT "case_flow_steps_caseFlowId_fkey" FOREIGN KEY ("caseFlowId") REFERENCES "case_flows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_flow_executions" ADD CONSTRAINT "case_flow_executions_caseFlowId_fkey" FOREIGN KEY ("caseFlowId") REFERENCES "case_flows"("id") ON DELETE CASCADE ON UPDATE CASCADE;
