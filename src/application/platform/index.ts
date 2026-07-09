/**
 * Platform Orchestration Application Layer — Phase A5.4.6
 * ==========================================================
 * Barrel export for all Platform Orchestration Pipelines and the master PlatformOrchestrator.
 */

export {
  PlatformOrchestrator,
  platformOrchestrator,
} from './PlatformOrchestrator';

export {
  InvestigationPipeline,
  investigationPipeline,
  InvestigationPipelineInput,
  InvestigationPipelineRun,
} from './InvestigationPipeline';

export {
  CorrelationPipeline,
  correlationPipeline,
} from './CorrelationPipeline';

export {
  ResponsePipeline,
  responsePipeline,
  AlertResponseInput,
  PlaybookResponseInput,
  AutomationResponseInput,
  CaseResponseInput,
} from './ResponsePipeline';

export {
  ReportingPipeline,
  reportingPipeline,
  ReportingPipelineInput,
} from './ReportingPipeline';

export {
  MaintenancePipeline,
  maintenancePipeline,
} from './MaintenancePipeline';
