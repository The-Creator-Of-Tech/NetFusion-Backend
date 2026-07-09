/**
 * Knowledge Application Layer — Phase A5.4.3
 * ==============================================
 * Barrel export for all Knowledge Orchestrators.
 *
 * Architecture:
 *   Router → Knowledge Orchestrators (this) → Service Layer → Repository → Prisma → PostgreSQL
 */

export {
  KnowledgeOrchestrator,
  knowledgeOrchestrator,
  KnowledgeCorrelateFindingInput,
  KnowledgeCorrelateAssetInput,
  KnowledgeCorrelateInvestigationInput,
  ThreatContextInput,
  ThreatContext,
  ThreatSummaryInput,
  ThreatSummary,
  GenerateRecommendationsInput,
  RecommendationSet,
} from './KnowledgeOrchestrator';

export {
  MitreOrchestrator,
  mitreOrchestrator,
  MapTechniqueInput,
  MapTacticInput,
  FindMitigationsInput,
  FindDetectionsInput,
  FindRelatedTechniquesInput,
  TechniqueMappingResult,
} from './MitreOrchestrator';

export {
  CveOrchestrator,
  cveOrchestrator,
  FindAffectedProductsInput,
  CalculateRiskInput,
  FindExploitabilityInput,
  FindRelatedIoCsInput,
  FindCveMitigationsInput,
  PrioritizeCvesInput,
  CvePriority,
} from './CveOrchestrator';

export {
  IocOrchestrator,
  iocOrchestrator,
  EnrichIOCInput,
  CorrelateIOCInput,
  CalculateConfidenceInput,
  LookupReputationInput,
  FindRelatedThreatsInput,
  IOCEnrichmentResult,
} from './IocOrchestrator';

export {
  ThreatOrchestrator,
  threatOrchestrator,
  IdentifyThreatActorInput,
  IdentifyCampaignInput,
  AssociateTechniquesInput,
  AssociateIOCsInput,
  AssociateCVEsInput,
  CalculateThreatScoreInput,
  ThreatActorResult,
  ThreatScoreResult,
} from './ThreatOrchestrator';

export {
  CorrelationOrchestrator,
  correlationOrchestrator,
  CorrelateFindingInput,
  CorrelateAssetInput,
  CorrelateInvestigationInput,
  CorrelationResult,
  KnowledgeGraph,
  KnowledgeGraphNode,
  KnowledgeGraphEdge,
} from './CorrelationOrchestrator';
