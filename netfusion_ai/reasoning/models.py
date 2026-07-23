"""
ATRE Domain Models & Schemas — NetFusion IL-9
===============================================
Core data structures for the AI Threat Reasoning Engine.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class QuestionType(str, Enum):
    WHAT_HAPPENED = "WHAT_HAPPENED"
    WHY_HAPPENED = "WHY_HAPPENED"
    WHAT_AFFECTED = "WHAT_AFFECTED"
    ASSETS_AT_RISK = "ASSETS_AT_RISK"
    EVIDENCE_SUPPORT = "EVIDENCE_SUPPORT"
    VULNERABILITIES_INVOLVED = "VULNERABILITIES_INVOLVED"
    ATTACK_TECHNIQUES = "ATTACK_TECHNIQUES"
    CAMPAIGNS_MATCH = "CAMPAIGNS_MATCH"
    THREAT_ACTOR_LIKELY = "THREAT_ACTOR_LIKELY"
    MALWARE_FAMILIES = "MALWARE_FAMILIES"
    SHOW_ATTACK_CHAIN = "SHOW_ATTACK_CHAIN"
    SHOW_CONFIDENCE = "SHOW_CONFIDENCE"
    RECOMMEND_INVESTIGATION = "RECOMMEND_INVESTIGATION"
    RECOMMEND_CONTAINMENT = "RECOMMEND_CONTAINMENT"
    RECOMMEND_REMEDIATION = "RECOMMEND_REMEDIATION"
    EXEC_SUMMARY = "EXEC_SUMMARY"
    SOC_REPORT = "SOC_REPORT"
    IR_REPORT = "IR_REPORT"
    ANALYST_NOTES = "ANALYST_NOTES"
    GENERAL_QUERY = "GENERAL_QUERY"


class HypothesisStatus(str, Enum):
    LIKELY = "LIKELY"
    COMPETING = "COMPETING"
    DISMISSED = "DISMISSED"
    CONTRADICTED = "CONTRADICTED"


class ContradictionSeverity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ContradictionType(str, Enum):
    CONFLICTING_IOCS = "Conflicting IOCs"
    CONFLICTING_MALWARE = "Conflicting malware"
    CONFLICTING_CAMPAIGNS = "Conflicting campaigns"
    IMPOSSIBLE_TIMELINES = "Impossible timelines"
    DISCONNECTED_EVIDENCE = "Disconnected evidence"
    CIRCULAR_REASONING = "Circular reasoning"
    MISSING_PREREQUISITES = "Missing prerequisites"


class RecommendationCategory(str, Enum):
    IMMEDIATE_ACTIONS = "Immediate Actions"
    CONTAINMENT = "Containment"
    MITIGATION = "Mitigation"
    DETECTION_IMPROVEMENTS = "Detection Improvements"
    MONITORING_SUGGESTIONS = "Monitoring Suggestions"
    MISSING_EVIDENCE = "Missing Evidence"
    PRIORITY_TASKS = "Priority Tasks"
    FALSE_POSITIVE_CHECKS = "False Positive Checks"


class RecommendationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TimelineSource(str, Enum):
    PACKETS = "Packets"
    FLOWS = "Flows"
    ALERTS = "Alerts"
    LOGS = "Logs"
    IOC_SIGHTINGS = "IOC Sightings"
    WORKFLOW_EVENTS = "Workflow Events"
    INVESTIGATION_EVENTS = "Investigation Events"


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


class ReasoningRequest(BaseModel):
    user_question: str
    question_type: Optional[QuestionType] = None
    context_node_ids: List[str] = Field(default_factory=list)
    investigation_id: Optional[str] = None
    time_range: Optional[Dict[str, Any]] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class CIILResolvedEntity(BaseModel):
    canonical_id: str
    entity_type: str
    display_name: str
    external_identifiers: List[Dict[str, str]] = Field(default_factory=list)
    aliases: List[str] = Field(default_factory=list)
    confidence: float = 1.0


class GraphEvidence(BaseModel):
    evidence_id: str
    source_type: str  # e.g., IOC, CVE, KEV, EPSS, ATTACK, CAPEC, CWE, Alert, Log
    node_id: str
    label: str
    description: str
    confidence_score: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)
    recency: Optional[str] = None
    source_feed: str = "UTKG"


class RelationshipRanking(BaseModel):
    source_id: str
    target_id: str
    edge_type: str
    relationship_strength: float
    graph_distance: int
    evidence_count: int
    score: float


class AttackChainStage(BaseModel):
    stage_number: int
    tactic: str  # Initial Access, Execution, etc.
    attack_ids: List[str] = Field(default_factory=list)
    capec_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    ioc_ids: List[str] = Field(default_factory=list)
    description: str
    confidence: float = 0.8


class AttackChain(BaseModel):
    stages: List[AttackChainStage] = Field(default_factory=list)
    total_stages: int = 0
    overall_confidence: float = 0.0
    summary: str = ""


class Hypothesis(BaseModel):
    hypothesis_id: str
    title: str
    description: str
    confidence_score: float
    status: HypothesisStatus
    supported_by: List[GraphEvidence] = Field(default_factory=list)
    contradicted_by: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)


class ConfidenceBreakdown(BaseModel):
    edge_confidence: float = 0.0
    evidence_count_factor: float = 0.0
    ioc_reputation_score: float = 0.0
    epss_score: float = 0.0
    kev_factor: float = 0.0
    cvss_score: float = 0.0
    relationship_strength: float = 0.0
    feed_trust_score: float = 0.0
    recency_factor: float = 0.0
    analyst_confirmation_factor: float = 0.0
    overall_score: float = 0.0  # 0.0 - 1.0 (or 0-100%)
    formula_explanation: str = ""


class Contradiction(BaseModel):
    contradiction_id: str
    type: ContradictionType
    description: str
    conflicting_evidence: List[str] = Field(default_factory=list)
    severity: ContradictionSeverity
    explanation: str


class RiskAssessment(BaseModel):
    asset_risk: float = 0.0
    host_risk: float = 0.0
    investigation_risk: float = 0.0
    campaign_severity: float = 0.0
    threat_actor_confidence: float = 0.0
    attack_likelihood: float = 0.0
    business_impact: float = 0.0
    weighted_total_score: float = 0.0
    weighting_config: Dict[str, float] = Field(default_factory=dict)


class Recommendation(BaseModel):
    rec_id: str
    category: RecommendationCategory
    title: str
    description: str
    priority: RecommendationPriority
    reasoning: str
    target_entities: List[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: str
    source: TimelineSource
    title: str
    description: str
    entity_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    severity: str = "INFO"


class Timeline(BaseModel):
    events: List[TimelineEvent] = Field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_events: int = 0


class MemoryItem(BaseModel):
    memory_id: str
    investigation_id: str
    pattern_type: str
    analyst_confirmations: List[str] = Field(default_factory=list)
    dismissed_hypotheses: List[str] = Field(default_factory=list)
    known_false_positives: List[str] = Field(default_factory=list)
    lessons_learned: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    timestamp: str = ""


class ReasoningPlan(BaseModel):
    question_type: QuestionType
    primary_intent: str
    extracted_entities: List[str]
    expansion_depth: int = 2
    target_node_types: List[str] = Field(default_factory=list)
    hypothesis_strategy: str = "competing"


class ReasoningTraceStep(BaseModel):
    step_number: int
    stage_name: str
    description: str
    input_data: Dict[str, Any] = Field(default_factory=dict)
    output_summary: str = ""
    timestamp: float = 0.0


class ExplanationResult(BaseModel):
    executive_summary: str
    soc_summary: str
    ir_summary: str
    technical_analysis: str
    evidence_table: List[Dict[str, Any]] = Field(default_factory=list)
    confidence_explanation: str
    reasoning_trace: List[str] = Field(default_factory=list)
    format: ReportFormat = ReportFormat.MARKDOWN
    formatted_output: str = ""


class ReasoningResult(BaseModel):
    request: ReasoningRequest
    intent: QuestionType
    resolved_entities: List[CIILResolvedEntity] = Field(default_factory=list)
    expanded_subgraph: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[GraphEvidence] = Field(default_factory=list)
    relationship_rankings: List[RelationshipRanking] = Field(default_factory=list)
    attack_chain: AttackChain = Field(default_factory=AttackChain)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    confidence: ConfidenceBreakdown = Field(default_factory=ConfidenceBreakdown)
    contradictions: List[Contradiction] = Field(default_factory=list)
    risk_assessment: RiskAssessment = Field(default_factory=RiskAssessment)
    recommendations: List[Recommendation] = Field(default_factory=list)
    timeline: Timeline = Field(default_factory=Timeline)
    memory_hits: List[MemoryItem] = Field(default_factory=list)
    explanation: ExplanationResult = Field(
        default_factory=lambda: ExplanationResult(
            executive_summary="",
            soc_summary="",
            ir_summary="",
            technical_analysis="",
            confidence_explanation="",
        )
    )
    trace_steps: List[ReasoningTraceStep] = Field(default_factory=list)
