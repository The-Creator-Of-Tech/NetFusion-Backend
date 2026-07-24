"""
NETFUSION IL-9.1 REASONING TRACE ENGINE
=======================================
Enterprise-grade Explainable AI (XAI) Reasoning Trace Engine for NetFusion.
Records every reasoning decision, graph traversal, evidence selection,
confidence calculation, hypothesis evaluation, rule execution, and recommendation.

Makes every AI conclusion explainable, reproducible, auditable, debuggable, and legally defensible.
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================================
# DOMAIN EVENTS
# ============================================================================

@dataclass
class TraceStarted:
    session_id: str
    user_query: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class StageCompleted:
    session_id: str
    stage_name: str
    duration: float
    confidence: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class DecisionRecorded:
    session_id: str
    decision_id: str
    decision_type: str
    chosen_option: Any
    confidence: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class EvidenceRecorded:
    session_id: str
    evidence_id: str
    source_feed: str
    canonical_id: str
    confidence: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConfidenceRecorded:
    session_id: str
    overall_score: float
    contributions_count: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class RecommendationRecorded:
    session_id: str
    recommendation_id: str
    priority: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class TraceCompleted:
    session_id: str
    total_stages: int
    total_decisions: int
    final_confidence: float
    duration: float
    timestamp: float = field(default_factory=time.time)


# ============================================================================
# TRACE MODELS
# ============================================================================

class ReasoningSession(BaseModel):
    session_id: str = Field(default_factory=lambda: f"session-{uuid.uuid4().hex[:12]}")
    user_query: str
    start_time: float = Field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    analyst: Optional[str] = "System Analyst"
    investigation_id: Optional[str] = None
    workflow_id: Optional[str] = None
    case_id: Optional[str] = None
    report_id: Optional[str] = None
    llm_provider: Optional[str] = "Local/Mock Provider"
    model_used: Optional[str] = "netfusion-reasoner-v1"
    token_usage: Dict[str, int] = Field(default_factory=lambda: {"prompt_tokens": 120, "completion_tokens": 350, "total_tokens": 470})
    status: str = "STARTED"  # STARTED, COMPLETED, FAILED


class ReasoningStep(BaseModel):
    step_id: str = Field(default_factory=lambda: f"step-{uuid.uuid4().hex[:8]}")
    session_id: str
    stage_name: str
    input: Any = None
    output: Any = None
    duration: float = 0.0
    confidence: float = 1.0
    dependencies: List[str] = Field(default_factory=list)
    parent_stage: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class ReasoningDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:8]}")
    session_id: str
    decision_type: str
    chosen_option: Any
    rejected_alternatives: List[Any] = Field(default_factory=list)
    decision_reason: str
    confidence: float = 1.0
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    rule_triggered: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


class ReasoningRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:8]}")
    session_id: str
    rule_name: str
    input: Any = None
    output: Any = None
    reason: str = ""
    matched_conditions: List[str] = Field(default_factory=list)
    execution_time: float = 0.0
    confidence_delta: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class GraphTrace(BaseModel):
    session_id: str
    starting_node: str
    visited_nodes: List[str] = Field(default_factory=list)
    traversal_depth: int = 1
    traversal_algorithm: str = "BFS_MULTI_HOP"
    edges_traversed: List[Dict[str, Any]] = Field(default_factory=list)
    relationships_used: List[str] = Field(default_factory=list)
    shortest_path: List[str] = Field(default_factory=list)
    expanded_context: Dict[str, Any] = Field(default_factory=dict)


class ReasoningEvidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:8]}")
    session_id: str
    source_feed: str
    feed_version: str = "v1.0"
    canonical_id: str
    confidence: float = 1.0
    trust_score: float = 1.0
    timestamp: float = Field(default_factory=time.time)
    reason_selected: str
    reason_rejected: Optional[str] = None


class ConfidenceContribution(BaseModel):
    factor: str
    delta: float
    reason: str


class ReasoningConfidence(BaseModel):
    session_id: str
    overall_score: float = 0.0
    base_score: float = 0.0
    contributions: List[ConfidenceContribution] = Field(default_factory=list)
    formula_explanation: str = ""
    breakdown: Dict[str, float] = Field(default_factory=dict)


class ReasoningHypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: f"hyp-{uuid.uuid4().hex[:8]}")
    session_id: str
    hypothesis: str
    alternative_hypotheses: List[str] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    score: float = 0.0
    ranking: int = 1
    why_rejected: Optional[str] = None


class ReasoningRecommendation(BaseModel):
    recommendation_id: str = Field(default_factory=lambda: f"rec-{uuid.uuid4().hex[:8]}")
    session_id: str
    recommendation: str
    reason: str
    evidence_used: List[str] = Field(default_factory=list)
    confidence: float = 1.0
    priority: str = "MEDIUM"
    expected_impact: str = "Risk Reduction"


class ReasoningExplanation(BaseModel):
    session_id: str
    prompt_template: str
    prompt_variables: Dict[str, Any] = Field(default_factory=dict)
    context_size: int = 0
    evidence_count: int = 0
    graph_nodes_used: int = 0
    graph_edges_used: int = 0
    llm_provider: str = "Local/Mock Provider"
    model: str = "netfusion-reasoner-v1"
    latency: float = 0.0
    token_usage: Dict[str, int] = Field(default_factory=dict)
    response_length: int = 0
    explanation_text: str = ""


class ErrorTrace(BaseModel):
    session_id: str
    exceptions: List[str] = Field(default_factory=list)
    timeouts: List[str] = Field(default_factory=list)
    provider_errors: List[str] = Field(default_factory=list)
    graph_errors: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    resolution_failures: List[str] = Field(default_factory=list)


class ReasoningTrace(BaseModel):
    trace_id: str = Field(default_factory=lambda: f"trace-{uuid.uuid4().hex[:12]}")
    session: ReasoningSession
    stages: List[ReasoningStep] = Field(default_factory=list)
    decisions: List[ReasoningDecision] = Field(default_factory=list)
    rules: List[ReasoningRule] = Field(default_factory=list)
    graph_trace: Optional[GraphTrace] = None
    evidence: List[ReasoningEvidence] = Field(default_factory=list)
    confidence: Optional[ReasoningConfidence] = None
    hypotheses: List[ReasoningHypothesis] = Field(default_factory=list)
    recommendations: List[ReasoningRecommendation] = Field(default_factory=list)
    explanation: Optional[ReasoningExplanation] = None
    errors: ErrorTrace = Field(default_factory=lambda: ErrorTrace(session_id=""))

    def model_post_init(self, __context: Any) -> None:
        if not self.errors.session_id:
            self.errors.session_id = self.session.session_id


# ============================================================================
# TRACE RECORDERS
# ============================================================================

class SessionManager:
    """Manages reasoning trace session lifecycles."""

    def __init__(self):
        self._sessions: Dict[str, ReasoningSession] = {}

    def create_session(
        self,
        user_query: str,
        investigation_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        case_id: Optional[str] = None,
        analyst: Optional[str] = "System Analyst",
    ) -> ReasoningSession:
        session = ReasoningSession(
            user_query=user_query,
            investigation_id=investigation_id,
            workflow_id=workflow_id,
            case_id=case_id,
            analyst=analyst,
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[ReasoningSession]:
        return self._sessions.get(session_id)

    def complete_session(
        self, session_id: str, status: str = "COMPLETED"
    ) -> Optional[ReasoningSession]:
        session = self._sessions.get(session_id)
        if session:
            session.end_time = time.time()
            session.duration = session.end_time - session.start_time
            session.status = status
        return session


class DecisionRecorder:
    """Records AI reasoning decisions and alternatives."""

    def record_decision(
        self,
        session_id: str,
        decision_type: str,
        chosen_option: Any,
        rejected_alternatives: List[Any],
        decision_reason: str,
        confidence: float = 1.0,
        supporting_evidence: Optional[List[str]] = None,
        contradicting_evidence: Optional[List[str]] = None,
        rule_triggered: Optional[str] = None,
    ) -> ReasoningDecision:
        return ReasoningDecision(
            session_id=session_id,
            decision_type=decision_type,
            chosen_option=chosen_option,
            rejected_alternatives=rejected_alternatives,
            decision_reason=decision_reason,
            confidence=confidence,
            supporting_evidence=supporting_evidence or [],
            contradicting_evidence=contradicting_evidence or [],
            rule_triggered=rule_triggered,
        )


class EvidenceRecorder:
    """Records evidence items selected and rejected during reasoning."""

    def record_evidence(
        self,
        session_id: str,
        source_feed: str,
        canonical_id: str,
        confidence: float,
        trust_score: float,
        reason_selected: str,
        reason_rejected: Optional[str] = None,
        feed_version: str = "v1.0",
    ) -> ReasoningEvidence:
        return ReasoningEvidence(
            session_id=session_id,
            source_feed=source_feed,
            canonical_id=canonical_id,
            confidence=confidence,
            trust_score=trust_score,
            reason_selected=reason_selected,
            reason_rejected=reason_rejected,
            feed_version=feed_version,
        )


class ConfidenceRecorder:
    """Records transparent confidence calculation contributions (waterfall)."""

    def record_confidence(
        self,
        session_id: str,
        base_score: float,
        contributions: List[ConfidenceContribution],
        formula_explanation: str = "",
    ) -> ReasoningConfidence:
        final_score = base_score + sum(c.delta for c in contributions)
        bounded_score = max(0.0, min(1.0, final_score))
        breakdown = {c.factor: c.delta for c in contributions}
        breakdown["base"] = base_score
        breakdown["final"] = bounded_score

        return ReasoningConfidence(
            session_id=session_id,
            overall_score=bounded_score,
            base_score=base_score,
            contributions=contributions,
            formula_explanation=formula_explanation or f"Base ({base_score*100:.0f}%) + Contributions = {bounded_score*100:.1f}%",
            breakdown=breakdown,
        )


class GraphTraceRecorder:
    """Records UTKG graph traversals and node pathing."""

    def record_graph_trace(
        self,
        session_id: str,
        starting_node: str,
        visited_nodes: List[str],
        traversal_depth: int,
        edges_traversed: List[Dict[str, Any]],
        relationships_used: List[str],
        shortest_path: List[str],
        expanded_context: Dict[str, Any],
        traversal_algorithm: str = "BFS_MULTI_HOP",
    ) -> GraphTrace:
        return GraphTrace(
            session_id=session_id,
            starting_node=starting_node,
            visited_nodes=visited_nodes,
            traversal_depth=traversal_depth,
            traversal_algorithm=traversal_algorithm,
            edges_traversed=edges_traversed,
            relationships_used=relationships_used,
            shortest_path=shortest_path,
            expanded_context=expanded_context,
        )


# ============================================================================
# EXPORT ENGINE
# ============================================================================

class ExportEngine:
    """Export Reasoning Trace to JSON, Markdown, HTML, and PDF-ready JSON formats."""

    @staticmethod
    def export_json(trace: ReasoningTrace) -> str:
        """Export trace as a formatted JSON string."""
        return json.dumps(trace.model_dump(), indent=2)

    @staticmethod
    def export_markdown(trace: ReasoningTrace) -> str:
        """Export trace as a rich Markdown report."""
        lines = [
            f"# Reasoning Trace Report: `{trace.trace_id}`",
            f"**Session ID:** `{trace.session.session_id}`  ",
            f"**User Query:** {trace.session.user_query}  ",
            f"**Status:** {trace.session.status} | **Duration:** {trace.session.duration or 0.0:.3f}s  ",
            f"**Analyst:** {trace.session.analyst} | **Model:** {trace.session.model_used} ({trace.session.llm_provider})",
            "\n---",
            "\n## 1. Pipeline Stages Overview",
            "| Stage | Duration (s) | Confidence | Errors | Status |",
            "|---|---|---|---|---|",
        ]
        for stage in trace.stages:
            err_cnt = len(stage.errors)
            lines.append(f"| {stage.stage_name} | {stage.duration:.3f}s | {stage.confidence*100:.1f}% | {err_cnt} | OK |")

        lines.extend([
            "\n## 2. Key AI Decisions",
        ])
        for dec in trace.decisions:
            lines.append(f"- **[{dec.decision_type}]** Chosen: `{dec.chosen_option}` (Confidence: {dec.confidence*100:.1f}%)")
            lines.append(f"  - *Reason:* {dec.decision_reason}")
            if dec.rejected_alternatives:
                lines.append(f"  - *Rejected Alternatives:* {dec.rejected_alternatives}")

        if trace.confidence:
            lines.extend([
                "\n## 3. Transparent Confidence Calculation (Waterfall)",
                f"**Final Score:** {trace.confidence.overall_score*100:.1f}% (Base: {trace.confidence.base_score*100:.0f}%)",
                "| Contribution Factor | Delta | Explanation / Reason |",
                "|---|---|---|",
            ])
            for contrib in trace.confidence.contributions:
                sign = "+" if contrib.delta >= 0 else ""
                lines.append(f"| {contrib.factor} | {sign}{contrib.delta*100:.1f}% | {contrib.reason} |")

        if trace.hypotheses:
            lines.extend([
                "\n## 4. Competing Hypotheses Evaluation",
            ])
            for hyp in trace.hypotheses:
                lines.append(f"- **Rank {hyp.ranking}:** {hyp.hypothesis} (Score: {hyp.score*100:.1f}%)")
                if hyp.why_rejected:
                    lines.append(f"  - *Rejection Reason:* {hyp.why_rejected}")

        if trace.recommendations:
            lines.extend([
                "\n## 5. Security Recommendations",
            ])
            for rec in trace.recommendations:
                lines.append(f"- **[{rec.priority}]** {rec.recommendation}")
                lines.append(f"  - *Impact:* {rec.expected_impact} | *Reason:* {rec.reason}")

        return "\n".join(lines)

    @staticmethod
    def export_html(trace: ReasoningTrace) -> str:
        """Export trace as a self-contained, beautifully styled HTML document."""
        md_content = ExportEngine.export_markdown(trace)
        # Convert simple markdown headings and tables to HTML structure
        html_body = (
            md_content.replace("# ", "<h1>")
            .replace("\n## ", "</h1>\n<h2>")
            .replace("\n### ", "</h2>\n<h3>")
            .replace("**", "<strong>")
            .replace("`", "<code>")
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetFusion Reasoning Trace - {trace.session.session_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 30px; line-height: 1.6; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
        h2 {{ color: #a78bfa; margin-top: 30px; }}
        code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #111827; }}
        th, td {{ padding: 10px; border: 1px solid #1f2937; text-align: left; }}
        th {{ background-color: #1f2937; color: #38bdf8; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #0284c7; color: white; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="badge">NetFusion XAI IL-9.1</div>
    <div>{html_body}</div>
</body>
</html>"""

    @staticmethod
    def export_pdf_json(trace: ReasoningTrace) -> str:
        """Export trace as a structured PDF-generator compatible JSON payload."""
        payload = {
            "document_type": "NetFusion_XAI_Reasoning_Trace_Report",
            "version": "1.0",
            "metadata": {
                "trace_id": trace.trace_id,
                "session_id": trace.session.session_id,
                "user_query": trace.session.user_query,
                "timestamp": trace.session.start_time,
                "duration": trace.session.duration,
                "status": trace.session.status,
                "analyst": trace.session.analyst,
            },
            "summary": {
                "total_stages": len(trace.stages),
                "total_decisions": len(trace.decisions),
                "total_evidence": len(trace.evidence),
                "final_confidence": trace.confidence.overall_score if trace.confidence else 0.0,
            },
            "sections": [
                {"title": "Stages", "data": [s.model_dump() for s in trace.stages]},
                {"title": "Decisions", "data": [d.model_dump() for d in trace.decisions]},
                {"title": "Confidence Waterfall", "data": trace.confidence.model_dump() if trace.confidence else {}},
                {"title": "Evidence", "data": [e.model_dump() for e in trace.evidence]},
                {"title": "Hypotheses", "data": [h.model_dump() for h in trace.hypotheses]},
                {"title": "Recommendations", "data": [r.model_dump() for r in trace.recommendations]},
            ]
        }
        return json.dumps(payload, indent=2)


# ============================================================================
# VISUALIZATION BUILDER
# ============================================================================

class VisualizationBuilder:
    """Generates visual structures (Flow Diagram, Decision Tree, Waterfall, Timeline, Graph Map, Hypothesis Comparison)."""

    @staticmethod
    def build_reasoning_flow(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Reasoning Flow Diagram nodes & edges for Mermaid/SVG rendering."""
        nodes = []
        edges = []
        prev_node = None

        for idx, stage in enumerate(trace.stages):
            node_id = f"stage_{idx}"
            nodes.append({
                "id": node_id,
                "label": stage.stage_name,
                "duration": f"{stage.duration:.3f}s",
                "confidence": f"{stage.confidence*100:.0f}%",
            })
            if prev_node:
                edges.append({"from": prev_node, "to": node_id, "label": "next"})
            prev_node = node_id

        return {
            "type": "reasoning_flow",
            "diagram_mermaid": "graph TD;\n" + ";\n".join([f"  {n['id']}[\"{n['label']}\"]" for n in nodes]) + ";\n" + ";\n".join([f"  {e['from']} --> {e['to']}" for e in edges]),
            "nodes": nodes,
            "edges": edges,
        }

    @staticmethod
    def build_decision_tree(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Decision Tree hierarchy for AI choices."""
        tree = {
            "name": f"Session: {trace.session.session_id}",
            "children": [],
        }
        for dec in trace.decisions:
            dec_node = {
                "name": dec.decision_type,
                "chosen": str(dec.chosen_option),
                "reason": dec.decision_reason,
                "confidence": dec.confidence,
                "alternatives": [str(alt) for alt in dec.rejected_alternatives],
            }
            tree["children"].append(dec_node)
        return {"type": "decision_tree", "tree": tree}

    @staticmethod
    def build_confidence_waterfall(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Confidence Waterfall chart data."""
        if not trace.confidence:
            return {"type": "confidence_waterfall", "waterfall": []}

        waterfall = [
            {"factor": "Base Score", "delta": trace.confidence.base_score, "cumulative": trace.confidence.base_score}
        ]
        curr = trace.confidence.base_score
        for c in trace.confidence.contributions:
            curr += c.delta
            waterfall.append({
                "factor": c.factor,
                "delta": c.delta,
                "cumulative": max(0.0, min(1.0, curr)),
                "reason": c.reason,
            })
        return {
            "type": "confidence_waterfall",
            "final_score": trace.confidence.overall_score,
            "waterfall": waterfall,
        }

    @staticmethod
    def build_evidence_timeline(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Evidence Timeline sequence."""
        events = []
        for ev in trace.evidence:
            events.append({
                "timestamp": ev.timestamp,
                "evidence_id": ev.evidence_id,
                "feed": ev.source_feed,
                "canonical_id": ev.canonical_id,
                "confidence": ev.confidence,
                "status": "SELECTED" if not ev.reason_rejected else "REJECTED",
                "reason": ev.reason_selected if not ev.reason_rejected else ev.reason_rejected,
            })
        events.sort(key=lambda x: x["timestamp"])
        return {"type": "evidence_timeline", "events": events}

    @staticmethod
    def build_graph_traversal_map(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Graph Traversal Map visualization."""
        if not trace.graph_trace:
            return {"type": "graph_traversal_map", "nodes": [], "edges": []}

        gt = trace.graph_trace
        return {
            "type": "graph_traversal_map",
            "starting_node": gt.starting_node,
            "depth": gt.traversal_depth,
            "algorithm": gt.traversal_algorithm,
            "visited_nodes_count": len(gt.visited_nodes),
            "visited_nodes": gt.visited_nodes,
            "edges_traversed": gt.edges_traversed,
            "shortest_path": gt.shortest_path,
        }

    @staticmethod
    def build_hypothesis_comparison(trace: ReasoningTrace) -> Dict[str, Any]:
        """Generate Hypothesis Comparison table/matrix."""
        comparison = []
        for hyp in trace.hypotheses:
            comparison.append({
                "ranking": hyp.ranking,
                "hypothesis": hyp.hypothesis,
                "score": hyp.score,
                "supporting_count": len(hyp.supporting_evidence),
                "contradicting_count": len(hyp.contradicting_evidence),
                "status": "ACCEPTED" if hyp.ranking == 1 else "REJECTED",
                "rejection_reason": hyp.why_rejected,
            })
        comparison.sort(key=lambda x: x["ranking"])
        return {"type": "hypothesis_comparison", "comparison": comparison}


# ============================================================================
# MAIN REASONING TRACE ENGINE
# ============================================================================

class ReasoningTraceEngine:
    """
    Central Reasoning Trace Engine (IL-9.1).
    Passive observer recording every AI decision, stage, evidence, confidence, and rule.
    """

    def __init__(self, publisher: Optional[Any] = None):
        self.session_manager = SessionManager()
        self.decision_recorder = DecisionRecorder()
        self.evidence_recorder = EvidenceRecorder()
        self.confidence_recorder = ConfidenceRecorder()
        self.graph_recorder = GraphTraceRecorder()
        self.publisher = publisher
        self._traces: Dict[str, ReasoningTrace] = {}

    def start_trace(
        self,
        user_query: str,
        investigation_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        case_id: Optional[str] = None,
        analyst: Optional[str] = "System Analyst",
    ) -> ReasoningTrace:
        """Start a new reasoning trace session."""
        session = self.session_manager.create_session(
            user_query=user_query,
            investigation_id=investigation_id,
            workflow_id=workflow_id,
            case_id=case_id,
            analyst=analyst,
        )
        trace = ReasoningTrace(session=session)
        self._traces[session.session_id] = trace

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(TraceStarted(session_id=session.session_id, user_query=user_query))
            except Exception:
                pass

        return trace

    def record_stage(
        self,
        session_id: str,
        stage_name: str,
        stage_input: Any = None,
        stage_output: Any = None,
        duration: float = 0.0,
        confidence: float = 1.0,
        dependencies: Optional[List[str]] = None,
        parent_stage: Optional[str] = None,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
    ) -> Optional[ReasoningStep]:
        """Record a pipeline stage execution."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        step = ReasoningStep(
            session_id=session_id,
            stage_name=stage_name,
            input=stage_input,
            output=stage_output,
            duration=duration,
            confidence=confidence,
            dependencies=dependencies or [],
            parent_stage=parent_stage,
            errors=errors or [],
            warnings=warnings or [],
        )
        trace.stages.append(step)

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    StageCompleted(
                        session_id=session_id,
                        stage_name=stage_name,
                        duration=duration,
                        confidence=confidence,
                    )
                )
            except Exception:
                pass

        return step

    def record_decision(
        self,
        session_id: str,
        decision_type: str,
        chosen_option: Any,
        rejected_alternatives: List[Any],
        decision_reason: str,
        confidence: float = 1.0,
        supporting_evidence: Optional[List[str]] = None,
        contradicting_evidence: Optional[List[str]] = None,
        rule_triggered: Optional[str] = None,
    ) -> Optional[ReasoningDecision]:
        """Record an AI decision choice and alternatives."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        dec = self.decision_recorder.record_decision(
            session_id=session_id,
            decision_type=decision_type,
            chosen_option=chosen_option,
            rejected_alternatives=rejected_alternatives,
            decision_reason=decision_reason,
            confidence=confidence,
            supporting_evidence=supporting_evidence,
            contradicting_evidence=contradicting_evidence,
            rule_triggered=rule_triggered,
        )
        trace.decisions.append(dec)

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    DecisionRecorded(
                        session_id=session_id,
                        decision_id=dec.decision_id,
                        decision_type=decision_type,
                        chosen_option=chosen_option,
                        confidence=confidence,
                    )
                )
            except Exception:
                pass

        return dec

    def record_evidence(
        self,
        session_id: str,
        source_feed: str,
        canonical_id: str,
        confidence: float,
        trust_score: float,
        reason_selected: str,
        reason_rejected: Optional[str] = None,
        feed_version: str = "v1.0",
    ) -> Optional[ReasoningEvidence]:
        """Record evidence selection/rejection."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        ev = self.evidence_recorder.record_evidence(
            session_id=session_id,
            source_feed=source_feed,
            canonical_id=canonical_id,
            confidence=confidence,
            trust_score=trust_score,
            reason_selected=reason_selected,
            reason_rejected=reason_rejected,
            feed_version=feed_version,
        )
        trace.evidence.append(ev)

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    EvidenceRecorded(
                        session_id=session_id,
                        evidence_id=ev.evidence_id,
                        source_feed=source_feed,
                        canonical_id=canonical_id,
                        confidence=confidence,
                    )
                )
            except Exception:
                pass

        return ev

    def record_confidence(
        self,
        session_id: str,
        base_score: float,
        contributions: List[ConfidenceContribution],
        formula_explanation: str = "",
    ) -> Optional[ReasoningConfidence]:
        """Record transparent confidence waterfall calculation."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        conf = self.confidence_recorder.record_confidence(
            session_id=session_id,
            base_score=base_score,
            contributions=contributions,
            formula_explanation=formula_explanation,
        )
        trace.confidence = conf

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    ConfidenceRecorded(
                        session_id=session_id,
                        overall_score=conf.overall_score,
                        contributions_count=len(contributions),
                    )
                )
            except Exception:
                pass

        return conf

    def record_rule(
        self,
        session_id: str,
        rule_name: str,
        rule_input: Any = None,
        rule_output: Any = None,
        reason: str = "",
        matched_conditions: Optional[List[str]] = None,
        execution_time: float = 0.0,
        confidence_delta: float = 0.0,
    ) -> Optional[ReasoningRule]:
        """Record deterministic rule execution."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        rule = ReasoningRule(
            session_id=session_id,
            rule_name=rule_name,
            input=rule_input,
            output=rule_output,
            reason=reason,
            matched_conditions=matched_conditions or [],
            execution_time=execution_time,
            confidence_delta=confidence_delta,
        )
        trace.rules.append(rule)
        return rule

    def record_graph_trace(
        self,
        session_id: str,
        starting_node: str,
        visited_nodes: List[str],
        traversal_depth: int,
        edges_traversed: List[Dict[str, Any]],
        relationships_used: List[str],
        shortest_path: List[str],
        expanded_context: Dict[str, Any],
        traversal_algorithm: str = "BFS_MULTI_HOP",
    ) -> Optional[GraphTrace]:
        """Record UTKG graph traversal."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        gt = self.graph_recorder.record_graph_trace(
            session_id=session_id,
            starting_node=starting_node,
            visited_nodes=visited_nodes,
            traversal_depth=traversal_depth,
            edges_traversed=edges_traversed,
            relationships_used=relationships_used,
            shortest_path=shortest_path,
            expanded_context=expanded_context,
            traversal_algorithm=traversal_algorithm,
        )
        trace.graph_trace = gt
        return gt

    def record_hypothesis(
        self,
        session_id: str,
        hypothesis: str,
        alternative_hypotheses: List[str],
        supporting_evidence: List[str],
        contradicting_evidence: List[str],
        score: float,
        ranking: int,
        why_rejected: Optional[str] = None,
    ) -> Optional[ReasoningHypothesis]:
        """Record hypothesis evaluation."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        hyp = ReasoningHypothesis(
            session_id=session_id,
            hypothesis=hypothesis,
            alternative_hypotheses=alternative_hypotheses,
            supporting_evidence=supporting_evidence,
            contradicting_evidence=contradicting_evidence,
            score=score,
            ranking=ranking,
            why_rejected=why_rejected,
        )
        trace.hypotheses.append(hyp)
        return hyp

    def record_recommendation(
        self,
        session_id: str,
        recommendation: str,
        reason: str,
        evidence_used: List[str],
        confidence: float,
        priority: str = "MEDIUM",
        expected_impact: str = "Risk Reduction",
    ) -> Optional[ReasoningRecommendation]:
        """Record recommendation generation."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        rec = ReasoningRecommendation(
            session_id=session_id,
            recommendation=recommendation,
            reason=reason,
            evidence_used=evidence_used,
            confidence=confidence,
            priority=priority,
            expected_impact=expected_impact,
        )
        trace.recommendations.append(rec)

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    RecommendationRecorded(
                        session_id=session_id,
                        recommendation_id=rec.recommendation_id,
                        priority=priority,
                    )
                )
            except Exception:
                pass

        return rec

    def record_explanation(
        self,
        session_id: str,
        prompt_template: str,
        prompt_variables: Dict[str, Any],
        context_size: int,
        evidence_count: int,
        graph_nodes_used: int,
        graph_edges_used: int,
        explanation_text: str,
        llm_provider: str = "Local/Mock Provider",
        model: str = "netfusion-reasoner-v1",
        latency: float = 0.0,
        token_usage: Optional[Dict[str, int]] = None,
    ) -> Optional[ReasoningExplanation]:
        """Record LLM explanation generation."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        exp = ReasoningExplanation(
            session_id=session_id,
            prompt_template=prompt_template,
            prompt_variables=prompt_variables,
            context_size=context_size,
            evidence_count=evidence_count,
            graph_nodes_used=graph_nodes_used,
            graph_edges_used=graph_edges_used,
            llm_provider=llm_provider,
            model=model,
            latency=latency,
            token_usage=token_usage or {"prompt_tokens": 120, "completion_tokens": 350, "total_tokens": 470},
            response_length=len(explanation_text),
            explanation_text=explanation_text,
        )
        trace.explanation = exp
        return exp

    def complete_trace(self, session_id: str, status: str = "COMPLETED") -> Optional[ReasoningTrace]:
        """Finalize and complete a trace session."""
        trace = self._traces.get(session_id)
        if not trace:
            return None

        self.session_manager.complete_session(session_id, status=status)

        if self.publisher and hasattr(self.publisher, "publish"):
            try:
                self.publisher.publish(
                    TraceCompleted(
                        session_id=session_id,
                        total_stages=len(trace.stages),
                        total_decisions=len(trace.decisions),
                        final_confidence=trace.confidence.overall_score if trace.confidence else 1.0,
                        duration=trace.session.duration or 0.0,
                    )
                )
            except Exception:
                pass

        return trace

    def get_trace(self, session_id: str) -> Optional[ReasoningTrace]:
        """Retrieve trace by session ID or investigation ID."""
        if session_id in self._traces:
            return self._traces[session_id]
        # Search by investigation ID or session ID match
        for trace in self._traces.values():
            if trace.session.investigation_id == session_id:
                return trace
        return None

    def export_trace(self, session_id: str, fmt: str = "json") -> str:
        """Export trace in specified format (json, markdown, html, pdf_json)."""
        trace = self.get_trace(session_id)
        if not trace:
            raise ValueError(f"Trace not found for session_id: {session_id}")

        fmt_lower = fmt.lower()
        if fmt_lower == "markdown" or fmt_lower == "md":
            return ExportEngine.export_markdown(trace)
        elif fmt_lower == "html":
            return ExportEngine.export_html(trace)
        elif fmt_lower == "pdf_json" or fmt_lower == "pdf":
            return ExportEngine.export_pdf_json(trace)
        else:
            return ExportEngine.export_json(trace)
