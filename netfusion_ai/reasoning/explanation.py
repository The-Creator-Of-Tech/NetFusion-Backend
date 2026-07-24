"""
ATRE Explanation Engine — NetFusion IL-9
========================================
Generates grounded stakeholder reports and explanations in Markdown, JSON, and HTML.
Uses LLM strictly for natural language synthesis over structured evidence context.
"""

import json
from typing import Any, Dict, List, Optional
from netfusion_ai.reasoning.models import (
    AttackChain,
    ConfidenceBreakdown,
    Contradiction,
    ExplanationResult,
    GraphEvidence,
    Hypothesis,
    Recommendation,
    ReportFormat,
    Timeline,
)
from netfusion_ai.reasoning.prompts import SYSTEM_PROMPT, build_explanation_prompt


class ExplanationEngine:
    """
    Produces grounded explanations for Executive, SOC, and IR stakeholders.
    Formats outputs in Markdown, JSON, and HTML.
    """

    def __init__(self, ai_provider: Optional[Any] = None):
        self.ai_provider = ai_provider

    def generate_explanation(
        self,
        user_question: str,
        question_type: str,
        evidence: List[GraphEvidence],
        attack_chain: AttackChain,
        hypotheses: List[Hypothesis],
        confidence: ConfidenceBreakdown,
        contradictions: List[Contradiction],
        recommendations: List[Recommendation],
        timeline: Timeline,
        report_format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> ExplanationResult:

        # Format structured evidence strings
        ev_str = "\n".join([f"- [{ev.evidence_id}] {ev.label}: {ev.description} (Conf: {ev.confidence_score})" for ev in evidence])
        ac_str = "\n".join([f"- Stage {s.stage_number} [{s.tactic}]: {s.description} (Tactics: {', '.join(s.attack_ids)})" for s in attack_chain.stages]) if attack_chain.stages else "No stages detected."
        hyp_str = "\n".join([f"- Hypothesis {h.hypothesis_id} ({h.status}): {h.title} (Conf: {h.confidence_score * 100:.1f}%)" for h in hypotheses])
        conf_str = f"Score: {confidence.overall_score * 100:.1f}%\nFormula: {confidence.formula_explanation}"
        cnt_str = "\n".join([f"- [{c.severity}] {c.type}: {c.description}" for c in contradictions]) if contradictions else "None detected."
        rec_str = "\n".join([f"- [{r.priority}] [{r.category}] {r.title}: {r.description} (Reasoning: {r.reasoning})" for r in recommendations])
        tl_str = "\n".join([f"- [{e.timestamp}] [{e.source}] {e.title}: {e.description}" for e in timeline.events])

        # Generate sections
        exec_summary = (
            f"**Executive Summary**\n"
            f"NetFusion ATRE investigation analyzed question: '{user_question}'. "
            f"Primary findings indicate a likely multi-stage threat campaign with overall confidence {confidence.overall_score * 100:.1f}%. "
            f"{len(evidence)} evidence nodes and {attack_chain.total_stages} attack stages were identified across UTKG graphs."
        )

        soc_summary = (
            f"**SOC Summary**\n"
            f"- Question Type: {question_type}\n"
            f"- High Confidence Hypothesis: {hypotheses[0].title if hypotheses else 'N/A'}\n"
            f"- Immediate Actions: {recommendations[0].title if recommendations else 'N/A'}\n"
            f"- Contradictions Flagged: {len(contradictions)}"
        )

        ir_summary = (
            f"**IR Summary**\n"
            f"Attack chain spans {attack_chain.total_stages} stages from Initial Access to Impact. "
            f"Critical containment action recommended: {recommendations[0].title if len(recommendations) > 0 else 'Isolate host'}."
        )

        tech_analysis = (
            f"**Technical Analysis**\n"
            f"Evidence collection retrieved {len(evidence)} artifacts from CIIL and UTKG.\n"
            f"Reconstructed Attack Chain:\n{ac_str}\n\n"
            f"Hypothesis Comparison:\n{hyp_str}"
        )

        ev_table = [
            {
                "id": ev.evidence_id,
                "type": ev.source_type,
                "label": ev.label,
                "confidence": ev.confidence_score,
                "feed": ev.source_feed,
            }
            for ev in evidence
        ]

        conf_exp = confidence.formula_explanation

        trace = [
            f"1. Natural Question: {user_question}",
            f"2. Intent: {question_type}",
            f"3. CIIL Evidence Collected: {len(evidence)} items",
            f"4. Attack Chain Reconstructed: {attack_chain.total_stages} stages",
            f"5. Confidence Calculated: {confidence.overall_score * 100:.1f}%",
        ]

        # LLM Synthesis if provider is attached
        if self.ai_provider and hasattr(self.ai_provider, "generate"):
            try:
                prompt = build_explanation_prompt(
                    user_question=user_question,
                    question_type=question_type,
                    evidence_text=ev_str,
                    attack_chain_text=ac_str,
                    hypotheses_text=hyp_str,
                    confidence_text=conf_str,
                    contradictions_text=cnt_str,
                    recommendations_text=rec_str,
                    timeline_text=tl_str,
                )
                response = self.ai_provider.generate(prompt=prompt, system=SYSTEM_PROMPT)
                if isinstance(response, str) and response.strip():
                    tech_analysis = response
            except Exception:
                pass

        # Formatting
        formatted = ""
        if report_format == ReportFormat.JSON:
            formatted = json.dumps(
                {
                    "executive_summary": exec_summary,
                    "soc_summary": soc_summary,
                    "ir_summary": ir_summary,
                    "technical_analysis": tech_analysis,
                    "evidence_table": ev_table,
                    "confidence_explanation": conf_exp,
                    "reasoning_trace": trace,
                },
                indent=2,
            )
        elif report_format == ReportFormat.HTML:
            formatted = f"""<html>
<head><title>NetFusion ATRE Investigation Report</title></head>
<body>
<h1>NetFusion AI Threat Reasoning Engine Report</h1>
<h2>Executive Summary</h2>
<p>{exec_summary}</p>
<h2>SOC Summary</h2>
<pre>{soc_summary}</pre>
<h2>Technical Analysis</h2>
<div>{tech_analysis}</div>
<h2>Confidence Score</h2>
<p>{conf_exp}</p>
</body>
</html>"""
        else:
            # Markdown default
            formatted = f"""# NetFusion ATRE Investigation Report

## Executive Summary
{exec_summary}

---

## SOC Operational Summary
{soc_summary}

---

## Incident Response Summary
{ir_summary}

---

## Technical Analysis
{tech_analysis}

---

## Evidence Table
| ID | Type | Label | Confidence | Source |
|---|---|---|---|---|
""" + "\n".join([f"| {e['id']} | {e['type']} | {e['label']} | {e['confidence']} | {e['feed']} |" for e in ev_table]) + f"""

---

## Confidence Explanation
{conf_exp}
"""

        return ExplanationResult(
            executive_summary=exec_summary,
            soc_summary=soc_summary,
            ir_summary=ir_summary,
            technical_analysis=tech_analysis,
            evidence_table=ev_table,
            confidence_explanation=conf_exp,
            reasoning_trace=trace,
            format=report_format,
            formatted_output=formatted,
        )
