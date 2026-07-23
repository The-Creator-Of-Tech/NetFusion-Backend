"""
ATRE Grounded LLM Prompt Templates — NetFusion IL-9
====================================================
Strict prompt templates ensuring LLMs operate ONLY on structured evidence context.
"""

SYSTEM_PROMPT = """You are the AI Threat Reasoning Engine (ATRE) explanation component for NetFusion.
Your sole role is to summarize, format, and explain the structured evidence, attack chain, hypotheses, confidence breakdown, contradictions, and recommendations provided below.

CRITICAL CONSTRAINTS:
1. Reason First, LLM Second, Evidence Before Language.
2. DO NOT make assumptions or hallucinate ungrounded facts not present in the provided evidence.
3. Every conclusion or claim MUST reference supporting evidence IDs (e.g., [EV-1], [CVE-2023-34362]).
4. Maintain strict factual alignment with the graph evidence.
"""


def build_explanation_prompt(
    user_question: str,
    question_type: str,
    evidence_text: str,
    attack_chain_text: str,
    hypotheses_text: str,
    confidence_text: str,
    contradictions_text: str,
    recommendations_text: str,
    timeline_text: str,
) -> str:
    return f"""### USER QUESTION:
{user_question} (Intent: {question_type})

### GROUNDED STRUCTURED EVIDENCE CONTEXT:
--- EVIDENCE LIST ---
{evidence_text}

--- ATTACK CHAIN STAGES ---
{attack_chain_text}

--- COMPETING HYPOTHESES ---
{hypotheses_text}

--- TRANSPARENT CONFIDENCE SCORE ---
{confidence_text}

--- CONTRADICTION ANALYSIS ---
{contradictions_text}

--- ACTIONABLE RECOMMENDATIONS ---
{recommendations_text}

--- CHRONOLOGICAL TIMELINE ---
{timeline_text}

--- INSTRUCTIONS ---
Using ONLY the structured context provided above, generate an authoritative analyst response containing:
1. Executive Summary
2. SOC Operational Summary
3. Incident Response Summary
4. Detailed Technical Analysis
5. Evidence Summary Table
6. Transparent Confidence Explanation
7. Traceability / Reasoning Steps
"""
