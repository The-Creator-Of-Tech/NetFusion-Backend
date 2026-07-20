"""
NetFusion Prompt Builder Engine
Provides specialized SOC security prompt templates for:
- Incident Summary
- Threat Hunting
- IOC Analysis
- MITRE Analysis
- Malware Analysis
- Executive Report
- Technical Report
- Next Investigation Steps
- Root Cause Analysis
- False Positive Review
- Containment Advice
Integrates safety constraints and strict non-fabrication guardrails.
"""

from typing import Any, Dict, Optional
from netfusion_ai.enums import PromptTemplateType
from netfusion_ai.exceptions import PromptTemplateError
from netfusion_ai.providers.base import LLMRequest


SYSTEM_SAFETY_GUARDRAILS = """
You are the NetFusion AI Investigation Assistant, a specialized SOC Security Copilot.
MANDATORY SAFETY PRINCIPLES:
1. NEVER fabricate evidence, file hashes, IP addresses, domains, or timestamps.
2. Rely ONLY on the provided investigation context. If data is absent, state "Information not provided in investigation context".
3. STRICTLY SEPARATE:
   - FACTS: Explicitly verified data from evidence/timeline.
   - INFERENCES: Logical deductions based on facts.
   - HYPOTHESES: Explanatory models requiring further validation.
   - RECOMMENDATIONS: Actionable mitigation/investigation steps.
4. Output structured analysis adhering strictly to requested JSON schemas when requested.
"""


PROMPT_TEMPLATES: Dict[PromptTemplateType, str] = {
    PromptTemplateType.INCIDENT_SUMMARY: """
Analyze the provided investigation context and generate a comprehensive Incident Summary.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Provide a structured analysis covering:
1. High-level Overview & Executive Context
2. Key Attack Indicators & Timeline Milestones
3. Affected Systems & Assets
4. Current Investigation State
""",

    PromptTemplateType.THREAT_HUNTING: """
Perform threat hunting analysis over the provided investigation context to discover hidden persistence, lateral movement, or evasion.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Formulate hunt queries, anomalous patterns, and recommended hunting actions based ONLY on observed telemetry.
""",

    PromptTemplateType.IOC_ANALYSIS: """
Correlate and analyze all Indicators of Compromise (IOCs) in the investigation context.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Evaluate IOC confidence, threat intelligence context, reputation, and potential impact. Do not invent IOC values.
""",

    PromptTemplateType.MITRE_ANALYSIS: """
Map observed evidence and timeline events to the MITRE ATT&CK Framework.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Infer Tactics, Techniques (Txxxx), and Sub-techniques (Txxxx.xxx) with confidence scores and evidence references.
""",

    PromptTemplateType.MALWARE_ANALYSIS: """
Assess potential malware artifacts, process command-lines, and network communication signatures.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Detail process execution chains, file hashes, registry modifications, and C2 beacons.
""",

    PromptTemplateType.EXECUTIVE_REPORT: """
Generate an Executive-level Incident Brief for CISOs and executive leadership.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Focus on business impact, overall risk, root cause summary, and strategic remediation steps. Avoid deep raw logs.
""",

    PromptTemplateType.TECHNICAL_REPORT: """
Generate a detailed Technical Investigation Report for Tier-2/Tier-3 SOC Analysts and Incident Responders.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Include full chronological timeline analysis, technical evidence breakdown, IOC tables, and MITRE matrix.
""",

    PromptTemplateType.NEXT_INVESTIGATION_STEPS: """
Recommend immediate next technical investigation steps for the incident response team.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Group actions by priority and required data sources (e.g. Memory Dump, Firewall Logs, PCAP Analysis).
""",

    PromptTemplateType.ROOT_CAUSE_ANALYSIS: """
Analyze the initial access vector and root cause of the security incident.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Identify initial access technique, exploited vulnerability or credential misuse, and vector confidence.
""",

    PromptTemplateType.FALSE_POSITIVE_REVIEW: """
Evaluate whether the investigation or specific alert represents a True Positive, False Positive, or Benign Activity.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

Provide detailed justification, baseline context, and rule tuning suggestions.
""",

    PromptTemplateType.CONTAINMENT_ADVICE: """
Produce immediate containment and isolation advice to stop active adversary progression.

INVESTIGATION CONTEXT:
{context_markdown}

USER INSTRUCTIONS:
{user_query}

List host isolation, network block rules, account suspensions, and credential reset actions.
""",
}


class PromptBuilder:
    """Prompt Builder rendering specialized SOC security prompts."""

    def __init__(self, custom_system_prompt: Optional[str] = None):
        self.system_prompt = custom_system_prompt or SYSTEM_SAFETY_GUARDRAILS

    def build_prompt(
        self,
        template_type: PromptTemplateType,
        context_markdown: str,
        user_query: str = "Perform analytical evaluation.",
        json_mode: bool = False,
        extra_variables: Optional[Dict[str, Any]] = None,
    ) -> LLMRequest:
        """Renders an LLMRequest for a given prompt template and context."""
        if template_type not in PROMPT_TEMPLATES:
            raise PromptTemplateError(f"Unsupported prompt template type: '{template_type}'")

        template_str = PROMPT_TEMPLATES[template_type]
        kwargs = {
            "context_markdown": context_markdown,
            "user_query": user_query,
        }
        if extra_variables:
            kwargs.update(extra_variables)

        try:
            rendered_user_prompt = template_str.format(**kwargs)
        except Exception as e:
            raise PromptTemplateError(f"Failed rendering template {template_type}: {str(e)}") from e

        return LLMRequest(
            system_prompt=self.system_prompt,
            user_prompt=rendered_user_prompt,
            json_mode=json_mode,
        )
