"""
NetFusion Explanation Engine
Generates structured explanations for every AI conclusion including:
- Evidence References
- Reasoning Summary
- Confidence
- Assumptions
- Limitations
- Unknowns
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import Explanation, EvidenceReference, ConfidenceMetadata
from netfusion_ai.enums import ConfidenceLevel
from netfusion_ai.context_builder import InvestigationContextContainer


class ExplanationEngine:
    """Reasoning transparency and explanation generator."""

    def build_explanation(
        self,
        reasoning_summary: str,
        evidence_references: List[EvidenceReference],
        confidence_metadata: ConfidenceMetadata,
        assumptions: Optional[List[str]] = None,
        limitations: Optional[List[str]] = None,
        unknowns: Optional[List[str]] = None,
    ) -> Explanation:
        """Constructs structured Explanation object."""

        default_assumptions = [
            "Telemetry sources collected reflect true system behavior.",
            "Timestamps across network and host collectors are synchronized.",
        ]
        default_limitations = [
            "Analysis is constrained to telemetry provided in the active investigation context.",
            "Encrypted payload inspection may be limited.",
        ]
        default_unknowns = confidence_metadata.missing_information or [
            "Initial access payload source requires memory dump verification."
        ]

        return Explanation(
            evidence_references=evidence_references,
            reasoning_summary=reasoning_summary,
            confidence=confidence_metadata.confidence_level,
            assumptions=assumptions if assumptions is not None else default_assumptions,
            limitations=limitations if limitations is not None else default_limitations,
            unknowns=unknowns if unknowns is not None else default_unknowns,
        )
