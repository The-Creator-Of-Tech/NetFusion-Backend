"""
NetFusion Confidence Engine
Calculates multi-factor confidence metadata based on:
- Evidence Quality
- Evidence Quantity
- Collector Reliability
- Threat Intel Confidence
- Correlation Strength
- Missing Information
Exposes confidence as structured metadata.
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import ConfidenceMetadata
from netfusion_ai.enums import ConfidenceLevel
from netfusion_ai.context_builder import InvestigationContextContainer


class ConfidenceEngine:
    """Multi-factor confidence scoring engine."""

    def calculate_confidence(
        self,
        context: InvestigationContextContainer,
        extra_factors: Optional[Dict[str, float]] = None,
    ) -> ConfidenceMetadata:
        """Calculates multi-factor confidence score and structured metadata."""

        missing_info: List[str] = []

        # 1. Evidence Quantity
        total_evidence_items = len(context.evidence) + len(context.timeline) + len(context.canonical_objects)
        if total_evidence_items > 20:
            qty_score = 0.95
        elif total_evidence_items > 10:
            qty_score = 0.8
        elif total_evidence_items > 3:
            qty_score = 0.6
        else:
            qty_score = 0.3
            missing_info.append("Sparse evidence artifacts available")

        # 2. Evidence Quality
        verified_count = sum(1 for e in context.evidence if e.get("integrity_status") == "verified")
        quality_score = (verified_count / len(context.evidence)) if context.evidence else 0.5

        # 3. Collector Reliability
        active_collectors = set()
        if context.sysmon_events:
            active_collectors.add("sysmon")
        if context.nmap_scans:
            active_collectors.add("nmap")
        if context.tshark_captures:
            active_collectors.add("tshark")

        rel_score = 0.5 + (0.15 * len(active_collectors))
        rel_score = min(rel_score, 0.95)
        if len(active_collectors) < 2:
            missing_info.append("Multi-collector telemetry triangulation unavailable")

        # 4. Threat Intel Confidence
        if context.threat_intelligence:
            ti_score = 0.85
        elif context.iocs:
            ti_score = 0.70
        else:
            ti_score = 0.40
            missing_info.append("Threat intelligence IOC enrichments missing")

        # 5. Correlation Strength
        if len(context.timeline) >= 5 and len(context.canonical_objects) >= 3:
            corr_score = 0.85
        elif len(context.timeline) >= 2:
            corr_score = 0.65
        else:
            corr_score = 0.40

        # Weighted aggregate score calculation
        w_qty = 0.20
        w_qual = 0.25
        w_rel = 0.20
        w_ti = 0.15
        w_corr = 0.20

        overall_score = (
            (qty_score * w_qty)
            + (quality_score * w_qual)
            + (rel_score * w_rel)
            + (ti_score * w_ti)
            + (corr_score * w_corr)
        )

        if extra_factors:
            for k, val in extra_factors.items():
                overall_score = (overall_score * 0.8) + (val * 0.2)

        overall_score = round(max(0.0, min(1.0, overall_score)), 2)

        if overall_score >= 0.85:
            conf_level = ConfidenceLevel.VERY_HIGH
        elif overall_score >= 0.70:
            conf_level = ConfidenceLevel.HIGH
        elif overall_score >= 0.50:
            conf_level = ConfidenceLevel.MEDIUM
        elif overall_score >= 0.30:
            conf_level = ConfidenceLevel.LOW
        else:
            conf_level = ConfidenceLevel.VERY_LOW

        return ConfidenceMetadata(
            overall_score=overall_score,
            confidence_level=conf_level,
            evidence_quality=round(quality_score, 2),
            evidence_quantity=round(qty_score, 2),
            collector_reliability=round(rel_score, 2),
            threat_intel_confidence=round(ti_score, 2),
            correlation_strength=round(corr_score, 2),
            missing_information=missing_info,
        )
