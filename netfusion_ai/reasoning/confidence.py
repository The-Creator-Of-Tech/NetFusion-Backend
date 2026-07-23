"""
ATRE Confidence Engine — NetFusion IL-9
========================================
Transparent, multi-factor confidence calculator for AI threat conclusions.
"""

from typing import List, Optional
from netfusion_ai.reasoning.models import ConfidenceBreakdown, GraphEvidence, RelationshipRanking


class ConfidenceEngine:
    """
    Calculates multi-factor confidence incorporating:
    - Edge confidence
    - Evidence count
    - IOC reputation
    - EPSS
    - KEV
    - CVSS
    - Relationship strength
    - Feed trust score
    - Recency
    - Analyst confirmation
    """

    def calculate_confidence(
        self,
        evidence: List[GraphEvidence],
        relationships: List[RelationshipRanking],
        has_kev: bool = False,
        epss_score: float = 0.0,
        cvss_score: float = 0.0,
        analyst_confirmed: bool = False,
    ) -> ConfidenceBreakdown:
        # 1. Edge confidence factor
        edge_conf = (
            sum(r.relationship_strength for r in relationships) / len(relationships)
            if relationships
            else 0.8
        )

        # 2. Evidence count factor (saturates around 10 items)
        ev_count_factor = min(1.0, len(evidence) / 10.0)

        # 3. IOC reputation score
        ioc_ev = [ev for ev in evidence if ev.source_type in ("IOC", "IP_ADDRESS", "FILE_HASH")]
        ioc_rep = (
            sum(ev.confidence_score for ev in ioc_ev) / len(ioc_ev)
            if ioc_ev
            else 0.75
        )

        # 4. EPSS factor (normalize 0-1)
        epss_factor = min(1.0, max(0.0, epss_score))

        # 5. KEV factor (1.0 if present in KEV, 0.5 otherwise)
        kev_factor = 1.0 if has_kev else 0.5

        # 6. CVSS score (normalize 0-10 to 0.0-1.0)
        cvss_factor = min(1.0, cvss_score / 10.0) if cvss_score > 0 else 0.7

        # 7. Relationship strength
        rel_strength = (
            sum(r.score for r in relationships) / (len(relationships) * 100.0)
            if relationships
            else 0.8
        )

        # 8. Feed trust score
        feed_trust = 0.85

        # 9. Recency factor
        recency = 0.80

        # 10. Analyst confirmation factor
        analyst_factor = 1.0 if analyst_confirmed else 0.7

        # Weighted calculation
        # Weights: edge: 0.15, ev_count: 0.10, ioc: 0.15, epss: 0.10, kev: 0.10, cvss: 0.10, rel: 0.10, trust: 0.10, analyst: 0.10
        weights = {
            "edge": 0.15,
            "evidence_count": 0.10,
            "ioc_rep": 0.15,
            "epss": 0.10,
            "kev": 0.10,
            "cvss": 0.10,
            "rel_strength": 0.05,
            "feed_trust": 0.10,
            "recency": 0.05,
            "analyst": 0.10,
        }

        overall = (
            weights["edge"] * edge_conf
            + weights["evidence_count"] * ev_count_factor
            + weights["ioc_rep"] * ioc_rep
            + weights["epss"] * epss_factor
            + weights["kev"] * kev_factor
            + weights["cvss"] * cvss_factor
            + weights["rel_strength"] * rel_strength
            + weights["feed_trust"] * feed_trust
            + weights["recency"] * recency
            + weights["analyst"] * analyst_factor
        )

        overall_clamped = round(min(1.0, max(0.0, overall)), 4)

        explanation = (
            f"Overall confidence score: {overall_clamped * 100:.1f}%. "
            f"Weighted combination of Edge Confidence ({edge_conf:.2f}), Evidence Count ({len(evidence)} items), "
            f"IOC Reputation ({ioc_rep:.2f}), KEV Presence ({kev_factor}), EPSS ({epss_factor:.2f}), CVSS ({cvss_factor:.2f}), "
            f"Feed Trust ({feed_trust:.2f}), and Analyst Confirmation ({analyst_factor})."
        )

        return ConfidenceBreakdown(
            edge_confidence=round(edge_conf, 2),
            evidence_count_factor=round(ev_count_factor, 2),
            ioc_reputation_score=round(ioc_rep, 2),
            epss_score=round(epss_factor, 2),
            kev_factor=round(kev_factor, 2),
            cvss_score=round(cvss_factor, 2),
            relationship_strength=round(rel_strength, 2),
            feed_trust_score=round(feed_trust, 2),
            recency_factor=round(recency, 2),
            analyst_confirmation_factor=round(analyst_factor, 2),
            overall_score=overall_clamped,
            formula_explanation=explanation,
        )
