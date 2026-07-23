"""
IL-7 IOC Confidence Engine.
Computes and aggregates confidence scores for IOC entities from multiple
source signals: provider trust, source count, sighting corroboration,
temporal decay, and false positive history.
"""

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IocConfidenceEngine:
    """
    Computes final aggregated confidence scores for IOC entities.
    Confidence represents the probability that an indicator is truly malicious
    (0.0 = benign/uncertain, 1.0 = high confidence malicious).
    """

    # Default trust scores by provider type
    _PROVIDER_TRUST: Dict[str, float] = {
        "misp": 0.85,
        "opencti": 0.80,
        "stix": 0.75,
        "taxii": 0.75,
        "csv": 0.55,
        "json": 0.55,
        "yaml": 0.50,
        "manual": 0.60,
    }

    def compute(
        self,
        base_confidence: float,
        provider_type: Optional[str] = None,
        source_count: int = 1,
        sighting_count: int = 0,
        false_positive_score: float = 0.0,
        age_days: Optional[float] = None,
        tlp: Optional[str] = None,
    ) -> float:
        """
        Compute a final aggregated confidence score.

        Args:
            base_confidence:    Raw confidence from provider (0.0–1.0)
            provider_type:      Provider type string for trust adjustment
            source_count:       Number of independent sources corroborating
            sighting_count:     Observed sightings count
            false_positive_score: Historical FP signal (0.0–1.0)
            age_days:           Days since first_seen (None = no decay)
            tlp:                TLP marking (RED/AMBER = higher trust)
        Returns:
            Aggregated confidence float [0.0, 1.0]
        """
        # Provider trust adjustment
        provider_trust = self._PROVIDER_TRUST.get(
            (provider_type or "").lower(), 0.5
        )
        # Weighted base
        score = base_confidence * 0.6 + provider_trust * 0.4

        # Multi-source corroboration boost: log1p curve capped at +0.15
        if source_count > 1:
            score += min(0.15, math.log1p(source_count - 1) * 0.07)

        # Sighting corroboration boost: capped at +0.10
        if sighting_count > 0:
            score += min(0.10, math.log1p(sighting_count) * 0.05)

        # TLP trust boost
        if tlp:
            tlp_upper = tlp.upper()
            if "RED" in tlp_upper:
                score += 0.05
            elif "AMBER" in tlp_upper:
                score += 0.03

        # Temporal decay (indicators older than 30 days lose confidence)
        if age_days is not None and age_days > 30:
            decay = math.exp(-0.01 * (age_days - 30))
            score *= max(0.3, decay)

        # False positive penalty
        score -= false_positive_score * 0.5

        return round(max(0.0, min(1.0, score)), 4)

    def merge_confidences(self, scores: List[float]) -> float:
        """
        Aggregate multiple confidence scores from different sources.
        Uses a weighted harmonic-like mean that rewards consensus.
        """
        if not scores:
            return 0.0
        if len(scores) == 1:
            return scores[0]
        # Noisy OR: P(any source correct) = 1 - product(1 - p_i)
        noisy_or = 1.0 - math.prod(1.0 - max(0.0, min(1.0, s)) for s in scores)
        # Average for conservative estimate
        avg = sum(scores) / len(scores)
        # Blend: 60% noisy-OR + 40% average
        return round(min(1.0, 0.6 * noisy_or + 0.4 * avg), 4)

    def age_days(self, first_seen_iso: Optional[str]) -> Optional[float]:
        """Compute the age of an indicator in days from first_seen ISO timestamp."""
        if not first_seen_iso:
            return None
        try:
            dt = datetime.fromisoformat(first_seen_iso.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = now - dt
            return max(0.0, delta.total_seconds() / 86400.0)
        except Exception:
            return None
