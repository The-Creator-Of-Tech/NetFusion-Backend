"""
IL-7 IOC Reputation Engine.
Computes and updates reputation scores for IOC entities based on
source count, confidence, severity, sightings, and false positive signals.
Every IOC stores: Confidence, Severity, Priority, Reputation, FirstSeen,
LastSeen, LastUpdated, Expiration, SourceCount, FalsePositiveScore.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.feeds.ioc.models import IocEntity, IocReputation, IocSeverity


class IocReputationEngine:
    """
    Computes and re-evaluates IOC reputation scores.
    Called during normalization (initial) and when new sightings/sources arrive.
    """

    # Severity weights for reputation computation
    _SEVERITY_WEIGHT: Dict[str, float] = {
        IocSeverity.CRITICAL.value: 1.0,
        IocSeverity.HIGH.value: 0.8,
        IocSeverity.MEDIUM.value: 0.5,
        IocSeverity.LOW.value: 0.25,
        IocSeverity.INFO.value: 0.1,
        IocSeverity.UNKNOWN.value: 0.3,
    }

    def compute_initial_reputation(self, entity: IocEntity) -> IocReputation:
        """Compute the initial reputation record for a freshly normalized IOC entity."""
        score = self._compute_score(
            confidence=entity.confidence,
            severity=entity.severity,
            source_count=entity.source_count,
            sighting_count=0,
            false_positive_score=entity.false_positive_score,
        )
        return IocReputation(
            ioc_id=entity.ioc_id,
            reputation_score=score,
            false_positive_score=entity.false_positive_score,
            confidence=entity.confidence,
            severity=entity.severity,
            priority=entity.priority,
            source_count=entity.source_count,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen,
            last_updated=datetime.now(timezone.utc).isoformat(),
            expiration=entity.expiration,
            contributing_sources=(entity.provider,) if entity.provider else tuple(),
        )

    def update_reputation(
        self,
        existing: IocReputation,
        new_confidence: float,
        new_source: Optional[str] = None,
        sighting_count: int = 0,
        false_positive_signal: float = 0.0,
    ) -> IocReputation:
        """
        Re-compute reputation after a new source or sighting is recorded.
        Merges the new evidence with the existing reputation record.
        """
        merged_confidence = min(1.0, (existing.confidence + new_confidence) / 2.0)
        new_source_count = existing.source_count + (1 if new_source else 0)
        new_fp = min(1.0, (existing.false_positive_score + false_positive_signal) / 2.0)
        new_sources = list(existing.contributing_sources)
        if new_source and new_source not in new_sources:
            new_sources.append(new_source)

        new_score = self._compute_score(
            confidence=merged_confidence,
            severity=existing.severity,
            source_count=new_source_count,
            sighting_count=sighting_count,
            false_positive_score=new_fp,
        )
        now = datetime.now(timezone.utc).isoformat()
        return IocReputation(
            ioc_id=existing.ioc_id,
            reputation_score=new_score,
            false_positive_score=new_fp,
            confidence=merged_confidence,
            severity=existing.severity,
            priority=existing.priority,
            source_count=new_source_count,
            first_seen=existing.first_seen,
            last_seen=now,
            last_updated=now,
            expiration=existing.expiration,
            contributing_sources=tuple(new_sources),
            reputation_notes=existing.reputation_notes,
        )

    def bulk_compute(
        self,
        entities: Dict[str, IocEntity],
    ) -> Dict[str, IocReputation]:
        """Compute initial reputations for all entities in the normalized dataset."""
        return {fp: self.compute_initial_reputation(entity) for fp, entity in entities.items()}

    def _compute_score(
        self,
        confidence: float,
        severity: str,
        source_count: int,
        sighting_count: int,
        false_positive_score: float,
    ) -> float:
        """
        Score formula (0.0–10.0):
          base     = confidence * severity_weight * 5
          boost    = log1p(source_count) * 0.5 + log1p(sighting_count) * 0.3
          penalty  = false_positive_score * 5
          final    = clamp(base + boost - penalty, 0, 10)
        """
        import math
        sev_w = self._SEVERITY_WEIGHT.get(severity, 0.3)
        base = confidence * sev_w * 5.0
        boost = math.log1p(source_count) * 0.5 + math.log1p(sighting_count) * 0.3
        penalty = false_positive_score * 5.0
        score = base + boost - penalty
        return round(max(0.0, min(10.0, score)), 3)
