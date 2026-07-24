"""
Historical score tracking for FIRST EPSS Intelligence Pipeline.
Manages daily score snapshots, trend persistence, and delta computation.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.feeds.epss.models import EpssHistoricalScore, EpssRecord
from netfusion_intelligence.feeds.epss.scoring import EpssScoringEngine

logger = logging.getLogger(__name__)


class EpssHistoryTracker:
    """
    Tracks and manages historical EPSS score data for each CVE.
    Supports trend analysis, delta computation, and moving averages.
    """

    def __init__(self, scoring_engine: Optional[EpssScoringEngine] = None):
        self.scoring_engine = scoring_engine or EpssScoringEngine()

    def build_historical_snapshots(
        self,
        records: List[EpssRecord],
        dataset_version: str,
        previous_scores: Optional[Dict[str, float]] = None,
    ) -> List[EpssHistoricalScore]:
        """
        Creates EpssHistoricalScore snapshots from the current dataset.
        Computes daily deltas when previous scores are available.
        """
        previous_scores = previous_scores or {}
        snapshots: List[EpssHistoricalScore] = []

        for record in records:
            cve_id = record.cve_id
            prev_score = previous_scores.get(cve_id, record.current_score)
            prev_percentile = previous_scores.get(f"{cve_id}_percentile", record.current_percentile)

            daily_delta_score = self.scoring_engine.calculate_daily_delta(
                current_score=record.current_score,
                previous_score=prev_score,
            )

            daily_delta_percentile = self.scoring_engine.calculate_daily_delta(
                current_score=record.current_percentile,
                previous_score=prev_percentile,
            )

            snapshot = EpssHistoricalScore(
                cve_id=cve_id,
                epss_score=record.current_score,
                epss_percentile=record.current_percentile,
                date=record.publication_date,
                dataset_version=dataset_version,
                model_version=record.model_version,
                daily_delta_score=daily_delta_score,
                daily_delta_percentile=daily_delta_percentile,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

            snapshots.append(snapshot)

        logger.info(f"Built {len(snapshots)} historical snapshots for dataset {dataset_version}")
        return snapshots

    def enrich_records_with_history(
        self,
        records: List[EpssRecord],
        historical_data: Dict[str, List[EpssHistoricalScore]],
    ) -> List[EpssRecord]:
        """
        Enriches current EpssRecord objects with historical metrics and trends.
        Returns new immutable EpssRecord objects with updated historical fields.
        """
        enriched_records = []

        for record in records:
            cve_history = historical_data.get(record.cve_id, [])

            if not cve_history:
                enriched_records.append(record)
                continue

            # Add current score to history for trend calculation
            all_scores = list(cve_history)

            # Calculate trend
            trend = self.scoring_engine.calculate_trend(all_scores, window_days=7)

            # Calculate historical metrics
            metrics = self.scoring_engine.calculate_historical_metrics(all_scores)

            # Create enriched record
            enriched = EpssRecord(
                cve_id=record.cve_id,
                current_score=record.current_score,
                current_percentile=record.current_percentile,
                publication_date=record.publication_date,
                model_version=record.model_version,
                dataset_version=record.dataset_version,
                trend=trend,
                moving_avg_7d=metrics.get("moving_avg_7d"),
                moving_avg_30d=metrics.get("moving_avg_30d"),
                historical_high=metrics.get("historical_high"),
                historical_low=metrics.get("historical_low"),
                first_observed=record.first_observed,
                last_updated=datetime.now(timezone.utc).isoformat(),
                observation_count=len(cve_history) + 1,
                source=record.source,
                status=record.status,
                metadata=record.metadata,
            )

            enriched_records.append(enriched)

        logger.info(f"Enriched {len(enriched_records)} records with historical data")
        return enriched_records

    def identify_trending_cves(
        self,
        records: List[EpssRecord],
        min_delta: float = 0.05,
    ) -> Dict[str, List[EpssRecord]]:
        """
        Identifies CVEs with significant score changes.
        Returns dict with 'increasing' and 'decreasing' lists.
        """
        increasing = []
        decreasing = []

        for record in records:
            if record.trend in ("RAPIDLY_INCREASING", "INCREASING"):
                increasing.append(record)
            elif record.trend in ("RAPIDLY_DECREASING", "DECREASING"):
                decreasing.append(record)

        # Sort by score descending
        increasing.sort(key=lambda r: r.current_score, reverse=True)
        decreasing.sort(key=lambda r: r.current_score, reverse=True)

        return {
            "increasing": increasing,
            "decreasing": decreasing,
            "rapidly_increasing": [r for r in increasing if r.trend == "RAPIDLY_INCREASING"],
            "rapidly_decreasing": [r for r in decreasing if r.trend == "RAPIDLY_DECREASING"],
        }

    def get_daily_deltas(
        self,
        snapshots: List[EpssHistoricalScore],
        top_n: int = 20,
    ) -> Dict[str, List[EpssHistoricalScore]]:
        """
        Returns the CVEs with the largest daily score increases and decreases.
        """
        sorted_by_delta = sorted(snapshots, key=lambda s: s.daily_delta_score)

        largest_decreases = sorted_by_delta[:top_n]
        largest_increases = sorted_by_delta[-top_n:]
        largest_increases.reverse()

        return {
            "largest_increases": largest_increases,
            "largest_decreases": largest_decreases,
        }
