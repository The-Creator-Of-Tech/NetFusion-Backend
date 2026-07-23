"""
Statistics aggregation engine for FIRST EPSS Intelligence Pipeline.
Computes and tracks EPSS dataset metrics and trends.
"""

import logging
from typing import Any, Dict, List

from netfusion_intelligence.feeds.epss.models import EpssRecord

logger = logging.getLogger(__name__)


class EpssStatistics:
    """
    Computes statistics and metrics for EPSS datasets.
    """

    def __init__(self):
        self._last_stats: Dict[str, Any] = {}

    @property
    def last_statistics(self) -> Dict[str, Any]:
        return self._last_stats

    def calculate_statistics(
        self,
        records: List[EpssRecord],
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculates comprehensive statistics for an EPSS dataset.
        """
        if not records:
            return self._empty_statistics()

        metadata = metadata or {}

        scores = [rec.current_score for rec in records]
        percentiles = [rec.current_percentile for rec in records]

        total_records = len(records)
        avg_score = sum(scores) / total_records if scores else 0.0
        avg_percentile = sum(percentiles) / total_records if percentiles else 0.0

        high_prob = sum(1 for s in scores if s >= 0.5)
        medium_prob = sum(1 for s in scores if 0.1 <= s < 0.5)
        low_prob = sum(1 for s in scores if s < 0.1)

        critical_threshold = 0.7
        critical_cves = sum(1 for s in scores if s >= critical_threshold)

        # Trend distribution
        trend_counts = {}
        for rec in records:
            trend_counts[rec.trend] = trend_counts.get(rec.trend, 0) + 1

        # Score distribution buckets
        score_buckets = self._calculate_score_distribution(scores)

        # Top CVEs by score
        sorted_records = sorted(records, key=lambda r: r.current_score, reverse=True)
        top_cves = [
            {
                "cve_id": rec.cve_id,
                "epss_score": rec.current_score,
                "epss_percentile": rec.current_percentile,
                "trend": rec.trend,
            }
            for rec in sorted_records[:20]
        ]

        # Daily delta statistics (if available)
        largest_increases = []
        largest_decreases = []

        stats = {
            "total_records": total_records,
            "average_score": round(avg_score, 6),
            "average_percentile": round(avg_percentile, 6),
            "highest_score": max(scores) if scores else 0.0,
            "lowest_score": min(scores) if scores else 0.0,
            "median_score": self._calculate_median(scores),
            "high_probability_cves": high_prob,
            "medium_probability_cves": medium_prob,
            "low_probability_cves": low_prob,
            "critical_cves": critical_cves,
            "trend_distribution": trend_counts,
            "score_distribution": score_buckets,
            "top_cves": top_cves,
            "largest_increases": largest_increases,
            "largest_decreases": largest_decreases,
            "model_version": metadata.get("model_version", ""),
            "score_date": metadata.get("score_date", ""),
        }

        self._last_stats = stats
        logger.info(
            f"EPSS statistics calculated: {total_records} records, "
            f"avg_score={avg_score:.4f}, high_prob={high_prob}"
        )

        return stats

    def _empty_statistics(self) -> Dict[str, Any]:
        """Returns empty statistics structure."""
        return {
            "total_records": 0,
            "average_score": 0.0,
            "average_percentile": 0.0,
            "highest_score": 0.0,
            "lowest_score": 0.0,
            "median_score": 0.0,
            "high_probability_cves": 0,
            "medium_probability_cves": 0,
            "low_probability_cves": 0,
            "critical_cves": 0,
            "trend_distribution": {},
            "score_distribution": {},
            "top_cves": [],
            "largest_increases": [],
            "largest_decreases": [],
        }

    def _calculate_score_distribution(self, scores: List[float]) -> Dict[str, int]:
        """
        Groups scores into distribution buckets.
        """
        buckets = {
            "0.0-0.1": 0,
            "0.1-0.2": 0,
            "0.2-0.3": 0,
            "0.3-0.4": 0,
            "0.4-0.5": 0,
            "0.5-0.6": 0,
            "0.6-0.7": 0,
            "0.7-0.8": 0,
            "0.8-0.9": 0,
            "0.9-1.0": 0,
        }

        for score in scores:
            if score < 0.1:
                buckets["0.0-0.1"] += 1
            elif score < 0.2:
                buckets["0.1-0.2"] += 1
            elif score < 0.3:
                buckets["0.2-0.3"] += 1
            elif score < 0.4:
                buckets["0.3-0.4"] += 1
            elif score < 0.5:
                buckets["0.4-0.5"] += 1
            elif score < 0.6:
                buckets["0.5-0.6"] += 1
            elif score < 0.7:
                buckets["0.6-0.7"] += 1
            elif score < 0.8:
                buckets["0.7-0.8"] += 1
            elif score < 0.9:
                buckets["0.8-0.9"] += 1
            else:
                buckets["0.9-1.0"] += 1

        return buckets

    def _calculate_median(self, values: List[float]) -> float:
        """Calculates median value from a list of floats."""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        n = len(sorted_values)
        mid = n // 2

        if n % 2 == 0:
            return (sorted_values[mid - 1] + sorted_values[mid]) / 2.0
        else:
            return sorted_values[mid]
