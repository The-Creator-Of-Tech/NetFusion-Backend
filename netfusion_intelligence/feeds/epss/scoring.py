"""
EPSS Scoring Engine for trend analysis and risk classification.
Calculates score trends, moving averages, and classification labels.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from netfusion_intelligence.feeds.epss.models import EpssHistoricalScore, EpssTrend

logger = logging.getLogger(__name__)


class EpssScoringEngine:
    """
    Analyzes EPSS score history to calculate trends, moving averages,
    and classification labels for risk prioritization.
    """

    def __init__(self):
        pass

    def calculate_trend(
        self,
        historical_scores: List[EpssHistoricalScore],
        window_days: int = 7,
    ) -> str:
        """
        Calculates trend classification from historical EPSS scores.

        Trend Classification:
        - RAPIDLY_INCREASING: avg delta > +0.1 per day
        - INCREASING: avg delta > +0.01 per day
        - STABLE: -0.01 <= avg delta <= +0.01
        - DECREASING: avg delta < -0.01 per day
        - RAPIDLY_DECREASING: avg delta < -0.1 per day
        - INSUFFICIENT_DATA: < 2 data points
        """
        if not historical_scores or len(historical_scores) < 2:
            return EpssTrend.INSUFFICIENT_DATA.value

        # Sort by date ascending
        sorted_scores = sorted(historical_scores, key=lambda x: x.date)

        # Take most recent window_days
        recent_scores = sorted_scores[-window_days:] if len(sorted_scores) > window_days else sorted_scores

        if len(recent_scores) < 2:
            return EpssTrend.INSUFFICIENT_DATA.value

        # Calculate average daily delta
        total_delta = 0.0
        delta_count = 0

        for i in range(1, len(recent_scores)):
            prev = recent_scores[i - 1]
            curr = recent_scores[i]
            delta = curr.epss_score - prev.epss_score
            total_delta += delta
            delta_count += 1

        avg_daily_delta = total_delta / delta_count if delta_count > 0 else 0.0

        # Classify trend
        if avg_daily_delta >= 0.1:
            return EpssTrend.RAPIDLY_INCREASING.value
        elif avg_daily_delta >= 0.01:
            return EpssTrend.INCREASING.value
        elif avg_daily_delta <= -0.1:
            return EpssTrend.RAPIDLY_DECREASING.value
        elif avg_daily_delta <= -0.01:
            return EpssTrend.DECREASING.value
        else:
            return EpssTrend.STABLE.value

    def calculate_moving_average(
        self,
        historical_scores: List[EpssHistoricalScore],
        window_days: int = 7,
    ) -> Optional[float]:
        """
        Calculates simple moving average of EPSS scores over window_days.
        """
        if not historical_scores:
            return None

        sorted_scores = sorted(historical_scores, key=lambda x: x.date, reverse=True)
        recent_scores = sorted_scores[:window_days]

        if not recent_scores:
            return None

        avg = sum(s.epss_score for s in recent_scores) / len(recent_scores)
        return round(avg, 6)

    def calculate_historical_metrics(
        self,
        historical_scores: List[EpssHistoricalScore],
    ) -> Dict[str, Optional[float]]:
        """
        Calculates comprehensive historical metrics.

        Returns dict with:
        - historical_high: highest score ever recorded
        - historical_low: lowest score ever recorded
        - moving_avg_7d: 7-day moving average
        - moving_avg_30d: 30-day moving average
        """
        if not historical_scores:
            return {
                "historical_high": None,
                "historical_low": None,
                "moving_avg_7d": None,
                "moving_avg_30d": None,
            }

        scores = [s.epss_score for s in historical_scores]
        historical_high = max(scores)
        historical_low = min(scores)

        moving_avg_7d = self.calculate_moving_average(historical_scores, window_days=7)
        moving_avg_30d = self.calculate_moving_average(historical_scores, window_days=30)

        return {
            "historical_high": round(historical_high, 6),
            "historical_low": round(historical_low, 6),
            "moving_avg_7d": moving_avg_7d,
            "moving_avg_30d": moving_avg_30d,
        }

    def calculate_daily_delta(
        self,
        current_score: float,
        previous_score: float,
    ) -> float:
        """
        Calculates daily score delta.
        """
        return round(current_score - previous_score, 6)

    def classify_risk_level(
        self,
        epss_score: float,
        epss_percentile: float,
        trend: str,
        cvss_score: Optional[float] = None,
        kev_status: bool = False,
    ) -> str:
        """
        Classifies overall risk level based on EPSS and other factors.
        This is a foundation for future composite risk scoring.

        Risk Classification:
        - CRITICAL: EPSS >= 0.7 OR (KEV && EPSS >= 0.3)
        - HIGH: EPSS >= 0.5 OR (EPSS >= 0.3 && CVSS >= 7.0)
        - MEDIUM: EPSS >= 0.1
        - LOW: EPSS < 0.1
        """
        if kev_status and epss_score >= 0.3:
            return "CRITICAL"

        if epss_score >= 0.7:
            return "CRITICAL"

        if epss_score >= 0.5:
            return "HIGH"

        if cvss_score and epss_score >= 0.3 and cvss_score >= 7.0:
            return "HIGH"

        if epss_score >= 0.1:
            return "MEDIUM"

        return "LOW"

    def calculate_composite_risk_inputs(
        self,
        epss_score: float,
        epss_percentile: float,
        trend: str,
        cvss_score: Optional[float] = None,
        kev_status: bool = False,
        asset_criticality: Optional[str] = None,
        exposure: Optional[str] = None,
    ) -> Dict[str, any]:
        """
        Prepares inputs for future composite risk scoring algorithm.
        Does NOT implement the final algorithm - only structures the inputs.

        Future composite risk formula might be:
        composite_risk = (
            0.40 * epss_normalized +
            0.25 * cvss_normalized +
            0.15 * kev_multiplier +
            0.10 * trend_factor +
            0.05 * asset_criticality +
            0.05 * exposure
        )
        """
        inputs = {
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "epss_trend": trend,
            "cvss_score": cvss_score,
            "kev_status": kev_status,
            "asset_criticality": asset_criticality,
            "exposure": exposure,
            # Normalized values for future computation
            "epss_normalized": epss_score,  # Already 0.0-1.0
            "cvss_normalized": (cvss_score / 10.0) if cvss_score else None,
            "kev_multiplier": 2.0 if kev_status else 1.0,
            "trend_factor": self._trend_to_factor(trend),
        }

        return inputs

    def _trend_to_factor(self, trend: str) -> float:
        """
        Converts trend classification to a numeric factor for future composite scoring.
        """
        trend_map = {
            "RAPIDLY_INCREASING": 1.5,
            "INCREASING": 1.2,
            "STABLE": 1.0,
            "DECREASING": 0.8,
            "RAPIDLY_DECREASING": 0.6,
            "INSUFFICIENT_DATA": 1.0,
        }
        return trend_map.get(trend, 1.0)
