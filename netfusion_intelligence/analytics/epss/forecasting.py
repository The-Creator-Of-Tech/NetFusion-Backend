"""
IL-5.1 EPSS Forecasting Foundation.

Prepares mathematical indicators for future AI-driven forecasting.
NO machine learning is implemented here.
Stores: trend_slope, volatility, growth_rate, moving_average, momentum,
        prediction_confidence.

These indicators are computed from historical data and exposed via the
analytics API so they are available as features when a forecasting
model is introduced in a later IL phase.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

from netfusion_intelligence.analytics.epss.models import (
    EpssScoreSnapshot,
    EpssTrendAnalysis,
)
from netfusion_intelligence.analytics.epss.trend_analyzer import EpssTrendAnalyzer

logger = logging.getLogger(__name__)


class EpssForecastingFoundation:
    """
    Computes and packages the mathematical indicators that will underpin
    future ML-based EPSS forecasting.

    Current scope: purely deterministic maths — no statistical models.
    """

    def __init__(self, trend_analyzer: Optional[EpssTrendAnalyzer] = None) -> None:
        self._analyzer = trend_analyzer or EpssTrendAnalyzer()

    # ------------------------------------------------------------------
    # Public Interface
    # ------------------------------------------------------------------

    def prepare_forecast_indicators(
        self,
        cve_id: str,
        history: List[EpssScoreSnapshot],
        current_score: float,
        current_percentile: float,
    ) -> Dict[str, Any]:
        """
        Computes all forecasting indicators for a single CVE.

        Returns a dict suitable for API serialization and future ML feature extraction.
        """
        if not history or len(history) < 2:
            return self._empty_indicators(cve_id)

        # Re-use trend analysis to avoid duplication
        analysis = self._analyzer.analyze(
            cve_id=cve_id,
            history=history,
            current_score=current_score,
            current_percentile=current_percentile,
        )

        # Compute additional window-specific moving averages
        scores_desc = [s.score for s in sorted(history, key=lambda s: s.date, reverse=True)]

        return {
            "cve_id": cve_id,
            "current_score": current_score,
            "current_percentile": current_percentile,
            # Core indicators
            "trend_slope": analysis.trend_slope,
            "volatility": analysis.volatility,
            "growth_rate": analysis.growth_rate,
            "momentum": analysis.momentum,
            "prediction_confidence": analysis.prediction_confidence,
            # Moving averages for multiple windows
            "moving_avg_7d": analysis.moving_avg_7d,
            "moving_avg_30d": analysis.moving_avg_30d,
            "moving_avg_90d": analysis.moving_avg_90d,
            # Historical context
            "historical_high": analysis.historical_high,
            "historical_low": analysis.historical_low,
            "historical_average": analysis.historical_average,
            "observation_count": analysis.observation_count,
            # Delta reference points
            "daily_delta": analysis.daily_delta,
            "weekly_delta": analysis.weekly_delta,
            "monthly_delta": analysis.monthly_delta,
            # Classification
            "trend_classification": analysis.trend.value,
            # Additional derived indicators
            "range_utilization": self._range_utilization(
                current_score, analysis.historical_low, analysis.historical_high
            ),
            "score_percentile_ratio": self._score_percentile_ratio(
                current_score, current_percentile
            ),
            "recent_acceleration": self._recent_acceleration(scores_desc),
            # Feature readiness flag for future ML pipeline
            "ml_ready": analysis.observation_count >= 7,
            "feature_version": "il5.1-v1",
        }

    def prepare_batch_indicators(
        self,
        analyses: List[EpssTrendAnalysis],
    ) -> List[Dict[str, Any]]:
        """
        Packages forecasting indicators from pre-computed trend analyses.
        Efficient for bulk API responses.
        """
        results: List[Dict[str, Any]] = []
        for analysis in analyses:
            scores = []  # Individual scores not available at this point
            indicators = {
                "cve_id": analysis.cve_id,
                "current_score": analysis.current_score,
                "trend_slope": analysis.trend_slope,
                "volatility": analysis.volatility,
                "growth_rate": analysis.growth_rate,
                "momentum": analysis.momentum,
                "prediction_confidence": analysis.prediction_confidence,
                "moving_avg_7d": analysis.moving_avg_7d,
                "moving_avg_30d": analysis.moving_avg_30d,
                "moving_avg_90d": analysis.moving_avg_90d,
                "daily_delta": analysis.daily_delta,
                "weekly_delta": analysis.weekly_delta,
                "monthly_delta": analysis.monthly_delta,
                "trend_classification": analysis.trend.value,
                "observation_count": analysis.observation_count,
                "ml_ready": analysis.observation_count >= 7,
                "feature_version": "il5.1-v1",
            }
            results.append(indicators)
        return results

    # ------------------------------------------------------------------
    # Derived Indicators
    # ------------------------------------------------------------------

    @staticmethod
    def _range_utilization(
        current: float,
        hist_low: Optional[float],
        hist_high: Optional[float],
    ) -> Optional[float]:
        """
        Current score position within historical range.
        0.0 = at historical low, 1.0 = at historical high.
        """
        if hist_low is None or hist_high is None:
            return None
        spread = hist_high - hist_low
        if spread == 0:
            return 1.0
        return round((current - hist_low) / spread, 4)

    @staticmethod
    def _score_percentile_ratio(score: float, percentile: float) -> Optional[float]:
        """
        EPSS score / percentile ratio.
        A high ratio (score >> percentile) can indicate a concentrated spike.
        """
        if percentile == 0:
            return None
        return round(score / percentile, 4)

    @staticmethod
    def _recent_acceleration(scores_desc: List[float], window: int = 5) -> float:
        """
        Second derivative of recent scores — rate of change of the rate of change.
        Positive = acceleration, Negative = deceleration.
        """
        if len(scores_desc) < window + 2:
            return 0.0

        recent = list(reversed(scores_desc[: window + 1]))  # Ascending order
        first_deltas = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        if len(first_deltas) < 2:
            return 0.0

        second_deltas = [
            first_deltas[i + 1] - first_deltas[i] for i in range(len(first_deltas) - 1)
        ]
        return round(sum(second_deltas) / len(second_deltas), 8)

    # ------------------------------------------------------------------
    # Empty fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_indicators(cve_id: str) -> Dict[str, Any]:
        return {
            "cve_id": cve_id,
            "current_score": 0.0,
            "trend_slope": None,
            "volatility": None,
            "growth_rate": None,
            "momentum": None,
            "prediction_confidence": None,
            "moving_avg_7d": None,
            "moving_avg_30d": None,
            "moving_avg_90d": None,
            "daily_delta": None,
            "weekly_delta": None,
            "monthly_delta": None,
            "trend_classification": "INSUFFICIENT_DATA",
            "observation_count": 0,
            "ml_ready": False,
            "feature_version": "il5.1-v1",
        }
