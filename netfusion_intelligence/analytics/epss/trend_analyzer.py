"""
IL-5.1 EPSS Trend Analyzer.

Computes comprehensive trend analysis for a single CVE based on
historical snapshots.  Produces EpssTrendAnalysis with:
- Scores at multiple reference points (yesterday, 7d, 30d, 90d)
- Daily / weekly / monthly deltas
- All three moving averages (7d, 30d, 90d)
- Historical extremes and average
- Extended trend classification (11 categories)
- Forecasting mathematical indicators (slope, volatility, growth, momentum)
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from netfusion_intelligence.analytics.epss.models import (
    EpssScoreSnapshot,
    EpssTrendAnalysis,
    TrendClassification,
    TrendThresholds,
)

logger = logging.getLogger(__name__)


class EpssTrendAnalyzer:
    """
    Computes historical trend analysis for a single CVE.

    Operates purely on a list of EpssScoreSnapshot objects — no DB access.
    This makes it fully testable without any infrastructure.
    """

    def __init__(self, thresholds: Optional[TrendThresholds] = None) -> None:
        self.thresholds = thresholds or TrendThresholds()

    # ------------------------------------------------------------------
    # Primary Analysis Entry Point
    # ------------------------------------------------------------------

    def analyze(
        self,
        cve_id: str,
        history: List[EpssScoreSnapshot],
        current_score: float,
        current_percentile: float,
        reference_date: Optional[datetime] = None,
    ) -> EpssTrendAnalysis:
        """
        Produces a full EpssTrendAnalysis from a list of historical snapshots.

        `history` should be sorted newest → oldest (as returned by the repo).
        `current_score` is the live score from the active dataset.
        """
        now = reference_date or datetime.now(timezone.utc)
        today_str = now.strftime("%Y-%m-%d")

        # Sort by date ascending for computation; keep descending for reference lookups
        history_asc = sorted(history, key=lambda s: s.date)
        history_desc = sorted(history, key=lambda s: s.date, reverse=True)

        analysis = EpssTrendAnalysis(
            cve_id=cve_id,
            current_score=current_score,
            current_percentile=current_percentile,
            observation_count=len(history),
        )

        if not history:
            return analysis

        # ── Reference point scores ──────────────────────────────────
        analysis.yesterday_score = self._score_at_offset(history_desc, today_str, 1)
        analysis.score_7d = self._score_at_offset(history_desc, today_str, 7)
        analysis.score_30d = self._score_at_offset(history_desc, today_str, 30)
        analysis.score_90d = self._score_at_offset(history_desc, today_str, 90)

        # ── Deltas ──────────────────────────────────────────────────
        if analysis.yesterday_score is not None:
            analysis.daily_delta = round(current_score - analysis.yesterday_score, 6)
        if analysis.score_7d is not None:
            analysis.weekly_delta = round(current_score - analysis.score_7d, 6)
        if analysis.score_30d is not None:
            analysis.monthly_delta = round(current_score - analysis.score_30d, 6)

        # ── Moving Averages ─────────────────────────────────────────
        all_scores = [s.score for s in history_asc]
        analysis.moving_avg_7d = self._moving_average(history_desc, 7)
        analysis.moving_avg_30d = self._moving_average(history_desc, 30)
        analysis.moving_avg_90d = self._moving_average(history_desc, 90)

        # ── Historical Extremes ─────────────────────────────────────
        analysis.historical_high = max(all_scores)
        analysis.historical_low = min(all_scores)
        analysis.historical_average = round(sum(all_scores) / len(all_scores), 6)

        # ── Metadata ────────────────────────────────────────────────
        analysis.first_observed = history_asc[0].date if history_asc else None
        analysis.last_updated = history_desc[0].date if history_desc else None
        analysis.model_version = history_desc[0].model_version if history_desc else ""

        # ── Forecasting Indicators (no ML) ──────────────────────────
        analysis.volatility = self._std_dev(all_scores[-30:])
        analysis.trend_slope = self._slope(all_scores[-30:])
        analysis.growth_rate = self._growth_rate(
            all_scores[0] if len(all_scores) > 1 else current_score,
            current_score,
        )
        analysis.momentum = self._momentum(history_desc)
        analysis.prediction_confidence = self._prediction_confidence(len(history), analysis.volatility)

        # ── Trend Classification ─────────────────────────────────────
        analysis.trend = self._classify_trend(analysis, history_desc)

        return analysis

    # ------------------------------------------------------------------
    # Trend Classification
    # ------------------------------------------------------------------

    def _classify_trend(
        self,
        analysis: EpssTrendAnalysis,
        history_desc: List[EpssScoreSnapshot],
    ) -> TrendClassification:
        """
        Applies the extended 11-category trend classification rules.
        Rules are evaluated in priority order.
        """
        t = self.thresholds
        current = analysis.current_score

        if analysis.observation_count < 2:
            return TrendClassification.INSUFFICIENT_DATA

        # NEW_HIGH: current score is a new all-time high
        if analysis.historical_high is not None and current > analysis.historical_high:
            return TrendClassification.NEW_HIGH

        # NEW_LOW: current score is a new all-time low
        if analysis.historical_low is not None and current < analysis.historical_low:
            return TrendClassification.NEW_LOW

        # CONSISTENTLY_HIGH: average score above high threshold
        if (
            analysis.historical_average is not None
            and analysis.historical_average >= t.consistently_high_min_avg
            and current >= t.high_risk_score
        ):
            return TrendClassification.CONSISTENTLY_HIGH

        # CONSISTENTLY_LOW: average score below low threshold
        if (
            analysis.historical_average is not None
            and analysis.historical_average <= t.consistently_low_max_avg
        ):
            return TrendClassification.CONSISTENTLY_LOW

        # RECOVERY_TREND: previously low, recently recovering
        if self._is_recovery(history_desc, current):
            return TrendClassification.RECOVERY_TREND

        # Delta-based classifications
        daily_delta = analysis.daily_delta or 0.0

        if daily_delta >= t.rapidly_increasing_threshold:
            return TrendClassification.RAPIDLY_INCREASING
        if daily_delta >= t.increasing_threshold:
            return TrendClassification.INCREASING
        if daily_delta <= t.rapidly_decreasing_threshold:
            return TrendClassification.RAPIDLY_DECREASING
        if daily_delta <= t.decreasing_threshold:
            return TrendClassification.DECREASING

        return TrendClassification.STABLE

    def _is_recovery(
        self,
        history_desc: List[EpssScoreSnapshot],
        current: float,
        lookback: int = 14,
    ) -> bool:
        """
        Returns True if:
        - Score dropped significantly in the earlier window
        - AND has been increasing in the recent window
        """
        t = self.thresholds
        if len(history_desc) < lookback:
            return False

        recent = history_desc[: lookback // 2]
        older = history_desc[lookback // 2 : lookback]

        if not recent or not older:
            return False

        recent_avg = sum(s.score for s in recent) / len(recent)
        older_avg = sum(s.score for s in older) / len(older)

        return (
            recent_avg > older_avg + t.recovery_delta_threshold
            and current > recent_avg
        )

    # ------------------------------------------------------------------
    # Moving Average
    # ------------------------------------------------------------------

    @staticmethod
    def _moving_average(
        history_desc: List[EpssScoreSnapshot],
        window: int,
    ) -> Optional[float]:
        """Simple moving average over the most recent `window` observations."""
        subset = history_desc[:window]
        if not subset:
            return None
        return round(sum(s.score for s in subset) / len(subset), 6)

    # ------------------------------------------------------------------
    # Reference Score at Date Offset
    # ------------------------------------------------------------------

    @staticmethod
    def _score_at_offset(
        history_desc: List[EpssScoreSnapshot],
        today_str: str,
        offset_days: int,
    ) -> Optional[float]:
        """
        Returns score closest to (today - offset_days).
        Looks for the nearest match within ±2 days to handle sparse data.
        """
        target_dt = datetime.strptime(today_str, "%Y-%m-%d") - timedelta(days=offset_days)
        target_str = target_dt.strftime("%Y-%m-%d")
        tolerance_str = (target_dt - timedelta(days=2)).strftime("%Y-%m-%d")

        # Find closest snapshot at or before target
        candidates = [s for s in history_desc if tolerance_str <= s.date <= target_str]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.date).score

    # ------------------------------------------------------------------
    # Mathematical Indicators
    # ------------------------------------------------------------------

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return round(math.sqrt(variance), 8)

    @staticmethod
    def _slope(values: List[float]) -> float:
        """
        Linear regression slope over the provided values.
        Positive = increasing trend, negative = decreasing.
        """
        n = len(values)
        if n < 2:
            return 0.0
        xs = list(range(n))
        x_mean = (n - 1) / 2.0
        y_mean = sum(values) / n
        num = sum((xs[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        den = sum((xs[i] - x_mean) ** 2 for i in range(n))
        return round(num / den, 8) if den else 0.0

    @staticmethod
    def _growth_rate(start: float, end: float) -> Optional[float]:
        """Percentage change from start to end."""
        if start == 0:
            return None
        return round((end - start) / start * 100.0, 4)

    @staticmethod
    def _momentum(history_desc: List[EpssScoreSnapshot], window: int = 5) -> float:
        """
        Weighted recent delta — more recent observations carry higher weight.
        Implements exponential weighting: weight[i] = 2^(window-i).
        """
        if len(history_desc) < 2:
            return 0.0

        subset = history_desc[: window + 1]
        if len(subset) < 2:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0
        for i in range(1, len(subset)):
            weight = 2 ** (len(subset) - i)
            delta = subset[i - 1].score - subset[i].score
            weighted_sum += delta * weight
            total_weight += weight

        return round(weighted_sum / total_weight, 8) if total_weight else 0.0

    @staticmethod
    def _prediction_confidence(observation_count: int, volatility: float) -> float:
        """
        Foundation only — returns a confidence proxy between 0.0 and 1.0.
        More observations and lower volatility → higher confidence.
        Formula: confidence = min(obs/90, 1.0) * (1 - min(volatility/0.2, 1.0))
        """
        obs_factor = min(observation_count / 90.0, 1.0)
        vol_penalty = min(volatility / 0.2, 1.0)
        return round(obs_factor * (1.0 - vol_penalty), 4)
