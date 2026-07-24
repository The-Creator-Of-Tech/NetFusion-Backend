"""
IL-5.1 EPSS Analytics Statistics Engine.

Computes system-wide and time-window-scoped statistics over
historical EPSS data.  No ML.  Pure mathematical aggregations.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from netfusion_intelligence.analytics.epss.models import (
    EpssAnalyticsSummary,
    EpssScoreSnapshot,
    TrendClassification,
)
from netfusion_intelligence.analytics.epss.repository import EpssAnalyticsRepository

logger = logging.getLogger(__name__)


class EpssStatisticsEngine:
    """
    Computes comprehensive statistics over historical EPSS data.

    All computations operate on data already stored by the IL-5
    pipeline — no ingestion code is modified.
    """

    HIGH_RISK_THRESHOLD = 0.50
    CRITICAL_THRESHOLD = 0.70

    def __init__(self, analytics_repo: EpssAnalyticsRepository) -> None:
        self._repo = analytics_repo

    # ------------------------------------------------------------------
    # Global Statistics
    # ------------------------------------------------------------------

    def get_global_statistics(
        self,
        time_window_days: int = 7,
        limit_cves: int = 5_000,
    ) -> EpssAnalyticsSummary:
        """
        Computes global EPSS analytics statistics for the given time window.
        """
        now = datetime.now(timezone.utc)
        summary = EpssAnalyticsSummary(time_window=f"{time_window_days}d")

        # All current scores
        all_scores = self._repo.list_current_scores(limit=limit_cves)
        summary.total_cves_analyzed = len(all_scores)

        if not all_scores:
            return summary

        # Trend distribution from stored trend field
        trend_dist: Dict[str, int] = {}
        risk_dist: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for rec in all_scores:
            trend = str(rec.get("trend", "INSUFFICIENT_DATA"))
            trend_dist[trend] = trend_dist.get(trend, 0) + 1

            score = float(rec.get("epss_score", 0.0))
            if score >= self.CRITICAL_THRESHOLD:
                risk_dist["CRITICAL"] += 1
            elif score >= self.HIGH_RISK_THRESHOLD:
                risk_dist["HIGH"] += 1
            elif score >= 0.1:
                risk_dist["MEDIUM"] += 1
            else:
                risk_dist["LOW"] += 1

        summary.trend_distribution = trend_dist
        summary.risk_distribution = risk_dist

        # Delta statistics
        delta_stats = self._repo.get_daily_delta_statistics(limit_cves=limit_cves)
        summary.average_daily_change = delta_stats.get("average_daily_change", 0.0)
        summary.largest_daily_increase = delta_stats.get("largest_daily_increase")
        summary.largest_daily_increase_cve = delta_stats.get("largest_daily_increase_cve")

        # Weekly and monthly largest increases
        weekly_rising = self._repo.get_top_rising_in_window(days=7, limit=1, reference_date=now)
        if weekly_rising:
            summary.largest_weekly_increase = weekly_rising[0].get("delta")
            summary.largest_weekly_increase_cve = weekly_rising[0].get("cve_id")

        monthly_rising = self._repo.get_top_rising_in_window(days=30, limit=1, reference_date=now)
        if monthly_rising:
            summary.largest_monthly_increase = monthly_rising[0].get("delta")
            summary.largest_monthly_increase_cve = monthly_rising[0].get("cve_id")

        # Average weekly change
        summary.average_weekly_change = self._compute_average_weekly_change(
            all_scores[:500], now  # sample to avoid N+1 on large datasets
        )

        # Most stable / volatile
        stability_data = self._compute_stability(all_scores[:500], window_days=time_window_days)
        summary.most_stable_cves = stability_data["stable"][:10]
        summary.most_volatile_cves = stability_data["volatile"][:10]

        # New high-risk count
        new_high_risk = self._repo.get_new_high_risk_cves(
            lookback_days=time_window_days,
            reference_date=now,
        )
        summary.high_risk_alerts_count = len(new_high_risk)
        summary.new_high_risk_cves = [r["cve_id"] for r in new_high_risk[:20]]
        summary.cves_with_history = len(new_high_risk)  # approximate

        return summary

    # ------------------------------------------------------------------
    # Time-Window Statistics
    # ------------------------------------------------------------------

    def get_score_statistics(
        self,
        cve_id: str,
        window_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Returns per-CVE statistics over a time window.
        """
        history = self._repo.get_history(cve_id, limit=window_days + 5)
        if not history:
            return {"cve_id": cve_id, "observation_count": 0}

        scores = [s.score for s in history]
        deltas = [s.daily_delta_score for s in history]

        return {
            "cve_id": cve_id,
            "observation_count": len(scores),
            "current_score": scores[0] if scores else 0.0,
            "average_score": self._mean(scores),
            "median_score": self._median(scores),
            "min_score": min(scores),
            "max_score": max(scores),
            "std_deviation": self._std_dev(scores),
            "average_daily_delta": self._mean(deltas),
            "max_daily_delta": max(deltas) if deltas else 0.0,
            "min_daily_delta": min(deltas) if deltas else 0.0,
            "window_days": window_days,
        }

    # ------------------------------------------------------------------
    # Stability / Volatility
    # ------------------------------------------------------------------

    def _compute_stability(
        self,
        all_scores: List[Dict[str, Any]],
        window_days: int = 7,
    ) -> Dict[str, List[str]]:
        """
        Ranks CVEs by std-deviation of recent scores (low = stable, high = volatile).
        """
        volatility_scores: List[Tuple[str, float]] = []

        for rec in all_scores:
            cve_id = rec.get("cve_id", "")
            history = self._repo.get_history(cve_id, limit=window_days + 2)
            if len(history) < 3:
                continue
            scores = [s.score for s in history[:window_days]]
            vol = self._std_dev(scores)
            volatility_scores.append((cve_id, vol))

        volatility_scores.sort(key=lambda x: x[1])
        stable = [cve_id for cve_id, _ in volatility_scores[:20]]
        volatile = [cve_id for cve_id, _ in reversed(volatility_scores[-20:])]
        return {"stable": stable, "volatile": volatile}

    # ------------------------------------------------------------------
    # Average Weekly Change
    # ------------------------------------------------------------------

    def _compute_average_weekly_change(
        self,
        sample_scores: List[Dict[str, Any]],
        now: datetime,
    ) -> float:
        """
        Computes average (current - 7d_ago) across the sample.
        """
        past_7d = (now - timedelta(days=7)).strftime("%Y-%m-%d")
        deltas: List[float] = []

        for rec in sample_scores:
            cve_id = rec.get("cve_id", "")
            current = float(rec.get("epss_score", 0.0))
            past = self._repo.get_score_at_date(cve_id, past_7d)
            if past:
                deltas.append(current - past.score)

        return self._mean(deltas) if deltas else 0.0

    # ------------------------------------------------------------------
    # Math helpers (stdlib only — no numpy)
    # ------------------------------------------------------------------

    @staticmethod
    def _mean(values: List[float]) -> float:
        return round(sum(values) / len(values), 6) if values else 0.0

    @staticmethod
    def _median(values: List[float]) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        mid = n // 2
        return s[mid] if n % 2 else round((s[mid - 1] + s[mid]) / 2, 6)

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return round(math.sqrt(variance), 6)

    @staticmethod
    def _slope(values: List[float]) -> float:
        """Simple linear regression slope (y = mx + b, returns m)."""
        n = len(values)
        if n < 2:
            return 0.0
        xs = list(range(n))
        x_mean = (n - 1) / 2.0
        y_mean = sum(values) / n
        numerator = sum((xs[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((xs[i] - x_mean) ** 2 for i in range(n))
        return round(numerator / denominator, 8) if denominator else 0.0

    @staticmethod
    def _growth_rate(old_value: float, new_value: float) -> Optional[float]:
        """Percentage growth from old to new."""
        if old_value == 0:
            return None
        return round((new_value - old_value) / old_value * 100.0, 4)
