"""
IL-5.1 EPSS Ranking Engine.

Produces ranked lists of CVEs across nine ranking dimensions.
Operates on data from the analytics repository — no ingestion changes.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.analytics.epss.models import (
    EpssQueryFilter,
    EpssRankedEntry,
    RankingCriteria,
    TrendClassification,
)
from netfusion_intelligence.analytics.epss.repository import EpssAnalyticsRepository

logger = logging.getLogger(__name__)

_TREND_FROM_STR = {t.value: t for t in TrendClassification}


class EpssRankingEngine:
    """
    Computes ranked EPSS lists for threat prioritization.

    All nine ranking criteria are supported:
    1. Largest Daily Increase
    2. Largest Weekly Increase
    3. Largest Monthly Increase
    4. Highest Current Score
    5. Highest Percentile
    6. Fastest Rising (slope-based)
    7. Fastest Falling (slope-based)
    8. Recently Entered High Risk
    9. Recently Left High Risk
    """

    HIGH_RISK_THRESHOLD = 0.50

    def __init__(self, analytics_repo: EpssAnalyticsRepository) -> None:
        self._repo = analytics_repo

    # ------------------------------------------------------------------
    # Public Ranking Methods
    # ------------------------------------------------------------------

    def rank_by(
        self,
        criteria: RankingCriteria,
        query_filter: Optional[EpssQueryFilter] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """
        Dispatcher — routes to the appropriate ranking method.
        """
        f = query_filter or EpssQueryFilter()
        now = reference_date or datetime.now(timezone.utc)

        dispatch = {
            RankingCriteria.LARGEST_DAILY_INCREASE: lambda: self._rank_largest_increase(
                days=1, criteria=RankingCriteria.LARGEST_DAILY_INCREASE, f=f, now=now
            ),
            RankingCriteria.LARGEST_WEEKLY_INCREASE: lambda: self._rank_largest_increase(
                days=7, criteria=RankingCriteria.LARGEST_WEEKLY_INCREASE, f=f, now=now
            ),
            RankingCriteria.LARGEST_MONTHLY_INCREASE: lambda: self._rank_largest_increase(
                days=30, criteria=RankingCriteria.LARGEST_MONTHLY_INCREASE, f=f, now=now
            ),
            RankingCriteria.HIGHEST_CURRENT_SCORE: lambda: self._rank_by_current_score(f),
            RankingCriteria.HIGHEST_PERCENTILE: lambda: self._rank_by_percentile(f),
            RankingCriteria.FASTEST_RISING: lambda: self._rank_fastest_moving(
                direction="rising", f=f
            ),
            RankingCriteria.FASTEST_FALLING: lambda: self._rank_fastest_moving(
                direction="falling", f=f
            ),
            RankingCriteria.RECENTLY_ENTERED_HIGH_RISK: lambda: self._rank_recently_entered_high_risk(
                f=f, now=now
            ),
            RankingCriteria.RECENTLY_LEFT_HIGH_RISK: lambda: self._rank_recently_left_high_risk(
                f=f, now=now
            ),
        }

        fn = dispatch.get(criteria)
        if fn is None:
            logger.warning(f"Unknown ranking criteria: {criteria}")
            return []

        return fn()

    # ------------------------------------------------------------------
    # Convenience shortcuts
    # ------------------------------------------------------------------

    def top_fastest_rising(
        self,
        limit: int = 50,
        time_window_days: int = 7,
        min_score: Optional[float] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """Top fastest-rising CVEs within the time window."""
        now = reference_date or datetime.now(timezone.utc)
        raw = self._repo.get_top_rising_in_window(
            days=time_window_days, limit=limit, min_score=min_score, reference_date=now
        )
        return self._build_ranked_entries(raw, RankingCriteria.FASTEST_RISING, "delta")

    def top_fastest_falling(
        self,
        limit: int = 50,
        time_window_days: int = 7,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """Top fastest-falling CVEs within the time window."""
        now = reference_date or datetime.now(timezone.utc)
        raw = self._repo.get_top_falling_in_window(
            days=time_window_days, limit=limit, reference_date=now
        )
        # Convert to positive ranking value (magnitude of decrease)
        for r in raw:
            r["ranking_value"] = abs(r["delta"])
        raw.sort(key=lambda x: x["ranking_value"], reverse=True)
        return self._build_ranked_entries(raw, RankingCriteria.FASTEST_FALLING, "ranking_value")

    def top_highest_score(
        self,
        limit: int = 100,
        min_percentile: Optional[float] = None,
    ) -> List[EpssRankedEntry]:
        """Top CVEs ranked by current EPSS score."""
        f = EpssQueryFilter(min_percentile=min_percentile, limit=limit)
        return self._rank_by_current_score(f)

    def top_recently_entered_high_risk(
        self,
        limit: int = 50,
        lookback_days: int = 7,
        high_risk_threshold: float = 0.50,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """CVEs that newly crossed into high-risk territory."""
        now = reference_date or datetime.now(timezone.utc)
        raw = self._repo.get_new_high_risk_cves(
            lookback_days=lookback_days,
            high_risk_threshold=high_risk_threshold,
            reference_date=now,
        )
        raw = raw[:limit]
        for r in raw:
            r["ranking_value"] = r["current_score"]
            r["delta"] = (
                round(r["current_score"] - r["past_score"], 6)
                if r.get("past_score") is not None
                else None
            )
        return self._build_ranked_entries(raw, RankingCriteria.RECENTLY_ENTERED_HIGH_RISK, "ranking_value")

    # ------------------------------------------------------------------
    # Internal ranking implementations
    # ------------------------------------------------------------------

    def _rank_largest_increase(
        self,
        days: int,
        criteria: RankingCriteria,
        f: EpssQueryFilter,
        now: datetime,
    ) -> List[EpssRankedEntry]:
        raw = self._repo.get_top_rising_in_window(
            days=days,
            limit=f.limit,
            min_score=f.min_score,
            reference_date=now,
        )
        for r in raw:
            r["ranking_value"] = r["delta"]
        return self._build_ranked_entries(raw, criteria, "ranking_value")

    def _rank_by_current_score(self, f: EpssQueryFilter) -> List[EpssRankedEntry]:
        records = self._repo.list_current_scores(
            min_score=f.min_score,
            min_percentile=f.min_percentile,
            trend=f.trend_type,
            limit=f.limit,
        )
        rows = [
            {
                "cve_id": r.get("cve_id", ""),
                "current_score": float(r.get("epss_score", 0.0)),
                "current_percentile": float(r.get("epss_percentile", 0.0)),
                "trend": r.get("trend", "INSUFFICIENT_DATA"),
                "ranking_value": float(r.get("epss_score", 0.0)),
                "delta": None,
            }
            for r in records
        ]
        rows.sort(key=lambda x: x["ranking_value"], reverse=True)
        return self._build_ranked_entries(rows, RankingCriteria.HIGHEST_CURRENT_SCORE, "ranking_value")

    def _rank_by_percentile(self, f: EpssQueryFilter) -> List[EpssRankedEntry]:
        records = self._repo.list_current_scores(
            min_score=f.min_score,
            min_percentile=f.min_percentile,
            limit=f.limit,
        )
        rows = [
            {
                "cve_id": r.get("cve_id", ""),
                "current_score": float(r.get("epss_score", 0.0)),
                "current_percentile": float(r.get("epss_percentile", 0.0)),
                "trend": r.get("trend", "INSUFFICIENT_DATA"),
                "ranking_value": float(r.get("epss_percentile", 0.0)),
                "delta": None,
            }
            for r in records
        ]
        rows.sort(key=lambda x: x["ranking_value"], reverse=True)
        return self._build_ranked_entries(rows, RankingCriteria.HIGHEST_PERCENTILE, "ranking_value")

    def _rank_fastest_moving(
        self, direction: str, f: EpssQueryFilter
    ) -> List[EpssRankedEntry]:
        """Slope-based ranking using the stored trend field as a proxy."""
        trend_filter = (
            "RAPIDLY_INCREASING" if direction == "rising" else "RAPIDLY_DECREASING"
        )
        records = self._repo.list_current_scores(
            min_score=f.min_score,
            trend=trend_filter,
            limit=f.limit,
        )

        # Fallback: include INCREASING/DECREASING if RAPIDLY is empty
        if not records:
            fallback = "INCREASING" if direction == "rising" else "DECREASING"
            records = self._repo.list_current_scores(
                min_score=f.min_score,
                trend=fallback,
                limit=f.limit,
            )

        criteria = (
            RankingCriteria.FASTEST_RISING
            if direction == "rising"
            else RankingCriteria.FASTEST_FALLING
        )

        rows = [
            {
                "cve_id": r.get("cve_id", ""),
                "current_score": float(r.get("epss_score", 0.0)),
                "current_percentile": float(r.get("epss_percentile", 0.0)),
                "trend": r.get("trend", "INSUFFICIENT_DATA"),
                "ranking_value": float(r.get("epss_score", 0.0)),
                "delta": None,
            }
            for r in records
        ]
        rows.sort(key=lambda x: x["ranking_value"], reverse=True)
        return self._build_ranked_entries(rows, criteria, "ranking_value")

    def _rank_recently_entered_high_risk(
        self, f: EpssQueryFilter, now: datetime
    ) -> List[EpssRankedEntry]:
        lookback = int(
            self._window_days(f.time_window) or 7
        )
        raw = self._repo.get_new_high_risk_cves(
            lookback_days=lookback,
            reference_date=now,
        )
        raw = raw[: f.limit]
        for r in raw:
            r["ranking_value"] = r["current_score"]
        return self._build_ranked_entries(
            raw, RankingCriteria.RECENTLY_ENTERED_HIGH_RISK, "ranking_value"
        )

    def _rank_recently_left_high_risk(
        self, f: EpssQueryFilter, now: datetime
    ) -> List[EpssRankedEntry]:
        """
        CVEs that were high-risk N days ago but are no longer above threshold.
        """
        lookback = int(self._window_days(f.time_window) or 7)
        past_date = (now - timedelta(days=lookback)).strftime("%Y-%m-%d")

        # Query anything below threshold now
        records = self._repo.list_current_scores(limit=10_000)
        below_threshold = [
            r
            for r in records
            if float(r.get("epss_score", 0.0)) < self.HIGH_RISK_THRESHOLD
        ]

        results: List[Dict[str, Any]] = []
        for rec in below_threshold:
            cve_id = rec.get("cve_id", "")
            past = self._repo.get_score_at_date(cve_id, past_date)
            if past and past.score >= self.HIGH_RISK_THRESHOLD:
                results.append(
                    {
                        "cve_id": cve_id,
                        "current_score": float(rec.get("epss_score", 0.0)),
                        "current_percentile": float(rec.get("epss_percentile", 0.0)),
                        "trend": rec.get("trend", "INSUFFICIENT_DATA"),
                        "ranking_value": past.score,  # rank by how high it was
                        "delta": round(
                            float(rec.get("epss_score", 0.0)) - past.score, 6
                        ),
                    }
                )

        results.sort(key=lambda x: x["ranking_value"], reverse=True)
        results = results[: f.limit]
        return self._build_ranked_entries(
            results, RankingCriteria.RECENTLY_LEFT_HIGH_RISK, "ranking_value"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_ranked_entries(
        rows: List[Dict[str, Any]],
        criteria: RankingCriteria,
        value_key: str,
    ) -> List[EpssRankedEntry]:
        entries: List[EpssRankedEntry] = []
        for rank, row in enumerate(rows, start=1):
            trend_str = row.get("trend", "INSUFFICIENT_DATA")
            trend = _TREND_FROM_STR.get(trend_str, TrendClassification.INSUFFICIENT_DATA)
            entry = EpssRankedEntry(
                rank=rank,
                cve_id=row.get("cve_id", ""),
                current_score=float(row.get("current_score", row.get("epss_score", 0.0))),
                current_percentile=float(row.get("current_percentile", row.get("epss_percentile", 0.0))),
                trend=trend,
                ranking_criteria=criteria,
                ranking_value=float(row.get(value_key, 0.0) or 0.0),
                daily_delta=row.get("delta") if row.get("days", 1) == 1 else None,
                weekly_delta=row.get("delta") if row.get("days", 0) == 7 else None,
                monthly_delta=row.get("delta") if row.get("days", 0) == 30 else None,
                first_observed=row.get("first_observed"),
                canonical_uuid=row.get("canonical_uuid"),
            )
            entries.append(entry)
        return entries

    @staticmethod
    def _window_days(time_window: str) -> Optional[int]:
        _map = {"24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90}
        return _map.get(time_window)
