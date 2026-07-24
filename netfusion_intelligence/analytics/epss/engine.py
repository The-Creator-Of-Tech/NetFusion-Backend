"""
IL-5.1 EPSS Analytics Engine.

Central orchestrator for the Time-Aware EPSS Analytics Engine.
Coordinates: repository, trend analyzer, ranking engine,
forecasting foundation, statistics engine, and high-risk detector.

DOES NOT modify any IL-5 ingestion pipeline components.
Operates entirely on historical data already stored.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.analytics.epss.forecasting import EpssForecastingFoundation
from netfusion_intelligence.analytics.epss.models import (
    EpssAnalyticsSummary,
    EpssHistoryView,
    EpssHighRiskAlert,
    EpssQueryFilter,
    EpssRankedEntry,
    EpssTimeSeriesPoint,
    EpssTrendAnalysis,
    HighRiskCategory,
    RankingCriteria,
    TimeWindow,
    TrendClassification,
    TrendThresholds,
)
from netfusion_intelligence.analytics.epss.ranking import EpssRankingEngine
from netfusion_intelligence.analytics.epss.repository import EpssAnalyticsRepository
from netfusion_intelligence.analytics.epss.statistics import EpssStatisticsEngine
from netfusion_intelligence.analytics.epss.trend_analyzer import EpssTrendAnalyzer
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface

logger = logging.getLogger(__name__)

_TREND_FROM_STR = {t.value: t for t in TrendClassification}


class EpssAnalyticsEngine:
    """
    IL-5.1 Time-Aware EPSS Analytics Engine.

    Public API surface for all analytics workflows:
    - get_trend_analysis(cve_id)
    - get_history_view(cve_id)
    - get_top_rising(window, limit)
    - get_top_falling(window, limit)
    - get_new_high_risk(window)
    - get_ranked_list(criteria)
    - get_global_statistics(window)
    - get_forecast_indicators(cve_id)
    - query(filter)
    """

    HIGH_RISK_THRESHOLD = 0.50
    CRITICAL_THRESHOLD = 0.70
    HIGH_CVSS_THRESHOLD = 7.0

    def __init__(
        self,
        repository: IntelligenceRepositoryInterface,
        thresholds: Optional[TrendThresholds] = None,
    ) -> None:
        self._raw_repo = repository
        self._thresholds = thresholds or TrendThresholds()

        # Sub-engines
        self._analytics_repo = EpssAnalyticsRepository(repository)
        self._trend_analyzer = EpssTrendAnalyzer(self._thresholds)
        self._ranking_engine = EpssRankingEngine(self._analytics_repo)
        self._stats_engine = EpssStatisticsEngine(self._analytics_repo)
        self._forecasting = EpssForecastingFoundation(self._trend_analyzer)

    # ================================================================
    # Trend Analysis
    # ================================================================

    def get_trend_analysis(
        self,
        cve_id: str,
        version_id: Optional[str] = None,
    ) -> Optional[EpssTrendAnalysis]:
        """
        Full trend analysis for a single CVE.
        Returns None if the CVE has no EPSS data.
        """
        current_rec = self._analytics_repo.get_current_score(cve_id, version_id)
        if not current_rec:
            return None

        history = self._analytics_repo.get_history(cve_id, limit=365)
        current_score = float(current_rec.get("epss_score", 0.0))
        current_percentile = float(current_rec.get("epss_percentile", 0.0))

        analysis = self._trend_analyzer.analyze(
            cve_id=cve_id.upper(),
            history=history,
            current_score=current_score,
            current_percentile=current_percentile,
        )

        # Resolve CIIL canonical UUID
        analysis.canonical_uuid = self._analytics_repo.resolve_canonical_uuid(cve_id)
        return analysis

    def get_trend_analyses_bulk(
        self,
        cve_ids: List[str],
        version_id: Optional[str] = None,
    ) -> Dict[str, EpssTrendAnalysis]:
        """
        Trend analyses for multiple CVEs.  Returns dict: cve_id → analysis.
        """
        results: Dict[str, EpssTrendAnalysis] = {}
        for cve_id in cve_ids:
            analysis = self.get_trend_analysis(cve_id, version_id)
            if analysis:
                results[cve_id.upper()] = analysis
        return results

    # ================================================================
    # History View (Visualization Foundation)
    # ================================================================

    def get_history_view(
        self,
        cve_id: str,
        limit: int = 365,
    ) -> Optional[EpssHistoryView]:
        """
        Constructs a full history view including time-series data suitable
        for dashboard visualization.
        """
        current_rec = self._analytics_repo.get_current_score(cve_id)
        if not current_rec:
            return None

        history = self._analytics_repo.get_history(cve_id, limit=limit)
        current_score = float(current_rec.get("epss_score", 0.0))
        current_percentile = float(current_rec.get("epss_percentile", 0.0))

        # Build trend analysis
        analysis = self._trend_analyzer.analyze(
            cve_id=cve_id.upper(),
            history=history,
            current_score=current_score,
            current_percentile=current_percentile,
        )

        # Build time-series points
        history_asc = sorted(history, key=lambda s: s.date)
        time_series: List[EpssTimeSeriesPoint] = []
        scores_window = []

        for snap in history_asc:
            scores_window.append(snap.score)
            ma7 = (
                round(sum(scores_window[-7:]) / min(len(scores_window), 7), 6)
                if len(scores_window) >= 1
                else None
            )
            ma30 = (
                round(sum(scores_window[-30:]) / min(len(scores_window), 30), 6)
                if len(scores_window) >= 1
                else None
            )
            time_series.append(
                EpssTimeSeriesPoint(
                    date=snap.date,
                    score=snap.score,
                    percentile=snap.percentile,
                    daily_delta=snap.daily_delta_score,
                    moving_avg_7d=ma7,
                    moving_avg_30d=ma30,
                )
            )

        trend = _TREND_FROM_STR.get(
            current_rec.get("trend", "INSUFFICIENT_DATA"),
            TrendClassification.INSUFFICIENT_DATA,
        )

        return EpssHistoryView(
            cve_id=cve_id.upper(),
            current_score=current_score,
            current_percentile=current_percentile,
            trend=trend,
            time_series=time_series,
            trend_analysis=analysis,
            canonical_uuid=self._analytics_repo.resolve_canonical_uuid(cve_id),
        )

    # ================================================================
    # Ranking
    # ================================================================

    def get_top_rising(
        self,
        limit: int = 50,
        time_window: str = "7d",
        min_score: Optional[float] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """Top fastest-rising CVEs in the given time window."""
        days = self._window_days(time_window)
        return self._ranking_engine.top_fastest_rising(
            limit=limit,
            time_window_days=days,
            min_score=min_score,
            reference_date=reference_date,
        )

    def get_top_falling(
        self,
        limit: int = 50,
        time_window: str = "7d",
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """Top fastest-falling CVEs in the given time window."""
        days = self._window_days(time_window)
        return self._ranking_engine.top_fastest_falling(
            limit=limit,
            time_window_days=days,
            reference_date=reference_date,
        )

    def get_top_highest_score(
        self,
        limit: int = 100,
        min_percentile: Optional[float] = None,
    ) -> List[EpssRankedEntry]:
        """Top CVEs by current score."""
        return self._ranking_engine.top_highest_score(limit=limit, min_percentile=min_percentile)

    def get_ranked_list(
        self,
        criteria: RankingCriteria,
        query_filter: Optional[EpssQueryFilter] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssRankedEntry]:
        """General ranking by any of the nine supported criteria."""
        return self._ranking_engine.rank_by(
            criteria=criteria, query_filter=query_filter, reference_date=reference_date
        )

    # ================================================================
    # High-Risk Detection
    # ================================================================

    def get_new_high_risk(
        self,
        lookback_days: int = 7,
        high_risk_threshold: Optional[float] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssHighRiskAlert]:
        """
        Detects CVEs that newly entered high-risk territory.
        """
        threshold = high_risk_threshold or self.HIGH_RISK_THRESHOLD
        now = reference_date or datetime.now(timezone.utc)

        raw = self._analytics_repo.get_new_high_risk_cves(
            lookback_days=lookback_days,
            high_risk_threshold=threshold,
            reference_date=now,
        )

        alerts: List[EpssHighRiskAlert] = []
        for r in raw:
            trend_str = r.get("trend", "INSUFFICIENT_DATA")
            trend = _TREND_FROM_STR.get(trend_str, TrendClassification.INSUFFICIENT_DATA)
            alert = EpssHighRiskAlert(
                cve_id=r["cve_id"],
                category=HighRiskCategory.NEW_HIGH_RISK,
                current_score=r["current_score"],
                current_percentile=r.get("current_percentile", 0.0),
                trend=trend,
                risk_reason=(
                    f"CVE crossed high-risk threshold ({threshold}) "
                    f"within last {lookback_days} days"
                ),
                daily_delta=(
                    round(r["current_score"] - r["past_score"], 6)
                    if r.get("past_score") is not None
                    else None
                ),
                canonical_uuid=self._analytics_repo.resolve_canonical_uuid(r["cve_id"]),
            )
            alerts.append(alert)
        return alerts

    def get_rapidly_increasing_alerts(
        self,
        delta_threshold: float = 0.10,
        time_window_days: int = 1,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssHighRiskAlert]:
        """
        Detects CVEs with rapidly increasing exploit probability.
        """
        now = reference_date or datetime.now(timezone.utc)
        rising = self._analytics_repo.get_scores_above_delta_threshold(
            delta_threshold=delta_threshold,
            days=time_window_days,
            limit=200,
            reference_date=now,
        )

        alerts: List[EpssHighRiskAlert] = []
        for r in rising:
            trend_str = r.get("trend", "RAPIDLY_INCREASING")
            trend = _TREND_FROM_STR.get(trend_str, TrendClassification.RAPIDLY_INCREASING)
            alert = EpssHighRiskAlert(
                cve_id=r["cve_id"],
                category=HighRiskCategory.RAPIDLY_INCREASING,
                current_score=r["current_score"],
                current_percentile=r.get("current_percentile", 0.0),
                trend=trend,
                risk_reason=(
                    f"EPSS score increased by {r['delta']:.4f} over "
                    f"{time_window_days} day(s)"
                ),
                daily_delta=r.get("delta"),
                canonical_uuid=self._analytics_repo.resolve_canonical_uuid(r["cve_id"]),
            )
            alerts.append(alert)
        return alerts

    def get_high_risk_kev_alerts(
        self,
        min_score: float = 0.50,
        kev_cve_ids: Optional[List[str]] = None,
    ) -> List[EpssHighRiskAlert]:
        """
        Detects CVEs that are both high-EPSS and in the KEV catalog.
        Requires caller to provide kev_cve_ids list (fetched from IL-4 layer).
        Foundation for future cross-feed correlation.
        """
        if not kev_cve_ids:
            return []

        kev_set = {c.upper() for c in kev_cve_ids}
        high_epss = self._analytics_repo.list_current_scores(min_score=min_score, limit=50_000)

        alerts: List[EpssHighRiskAlert] = []
        for r in high_epss:
            cve_id = r.get("cve_id", "").upper()
            if cve_id not in kev_set:
                continue
            trend_str = r.get("trend", "INSUFFICIENT_DATA")
            trend = _TREND_FROM_STR.get(trend_str, TrendClassification.INSUFFICIENT_DATA)
            alert = EpssHighRiskAlert(
                cve_id=cve_id,
                category=HighRiskCategory.HIGH_SCORE_KEV,
                current_score=float(r.get("epss_score", 0.0)),
                current_percentile=float(r.get("epss_percentile", 0.0)),
                trend=trend,
                risk_reason=(
                    f"CVE has high EPSS score ({r.get('epss_score', 0):.4f}) "
                    f"AND is in CISA KEV catalog"
                ),
                kev_status=True,
                canonical_uuid=self._analytics_repo.resolve_canonical_uuid(cve_id),
            )
            alerts.append(alert)
        return alerts

    def get_high_risk_high_cvss_alerts(
        self,
        min_epss_score: float = 0.50,
        min_cvss: float = 7.0,
        cvss_data: Optional[Dict[str, float]] = None,
    ) -> List[EpssHighRiskAlert]:
        """
        Detects CVEs with high EPSS AND high CVSS.
        Requires caller to provide cvss_data dict: cve_id → cvss_score (from IL-3).
        Foundation for future cross-feed scoring.
        """
        if not cvss_data:
            return []

        high_epss = self._analytics_repo.list_current_scores(
            min_score=min_epss_score, limit=50_000
        )

        alerts: List[EpssHighRiskAlert] = []
        for r in high_epss:
            cve_id = r.get("cve_id", "").upper()
            cvss = cvss_data.get(cve_id)
            if cvss is None or cvss < min_cvss:
                continue
            trend_str = r.get("trend", "INSUFFICIENT_DATA")
            trend = _TREND_FROM_STR.get(trend_str, TrendClassification.INSUFFICIENT_DATA)
            alert = EpssHighRiskAlert(
                cve_id=cve_id,
                category=HighRiskCategory.HIGH_SCORE_HIGH_CVSS,
                current_score=float(r.get("epss_score", 0.0)),
                current_percentile=float(r.get("epss_percentile", 0.0)),
                trend=trend,
                risk_reason=(
                    f"CVE has high EPSS ({r.get('epss_score', 0):.4f}) "
                    f"AND high CVSS ({cvss:.1f})"
                ),
                cvss_score=cvss,
                canonical_uuid=self._analytics_repo.resolve_canonical_uuid(cve_id),
            )
            alerts.append(alert)
        return alerts

    # ================================================================
    # Query Engine
    # ================================================================

    def query(
        self,
        query_filter: EpssQueryFilter,
        reference_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Flexible query engine supporting the standard EPSS analytics queries.

        Interprets the time_window and optional delta filter.
        Returns dicts for lightweight API serialization.
        """
        now = reference_date or datetime.now(timezone.utc)
        days = self._window_days(query_filter.time_window)

        results = self._analytics_repo.get_top_rising_in_window(
            days=days,
            limit=query_filter.limit,
            min_score=query_filter.min_score,
            reference_date=now,
        )
        return results

    # ================================================================
    # Statistics
    # ================================================================

    def get_global_statistics(
        self,
        time_window: str = "7d",
        limit_cves: int = 5_000,
    ) -> EpssAnalyticsSummary:
        """Global EPSS analytics statistics summary."""
        days = self._window_days(time_window)
        return self._stats_engine.get_global_statistics(
            time_window_days=days,
            limit_cves=limit_cves,
        )

    def get_cve_statistics(
        self,
        cve_id: str,
        window_days: int = 30,
    ) -> Dict[str, Any]:
        """Per-CVE statistics over a time window."""
        return self._stats_engine.get_score_statistics(cve_id=cve_id, window_days=window_days)

    # ================================================================
    # Forecasting
    # ================================================================

    def get_forecast_indicators(
        self,
        cve_id: str,
        version_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Returns forecasting mathematical indicators for a CVE.
        Foundation for future ML integration.
        """
        current_rec = self._analytics_repo.get_current_score(cve_id, version_id)
        if not current_rec:
            return self._forecasting._empty_indicators(cve_id)

        history = self._analytics_repo.get_history(cve_id, limit=365)
        return self._forecasting.prepare_forecast_indicators(
            cve_id=cve_id.upper(),
            history=history,
            current_score=float(current_rec.get("epss_score", 0.0)),
            current_percentile=float(current_rec.get("epss_percentile", 0.0)),
        )

    # ================================================================
    # Helper
    # ================================================================

    @staticmethod
    def _window_days(time_window: str) -> int:
        _map = {"24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90}
        return _map.get(time_window, 7)
