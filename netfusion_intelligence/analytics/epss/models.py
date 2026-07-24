"""
IL-5.1 EPSS Analytics Domain Models.

Pure data contracts for trend analysis, ranking, forecasting,
statistics, and high-risk detection.  No I/O, no SQLAlchemy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TrendClassification(str, Enum):
    """Extended trend classification beyond the pipeline's EpssTrend."""

    RAPIDLY_INCREASING = "RAPIDLY_INCREASING"
    INCREASING = "INCREASING"
    STABLE = "STABLE"
    DECREASING = "DECREASING"
    RAPIDLY_DECREASING = "RAPIDLY_DECREASING"
    NEW_HIGH = "NEW_HIGH"
    NEW_LOW = "NEW_LOW"
    CONSISTENTLY_HIGH = "CONSISTENTLY_HIGH"
    CONSISTENTLY_LOW = "CONSISTENTLY_LOW"
    RECOVERY_TREND = "RECOVERY_TREND"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class TimeWindow(str, Enum):
    """Supported analytic time windows."""

    H24 = "24h"
    D7 = "7d"
    D14 = "14d"
    D30 = "30d"
    D90 = "90d"
    CUSTOM = "custom"

    @property
    def days(self) -> Optional[int]:
        _map = {
            "24h": 1,
            "7d": 7,
            "14d": 14,
            "30d": 30,
            "90d": 90,
            "custom": None,
        }
        return _map[self.value]


class RankingCriteria(str, Enum):
    """Supported ranking dimensions."""

    LARGEST_DAILY_INCREASE = "largest_daily_increase"
    LARGEST_WEEKLY_INCREASE = "largest_weekly_increase"
    LARGEST_MONTHLY_INCREASE = "largest_monthly_increase"
    HIGHEST_CURRENT_SCORE = "highest_current_score"
    HIGHEST_PERCENTILE = "highest_percentile"
    FASTEST_RISING = "fastest_rising"
    FASTEST_FALLING = "fastest_falling"
    RECENTLY_ENTERED_HIGH_RISK = "recently_entered_high_risk"
    RECENTLY_LEFT_HIGH_RISK = "recently_left_high_risk"


class HighRiskCategory(str, Enum):
    """Categories of high-risk vulnerability detection."""

    NEW_HIGH_RISK = "NEW_HIGH_RISK"
    RAPIDLY_INCREASING = "RAPIDLY_INCREASING"
    HIGH_SCORE_KEV = "HIGH_SCORE_KEV"
    HIGH_SCORE_HIGH_CVSS = "HIGH_SCORE_HIGH_CVSS"
    HIGH_SCORE_INTERNET_FACING = "HIGH_SCORE_INTERNET_FACING"  # foundation only


# ---------------------------------------------------------------------------
# Core Analytics Models
# ---------------------------------------------------------------------------


@dataclass
class EpssScoreSnapshot:
    """
    Represents a single historical EPSS data point (sourced from epss_history table).
    """

    cve_id: str
    score: float
    percentile: float
    date: str  # YYYY-MM-DD
    daily_delta_score: float = 0.0
    daily_delta_percentile: float = 0.0
    dataset_version_id: str = ""
    model_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "score": self.score,
            "percentile": self.percentile,
            "date": self.date,
            "daily_delta_score": self.daily_delta_score,
            "daily_delta_percentile": self.daily_delta_percentile,
            "dataset_version_id": self.dataset_version_id,
            "model_version": self.model_version,
        }


@dataclass
class EpssTrendAnalysis:
    """
    Complete trend analysis result for a single CVE.

    Scores at multiple time windows, deltas, moving averages,
    extremes, and automatic trend classification.
    """

    cve_id: str

    # Current state
    current_score: float = 0.0
    current_percentile: float = 0.0

    # Historical reference points
    yesterday_score: Optional[float] = None
    score_7d: Optional[float] = None
    score_30d: Optional[float] = None
    score_90d: Optional[float] = None

    # Deltas
    daily_delta: Optional[float] = None
    weekly_delta: Optional[float] = None
    monthly_delta: Optional[float] = None

    # Extremes
    historical_high: Optional[float] = None
    historical_low: Optional[float] = None
    historical_average: Optional[float] = None

    # Moving averages
    moving_avg_7d: Optional[float] = None
    moving_avg_30d: Optional[float] = None
    moving_avg_90d: Optional[float] = None

    # Classification
    trend: TrendClassification = TrendClassification.INSUFFICIENT_DATA

    # Forecasting foundation (no ML – pure mathematical indicators)
    trend_slope: Optional[float] = None          # Linear regression slope
    volatility: Optional[float] = None           # Std-deviation of recent scores
    growth_rate: Optional[float] = None          # % growth over trend window
    momentum: Optional[float] = None             # Weighted recent delta
    prediction_confidence: Optional[float] = None  # 0.0–1.0 placeholder

    # Metadata
    observation_count: int = 0
    first_observed: Optional[str] = None
    last_updated: Optional[str] = None
    model_version: str = ""
    canonical_uuid: Optional[str] = None         # CIIL integration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "current_score": self.current_score,
            "current_percentile": self.current_percentile,
            "yesterday_score": self.yesterday_score,
            "score_7d": self.score_7d,
            "score_30d": self.score_30d,
            "score_90d": self.score_90d,
            "daily_delta": self.daily_delta,
            "weekly_delta": self.weekly_delta,
            "monthly_delta": self.monthly_delta,
            "historical_high": self.historical_high,
            "historical_low": self.historical_low,
            "historical_average": self.historical_average,
            "moving_avg_7d": self.moving_avg_7d,
            "moving_avg_30d": self.moving_avg_30d,
            "moving_avg_90d": self.moving_avg_90d,
            "trend": self.trend.value,
            "trend_slope": self.trend_slope,
            "volatility": self.volatility,
            "growth_rate": self.growth_rate,
            "momentum": self.momentum,
            "prediction_confidence": self.prediction_confidence,
            "observation_count": self.observation_count,
            "first_observed": self.first_observed,
            "last_updated": self.last_updated,
            "model_version": self.model_version,
            "canonical_uuid": self.canonical_uuid,
        }


@dataclass
class EpssRankedEntry:
    """
    A ranked EPSS entry with position, trend, and the delta that caused the ranking.
    """

    rank: int
    cve_id: str
    current_score: float
    current_percentile: float
    trend: TrendClassification
    ranking_criteria: RankingCriteria
    ranking_value: float           # The value used for ranking (delta, score, etc.)
    daily_delta: Optional[float] = None
    weekly_delta: Optional[float] = None
    monthly_delta: Optional[float] = None
    first_observed: Optional[str] = None
    canonical_uuid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rank": self.rank,
            "cve_id": self.cve_id,
            "current_score": self.current_score,
            "current_percentile": self.current_percentile,
            "trend": self.trend.value,
            "ranking_criteria": self.ranking_criteria.value,
            "ranking_value": self.ranking_value,
            "daily_delta": self.daily_delta,
            "weekly_delta": self.weekly_delta,
            "monthly_delta": self.monthly_delta,
            "first_observed": self.first_observed,
            "canonical_uuid": self.canonical_uuid,
        }


@dataclass
class EpssHighRiskAlert:
    """
    High-risk vulnerability detection result.
    """

    cve_id: str
    category: HighRiskCategory
    current_score: float
    current_percentile: float
    trend: TrendClassification
    risk_reason: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    daily_delta: Optional[float] = None
    kev_status: bool = False
    cvss_score: Optional[float] = None
    internet_facing: Optional[bool] = None   # Future: from asset inventory
    canonical_uuid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "category": self.category.value,
            "current_score": self.current_score,
            "current_percentile": self.current_percentile,
            "trend": self.trend.value,
            "risk_reason": self.risk_reason,
            "detected_at": self.detected_at,
            "daily_delta": self.daily_delta,
            "kev_status": self.kev_status,
            "cvss_score": self.cvss_score,
            "internet_facing": self.internet_facing,
            "canonical_uuid": self.canonical_uuid,
        }


@dataclass
class EpssAnalyticsSummary:
    """
    Global EPSS analytics summary for a given time window.
    """

    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    time_window: str = "7d"
    total_cves_analyzed: int = 0
    cves_with_history: int = 0

    # Trend distribution
    trend_distribution: Dict[str, int] = field(default_factory=dict)
    risk_distribution: Dict[str, int] = field(default_factory=dict)

    # Change statistics
    average_daily_change: float = 0.0
    average_weekly_change: float = 0.0
    largest_daily_increase: Optional[float] = None
    largest_daily_increase_cve: Optional[str] = None
    largest_weekly_increase: Optional[float] = None
    largest_weekly_increase_cve: Optional[str] = None
    largest_monthly_increase: Optional[float] = None
    largest_monthly_increase_cve: Optional[str] = None

    # Notable CVEs
    most_stable_cves: List[str] = field(default_factory=list)
    most_volatile_cves: List[str] = field(default_factory=list)
    high_risk_alerts_count: int = 0
    new_high_risk_cves: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "time_window": self.time_window,
            "total_cves_analyzed": self.total_cves_analyzed,
            "cves_with_history": self.cves_with_history,
            "trend_distribution": self.trend_distribution,
            "risk_distribution": self.risk_distribution,
            "average_daily_change": self.average_daily_change,
            "average_weekly_change": self.average_weekly_change,
            "largest_daily_increase": self.largest_daily_increase,
            "largest_daily_increase_cve": self.largest_daily_increase_cve,
            "largest_weekly_increase": self.largest_weekly_increase,
            "largest_weekly_increase_cve": self.largest_weekly_increase_cve,
            "largest_monthly_increase": self.largest_monthly_increase,
            "largest_monthly_increase_cve": self.largest_monthly_increase_cve,
            "most_stable_cves": self.most_stable_cves,
            "most_volatile_cves": self.most_volatile_cves,
            "high_risk_alerts_count": self.high_risk_alerts_count,
            "new_high_risk_cves": self.new_high_risk_cves,
        }


@dataclass
class EpssQueryFilter:
    """
    Query filter parameters for analytics endpoints.
    """

    min_score: Optional[float] = None
    min_percentile: Optional[float] = None
    trend_type: Optional[str] = None      # TrendClassification value
    time_window: str = "7d"               # TimeWindow value
    start_date: Optional[str] = None      # YYYY-MM-DD for custom window
    end_date: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    kev_status: Optional[bool] = None
    cvss_threshold: Optional[float] = None
    limit: int = 100
    offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_score": self.min_score,
            "min_percentile": self.min_percentile,
            "trend_type": self.trend_type,
            "time_window": self.time_window,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "vendor": self.vendor,
            "product": self.product,
            "kev_status": self.kev_status,
            "cvss_threshold": self.cvss_threshold,
            "limit": self.limit,
            "offset": self.offset,
        }


@dataclass
class EpssTimeSeriesPoint:
    """A single time-series data point for visualization."""

    date: str
    score: float
    percentile: float
    daily_delta: float = 0.0
    moving_avg_7d: Optional[float] = None
    moving_avg_30d: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.date,
            "score": self.score,
            "percentile": self.percentile,
            "daily_delta": self.daily_delta,
            "moving_avg_7d": self.moving_avg_7d,
            "moving_avg_30d": self.moving_avg_30d,
        }


@dataclass
class EpssHistoryView:
    """
    Full history view for a single CVE — used for visualization foundation.
    """

    cve_id: str
    current_score: float
    current_percentile: float
    trend: TrendClassification
    time_series: List[EpssTimeSeriesPoint] = field(default_factory=list)
    trend_analysis: Optional[EpssTrendAnalysis] = None
    canonical_uuid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "current_score": self.current_score,
            "current_percentile": self.current_percentile,
            "trend": self.trend.value,
            "time_series": [p.to_dict() for p in self.time_series],
            "trend_analysis": self.trend_analysis.to_dict() if self.trend_analysis else None,
            "canonical_uuid": self.canonical_uuid,
        }


@dataclass
class TrendThresholds:
    """
    Configurable thresholds for trend classification.
    Defaults match the IL-5 scoring engine conventions.
    """

    # Score delta thresholds (per observation period)
    rapidly_increasing_threshold: float = 0.10
    increasing_threshold: float = 0.01
    decreasing_threshold: float = -0.01
    rapidly_decreasing_threshold: float = -0.10

    # Score thresholds for category classifications
    high_risk_score: float = 0.50        # >= this → HIGH RISK
    critical_risk_score: float = 0.70    # >= this → CRITICAL
    consistently_high_min_avg: float = 0.50   # avg >= this → CONSISTENTLY_HIGH
    consistently_low_max_avg: float = 0.05    # avg <= this → CONSISTENTLY_LOW
    new_high_lookback_days: int = 7      # Entered high risk in last N days
    recovery_delta_threshold: float = 0.05   # Prior large drop + recent recovery

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rapidly_increasing_threshold": self.rapidly_increasing_threshold,
            "increasing_threshold": self.increasing_threshold,
            "decreasing_threshold": self.decreasing_threshold,
            "rapidly_decreasing_threshold": self.rapidly_decreasing_threshold,
            "high_risk_score": self.high_risk_score,
            "critical_risk_score": self.critical_risk_score,
            "consistently_high_min_avg": self.consistently_high_min_avg,
            "consistently_low_max_avg": self.consistently_low_max_avg,
            "new_high_lookback_days": self.new_high_lookback_days,
            "recovery_delta_threshold": self.recovery_delta_threshold,
        }
