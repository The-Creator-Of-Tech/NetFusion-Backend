"""
IL-5.1 Model Unit Tests.

Tests domain models: enums, data classes, to_dict(), serialization.
"""

import pytest
from netfusion_intelligence.analytics.epss.models import (
    EpssAnalyticsSummary,
    EpssHistoryView,
    EpssHighRiskAlert,
    EpssQueryFilter,
    EpssRankedEntry,
    EpssScoreSnapshot,
    EpssTimeSeriesPoint,
    EpssTrendAnalysis,
    HighRiskCategory,
    RankingCriteria,
    TimeWindow,
    TrendClassification,
    TrendThresholds,
)


# ================================================================
# TimeWindow enum
# ================================================================

def test_time_window_days():
    assert TimeWindow.H24.days == 1
    assert TimeWindow.D7.days == 7
    assert TimeWindow.D14.days == 14
    assert TimeWindow.D30.days == 30
    assert TimeWindow.D90.days == 90
    assert TimeWindow.CUSTOM.days is None


# ================================================================
# TrendClassification enum
# ================================================================

def test_trend_classification_values():
    expected = {
        "RAPIDLY_INCREASING", "INCREASING", "STABLE", "DECREASING",
        "RAPIDLY_DECREASING", "NEW_HIGH", "NEW_LOW", "CONSISTENTLY_HIGH",
        "CONSISTENTLY_LOW", "RECOVERY_TREND", "INSUFFICIENT_DATA",
    }
    actual = {t.value for t in TrendClassification}
    assert expected == actual


# ================================================================
# RankingCriteria enum
# ================================================================

def test_ranking_criteria_values():
    expected = {
        "largest_daily_increase", "largest_weekly_increase", "largest_monthly_increase",
        "highest_current_score", "highest_percentile", "fastest_rising", "fastest_falling",
        "recently_entered_high_risk", "recently_left_high_risk",
    }
    actual = {c.value for c in RankingCriteria}
    assert expected == actual


# ================================================================
# EpssScoreSnapshot
# ================================================================

def test_score_snapshot_to_dict():
    snap = EpssScoreSnapshot(
        cve_id="CVE-2024-0001",
        score=0.75,
        percentile=0.95,
        date="2024-06-01",
        daily_delta_score=0.05,
    )
    d = snap.to_dict()
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["score"] == 0.75
    assert d["date"] == "2024-06-01"
    assert d["daily_delta_score"] == 0.05


# ================================================================
# EpssTrendAnalysis
# ================================================================

def test_trend_analysis_to_dict_complete():
    analysis = EpssTrendAnalysis(cve_id="CVE-2024-TEST", current_score=0.60)
    d = analysis.to_dict()
    keys = [
        "cve_id", "current_score", "current_percentile",
        "yesterday_score", "score_7d", "score_30d", "score_90d",
        "daily_delta", "weekly_delta", "monthly_delta",
        "historical_high", "historical_low", "historical_average",
        "moving_avg_7d", "moving_avg_30d", "moving_avg_90d",
        "trend", "trend_slope", "volatility", "growth_rate",
        "momentum", "prediction_confidence",
        "observation_count", "first_observed", "last_updated",
        "model_version", "canonical_uuid",
    ]
    for k in keys:
        assert k in d


def test_trend_analysis_trend_serialized():
    analysis = EpssTrendAnalysis(
        cve_id="CVE-TEST",
        current_score=0.5,
        trend=TrendClassification.RAPIDLY_INCREASING,
    )
    d = analysis.to_dict()
    assert d["trend"] == "RAPIDLY_INCREASING"


# ================================================================
# EpssRankedEntry
# ================================================================

def test_ranked_entry_to_dict():
    entry = EpssRankedEntry(
        rank=1,
        cve_id="CVE-2024-0001",
        current_score=0.95,
        current_percentile=0.999,
        trend=TrendClassification.RAPIDLY_INCREASING,
        ranking_criteria=RankingCriteria.FASTEST_RISING,
        ranking_value=0.12,
    )
    d = entry.to_dict()
    assert d["rank"] == 1
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["trend"] == "RAPIDLY_INCREASING"
    assert d["ranking_criteria"] == "fastest_rising"


# ================================================================
# EpssHighRiskAlert
# ================================================================

def test_high_risk_alert_to_dict():
    alert = EpssHighRiskAlert(
        cve_id="CVE-2024-0001",
        category=HighRiskCategory.NEW_HIGH_RISK,
        current_score=0.85,
        current_percentile=0.99,
        trend=TrendClassification.RAPIDLY_INCREASING,
        risk_reason="Crossed threshold",
        kev_status=True,
        cvss_score=9.8,
    )
    d = alert.to_dict()
    assert d["category"] == "NEW_HIGH_RISK"
    assert d["kev_status"] is True
    assert d["cvss_score"] == 9.8
    assert "detected_at" in d


# ================================================================
# EpssAnalyticsSummary
# ================================================================

def test_analytics_summary_to_dict():
    summary = EpssAnalyticsSummary(
        time_window="7d",
        total_cves_analyzed=1000,
        trend_distribution={"INCREASING": 50, "STABLE": 900, "DECREASING": 50},
        risk_distribution={"CRITICAL": 10, "HIGH": 90, "MEDIUM": 400, "LOW": 500},
    )
    d = summary.to_dict()
    assert d["total_cves_analyzed"] == 1000
    assert d["trend_distribution"]["INCREASING"] == 50
    assert "generated_at" in d


# ================================================================
# EpssTimeSeriesPoint
# ================================================================

def test_time_series_point_to_dict():
    pt = EpssTimeSeriesPoint(
        date="2024-06-01",
        score=0.75,
        percentile=0.95,
        daily_delta=0.05,
        moving_avg_7d=0.72,
        moving_avg_30d=0.68,
    )
    d = pt.to_dict()
    assert d["date"] == "2024-06-01"
    assert d["moving_avg_7d"] == 0.72
    assert d["daily_delta"] == 0.05


# ================================================================
# EpssQueryFilter
# ================================================================

def test_query_filter_defaults():
    f = EpssQueryFilter()
    assert f.time_window == "7d"
    assert f.limit == 100
    assert f.offset == 0
    assert f.min_score is None


def test_query_filter_to_dict():
    f = EpssQueryFilter(min_score=0.5, time_window="30d", limit=50)
    d = f.to_dict()
    assert d["min_score"] == 0.5
    assert d["time_window"] == "30d"
    assert d["limit"] == 50


# ================================================================
# TrendThresholds
# ================================================================

def test_trend_thresholds_defaults():
    t = TrendThresholds()
    assert t.rapidly_increasing_threshold == 0.10
    assert t.high_risk_score == 0.50
    assert t.critical_risk_score == 0.70


def test_trend_thresholds_custom():
    t = TrendThresholds(rapidly_increasing_threshold=0.05, high_risk_score=0.70)
    d = t.to_dict()
    assert d["rapidly_increasing_threshold"] == 0.05
    assert d["high_risk_score"] == 0.70


# ================================================================
# EpssHistoryView
# ================================================================

def test_history_view_to_dict():
    view = EpssHistoryView(
        cve_id="CVE-2024-0001",
        current_score=0.95,
        current_percentile=0.999,
        trend=TrendClassification.RAPIDLY_INCREASING,
        time_series=[],
        trend_analysis=None,
    )
    d = view.to_dict()
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["trend"] == "RAPIDLY_INCREASING"
    assert d["time_series"] == []
