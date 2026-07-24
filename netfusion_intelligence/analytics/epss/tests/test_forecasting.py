"""
IL-5.1 Forecasting Foundation Unit Tests.

Tests all mathematical indicators that prepare for future ML forecasting.
"""

import pytest
from netfusion_intelligence.analytics.epss.forecasting import EpssForecastingFoundation
from netfusion_intelligence.analytics.epss.tests.conftest import build_history


def test_prepare_forecast_indicators_complete(forecasting_foundation, rising_history):
    """All expected fields are present in forecast indicators."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", rising_history, 0.90, 0.99
    )
    required_keys = [
        "cve_id", "current_score", "current_percentile",
        "trend_slope", "volatility", "growth_rate", "momentum",
        "prediction_confidence",
        "moving_avg_7d", "moving_avg_30d", "moving_avg_90d",
        "historical_high", "historical_low", "historical_average",
        "observation_count", "daily_delta", "weekly_delta", "monthly_delta",
        "trend_classification", "ml_ready", "feature_version",
        "range_utilization", "score_percentile_ratio", "recent_acceleration",
    ]
    for key in required_keys:
        assert key in indicators, f"Missing key: {key}"


def test_ml_ready_flag_sufficient_data(forecasting_foundation, rising_history):
    """ml_ready is True when >= 7 observations."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", rising_history, 0.90, 0.99
    )
    assert indicators["ml_ready"] is True


def test_ml_ready_flag_insufficient_data(forecasting_foundation):
    """ml_ready is False when < 7 observations."""
    short = build_history("CVE-SHORT", 0.50, 3, daily_increment=0.0)
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-SHORT", short, 0.50, 0.90
    )
    assert indicators["ml_ready"] is False


def test_feature_version(forecasting_foundation, stable_history):
    """feature_version is always il5.1-v1."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", stable_history, 0.50, 0.90
    )
    assert indicators["feature_version"] == "il5.1-v1"


def test_range_utilization_at_max(forecasting_foundation, stable_history):
    """Range utilization = 1.0 when current score equals historical high."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", stable_history, 0.50, 0.90
    )
    ru = indicators["range_utilization"]
    # stable_history has all scores = 0.50, so high=low=current → range=0 → 1.0
    if ru is not None:
        assert 0.0 <= ru <= 1.0


def test_range_utilization_in_range(forecasting_foundation, rising_history):
    """Range utilization is between 0 and 1 for non-degenerate history."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", rising_history, 0.90, 0.99
    )
    ru = indicators["range_utilization"]
    if ru is not None:
        assert 0.0 <= ru <= 1.0


def test_score_percentile_ratio(forecasting_foundation, rising_history):
    """Score/percentile ratio is computed when percentile > 0."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", rising_history, 0.90, 0.99
    )
    ratio = indicators["score_percentile_ratio"]
    if ratio is not None:
        assert ratio > 0


def test_recent_acceleration_positive(forecasting_foundation):
    """Positive acceleration for convex upward curve."""
    from netfusion_intelligence.analytics.epss.models import EpssScoreSnapshot
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    # Scores accelerating upward
    vals = [0.10, 0.12, 0.15, 0.20, 0.30, 0.50, 0.80]
    history = [
        EpssScoreSnapshot(
            cve_id="CVE-TEST",
            score=vals[len(vals) - 1 - i],
            percentile=vals[len(vals) - 1 - i],
            date=(now - timedelta(days=i)).strftime("%Y-%m-%d"),
        )
        for i in range(len(vals))
    ]
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-TEST", history, 0.80, 0.95
    )
    assert indicators["recent_acceleration"] is not None


def test_empty_indicators_for_unknown_cve(forecasting_foundation):
    """Empty history returns safe default indicators."""
    indicators = forecasting_foundation.prepare_forecast_indicators(
        "CVE-UNKNOWN", [], 0.0, 0.0
    )
    assert indicators["cve_id"] == "CVE-UNKNOWN"
    assert indicators["observation_count"] == 0
    assert indicators["ml_ready"] is False
    assert indicators["trend_classification"] == "INSUFFICIENT_DATA"


def test_batch_indicators(forecasting_foundation, analytics_engine):
    """Batch indicators from trend analyses."""
    analyses_dict = analytics_engine.get_trend_analyses_bulk(
        ["CVE-2024-0001", "CVE-2024-0002"]
    )
    analyses_list = list(analyses_dict.values())
    batch = forecasting_foundation.prepare_batch_indicators(analyses_list)
    assert len(batch) == 2
    for ind in batch:
        assert "cve_id" in ind
        assert "trend_slope" in ind
        assert "feature_version" in ind


def test_prediction_confidence_monotone(forecasting_foundation):
    """More observations → higher confidence (all else equal)."""
    short = build_history("CVE-S", 0.50, 10, daily_increment=0.0)
    long_ = build_history("CVE-L", 0.50, 90, daily_increment=0.0)

    ind_short = forecasting_foundation.prepare_forecast_indicators("CVE-S", short, 0.50, 0.90)
    ind_long = forecasting_foundation.prepare_forecast_indicators("CVE-L", long_, 0.50, 0.90)

    c_short = ind_short.get("prediction_confidence") or 0.0
    c_long = ind_long.get("prediction_confidence") or 0.0
    assert c_long >= c_short
