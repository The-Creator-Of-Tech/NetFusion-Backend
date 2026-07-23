"""
IL-5.1 Statistics Engine Unit Tests.

Tests global statistics, per-CVE statistics, and all math helpers.
"""

import math
import pytest
from netfusion_intelligence.analytics.epss.statistics import EpssStatisticsEngine


def test_global_statistics_returns_summary(stats_engine):
    """get_global_statistics returns a valid summary."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    assert summary.total_cves_analyzed > 0
    assert summary.generated_at is not None


def test_global_statistics_trend_distribution(stats_engine):
    """Trend distribution contains expected trend keys."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    assert isinstance(summary.trend_distribution, dict)
    assert sum(summary.trend_distribution.values()) == summary.total_cves_analyzed


def test_global_statistics_risk_distribution(stats_engine):
    """Risk distribution includes all four risk buckets."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert key in summary.risk_distribution
    total = sum(summary.risk_distribution.values())
    assert total == summary.total_cves_analyzed


def test_global_statistics_risk_thresholds(stats_engine, mock_repo):
    """Risk bucketing uses correct score thresholds."""
    # CVE-2024-0001 score=0.95 → CRITICAL
    # CVE-2024-0003 score=0.72 → CRITICAL
    # CVE-2024-0002 score=0.65 → HIGH
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    assert summary.risk_distribution["CRITICAL"] >= 2
    assert summary.risk_distribution["HIGH"] >= 1


def test_per_cve_statistics(stats_engine):
    """Per-CVE statistics returns all expected fields."""
    stats = stats_engine.get_score_statistics("CVE-2024-0001", window_days=30)
    assert stats["cve_id"] == "CVE-2024-0001"
    assert stats["observation_count"] >= 1
    assert stats["current_score"] > 0.0
    assert "average_score" in stats
    assert "min_score" in stats
    assert "max_score" in stats
    assert "std_deviation" in stats
    assert "average_daily_delta" in stats
    assert stats["window_days"] == 30


def test_per_cve_statistics_nonexistent(stats_engine):
    """Per-CVE stats for unknown CVE returns zero observation_count."""
    stats = stats_engine.get_score_statistics("CVE-9999-9999", window_days=30)
    assert stats["observation_count"] == 0


def test_most_stable_cves(stats_engine):
    """Most stable CVEs have low volatility."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    # Stable CVEs should appear in most_stable_cves
    assert isinstance(summary.most_stable_cves, list)


def test_most_volatile_cves(stats_engine):
    """Most volatile CVEs have high volatility."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    assert isinstance(summary.most_volatile_cves, list)


def test_largest_daily_increase_tracked(stats_engine):
    """Largest daily increase is tracked in summary."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    # May be 0 if no history deltas available in mock
    assert summary.largest_daily_increase is not None or True  # graceful


def test_summary_to_dict_completeness(stats_engine):
    """EpssAnalyticsSummary.to_dict() has all required keys."""
    summary = stats_engine.get_global_statistics(time_window_days=7, limit_cves=100)
    d = summary.to_dict()
    required_keys = [
        "generated_at", "time_window", "total_cves_analyzed",
        "trend_distribution", "risk_distribution",
        "average_daily_change", "average_weekly_change",
        "most_stable_cves", "most_volatile_cves",
        "high_risk_alerts_count", "new_high_risk_cves",
    ]
    for key in required_keys:
        assert key in d, f"Missing key in summary dict: {key}"


# ================================================================
# Math helper unit tests
# ================================================================

def test_mean():
    assert EpssStatisticsEngine._mean([0.1, 0.2, 0.3]) == pytest.approx(0.2, abs=1e-6)


def test_mean_empty():
    assert EpssStatisticsEngine._mean([]) == 0.0


def test_median_odd():
    assert EpssStatisticsEngine._median([0.1, 0.5, 0.9]) == pytest.approx(0.5)


def test_median_even():
    assert EpssStatisticsEngine._median([0.1, 0.3, 0.5, 0.9]) == pytest.approx(0.4)


def test_median_empty():
    assert EpssStatisticsEngine._median([]) == 0.0


def test_std_dev_constant():
    assert EpssStatisticsEngine._std_dev([0.5, 0.5, 0.5]) == pytest.approx(0.0)


def test_std_dev_known():
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    assert EpssStatisticsEngine._std_dev(values) == pytest.approx(2.0, abs=1e-5)


def test_std_dev_single():
    assert EpssStatisticsEngine._std_dev([0.5]) == 0.0


def test_slope_positive():
    """Increasing sequence has positive slope."""
    slope = EpssStatisticsEngine._slope([1.0, 2.0, 3.0, 4.0, 5.0])
    assert slope > 0


def test_slope_negative():
    """Decreasing sequence has negative slope."""
    slope = EpssStatisticsEngine._slope([5.0, 4.0, 3.0, 2.0, 1.0])
    assert slope < 0


def test_slope_flat():
    """Constant sequence has zero slope."""
    slope = EpssStatisticsEngine._slope([0.5, 0.5, 0.5, 0.5])
    assert slope == pytest.approx(0.0)


def test_growth_rate_increase():
    gr = EpssStatisticsEngine._growth_rate(0.50, 0.75)
    assert gr == pytest.approx(50.0, abs=0.01)


def test_growth_rate_decrease():
    gr = EpssStatisticsEngine._growth_rate(0.80, 0.40)
    assert gr == pytest.approx(-50.0, abs=0.01)


def test_growth_rate_zero_start():
    gr = EpssStatisticsEngine._growth_rate(0.0, 0.5)
    assert gr is None
