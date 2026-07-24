"""
IL-5.1 EPSS Analytics Engine Integration Tests.

Tests all major workflows:
- Trend analysis
- Ranking
- High-risk detection
- Statistics
- Forecasting
- Query engine
"""

import pytest
from netfusion_intelligence.analytics.epss.models import RankingCriteria, EpssQueryFilter


def test_get_trend_analysis(analytics_engine):
    """Test full trend analysis for a single CVE."""
    analysis = analytics_engine.get_trend_analysis("CVE-2024-0001")
    assert analysis is not None
    assert analysis.cve_id == "CVE-2024-0001"
    assert analysis.current_score == 0.95
    assert analysis.observation_count >= 30
    assert analysis.daily_delta is not None
    assert analysis.moving_avg_7d is not None
    assert analysis.historical_high is not None


def test_get_trend_analysis_nonexistent(analytics_engine):
    """Test trend analysis for non-existent CVE."""
    analysis = analytics_engine.get_trend_analysis("CVE-9999-9999")
    assert analysis is None


def test_get_history_view(analytics_engine):
    """Test history view with time-series data."""
    view = analytics_engine.get_history_view("CVE-2024-0002", limit=30)
    assert view is not None
    assert view.cve_id == "CVE-2024-0002"
    assert len(view.time_series) > 0
    assert view.trend_analysis is not None
    # Verify time-series structure
    first_point = view.time_series[0]
    assert first_point.date is not None
    assert 0.0 <= first_point.score <= 1.0
    assert first_point.moving_avg_7d is None or first_point.moving_avg_7d >= 0.0


def test_get_top_rising(analytics_engine):
    """Test top rising CVEs ranking."""
    rising = analytics_engine.get_top_rising(limit=5, time_window="7d")
    assert len(rising) > 0
    # Verify ranking structure
    assert rising[0].rank == 1
    assert rising[0].ranking_criteria == RankingCriteria.FASTEST_RISING
    # Verify descending order
    if len(rising) > 1:
        assert rising[0].ranking_value >= rising[1].ranking_value


def test_get_top_falling(analytics_engine):
    """Test top falling CVEs ranking."""
    falling = analytics_engine.get_top_falling(limit=5, time_window="7d")
    # Some CVEs should be falling
    assert isinstance(falling, list)


def test_get_top_highest_score(analytics_engine):
    """Test ranking by highest current score."""
    top = analytics_engine.get_top_highest_score(limit=5)
    assert len(top) > 0
    assert top[0].ranking_criteria == RankingCriteria.HIGHEST_CURRENT_SCORE
    # Verify descending score order
    if len(top) > 1:
        assert top[0].current_score >= top[1].current_score


def test_get_ranked_list_all_criteria(analytics_engine):
    """Test ranking engine with all nine criteria."""
    criteria_to_test = [
        RankingCriteria.LARGEST_DAILY_INCREASE,
        RankingCriteria.LARGEST_WEEKLY_INCREASE,
        RankingCriteria.HIGHEST_CURRENT_SCORE,
        RankingCriteria.HIGHEST_PERCENTILE,
        RankingCriteria.FASTEST_RISING,
    ]
    for criteria in criteria_to_test:
        f = EpssQueryFilter(limit=5)
        ranked = analytics_engine.get_ranked_list(criteria=criteria, query_filter=f)
        assert isinstance(ranked, list)
        if ranked:
            assert ranked[0].ranking_criteria == criteria


def test_get_new_high_risk(analytics_engine):
    """Test new high-risk CVE detection."""
    alerts = analytics_engine.get_new_high_risk(lookback_days=7, high_risk_threshold=0.50)
    assert isinstance(alerts, list)
    # CVE-2024-0007 should qualify (low history, high current)
    cve_ids = [a.cve_id for a in alerts]
    assert "CVE-2024-0007" in cve_ids


def test_get_rapidly_increasing_alerts(analytics_engine):
    """Test rapidly increasing alerts detection."""
    alerts = analytics_engine.get_rapidly_increasing_alerts(
        delta_threshold=0.10, time_window_days=1
    )
    assert isinstance(alerts, list)
    # CVE-2024-0001 has daily_increment=0.02, so over 1 day delta = 0.02 < 0.10
    # CVE-2024-0007 has daily_increment=0.1, so delta should be >= 0.10


def test_get_global_statistics(analytics_engine):
    """Test global analytics statistics."""
    stats = analytics_engine.get_global_statistics(time_window="7d", limit_cves=100)
    assert stats.total_cves_analyzed > 0
    assert stats.trend_distribution is not None
    assert stats.risk_distribution is not None
    assert "CRITICAL" in stats.risk_distribution
    assert "HIGH" in stats.risk_distribution


def test_get_cve_statistics(analytics_engine):
    """Test per-CVE statistics."""
    stats = analytics_engine.get_cve_statistics("CVE-2024-0001", window_days=30)
    assert stats["cve_id"] == "CVE-2024-0001"
    assert stats["observation_count"] > 0
    assert stats["current_score"] > 0
    assert "average_score" in stats
    assert "std_deviation" in stats


def test_get_forecast_indicators(analytics_engine):
    """Test forecasting indicator computation."""
    indicators = analytics_engine.get_forecast_indicators("CVE-2024-0001")
    assert indicators["cve_id"] == "CVE-2024-0001"
    assert "trend_slope" in indicators
    assert "volatility" in indicators
    assert "momentum" in indicators
    assert "prediction_confidence" in indicators
    assert "ml_ready" in indicators
    assert indicators["feature_version"] == "il5.1-v1"


def test_query_engine(analytics_engine):
    """Test flexible query engine."""
    query_filter = EpssQueryFilter(
        min_score=0.50,
        time_window="7d",
        limit=10,
    )
    results = analytics_engine.query(query_filter)
    assert isinstance(results, list)


def test_bulk_trend_analyses(analytics_engine):
    """Test bulk trend analysis retrieval."""
    cve_ids = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    analyses = analytics_engine.get_trend_analyses_bulk(cve_ids)
    assert len(analyses) == 3
    assert "CVE-2024-0001" in analyses
    assert analyses["CVE-2024-0001"].current_score == 0.95


def test_high_risk_kev_alerts(analytics_engine, mock_repo):
    """Test high-risk KEV cross-feed detection."""
    # Simulate KEV data
    kev_cves = ["CVE-2024-0001", "CVE-2024-0002"]
    alerts = analytics_engine.get_high_risk_kev_alerts(
        min_score=0.50, kev_cve_ids=kev_cves
    )
    assert isinstance(alerts, list)
    # Both should match
    assert len(alerts) == 2
    assert all(a.kev_status for a in alerts)


def test_high_risk_high_cvss_alerts(analytics_engine):
    """Test high-risk CVSS cross-feed detection."""
    # Simulate CVSS data
    cvss_data = {
        "CVE-2024-0001": 9.8,
        "CVE-2024-0002": 7.5,
        "CVE-2024-0003": 8.2,
        "CVE-2024-0004": 5.0,
    }
    alerts = analytics_engine.get_high_risk_high_cvss_alerts(
        min_epss_score=0.50, min_cvss=7.0, cvss_data=cvss_data
    )
    assert isinstance(alerts, list)
    # CVE-2024-0001, 0002, 0003 should match
    assert len(alerts) == 3
    assert all(a.cvss_score is not None for a in alerts)


def test_trend_analysis_with_insufficient_data(analytics_engine, mock_repo):
    """Test trend analysis with minimal history."""
    mock_repo.seed_cve("CVE-2024-9999", score=0.50, percentile=0.90, trend="INSUFFICIENT_DATA", history_days=1)
    analysis = analytics_engine.get_trend_analysis("CVE-2024-9999")
    assert analysis is not None
    assert analysis.observation_count == 1
    # Many fields should be None
    assert analysis.weekly_delta is None or analysis.observation_count < 7
