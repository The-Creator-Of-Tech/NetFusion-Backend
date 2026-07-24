"""
IL-5.1 Analytics Repository Unit Tests.

Tests all read methods and data conversion logic.
"""

import pytest
from datetime import datetime, timedelta, timezone
from netfusion_intelligence.analytics.epss.models import EpssScoreSnapshot


def test_get_current_score(analytics_repo):
    """get_current_score returns record for known CVE."""
    rec = analytics_repo.get_current_score("CVE-2024-0001")
    assert rec is not None
    assert rec["cve_id"] == "CVE-2024-0001"
    assert rec["epss_score"] == 0.95


def test_get_current_score_none(analytics_repo):
    """get_current_score returns None for unknown CVE."""
    rec = analytics_repo.get_current_score("CVE-9999-9999")
    assert rec is None


def test_get_history_returns_snapshots(analytics_repo):
    """get_history returns typed EpssScoreSnapshot objects."""
    history = analytics_repo.get_history("CVE-2024-0001", limit=30)
    assert len(history) == 30
    assert all(isinstance(s, EpssScoreSnapshot) for s in history)


def test_get_history_newest_first(analytics_repo):
    """History is ordered newest-first."""
    history = analytics_repo.get_history("CVE-2024-0001", limit=30)
    dates = [s.date for s in history]
    assert dates == sorted(dates, reverse=True)


def test_get_history_limit_respected(analytics_repo):
    """Limit parameter is respected."""
    history = analytics_repo.get_history("CVE-2024-0001", limit=5)
    assert len(history) <= 5


def test_get_history_in_window(analytics_repo):
    """get_history_in_window filters to the time window."""
    history = analytics_repo.get_history_in_window("CVE-2024-0001", days=7)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    for snap in history:
        assert snap.date >= cutoff


def test_get_score_at_date(analytics_repo):
    """get_score_at_date returns closest past snapshot."""
    # Request a date slightly in the past
    target = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    snap = analytics_repo.get_score_at_date("CVE-2024-0001", target)
    if snap:
        assert snap.date <= target


def test_get_score_at_date_future_returns_none(analytics_repo):
    """get_score_at_date returns None when no prior data exists."""
    far_past = "2000-01-01"
    snap = analytics_repo.get_score_at_date("CVE-2024-0001", far_past)
    assert snap is None


def test_list_current_scores(analytics_repo):
    """list_current_scores returns all seeded CVEs."""
    scores = analytics_repo.list_current_scores(limit=100)
    assert len(scores) == 7  # 7 CVEs seeded in conftest


def test_list_current_scores_min_score_filter(analytics_repo):
    """min_score filter excludes low-scoring CVEs."""
    scores = analytics_repo.list_current_scores(min_score=0.50)
    for s in scores:
        assert s["epss_score"] >= 0.50


def test_list_current_scores_trend_filter(analytics_repo):
    """Trend filter returns only matching CVEs."""
    scores = analytics_repo.list_current_scores(trend="RAPIDLY_INCREASING")
    assert all(s["trend"] == "RAPIDLY_INCREASING" for s in scores)


def test_get_top_rising_in_window(analytics_repo):
    """get_top_rising_in_window returns positive deltas."""
    results = analytics_repo.get_top_rising_in_window(days=7, limit=10)
    for r in results:
        assert r["delta"] > 0


def test_get_top_falling_in_window(analytics_repo):
    """get_top_falling_in_window returns negative deltas."""
    results = analytics_repo.get_top_falling_in_window(days=7, limit=10)
    for r in results:
        assert r["delta"] < 0


def test_get_new_high_risk_cves(analytics_repo):
    """get_new_high_risk_cves returns CVEs above threshold not previously high-risk."""
    results = analytics_repo.get_new_high_risk_cves(lookback_days=7, high_risk_threshold=0.50)
    for r in results:
        assert r["current_score"] >= 0.50


def test_get_scores_above_delta_threshold(analytics_repo):
    """Delta threshold filter works correctly."""
    results = analytics_repo.get_scores_above_delta_threshold(
        delta_threshold=0.05, days=30, limit=20
    )
    for r in results:
        assert r["delta"] >= 0.05


def test_snapshot_field_types(analytics_repo):
    """EpssScoreSnapshot fields have correct types."""
    history = analytics_repo.get_history("CVE-2024-0001", limit=1)
    assert history
    s = history[0]
    assert isinstance(s.cve_id, str)
    assert isinstance(s.score, float)
    assert isinstance(s.percentile, float)
    assert isinstance(s.date, str)
    assert isinstance(s.daily_delta_score, float)


def test_get_bulk_current_scores(analytics_repo):
    """Bulk lookup returns dict keyed by CVE ID."""
    cve_ids = ["CVE-2024-0001", "CVE-2024-0002", "CVE-9999-9999"]
    result = analytics_repo.get_current_scores_bulk(cve_ids)
    assert "CVE-2024-0001" in result
    assert "CVE-2024-0002" in result
    assert "CVE-9999-9999" not in result
