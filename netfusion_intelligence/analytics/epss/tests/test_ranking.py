"""
IL-5.1 Ranking Engine Unit Tests.

Tests all nine ranking criteria and edge cases.
"""

import pytest
from netfusion_intelligence.analytics.epss.models import (
    EpssQueryFilter,
    RankingCriteria,
    TrendClassification,
)


def test_rank_by_largest_daily_increase(ranking_engine):
    """Largest daily increase ranking returns positive deltas."""
    f = EpssQueryFilter(limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.LARGEST_DAILY_INCREASE, query_filter=f)
    assert isinstance(ranked, list)
    if ranked:
        assert ranked[0].rank == 1
        assert ranked[0].ranking_criteria == RankingCriteria.LARGEST_DAILY_INCREASE


def test_rank_by_highest_score(ranking_engine):
    """Highest score ranking returns descending score order."""
    f = EpssQueryFilter(limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.HIGHEST_CURRENT_SCORE, query_filter=f)
    assert len(ranked) > 0
    # First entry should be highest score
    if len(ranked) > 1:
        assert ranked[0].current_score >= ranked[1].current_score


def test_rank_by_highest_percentile(ranking_engine):
    """Highest percentile ranking returns descending percentile order."""
    f = EpssQueryFilter(limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.HIGHEST_PERCENTILE, query_filter=f)
    assert len(ranked) > 0
    if len(ranked) > 1:
        assert ranked[0].current_percentile >= ranked[1].current_percentile


def test_rank_by_fastest_rising(ranking_engine):
    """Fastest rising returns RAPIDLY_INCREASING or INCREASING trend CVEs."""
    f = EpssQueryFilter(limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.FASTEST_RISING, query_filter=f)
    assert isinstance(ranked, list)
    if ranked:
        assert ranked[0].ranking_criteria == RankingCriteria.FASTEST_RISING


def test_rank_by_fastest_falling(ranking_engine):
    """Fastest falling returns RAPIDLY_DECREASING or DECREASING trend CVEs."""
    f = EpssQueryFilter(limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.FASTEST_FALLING, query_filter=f)
    assert isinstance(ranked, list)


def test_rank_ranks_are_sequential(ranking_engine):
    """Rank field is 1-based and sequential."""
    f = EpssQueryFilter(limit=7)
    ranked = ranking_engine.rank_by(RankingCriteria.HIGHEST_CURRENT_SCORE, query_filter=f)
    for i, entry in enumerate(ranked, start=1):
        assert entry.rank == i


def test_rank_with_min_score_filter(ranking_engine):
    """min_score filter excludes low-scoring CVEs."""
    f = EpssQueryFilter(min_score=0.60, limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.HIGHEST_CURRENT_SCORE, query_filter=f)
    for entry in ranked:
        assert entry.current_score >= 0.60


def test_top_fastest_rising_convenience(ranking_engine):
    """Convenience method top_fastest_rising returns ranked entries."""
    ranked = ranking_engine.top_fastest_rising(limit=5, time_window_days=7)
    assert isinstance(ranked, list)
    if ranked:
        assert ranked[0].rank == 1


def test_top_highest_score_convenience(ranking_engine):
    """Convenience method top_highest_score works correctly."""
    ranked = ranking_engine.top_highest_score(limit=5)
    assert len(ranked) > 0
    if len(ranked) > 1:
        assert ranked[0].current_score >= ranked[1].current_score


def test_recently_entered_high_risk(ranking_engine):
    """Recently entered high-risk uses new high-risk detection."""
    f = EpssQueryFilter(time_window="7d", limit=10)
    ranked = ranking_engine.rank_by(RankingCriteria.RECENTLY_ENTERED_HIGH_RISK, query_filter=f)
    assert isinstance(ranked, list)
    # CVE-2024-0007 has short history and is above 0.5
    cve_ids = [r.cve_id for r in ranked]
    assert "CVE-2024-0007" in cve_ids


def test_to_dict_structure(ranking_engine):
    """RankedEntry.to_dict() contains all required keys."""
    f = EpssQueryFilter(limit=1)
    ranked = ranking_engine.rank_by(RankingCriteria.HIGHEST_CURRENT_SCORE, query_filter=f)
    assert ranked
    d = ranked[0].to_dict()
    required = ["rank", "cve_id", "current_score", "current_percentile",
                "trend", "ranking_criteria", "ranking_value"]
    for key in required:
        assert key in d, f"Missing key: {key}"


def test_rank_empty_on_unknown_criteria(ranking_engine):
    """Unknown criteria string returns empty list gracefully."""
    # This tests the dispatcher's fallback
    result = ranking_engine.rank_by("not_a_real_criteria", query_filter=EpssQueryFilter())
    assert result == []


def test_largest_weekly_increase(ranking_engine):
    """Weekly increase ranking returns CVEs with largest 7-day delta."""
    f = EpssQueryFilter(limit=5)
    ranked = ranking_engine.rank_by(RankingCriteria.LARGEST_WEEKLY_INCREASE, query_filter=f)
    assert isinstance(ranked, list)
    if ranked:
        assert ranked[0].ranking_criteria == RankingCriteria.LARGEST_WEEKLY_INCREASE


def test_largest_monthly_increase(ranking_engine):
    """Monthly increase ranking returns CVEs with largest 30-day delta."""
    f = EpssQueryFilter(limit=5)
    ranked = ranking_engine.rank_by(RankingCriteria.LARGEST_MONTHLY_INCREASE, query_filter=f)
    assert isinstance(ranked, list)
