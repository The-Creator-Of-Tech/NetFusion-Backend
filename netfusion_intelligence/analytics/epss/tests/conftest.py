"""
IL-5.1 Test fixtures and helpers.
All tests use in-memory mocks — no real DB required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from netfusion_intelligence.analytics.epss.engine import EpssAnalyticsEngine
from netfusion_intelligence.analytics.epss.models import (
    EpssScoreSnapshot,
    TrendThresholds,
)
from netfusion_intelligence.analytics.epss.repository import EpssAnalyticsRepository
from netfusion_intelligence.analytics.epss.statistics import EpssStatisticsEngine
from netfusion_intelligence.analytics.epss.trend_analyzer import EpssTrendAnalyzer
from netfusion_intelligence.analytics.epss.ranking import EpssRankingEngine
from netfusion_intelligence.analytics.epss.forecasting import EpssForecastingFoundation


# ---------------------------------------------------------------------------
# Helper: build a synthetic history list
# ---------------------------------------------------------------------------

def build_history(
    cve_id: str,
    base_score: float,
    days: int,
    daily_increment: float = 0.005,
    start_offset_days: int = 0,
) -> List[EpssScoreSnapshot]:
    """
    Builds a synthetic score history ascending/descending over `days`.
    Returns list newest-first (as the real repository returns).
    """
    ref_date = datetime.now(timezone.utc) - timedelta(days=start_offset_days)
    snapshots: List[EpssScoreSnapshot] = []
    for i in range(days):
        date = ref_date - timedelta(days=i)
        score = max(0.0, min(1.0, base_score - i * daily_increment))
        snapshots.append(
            EpssScoreSnapshot(
                cve_id=cve_id,
                score=round(score, 6),
                percentile=round(min(score * 1.1, 1.0), 6),
                date=date.strftime("%Y-%m-%d"),
                daily_delta_score=round(daily_increment, 6),
                daily_delta_percentile=round(daily_increment * 1.1, 6),
                dataset_version_id=f"v-{i}",
                model_version="v2023.03.01",
            )
        )
    return snapshots  # newest first


# ---------------------------------------------------------------------------
# Mock repository
# ---------------------------------------------------------------------------

class MockIntelligenceRepository:
    """
    In-memory mock of IntelligenceRepositoryInterface for analytics tests.
    Pre-populated with a configurable set of CVEs and histories.
    """

    def __init__(self) -> None:
        # cve_id → current score record
        self._scores: Dict[str, Dict[str, Any]] = {}
        # cve_id → list of history dicts (newest first)
        self._history: Dict[str, List[Dict[str, Any]]] = {}

    def seed_cve(
        self,
        cve_id: str,
        score: float,
        percentile: float,
        trend: str = "STABLE",
        history_days: int = 30,
        daily_increment: float = 0.005,
    ) -> None:
        cve_id = cve_id.upper()
        self._scores[cve_id] = {
            "cve_id": cve_id,
            "epss_score": score,
            "epss_percentile": percentile,
            "trend": trend,
            "publication_date": "2024-01-15",
            "model_version": "v2023.03.01",
            "dataset_version_id": "v-active",
        }

        snaps = build_history(
            cve_id, score, history_days, daily_increment=daily_increment
        )
        self._history[cve_id] = [
            {
                "cve_id": s.cve_id,
                "epss_score": s.score,
                "epss_percentile": s.percentile,
                "date": s.date,
                "score_date": s.date,
                "daily_delta_score": s.daily_delta_score,
                "daily_delta_percentile": s.daily_delta_percentile,
                "dataset_version_id": s.dataset_version_id,
                "model_version": s.model_version,
            }
            for s in snaps
        ]

    # --- IntelligenceRepositoryInterface stubs (analytics-relevant subset) ---

    def get_epss_score(self, cve_id: str, version_id: Optional[str] = None):
        return self._scores.get(cve_id.upper())

    def get_epss_history(self, cve_id: str, limit: int = 100):
        records = self._history.get(cve_id.upper(), [])
        return records[:limit]

    def list_epss_scores(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        results = list(self._scores.values())
        if min_score is not None:
            results = [r for r in results if r["epss_score"] >= min_score]
        if max_score is not None:
            results = [r for r in results if r["epss_score"] <= max_score]
        if min_percentile is not None:
            results = [r for r in results if r["epss_percentile"] >= min_percentile]
        if trend:
            results = [r for r in results if r.get("trend") == trend]
        results.sort(key=lambda r: r["epss_score"], reverse=True)
        return results[offset : offset + limit]

    def get_active_dataset_version(self, feed_id: str):
        from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
        if feed_id == "first_epss_1.0":
            v = DatasetVersion(feed_id=feed_id, version_id="v-active")
            v.status = DatasetStatus.ACTIVE
            return v
        return None

    # Stubs for other interface methods (not used in analytics)
    def save_feed_record(self, *a, **kw): pass
    def get_feed_record(self, *a, **kw): return None
    def list_feed_records(self, *a, **kw): return []
    def save_dataset_version(self, v, **kw): return v
    def get_dataset_version(self, *a, **kw): return None
    def list_dataset_versions(self, *a, **kw): return []
    def set_active_dataset_version(self, *a, **kw): return True
    def save_import_result(self, r, **kw): return r
    def list_import_results(self, *a, **kw): return []
    def save_feed_health(self, h, **kw): return h
    def get_feed_health(self, *a, **kw): return None
    def list_feed_healths(self, *a, **kw): return []
    def save_import_logs(self, *a, **kw): pass
    def get_statistics(self, *a, **kw):
        from netfusion_intelligence.models.statistics import IntelligenceStatistics
        return IntelligenceStatistics()
    def save_audit_event(self, e, **kw): return e
    def list_audit_events(self, *a, **kw): return []


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_repo():
    """Seeded in-memory repository with diverse CVE data."""
    repo = MockIntelligenceRepository()
    # Rapidly increasing
    repo.seed_cve("CVE-2024-0001", score=0.95, percentile=0.998, trend="RAPIDLY_INCREASING", daily_increment=0.02)
    # Increasing
    repo.seed_cve("CVE-2024-0002", score=0.65, percentile=0.950, trend="INCREASING", daily_increment=0.01)
    # Stable high
    repo.seed_cve("CVE-2024-0003", score=0.72, percentile=0.970, trend="CONSISTENTLY_HIGH", daily_increment=0.0)
    # Decreasing
    repo.seed_cve("CVE-2024-0004", score=0.30, percentile=0.800, trend="DECREASING", daily_increment=-0.008)
    # Rapidly decreasing
    repo.seed_cve("CVE-2024-0005", score=0.05, percentile=0.200, trend="RAPIDLY_DECREASING", daily_increment=-0.02)
    # Low stable
    repo.seed_cve("CVE-2024-0006", score=0.01, percentile=0.050, trend="STABLE", daily_increment=0.0)
    # Newly high risk (low history but current > 0.5)
    repo.seed_cve("CVE-2024-0007", score=0.55, percentile=0.920, trend="INCREASING", history_days=5, daily_increment=0.1)
    return repo


@pytest.fixture
def analytics_repo(mock_repo):
    return EpssAnalyticsRepository(mock_repo)


@pytest.fixture
def trend_analyzer():
    return EpssTrendAnalyzer()


@pytest.fixture
def ranking_engine(analytics_repo):
    return EpssRankingEngine(analytics_repo)


@pytest.fixture
def stats_engine(analytics_repo):
    return EpssStatisticsEngine(analytics_repo)


@pytest.fixture
def forecasting_foundation():
    return EpssForecastingFoundation()


@pytest.fixture
def analytics_engine(mock_repo):
    return EpssAnalyticsEngine(mock_repo)


@pytest.fixture
def stable_history():
    return build_history("CVE-TEST-0001", 0.50, 30, daily_increment=0.0)


@pytest.fixture
def rising_history():
    return build_history("CVE-TEST-0002", 0.90, 30, daily_increment=0.01)


@pytest.fixture
def falling_history():
    return build_history("CVE-TEST-0003", 0.20, 30, daily_increment=-0.01)
