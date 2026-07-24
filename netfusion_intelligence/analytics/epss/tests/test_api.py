"""
IL-5.1 Analytics REST API Unit Tests.

Tests all API endpoints using FastAPI TestClient with mocked engine.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netfusion_intelligence.analytics.epss.api import router, set_analytics_engine
from netfusion_intelligence.analytics.epss.engine import EpssAnalyticsEngine


@pytest.fixture
def app(mock_repo):
    """FastAPI app with analytics router wired to mock engine."""
    engine = EpssAnalyticsEngine(mock_repo)
    set_analytics_engine(engine)

    _app = FastAPI()
    _app.include_router(router)
    return _app


@pytest.fixture
def client(app):
    return TestClient(app)


# ================================================================
# /intelligence/epss/analytics
# ================================================================

def test_get_analytics(client):
    resp = client.get("/intelligence/epss/analytics?time_window=7d")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "analytics" in data
    assert data["analytics"]["total_cves_analyzed"] > 0


def test_get_analytics_trend_distribution(client):
    resp = client.get("/intelligence/epss/analytics?time_window=7d")
    assert resp.status_code == 200
    analytics = resp.json()["analytics"]
    assert "trend_distribution" in analytics
    assert "risk_distribution" in analytics


def test_get_analytics_risk_buckets(client):
    resp = client.get("/intelligence/epss/analytics")
    assert resp.status_code == 200
    risk_dist = resp.json()["analytics"]["risk_distribution"]
    for bucket in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert bucket in risk_dist


# ================================================================
# /intelligence/epss/trends
# ================================================================

def test_get_trends_with_cve_ids(client):
    resp = client.get("/intelligence/epss/trends?cve_ids=CVE-2024-0001,CVE-2024-0002")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "trends" in data
    assert "CVE-2024-0001" in data["trends"]


def test_get_trends_without_cve_ids(client):
    resp = client.get("/intelligence/epss/trends?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"


def test_get_trends_unknown_cve(client):
    resp = client.get("/intelligence/epss/trends?cve_ids=CVE-9999-0000")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0


# ================================================================
# /intelligence/epss/history/{cve_id}
# ================================================================

def test_get_history_known_cve(client):
    resp = client.get("/intelligence/epss/history/CVE-2024-0001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    h = data["history"]
    assert h["cve_id"] == "CVE-2024-0001"
    assert len(h["time_series"]) > 0


def test_get_history_time_series_structure(client):
    resp = client.get("/intelligence/epss/history/CVE-2024-0001?limit=10")
    assert resp.status_code == 200
    ts = resp.json()["history"]["time_series"]
    assert len(ts) <= 10
    for point in ts:
        assert "date" in point
        assert "score" in point
        assert "percentile" in point
        assert "daily_delta" in point


def test_get_history_includes_trend_analysis(client):
    resp = client.get("/intelligence/epss/history/CVE-2024-0001")
    assert resp.status_code == 200
    h = resp.json()["history"]
    assert "trend_analysis" in h
    ta = h["trend_analysis"]
    assert "moving_avg_7d" in ta
    assert "historical_high" in ta


def test_get_history_unknown_cve(client):
    resp = client.get("/intelligence/epss/history/CVE-9999-9999")
    assert resp.status_code == 404


# ================================================================
# /intelligence/epss/top-rising
# ================================================================

def test_get_top_rising(client):
    resp = client.get("/intelligence/epss/top-rising?limit=5&time_window=7d")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["time_window"] == "7d"
    assert "cves" in data


def test_get_top_rising_structure(client):
    resp = client.get("/intelligence/epss/top-rising?limit=3")
    assert resp.status_code == 200
    cves = resp.json()["cves"]
    for cve in cves:
        assert "rank" in cve
        assert "cve_id" in cve
        assert "current_score" in cve
        assert "ranking_value" in cve


def test_get_top_rising_with_min_score(client):
    resp = client.get("/intelligence/epss/top-rising?min_score=0.50&limit=10")
    assert resp.status_code == 200
    cves = resp.json()["cves"]
    for cve in cves:
        assert cve["current_score"] >= 0.50


def test_get_top_rising_different_windows(client):
    for window in ["24h", "7d", "14d", "30d", "90d"]:
        resp = client.get(f"/intelligence/epss/top-rising?time_window={window}")
        assert resp.status_code == 200, f"Failed for window={window}"


# ================================================================
# /intelligence/epss/top-falling
# ================================================================

def test_get_top_falling(client):
    resp = client.get("/intelligence/epss/top-falling?limit=5&time_window=7d")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "cves" in data


# ================================================================
# /intelligence/epss/new-high-risk
# ================================================================

def test_get_new_high_risk(client):
    resp = client.get("/intelligence/epss/new-high-risk?lookback_days=7&high_risk_threshold=0.50")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["lookback_days"] == 7
    assert data["threshold"] == 0.50
    alerts = data["alerts"]
    # CVE-2024-0007 should appear
    cve_ids = [a["cve_id"] for a in alerts]
    assert "CVE-2024-0007" in cve_ids


def test_get_new_high_risk_alert_structure(client):
    resp = client.get("/intelligence/epss/new-high-risk")
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    for alert in alerts:
        assert "cve_id" in alert
        assert "category" in alert
        assert "current_score" in alert
        assert "risk_reason" in alert
        assert "detected_at" in alert


# ================================================================
# /intelligence/epss/forecast
# ================================================================

def test_get_forecast_indicators(client):
    resp = client.get("/intelligence/epss/forecast?cve_id=CVE-2024-0001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    ind = data["indicators"]
    assert ind["cve_id"] == "CVE-2024-0001"
    assert "trend_slope" in ind
    assert "volatility" in ind
    assert "momentum" in ind
    assert "prediction_confidence" in ind
    assert "ml_ready" in ind
    assert ind["feature_version"] == "il5.1-v1"


def test_get_forecast_indicators_unknown_cve(client):
    resp = client.get("/intelligence/epss/forecast?cve_id=CVE-9999-9999")
    assert resp.status_code == 404


# ================================================================
# /intelligence/epss/statistics
# ================================================================

def test_get_statistics(client):
    resp = client.get("/intelligence/epss/statistics?time_window=7d")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    stats = data["statistics"]
    assert "total_cves_analyzed" in stats
    assert "trend_distribution" in stats
    assert "risk_distribution" in stats


# ================================================================
# /intelligence/epss/ranked
# ================================================================

def test_get_ranked_highest_score(client):
    resp = client.get("/intelligence/epss/ranked?criteria=highest_current_score&limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["criteria"] == "highest_current_score"
    assert len(data["cves"]) > 0


def test_get_ranked_fastest_rising(client):
    resp = client.get("/intelligence/epss/ranked?criteria=fastest_rising&limit=5")
    assert resp.status_code == 200


def test_get_ranked_invalid_criteria(client):
    resp = client.get("/intelligence/epss/ranked?criteria=invalid_criteria")
    assert resp.status_code == 400


def test_get_ranked_all_criteria(client):
    """All nine criteria return 200."""
    criteria_list = [
        "largest_daily_increase", "largest_weekly_increase", "largest_monthly_increase",
        "highest_current_score", "highest_percentile", "fastest_rising", "fastest_falling",
        "recently_entered_high_risk", "recently_left_high_risk",
    ]
    for criteria in criteria_list:
        resp = client.get(f"/intelligence/epss/ranked?criteria={criteria}&limit=5")
        assert resp.status_code == 200, f"Failed for criteria={criteria}: {resp.text}"


# ================================================================
# /intelligence/epss/cve/{cve_id}/statistics
# ================================================================

def test_get_cve_statistics(client):
    resp = client.get("/intelligence/epss/cve/CVE-2024-0001/statistics?window_days=30")
    assert resp.status_code == 200
    data = resp.json()
    assert data["cve_id"] == "CVE-2024-0001"
    stats = data["statistics"]
    assert stats["observation_count"] >= 1
    assert "average_score" in stats


def test_get_cve_statistics_unknown(client):
    resp = client.get("/intelligence/epss/cve/CVE-9999-9999/statistics")
    assert resp.status_code == 404


# ================================================================
# /intelligence/epss/alerts/rapidly-increasing
# ================================================================

def test_get_rapidly_increasing_alerts(client):
    resp = client.get("/intelligence/epss/alerts/rapidly-increasing?delta_threshold=0.05&days=1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "alerts" in data
    assert "delta_threshold" in data


def test_get_rapidly_increasing_structure(client):
    resp = client.get("/intelligence/epss/alerts/rapidly-increasing")
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    for alert in alerts:
        assert "cve_id" in alert
        assert "category" in alert
        assert "current_score" in alert
