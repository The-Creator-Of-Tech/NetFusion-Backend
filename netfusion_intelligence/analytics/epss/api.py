"""
IL-5.1 EPSS Analytics REST API Routes.

Exposes all analytics capabilities over HTTP.  Integrated into
the netfusion_intelligence/api/routes.py via include_router.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Path

from netfusion_intelligence.analytics.epss.engine import EpssAnalyticsEngine
from netfusion_intelligence.analytics.epss.models import (
    EpssQueryFilter,
    RankingCriteria,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intelligence/epss", tags=["EPSS Analytics"])

# Global singleton instance — wired externally by intelligence engine
_analytics_engine: Optional[EpssAnalyticsEngine] = None


def set_analytics_engine(engine: EpssAnalyticsEngine) -> None:
    global _analytics_engine
    _analytics_engine = engine


def get_analytics_engine() -> EpssAnalyticsEngine:
    if _analytics_engine is None:
        raise HTTPException(
            status_code=503,
            detail="EPSS Analytics Engine not initialized. Contact system administrator.",
        )
    return _analytics_engine


# ================================================================
# Analytics Endpoints
# ================================================================


@router.get("/analytics")
def get_epss_analytics(
    time_window: str = Query("7d", description="Time window: 24h, 7d, 14d, 30d, 90d"),
    limit_cves: int = Query(5000, ge=100, le=50000),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/analytics
    Returns global EPSS analytics summary for the specified time window.
    """
    engine = get_analytics_engine()
    summary = engine.get_global_statistics(time_window=time_window, limit_cves=limit_cves)
    return {"status": "success", "analytics": summary.to_dict()}


@router.get("/trends")
def get_epss_trends(
    cve_ids: Optional[str] = Query(None, description="Comma-separated CVE IDs"),
    trend_type: Optional[str] = Query(None, description="Filter by trend classification"),
    min_score: Optional[float] = Query(None, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/trends
    Returns trend analyses for specified CVEs or filtered by criteria.
    """
    engine = get_analytics_engine()

    if cve_ids:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        analyses = engine.get_trend_analyses_bulk(ids)
        return {
            "status": "success",
            "count": len(analyses),
            "trends": {cve_id: a.to_dict() for cve_id, a in analyses.items()},
        }

    # Return recent top rising CVEs as a default
    rising = engine.get_top_rising(limit=limit, min_score=min_score)
    trend_cves = [r.cve_id for r in rising]
    analyses = engine.get_trend_analyses_bulk(trend_cves)
    return {
        "status": "success",
        "count": len(analyses),
        "trends": {cve_id: a.to_dict() for cve_id, a in analyses.items()},
    }


@router.get("/history/{cve_id}")
def get_epss_history_view(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-1234)"),
    limit: int = Query(365, ge=1, le=730),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/history/{cve_id}
    Returns full history view with time-series data for visualization.
    """
    engine = get_analytics_engine()
    view = engine.get_history_view(cve_id.upper(), limit=limit)
    if not view:
        raise HTTPException(status_code=404, detail=f"No EPSS history found for {cve_id}")
    return {"status": "success", "history": view.to_dict()}


@router.get("/top-rising")
def get_epss_top_rising(
    limit: int = Query(50, ge=1, le=200),
    time_window: str = Query("7d", description="Time window: 24h, 7d, 14d, 30d, 90d"),
    min_score: Optional[float] = Query(None, ge=0.0, le=1.0),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/top-rising
    Returns top fastest-rising CVEs in the specified time window.
    """
    engine = get_analytics_engine()
    ranked = engine.get_top_rising(limit=limit, time_window=time_window, min_score=min_score)
    return {
        "status": "success",
        "time_window": time_window,
        "count": len(ranked),
        "cves": [r.to_dict() for r in ranked],
    }


@router.get("/top-falling")
def get_epss_top_falling(
    limit: int = Query(50, ge=1, le=200),
    time_window: str = Query("7d", description="Time window: 24h, 7d, 14d, 30d, 90d"),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/top-falling
    Returns top fastest-falling CVEs in the specified time window.
    """
    engine = get_analytics_engine()
    ranked = engine.get_top_falling(limit=limit, time_window=time_window)
    return {
        "status": "success",
        "time_window": time_window,
        "count": len(ranked),
        "cves": [r.to_dict() for r in ranked],
    }


@router.get("/new-high-risk")
def get_epss_new_high_risk(
    lookback_days: int = Query(7, ge=1, le=90),
    high_risk_threshold: float = Query(0.50, ge=0.0, le=1.0),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/new-high-risk
    Returns CVEs that recently entered high-risk territory.
    """
    engine = get_analytics_engine()
    alerts = engine.get_new_high_risk(
        lookback_days=lookback_days, high_risk_threshold=high_risk_threshold
    )
    return {
        "status": "success",
        "lookback_days": lookback_days,
        "threshold": high_risk_threshold,
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


@router.get("/forecast")
def get_epss_forecast_indicators(
    cve_id: str = Query(..., description="CVE ID (e.g., CVE-2024-1234)"),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/forecast
    Returns forecasting mathematical indicators for a CVE.
    Foundation for future ML-based forecasting.
    """
    engine = get_analytics_engine()
    indicators = engine.get_forecast_indicators(cve_id.upper())
    if indicators.get("observation_count", 0) == 0:
        raise HTTPException(status_code=404, detail=f"No EPSS data found for {cve_id}")
    return {"status": "success", "indicators": indicators}


@router.get("/statistics")
def get_epss_analytics_statistics(
    time_window: str = Query("7d", description="Time window: 24h, 7d, 14d, 30d, 90d"),
    limit_cves: int = Query(5000, ge=100, le=50000),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/statistics
    Returns comprehensive EPSS analytics statistics.
    (Alias endpoint for /analytics)
    """
    engine = get_analytics_engine()
    summary = engine.get_global_statistics(time_window=time_window, limit_cves=limit_cves)
    return {"status": "success", "statistics": summary.to_dict()}


@router.get("/ranked")
def get_epss_ranked_list(
    criteria: str = Query(..., description="Ranking criteria: largest_daily_increase, highest_current_score, fastest_rising, etc."),
    limit: int = Query(50, ge=1, le=200),
    time_window: str = Query("7d", description="Time window: 24h, 7d, 14d, 30d, 90d"),
    min_score: Optional[float] = Query(None, ge=0.0, le=1.0),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/ranked
    Returns ranked CVE list for any of the nine supported ranking criteria.
    """
    engine = get_analytics_engine()

    # Map string to enum
    criteria_map = {
        "largest_daily_increase": RankingCriteria.LARGEST_DAILY_INCREASE,
        "largest_weekly_increase": RankingCriteria.LARGEST_WEEKLY_INCREASE,
        "largest_monthly_increase": RankingCriteria.LARGEST_MONTHLY_INCREASE,
        "highest_current_score": RankingCriteria.HIGHEST_CURRENT_SCORE,
        "highest_percentile": RankingCriteria.HIGHEST_PERCENTILE,
        "fastest_rising": RankingCriteria.FASTEST_RISING,
        "fastest_falling": RankingCriteria.FASTEST_FALLING,
        "recently_entered_high_risk": RankingCriteria.RECENTLY_ENTERED_HIGH_RISK,
        "recently_left_high_risk": RankingCriteria.RECENTLY_LEFT_HIGH_RISK,
    }

    criteria_enum = criteria_map.get(criteria.lower())
    if not criteria_enum:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown ranking criteria: {criteria}. Valid: {', '.join(criteria_map.keys())}",
        )

    query_filter = EpssQueryFilter(
        min_score=min_score,
        time_window=time_window,
        limit=limit,
    )

    ranked = engine.get_ranked_list(criteria=criteria_enum, query_filter=query_filter)
    return {
        "status": "success",
        "criteria": criteria_enum.value,
        "count": len(ranked),
        "cves": [r.to_dict() for r in ranked],
    }


@router.get("/cve/{cve_id}/statistics")
def get_cve_statistics(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-1234)"),
    window_days: int = Query(30, ge=1, le=365),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/cve/{cve_id}/statistics
    Returns per-CVE statistics over the specified time window.
    """
    engine = get_analytics_engine()
    stats = engine.get_cve_statistics(cve_id.upper(), window_days=window_days)
    if stats.get("observation_count", 0) == 0:
        raise HTTPException(status_code=404, detail=f"No EPSS data found for {cve_id}")
    return {"status": "success", "cve_id": cve_id.upper(), "statistics": stats}


@router.get("/alerts/rapidly-increasing")
def get_rapidly_increasing_alerts(
    delta_threshold: float = Query(0.10, ge=0.01, le=1.0),
    days: int = Query(1, ge=1, le=30),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/alerts/rapidly-increasing
    Returns CVEs with rapidly increasing EPSS scores above the delta threshold.
    """
    engine = get_analytics_engine()
    alerts = engine.get_rapidly_increasing_alerts(
        delta_threshold=delta_threshold, time_window_days=days
    )
    return {
        "status": "success",
        "delta_threshold": delta_threshold,
        "time_window_days": days,
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
