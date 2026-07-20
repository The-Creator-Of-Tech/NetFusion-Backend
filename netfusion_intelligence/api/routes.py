"""
FastAPI Management Endpoints for netfusion_intelligence.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Path

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.exceptions import FeedNotFoundError, IntelligenceException

# Global singleton or injected engine instance
_engine_instance: Optional[IntelligenceEngine] = None


def set_intelligence_engine(engine: IntelligenceEngine) -> None:
    global _engine_instance
    _engine_instance = engine


def get_intelligence_engine() -> IntelligenceEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = IntelligenceEngine()
    return _engine_instance


router = APIRouter(prefix="/intelligence", tags=["Intelligence Subsystem"])


@router.get("/feeds")
def list_feeds() -> Dict[str, Any]:
    """
    GET /intelligence/feeds
    List all registered intelligence feeds, their configs, and declared manifests.
    """
    engine = get_intelligence_engine()
    feeds = engine.list_feeds()
    return {
        "status": "success",
        "count": len(feeds),
        "feeds": [
            {
                "feed_id": f.feed_id,
                "name": f.feed_name,
                "description": f.description,
                "enabled": f.config.enabled,
                "config": f.config.to_dict(),
                "manifest": f.manifest.to_dict() if f.manifest else None,
            }
            for f in feeds
        ],
    }


@router.get("/health")
def get_health(feed_id: Optional[str] = Query(None, description="Optional feed ID filter")) -> Dict[str, Any]:
    """
    GET /intelligence/health
    Get platform or feed-specific health state.
    """
    engine = get_intelligence_engine()
    if feed_id:
        health = engine.get_health(feed_id)
        if not health:
            raise HTTPException(status_code=404, detail=f"Feed health for '{feed_id}' not found")
        return {"status": "success", "health": health.to_dict()}
    
    summary = engine.get_health()
    return {"status": "success", "summary": summary.to_dict()}


@router.get("/dashboard")
def get_dashboard() -> Dict[str, Any]:
    """
    GET /intelligence/dashboard
    Get comprehensive Framework Health Dashboard.
    """
    engine = get_intelligence_engine()
    summary = engine.get_health()
    metrics = engine.get_metrics()
    return {
        "status": "success",
        "dashboard": {
            "health_summary": summary.to_dict(),
            "metrics": metrics.to_dict(),
            "execution_order": engine.get_execution_order(),
        },
    }


@router.get("/versions")
def list_versions(feed_id: Optional[str] = Query(None, description="Filter dataset versions by feed ID")) -> Dict[str, Any]:
    """
    GET /intelligence/versions
    List dataset versions managed by the framework.
    """
    engine = get_intelligence_engine()
    versions = engine.get_dataset_versions(feed_id=feed_id)
    return {
        "status": "success",
        "count": len(versions),
        "versions": [v.to_dict() for v in versions],
    }


@router.get("/imports")
def list_imports(
    feed_id: Optional[str] = Query(None, description="Filter import history by feed ID"),
    status: Optional[str] = Query(None, description="Filter import history by status"),
    trigger: Optional[str] = Query(None, description="Filter import history by trigger (manual/scheduled)"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/imports
    List permanent synchronization import history and statistics.
    """
    engine = get_intelligence_engine()
    imports = engine.get_import_history(feed_id=feed_id, status=status, trigger=trigger, limit=limit)
    return {
        "status": "success",
        "count": len(imports),
        "imports": [i.to_dict() for i in imports],
    }


@router.post("/feeds/{feed_id}/sync")
def sync_feed(feed_id: str = Path(..., description="ID of feed to synchronize")) -> Dict[str, Any]:
    """
    POST /intelligence/feeds/{feed_id}/sync
    Triggers manual synchronization execution for a registered feed.
    """
    engine = get_intelligence_engine()
    try:
        result = engine.sync_feed(feed_id)
        return {
            "status": "success",
            "message": f"Synchronization for feed '{feed_id}' completed",
            "result": result.to_dict(),
        }
    except FeedNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except IntelligenceException as ie:
        raise HTTPException(status_code=500, detail=str(ie))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Unexpected error during sync: {ex}")


@router.get("/statistics")
def get_statistics() -> Dict[str, Any]:
    """
    GET /intelligence/statistics
    Expose global intelligence ingestion & dataset statistics.
    """
    engine = get_intelligence_engine()
    stats = engine.get_statistics()
    return {
        "status": "success",
        "statistics": stats.to_dict(),
    }


@router.get("/metrics")
def get_metrics() -> Dict[str, Any]:
    """
    GET /intelligence/metrics
    Expose structured operational metrics.
    """
    engine = get_intelligence_engine()
    metrics = engine.get_metrics()
    return {
        "status": "success",
        "metrics": metrics.to_dict(),
    }


@router.get("/audit-logs")
def get_audit_logs(
    event_type: Optional[str] = Query(None, description="Filter audit logs by event type"),
    feed_id: Optional[str] = Query(None, description="Filter audit logs by feed ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/audit-logs
    Expose domain event audit log history.
    """
    engine = get_intelligence_engine()
    logs = engine.get_audit_logs(event_type=event_type, feed_id=feed_id, limit=limit)
    return {
        "status": "success",
        "count": len(logs),
        "audit_logs": [l.to_dict() for l in logs],
    }


@router.get("/dependencies")
def get_dependencies() -> Dict[str, Any]:
    """
    GET /intelligence/dependencies
    Expose feed dependency graph and topological execution order.
    """
    engine = get_intelligence_engine()
    order = engine.get_execution_order()
    return {
        "status": "success",
        "execution_order": order,
    }


# -------------------------------------------------------------------------
# Security & Trust Verification Framework API Endpoints
# -------------------------------------------------------------------------

@router.get("/trust")
def get_trust_summary() -> Dict[str, Any]:
    """
    GET /intelligence/trust
    Expose overall trust framework summary across all feeds.
    """
    engine = get_intelligence_engine()
    summary = engine.get_trust_summary()
    return {
        "status": "success",
        "trust_summary": summary,
    }


@router.get("/trust/history")
def get_trust_history(
    feed_id: Optional[str] = Query(None, description="Filter trust history by feed ID"),
    overall_trust: Optional[str] = Query(None, description="Filter trust history by decision (TRUSTED, BLOCKED, etc)"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/trust/history
    Expose persistent trust audit history log.
    """
    engine = get_intelligence_engine()
    history = engine.get_trust_history(feed_id=feed_id, overall_trust=overall_trust, limit=limit)
    return {
        "status": "success",
        "count": len(history),
        "history": history,
    }


@router.get("/trust/{feed}")
def get_feed_trust(feed: str = Path(..., description="Feed ID to retrieve trust evaluation for")) -> Dict[str, Any]:
    """
    GET /intelligence/trust/{feed}
    Expose TrustProfile and latest verification results for a specific feed.
    """
    engine = get_intelligence_engine()
    try:
        data = engine.get_feed_trust(feed)
        return {
            "status": "success",
            "trust": data,
        }
    except Exception as ex:
        raise HTTPException(status_code=404, detail=f"Trust profile for feed '{feed}' not found or invalid: {ex}")

