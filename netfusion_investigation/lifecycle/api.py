"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - REST API Router

FastAPI endpoints for managing investigation lifecycles, replay, snapshots, trace comparisons,
timeline, reports, and activity logs.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Path, Body

from netfusion_investigation.lifecycle.manager import InvestigationLifecycleManager
from netfusion_investigation.lifecycle.models import Priority, Severity, InvestigationStatus

router = APIRouter(prefix="/investigations", tags=["IL-10 Investigation Lifecycle Manager"])

# Singleton manager instance for REST API endpoints
_lifecycle_manager = InvestigationLifecycleManager()


def get_manager() -> InvestigationLifecycleManager:
    return _lifecycle_manager


@router.post("", status_code=201)
def create_investigation(payload: Dict[str, Any] = Body(...)):
    """POST /investigations - Create a new investigation."""
    try:
        case_id = payload.get("case_id")
        title = payload.get("title")
        if not case_id or not title:
            raise HTTPException(status_code=400, detail="case_id and title are required")

        inv = get_manager().create_investigation(
            case_id=case_id,
            title=title,
            description=payload.get("description", ""),
            priority=payload.get("priority", "MEDIUM"),
            severity=payload.get("severity", "MEDIUM"),
            owner=payload.get("owner", "unassigned"),
            team=payload.get("team", "SOC"),
            labels=payload.get("labels", []),
            metadata=payload.get("metadata", {}),
        )
        return inv.to_dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
def list_or_search_investigations(
    query: Optional[str] = Query(None),
    ioc: Optional[str] = Query(None),
    cve: Optional[str] = Query(None),
    asset: Optional[str] = Query(None),
    threat_actor: Optional[str] = Query(None),
    campaign: Optional[str] = Query(None),
    malware: Optional[str] = Query(None),
    analyst: Optional[str] = Query(None),
    workflow: Optional[str] = Query(None),
    timeline: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    case_id: Optional[str] = Query(None),
):
    """GET /investigations - List or search investigations by multiple indexed criteria."""
    results = get_manager().search_investigations(
        query=query,
        ioc=ioc,
        cve=cve,
        asset=asset,
        threat_actor=threat_actor,
        campaign=campaign,
        malware=malware,
        analyst=analyst,
        workflow=workflow,
        timeline=timeline,
        tags=tags,
        case_id=case_id,
    )
    return [inv.to_dict() for inv in results]


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str = Path(...)):
    """GET /investigations/{id} - Get investigation details by ID."""
    inv = get_manager().get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    return inv.to_dict()


@router.patch("/{investigation_id}")
def update_investigation(
    investigation_id: str = Path(...),
    payload: Dict[str, Any] = Body(...),
):
    """PATCH /investigations/{id} - Update an existing investigation."""
    try:
        updated = get_manager().update_investigation(investigation_id, **payload)
        return updated.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404 if "not found" in str(e) else 400, detail=str(e))


@router.delete("/{investigation_id}")
def delete_investigation(investigation_id: str = Path(...)):
    """DELETE /investigations/{id} - Delete an investigation."""
    success = get_manager().delete_investigation(investigation_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    return {"status": "success", "deleted_id": investigation_id}


@router.post("/{investigation_id}/replay")
def replay_investigation(
    investigation_id: str = Path(...),
    payload: Dict[str, Any] = Body(default={}),
):
    """POST /investigations/{id}/replay - Control step-by-step investigation replay."""
    mgr = get_manager()
    inv = mgr.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")

    action = payload.get("action", "INITIALIZE").upper()
    replay_id = payload.get("replay_id")

    if action == "INITIALIZE" or not replay_id:
        sess = mgr.initialize_replay(
            investigation_id,
            timeline_events=payload.get("timeline_events", []),
            graph_events=payload.get("graph_events", []),
            evidence_events=payload.get("evidence_events", []),
            reasoning_events=payload.get("reasoning_events", []),
            recommendation_events=payload.get("recommendation_events", []),
            report_events=payload.get("report_events", []),
        )
        return sess.to_dict()

    if action == "PLAY":
        return mgr.replay_engine.play(replay_id).to_dict()
    elif action == "PAUSE":
        return mgr.replay_engine.pause(replay_id).to_dict()
    elif action == "FORWARD":
        step = mgr.replay_engine.forward(replay_id)
        return step.to_dict()
    elif action == "BACKWARD":
        step = mgr.replay_engine.backward(replay_id)
        return step.to_dict()
    elif action == "JUMP":
        step_idx = payload.get("step_index", 0)
        step = mgr.replay_engine.jump_to_step(replay_id, step_idx)
        return step.to_dict()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown replay action '{action}'")


@router.post("/{investigation_id}/snapshot")
def create_snapshot(
    investigation_id: str = Path(...),
    payload: Dict[str, Any] = Body(default={}),
):
    """POST /investigations/{id}/snapshot - Create a point-in-time snapshot."""
    try:
        snap = get_manager().create_snapshot(
            investigation=investigation_id,
            label=payload.get("label", "Point-in-time Snapshot"),
            created_by=payload.get("created_by", "analyst"),
        )
        return snap.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/compare")
def compare_investigation(
    investigation_id: str = Path(...),
    target_id: str = Query(...),
):
    """GET /investigations/{id}/compare - Compare with another investigation or target."""
    try:
        diff = get_manager().compare_investigations(investigation_id, target_id)
        return diff.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/timeline")
def get_timeline(investigation_id: str = Path(...)):
    """GET /investigations/{id}/timeline - Get timeline events for an investigation."""
    inv = get_manager().get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    return {"investigation_id": investigation_id, "timeline_event_ids": inv.links.timeline_event_ids}


@router.get("/{investigation_id}/trace")
def get_trace(investigation_id: str = Path(...)):
    """GET /investigations/{id}/trace - Get reasoning trace links for an investigation."""
    inv = get_manager().get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    return {"investigation_id": investigation_id, "reasoning_trace_ids": inv.links.reasoning_trace_ids}


@router.get("/{investigation_id}/reports")
def get_reports(investigation_id: str = Path(...)):
    """GET /investigations/{id}/reports - Get reports stored for an investigation."""
    inv = get_manager().get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    arts = get_manager().artifact_manager.list_artifacts(investigation_id, artifact_type="REPORT")
    return [a.to_dict() for a in arts]


@router.get("/{investigation_id}/activity")
def get_activity(investigation_id: str = Path(...)):
    """GET /investigations/{id}/activity - Get immutable audit activity log."""
    inv = get_manager().get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    activities = get_manager().get_activities(investigation_id=investigation_id)
    return [a.to_dict() for a in activities]
