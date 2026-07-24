"""
Tests for IL-10 REST API Endpoints using FastAPI TestClient.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netfusion_investigation.lifecycle.api import router, get_manager


app = FastAPI()
app.include_router(router)
client = TestClient(app)


def test_rest_api_lifecycle_endpoints():
    mgr = get_manager()
    mgr.repository.clear()

    # 1. POST /investigations
    res_create = client.post(
        "/investigations",
        json={
            "case_id": "API-CASE-100",
            "title": "API Test Investigation",
            "description": "Created via REST API",
            "owner": "api_user",
            "labels": ["REST", "API"],
        },
    )
    assert res_create.status_code == 201
    inv_data = res_create.json()
    inv_id = inv_data["id"]
    assert inv_data["case_id"] == "API-CASE-100"

    # Link an entity for search
    mgr.link_entities(inv_id, ioc_values=["10.0.0.1"])

    # 2. GET /investigations
    res_list = client.get("/investigations?query=API")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    res_search_ioc = client.get("/investigations?ioc=10.0.0.1")
    assert res_search_ioc.status_code == 200
    assert len(res_search_ioc.json()) == 1

    # 3. GET /investigations/{id}
    res_get = client.get(f"/investigations/{inv_id}")
    assert res_get.status_code == 200
    assert res_get.json()["title"] == "API Test Investigation"

    # 4. PATCH /investigations/{id}
    res_patch = client.patch(
        f"/investigations/{inv_id}",
        json={"title": "Updated API Title", "priority": "CRITICAL"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["title"] == "Updated API Title"
    assert res_patch.json()["priority"] == "CRITICAL"

    # 5. POST /investigations/{id}/snapshot
    res_snap = client.post(
        f"/investigations/{inv_id}/snapshot",
        json={"label": "API Snapshot"},
    )
    assert res_snap.status_code == 200
    assert res_snap.json()["label"] == "API Snapshot"

    # 6. POST /investigations/{id}/replay
    res_rpl_init = client.post(
        f"/investigations/{inv_id}/replay",
        json={"action": "INITIALIZE", "timeline_events": [{"timestamp": "2026-07-22T12:00:00Z", "title": "API Timeline Event"}]},
    )
    assert res_rpl_init.status_code == 200
    rpl_id = res_rpl_init.json()["replay_id"]

    res_rpl_play = client.post(
        f"/investigations/{inv_id}/replay",
        json={"action": "PLAY", "replay_id": rpl_id},
    )
    assert res_rpl_play.status_code == 200
    assert res_rpl_play.json()["status"] == "PLAYING"

    # 7. GET /investigations/{id}/timeline
    res_tl = client.get(f"/investigations/{inv_id}/timeline")
    assert res_tl.status_code == 200

    # 8. GET /investigations/{id}/trace
    res_tr = client.get(f"/investigations/{inv_id}/trace")
    assert res_tr.status_code == 200

    # 9. GET /investigations/{id}/reports
    res_rep = client.get(f"/investigations/{inv_id}/reports")
    assert res_rep.status_code == 200

    # 10. GET /investigations/{id}/activity
    res_act = client.get(f"/investigations/{inv_id}/activity")
    assert res_act.status_code == 200
    assert len(res_act.json()) > 0

    # 11. GET /investigations/{id}/compare
    # Create second investigation to compare
    res_c2 = client.post(
        "/investigations",
        json={"case_id": "API-CASE-101", "title": "Second Inv"},
    )
    inv_id2 = res_c2.json()["id"]
    res_cmp = client.get(f"/investigations/{inv_id}/compare?target_id={inv_id2}")
    assert res_cmp.status_code == 200
    assert "confidence_delta" in res_cmp.json()

    # 12. DELETE /investigations/{id}
    res_del = client.delete(f"/investigations/{inv_id}")
    assert res_del.status_code == 200
    assert res_del.json()["deleted_id"] == inv_id
