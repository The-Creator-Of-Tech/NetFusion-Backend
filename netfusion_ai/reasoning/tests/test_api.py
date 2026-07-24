"""
Tests for ATRE FastAPI REST API endpoints.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from netfusion_ai.reasoning import router


def create_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_api_endpoints():
    app = create_test_app()
    client = TestClient(app)

    payload = {
        "user_question": "What happened on host-srv-01?",
        "context_node_ids": ["CVE-2023-34362"],
        "investigation_id": "inv-test-api-01",
    }

    # 1. POST /reasoning/query
    res = client.post("/reasoning/query", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["investigation_id"] == "inv-test-api-01"
    assert "explanation" in data

    # 2. POST /reasoning/hypothesis
    res = client.post("/reasoning/hypothesis", json=payload)
    assert res.status_code == 200
    assert res.json()["count"] >= 1

    # 3. POST /reasoning/explain
    res = client.post("/reasoning/explain", json=payload)
    assert res.status_code == 200
    assert "explanation" in res.json()

    # 4. POST /reasoning/risk
    res = client.post("/reasoning/risk", json=payload)
    assert res.status_code == 200
    assert "risk_assessment" in res.json()

    # 5. POST /reasoning/attack-chain
    res = client.post("/reasoning/attack-chain", json=payload)
    assert res.status_code == 200
    assert res.json()["attack_chain"]["total_stages"] == 11

    # 6. POST /reasoning/recommendations
    res = client.post("/reasoning/recommendations", json=payload)
    assert res.status_code == 200
    assert res.json()["count"] == 8

    # 7. POST /reasoning/timeline
    res = client.post("/reasoning/timeline", json=payload)
    assert res.status_code == 200
    assert "timeline" in res.json()

    # 8. POST /reasoning/report
    res = client.post("/reasoning/report", json=payload)
    assert res.status_code == 200
    assert "report" in res.json()

    # 9. GET /reasoning/history
    res = client.get("/reasoning/history")
    assert res.status_code == 200
    assert res.json()["count"] >= 1

    # 10. GET /reasoning/statistics
    res = client.get("/reasoning/statistics")
    assert res.status_code == 200
    assert res.json()["statistics"]["supported_question_types"] == 19
