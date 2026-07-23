"""
Tests for REST API endpoints in NetFusion CIIL using FastAPI TestClient.
"""

from fastapi.testclient import TestClient
from fastapi import FastAPI
import pytest

from netfusion_intelligence.identity.api import router as identity_router, set_identity_service
from netfusion_intelligence.identity.service import IdentityService


@pytest.fixture
def api_client():
    app = FastAPI()
    app.include_router(identity_router)

    service = IdentityService()
    set_identity_service(service)

    client = TestClient(app)
    return client, service


def test_api_resolve_and_lookup_endpoints(api_client):
    client, service = api_client

    # Resolve POST endpoint
    payload = {
        "entity_type": "ATTACK_TECHNIQUE",
        "display_name": "Phishing",
        "external_identifiers": [
            {"source": "MITRE", "identifier": "T1566", "identifier_type": "ATTACK_ID"}
        ],
        "aliases": ["T1566"],
        "feed_source": "MITRE",
    }
    resp = client.post("/intelligence/identity/resolve", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    u_val = data["entity"]["canonical_uuid"]

    # GET by UUID endpoint
    resp_get = client.get(f"/intelligence/identity/{u_val}")
    assert resp_get.status_code == 200
    assert resp_get.json()["entity"]["display_name"] == "Phishing"

    # GET by External ID endpoint
    resp_ext = client.get("/intelligence/identity/external/MITRE/T1566")
    assert resp_ext.status_code == 200
    assert resp_ext.json()["count"] == 1

    # Search endpoint
    resp_search = client.get("/intelligence/identity/search?q=Phishing")
    assert resp_search.status_code == 200
    assert resp_search.json()["count"] == 1

    # Statistics endpoint
    resp_stats = client.get("/intelligence/identity/statistics")
    assert resp_stats.status_code == 200
    assert resp_stats.json()["statistics"]["total_canonical_entities"] == 1
