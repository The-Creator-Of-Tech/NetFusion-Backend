"""
Unit tests for FastAPI endpoints in api/routes.py.
"""

from fastapi.testclient import TestClient
import pytest
from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.tests.conftest import SampleGenericIntelligenceFeed
from fastapi import FastAPI


def test_api_routes_integration():
    repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)
    feed = SampleGenericIntelligenceFeed("api_feed_1")
    engine.register_feed(feed)
    set_intelligence_engine(engine)

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # GET /intelligence/feeds
    resp = client.get("/intelligence/feeds")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["feeds"][0]["feed_id"] == "api_feed_1"

    # POST /intelligence/feeds/api_feed_1/sync
    sync_resp = client.post("/intelligence/feeds/api_feed_1/sync")
    assert sync_resp.status_code == 200, sync_resp.json()
    assert sync_resp.json()["status"] == "success"

    # GET /intelligence/health
    health_resp = client.get("/intelligence/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["summary"]["total_feeds"] == 1

    # GET /intelligence/versions
    ver_resp = client.get("/intelligence/versions")
    assert ver_resp.status_code == 200
    assert ver_resp.json()["count"] == 1

    # GET /intelligence/imports
    imp_resp = client.get("/intelligence/imports")
    assert imp_resp.status_code == 200
    assert imp_resp.json()["count"] == 1

    # GET /intelligence/statistics
    stat_resp = client.get("/intelligence/statistics")
    assert stat_resp.status_code == 200
    assert stat_resp.json()["statistics"]["total_feeds_registered"] == 1
