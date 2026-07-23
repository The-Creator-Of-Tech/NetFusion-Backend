"""
Integration tests for MITRE REST API endpoints.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.mitre.feed import MitreAttackFeed
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_mitre_api_endpoints():
    # Setup test engine with in-memory repository
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)
    
    # Register MITRE feed with offline sample STIX data
    feed = MitreAttackFeed(repository=repo, offline_data=SAMPLE_STIX_BUNDLE)
    engine.register_feed(feed)

    # Sync feed to populate database
    res = engine.sync_feed("mitre_attack_enterprise")
    assert res.status.value == "COMPLETED"

    # Setup FastAPI test client
    set_intelligence_engine(engine)
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # GET /intelligence/mitre/techniques
    resp = client.get("/intelligence/mitre/techniques")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["count"] >= 2

    # GET /intelligence/mitre/techniques/T1059
    resp_tech = client.get("/intelligence/mitre/techniques/T1059")
    assert resp_tech.status_code == 200
    assert resp_tech.json()["technique"]["name"] == "Command and Scripting Interpreter"

    # GET /intelligence/mitre/techniques/T1059/relationships
    resp_rels = client.get("/intelligence/mitre/techniques/T1059/relationships")
    assert resp_rels.status_code == 200
    assert resp_rels.json()["count"] >= 2

    # GET /intelligence/mitre/groups
    resp_grp = client.get("/intelligence/mitre/groups")
    assert resp_grp.status_code == 200
    assert resp_grp.json()["count"] == 1

    # GET /intelligence/mitre/search
    resp_srch = client.get("/intelligence/mitre/search?query=Fancy%20Bear")
    assert resp_srch.status_code == 200
    assert resp_srch.json()["count"] == 1

    # GET /intelligence/mitre/statistics
    resp_stats = client.get("/intelligence/mitre/statistics")
    assert resp_stats.status_code == 200
    assert resp_stats.json()["statistics"]["total_objects"] == 9
