"""
Unit tests for NVD REST API endpoints (routes.py).
"""

from fastapi.testclient import TestClient
from fastapi import FastAPI

from netfusion_intelligence.api.routes import set_intelligence_engine, router
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.feeds.nvd.feed import NvdCveFeed
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_JSON_RESPONSE
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_nvd_api_endpoints():
    app = FastAPI()
    app.include_router(router)

    sql_repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    engine = IntelligenceEngine(repository=sql_repo)
    set_intelligence_engine(engine)

    nvd_feed = NvdCveFeed(repository=sql_repo, offline_data=SAMPLE_NVD_JSON_RESPONSE)
    engine.register_feed(nvd_feed)
    engine.sync_feed("nvd_cve_2.0")

    client = TestClient(app)

    # Test GET /intelligence/nvd/cves
    resp = client.get("/intelligence/nvd/cves")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["count"] == 2

    # Test GET /intelligence/nvd/cves/CVE-2024-1234
    resp_detail = client.get("/intelligence/nvd/cves/CVE-2024-1234")
    assert resp_detail.status_code == 200
    cve_data = resp_detail.json()
    assert cve_data["cve"]["cve_id"] == "CVE-2024-1234"

    # Test GET /intelligence/nvd/search
    resp_search = client.get("/intelligence/nvd/search?severity=CRITICAL")
    assert resp_search.status_code == 200
    search_data = resp_search.json()
    assert search_data["count"] == 1
    assert search_data["results"][0]["cve_id"] == "CVE-2024-1234"

    # Test GET /intelligence/nvd/statistics
    resp_stats = client.get("/intelligence/nvd/statistics")
    assert resp_stats.status_code == 200
    stats_data = resp_stats.json()
    assert stats_data["statistics"]["total_cves"] == 2
