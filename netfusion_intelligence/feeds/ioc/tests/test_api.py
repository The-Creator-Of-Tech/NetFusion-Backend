"""
Tests for IL-7 REST API routes — IOC endpoints.
Uses TestClient with a fully wired engine and IOC feed.
"""

import uuid
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.config import EngineConfig
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.ioc.feed import IocFeed
from netfusion_intelligence.feeds.ioc.providers import OfflineImportProvider
from netfusion_intelligence.feeds.ioc.repository import IocRepository
from netfusion_intelligence.feeds.ioc.models import IocEntity
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from datetime import datetime, timezone


SAMPLE = {"indicators": [
    {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.9, "severity": "high",
     "malware_families": ["Emotet"]},
    {"type": "domain", "value": "malware.example.com", "confidence": 0.7},
    {"type": "sha256", "value": "a" * 64, "confidence": 0.95, "severity": "critical"},
]}

VID = "api-test-v001"


@pytest.fixture(scope="module")
def client():
    raw_repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(
        config=EngineConfig(db_url="sqlite:///:memory:"),
        repository=raw_repo,
    )
    provider = OfflineImportProvider(data=SAMPLE, name="APITest")
    feed = IocFeed(repository=raw_repo, providers=[provider])
    engine.register_feed(feed)
    # Use lifecycle_runner directly to bypass the dependency pre-check in the
    # scheduler (prerequisite feeds are not registered in unit test environments)
    engine.lifecycle_runner.execute(feed)

    set_intelligence_engine(engine)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestIocApiList:

    def test_list_indicators_200(self, client):
        resp = client.get("/intelligence/ioc")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "indicators" in data
        assert data["count"] >= 3

    def test_list_filter_by_type(self, client):
        resp = client.get("/intelligence/ioc?ioc_type=ipv4")
        assert resp.status_code == 200
        data = resp.json()
        assert all(i["ioc_type"] == "ipv4" for i in data["indicators"])

    def test_list_filter_by_severity(self, client):
        resp = client.get("/intelligence/ioc?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        assert all(i["severity"] == "critical" for i in data["indicators"])

    def test_list_limit(self, client):
        resp = client.get("/intelligence/ioc?limit=1")
        assert resp.status_code == 200
        assert len(resp.json()["indicators"]) <= 1


class TestIocApiSearch:

    def test_search_by_malware(self, client):
        resp = client.get("/intelligence/ioc/search?malware=Emotet")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1

    def test_search_by_type(self, client):
        resp = client.get("/intelligence/ioc/search?ioc_type=domain")
        assert resp.status_code == 200
        assert all(r["ioc_type"] == "domain" for r in resp.json()["results"])

    def test_search_by_value(self, client):
        resp = client.get("/intelligence/ioc/search?value=malware.example")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_search_empty_query_returns_all(self, client):
        resp = client.get("/intelligence/ioc/search")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 3


class TestIocApiGetById:

    def test_get_existing_indicator(self, client):
        # First get a valid ID
        list_resp = client.get("/intelligence/ioc?limit=1")
        ioc_id = list_resp.json()["indicators"][0]["ioc_id"]

        resp = client.get(f"/intelligence/ioc/{ioc_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["indicator"]["ioc_id"] == ioc_id

    def test_get_nonexistent_returns_404(self, client):
        resp = client.get("/intelligence/ioc/does-not-exist")
        assert resp.status_code == 404


class TestIocApiStatistics:

    def test_statistics_200(self, client):
        resp = client.get("/intelligence/ioc/statistics")
        assert resp.status_code == 200
        stats = resp.json()["statistics"]
        assert "total_indicators" in stats
        assert stats["total_indicators"] >= 3

    def test_statistics_by_type_present(self, client):
        resp = client.get("/intelligence/ioc/statistics")
        by_type = resp.json()["statistics"]["by_type"]
        assert "ipv4" in by_type or "domain" in by_type


class TestIocApiVersion:

    def test_version_200(self, client):
        resp = client.get("/intelligence/ioc/version")
        assert resp.status_code == 200
        assert "version" in resp.json()


class TestIocApiReputation:

    def test_get_reputation_for_existing(self, client):
        list_resp = client.get("/intelligence/ioc?limit=1")
        ioc_id = list_resp.json()["indicators"][0]["ioc_id"]
        resp = client.get(f"/intelligence/ioc/{ioc_id}/reputation")
        assert resp.status_code == 200
        assert "reputation" in resp.json()
        assert resp.json()["reputation"]["ioc_id"] == ioc_id

    def test_get_reputation_nonexistent_404(self, client):
        resp = client.get("/intelligence/ioc/no-such-id/reputation")
        assert resp.status_code == 404


class TestIocApiSightings:

    def test_get_sightings_empty(self, client):
        list_resp = client.get("/intelligence/ioc?limit=1")
        ioc_id = list_resp.json()["indicators"][0]["ioc_id"]
        resp = client.get(f"/intelligence/ioc/{ioc_id}/sightings")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


class TestIocApiCorrelation:

    def test_get_correlation_empty_before_build(self, client):
        list_resp = client.get("/intelligence/ioc?limit=1")
        ioc_id = list_resp.json()["indicators"][0]["ioc_id"]
        resp = client.get(f"/intelligence/ioc/{ioc_id}/correlation")
        assert resp.status_code == 200
        assert "relationships" in resp.json()
