"""
Tests for CISA KEV REST API endpoints.
"""

from fastapi.testclient import TestClient
from fastapi import FastAPI

from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def _setup_app():
    app = FastAPI()
    app.include_router(router)

    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)
    set_intelligence_engine(engine)

    # Create and activate a dataset version
    from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus
    v = DatasetVersion(feed_id="cisa_kev_1.0", version_id="v1.0", status=DatasetStatus.CREATED)
    repo.save_dataset_version(v)
    repo.set_active_dataset_version("cisa_kev_1.0", "v1.0")

    # Populate sample KEV data
    records = [
        KevRecord(cve_id="CVE-2021-44228", vendor_project="Apache", product="Log4j", due_date="2021-12-24", known_ransomware_campaign_use="Known"),
        KevRecord(cve_id="CVE-2023-23397", vendor_project="Microsoft", product="Outlook", due_date="2023-04-04", known_ransomware_campaign_use="Known"),
    ]
    repo.store_kev_records("v1.0", records)

    return TestClient(app)


def test_api_list_kev():
    client = _setup_app()
    resp = client.get("/intelligence/kev")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["count"] == 2


def test_api_get_kev_by_cve():
    client = _setup_app()
    resp = client.get("/intelligence/kev/CVE-2021-44228")
    assert resp.status_code == 200
    data = resp.json()
    assert data["kev_entry"]["cve_id"] == "CVE-2021-44228"


def test_api_get_kev_404():
    client = _setup_app()
    resp = client.get("/intelligence/kev/CVE-9999-99999")
    assert resp.status_code == 404


def test_api_kev_vendors():
    client = _setup_app()
    resp = client.get("/intelligence/kev/vendors")
    assert resp.status_code == 200
    data = resp.json()
    assert "Apache" in data["vendors"]
    assert "Microsoft" in data["vendors"]


def test_api_kev_products():
    client = _setup_app()
    resp = client.get("/intelligence/kev/products")
    assert resp.status_code == 200
    data = resp.json()
    assert "Log4j" in data["products"]


def test_api_kev_search():
    client = _setup_app()
    resp = client.get("/intelligence/kev/search", params={"vendor": "Apache"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1


def test_api_kev_statistics():
    client = _setup_app()
    resp = client.get("/intelligence/kev/statistics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["statistics"]["total_entries"] == 2


def test_api_kev_version():
    client = _setup_app()
    resp = client.get("/intelligence/kev/version")
    assert resp.status_code == 200
    data = resp.json()
    assert data["active_version"]["version_id"] == "v1.0"
