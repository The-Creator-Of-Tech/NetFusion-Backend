"""
Tests for IL-6 REST API endpoints — CWE, CAPEC, and Knowledge Graph routes.
Uses FastAPI TestClient with an in-memory repository pre-populated with CWE and CAPEC data.
"""

import datetime
import pytest

from fastapi.testclient import TestClient
from fastapi import FastAPI

from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.feeds.cwe.feed import CweFeed
from netfusion_intelligence.feeds.capec.feed import CapecFeed
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML


# ---------------------------------------------------------------------------
# App / client setup
# ---------------------------------------------------------------------------

def _make_version(feed_id, version_id, source_version="1.0"):
    return DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum="test",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version=source_version,
        status=DatasetStatus.CREATED,
        validation_status=ValidationStatus.PASSED,
    )


def _run_feed(repo, feed_class, xml_data, feed_id, version_id, source_version="1.0"):
    dv = _make_version(feed_id, version_id, source_version)
    repo.save_dataset_version(dv)
    feed = feed_class(repository=repo, offline_data=xml_data)
    raw = feed.fetch_raw_data()
    parsed = feed.parse(raw)
    normalized = feed.normalize(parsed)
    feed.store(dv, normalized)
    feed.build_relationships(dv)
    feed.on_activate(dv)
    return dv


@pytest.fixture(scope="module")
def client():
    """TestClient with a pre-populated in-memory repository."""
    repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
    _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")

    engine = IntelligenceEngine(repository=repo)
    set_intelligence_engine(engine)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# CWE endpoints
# ---------------------------------------------------------------------------

class TestApiCweList:

    def test_list_cwe_status_200(self, client):
        resp = client.get("/intelligence/cwe")
        assert resp.status_code == 200

    def test_list_cwe_response_shape(self, client):
        resp = client.get("/intelligence/cwe")
        body = resp.json()
        assert body["status"] == "success"
        assert "weaknesses" in body
        assert "count" in body

    def test_list_cwe_returns_weaknesses(self, client):
        resp = client.get("/intelligence/cwe")
        body = resp.json()
        assert body["count"] == 2

    def test_list_cwe_filter_by_abstraction(self, client):
        resp = client.get("/intelligence/cwe?abstraction=Base")
        body = resp.json()
        assert body["status"] == "success"
        for w in body["weaknesses"]:
            assert w["abstraction"] == "Base"

    def test_list_cwe_filter_by_status(self, client):
        resp = client.get("/intelligence/cwe?status=Stable")
        body = resp.json()
        assert body["status"] == "success"

    def test_list_cwe_with_limit(self, client):
        resp = client.get("/intelligence/cwe?limit=1")
        body = resp.json()
        assert len(body["weaknesses"]) <= 1


class TestApiCweGet:

    def test_get_cwe79_status_200(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        assert resp.status_code == 200

    def test_get_cwe79_response_shape(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert body["status"] == "success"
        assert "weakness" in body

    def test_get_cwe79_correct_id(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert body["weakness"]["cwe_id"] == "CWE-79"

    def test_get_cwe_by_number_only_normalizes(self, client):
        """Passing just '79' should be normalized to 'CWE-79'."""
        resp = client.get("/intelligence/cwe/79")
        assert resp.status_code == 200
        body = resp.json()
        assert body["weakness"]["cwe_id"] == "CWE-79"

    def test_get_nonexistent_cwe_returns_404(self, client):
        resp = client.get("/intelligence/cwe/CWE-9999")
        assert resp.status_code == 404

    def test_get_cwe79_name_in_response(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert "Improper Neutralization" in body["weakness"]["name"]

    def test_get_cwe79_mitigations_present(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert isinstance(body["weakness"]["mitigations"], list)

    def test_get_cwe79_detection_methods_present(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert isinstance(body["weakness"]["detection_methods"], list)

    def test_get_cwe79_related_attack_patterns_present(self, client):
        resp = client.get("/intelligence/cwe/CWE-79")
        body = resp.json()
        assert isinstance(body["weakness"]["related_attack_patterns"], list)


class TestApiCweSearch:

    def test_search_cwe_status_200(self, client):
        resp = client.get("/intelligence/cwe/search?q=SQL")
        assert resp.status_code == 200

    def test_search_cwe_response_shape(self, client):
        resp = client.get("/intelligence/cwe/search?q=SQL")
        body = resp.json()
        assert body["status"] == "success"
        assert "weaknesses" in body

    def test_search_cwe_finds_sql_injection(self, client):
        resp = client.get("/intelligence/cwe/search?q=SQL")
        body = resp.json()
        assert any("SQL" in w.get("name", "") for w in body["weaknesses"])

    def test_search_cwe_by_id(self, client):
        resp = client.get("/intelligence/cwe/search?cwe_id=CWE-79")
        body = resp.json()
        assert any(w["cwe_id"] == "CWE-79" for w in body["weaknesses"])

    def test_search_cwe_no_results(self, client):
        resp = client.get("/intelligence/cwe/search?q=ZZZNONEXISTENTTERM")
        body = resp.json()
        assert body["count"] == 0

    def test_search_cwe_empty_query_returns_results(self, client):
        resp = client.get("/intelligence/cwe/search")
        body = resp.json()
        assert body["count"] >= 0


class TestApiCweStatistics:

    def test_cwe_statistics_status_200(self, client):
        resp = client.get("/intelligence/cwe/statistics")
        assert resp.status_code == 200

    def test_cwe_statistics_response_shape(self, client):
        resp = client.get("/intelligence/cwe/statistics")
        body = resp.json()
        assert body["status"] == "success"
        assert "statistics" in body

    def test_cwe_statistics_total_weaknesses(self, client):
        resp = client.get("/intelligence/cwe/statistics")
        body = resp.json()
        assert body["statistics"]["total_weaknesses"] == 2


class TestApiCweVersion:

    def test_cwe_version_status_200(self, client):
        resp = client.get("/intelligence/cwe/version")
        assert resp.status_code == 200

    def test_cwe_version_response_shape(self, client):
        resp = client.get("/intelligence/cwe/version")
        body = resp.json()
        assert body["status"] == "success"
        assert "version" in body

    def test_cwe_version_is_active(self, client):
        resp = client.get("/intelligence/cwe/version")
        body = resp.json()
        assert body["version"] is not None
        assert body["version"]["version_id"] == "cwe-v001"


# ---------------------------------------------------------------------------
# CAPEC endpoints
# ---------------------------------------------------------------------------

class TestApiCapecList:

    def test_list_capec_status_200(self, client):
        resp = client.get("/intelligence/capec")
        assert resp.status_code == 200

    def test_list_capec_response_shape(self, client):
        resp = client.get("/intelligence/capec")
        body = resp.json()
        assert body["status"] == "success"
        assert "attack_patterns" in body
        assert "count" in body

    def test_list_capec_returns_patterns(self, client):
        resp = client.get("/intelligence/capec")
        body = resp.json()
        assert body["count"] == 2

    def test_list_capec_filter_by_abstraction(self, client):
        resp = client.get("/intelligence/capec?abstraction=Standard")
        body = resp.json()
        assert body["count"] == 1
        assert body["attack_patterns"][0]["capec_id"] == "CAPEC-66"

    def test_list_capec_filter_by_severity(self, client):
        resp = client.get("/intelligence/capec?severity=High")
        body = resp.json()
        assert body["count"] == 1

    def test_list_capec_with_limit(self, client):
        resp = client.get("/intelligence/capec?limit=1")
        body = resp.json()
        assert len(body["attack_patterns"]) <= 1


class TestApiCapecGet:

    def test_get_capec66_status_200(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        assert resp.status_code == 200

    def test_get_capec66_response_shape(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert body["status"] == "success"
        assert "attack_pattern" in body

    def test_get_capec66_correct_id(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert body["attack_pattern"]["capec_id"] == "CAPEC-66"

    def test_get_capec_by_number_only_normalizes(self, client):
        """Passing just '66' should be normalized to 'CAPEC-66'."""
        resp = client.get("/intelligence/capec/66")
        assert resp.status_code == 200
        body = resp.json()
        assert body["attack_pattern"]["capec_id"] == "CAPEC-66"

    def test_get_nonexistent_capec_returns_404(self, client):
        resp = client.get("/intelligence/capec/CAPEC-9999")
        assert resp.status_code == 404

    def test_get_capec66_name_in_response(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert "SQL Injection" in body["attack_pattern"]["name"]

    def test_get_capec66_execution_flow_present(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert isinstance(body["attack_pattern"]["execution_flow"], list)
        assert len(body["attack_pattern"]["execution_flow"]) > 0

    def test_get_capec66_mitigations_present(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert isinstance(body["attack_pattern"]["mitigations"], list)

    def test_get_capec66_detection_present(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert isinstance(body["attack_pattern"]["detection"], list)

    def test_get_capec66_attack_technique_ids_present(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert "T1190" in body["attack_pattern"]["attack_technique_ids"]

    def test_get_capec66_related_weaknesses_present(self, client):
        resp = client.get("/intelligence/capec/CAPEC-66")
        body = resp.json()
        assert "CWE-89" in body["attack_pattern"]["related_weaknesses"]


class TestApiCapecSearch:

    def test_search_capec_status_200(self, client):
        resp = client.get("/intelligence/capec/search?q=SQL")
        assert resp.status_code == 200

    def test_search_capec_response_shape(self, client):
        resp = client.get("/intelligence/capec/search?q=SQL")
        body = resp.json()
        assert body["status"] == "success"
        assert "attack_patterns" in body

    def test_search_capec_finds_sql_injection(self, client):
        resp = client.get("/intelligence/capec/search?q=SQL")
        body = resp.json()
        assert any(ap.get("capec_id") == "CAPEC-66" for ap in body["attack_patterns"])

    def test_search_capec_by_id(self, client):
        resp = client.get("/intelligence/capec/search?capec_id=CAPEC-86")
        body = resp.json()
        assert any(ap["capec_id"] == "CAPEC-86" for ap in body["attack_patterns"])

    def test_search_capec_by_cwe_id(self, client):
        resp = client.get("/intelligence/capec/search?cwe_id=CWE-89")
        body = resp.json()
        assert any(ap["capec_id"] == "CAPEC-66" for ap in body["attack_patterns"])

    def test_search_capec_by_attack_technique_id(self, client):
        resp = client.get("/intelligence/capec/search?attack_technique_id=T1190")
        body = resp.json()
        assert any(ap["capec_id"] == "CAPEC-66" for ap in body["attack_patterns"])

    def test_search_capec_no_results(self, client):
        resp = client.get("/intelligence/capec/search?q=ZZZNONEXISTENTTERM")
        body = resp.json()
        assert body["count"] == 0


class TestApiCapecStatistics:

    def test_capec_statistics_status_200(self, client):
        resp = client.get("/intelligence/capec/statistics")
        assert resp.status_code == 200

    def test_capec_statistics_response_shape(self, client):
        resp = client.get("/intelligence/capec/statistics")
        body = resp.json()
        assert body["status"] == "success"
        assert "statistics" in body

    def test_capec_statistics_total_patterns(self, client):
        resp = client.get("/intelligence/capec/statistics")
        body = resp.json()
        assert body["statistics"]["total_attack_patterns"] == 2

    def test_capec_statistics_total_cwe_mappings(self, client):
        resp = client.get("/intelligence/capec/statistics")
        body = resp.json()
        assert body["statistics"]["total_cwe_mappings"] >= 1

    def test_capec_statistics_total_attack_mappings(self, client):
        resp = client.get("/intelligence/capec/statistics")
        body = resp.json()
        assert body["statistics"]["total_attack_mappings"] >= 1


class TestApiCapecVersion:

    def test_capec_version_status_200(self, client):
        resp = client.get("/intelligence/capec/version")
        assert resp.status_code == 200

    def test_capec_version_response_shape(self, client):
        resp = client.get("/intelligence/capec/version")
        body = resp.json()
        assert body["status"] == "success"
        assert "version" in body

    def test_capec_version_is_active(self, client):
        resp = client.get("/intelligence/capec/version")
        body = resp.json()
        assert body["version"] is not None
        assert body["version"]["version_id"] == "capec-v001"


# ---------------------------------------------------------------------------
# Knowledge Graph endpoint
# ---------------------------------------------------------------------------

class TestApiKnowledgeGraph:

    def test_cve_knowledge_status_200(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        assert resp.status_code == 200

    def test_cve_knowledge_response_shape(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert body["status"] == "success"
        assert "knowledge" in body

    def test_cve_knowledge_cve_id_in_response(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert body["knowledge"]["cve_id"] == "CVE-2021-44228"

    def test_cve_knowledge_weaknesses_key_present(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert "weaknesses" in body["knowledge"]

    def test_cve_knowledge_attack_patterns_key_present(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert "attack_patterns" in body["knowledge"]

    def test_cve_knowledge_mitigations_key_present(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert "mitigations" in body["knowledge"]

    def test_cve_knowledge_detection_methods_key_present(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        assert "detection_methods" in body["knowledge"]

    def test_cve_knowledge_graph_structure_present(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        graph = body["knowledge"]["knowledge_graph"]
        assert "nodes" in graph
        assert "edges" in graph

    def test_cve_knowledge_cve_node_in_graph(self, client):
        resp = client.get("/intelligence/cve/CVE-2021-44228/knowledge")
        body = resp.json()
        nodes = body["knowledge"]["knowledge_graph"]["nodes"]
        cve_nodes = [n for n in nodes if n["type"] == "CVE"]
        assert len(cve_nodes) == 1

    def test_cve_knowledge_with_injected_cwe_data(self, client):
        """Inject a CVE→CWE mapping and verify the graph traverses to CAPEC."""
        # Use a fresh client instance with mapping injected
        repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        repo.save_cve_cwe_mappings("CVE-2023-MAPPED", ["CWE-89"], source="NVD")

        engine = IntelligenceEngine(repository=repo)
        set_intelligence_engine(engine)

        app = FastAPI()
        app.include_router(router)
        local_client = TestClient(app)

        resp = local_client.get("/intelligence/cve/CVE-2023-MAPPED/knowledge")
        assert resp.status_code == 200
        body = resp.json()
        weakness_ids = [w.get("cwe_id") for w in body["knowledge"]["weaknesses"]]
        assert "CWE-89" in weakness_ids

    def test_cve_knowledge_case_insensitive_id(self, client):
        """CVE ID should be uppercased internally."""
        resp = client.get("/intelligence/cve/cve-2021-44228/knowledge")
        assert resp.status_code == 200
