"""
IL-8 UTKG — REST API Tests
Uses FastAPI TestClient with an isolated in-memory graph.
"""

import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netfusion_intelligence.graph.api import router as graph_router, set_utkg
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_app(graph_repo, sample_nodes, sample_edges):
    """Create isolated FastAPI app wired to the test graph repo."""
    app = FastAPI()
    utkg = UnifiedThreatKnowledgeGraph(graph_repository=graph_repo)
    set_utkg(utkg)

    # Patch the module-level getter to always return our test instance
    import netfusion_intelligence.graph.api as api_mod
    api_mod.get_utkg = lambda: utkg

    app.include_router(graph_router)
    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


# ---------------------------------------------------------------------------
# Node endpoints
# ---------------------------------------------------------------------------

class TestNodeEndpoints:
    def test_get_node_success(self, client, sample_nodes):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(f"/graph/node/{cve.node_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["node"]["node_id"] == cve.node_id

    def test_get_node_not_found(self, client):
        resp = client.get("/graph/node/nonexistent-uuid-000")
        assert resp.status_code == 404

    def test_get_neighbors(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(f"/graph/node/{cve.node_id}/neighbors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "neighbors" in data
        assert data["neighbor_count"] >= 1

    def test_add_node(self, client):
        payload = {
            "canonical_id": "test-canonical-001",
            "node_type": "cve",
            "label": "CVE-2099-FAKE",
            "external_id": "CVE-2099-FAKE",
            "source_feed": "test",
            "confidence": 0.8,
        }
        resp = client.post("/graph/nodes", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["created"] is True

    def test_add_node_duplicate(self, client, sample_nodes):
        cve = sample_nodes["CVE-2021-44228"]
        payload = {
            "canonical_id": cve.canonical_id,
            "node_type": cve.node_type,
            "label": cve.label,
        }
        resp = client.post("/graph/nodes", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is False   # upsert — not a new node


# ---------------------------------------------------------------------------
# Edge endpoints
# ---------------------------------------------------------------------------

class TestEdgeEndpoints:
    def test_add_edge(self, client, sample_nodes):
        src = sample_nodes["CVE-2021-44228"]
        tgt = sample_nodes["KEV:CVE-2021-44228"]
        payload = {
            "source_node_id": src.node_id,
            "target_node_id": tgt.node_id,
            "edge_type": "LINKED_TO",
            "confidence": 1.0,
            "weight": 1.0,
        }
        resp = client.post("/graph/edges", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "edge" in data


# ---------------------------------------------------------------------------
# Path endpoint
# ---------------------------------------------------------------------------

class TestPathEndpoints:
    def test_path_found(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        resp = client.get(f"/graph/path?source={cve.node_id}&target={cwe.node_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["path"] is not None

    def test_path_not_found_returns_null(self, client, sample_nodes):
        cve = sample_nodes["CVE-2021-44228"]
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/graph/path?source={cve.node_id}&target={fake_id}&max_depth=1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["path"] is None

    def test_shortest_path_query(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        resp = client.get(
            f"/graph/query/shortest-path?source={cve.node_id}&target={cwe.node_id}"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "path" in data


# ---------------------------------------------------------------------------
# Search endpoint
# ---------------------------------------------------------------------------

class TestSearchEndpoints:
    def test_search_returns_results(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/search?q=CVE-2021")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_count"] >= 1

    def test_search_empty_query_returns_nodes(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/search?q=&limit=5")
        assert resp.status_code == 200

    def test_search_with_type_filter(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/search?q=&node_type=cve")
        assert resp.status_code == 200
        data = resp.json()
        for n in data["nodes"]:
            assert n["node_type"] == "cve"


# ---------------------------------------------------------------------------
# Traversal endpoint
# ---------------------------------------------------------------------------

class TestTraversalEndpoints:
    def test_bfs_traversal(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(
            f"/graph/traverse?node_id={cve.node_id}&algorithm=bfs&max_depth=2"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["traversal"]["node_count"] >= 1

    def test_dfs_traversal(self, client, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        resp = client.get(
            f"/graph/traverse?node_id={apt.node_id}&algorithm=dfs&max_depth=2"
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Subgraph endpoint
# ---------------------------------------------------------------------------

class TestSubgraphEndpoints:
    def test_subgraph_by_center(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(f"/graph/subgraph?center_node_id={cve.node_id}&depth=2")
        assert resp.status_code == 200
        data = resp.json()
        assert "subgraph" in data
        assert data["subgraph"]["node_count"] >= 1

    def test_subgraph_by_node_ids(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        ids = f"{cve.node_id},{cwe.node_id}"
        resp = client.get(f"/graph/subgraph?node_ids={ids}&depth=1")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Statistics endpoint
# ---------------------------------------------------------------------------

class TestStatisticsEndpoints:
    def test_statistics_returns_counts(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/statistics?recompute=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["statistics"]["node_count"] == len(sample_nodes)
        assert data["statistics"]["edge_count"] == len(sample_edges)

    def test_node_breakdown(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/statistics/nodes")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_type" in data["breakdown"]

    def test_edge_breakdown(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/statistics/edges")
        assert resp.status_code == 200

    def test_hub_nodes(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/statistics/hub-nodes?top_n=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["hub_nodes"]) <= 5


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------

class TestExportEndpoints:
    def test_json_export(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/export?fmt=json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["record"]["format"] == "json"
        assert "content" in data

    def test_graphml_export(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/export?fmt=graphml")
        assert resp.status_code == 200
        data = resp.json()
        assert "<graphml" in data["content"]

    def test_csv_export(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/export?fmt=csv")
        assert resp.status_code == 200

    def test_dot_export(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/export?fmt=dot")
        assert resp.status_code == 200
        data = resp.json()
        assert "digraph" in data["content"]

    def test_mermaid_export(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/export?fmt=mermaid")
        assert resp.status_code == 200
        data = resp.json()
        assert "graph LR" in data["content"]


# ---------------------------------------------------------------------------
# Visualization endpoint
# ---------------------------------------------------------------------------

class TestVisualizationEndpoints:
    def test_cytoscape_visualization(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(
            f"/graph/visualization?fmt=cytoscape&center_node_id={cve.node_id}&depth=2"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["visualization"]["format"] == "cytoscape"

    def test_react_flow_visualization(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(
            f"/graph/visualization?fmt=react_flow&center_node_id={cve.node_id}"
        )
        assert resp.status_code == 200

    def test_d3_visualization(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/visualization?fmt=d3")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Version endpoints
# ---------------------------------------------------------------------------

class TestVersionEndpoints:
    def test_list_versions(self, client):
        resp = client.get("/graph/versions")
        assert resp.status_code == 200
        data = resp.json()
        assert "versions" in data

    def test_create_version(self, client):
        resp = client.post("/graph/versions", json="test version")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data

    def test_rollback_version(self, client):
        # Create two versions then rollback
        v1 = client.post("/graph/versions", json="v1").json()["version"]
        client.post("/graph/versions", json="v2")
        resp = client.post(f"/graph/versions/{v1['version_id']}/rollback")
        assert resp.status_code == 200

    def test_rollback_nonexistent(self, client):
        resp = client.post("/graph/versions/00000000-fake/rollback")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Investigation Query endpoints
# ---------------------------------------------------------------------------

class TestInvestigationEndpoints:
    def test_iocs_for_cve(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/query/iocs-for-cve/CVE-2021-44228")
        assert resp.status_code == 200
        data = resp.json()
        assert "iocs" in data

    def test_techniques_for_actor(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/query/techniques-for-actor/APT28")
        assert resp.status_code == 200
        data = resp.json()
        assert "techniques" in data

    def test_campaigns_for_ioc(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/query/campaigns-for-ioc?ioc_value=1.2.3.4")
        assert resp.status_code == 200

    def test_assets_exposed_to_kev(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/query/assets-exposed-to-kev/CVE-2021-44228")
        assert resp.status_code == 200

    def test_investigations_for_ioc(self, client, sample_nodes, sample_edges):
        resp = client.get("/graph/query/investigations-for-ioc?ioc_value=1.2.3.4")
        assert resp.status_code == 200

    def test_evidence_for_report(self, client, sample_nodes, sample_edges):
        report = sample_nodes["REPORT-001"]
        resp = client.get(f"/graph/query/evidence-for-report/{report.node_id}")
        assert resp.status_code == 200

    def test_attack_chain(self, client, sample_nodes, sample_edges):
        inv = sample_nodes["INV-001"]
        resp = client.get(f"/graph/query/attack-chain/{inv.node_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "attack_chain" in data


# ---------------------------------------------------------------------------
# AI Foundation endpoints
# ---------------------------------------------------------------------------

class TestAIEndpoints:
    def test_expand_context(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(f"/graph/ai/expand-context/{cve.node_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "context" in data
        assert "context_by_type" in data["context"]

    def test_related_entities(self, client, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        resp = client.get(
            f"/graph/ai/related-entities/{cve.node_id}?target_type=cwe"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "entities" in data

    def test_rank_relationships(self, client, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        resp = client.get(f"/graph/ai/rank-relationships/{apt.node_id}?top_n=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "ranked_relationships" in data
        assert len(data["ranked_relationships"]) <= 5

    def test_confidence_propagation(self, client, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        resp = client.get(f"/graph/ai/confidence-propagation/{apt.node_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "confidence_map" in data
        assert apt.node_id in data["confidence_map"]
