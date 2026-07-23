"""
IL-8 UTKG — Service Integration Tests
End-to-end test of the UnifiedThreatKnowledgeGraph facade.
"""

import pytest
from netfusion_intelligence.graph.models import GraphExportFormat, GraphNodeType


class TestServiceNodeOperations:
    def test_add_and_get_node(self, utkg):
        result = utkg.add_node(
            canonical_id="test-canon-svc-001",
            node_type=GraphNodeType.CVE.value,
            label="CVE-SVC-TEST",
            external_id="CVE-SVC-TEST",
            confidence=0.9,
        )
        assert result["created"] is True
        node_id = result["node"]["node_id"]
        fetched = utkg.get_node(node_id)
        assert fetched is not None
        assert fetched["label"] == "CVE-SVC-TEST"

    def test_get_node_not_found_returns_none(self, utkg):
        result = utkg.get_node("fake-id-000")
        assert result is None

    def test_get_node_neighbors(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        result = utkg.get_node_neighbors(cve.node_id)
        assert result["neighbor_count"] >= 1

    def test_add_node_idempotent(self, utkg):
        utkg.add_node(canonical_id="idem-001", node_type="cve", label="CVE-IDEM")
        result = utkg.add_node(canonical_id="idem-001", node_type="cve", label="CVE-IDEM-UPD")
        assert result["created"] is False


class TestServiceTraversal:
    def test_bfs_traversal(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        result = utkg.traverse(cve.node_id, algorithm="bfs", max_depth=2)
        assert "node_count" in result
        assert result["node_count"] >= 1

    def test_dfs_traversal(self, utkg, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        result = utkg.traverse(apt.node_id, algorithm="dfs", max_depth=2)
        assert "node_count" in result

    def test_can_reach_connected(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        assert utkg.can_reach(cve.node_id, cwe.node_id, max_depth=2)

    def test_cycle_detection(self, utkg, sample_nodes):
        cve = sample_nodes["CVE-2021-44228"]
        result = utkg.detect_cycle(cve.node_id)
        assert isinstance(result, bool)


class TestServicePathFinding:
    def test_shortest_path_found(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path = utkg.find_path(cve.node_id, cwe.node_id)
        assert path is not None
        assert path["length"] == 1

    def test_dijkstra_path(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path = utkg.find_path(cve.node_id, cwe.node_id, algorithm="dijkstra")
        assert path is not None

    def test_attack_chain(self, utkg, sample_nodes, sample_edges):
        inv = sample_nodes["INV-001"]
        chain = utkg.reconstruct_attack_chain(inv.node_id, max_depth=5)
        assert "attack_chain" in chain
        assert "total_nodes" in chain


class TestServiceSearch:
    def test_search_finds_nodes(self, utkg, sample_nodes, sample_edges):
        result = utkg.search_graph("CVE")
        assert result["total_count"] >= 2

    def test_iocs_for_cve(self, utkg, sample_nodes, sample_edges):
        result = utkg.iocs_for_cve("CVE-2021-44228")
        assert "iocs" in result

    def test_techniques_for_actor(self, utkg, sample_nodes, sample_edges):
        result = utkg.techniques_for_actor("APT28")
        assert "techniques" in result
        assert result["technique_count"] >= 2

    def test_campaigns_for_ioc(self, utkg, sample_nodes, sample_edges):
        result = utkg.campaigns_for_ioc("1.2.3.4")
        assert "campaigns" in result

    def test_assets_exposed_to_kev(self, utkg, sample_nodes, sample_edges):
        result = utkg.assets_exposed_to_kev("CVE-2021-44228")
        assert "assets" in result

    def test_investigations_for_ioc(self, utkg, sample_nodes, sample_edges):
        result = utkg.investigations_for_ioc("1.2.3.4")
        assert "investigations" in result

    def test_evidence_for_report(self, utkg, sample_nodes, sample_edges):
        report = sample_nodes["REPORT-001"]
        result = utkg.evidence_for_report(report.node_id)
        assert "evidence" in result


class TestServiceSubgraph:
    def test_subgraph_by_center(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        result = utkg.get_subgraph(center_node_id=cve.node_id, depth=2)
        assert "node_count" in result
        assert result["node_count"] >= 1

    def test_subgraph_by_ids(self, utkg, sample_nodes, sample_edges):
        ids = [sample_nodes["CVE-2021-44228"].node_id, sample_nodes["APT28"].node_id]
        result = utkg.get_subgraph(node_ids=ids, depth=1)
        assert result["node_count"] >= 2


class TestServiceStatistics:
    def test_get_statistics(self, utkg, sample_nodes, sample_edges):
        stats = utkg.get_statistics(recompute=True)
        assert stats["node_count"] == len(sample_nodes)
        assert stats["edge_count"] == len(sample_edges)

    def test_statistics_cached(self, utkg, sample_nodes, sample_edges):
        utkg.get_statistics(recompute=True)
        stats2 = utkg.get_statistics(recompute=False)
        assert stats2["node_count"] == len(sample_nodes)


class TestServiceExport:
    def test_json_export(self, utkg, sample_nodes, sample_edges):
        result = utkg.export_graph(fmt=GraphExportFormat.JSON.value)
        assert "content" in result
        import json
        data = json.loads(result["content"])
        assert data["graph"]["node_count"] >= 1

    def test_all_formats_export(self, utkg, sample_nodes, sample_edges):
        for fmt in ["json", "graphml", "gexf", "csv", "dot", "mermaid"]:
            result = utkg.export_graph(fmt=fmt)
            assert result["content"] is not None
            assert len(result["content"]) > 0


class TestServiceVisualization:
    def test_cytoscape_visualization(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        result = utkg.build_visualization(
            fmt="cytoscape", center_node_id=cve.node_id, depth=2
        )
        assert result["format"] == "cytoscape"

    def test_all_visualization_formats(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        for fmt in ["cytoscape", "react_flow", "d3", "sigma", "neo4j"]:
            result = utkg.build_visualization(fmt=fmt, center_node_id=cve.node_id)
            assert "format" in result


class TestServiceVersioning:
    def test_create_and_list_versions(self, utkg):
        v = utkg.create_version("test v1")
        versions = utkg.list_versions()
        assert any(ver["version_id"] == v["version_id"] for ver in versions)

    def test_rollback_version(self, utkg):
        v1 = utkg.create_version("v1")
        utkg.create_version("v2")
        ok = utkg.rollback_version(v1["version_id"])
        assert ok is True


class TestServiceAIFoundation:
    def test_expand_context(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        ctx = utkg.expand_context(cve.node_id, depth=2)
        assert "context_by_type" in ctx
        assert ctx["total_context_nodes"] >= 1

    def test_find_related_entities(self, utkg, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        entities = utkg.find_related_entities(cve.node_id, target_type="cwe", depth=2)
        assert isinstance(entities, list)

    def test_rank_relationships(self, utkg, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        ranked = utkg.rank_relationships(apt.node_id, top_n=5)
        assert len(ranked) <= 5
        if len(ranked) > 1:
            # Verify descending score order
            scores = [r["score"] for r in ranked]
            assert scores == sorted(scores, reverse=True)

    def test_confidence_propagation(self, utkg, sample_nodes, sample_edges):
        apt = sample_nodes["APT28"]
        conf_map = utkg.propagate_confidence(apt.node_id, decay=0.8, max_depth=3)
        assert apt.node_id in conf_map
        assert conf_map[apt.node_id] >= 0.0
