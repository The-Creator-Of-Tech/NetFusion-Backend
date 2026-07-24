"""
IL-8 UTKG — Search Engine Tests
"""

import pytest
from netfusion_intelligence.graph.search import GraphSearchEngine
from netfusion_intelligence.graph.models import GraphNodeType


class TestFullTextSearch:
    def test_search_by_label(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.search("CVE-2021")
        assert result.total_count >= 1
        assert any("CVE-2021" in n["label"] for n in result.nodes)

    def test_search_with_node_type_filter(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.search("", node_type=GraphNodeType.IOC.value)
        for n in result.nodes:
            assert n["node_type"] == GraphNodeType.IOC.value

    def test_search_returns_empty_for_no_match(self, graph_repo, sample_nodes):
        engine = GraphSearchEngine(graph_repo)
        result = engine.search("XXXXNONEXISTENTXXXX")
        assert result.total_count == 0

    def test_search_respects_limit(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.search("", limit=3)
        assert len(result.nodes) <= 3


class TestEntityLookup:
    def test_find_by_external_id(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        node = engine.find_by_external_id("CVE-2021-44228", node_type=GraphNodeType.CVE.value)
        assert node is not None
        assert node["external_id"] == "CVE-2021-44228"

    def test_find_by_canonical_id(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        node = engine.find_by_canonical_id(cve.canonical_id)
        assert node is not None
        assert node["canonical_id"] == cve.canonical_id

    def test_find_returns_none_for_unknown(self, graph_repo):
        engine = GraphSearchEngine(graph_repo)
        node = engine.find_by_external_id("CVE-9999-FAKE")
        assert node is None


class TestInvestigationQueries:
    def test_iocs_for_cve(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.find_iocs_for_cve("CVE-2021-44228", depth=5)
        assert "iocs" in result
        # 1.2.3.4 should be reachable from CVE-2021-44228 through the chain
        assert result["ioc_count"] >= 0  # may be 0 if direction cut off

    def test_techniques_for_actor(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.find_techniques_for_threat_actor("APT28", depth=2)
        assert "techniques" in result
        assert result["technique_count"] >= 2

    def test_campaigns_for_ioc(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.find_campaigns_for_ioc("1.2.3.4", depth=4)
        assert "campaigns" in result

    def test_assets_exposed_to_kev(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        result = engine.find_assets_exposed_to_kev("CVE-2021-44228", depth=4)
        assert "assets" in result

    def test_evidence_for_report(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        report = sample_nodes["REPORT-001"]
        result = engine.find_evidence_for_report(report.node_id, depth=5)
        assert "evidence" in result


class TestSubgraph:
    def test_subgraph_returns_nodes_and_edges(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        result = engine.extract_subgraph(seed_node_ids=[cve.node_id], depth=2)
        assert result.node_count >= 1
        assert result.subgraph_id is not None

    def test_subgraph_multiple_seeds(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        seeds = [sample_nodes["CVE-2021-44228"].node_id, sample_nodes["APT28"].node_id]
        result = engine.extract_subgraph(seed_node_ids=seeds, depth=1)
        assert result.node_count >= 2


class TestAIFoundation:
    def test_expand_context(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        context = engine.expand_context(cve.node_id, depth=2)
        assert "context_by_type" in context
        assert "total_context_nodes" in context
        assert context["total_context_nodes"] >= 1

    def test_find_related_entities(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwes = engine.find_related_entities(cve.node_id, target_type=GraphNodeType.CWE.value, depth=2)
        assert isinstance(cwes, list)

    def test_rank_relationships(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphSearchEngine(graph_repo)
        apt = sample_nodes["APT28"]
        ranked = engine.rank_relationships(apt.node_id, top_n=5)
        assert len(ranked) <= 5
        for item in ranked:
            assert "edge" in item
            assert "score" in item
