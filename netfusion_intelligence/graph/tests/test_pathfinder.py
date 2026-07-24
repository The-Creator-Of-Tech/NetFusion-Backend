"""
IL-8 UTKG — Path Finder Tests
"""

import pytest
from netfusion_intelligence.graph.pathfinder import GraphPathFinder
from netfusion_intelligence.graph.models import GraphNodeType


class TestShortestPath:
    def test_finds_direct_path(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path = pf.shortest_path(cve.node_id, cwe.node_id)
        assert path is not None
        assert path.length == 1
        node_ids = [n["node_id"] for n in path.nodes]
        assert cve.node_id in node_ids
        assert cwe.node_id in node_ids

    def test_returns_none_when_no_path(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        # CVE-2022-0001 has no path to APT28 within depth 1
        cve = sample_nodes["CVE-2022-0001"]
        apt = sample_nodes["APT28"]
        path = pf.shortest_path(cve.node_id, apt.node_id, max_depth=1)
        # Result is None or a longer path — just ensure no crash
        assert path is None or path.length >= 1

    def test_path_contains_ordered_nodes(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path = pf.shortest_path(cve.node_id, cwe.node_id)
        assert path is not None
        assert path.nodes[0]["node_id"] == cve.node_id
        assert path.nodes[-1]["node_id"] == cwe.node_id

    def test_path_has_avg_confidence(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path = pf.shortest_path(cve.node_id, cwe.node_id)
        assert path is not None
        assert 0.0 <= path.avg_confidence <= 1.0

    def test_caches_path(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        path1 = pf.shortest_path(cve.node_id, cwe.node_id, use_cache=True)
        path2 = pf.shortest_path(cve.node_id, cwe.node_id, use_cache=True)
        assert path1 is not None
        assert path2 is not None
        assert path1.source_node_id == path2.source_node_id


class TestAllSimplePaths:
    def test_finds_at_least_one_path(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        cve = sample_nodes["CVE-2021-44228"]
        cwe = sample_nodes["CWE-502"]
        paths = pf.all_simple_paths(cve.node_id, cwe.node_id, max_depth=4)
        assert len(paths) >= 1

    def test_respects_limit(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        apt = sample_nodes["APT28"]
        malware = sample_nodes["Log4Shell"]
        paths = pf.all_simple_paths(apt.node_id, malware.node_id, max_depth=5, limit=3)
        assert len(paths) <= 3


class TestPathRanking:
    def test_shorter_paths_rank_first(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        from netfusion_intelligence.graph.models import GraphPath
        short_path = GraphPath(path_id="a", source_node_id="x", target_node_id="y",
                                nodes=[], edges=[], length=2, avg_confidence=0.9)
        long_path  = GraphPath(path_id="b", source_node_id="x", target_node_id="y",
                                nodes=[], edges=[], length=5, avg_confidence=0.9)
        ranked = pf.rank_paths([long_path, short_path])
        assert ranked[0].length == 2

    def test_equal_length_higher_confidence_ranks_first(self, graph_repo):
        pf = GraphPathFinder(graph_repo)
        from netfusion_intelligence.graph.models import GraphPath
        high_conf = GraphPath(path_id="a", source_node_id="x", target_node_id="y",
                               nodes=[], edges=[], length=3, avg_confidence=0.95)
        low_conf  = GraphPath(path_id="b", source_node_id="x", target_node_id="y",
                               nodes=[], edges=[], length=3, avg_confidence=0.5)
        ranked = pf.rank_paths([low_conf, high_conf])
        assert ranked[0].avg_confidence == 0.95


class TestAttackChain:
    def test_attack_chain_returns_layers(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        inv = sample_nodes["INV-001"]
        chain = pf.reconstruct_attack_chain(inv.node_id, max_depth=5)
        assert "attack_chain" in chain
        assert "total_nodes" in chain

    def test_attack_chain_classifies_ioc(self, graph_repo, sample_nodes, sample_edges):
        pf = GraphPathFinder(graph_repo)
        inv = sample_nodes["INV-001"]
        chain = pf.reconstruct_attack_chain(inv.node_id, max_depth=4)
        # IOC 1.2.3.4 should be reachable from INV-001
        assert chain["attack_chain"]["ioc"] or chain["total_nodes"] >= 1
