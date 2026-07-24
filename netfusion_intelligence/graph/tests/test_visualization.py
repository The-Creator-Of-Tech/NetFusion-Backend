"""
IL-8 UTKG — Visualization Builder Tests
"""

import pytest
from netfusion_intelligence.graph.visualization import GraphVisualizationBuilder


class TestCytoscape:
    def test_returns_cytoscape_format(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_cytoscape(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=2
        )
        assert result["format"] == "cytoscape"
        assert "elements" in result
        assert "nodes" in result["elements"]
        assert "edges" in result["elements"]

    def test_contains_data_and_style(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_cytoscape(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=1
        )
        for n in result["elements"]["nodes"]:
            assert "data" in n
            assert "style" in n
            assert "id" in n["data"]
            assert "label" in n["data"]

    def test_edges_have_source_and_target(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_cytoscape(
            center_node_id=sample_nodes["APT28"].node_id, depth=1
        )
        for e in result["elements"]["edges"]:
            assert "source" in e["data"]
            assert "target" in e["data"]

    def test_node_count_matches(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_cytoscape(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=2
        )
        assert result["node_count"] == len(result["elements"]["nodes"])

    def test_no_center_returns_all_nodes(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_cytoscape(max_nodes=50)
        assert result["node_count"] >= 1


class TestReactFlow:
    def test_returns_react_flow_format(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_react_flow(
            center_node_id=sample_nodes["APT28"].node_id, depth=2
        )
        assert result["format"] == "react_flow"
        assert "nodes" in result
        assert "edges" in result

    def test_react_flow_nodes_have_position(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_react_flow(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=1
        )
        for n in result["nodes"]:
            assert "position" in n
            assert "x" in n["position"]
            assert "y" in n["position"]

    def test_react_flow_edges_have_label(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_react_flow(
            center_node_id=sample_nodes["APT28"].node_id, depth=1
        )
        for e in result["edges"]:
            assert "label" in e


class TestD3Force:
    def test_returns_d3_format(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_d3_force(
            center_node_id=sample_nodes["Log4Shell"].node_id, depth=2
        )
        assert result["format"] == "d3_force"
        assert "nodes" in result
        assert "links" in result

    def test_d3_nodes_have_group_and_color(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_d3_force(
            center_node_id=sample_nodes["Log4Shell"].node_id, depth=1
        )
        for n in result["nodes"]:
            assert "group" in n
            assert "color" in n

    def test_d3_links_have_source_and_target(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_d3_force(
            center_node_id=sample_nodes["APT28"].node_id, depth=1
        )
        for lnk in result["links"]:
            assert "source" in lnk
            assert "target" in lnk


class TestSigma:
    def test_returns_sigma_format(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_sigma(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=2
        )
        assert result["format"] == "sigma"

    def test_sigma_nodes_have_xy(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_sigma(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=1
        )
        for n in result["nodes"]:
            assert "x" in n
            assert "y" in n


class TestNeo4jBrowser:
    def test_returns_neo4j_format(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_neo4j_browser(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=2
        )
        assert result["format"] == "neo4j_browser"

    def test_cypher_create_has_merge(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_neo4j_browser(
            center_node_id=sample_nodes["CVE-2021-44228"].node_id, depth=1
        )
        assert "MERGE" in result["cypher_create"]

    def test_neo4j_node_list_non_empty(self, graph_repo, sample_nodes, sample_edges):
        builder = GraphVisualizationBuilder(graph_repo)
        result = builder.build_neo4j_browser(
            center_node_id=sample_nodes["APT28"].node_id, depth=2
        )
        assert result["node_count"] >= 1
