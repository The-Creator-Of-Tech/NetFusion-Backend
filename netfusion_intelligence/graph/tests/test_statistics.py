"""
IL-8 UTKG — Statistics Engine Tests
"""

import pytest
from netfusion_intelligence.graph.statistics import GraphStatisticsEngine


class TestStatisticsComputation:
    def test_node_count_correct(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert stats.node_count == len(sample_nodes)

    def test_edge_count_positive(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert stats.edge_count == len(sample_edges)

    def test_node_types_populated(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert len(stats.node_types) >= 3
        assert "cve" in stats.node_types

    def test_edge_types_populated(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert len(stats.edge_types) >= 1

    def test_density_between_0_and_1(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert 0.0 <= stats.relationship_density <= 1.0

    def test_average_degree_positive(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert stats.average_degree >= 0.0

    def test_persists_to_db(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        engine.compute_statistics(persist=True)
        retrieved = engine.get_current_statistics()
        assert retrieved is not None
        assert retrieved.node_count == len(sample_nodes)

    def test_get_or_compute_returns_stats(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.get_or_compute_statistics()
        assert stats.node_count > 0

    def test_to_dict_serializable(self, graph_repo, sample_nodes, sample_edges):
        import json
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        d = stats.to_dict()
        # Should be JSON-serializable
        json.dumps(d)

    def test_connected_components_at_least_1(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert stats.connected_components_count >= 1

    def test_largest_component_gte_1(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        stats = engine.compute_statistics(persist=False)
        assert stats.largest_component_size >= 1


class TestTypeBreakdowns:
    def test_node_type_breakdown_has_percentages(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        breakdown = engine.get_node_type_breakdown()
        assert "total" in breakdown
        assert "percentages" in breakdown
        assert breakdown["total"] == len(sample_nodes)

    def test_edge_type_breakdown_correct_total(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        breakdown = engine.get_edge_type_breakdown()
        assert breakdown["total"] == len(sample_edges)

    def test_high_degree_nodes_returns_list(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        hub_nodes = engine.get_high_degree_nodes(top_n=5)
        assert len(hub_nodes) <= 5
        for item in hub_nodes:
            assert "degree" in item
            assert "node" in item

    def test_feed_contribution_summary(self, graph_repo, sample_nodes, sample_edges):
        engine = GraphStatisticsEngine(graph_repo)
        summary = engine.get_feed_contribution_summary()
        assert "by_feed" in summary
        assert "test" in summary["by_feed"]
