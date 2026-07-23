"""
IL-8 UTKG — Export Service Tests
"""

import json
import pytest
from netfusion_intelligence.graph.export import GraphExportService
from netfusion_intelligence.graph.models import GraphExportFormat


class TestJsonExport:
    def test_json_export_valid(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.JSON.value)
        assert record.content is not None
        data = json.loads(record.content)
        assert "graph" in data
        assert data["graph"]["node_count"] == len(sample_nodes)

    def test_json_export_has_nodes_and_edges(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.JSON.value)
        data = json.loads(record.content)
        assert len(data["graph"]["nodes"]) >= 1
        assert len(data["graph"]["edges"]) >= 1

    def test_json_export_record_persisted(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.JSON.value)
        exports = graph_repo.list_exports()
        assert any(e["export_id"] == record.export_id for e in exports)


class TestGraphMLExport:
    def test_graphml_has_xml_header(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.GRAPHML.value)
        assert record.content.startswith("<?xml")
        assert "<graphml" in record.content

    def test_graphml_contains_nodes(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.GRAPHML.value)
        assert "<node" in record.content

    def test_graphml_contains_edges(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.GRAPHML.value)
        assert "<edge" in record.content


class TestGEXFExport:
    def test_gexf_has_gexf_tag(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.GEXF.value)
        assert "<gexf" in record.content
        assert "<nodes>" in record.content


class TestCSVExport:
    def test_csv_has_headers(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.CSV.value)
        assert "node_id" in record.content
        assert "edge_id" in record.content

    def test_csv_node_and_edge_sections(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.CSV.value)
        assert "# NODES" in record.content
        assert "# EDGES" in record.content


class TestDOTExport:
    def test_dot_has_digraph(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.DOT.value)
        assert "digraph UTKG" in record.content

    def test_dot_has_arrows(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.DOT.value)
        assert "->" in record.content


class TestMermaidExport:
    def test_mermaid_has_graph_lr(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.MERMAID.value)
        assert "graph LR" in record.content

    def test_mermaid_has_arrows(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.MERMAID.value)
        assert "-->" in record.content


class TestFilteredExport:
    def test_export_by_node_type(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        record = svc.export(fmt=GraphExportFormat.JSON.value, node_type="cve")
        data = json.loads(record.content)
        for n in data["graph"]["nodes"]:
            assert n["node_type"] == "cve"

    def test_export_by_node_ids(self, graph_repo, sample_nodes, sample_edges):
        svc = GraphExportService(graph_repo)
        ids = [sample_nodes["CVE-2021-44228"].node_id, sample_nodes["CWE-502"].node_id]
        record = svc.export(fmt=GraphExportFormat.JSON.value, node_ids=ids)
        data = json.loads(record.content)
        assert data["graph"]["node_count"] == 2
