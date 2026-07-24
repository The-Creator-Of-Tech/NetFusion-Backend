"""
IL-8 UTKG — Repository Tests
"""

import uuid
import pytest

from netfusion_intelligence.graph.models import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from netfusion_intelligence.graph.tests.conftest import _make_node


class TestNodeUpsert:
    def test_insert_new_node(self, graph_repo):
        node = _make_node(GraphNodeType.CVE.value, "CVE-2024-0001", "CVE-2024-0001")
        saved, created = graph_repo.upsert_node(node)
        assert created is True
        assert saved.node_id == node.node_id
        assert saved.node_type == GraphNodeType.CVE.value

    def test_update_existing_node(self, graph_repo):
        node = _make_node(GraphNodeType.CVE.value, "CVE-2024-0002", "CVE-2024-0002")
        graph_repo.upsert_node(node)
        # Update label
        node.label = "CVE-2024-0002-UPDATED"
        _, created = graph_repo.upsert_node(node)
        assert created is False

    def test_no_duplicate_nodes_same_canonical_and_type(self, graph_repo):
        canonical = str(uuid.uuid4())
        n1 = GraphNode.create(canonical_id=canonical, node_type=GraphNodeType.CVE.value,
                               label="CVE-A", external_id="CVE-A")
        n2 = GraphNode.create(canonical_id=canonical, node_type=GraphNodeType.CVE.value,
                               label="CVE-A-DUP", external_id="CVE-A")
        graph_repo.upsert_node(n1)
        graph_repo.upsert_node(n2)
        assert graph_repo.count_nodes(node_type=GraphNodeType.CVE.value) == 1

    def test_get_node_by_external_id(self, graph_repo):
        node = _make_node(GraphNodeType.CVE.value, "CVE-2024-0099", "CVE-2024-0099")
        graph_repo.upsert_node(node)
        found = graph_repo.get_node_by_external_id("CVE-2024-0099", node_type=GraphNodeType.CVE.value)
        assert found is not None
        assert found.external_id == "CVE-2024-0099"

    def test_bulk_upsert(self, graph_repo):
        nodes = [_make_node(GraphNodeType.IOC.value, f"IOC-{i}", f"IOC-{i}") for i in range(10)]
        result = graph_repo.bulk_upsert_nodes(nodes)
        assert result["inserted"] == 10
        assert result["updated"] == 0

    def test_list_nodes_by_type(self, graph_repo, sample_nodes):
        cves = graph_repo.list_nodes(node_type=GraphNodeType.CVE.value)
        assert len(cves) >= 2
        for n in cves:
            assert n.node_type == GraphNodeType.CVE.value

    def test_search_nodes_by_keyword(self, graph_repo, sample_nodes):
        results = graph_repo.search_nodes(query="CVE-2021")
        assert any("CVE-2021" in n.label for n in results)


class TestEdgeUpsert:
    def test_insert_new_edge(self, graph_repo, sample_nodes):
        src = sample_nodes["CVE-2021-44228"]
        tgt = sample_nodes["CWE-502"]
        edge = GraphEdge.create(
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            source_canonical_id=src.canonical_id,
            target_canonical_id=tgt.canonical_id,
            edge_type=GraphEdgeType.HAS_WEAKNESS.value,
        )
        _, created = graph_repo.upsert_edge(edge)
        assert created is True

    def test_no_duplicate_edges(self, graph_repo, sample_nodes, sample_edges):
        count_before = graph_repo.count_edges()
        # Re-insert the same edges
        from netfusion_intelligence.graph.relationships import GraphRelationshipManager
        rm = GraphRelationshipManager(graph_repo)
        for src, tgt, etype, conf in sample_edges:
            rm.add_relationship(src.node_id, tgt.node_id, etype, confidence=conf)
        count_after = graph_repo.count_edges()
        assert count_after == count_before   # all were updates, not inserts

    def test_get_edges_for_node_outgoing(self, graph_repo, sample_nodes, sample_edges):
        apt28 = sample_nodes["APT28"]
        out_edges = graph_repo.get_edges_for_node(apt28.node_id, direction="out")
        assert len(out_edges) >= 2

    def test_get_edges_for_node_incoming(self, graph_repo, sample_nodes, sample_edges):
        cve = sample_nodes["CVE-2021-44228"]
        in_edges = graph_repo.get_edges_for_node(cve.node_id, direction="in")
        assert len(in_edges) >= 1

    def test_evidence_count_accumulates(self, graph_repo, sample_nodes, sample_edges):
        from netfusion_intelligence.graph.relationships import GraphRelationshipManager
        rm = GraphRelationshipManager(graph_repo)
        src = sample_nodes["1.2.3.4"]
        tgt = sample_nodes["CVE-2021-44228"]
        rm.add_relationship(src.node_id, tgt.node_id, GraphEdgeType.IOC_TO_CVE.value,
                             evidence_count=5)
        rm.add_relationship(src.node_id, tgt.node_id, GraphEdgeType.IOC_TO_CVE.value,
                             evidence_count=3)
        edges = graph_repo.get_edges_for_node(src.node_id, direction="out",
                                               edge_type=GraphEdgeType.IOC_TO_CVE.value)
        assert any(e.evidence_count >= 5 for e in edges)


class TestVersioning:
    def test_create_version(self, graph_repo):
        v = graph_repo.create_version(description="test version")
        assert v.version_number == 1
        assert v.is_active is True

    def test_active_version(self, graph_repo):
        graph_repo.create_version(description="v1")
        graph_repo.create_version(description="v2")
        active = graph_repo.get_active_version()
        assert active is not None
        assert active.version_number == 2

    def test_rollback(self, graph_repo):
        v1 = graph_repo.create_version(description="v1")
        graph_repo.create_version(description="v2")
        success = graph_repo.rollback_to_version(v1.version_id)
        assert success is True
        active = graph_repo.get_active_version()
        assert active.version_id == v1.version_id
