"""
IL-8 UTKG — Rollback & Versioning Tests
"""

import pytest
from netfusion_intelligence.graph.models import GraphNodeType
from netfusion_intelligence.graph.tests.conftest import _make_node


class TestRollback:
    def test_rollback_activates_old_version(self, graph_repo):
        v1 = graph_repo.create_version(description="v1")
        v2 = graph_repo.create_version(description="v2")
        # v2 is now active
        assert graph_repo.get_active_version().version_id == v2.version_id
        # rollback to v1
        ok = graph_repo.rollback_to_version(v1.version_id)
        assert ok is True
        assert graph_repo.get_active_version().version_id == v1.version_id

    def test_rollback_deactivates_current(self, graph_repo):
        v1 = graph_repo.create_version("v1")
        graph_repo.create_version("v2")
        graph_repo.rollback_to_version(v1.version_id)
        versions = graph_repo.list_versions()
        active = [v for v in versions if v.is_active]
        assert len(active) == 1
        assert active[0].version_id == v1.version_id

    def test_rollback_nonexistent_version_returns_false(self, graph_repo):
        result = graph_repo.rollback_to_version("00000000-fake-0000-0000-000000000000")
        assert result is False

    def test_version_list_ordered_descending(self, graph_repo):
        graph_repo.create_version("v1")
        graph_repo.create_version("v2")
        graph_repo.create_version("v3")
        versions = graph_repo.list_versions()
        numbers = [v.version_number for v in versions]
        assert numbers == sorted(numbers, reverse=True)

    def test_multiple_rollbacks(self, graph_repo):
        v1 = graph_repo.create_version("v1")
        v2 = graph_repo.create_version("v2")
        v3 = graph_repo.create_version("v3")
        graph_repo.rollback_to_version(v1.version_id)
        assert graph_repo.get_active_version().version_id == v1.version_id
        graph_repo.rollback_to_version(v3.version_id)
        assert graph_repo.get_active_version().version_id == v3.version_id


class TestIncrementalUpdates:
    def test_node_version_increments_on_update(self, graph_repo):
        node = _make_node(GraphNodeType.CVE.value, "CVE-INC-001", "CVE-INC-001")
        saved, _ = graph_repo.upsert_node(node)
        assert saved.version == 1
        saved.label = "CVE-INC-001-UPDATED"
        saved2, _ = graph_repo.upsert_node(saved)
        assert saved2.version == 2

    def test_edge_version_increments_on_update(self, graph_repo, sample_nodes, sample_edges):
        from netfusion_intelligence.graph.relationships import GraphRelationshipManager
        rm = GraphRelationshipManager(graph_repo)
        src = sample_nodes["CVE-2021-44228"]
        tgt = sample_nodes["CWE-502"]
        # Add initial edge
        e1, _ = rm.add_relationship(src.node_id, tgt.node_id, "RELATED_TO", confidence=0.5)
        assert e1.version >= 1
        # Update same edge
        e2, created = rm.add_relationship(src.node_id, tgt.node_id, "RELATED_TO", confidence=0.9)
        assert created is False
        assert e2.version >= e1.version

    def test_bulk_upsert_does_not_duplicate(self, graph_repo):
        nodes = [_make_node(GraphNodeType.HASH.value, f"SHA256-{i}", f"SHA256-{i}")
                 for i in range(5)]
        graph_repo.bulk_upsert_nodes(nodes)
        count1 = graph_repo.count_nodes(node_type=GraphNodeType.HASH.value)
        # Insert same nodes again
        graph_repo.bulk_upsert_nodes(nodes)
        count2 = graph_repo.count_nodes(node_type=GraphNodeType.HASH.value)
        assert count1 == count2

    def test_evidence_count_accumulates_across_updates(self, graph_repo, sample_nodes, sample_edges):
        from netfusion_intelligence.graph.relationships import GraphRelationshipManager
        rm = GraphRelationshipManager(graph_repo)
        src = sample_nodes["Log4Shell"]
        tgt = sample_nodes["1.2.3.4"]
        rm.add_relationship(src.node_id, tgt.node_id, "COMMUNICATES_WITH",
                             evidence_count=3)
        rm.add_relationship(src.node_id, tgt.node_id, "COMMUNICATES_WITH",
                             evidence_count=7)
        edges = graph_repo.get_edges_for_node(src.node_id, direction="out",
                                               edge_type="COMMUNICATES_WITH")
        comm_edges = [e for e in edges if e.target_node_id == tgt.node_id]
        assert any(e.evidence_count >= 7 for e in comm_edges)
