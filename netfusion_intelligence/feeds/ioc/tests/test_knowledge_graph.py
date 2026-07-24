"""
Tests for IL-7 Knowledge Graph IOC integration.
Verifies IOC → ATT&CK, CAPEC, CWE, CVE graph traversal.
"""

import uuid
import pytest
from netfusion_intelligence.feeds.ioc.repository import IocRepository
from netfusion_intelligence.feeds.ioc.models import IocEntity
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.services.knowledge_graph import KnowledgeGraphService


VID = "kg-test-v1"


def _ent(**kwargs) -> IocEntity:
    defaults = dict(
        ioc_id=str(uuid.uuid4()), ioc_type="ipv4", value="10.0.0.99",
        confidence=0.85, severity="high", source_count=1,
    )
    defaults.update(kwargs)
    return IocEntity(**defaults)


@pytest.fixture
def repo_with_ioc():
    raw = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    ioc_repo = IocRepository(raw)
    ent = _ent(
        attack_technique_ids=("T1059",),
        capec_ids=("CAPEC-66",),
        cwe_ids=("CWE-79",),
        cve_ids=("CVE-2021-44228",),
        malware_families=("Emotet",),
        campaigns=("PhishWave",),
    )
    ioc_repo.store_indicators(VID, [ent])
    # Activate version so knowledge graph can resolve it
    from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
    from datetime import datetime, timezone
    dv = DatasetVersion(
        feed_id="netfusion_ioc_v1", version_id=VID,
        checksum="kg-test", imported_at=datetime.now(timezone.utc).isoformat(),
        status=DatasetStatus.ACTIVE, validation_status=ValidationStatus.PASSED,
    )
    raw.save_dataset_version(dv)
    raw.set_active_dataset_version("netfusion_ioc_v1", VID)
    return raw, ent


class TestIocKnowledgeGraph:

    def test_get_ioc_knowledge_returns_indicator(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        assert knowledge["ioc_id"] == ent.ioc_id
        assert knowledge["indicator"] is not None
        assert knowledge["indicator"]["ioc_type"] == "ipv4"

    def test_knowledge_graph_has_nodes(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        graph = knowledge["knowledge_graph"]
        assert len(graph["nodes"]) >= 1
        node_ids = {n["id"] for n in graph["nodes"]}
        assert ent.ioc_id in node_ids

    def test_knowledge_graph_malware_nodes(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        node_ids = {n["id"] for n in knowledge["knowledge_graph"]["nodes"]}
        assert "Emotet" in node_ids

    def test_knowledge_graph_campaign_nodes(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        node_ids = {n["id"] for n in knowledge["knowledge_graph"]["nodes"]}
        assert "PhishWave" in node_ids

    def test_knowledge_graph_edges_present(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        edges = knowledge["knowledge_graph"]["edges"]
        assert len(edges) >= 2  # malware + campaign at minimum

    def test_nonexistent_ioc_returns_empty_knowledge(self, repo_with_ioc):
        raw, _ = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge("nonexistent-ioc-id")
        assert knowledge["indicator"] is None
        assert knowledge["attack_techniques"] == []
        assert knowledge["knowledge_graph"]["nodes"] == []

    def test_get_iocs_for_malware(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        results = kg.get_iocs_for_malware("Emotet")
        assert len(results) >= 1
        assert any(r["ioc_id"] == ent.ioc_id for r in results)

    def test_get_iocs_for_technique(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        results = kg.get_iocs_for_technique("T1059")
        assert len(results) >= 1

    def test_sightings_empty_by_default(self, repo_with_ioc):
        raw, ent = repo_with_ioc
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        assert knowledge["sightings"] == []

    def test_relationships_populated_after_build(self, repo_with_ioc):
        """After storing correlation relationships, they should appear in knowledge."""
        raw, ent = repo_with_ioc
        from netfusion_intelligence.feeds.ioc.models import IocRelationship
        from netfusion_intelligence.feeds.ioc.repository import IocRepository
        ioc_repo = IocRepository(raw)
        rel = IocRelationship.create(
            source_ioc_id=ent.ioc_id,
            target_id="T1059",
            target_type="attack_technique",
            relationship_type="ioc_to_attack_technique",
            confidence=0.9,
        )
        ioc_repo.store_relationships(VID, [rel])
        kg = KnowledgeGraphService(raw)
        knowledge = kg.get_ioc_knowledge(ent.ioc_id)
        assert len(knowledge["relationships"]) >= 1
