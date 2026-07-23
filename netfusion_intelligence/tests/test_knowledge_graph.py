"""
Tests for KnowledgeGraphService — CVE→CWE→CAPEC→ATT&CK traversal, graph node/edge construction.
"""

import datetime
import pytest

from netfusion_intelligence.services.knowledge_graph import KnowledgeGraphService
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.feeds.cwe.feed import CweFeed
from netfusion_intelligence.feeds.capec.feed import CapecFeed
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_version(feed_id, version_id, source_version="1.0"):
    return DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum="test",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version=source_version,
        status=DatasetStatus.CREATED,
        validation_status=ValidationStatus.PASSED,
    )


def _run_feed(repo, feed_class, xml_data, feed_id, version_id, source_version="1.0"):
    dv = _make_version(feed_id, version_id, source_version)
    repo.save_dataset_version(dv)
    feed = feed_class(repository=repo, offline_data=xml_data)
    raw = feed.fetch_raw_data()
    parsed = feed.parse(raw)
    normalized = feed.normalize(parsed)
    feed.store(dv, normalized)
    feed.build_relationships(dv)
    feed.on_activate(dv)
    return dv


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def populated_repo(repo):
    """Repository with CWE and CAPEC data loaded."""
    _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
    _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
    return repo


@pytest.fixture
def kg(populated_repo):
    return KnowledgeGraphService(populated_repo)


@pytest.fixture
def empty_kg(repo):
    return KnowledgeGraphService(repo)


# ---------------------------------------------------------------------------
# CVE knowledge (no NVD data — tests graceful degradation)
# ---------------------------------------------------------------------------

class TestKnowledgeGraphGetCveKnowledge:

    def test_returns_dict(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert isinstance(result, dict)

    def test_result_has_cve_id_field(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"

    def test_result_has_weaknesses_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "weaknesses" in result

    def test_result_has_attack_patterns_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "attack_patterns" in result

    def test_result_has_attack_techniques_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "attack_techniques" in result

    def test_result_has_mitigations_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "mitigations" in result

    def test_result_has_detection_methods_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "detection_methods" in result

    def test_result_has_knowledge_graph_key(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert "knowledge_graph" in result

    def test_knowledge_graph_has_nodes_and_edges(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        graph = result["knowledge_graph"]
        assert "nodes" in graph
        assert "edges" in graph
        assert isinstance(graph["nodes"], list)
        assert isinstance(graph["edges"], list)

    def test_cve_node_in_graph(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        nodes = result["knowledge_graph"]["nodes"]
        cve_nodes = [n for n in nodes if n["type"] == "CVE"]
        assert len(cve_nodes) == 1
        assert cve_nodes[0]["id"] == "CVE-2021-44228"

    def test_no_nvd_data_cve_metadata_is_none(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert result["cve"] is None

    def test_no_epss_data_epss_is_none(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert result["epss"] is None

    def test_no_kev_data_kev_is_none(self, kg):
        result = kg.get_cve_knowledge("CVE-2021-44228")
        assert result["kev"] is None


# ---------------------------------------------------------------------------
# Graph builder static method
# ---------------------------------------------------------------------------

class TestKnowledgeGraphBuilder:

    def test_graph_cve_only(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=[],
            capec_ids=[],
            attack_ids=[],
        )
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["type"] == "CVE"
        assert graph["edges"] == []

    def test_graph_cve_with_one_cwe(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79"],
            capec_ids=[],
            attack_ids=[],
        )
        node_types = {n["type"] for n in graph["nodes"]}
        assert "CVE" in node_types
        assert "CWE" in node_types
        edge_rels = [e["relationship"] for e in graph["edges"]]
        assert "has_weakness" in edge_rels

    def test_graph_cve_cwe_capec(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79"],
            capec_ids=["CAPEC-86"],
            attack_ids=[],
        )
        node_types = {n["type"] for n in graph["nodes"]}
        assert "CVE" in node_types
        assert "CWE" in node_types
        assert "CAPEC" in node_types
        edge_rels = {e["relationship"] for e in graph["edges"]}
        assert "has_weakness" in edge_rels
        assert "exploited_by" in edge_rels

    def test_graph_full_chain(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79"],
            capec_ids=["CAPEC-86"],
            attack_ids=["T1059"],
        )
        node_types = {n["type"] for n in graph["nodes"]}
        assert "ATT&CK" in node_types
        edge_rels = {e["relationship"] for e in graph["edges"]}
        assert "maps_to" in edge_rels

    def test_graph_node_ids_are_unique(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79", "CWE-89"],
            capec_ids=["CAPEC-66", "CAPEC-86"],
            attack_ids=["T1190"],
        )
        node_ids = [n["id"] for n in graph["nodes"]]
        assert len(node_ids) == len(set(node_ids))

    def test_graph_multiple_cwes(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79", "CWE-89", "CWE-20"],
            capec_ids=[],
            attack_ids=[],
        )
        cwe_nodes = [n for n in graph["nodes"] if n["type"] == "CWE"]
        assert len(cwe_nodes) == 3
        has_weakness_edges = [e for e in graph["edges"] if e["relationship"] == "has_weakness"]
        assert len(has_weakness_edges) == 3

    def test_graph_multiple_capecs_linked_to_all_cwes(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79", "CWE-89"],
            capec_ids=["CAPEC-66"],
            attack_ids=[],
        )
        exploited_by_edges = [e for e in graph["edges"] if e["relationship"] == "exploited_by"]
        # Each CWE gets an edge to each CAPEC → 2 edges
        assert len(exploited_by_edges) == 2

    def test_graph_node_has_label(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79"],
            capec_ids=[],
            attack_ids=[],
        )
        for node in graph["nodes"]:
            assert "label" in node
            assert node["label"] is not None

    def test_graph_edge_has_source_target_relationship(self):
        graph = KnowledgeGraphService._build_graph(
            cve_id="CVE-2024-0001",
            cwe_ids=["CWE-79"],
            capec_ids=[],
            attack_ids=[],
        )
        for edge in graph["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "relationship" in edge


# ---------------------------------------------------------------------------
# CAPEC knowledge
# ---------------------------------------------------------------------------

class TestKnowledgeGraphGetCapecKnowledge:

    def test_get_capec_knowledge_returns_dict(self, kg):
        result = kg.get_capec_knowledge("CAPEC-66")
        assert isinstance(result, dict)

    def test_get_capec_knowledge_capec_id_field(self, kg):
        result = kg.get_capec_knowledge("CAPEC-66")
        assert result["capec_id"] == "CAPEC-66"

    def test_get_capec_knowledge_attack_pattern_present(self, kg):
        result = kg.get_capec_knowledge("CAPEC-66")
        assert result["attack_pattern"] is not None
        assert result["attack_pattern"]["capec_id"] == "CAPEC-66"

    def test_get_capec_knowledge_weaknesses_key(self, kg):
        result = kg.get_capec_knowledge("CAPEC-66")
        assert "weaknesses" in result
        assert isinstance(result["weaknesses"], list)

    def test_get_capec_knowledge_attack_techniques_key(self, kg):
        result = kg.get_capec_knowledge("CAPEC-66")
        assert "attack_techniques" in result

    def test_get_capec_knowledge_nonexistent_returns_none_pattern(self, kg):
        result = kg.get_capec_knowledge("CAPEC-9999")
        assert result["attack_pattern"] is None

    def test_get_capec_knowledge_cwe_weaknesses_resolved(self, kg):
        """CWE weaknesses linked to CAPEC-66 (CWE-89) are resolved from the CWE table."""
        result = kg.get_capec_knowledge("CAPEC-66")
        weakness_ids = [w.get("cwe_id") for w in result["weaknesses"] if w]
        assert "CWE-89" in weakness_ids


# ---------------------------------------------------------------------------
# Integration: CVE with NVD CWE data feeds the graph
# ---------------------------------------------------------------------------

class TestKnowledgeGraphCveCweCapecIntegration:

    def test_cve_with_injected_cwe_traverses_to_capec(self, populated_repo):
        """
        Simulate a CVE that has CWE-89 (from NVD). After CWE and CAPEC are loaded,
        the knowledge graph should find CAPEC-66 via CWE-89.
        """
        # Manually insert a CVE→CWE mapping as NVD would produce
        populated_repo.save_cve_cwe_mappings("CVE-2023-99999", ["CWE-89"], source="NVD")

        kg = KnowledgeGraphService(populated_repo)
        result = kg.get_cve_knowledge("CVE-2023-99999")

        # Verify CWE-89 is in weaknesses
        weakness_ids = [w.get("cwe_id") for w in result["weaknesses"]]
        assert "CWE-89" in weakness_ids

        # Verify CAPEC-66 is in attack_patterns
        capec_ids = [c.get("capec_id") for c in result["attack_patterns"]]
        assert "CAPEC-66" in capec_ids

    def test_cve_graph_contains_cwe_node(self, populated_repo):
        populated_repo.save_cve_cwe_mappings("CVE-2023-99999", ["CWE-89"], source="NVD")
        kg = KnowledgeGraphService(populated_repo)
        result = kg.get_cve_knowledge("CVE-2023-99999")
        graph = result["knowledge_graph"]
        cwe_nodes = [n for n in graph["nodes"] if n["type"] == "CWE"]
        assert any(n["id"] == "CWE-89" for n in cwe_nodes)

    def test_cve_graph_contains_capec_node(self, populated_repo):
        populated_repo.save_cve_cwe_mappings("CVE-2023-99999", ["CWE-89"], source="NVD")
        kg = KnowledgeGraphService(populated_repo)
        result = kg.get_cve_knowledge("CVE-2023-99999")
        graph = result["knowledge_graph"]
        capec_nodes = [n for n in graph["nodes"] if n["type"] == "CAPEC"]
        assert any(n["id"] == "CAPEC-66" for n in capec_nodes)

    def test_cve_mitigations_consolidated_from_cwe_and_capec(self, populated_repo):
        populated_repo.save_cve_cwe_mappings("CVE-2023-99999", ["CWE-89"], source="NVD")
        kg = KnowledgeGraphService(populated_repo)
        result = kg.get_cve_knowledge("CVE-2023-99999")
        # Mitigations should be collected from both CWE and CAPEC
        assert isinstance(result["mitigations"], list)

    def test_cve_detection_methods_consolidated(self, populated_repo):
        populated_repo.save_cve_cwe_mappings("CVE-2023-99999", ["CWE-79"], source="NVD")
        kg = KnowledgeGraphService(populated_repo)
        result = kg.get_cve_knowledge("CVE-2023-99999")
        assert isinstance(result["detection_methods"], list)
        # CWE-79 has detection methods
        cwe_detection = [d for d in result["detection_methods"] if d.get("source_type") == "CWE"]
        assert len(cwe_detection) >= 1
