"""
IL-8 UTKG — Knowledge Fusion Tests
Tests the fusion of IL-2..IL-7 data into the graph using mock repositories.
"""

import uuid
import pytest

from netfusion_intelligence.graph.fusion import KnowledgeFusionEngine
from netfusion_intelligence.graph.models import GraphNodeType
from netfusion_intelligence.graph.repository import GraphRepository


# ---------------------------------------------------------------------------
# Minimal mock intelligence repository
# ---------------------------------------------------------------------------

class MockIntelRepo:
    """Minimal mock with enough data to exercise all fusion paths."""

    def list_mitre_objects(self, type=None, limit=1000):
        base = [
            {"stix_id": "attack-pattern--001", "attack_id": "T1059", "name": "Command Execution",
             "type": "attack-pattern", "description": "Executes commands",
             "is_subtechnique": False, "parent_technique_id": None,
             "tactics": ["execution"], "platforms": ["Windows"],
             "aliases": [], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
            {"stix_id": "attack-pattern--002", "attack_id": "T1190", "name": "Exploit Public App",
             "type": "attack-pattern", "description": "Exploits public apps",
             "is_subtechnique": False, "parent_technique_id": None,
             "tactics": ["initial-access"], "platforms": ["Linux"],
             "aliases": [], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
            {"stix_id": "intrusion-set--001", "attack_id": "G0007", "name": "APT28",
             "type": "intrusion-set", "description": "Russian APT",
             "is_subtechnique": False, "parent_technique_id": None,
             "aliases": ["Fancy Bear"], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
            {"stix_id": "malware--001", "attack_id": "S0440", "name": "PowerSploit",
             "type": "malware", "description": "PowerShell framework",
             "is_subtechnique": False, "parent_technique_id": None,
             "aliases": [], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
            {"stix_id": "campaign--001", "attack_id": "C0001", "name": "Campaign Alpha",
             "type": "campaign", "description": "Test campaign",
             "is_subtechnique": False, "parent_technique_id": None,
             "aliases": [], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
            {"stix_id": "x-mitre-tactic--001", "attack_id": "TA0002", "name": "Execution",
             "type": "x-mitre-tactic", "description": "Execution tactic",
             "is_subtechnique": False, "parent_technique_id": None,
             "aliases": [], "kill_chain_phases": [], "detection": None,
             "external_references": [], "url": None, "version": "1.0",
             "created": "2020-01-01", "modified": "2021-01-01", "revoked": False, "deprecated": False},
        ]
        if type:
            return [o for o in base if o["type"] == type]
        return base

    def list_mitre_relationships(self, limit=1000):
        return [
            {"stix_id": "rel--001", "source_ref": "intrusion-set--001",
             "source_attack_id": "G0007", "source_type": "intrusion-set",
             "target_ref": "attack-pattern--001", "target_attack_id": "T1059",
             "target_type": "attack-pattern", "relationship_type": "uses",
             "description": None, "confidence": None,
             "created": "2020-01-01", "modified": "2021-01-01",
             "external_references": [], "revoked": False},
        ]

    def list_capec_attack_patterns(self, limit=5000):
        return [
            {"capec_id": "CAPEC-66", "name": "SQL Injection",
             "description": "SQL injection attack", "abstraction": "Standard",
             "status": "Stable", "likelihood_of_attack": "High",
             "typical_severity": "High", "execution_flow": [],
             "attack_technique_ids": ["T1059"],
             "related_weaknesses": ["CWE-89"],
             "notes": None, "source_version": "3.9", "url": None},
        ]

    def list_cwe_weaknesses(self, limit=5000):
        return [
            {"cwe_id": "CWE-89", "name": "SQL Injection",
             "description": "SQL Injection weakness",
             "abstraction": "Base", "structure": "Simple",
             "status": "Stable", "likelihood_of_exploit": "High",
             "related_weaknesses": [{"cwe_id": "CWE-20", "nature": "ChildOf"}]},
            {"cwe_id": "CWE-20", "name": "Improper Input Validation",
             "description": "Input validation weakness",
             "abstraction": "Class", "structure": "Simple",
             "status": "Stable", "likelihood_of_exploit": "Medium",
             "related_weaknesses": []},
        ]

    def list_nvd_cves(self, limit=50000):
        return [
            {"cve_id": "CVE-2021-44228", "description": "Log4Shell",
             "severity": "CRITICAL", "cvss_score": 10.0,
             "published": "2021-12-10", "cwes": ["CWE-502"]},
            {"cve_id": "CVE-2022-22965", "description": "Spring4Shell",
             "severity": "HIGH", "cvss_score": 9.8,
             "published": "2022-03-30", "cwes": ["CWE-94"]},
        ]

    def list_kev_records(self, limit=5000):
        return [
            {"cve_id": "CVE-2021-44228", "vendor_project": "Apache",
             "product": "Log4j", "short_description": "Log4Shell RCE",
             "due_date": "2021-12-24", "date_added": "2021-12-10",
             "known_ransomware_campaign_use": "Known"},
        ]

    def list_epss_scores(self, limit=50000):
        return [
            {"cve_id": "CVE-2021-44228", "epss_score": 0.97466,
             "epss_percentile": 0.99941, "trend": "STABLE",
             "publication_date": "2024-01-15"},
        ]

    def list_ioc_indicators(self, limit=50000):
        return [
            {"ioc_id": str(uuid.uuid4()), "ioc_type": "ipv4",
             "value": "192.168.1.100", "severity": "high",
             "confidence": 0.9, "reputation_score": 8.0,
             "malware_families": ["Log4Shell"], "campaigns": ["Campaign Alpha"],
             "threat_actors": [], "attack_technique_ids": ["T1059"],
             "cve_ids": ["CVE-2021-44228"], "capec_ids": [], "cwe_ids": [],
             "provider": "test_provider"},
            {"ioc_id": str(uuid.uuid4()), "ioc_type": "sha256",
             "value": "abc123def456" * 4, "severity": "critical",
             "confidence": 0.95, "reputation_score": 9.5,
             "malware_families": ["Log4Shell"], "campaigns": [],
             "threat_actors": [], "attack_technique_ids": [],
             "cve_ids": [], "capec_ids": [], "cwe_ids": [],
             "provider": "test_provider"},
        ]


# ---------------------------------------------------------------------------
# Fusion tests
# ---------------------------------------------------------------------------

@pytest.fixture
def fusion_engine(graph_repo):
    mock_intel = MockIntelRepo()
    return KnowledgeFusionEngine(
        graph_repository=graph_repo,
        intelligence_repository=mock_intel,
    )


class TestMitreFusion:
    def test_fuse_mitre_inserts_techniques(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_mitre()
        assert result.get("inserted", 0) + result.get("updated", 0) >= 2
        techs = graph_repo.list_nodes(node_type=GraphNodeType.ATTACK_TECHNIQUE.value)
        assert len(techs) >= 2

    def test_fuse_mitre_inserts_threat_actors(self, graph_repo, fusion_engine):
        fusion_engine.fuse_mitre()
        actors = graph_repo.list_nodes(node_type=GraphNodeType.THREAT_ACTOR.value)
        assert len(actors) >= 1
        assert actors[0].name == "APT28"

    def test_fuse_mitre_inserts_malware(self, graph_repo, fusion_engine):
        fusion_engine.fuse_mitre()
        malware = graph_repo.list_nodes(node_type=GraphNodeType.MALWARE.value)
        assert len(malware) >= 1

    def test_fuse_mitre_inserts_campaigns(self, graph_repo, fusion_engine):
        fusion_engine.fuse_mitre()
        camps = graph_repo.list_nodes(node_type=GraphNodeType.CAMPAIGN.value)
        assert len(camps) >= 1

    def test_fuse_mitre_creates_stix_edges(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_mitre()
        assert "edges" in result

    def test_fuse_mitre_idempotent(self, graph_repo, fusion_engine):
        fusion_engine.fuse_mitre()
        count_after_1 = graph_repo.count_nodes()
        fusion_engine.fuse_mitre()
        count_after_2 = graph_repo.count_nodes()
        assert count_after_1 == count_after_2   # no duplicates on second run


class TestCapecFusion:
    def test_fuse_capec_inserts_nodes(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_capec()
        assert result.get("inserted", 0) >= 1
        capec_nodes = graph_repo.list_nodes(node_type=GraphNodeType.CAPEC.value)
        assert len(capec_nodes) >= 1

    def test_fuse_capec_creates_attack_edge(self, graph_repo, fusion_engine):
        # Need ATT&CK nodes first
        fusion_engine.fuse_mitre()
        result = fusion_engine.fuse_capec()
        assert "edges" in result


class TestCweFusion:
    def test_fuse_cwe_inserts_nodes(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_cwe()
        assert result.get("inserted", 0) >= 2
        cwe_nodes = graph_repo.list_nodes(node_type=GraphNodeType.CWE.value)
        assert len(cwe_nodes) >= 2

    def test_fuse_cwe_creates_parent_edge(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_cwe()
        # CWE-89 ChildOf CWE-20 should create an edge
        assert "edges" in result


class TestCveFusion:
    def test_fuse_cve_inserts_nodes(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_cve()
        assert result.get("inserted", 0) >= 2
        cves = graph_repo.list_nodes(node_type=GraphNodeType.CVE.value)
        assert len(cves) >= 2

    def test_fuse_cve_creates_cwe_edges(self, graph_repo, fusion_engine):
        fusion_engine.fuse_cwe()
        result = fusion_engine.fuse_cve()
        assert "edges" in result

    def test_cve_confidence_proportional_to_cvss(self, graph_repo, fusion_engine):
        fusion_engine.fuse_cve()
        node = graph_repo.get_node_by_external_id(
            "CVE-2021-44228", node_type=GraphNodeType.CVE.value
        )
        assert node is not None
        assert node.confidence == 1.0   # CVSS 10 / 10 = 1.0


class TestKevFusion:
    def test_fuse_kev_inserts_nodes(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_kev()
        assert result.get("inserted", 0) >= 1
        kev_nodes = graph_repo.list_nodes(node_type=GraphNodeType.KEV.value)
        assert len(kev_nodes) >= 1

    def test_fuse_kev_creates_cve_edge(self, graph_repo, fusion_engine):
        fusion_engine.fuse_cve()   # CVE node must exist first
        result = fusion_engine.fuse_kev()
        assert result.get("edges", 0) >= 1


class TestEpssFusion:
    def test_fuse_epss_inserts_nodes(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_epss()
        assert result.get("inserted", 0) >= 1
        epss_nodes = graph_repo.list_nodes(node_type=GraphNodeType.EPSS_RECORD.value)
        assert len(epss_nodes) >= 1

    def test_fuse_epss_confidence_matches_score(self, graph_repo, fusion_engine):
        fusion_engine.fuse_epss()
        node = graph_repo.get_node_by_external_id(
            "CVE-2021-44228", node_type=GraphNodeType.EPSS_RECORD.value
        )
        assert node is not None
        assert abs(node.confidence - 0.97466) < 0.001


class TestIocFusion:
    def test_fuse_ioc_inserts_ip_node(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_ioc()
        assert result.get("inserted", 0) >= 2
        ip_nodes = graph_repo.list_nodes(node_type=GraphNodeType.IP.value)
        assert len(ip_nodes) >= 1

    def test_fuse_ioc_inserts_hash_node(self, graph_repo, fusion_engine):
        fusion_engine.fuse_ioc()
        hash_nodes = graph_repo.list_nodes(node_type=GraphNodeType.HASH.value)
        assert len(hash_nodes) >= 1

    def test_fuse_ioc_creates_malware_node(self, graph_repo, fusion_engine):
        fusion_engine.fuse_ioc()
        malware = graph_repo.list_nodes(node_type=GraphNodeType.MALWARE.value)
        assert any("Log4Shell" in n.name for n in malware if n.name)

    def test_fuse_ioc_creates_campaign_node(self, graph_repo, fusion_engine):
        fusion_engine.fuse_ioc()
        camps = graph_repo.list_nodes(node_type=GraphNodeType.CAMPAIGN.value)
        assert len(camps) >= 1

    def test_fuse_ioc_idempotent(self, graph_repo, fusion_engine):
        fusion_engine.fuse_ioc()
        count1 = graph_repo.count_nodes()
        fusion_engine.fuse_ioc()
        count2 = graph_repo.count_nodes()
        assert count1 == count2


class TestFullFusion:
    def test_fuse_all_runs_all_layers(self, graph_repo, fusion_engine):
        result = fusion_engine.fuse_all()
        assert "mitre" in result
        assert "capec" in result
        assert "cwe" in result
        assert "cve" in result
        assert "kev" in result
        assert "epss" in result
        assert "ioc" in result
        assert "cross" in result

    def test_fuse_all_populates_graph(self, graph_repo, fusion_engine):
        fusion_engine.fuse_all()
        total = graph_repo.count_nodes()
        assert total >= 10   # all layers contribute nodes

    def test_fuse_all_total_edges_positive(self, graph_repo, fusion_engine):
        fusion_engine.fuse_all()
        edge_count = graph_repo.count_edges()
        assert edge_count >= 1
