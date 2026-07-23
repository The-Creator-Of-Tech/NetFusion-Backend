"""
IL-8 UTKG Test Fixtures
"""

import uuid
import pytest

from netfusion_intelligence.graph.models import (
    GraphEdgeType, GraphNode, GraphNodeType
)
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph


@pytest.fixture
def graph_repo():
    """In-memory SQLite graph repository — isolated per test."""
    return GraphRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def utkg(graph_repo):
    """UTKG service wired to an in-memory repo."""
    return UnifiedThreatKnowledgeGraph(graph_repository=graph_repo)


def _make_node(
    node_type: str,
    label: str,
    external_id: str = None,
    source_feed: str = "test",
    confidence: float = 1.0,
) -> GraphNode:
    cid = str(uuid.uuid4())
    return GraphNode.create(
        canonical_id=cid,
        node_type=node_type,
        label=label,
        name=label,
        external_id=external_id or label,
        source_feed=source_feed,
        confidence=confidence,
    )


@pytest.fixture
def sample_nodes(graph_repo):
    """Insert a representative sample of nodes for testing."""
    nodes = [
        _make_node(GraphNodeType.CVE.value,              "CVE-2021-44228", "CVE-2021-44228"),
        _make_node(GraphNodeType.CVE.value,              "CVE-2022-0001",  "CVE-2022-0001"),
        _make_node(GraphNodeType.CWE.value,              "CWE-502",        "CWE-502"),
        _make_node(GraphNodeType.CWE.value,              "CWE-20",         "CWE-20"),
        _make_node(GraphNodeType.CAPEC.value,            "CAPEC-66",       "CAPEC-66"),
        _make_node(GraphNodeType.ATTACK_TECHNIQUE.value, "T1059",          "T1059"),
        _make_node(GraphNodeType.ATTACK_TECHNIQUE.value, "T1190",          "T1190"),
        _make_node(GraphNodeType.IOC.value,              "1.2.3.4",        "1.2.3.4"),
        _make_node(GraphNodeType.DOMAIN.value,           "evil.com",       "evil.com"),
        _make_node(GraphNodeType.MALWARE.value,          "Log4Shell",      "Log4Shell"),
        _make_node(GraphNodeType.CAMPAIGN.value,         "CAMPAIGN-A",     "CAMPAIGN-A"),
        _make_node(GraphNodeType.THREAT_ACTOR.value,     "APT28",          "APT28"),
        _make_node(GraphNodeType.KEV.value,              "KEV:CVE-2021-44228", "KEV:CVE-2021-44228", confidence=1.0),
        _make_node(GraphNodeType.EPSS_RECORD.value,      "EPSS:CVE-2021-44228", "CVE-2021-44228", confidence=0.97),
        _make_node(GraphNodeType.INVESTIGATION.value,    "INV-001",        "INV-001"),
        _make_node(GraphNodeType.HOST.value,             "web-server-01",  "web-server-01"),
        _make_node(GraphNodeType.EVIDENCE.value,         "pcap-001",       "pcap-001"),
        _make_node(GraphNodeType.REPORT.value,           "REPORT-001",     "REPORT-001"),
    ]
    result = {}
    for node in nodes:
        saved, _ = graph_repo.upsert_node(node)
        result[saved.label] = saved
    return result


@pytest.fixture
def sample_edges(graph_repo, sample_nodes):
    """Insert a representative set of edges."""
    from netfusion_intelligence.graph.relationships import GraphRelationshipManager
    rm = GraphRelationshipManager(graph_repo)

    edges_to_create = [
        # CVE → CWE
        (sample_nodes["CVE-2021-44228"], sample_nodes["CWE-502"],    GraphEdgeType.HAS_WEAKNESS.value,    1.0),
        (sample_nodes["CVE-2022-0001"],  sample_nodes["CWE-20"],     GraphEdgeType.HAS_WEAKNESS.value,    0.9),
        # CWE → CAPEC
        (sample_nodes["CWE-502"],        sample_nodes["CAPEC-66"],   GraphEdgeType.EXPLOITED_BY.value,    0.9),
        # CAPEC → ATT&CK
        (sample_nodes["CAPEC-66"],       sample_nodes["T1059"],      GraphEdgeType.MAPS_TO.value,         0.8),
        # ATT&CK → Threat Actor
        (sample_nodes["APT28"],          sample_nodes["T1190"],      GraphEdgeType.USES_TECHNIQUE.value,  0.95),
        (sample_nodes["APT28"],          sample_nodes["T1059"],      GraphEdgeType.USES_TECHNIQUE.value,  0.85),
        # Threat Actor → Campaign
        (sample_nodes["APT28"],          sample_nodes["CAMPAIGN-A"], GraphEdgeType.ASSOCIATED_WITH.value, 1.0),
        # Campaign → Malware
        (sample_nodes["CAMPAIGN-A"],     sample_nodes["Log4Shell"],  GraphEdgeType.USES.value,            1.0),
        # Malware → IOC
        (sample_nodes["Log4Shell"],      sample_nodes["1.2.3.4"],    GraphEdgeType.COMMUNICATES_WITH.value, 0.9),
        (sample_nodes["Log4Shell"],      sample_nodes["evil.com"],   GraphEdgeType.COMMUNICATES_WITH.value, 0.85),
        # IOC → CVE
        (sample_nodes["1.2.3.4"],        sample_nodes["CVE-2021-44228"], GraphEdgeType.IOC_TO_CVE.value,  0.8),
        # KEV → CVE
        (sample_nodes["KEV:CVE-2021-44228"], sample_nodes["CVE-2021-44228"], GraphEdgeType.HAS_KEV.value, 1.0),
        # EPSS → CVE
        (sample_nodes["EPSS:CVE-2021-44228"], sample_nodes["CVE-2021-44228"], GraphEdgeType.HAS_EPSS.value, 0.97),
        # Host → CVE (affected)
        (sample_nodes["web-server-01"],  sample_nodes["CVE-2021-44228"], GraphEdgeType.AFFECTS.value,    0.7),
        # Investigation → IOC
        (sample_nodes["INV-001"],        sample_nodes["1.2.3.4"],    GraphEdgeType.LINKED_TO.value,       1.0),
        # Evidence → Investigation
        (sample_nodes["pcap-001"],       sample_nodes["INV-001"],    GraphEdgeType.HAS_EVIDENCE.value,    1.0),
        # Report → Investigation
        (sample_nodes["REPORT-001"],     sample_nodes["INV-001"],    GraphEdgeType.REFERENCES.value,      1.0),
    ]

    for src, tgt, etype, conf in edges_to_create:
        rm.add_relationship(
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            edge_type=etype,
            confidence=conf,
            source_feed="test_fixture",
        )

    return edges_to_create
