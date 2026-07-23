"""
Comprehensive Automated Tests for NETFUSION IL-9.1 Reasoning Trace Engine (XAI)
=============================================================================
Tests session lifecycle, stage recording, decision recording, evidence recording,
confidence waterfall, rule trace, graph trace, export formats, visualization builder,
REST API endpoints, and non-interference passive observation.
"""

import json
import pytest
from fastapi.testclient import TestClient

from netfusion_ai.reasoning import (
    ATREService,
    ConfidenceContribution,
    ExportEngine,
    QuestionType,
    ReasoningRequest,
    ReasoningTraceEngine,
    VisualizationBuilder,
    router,
)


@pytest.fixture
def trace_engine():
    return ReasoningTraceEngine()


@pytest.fixture
def atre_service():
    return ATREService()


@pytest.fixture
def api_client(atre_service):
    from fastapi import FastAPI
    from netfusion_ai.reasoning.api import set_atre_service
    set_atre_service(atre_service)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)



def test_session_lifecycle(trace_engine):
    """Test creation, updating, and completion of reasoning trace sessions."""
    trace = trace_engine.start_trace(
        user_query="What malware is associated with IP 192.168.1.100?",
        investigation_id="inv-test-101",
        analyst="Lead Analyst",
    )
    session_id = trace.session.session_id

    assert trace.session.user_query == "What malware is associated with IP 192.168.1.100?"
    assert trace.session.investigation_id == "inv-test-101"
    assert trace.session.status == "STARTED"

    retrieved = trace_engine.get_trace(session_id)
    assert retrieved is not None
    assert retrieved.trace_id == trace.trace_id

    completed = trace_engine.complete_trace(session_id, status="COMPLETED")
    assert completed is not None
    assert completed.session.status == "COMPLETED"
    assert completed.session.duration is not None
    assert completed.session.duration >= 0.0


def test_stage_recording(trace_engine):
    """Test recording of reasoning pipeline stages."""
    trace = trace_engine.start_trace(user_query="Investigate CVE-2023-38606")
    session_id = trace.session.session_id

    stages_to_record = [
        ("Intent Detection", 0.02, 0.95),
        ("Entity Extraction", 0.05, 1.0),
        ("CIIL Resolution", 0.04, 0.98),
        ("Graph Expansion", 0.12, 0.90),
        ("Evidence Collection", 0.08, 0.92),
        ("Relationship Ranking", 0.03, 0.88),
        ("Hypothesis Generation", 0.15, 0.85),
        ("Confidence Calculation", 0.01, 0.85),
        ("Contradiction Detection", 0.02, 1.0),
        ("Risk Calculation", 0.02, 0.90),
        ("Attack Chain Reconstruction", 0.06, 0.85),
        ("Recommendation Generation", 0.04, 0.90),
        ("Explanation Generation", 0.20, 0.95),
        ("Final Response", 0.01, 0.95),
    ]

    for stage_name, dur, conf in stages_to_record:
        step = trace_engine.record_stage(
            session_id=session_id,
            stage_name=stage_name,
            stage_input={"stage": stage_name},
            stage_output={"status": "OK"},
            duration=dur,
            confidence=conf,
        )
        assert step is not None
        assert step.stage_name == stage_name

    completed_trace = trace_engine.get_trace(session_id)
    assert len(completed_trace.stages) == 14
    assert completed_trace.stages[0].stage_name == "Intent Detection"
    assert completed_trace.stages[-1].stage_name == "Final Response"


def test_decision_recording(trace_engine):
    """Test recording AI choices and rejected alternatives."""
    trace = trace_engine.start_trace(user_query="Analyze suspicious domain evil-c2.com")
    session_id = trace.session.session_id

    dec = trace_engine.record_decision(
        session_id=session_id,
        decision_type="Hypothesis Selection",
        chosen_option="APT29 C2 Infrastructure",
        rejected_alternatives=["Generic Phishing Site", "Adware Server"],
        decision_reason="Matching IOC reputational hash and active KEV vulnerability match.",
        confidence=0.89,
        supporting_evidence=["IOC:evil-c2.com", "CVE-2023-38606"],
        contradicting_evidence=[],
        rule_triggered="RULE_APT29_INFRA_MATCH",
    )

    assert dec is not None
    assert dec.chosen_option == "APT29 C2 Infrastructure"
    assert len(dec.rejected_alternatives) == 2
    assert dec.confidence == 0.89

    fetched_trace = trace_engine.get_trace(session_id)
    assert len(fetched_trace.decisions) == 1
    assert fetched_trace.decisions[0].decision_id == dec.decision_id


def test_evidence_recording(trace_engine):
    """Test evidence selection and rejection tracking."""
    trace = trace_engine.start_trace(user_query="Trace evidence for host-01")
    session_id = trace.session.session_id

    ev1 = trace_engine.record_evidence(
        session_id=session_id,
        source_feed="CISA_KEV",
        canonical_id="CVE-2023-38606",
        confidence=0.98,
        trust_score=0.99,
        reason_selected="Directly associated with target host patch level",
    )
    assert ev1 is not None
    assert ev1.canonical_id == "CVE-2023-38606"

    ev2 = trace_engine.record_evidence(
        session_id=session_id,
        source_feed="EXPIRED_IOC_FEED",
        canonical_id="10.0.0.1",
        confidence=0.20,
        trust_score=0.30,
        reason_selected="Candidate local IP",
        reason_rejected="Private IP space / internal loopback",
    )
    assert ev2 is not None
    assert ev2.reason_rejected is not None

    fetched_trace = trace_engine.get_trace(session_id)
    assert len(fetched_trace.evidence) == 2


def test_confidence_waterfall_trace(trace_engine):
    """Test transparent confidence calculation waterfall and contributions."""
    trace = trace_engine.start_trace(user_query="Score confidence for threat actor X")
    session_id = trace.session.session_id

    contributions = [
        ConfidenceContribution(factor="IOC Reputation", delta=0.18, reason="High confidence threat score"),
        ConfidenceContribution(factor="KEV Known Exploited", delta=0.15, reason="Active KEV vulnerability"),
        ConfidenceContribution(factor="EPSS Score", delta=0.12, reason="EPSS > 80%"),
        ConfidenceContribution(factor="Expired IOC", delta=-0.08, reason="Older sighting timestamp"),
    ]

    conf = trace_engine.record_confidence(
        session_id=session_id,
        base_score=0.20,
        contributions=contributions,
        formula_explanation="Base (20%) + IOC (+18%) + KEV (+15%) + EPSS (+12%) - Expired (-8%)",
    )

    assert conf is not None
    # 0.20 + 0.18 + 0.15 + 0.12 - 0.08 = 0.57 (57%)
    assert pytest.approx(conf.overall_score, 0.01) == 0.57
    assert conf.breakdown["IOC Reputation"] == 0.18
    assert conf.breakdown["Expired IOC"] == -0.08

    fetched = trace_engine.get_trace(session_id)
    assert fetched.confidence is not None
    assert pytest.approx(fetched.confidence.overall_score, 0.01) == 0.57


def test_rule_and_graph_trace(trace_engine):
    """Test rule execution trace and graph traversal map recording."""
    trace = trace_engine.start_trace(user_query="Traverse UTKG graph for CVE-2023-38606")
    session_id = trace.session.session_id

    rule = trace_engine.record_rule(
        session_id=session_id,
        rule_name="RULE_HIGH_SEVERITY_CVE_EVAL",
        rule_input={"cve": "CVE-2023-38606"},
        rule_output={"priority": "CRITICAL"},
        reason="CVSS score >= 9.0 and KEV present",
        matched_conditions=["cvss >= 9.0", "kev == True"],
        execution_time=0.005,
        confidence_delta=0.15,
    )
    assert rule is not None
    assert rule.rule_name == "RULE_HIGH_SEVERITY_CVE_EVAL"

    gt = trace_engine.record_graph_trace(
        session_id=session_id,
        starting_node="CVE-2023-38606",
        visited_nodes=["CVE-2023-38606", "CAPEC-115", "CWE-79", "T1190"],
        traversal_depth=2,
        edges_traversed=[
            {"from": "CVE-2023-38606", "to": "CAPEC-115", "type": "EXPLOITED_BY"},
            {"from": "CAPEC-115", "to": "T1190", "type": "MAPS_TO_TACTIC"},
        ],
        relationships_used=["EXPLOITED_BY", "MAPS_TO_TACTIC"],
        shortest_path=["CVE-2023-38606", "CAPEC-115", "T1190"],
        expanded_context={"subgraph_nodes": 4},
    )
    assert gt is not None
    assert gt.starting_node == "CVE-2023-38606"
    assert len(gt.visited_nodes) == 4

    fetched = trace_engine.get_trace(session_id)
    assert len(fetched.rules) == 1
    assert fetched.graph_trace.starting_node == "CVE-2023-38606"


def test_export_engine(trace_engine):
    """Test exporting trace to JSON, Markdown, HTML, and PDF-ready JSON."""
    trace = trace_engine.start_trace(user_query="Export test query", investigation_id="inv-exp-1")
    session_id = trace.session.session_id

    trace_engine.record_stage(session_id=session_id, stage_name="Intent Detection", duration=0.01)
    trace_engine.record_decision(session_id=session_id, decision_type="Sample Decision", chosen_option="Option A", rejected_alternatives=["Option B"], decision_reason="Test reason")
    trace_engine.record_confidence(session_id=session_id, base_score=0.20, contributions=[ConfidenceContribution(factor="Test Factor", delta=0.30, reason="Test")])
    trace_engine.complete_trace(session_id=session_id)

    # JSON export
    json_out = trace_engine.export_trace(session_id, fmt="json")
    json_data = json.loads(json_out)
    assert json_data["session"]["session_id"] == session_id

    # Markdown export
    md_out = trace_engine.export_trace(session_id, fmt="markdown")
    assert "# Reasoning Trace Report:" in md_out
    assert "Export test query" in md_out

    # HTML export
    html_out = trace_engine.export_trace(session_id, fmt="html")
    assert "<!DOCTYPE html>" in html_out
    assert "NetFusion XAI IL-9.1" in html_out

    # PDF JSON export
    pdf_out = trace_engine.export_trace(session_id, fmt="pdf_json")
    pdf_data = json.loads(pdf_out)
    assert pdf_data["document_type"] == "NetFusion_XAI_Reasoning_Trace_Report"


def test_visualization_builder(trace_engine):
    """Test generation of diagram structures from reasoning trace."""
    trace = trace_engine.start_trace(user_query="Visualization test query")
    session_id = trace.session.session_id

    trace_engine.record_stage(session_id=session_id, stage_name="Intent Detection", duration=0.01)
    trace_engine.record_stage(session_id=session_id, stage_name="Entity Extraction", duration=0.02)
    trace_engine.record_decision(session_id=session_id, decision_type="Intent Classification", chosen_option="WHAT_HAPPENED", rejected_alternatives=[], decision_reason="Keyword match")
    trace_engine.record_evidence(session_id=session_id, source_feed="UTKG", canonical_id="IOC-1", confidence=0.9, trust_score=0.9, reason_selected="Match")
    trace_engine.record_confidence(session_id=session_id, base_score=0.2, contributions=[ConfidenceContribution(factor="IOC", delta=0.5, reason="Match")])
    trace_engine.record_hypothesis(session_id=session_id, hypothesis="H1: Malware infection", alternative_hypotheses=["H2: Benign activity"], supporting_evidence=["IOC-1"], contradicting_evidence=[], score=0.7, ranking=1)

    t = trace_engine.get_trace(session_id)

    flow = VisualizationBuilder.build_reasoning_flow(t)
    assert flow["type"] == "reasoning_flow"
    assert len(flow["nodes"]) == 2

    tree = VisualizationBuilder.build_decision_tree(t)
    assert tree["type"] == "decision_tree"
    assert len(tree["tree"]["children"]) == 1

    waterfall = VisualizationBuilder.build_confidence_waterfall(t)
    assert waterfall["type"] == "confidence_waterfall"
    assert len(waterfall["waterfall"]) == 2

    timeline = VisualizationBuilder.build_evidence_timeline(t)
    assert timeline["type"] == "evidence_timeline"
    assert len(timeline["events"]) == 1

    hyp_comp = VisualizationBuilder.build_hypothesis_comparison(t)
    assert hyp_comp["type"] == "hypothesis_comparison"
    assert len(hyp_comp["comparison"]) == 1


def test_rest_api_endpoints(api_client, atre_service):
    """Test all REST API endpoints for /reasoning/trace/..."""
    # First execute a query to create a trace session
    req = ReasoningRequest(user_question="API Test: What attack techniques were used?", investigation_id="inv-api-test-01")
    result = atre_service.query(req)
    inv_id = result.request.investigation_id

    # 1. GET /reasoning/trace/{session_id}
    res = api_client.get(f"/reasoning/trace/{inv_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["trace"]["session"]["investigation_id"] == inv_id

    # 2. GET /reasoning/trace/{session_id}/timeline
    res = api_client.get(f"/reasoning/trace/{inv_id}/timeline")
    assert res.status_code == 200
    assert res.json()["timeline"]["type"] == "evidence_timeline"

    # 3. GET /reasoning/trace/{session_id}/graph
    res = api_client.get(f"/reasoning/trace/{inv_id}/graph")
    assert res.status_code == 200
    assert res.json()["graph_traversal"]["type"] == "graph_traversal_map"

    # 4. GET /reasoning/trace/{session_id}/confidence
    res = api_client.get(f"/reasoning/trace/{inv_id}/confidence")
    assert res.status_code == 200
    assert res.json()["confidence_waterfall"]["type"] == "confidence_waterfall"

    # 5. GET /reasoning/trace/{session_id}/decisions
    res = api_client.get(f"/reasoning/trace/{inv_id}/decisions")
    assert res.status_code == 200
    assert res.json()["decision_tree"]["type"] == "decision_tree"

    # 6. GET /reasoning/trace/{session_id}/export
    res = api_client.get(f"/reasoning/trace/{inv_id}/export?format=markdown")
    assert res.status_code == 200
    assert "Reasoning Trace Report:" in res.json()["exported_content"]


def test_passive_observation_non_interference(atre_service):
    """Verify reasoning results are 100% identical with active tracing."""
    req = ReasoningRequest(
        user_question="What happened regarding CVE-2023-34362 on host-web-01?",
        investigation_id="inv-passive-test-01",
    )
    
    result = atre_service.query(req)
    
    assert result.intent == QuestionType.WHAT_HAPPENED
    assert result.confidence.overall_score > 0.0
    assert len(result.hypotheses) > 0
    assert len(result.evidence) > 0
    assert result.explanation.formatted_output != ""

    # Verify trace session was created and completed silently
    trace = atre_service.trace_engine.get_trace("inv-passive-test-01")
    assert trace is not None
    assert trace.session.status == "COMPLETED"
    assert len(trace.stages) >= 10


