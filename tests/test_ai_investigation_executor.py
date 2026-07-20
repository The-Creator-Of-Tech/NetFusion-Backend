import os
import uuid
import pytest
from datetime import datetime
from services.workflow_execution_service import (
    WorkflowExecutionContext,
    WorkflowExecutionManager,
    StepExecutor,
    _REGISTRY,
    WorkflowArtifact
)

def test_ai_investigation_executor_can_execute():
    """Verify routing and matching rules for AIInvestigationExecutor."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "ai_investigation")
    
    # 1. Explicit identifier matching
    assert executor.can_execute({"executor": "ai_investigation", "stepType": "AUTOMATED"}) is True
    assert executor.can_execute({"executorType": "ai", "stepType": "AUTOMATED"}) is True
    assert executor.can_execute({"executor": "ai_summary", "stepType": "AUTOMATED"}) is True
    
    # 2. Text keyword matching (fallback routing)
    assert executor.can_execute({
        "stepType": "AUTOMATED",
        "title": "AI Summary of Traffic",
        "description": "Generate executive summary"
    }) is True
    assert executor.can_execute({
        "stepType": "AUTOMATED",
        "title": "Threat Investigation",
        "description": "Investigate alerts"
    }) is True
    
    # 3. Exclude mismatching steps
    assert executor.can_execute({"stepType": "MANUAL", "title": "AI Summary"}) is False
    assert executor.can_execute({"stepType": "AUTOMATED", "title": "Run Nmap Scan"}) is False


def test_nmap_executor_ignores_ai():
    """Verify that NmapExecutor does not greedily grab AI Summary steps anymore."""
    nmap = next(e for e in _REGISTRY._executors if e.identifier == "nmap")
    
    # Step that mentions scan and AI summary
    ai_step = {
        "stepType": "AUTOMATED",
        "title": "AI Summary",
        "description": "Generate executive summaries of large trace, packet or scan datasets."
    }
    assert nmap.can_execute(ai_step) is False


def test_ai_investigation_evidence_correlation():
    """Unit test to verify rule-based correlation, risk score, and recommendations."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "ai_investigation")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-id",
        playbook_id="test-playbook-id",
        playbook_name="Test Playbook",
        steps=[],
        total_steps=1
    )
    ctx.current_step_number = 1
    
    # Seed variables in context mimicking PCAP and Nmap results
    ctx.set_variable("protocols", ["TCP", "HTTP", "SMB"], "array")
    ctx.set_variable("open_ports", [80, 445, 3306], "array")
    ctx.set_variable("dns_queries", ["google.com", "malicious-c2.net", "attacker.xyz", "host1", "host2", "host3", "host4", "host5", "host6", "host7", "host8", "host9", "host10", "host11"], "array")
    ctx.set_variable("http_hosts", ["unencrypted-post.org"], "array")
    ctx.set_variable("endpoints", ["192.168.1.10", "8.8.8.8", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.16"], "array")
    ctx.set_variable("conversations", ["192.168.1.10 -> 8.8.8.8 (DNS)"] * 25, "array")
    ctx.set_variable("statistics", {
        "total_packets": 500,
        "duration_seconds": 12.5,
        "dns_queries_count": 14,
        "conversations_count": 25,
        "endpoints_count": 18
    }, "object")
    
    step = {
        "stepId": "ai-step",
        "title": "AI Summary",
        "stepType": "AUTOMATED",
        "config": {
            # Let's bind some variables via config interpolation, others via context fallback
            "protocols": "${protocols}",
            "open_ports": "${open_ports}",
            # dns_queries, http_hosts, endpoints, conversations, statistics are fallback
        }
    }
    
    # We simulate resolve_variables normally run by StepRunner
    from services.workflow_execution_service import resolve_variables
    resolved_step = resolve_variables(step, ctx)
    
    # Run the executor
    result = executor.execute(resolved_step, ctx)
    assert result["success"] is True
    
    output = result["output"]
    assert output["risk_score"] > 50
    assert output["severity"] in ("High", "Critical")
    
    # Verify findings count and details
    findings = output["findings"]
    assert len(findings) > 0
    
    # Check that SMB finding triggered
    smb_finding = next((f for f in findings if "SMB" in f["title"]), None)
    assert smb_finding is not None
    assert smb_finding["severity"] == "Critical"
    assert smb_finding["confidence"] == 95
    assert len(smb_finding["evidence"]) > 0
    
    # Check that DB finding triggered
    db_finding = next((f for f in findings if "Database" in f["title"]), None)
    assert db_finding is not None
    assert db_finding["severity"] == "High"
    
    # Check that HTTP finding triggered
    http_finding = next((f for f in findings if "HTTP" in f["title"]), None)
    assert http_finding is not None
    assert http_finding["severity"] == "Medium"
    
    # Check that High DNS triggered
    dns_finding = next((f for f in findings if "DNS" in f["title"]), None)
    assert dns_finding is not None
    
    # Check that Excessive Conversations triggered
    conv_finding = next((f for f in findings if "Conversations" in f["title"]), None)
    assert conv_finding is not None

    # Check that High Endpoints triggered
    ep_finding = next((f for f in findings if "Endpoint" in f["title"]), None)
    assert ep_finding is not None
    
    # Verify recommendations exist and contain security guidance
    recs = output["recommendations"]
    assert len(recs) >= 3
    assert any("445" in r or "SMB" in r for r in recs)
    
    # Verify Bullet Executive Summary format
    summary = output["executive_summary"]
    assert summary.startswith("- **")
    assert "Overall Risk" in summary
    assert "Key Findings" in summary
    
    # Verify published variables in context
    assert ctx.get_variable("risk_score") == output["risk_score"]
    assert ctx.get_variable("severity") == output["severity"]
    assert ctx.get_variable("findings") == output["findings"]
    assert ctx.get_variable("recommendations") == output["recommendations"]
    assert ctx.get_variable("executive_summary") == output["executive_summary"]
    assert ctx.get_variable("ioc_candidates") == output["ioc_candidates"]
    
    # Verify metadata completeness on variables
    for var_name in ["risk_score", "severity", "findings", "recommendations", "executive_summary", "ioc_candidates", "ai_investigation"]:
        var_entry = ctx.variables[var_name]
        assert var_entry["name"] == var_name
        assert var_entry["createdBy"] == "AIInvestigationExecutor"
        assert var_entry["stepNumber"] == 1
        assert var_entry["createdAt"] is not None


def test_ai_investigation_graceful_missing_evidence():
    """Verify that executor handles missing or corrupt evidence gracefully."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "ai_investigation")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-missing",
        playbook_id="test-playbook-id",
        playbook_name="Test Playbook",
        steps=[],
        total_steps=1
    )
    
    # We do not seed any variables. Everything is missing.
    step = {
        "stepId": "ai-step",
        "title": "AI Summary",
        "stepType": "AUTOMATED",
        "config": {}
    }
    
    result = executor.execute(step, ctx)
    assert result["success"] is True
    output = result["output"]
    
    # Baseline risk score should be 10 (Low)
    assert output["risk_score"] == 10
    assert output["severity"] == "Low"
    assert len(output["findings"]) == 0
    assert len(output["recommendations"]) == 1  # Default recommendation


def test_ai_investigation_artifact_creation(tmp_path):
    """Verify Markdown report artifact creation and registration."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "ai_investigation")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-art",
        playbook_id="test-playbook-id",
        playbook_name="Test Playbook",
        steps=[],
        total_steps=1
    )
    
    # Seed a capture file path inside temporary directory
    fake_pcap = os.path.join(tmp_path, "traffic_capture_sample.pcapng")
    with open(fake_pcap, "w") as f:
        f.write("mock pcap content")
        
    ctx.set_variable("capture_file", fake_pcap, "file")
    
    step = {
        "stepId": "ai-step",
        "title": "AI Summary",
        "stepType": "AUTOMATED",
        "config": {
            "capture_file": "${capture_file}"
        }
    }
    
    from services.workflow_execution_service import resolve_variables
    resolved_step = resolve_variables(step, ctx)
    
    result = executor.execute(resolved_step, ctx)
    assert result["success"] is True
    
    # Verify artifact was created on disk
    expected_artifact_file = os.path.join(tmp_path, "investigation_traffic_capture_sample.md")
    assert os.path.exists(expected_artifact_file), f"Expected artifact at {expected_artifact_file}"
    
    # Verify content in the file
    with open(expected_artifact_file, "r", encoding="utf-8") as f:
        content = f.read()
        assert "# AI Investigation Report" in content
        assert "## Executive Summary" in content
        assert "## Risk Score & Severity" in content
        assert "## Findings" in content
        assert "## Evidence" in content
        assert "## Network Statistics" in content
        assert "## Open Ports & Services" in content
        
    # Verify registered in context
    artifacts = ctx.list_artifacts()
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.name == "AI Investigation - traffic_capture_sample"
    assert art.type == "markdown"
    assert art.mimeType == "text/markdown"
    assert art.location == expected_artifact_file
    assert art.producerExecutor == "AIInvestigationExecutor"


def test_ai_investigation_backward_compatibility():
    """Verify executor API compatibility with legacy has_variable, hasVariable, get_variable, getVariable, etc."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "ai_investigation")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-compat",
        playbook_id="test-playbook-id",
        playbook_name="Test Playbook",
        steps=[],
        total_steps=1
    )
    
    ctx.set_variable("test_var", "value_123", "string")
    
    # Bind context to executor (StepExecutor.execute handles this, but let's test directly)
    executor.ctx = ctx
    
    # Assert Has/Get compatibility methods work as expected
    assert executor.has_variable("test_var") is True
    assert executor.hasVariable("test_var") is True
    assert executor.get_variable("test_var") == "value_123"
    assert executor.getVariable("test_var") == "value_123"
    
    # List variables
    list1 = executor.list_variables()
    list2 = executor.listVariables()
    assert len(list1) == 1
    assert list1 == list2
    assert list1[0]["name"] == "test_var"
    assert list1[0]["value"] == "value_123"


def test_workflow_end_to_end_integration(tmp_path):
    """E2E workflow test integrating PCAPAnalysisExecutor and AIInvestigationExecutor."""
    # Create the sample capture file
    fake_pcap = os.path.join(tmp_path, "live_capture.pcapng")
    with open(fake_pcap, "w") as f:
        f.write("mock pcap")
        
    # Set up the playbook
    pb_steps = [
        {
            "stepId": "pcap-analysis-step",
            "title": "Analyze PCAP",
            "stepType": "AUTOMATED",
            "executor": "pcap_analysis",
            "config": {
                "capture_file": "${capture_file}"
            }
        },
        {
            "stepId": "ai-investigation-step",
            "title": "AI Indicator Threat Analysis",
            "stepType": "AUTOMATED",
            "executor": "ai_investigation",
            "config": {
                "protocols": "${protocols}",
                "dns_queries": "${dns_queries}",
                "http_hosts": "${http_hosts}",
                "conversations": "${conversations}",
                "endpoints": "${endpoints}",
                "statistics": "${statistics}"
            }
        }
    ]
    
    ctx = WorkflowExecutionContext(
        execution_id=str(uuid.uuid4()),
        playbook_id="e2e-playbook",
        playbook_name="E2E NetFusion Investigation",
        steps=pb_steps,
        total_steps=2
    )
    
    # Seed the entry variable
    ctx.set_variable("capture_file", fake_pcap, "file")
    
    # We patch tshark_parser to return quick mock results to avoid executing real tshark
    import unittest.mock as mock
    from parsers import tshark_parser
    
    with mock.patch("parsers.tshark_parser.extract_protocol_lines", return_value=["TCP", "HTTP", "SMB"]):
        with mock.patch("parsers.tshark_parser.extract_dns_query_lines", return_value=["malicious-dns.com"]):
            with mock.patch("parsers.tshark_parser.extract_http_host_lines", return_value=["unencrypted-host.net"]):
                with mock.patch("parsers.tshark_parser.extract_tls_session_lines", return_value=[]):
                    with mock.patch("parsers.tshark_parser.extract_conversation_lines", return_value=["192.168.1.5\t10.0.0.2\tTCP"]):
                        with mock.patch("parsers.tshark_parser.run_tshark") as mock_run:
                            # Mock run_tshark to avoid real subprocessing
                            mock_res = mock.MagicMock()
                            mock_res.returncode = 0
                            mock_res.stdout = "1000.0"
                            mock_run.return_value = mock_res
                            
                            # Run workflow
                            WorkflowExecutionManager.run_execution_background(ctx)
                            
    # Verify execution complete
    assert ctx.status == "COMPLETED"
    assert ctx.completed_steps == 2
    assert ctx.failed_steps == 0
    
    # Verify variables produced by PCAP Analysis
    assert ctx.get_variable("protocols") == ["HTTP", "SMB", "TCP"]
    assert ctx.get_variable("dns_queries") == ["malicious-dns.com"]
    assert ctx.get_variable("http_hosts") == ["unencrypted-host.net"]
    
    # Verify variables produced by AI Investigation
    assert ctx.get_variable("risk_score") is not None
    assert ctx.get_variable("severity") is not None
    findings = ctx.get_variable("findings")
    assert len(findings) > 0
    
    # Ensure SMB and HTTP unencrypted findings triggered
    assert any("SMB" in f["title"] for f in findings)
    assert any("HTTP" in f["title"] for f in findings)
    
    # Verify artifact created
    artifacts = ctx.list_artifacts()
    # 1 from PCAP Analysis, 1 from AI Investigation
    assert len(artifacts) == 2
    investigation_art = next((a for a in artifacts if "investigation" in a.name.lower()), None)
    assert investigation_art is not None
    assert os.path.exists(investigation_art.location)
