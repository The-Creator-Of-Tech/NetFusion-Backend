import os
import uuid
import pytest
import unittest.mock as mock
from datetime import datetime
from services.workflow_execution_service import (
    WorkflowExecutionContext,
    WorkflowExecutionManager,
    StepExecutor,
    _REGISTRY,
    WorkflowArtifact,
    resolve_variables
)

def test_report_generator_can_execute():
    """Verify routing and matching rules for ReportGeneratorExecutor and ManualExecutor."""
    report_gen = next(e for e in _REGISTRY._executors if e.identifier == "report_generator")
    manual = next(e for e in _REGISTRY._executors if e.identifier == "manual")
    
    # 1. Explicit identifier matching
    assert report_gen.can_execute({"executor": "report_generator", "stepType": "AUTOMATED"}) is True
    assert report_gen.can_execute({"executorType": "report-generator", "stepType": "AUTOMATED"}) is True
    assert report_gen.can_execute({"executor": "report_generation", "stepType": "AUTOMATED"}) is True
    
    # 2. Text keyword matching (fallback routing)
    assert report_gen.can_execute({
        "stepType": "AUTOMATED",
        "title": "Generate Report",
        "description": "Create pdf or markdown summary"
    }) is True
    assert report_gen.can_execute({
        "stepType": "MANUAL",
        "title": "Workflow Generate Report",
        "description": "User clicks button to generate report"
    }) is True
    
    # 3. Manual executor must ignore report generation
    assert manual.can_execute({
        "stepType": "MANUAL",
        "title": "Generate Report"
    }) is False
    assert manual.can_execute({
        "stepType": "MANUAL",
        "title": "Approve changes manually"
    }) is True


def test_report_generator_can_resolve():
    """Verify registry resolves report steps to ReportGeneratorExecutor even if marked MANUAL or manual."""
    # Step has manual executor/stepType but title matches generate report
    step = {
        "stepId": "gen-report",
        "title": "Generate Report",
        "stepType": "MANUAL",
        "executor": "manual"
    }
    resolved = _REGISTRY.resolve(step)
    assert resolved is not None
    assert resolved.identifier == "report_generator"


def test_report_generator_execute_normal(tmp_path):
    """Verify successful report generation under standard conditions with full data."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "report_generator")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-report-normal",
        playbook_id="realistic-pb",
        playbook_name="Network Breach Investigation",
        steps=[],
        total_steps=1
    )
    ctx.current_step_number = 1
    
    # Create mock capture file in tmp_path
    fake_pcap = os.path.join(tmp_path, "capture_intel.pcapng")
    with open(fake_pcap, "w") as f:
        f.write("dummy pcap contents")
        
    # Seed full context variables
    ctx.set_variable("capture_file", fake_pcap, "file")
    ctx.set_variable("packet_count", 1500, "number")
    ctx.set_variable("capture_duration", 10.5, "number")
    ctx.set_variable("capture_interface", "eth0", "string")
    
    ctx.set_variable("statistics", {"total_packets": 1500, "endpoints_count": 5}, "object")
    ctx.set_variable("protocols", ["TCP", "HTTP", "DNS"], "array")
    ctx.set_variable("endpoints", ["192.168.1.5", "10.0.0.1"], "array")
    ctx.set_variable("conversations", ["192.168.1.5 -> 10.0.0.1 (TCP)"], "array")
    ctx.set_variable("dns_queries", ["evil-c2.com", "google.com"], "array")
    ctx.set_variable("http_hosts", ["evil-c2.com"], "array")
    ctx.set_variable("tls_sessions", ["secure.com"], "array")
    ctx.set_variable("analysis_summary", "Detected HTTP/DNS beaconing to suspect external hosts.", "string")
    
    ctx.set_variable("host", "192.168.1.5", "string")
    ctx.set_variable("target", "192.168.1.0/24", "string")
    ctx.set_variable("services", [{"port": 80, "service": "http", "state": "open"}], "array")
    ctx.set_variable("open_ports", [80, 445], "array")
    ctx.set_variable("scan_results", {"192.168.1.5": {"ports": [80, 445]}}, "object")
    
    ctx.set_variable("risk_score", 75, "number")
    ctx.set_variable("severity", "High", "string")
    ctx.set_variable("findings", [
        {
            "title": "Exposed SMB Service",
            "severity": "High",
            "confidence": 90,
            "description": "SMB exposed on internal asset.",
            "evidence": ["Port 445 found open"]
        }
    ], "array")
    ctx.set_variable("recommendations", ["Block external SMB ports.", "Apply security patches."], "array")
    ctx.set_variable("executive_summary", "- SMB exposure detected\n- Overall Risk: High", "string")
    ctx.set_variable("ioc_candidates", ["evil-c2.com", "192.168.1.5"], "array")
    
    step = {
        "stepId": "report-step",
        "title": "Generate Report",
        "stepType": "AUTOMATED",
        "config": {
            "capture_file": "${capture_file}"
        }
    }
    
    resolved_step = resolve_variables(step, ctx)
    result = executor.execute(resolved_step, ctx)
    
    assert result["success"] is True
    out = result["output"]
    assert "report_file" in out
    assert "report_generated_at" in out
    assert "report_summary" in out
    assert "artifactId" in out
    
    # Assert file generated inside the correct directory (tmp_path since capture_file was there)
    expected_file_path = os.path.join(tmp_path, "report_capture_intel.md")
    assert os.path.exists(expected_file_path)
    assert out["report_file"] == expected_file_path
    
    # Verify report content
    with open(expected_file_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "# NetFusion Investigation Report" in content
        assert "## Executive Summary" in content
        assert "- SMB exposure detected" in content
        assert "## Risk Assessment" in content
        assert "- **Risk Score**: 75.0" in content
        assert "- **Severity**: High" in content
        assert "## Capture Overview" in content
        assert "- **Packet Count**: 1500" in content
        assert "- **Capture Duration**: 10.5 seconds" in content
        assert "- **Interface**: eth0" in content
        assert "## Network Statistics" in content
        assert "- **Total Packets**: 1500" in content
        assert "- **Protocol Count**: 3" in content
        assert "## Open Services" in content
        assert "| Port | Service | State |" in content
        assert "| 80 | http | open |" in content
        assert "| 445 | Unknown | open |" in content
        assert "## Network Protocols" in content
        assert "- TCP" in content
        assert "- HTTP" in content
        assert "## DNS Activity" in content
        assert "- evil-c2.com" in content
        assert "## Key Findings" in content
        assert "### Exposed SMB Service" in content
        assert "## Recommendations" in content
        assert "1. Block external SMB ports." in content
        assert "2. Apply security patches." in content
        assert "## IOC Candidates" in content
        assert "### IP Addresses" in content
        assert "- 192.168.1.5" in content
        assert "### Domains" in content
        assert "- evil-c2.com" in content
        assert "## Investigation Timeline" in content
        assert "Packet Capture\n\n↓\n\nPCAP Analysis\n\n↓\n\nNmap Scan\n\n↓\n\nAI Investigation\n\n↓\n\nReport Generated" in content
        assert "## Conclusion" in content
        
    # Verify artifact is registered
    artifacts = ctx.list_artifacts()
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifactId == out["artifactId"]
    assert art.name == "Investigation Report - capture_intel"
    assert art.type == "markdown"
    assert art.location == expected_file_path
    assert art.producerExecutor == "ReportGeneratorExecutor"
    assert art.metadata["risk_score"] == 75.0
    assert art.metadata["severity"] == "High"
    assert art.metadata["findings_count"] == 1
    assert art.metadata["capture_id"] == "capture_intel"
    
    # Verify published registry variables
    assert ctx.get_variable("report_file") == expected_file_path
    assert ctx.get_variable("report_generated_at") == out["report_generated_at"]
    assert "High" in ctx.get_variable("report_summary")
    assert ctx.get_variable("report_artifact") == art.to_dict()


def test_report_generator_graceful_missing_variables():
    """Verify that ReportGeneratorExecutor executes safely even with entirely missing variables."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "report_generator")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-missing-vars",
        playbook_id="empty-pb",
        playbook_name="Empty Playbook Workflow",
        steps=[],
        total_steps=1
    )
    
    step = {
        "stepId": "report-step",
        "title": "Generate Report",
        "stepType": "AUTOMATED",
        "config": {}
    }
    
    result = executor.execute(step, ctx)
    assert result["success"] is True
    
    # Assert fallbacks are used
    assert ctx.get_variable("report_file") is not None
    assert os.path.exists(ctx.get_variable("report_file"))
    
    # Clean up file created in local root since capture_file was not present (defaults to Captured_packets/report_default.md)
    report_file = ctx.get_variable("report_file")
    if os.path.exists(report_file):
        try:
            os.remove(report_file)
        except Exception:
            pass


def test_report_generator_empty_findings(tmp_path):
    """Verify that ReportGeneratorExecutor runs cleanly with empty findings/recommendations lists."""
    executor = next(e for e in _REGISTRY._executors if e.identifier == "report_generator")
    ctx = WorkflowExecutionContext(
        execution_id="test-exec-empty-findings",
        playbook_id="empty-findings-pb",
        playbook_name="No Findings Workflow",
        steps=[],
        total_steps=1
    )
    
    fake_pcap = os.path.join(tmp_path, "empty_run.pcap")
    with open(fake_pcap, "w") as f:
        f.write("mock")
        
    ctx.set_variable("capture_file", fake_pcap)
    ctx.set_variable("risk_score", 10.0)
    ctx.set_variable("severity", "Low")
    ctx.set_variable("findings", [])
    ctx.set_variable("recommendations", [])
    
    step = {
        "stepId": "report-step",
        "title": "Generate Report",
        "stepType": "AUTOMATED",
        "config": {
            "capture_file": "${capture_file}"
        }
    }
    
    resolved_step = resolve_variables(step, ctx)
    result = executor.execute(resolved_step, ctx)
    
    assert result["success"] is True
    report_file = ctx.get_variable("report_file")
    assert os.path.exists(report_file)
    
    with open(report_file, "r", encoding="utf-8") as f:
        content = f.read()
        assert "No findings identified." in content
        assert "## Recommendations" in content
        assert "No recommendations provided" not in content # Default recommendations should be printed


def test_report_generator_integration_workflow(tmp_path):
    """Run E2E simulation to verify workflow executes and automatically resolves to ReportGeneratorExecutor."""
    fake_pcap_path = os.path.join(tmp_path, "integration_capture.pcapng")
    with open(fake_pcap_path, "w") as f:
        f.write("dummy")

    def mock_capture_execute(self, step, ctx):
        ctx.set_variable("capture_file", fake_pcap_path, "file")
        ctx.set_variable("packet_count", 200, "number")
        ctx.set_variable("capture_duration", 1, "number")
        ctx.set_variable("capture_interface", "eth0", "string")
        return {"success": True, "summary": "Captured 200 packets.", "output": {"capture_file": fake_pcap_path}}

    def mock_analysis_execute(self, step, ctx):
        ctx.set_variable("protocols", ["TCP", "HTTP", "DNS"], "array")
        ctx.set_variable("dns_queries", ["evil.com"], "array")
        ctx.set_variable("http_hosts", ["evil.com"], "array")
        return {"success": True, "summary": "Analyzed PCAP.", "output": {}}

    def mock_ai_execute(self, step, ctx):
        ctx.set_variable("risk_score", 90.0, "number")
        ctx.set_variable("severity", "Critical", "string")
        ctx.set_variable("findings", [{"title": "Suspicious Beaconing", "severity": "High", "confidence": 85}], "array")
        ctx.set_variable("recommendations", ["Isolate system"], "array")
        ctx.set_variable("executive_summary", "- Suspicious beaconing detected", "string")
        return {"success": True, "summary": "AI complete.", "output": {}}
    
    steps = [
        {
            "stepId": "capture-1",
            "title": "Start Network Capture",
            "stepType": "AUTOMATED",
            "stepNumber": 1,
            "executor": "packet_capture",
            "config": {"interface": "eth0", "duration": 1}
        },
        {
            "stepId": "analysis-2",
            "title": "Analyze PCAP",
            "stepType": "AUTOMATED",
            "stepNumber": 2,
            "executor": "pcap_analysis",
            "config": {"capture_file": "${capture_file}"}
        },
        {
            "stepId": "ai-3",
            "title": "AI Indicator Threat Analysis",
            "stepType": "AUTOMATED",
            "stepNumber": 3,
            "executor": "ai_investigation",
            "config": {
                "dns_queries": "${dns_queries}",
                "http_hosts": "${http_hosts}"
            }
        },
        {
            "stepId": "report-4",
            "title": "Generate Final Investigation Report",
            "stepType": "MANUAL",  # Marked manual to verify it resolves to ReportGeneratorExecutor automatically
            "stepNumber": 4,
            "executor": "manual",  # Explicitly set to manual to verify override
            "config": {
                "capture_file": "${capture_file}",
                "risk_score": "${risk_score}",
                "severity": "${severity}",
                "findings": "${findings}",
                "recommendations": "${recommendations}",
                "executive_summary": "${executive_summary}"
            }
        }
    ]
    
    ctx = WorkflowExecutionContext(
        execution_id="integration-test-e2e",
        playbook_id="integration-pb",
        playbook_name="E2E Integrated Security Workflow",
        steps=steps,
        total_steps=len(steps)
    )

    from services.workflow_execution_service import (
        PacketCaptureExecutor,
        PCAPAnalysisExecutor,
        AIInvestigationExecutor
    )
    
    # Setup mocks for intermediate executors
    with mock.patch.object(PacketCaptureExecutor, "_execute_internal", mock_capture_execute), \
         mock.patch.object(PCAPAnalysisExecutor, "_execute_internal", mock_analysis_execute), \
         mock.patch.object(AIInvestigationExecutor, "_execute_internal", mock_ai_execute), \
         mock.patch("time.sleep", return_value=None):
        WorkflowExecutionManager.run_execution_background(ctx)
        
    print(f"DEBUG: ctx.variables keys: {list(ctx.variables.keys())}")
    for k, v in ctx.variables.items():
        print(f"DEBUG: ctx.variables[{k}] = {v}")

    assert ctx.status == "COMPLETED"
    assert ctx.completed_steps == 4
    
    # Verify report generated successfully in background execution
    report_file = ctx.get_variable("report_file")
    assert report_file is not None
    assert os.path.exists(report_file)
    
    # Confirm correct artifact type and contents registered
    artifacts = ctx.list_artifacts()
    report_art = next((a for a in artifacts if a.producerExecutor == "ReportGeneratorExecutor"), None)
    assert report_art is not None
    assert report_art.location == report_file
    
    # Check trace log output has our steps
    log_messages = [log["message"] for log in ctx.logs]
    assert any("Starting Report Generation" in msg for msg in log_messages)
    assert any("Loading workflow variables" in msg for msg in log_messages)
    assert any("Building Executive Summary" in msg for msg in log_messages)
    assert any("Building Risk Assessment" in msg for msg in log_messages)
    assert any("Building Network Statistics" in msg for msg in log_messages)
    assert any("Building Findings" in msg for msg in log_messages)
    assert any("Building Recommendations" in msg for msg in log_messages)
    assert any("Writing Markdown report" in msg for msg in log_messages)
    assert any("Registering artifact" in msg for msg in log_messages)
    assert any("Publishing report variables" in msg for msg in log_messages)
    assert any("Report Generation completed successfully" in msg for msg in log_messages)
