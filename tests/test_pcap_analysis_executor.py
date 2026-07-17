import os
import uuid
from services.workflow_execution_service import (
    WorkflowExecutionContext,
    WorkflowExecutionManager,
    StepExecutor,
    _REGISTRY
)

def test_pcap_analysis_executor_integration():
    # Verify file existence of a sample capture
    pcap_dir = r"c:\Netfusion\NetFusion-Agent\Captured_packets"
    sample_file = os.path.join(pcap_dir, "live_capture.pcapng")
    assert os.path.exists(sample_file), f"Test requires {sample_file} to exist."

    # Create a 2-step playbook context:
    # Step 1: PCAP Analysis (using variable placeholder binding pointing to capture_file)
    # Step 2: Custom assertion step to check variable consumption
    execution_id = str(uuid.uuid4())
    
    # We will seed the capture_file in the variables registry to verify resolve_variables
    ctx = WorkflowExecutionContext(
        execution_id=execution_id,
        playbook_id="integration-test-pb",
        playbook_name="Integration Test Playbook",
        steps=[
            {
                "stepId": "analysis-step",
                "title": "Analyze PCAP",
                "stepType": "AUTOMATED",
                "stepNumber": 1,
                # No explicit executor key to test can_execute fallback mapping!
                "config": {
                    "capture_file": "${capture_file}"  # Resolves from variable registry
                }
            },
            {
                "stepId": "downstream-step",
                "title": "Evaluate Threat Indicators",
                "stepType": "AUTOMATED",
                "stepNumber": 2,
                "executor": "test_assert_executor",
                "config": {
                    "injected_dns": "${dns_queries}",
                    "injected_http": "${http_hosts}",
                    "injected_tls": "${tls_sessions}",
                    "injected_endpoints": "${endpoints}",
                    "injected_stats": "${statistics}"
                }
            }
        ],
        total_steps=2
    )

    # Pre-seed variables registry with capture_file
    ctx.set_variable("capture_file", sample_file, "file")

    # Define a custom downstream executor to assert that variables are successfully resolved
    class TestAssertExecutor(StepExecutor):
        identifier = "test_assert_executor"
        def can_execute(self, step):
            return step.get("executor") == "test_assert_executor"
            
        def _execute_internal(self, step, ctx):
            config = step.get("config") or {}
            dns = config.get("injected_dns")
            http = config.get("injected_http")
            tls = config.get("injected_tls")
            endpoints = config.get("injected_endpoints")
            stats = config.get("injected_stats")

            # Check variable values passed down
            assert isinstance(dns, list), "dns_queries should be list"
            assert isinstance(http, list), "http_hosts should be list"
            assert isinstance(tls, list), "tls_sessions should be list"
            assert isinstance(endpoints, list), "endpoints should be list"
            assert isinstance(stats, dict), "statistics should be dict"

            # Check that TShark actually found values
            assert "protocols" in ctx.variables, "protocols variable missing"
            assert "analysis_summary" in ctx.variables, "analysis_summary variable missing"
            
            return {
                "success": True,
                "summary": "Downstream step successfully consumed all published variables."
            }

    # Register our temporary test assert executor
    _REGISTRY.register(TestAssertExecutor())

    try:
        # Run workflow
        WorkflowExecutionManager.run_execution_background(ctx)

        # Assert status
        assert ctx.status == "COMPLETED", f"Execution failed: {ctx.returned_summary}"
        assert ctx.completed_steps == 2, f"Completed steps: {ctx.completed_steps}"

        # Assert variables registry contents
        assert "protocols" in ctx.variables
        assert "dns_queries" in ctx.variables
        assert "http_hosts" in ctx.variables
        assert "tls_sessions" in ctx.variables
        assert "conversations" in ctx.variables
        assert "endpoints" in ctx.variables
        assert "statistics" in ctx.variables
        assert "analysis_summary" in ctx.variables

        # Assert variable types and creators
        assert ctx.variables["protocols"]["type"] == "array"
        assert ctx.variables["protocols"]["createdBy"] == "PCAPAnalysisExecutor"
        assert ctx.variables["dns_queries"]["type"] == "array"
        assert ctx.variables["dns_queries"]["createdBy"] == "PCAPAnalysisExecutor"
        assert ctx.variables["statistics"]["type"] == "object"
        assert ctx.variables["statistics"]["createdBy"] == "PCAPAnalysisExecutor"
        assert ctx.variables["analysis_summary"]["type"] == "string"
        assert ctx.variables["analysis_summary"]["createdBy"] == "PCAPAnalysisExecutor"

        # Assert report artifact creation
        artifacts = ctx.list_artifacts()
        assert len(artifacts) > 0, "No artifacts were created"
        pcap_artifact = next((a for a in artifacts if a.type == "markdown"), None)
        assert pcap_artifact is not None, "PCAP analysis markdown report artifact is missing"
        assert os.path.exists(pcap_artifact.location), "Artifact file does not exist on disk"
        assert pcap_artifact.producerExecutor == "PCAPAnalysisExecutor"
        
        # Verify content of the report file
        with open(pcap_artifact.location, "r", encoding="utf-8") as f:
            content = f.read()
            assert "# PCAP Analysis Report" in content
            assert "## Extracted Statistics" in content
            assert "## Protocol Summary" in content
            assert "## DNS Summary" in content
            assert "## HTTP Summary" in content
            assert "## TLS Summary" in content
            assert "## Conversation Summary" in content

    finally:
        # Cleanup registered test executor
        _REGISTRY._executors = [e for e in _REGISTRY._executors if e.identifier != "test_assert_executor"]
        if "test_assert_executor" in _REGISTRY._executors_by_id:
            del _REGISTRY._executors_by_id["test_assert_executor"]


def test_pcap_analysis_executor_key_normalization():
    pcap_dir = r"c:\Netfusion\NetFusion-Agent\Captured_packets"
    sample_file = os.path.join(pcap_dir, "live_capture.pcapng")
    assert os.path.exists(sample_file), f"Test requires {sample_file} to exist."

    executor = next(e for e in _REGISTRY._executors if e.identifier == "pcap_analysis")

    # Let's test with 'pcap_file' configuration key which is used by the frontend
    ctx = WorkflowExecutionContext(
        execution_id="test-normalization-id",
        playbook_id="test-normalization-pb",
        playbook_name="Test Normalization Playbook",
        steps=[],
        total_steps=1
    )

    step = {
        "stepId": "analysis-step",
        "title": "Analyze PCAP",
        "stepType": "AUTOMATED",
        "config": {
            "pcap_file": sample_file
        }
    }

    result = executor.execute(step, ctx)
    assert result.get("success") is True, f"Execution failed: {result.get('error')}"
    assert "capture_file" in step["config"]
    assert step["config"]["capture_file"] == sample_file

