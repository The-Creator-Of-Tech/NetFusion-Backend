import unittest
import uuid
from datetime import datetime
from services.workflow_execution_service import (
    WorkflowExecutionContext,
    resolve_variables,
    StepExecutorRegistry,
    StepRunner
)

class TestVariableRegistryAndResolver(unittest.TestCase):
    def setUp(self):
        self.execution_id = str(uuid.uuid4())
        self.ctx = WorkflowExecutionContext(
            execution_id=self.execution_id,
            playbook_id="test-pb-1",
            playbook_name="Test Playbook",
            steps=[],
            total_steps=1,
            project_id="test-project"
        )

    def test_variable_type_inference_and_metadata(self):
        self.ctx.current_executor = "TestExecutor"
        self.ctx.current_step_number = 4

        # Test boolean
        self.ctx.set_variable("var_bool", True)
        var = self.ctx.variables["var_bool"]
        self.assertEqual(var["name"], "var_bool")
        self.assertEqual(var["type"], "boolean")
        self.assertEqual(var["value"], True)
        self.assertEqual(var["createdBy"], "TestExecutor")
        self.assertEqual(var["stepNumber"], 4)
        self.assertTrue("createdAt" in var)

        # Test number
        self.ctx.setVariable("var_num", 42.5)
        self.assertEqual(self.ctx.getVariable("var_num"), 42.5)
        self.assertEqual(self.ctx.variables["var_num"]["type"], "number")

        # Test array
        self.ctx.setVariable("var_arr", [1, 2, 3])
        self.assertEqual(self.ctx.getVariable("var_arr"), [1, 2, 3])
        self.assertEqual(self.ctx.variables["var_arr"]["type"], "array")

        # Test object
        self.ctx.setVariable("var_obj", {"key": "val"})
        self.assertEqual(self.ctx.getVariable("var_obj"), {"key": "val"})
        self.assertEqual(self.ctx.variables["var_obj"]["type"], "object")

        # Test string
        self.ctx.setVariable("var_str", "hello")
        self.assertEqual(self.ctx.getVariable("var_str"), "hello")
        self.assertEqual(self.ctx.variables["var_str"]["type"], "string")

        # Test file path string -> should infer as file
        # Starts with memory://
        self.ctx.setVariable("var_file_mem", "memory://capture.pcap")
        self.assertEqual(self.ctx.variables["var_file_mem"]["type"], "file")
        # Has absolute path or file suffix
        self.ctx.setVariable("var_file_suffix", "C:\\some\\path\\file.json")
        self.assertEqual(self.ctx.variables["var_file_suffix"]["type"], "file")

        # Test json string
        self.ctx.setVariable("var_json_str", '{"a": 1, "b": [true]}')
        self.assertEqual(self.ctx.variables["var_json_str"]["type"], "json")

    def test_legacy_flat_compatibility(self):
        # Inject variable directly as a flat string (legacy style)
        self.ctx.variables["legacy_var"] = "legacy_value"

        # get_variable should return it cleanly
        self.assertEqual(self.ctx.get_variable("legacy_var"), "legacy_value")
        self.assertTrue(self.ctx.has_variable("legacy_var"))

        # list_variables should convert it to structured on-the-fly
        vars_list = self.ctx.list_variables()
        legacy_struct = next(v for v in vars_list if v["name"] == "legacy_var")
        self.assertEqual(legacy_struct["value"], "legacy_value")
        self.assertEqual(legacy_struct["type"], "string")
        self.assertEqual(legacy_struct["createdBy"], "legacy")

    def test_variable_resolution_exact_match(self):
        self.ctx.setVariable("ip", "10.0.0.1", "string")
        self.ctx.setVariable("ports", [22, 80], "array")
        self.ctx.setVariable("is_valid", True, "boolean")

        config = {
            "target_host": "${ip}",
            "scan_ports": "${ports}",
            "debug_mode": "${is_valid}",
            "nested": {
                "inner_host": "${ip}"
            }
        }

        resolved = resolve_variables(config, self.ctx)
        # Type must be preserved in exact matches
        self.assertEqual(resolved["target_host"], "10.0.0.1")
        self.assertEqual(resolved["scan_ports"], [22, 80])
        self.assertEqual(resolved["debug_mode"], True)
        self.assertEqual(resolved["nested"]["inner_host"], "10.0.0.1")

    def test_variable_resolution_substring_interpolation(self):
        self.ctx.setVariable("host", "example.com", "string")
        self.ctx.setVariable("port", 8080, "number")
        self.ctx.setVariable("endpoints", ["/v1", "/v2"], "array")

        config = {
            "api_url": "http://${host}:${port}/api",
            "routes": "Available routes: ${endpoints}",
            "unresolved": "Hello ${missing_var}"
        }

        resolved = resolve_variables(config, self.ctx)
        self.assertEqual(resolved["api_url"], "http://example.com:8080/api")
        self.assertEqual(resolved["routes"], 'Available routes: ["/v1", "/v2"]')
        self.assertEqual(resolved["unresolved"], "Hello ${missing_var}")

if __name__ == "__main__":
    unittest.main()
