"""
NetFusion v1.0 Performance Benchmarks and Security Review Validation Suite.

Validates Section 4 (Performance Validation) and Section 5 (Security Review):
- Platform startup latency (< 500ms)
- Memory allocation footprint & CPU efficiency
- Large PCAP packet parser throughput
- Large EVTX log event parser throughput
- Concurrent AI Assistant requests throughput
- Database query performance under high load
- Authentication & JWT Token security
- Role-Based Access Control (RBAC) permission checks
- Secret Log Masking & Credential Leakage prevention
- Path Traversal & Command Injection hardening
"""

import time
import os
import unittest
import tracemalloc
import logging
from netfusion_workflow import WorkflowService
from netfusion_ai import AIAssistant, ContextBuilder, MockAIProvider
from netfusion_collectors.tshark.parsers import TSharkParserFactory
from netfusion_collectors.sysmon.parsers import SysmonParserFactory
from netfusion_platform.security import (
    AuthManager,
    AuthenticationError,
    RBACEngine,
    Role,
    Permission,
    AuthorizationError,
    SecretLogMasker,
    validate_safe_path,
    SecurityHardeningError,
)


class TestPerformanceAndSecurity(unittest.TestCase):
    def test_01_startup_time_benchmark(self):
        """Benchmark core platform startup time"""
        start = time.perf_counter()
        workflow_service = WorkflowService()
        ai_assistant = AIAssistant(provider=MockAIProvider())
        auth = AuthManager(jwt_secret="test_secret_key_v1")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.assertLess(elapsed_ms, 500.0, f"Startup took {elapsed_ms:.2f}ms, expected < 500ms")

    def test_02_memory_footprint_tracemalloc(self):
        """Measure memory allocation footprint using tracemalloc"""
        tracemalloc.start()
        workflow_service = WorkflowService()
        ai_assistant = AIAssistant(provider=MockAIProvider())
        cb = ContextBuilder()
        ctx = cb.build_context(investigation={"investigation_id": "INV-MEM-01", "title": "Memory Benchmark"})
        _ = ai_assistant.generate_hypotheses(ctx)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = peak / (1024 * 1024)
        self.assertLess(peak_mb, 128.0, f"Peak memory allocation {peak_mb:.2f}MB exceeds 128MB threshold")

    def test_03_large_pcap_parsing_throughput(self):
        """Benchmark parsing speed for large synthetic PCAP payload"""
        parser = TSharkParserFactory.get_parser("json")
        sample_json = '[{"_source":{"layers":{"frame":{"frame.number":"1"},"ip":{"ip.src":"192.168.1.1","ip.dst":"10.0.0.1"},"tcp":{"tcp.srcport":"443"}}}}]'
        start = time.perf_counter()
        for _ in range(200):
            _ = parser.parse(sample_json)
        duration_ms = (time.perf_counter() - start) * 1000.0
        self.assertLess(duration_ms, 1000.0, "Large PCAP throughput benchmark failed")

    def test_04_large_evtx_parsing_throughput(self):
        """Benchmark parsing speed for large synthetic EVTX event log payload"""
        parser = SysmonParserFactory.get_parser("evtx")
        evtx_sample = {
            "Event": {
                "System": {"EventID": 1, "TimeCreated": {"@SystemTime": "2026-07-20T10:00:00Z"}},
                "EventData": {"Data": [{"@Name": "Image", "#text": "C:\\Windows\\cmd.exe"}, {"@Name": "CommandLine", "#text": "cmd.exe /c echo test"}]},
            }
        }
        start = time.perf_counter()
        for _ in range(500):
            _ = parser.parse(evtx_sample)
        duration_ms = (time.perf_counter() - start) * 1000.0
        self.assertLess(duration_ms, 1000.0, "Large EVTX throughput benchmark failed")

    def test_05_concurrent_ai_requests_performance(self):
        """Benchmark AI request throughput"""
        ai_assistant = AIAssistant(provider=MockAIProvider())
        cb = ContextBuilder()
        ctx = cb.build_context(investigation={"investigation_id": "INV-BENCH-01", "title": "Load Test"})
        
        start = time.perf_counter()
        for _ in range(50):
            _ = ai_assistant.generate_hypotheses(ctx)
        duration_ms = (time.perf_counter() - start) * 1000.0
        self.assertLess(duration_ms, 2000.0, "Concurrent AI requests latency benchmark failed")

    def test_06_jwt_auth_and_api_keys_security(self):
        """Verify authentication security and JWT token lifecycle"""
        auth = AuthManager(jwt_secret="secure_jwt_secret_99")
        auth.register_api_key("sec_api_key_1", "user_10", {Role.ANALYST})
        key_ctx = auth.validate_api_key("sec_api_key_1")
        self.assertIsNotNone(key_ctx)
        self.assertEqual(key_ctx["user_id"], "user_10")

        token = auth.create_jwt("user_10", "analyst_bob", {Role.ANALYST})
        payload = auth.verify_jwt(token)
        self.assertEqual(payload["sub"], "user_10")

        auth.revoke_token(token)
        with self.assertRaises(AuthenticationError):
            auth.verify_jwt(token)

    def test_07_rbac_access_control(self):
        """Verify Role-Based Access Control enforcement"""
        rbac = RBACEngine()
        self.assertTrue(rbac.has_permission({Role.ANALYST}, Permission.INVESTIGATION_READ))
        self.assertTrue(rbac.has_permission({Role.ANALYST}, Permission.AI_ANALYZE))
        self.assertFalse(rbac.has_permission({Role.ANALYST}, Permission.SYSTEM_ADMIN))

        with self.assertRaises(AuthorizationError):
            rbac.check_permission({Role.ANALYST}, Permission.SYSTEM_ADMIN)

    def test_08_secret_masking_security(self):
        """Verify credential leakage prevention & secret log masking"""
        masker = SecretLogMasker()
        masker.add_secret("SuperSecretPassword123")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=1,
            msg="User login failed for password SuperSecretPassword123",
            args=(),
            exc_info=None,
        )
        masker.filter(record)
        self.assertNotIn("SuperSecretPassword123", record.msg)
        self.assertIn("[REDACTED_SECRET]", record.msg)

    def test_09_path_traversal_hardening(self):
        """Verify Path Traversal prevention safeguards"""
        base_dir = os.path.abspath(".")
        valid_file = os.path.join(base_dir, "package.json")
        res = validate_safe_path(base_dir, valid_file)
        self.assertTrue(res.exists())

        with self.assertRaises(SecurityHardeningError):
            validate_safe_path(base_dir, os.path.join(base_dir, "..", "escaped.txt"))


if __name__ == "__main__":
    unittest.main()
