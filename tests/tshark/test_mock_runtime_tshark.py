import unittest
from unittest.mock import MagicMock, patch
from netfusion_collector_sdk.testing import MockCollectorRuntimeHost
from netfusion_collectors.tshark import TSharkCollector
from netfusion_canonical import NormalizationPipeline, PacketObserved, NetworkFlowObserved


class TestMockRuntimeTShark(unittest.TestCase):

    @patch("netfusion_collectors.tshark.runner.TSharkProcessRunner.execute")
    def test_mock_runtime_execution(self, mock_execute):
        # Mock TShark JSON output
        sample_json = """[
            {
                "layers": {
                    "frame": {"frame.number": "1", "frame.len": "74"},
                    "eth": {"eth.src": "00:11:22:33:44:55", "eth.dst": "66:77:88:99:AA:BB"},
                    "ip": {"ip.src": "10.0.0.5", "ip.dst": "10.0.0.1"},
                    "tcp": {"tcp.srcport": "45000", "tcp.dstport": "80"}
                }
            }
        ]"""
        mock_execute.return_value = (0, sample_json, "")

        config = {
            "capture_mode": "pcap",
            "pcap_filepath": "dummy.pcap",
            "output_format": "json",
        }

        pipeline = NormalizationPipeline()
        host = MockCollectorRuntimeHost(TSharkCollector, config)
        result = host.execute(pipeline=pipeline)

        self.assertEqual(result.packets_captured, 1)
        self.assertGreater(result.objects_generated, 0)
        self.assertEqual(len(pipeline.validated_objects), result.objects_generated)

        # Verify emitted events
        events = host.event_bus.published_events
        event_types = [e.event_type for e in events]
        self.assertIn("CollectorStartedEvent", event_types)
        self.assertIn("CanonicalObjectEvent", event_types)
        self.assertIn("CompletedEvent", event_types)


if __name__ == "__main__":
    unittest.main()
