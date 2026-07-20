import os
import tempfile
import unittest
from unittest.mock import patch
from netfusion_collector_sdk import CollectorContext
from netfusion_canonical import NormalizationPipeline
from netfusion_collectors.tshark import TSharkCollector


class TestTSharkIntegration(unittest.TestCase):

    @patch("netfusion_collectors.tshark.runner.TSharkProcessRunner.execute")
    def test_full_pipeline_integration(self, mock_execute):
        sample_json = """[
            {
                "layers": {
                    "frame": {"frame.number": "1", "frame.len": "128"},
                    "ip": {"ip.src": "172.16.0.10", "ip.dst": "1.1.1.1"},
                    "tcp": {"tcp.srcport": "55555", "tcp.dstport": "443"},
                    "tls": {"tls.handshake.extensions_server_name": "cloudflare.com"}
                }
            },
            {
                "layers": {
                    "frame": {"frame.number": "2", "frame.len": "64"},
                    "ip": {"ip.src": "172.16.0.10", "ip.dst": "8.8.8.8"},
                    "udp": {"udp.srcport": "61000", "udp.dstport": "53"},
                    "dns": {"dns.qry.name": "example.org", "dns.qry.type": "A"}
                }
            }
        ]"""
        mock_execute.return_value = (0, sample_json, "")

        with tempfile.TemporaryDirectory() as tmp_dir:
            dummy_pcap = os.path.join(tmp_dir, "test.pcap")
            with open(dummy_pcap, "wb") as f:
                f.write(b"dummy pcap header content")

            context = CollectorContext(collector_id="col-integration-1")
            collector = TSharkCollector(context=context)

            pipeline = NormalizationPipeline()
            collector.initialize_runtime(pipeline=pipeline)

            collector.configure({
                "capture_mode": "pcap",
                "pcap_filepath": dummy_pcap,
                "output_format": "json",
                "temporary_storage": tmp_dir,
            })

            collector.on_pre_execute()
            result = collector.execute_collection()
            collector.on_post_execute(result)
            collector.on_cleanup()

            self.assertEqual(result.packets_captured, 2)
            self.assertGreater(result.objects_generated, 2)
            self.assertEqual(len(pipeline.dlq.get_messages()), 0)


if __name__ == "__main__":
    unittest.main()
