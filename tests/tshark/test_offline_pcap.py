import os
import tempfile
import unittest
from unittest.mock import patch
from netfusion_collectors.tshark import TSharkCollector, TSharkConfig, TSharkCaptureMode, TSharkOutputFormat
from netfusion_collector_sdk import CollectorContext


class TestOfflinePCAP(unittest.TestCase):

    @patch("netfusion_collectors.tshark.runner.TSharkProcessRunner.execute")
    def test_offline_pcap_mode(self, mock_execute):
        mock_execute.return_value = (0, '[\n  {\n    "layers": {\n      "frame": {"frame.number": "1", "frame.len": "54"}\n    }\n  }\n]', "")

        with tempfile.TemporaryDirectory() as tmp_dir:
            pcap_file = os.path.join(tmp_dir, "sample.pcap")
            with open(pcap_file, "w") as f:
                f.write("mock pcap")

            context = CollectorContext()
            collector = TSharkCollector(context=context)
            collector.configure({
                "capture_mode": TSharkCaptureMode.OFFLINE_PCAP.value,
                "pcap_filepath": pcap_file,
                "output_format": TSharkOutputFormat.JSON.value,
                "temporary_storage": tmp_dir,
            })

            collector.on_pre_execute()
            result = collector.execute_collection()

            self.assertEqual(result.packets_captured, 1)

    @patch("netfusion_collectors.tshark.runner.TSharkProcessRunner.execute")
    def test_offline_pcapng_mode(self, mock_execute):
        mock_execute.return_value = (0, '[\n  {\n    "layers": {\n      "frame": {"frame.number": "1", "frame.len": "1500"}\n    }\n  }\n]', "")

        with tempfile.TemporaryDirectory() as tmp_dir:
            pcapng_file = os.path.join(tmp_dir, "sample.pcapng")
            with open(pcapng_file, "w") as f:
                f.write("mock pcapng")

            context = CollectorContext()
            collector = TSharkCollector(context=context)
            collector.configure({
                "capture_mode": TSharkCaptureMode.OFFLINE_PCAPNG.value,
                "pcap_filepath": pcapng_file,
                "output_format": TSharkOutputFormat.JSON.value,
                "temporary_storage": tmp_dir,
            })

            collector.on_pre_execute()
            result = collector.execute_collection()

            self.assertEqual(result.packets_captured, 1)


if __name__ == "__main__":
    unittest.main()
