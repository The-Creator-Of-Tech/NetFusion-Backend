import unittest
from unittest.mock import patch
from netfusion_canonical import NormalizationPipeline, DeadLetterQueue, PacketObserved
from netfusion_collectors.tshark import TSharkCollector
from netfusion_collector_sdk import CollectorContext


class TestFailureResiliency(unittest.TestCase):

    @patch("netfusion_collectors.tshark.runner.TSharkProcessRunner.execute")
    def test_subprocess_failure_raises_exception(self, mock_execute):
        mock_execute.return_value = (1, "", "tshark: Invalid filter specified")

        context = CollectorContext()
        collector = TSharkCollector(context=context)
        collector.configure({
            "capture_mode": "live",
            "capture_interface": "eth0",
        })

        with self.assertRaises(RuntimeError):
            collector.execute_collection()

    def test_dlq_routing_invalid_objects(self):
        pipeline = NormalizationPipeline()
        context = CollectorContext()

        # Non-canonical object
        success = pipeline.process_object("not a canonical object", context)
        self.assertFalse(success)
        self.assertEqual(len(pipeline.dlq.get_messages()), 1)
        self.assertIn("does not inherit", pipeline.dlq.get_messages()[0].errors[0])

        # Invalid PacketObserved (capture_length > frame_length)
        invalid_packet = PacketObserved(
            frame_number=1,
            frame_length=50,
            capture_length=100, # Invalid invariant!
            collector_id=context.collector_id,
            correlation_id=context.correlation_id,
        )
        success2 = pipeline.process_object(invalid_packet, context)
        self.assertFalse(success2)
        self.assertEqual(len(pipeline.dlq.get_messages()), 2)
        self.assertIn("cannot exceed frame_length", pipeline.dlq.get_messages()[1].errors[0])


if __name__ == "__main__":
    unittest.main()
