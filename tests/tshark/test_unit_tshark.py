import unittest
from netfusion_collectors.tshark.config import TSharkConfig, TSharkOutputFormat, TSharkCaptureMode
from netfusion_collectors.tshark.parsers import (
    JSONTSharkParser,
    EKJSONTSharkParser,
    PDMLTSharkParser,
    PSMLTSharkParser,
    TSharkParserFactory,
)
from netfusion_collectors.tshark.mapper import TSharkCanonicalMapper
from netfusion_collectors.tshark.health import TSharkHealthChecker
from netfusion_collector_sdk.base import CollectorContext
from netfusion_canonical import PacketObserved, NetworkFlowObserved, DNSTransactionObserved, HTTPRequestObserved


class TestTSharkUnit(unittest.TestCase):

    def test_config_validation(self):
        config = TSharkConfig(
            capture_mode=TSharkCaptureMode.OFFLINE_PCAP,
            pcap_filepath="sample.pcap",
            packet_limit=50,
            output_format=TSharkOutputFormat.JSON,
        )
        self.assertEqual(config.packet_limit, 50)
        self.assertEqual(config.output_format, TSharkOutputFormat.JSON)

    def test_json_parser(self):
        parser = JSONTSharkParser()
        raw_json = """[
            {
                "layers": {
                    "frame": {"frame.number": "1", "frame.len": "100"},
                    "eth": {"eth.src": "00:11:22:33:44:55", "eth.dst": "66:77:88:99:AA:BB"},
                    "ip": {"ip.src": "192.168.1.5", "ip.dst": "10.0.0.1"},
                    "tcp": {"tcp.srcport": "12345", "tcp.dstport": "80"}
                }
            }
        ]"""
        packets = parser.parse(raw_json)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].get("ip.src"), "192.168.1.5")
        self.assertEqual(packets[0].get("tcp.dstport"), "80")

    def test_ek_json_parser(self):
        parser = EKJSONTSharkParser()
        raw_ek = '{"index": {"_index": "packets-2026"}}\n{"layers": {"ip": {"ip.src": "1.1.1.1", "ip.dst": "8.8.8.8"}, "dns": {"dns.qry.name": "example.com"}}}'
        packets = parser.parse(raw_ek)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].get("ip.src"), "1.1.1.1")
        self.assertEqual(packets[0].get("dns.qry.name"), "example.com")

    def test_pdml_parser(self):
        parser = PDMLTSharkParser()
        raw_pdml = """<pdml version="0">
            <packet>
                <proto name="geninfo">
                    <field name="num" show="1"/>
                    <field name="len" show="60"/>
                </proto>
                <proto name="ip">
                    <field name="ip.src" show="10.1.1.1"/>
                    <field name="ip.dst" show="10.1.1.2"/>
                </proto>
            </packet>
        </pdml>"""
        packets = parser.parse(raw_pdml)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].get("ip.src"), "10.1.1.1")

    def test_psml_parser(self):
        parser = PSMLTSharkParser()
        raw_psml = """<psml version="0">
            <structure>
                <section>No.</section>
                <section>Time</section>
                <section>Source</section>
                <section>Destination</section>
                <section>Protocol</section>
                <section>Length</section>
                <section>Info</section>
            </structure>
            <packet>
                <section>1</section>
                <section>0.000000</section>
                <section>192.168.1.20</section>
                <section>1.1.1.1</section>
                <section>DNS</section>
                <section>74</section>
                <section>Standard query A test.com</section>
            </packet>
        </psml>"""
        packets = parser.parse(raw_psml)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].get("Source"), "192.168.1.20")
        self.assertEqual(packets[0].get("Destination"), "1.1.1.1")

    def test_parser_factory(self):
        json_p = TSharkParserFactory.get_parser(TSharkOutputFormat.JSON)
        pdml_p = TSharkParserFactory.get_parser(TSharkOutputFormat.PDML)
        self.assertIsInstance(json_p, JSONTSharkParser)
        self.assertIsInstance(pdml_p, PDMLTSharkParser)

    def test_canonical_mapper(self):
        mapper = TSharkCanonicalMapper()
        ctx = CollectorContext(collector_id="col-test-1", correlation_id="corr-test-1")
        pkt_dict = {
            "frame.number": "10",
            "frame.len": "120",
            "ip.src": "192.168.1.50",
            "ip.dst": "8.8.8.8",
            "tcp.srcport": "54321",
            "tcp.dstport": "443",
            "dns.qry.name": "google.com",
            "http.request.method": "GET",
            "http.request.uri": "/search",
        }
        objs = mapper.map_packet_to_canonical(pkt_dict, ctx)
        self.assertTrue(any(isinstance(o, PacketObserved) for o in objs))
        self.assertTrue(any(isinstance(o, NetworkFlowObserved) for o in objs))
        self.assertTrue(any(isinstance(o, DNSTransactionObserved) for o in objs))
        self.assertTrue(any(isinstance(o, HTTPRequestObserved) for o in objs))

    def test_health_checker(self):
        checker = TSharkHealthChecker()
        report = checker.run_all(collector_id="col-test-health")
        self.assertIn("tshark_binary_check", report.checks)
        self.assertIn("npcap_driver_check", report.checks)


if __name__ == "__main__":
    unittest.main()
