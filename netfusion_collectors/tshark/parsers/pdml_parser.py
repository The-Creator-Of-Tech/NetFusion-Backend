import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from .base import BaseTSharkParser


class PDMLTSharkParser(BaseTSharkParser):
    """Parser for Packet Details Markup Language (PDML) XML output (`-T pdml`)."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        packets: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return packets

        for packet_elem in root.findall("packet"):
            packet_data: Dict[str, Any] = {}
            for proto_elem in packet_elem.findall("proto"):
                proto_name = proto_elem.attrib.get("name")
                for field_elem in proto_elem.findall(".//field"):
                    field_name = field_elem.attrib.get("name")
                    show_val = field_elem.attrib.get("show") or field_elem.attrib.get("value")
                    if field_name and show_val is not None:
                        packet_data[field_name] = show_val

            packets.append(packet_data)

        return packets
