import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from .base import BaseTSharkParser


class PSMLTSharkParser(BaseTSharkParser):
    """Parser for Packet Summary Markup Language (PSML) XML output (`-T psml`)."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        packets: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return packets

        # Extract column names from structure element
        column_names: List[str] = []
        struct_elem = root.find("structure")
        if struct_elem is not None:
            for section in struct_elem.findall("section"):
                column_names.append((section.text or "").strip())

        default_headers = ["frame.number", "frame.time", "ip.src", "ip.dst", "frame.protocols", "frame.len", "info"]

        for packet_elem in root.findall("packet"):
            packet_data: Dict[str, Any] = {}
            sections = packet_elem.findall("section")
            for idx, sec in enumerate(sections):
                col_name = column_names[idx] if idx < len(column_names) else (default_headers[idx] if idx < len(default_headers) else f"col_{idx}")
                packet_data[col_name] = (sec.text or "").strip()

            packets.append(packet_data)

        return packets
