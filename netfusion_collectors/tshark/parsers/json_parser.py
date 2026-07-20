import json
from typing import Any, Dict, List
from .base import BaseTSharkParser


class JSONTSharkParser(BaseTSharkParser):
    """Parser for standard TShark JSON format (`-T json`)."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        parsed_data = json.loads(raw_output)
        if not isinstance(parsed_data, list):
            parsed_data = [parsed_data]

        packets: List[Dict[str, Any]] = []
        for packet_entry in parsed_data:
            if not isinstance(packet_entry, dict):
                continue

            # Handles both `_source.layers` format and raw `layers` format
            layers = (
                packet_entry.get("_source", {}).get("layers")
                or packet_entry.get("layers")
                or packet_entry
            )

            flattened_packet: Dict[str, Any] = {"raw_layers": layers}
            if isinstance(layers, dict):

                def _extract_fields(d: Dict[str, Any]):
                    for k, v in d.items():
                        if isinstance(v, dict):
                            _extract_fields(v)
                        else:
                            flattened_packet[k] = v

                _extract_fields(layers)

            packets.append(flattened_packet)

        return packets
