import json
from typing import Any, Dict, List
from .base import BaseTSharkParser


class EKJSONTSharkParser(BaseTSharkParser):
    """Parser for Elastic / EK NDJSON TShark format (`-T ek`)."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        packets: List[Dict[str, Any]] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    continue

                # Skip ES index metadata lines (e.g. {"index": {...}})
                if "index" in data:
                    continue

                layers = data.get("layers", data)
                flattened_packet: Dict[str, Any] = {"raw_layers": layers}
                if isinstance(layers, dict):
                    def _extract(d: Dict[str, Any]):
                        for k, v in d.items():
                            if isinstance(v, dict):
                                _extract(v)
                            else:
                                flattened_packet[k] = v
                    _extract(layers)

                packets.append(flattened_packet)
            except json.JSONDecodeError:
                continue

        return packets
