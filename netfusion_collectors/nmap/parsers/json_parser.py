import json
from typing import Any, Dict, List
from .base import BaseNmapParser
from .xml_parser import XMLNmapParser


class JSONNmapParser(BaseNmapParser):
    """Parses JSON-formatted Nmap wrapper output or delegates XML to JSON conversion."""

    def __init__(self):
        self._xml_parser = XMLNmapParser()

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        cleaned = raw_output.strip()

        # Try parsing as JSON first
        if cleaned.startswith("{") or cleaned.startswith("["):
            try:
                data = json.loads(cleaned)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    if "hosts" in data and isinstance(data["hosts"], list):
                        return data["hosts"]
                    return [data]
            except Exception:
                pass

        # Fallback to XML parser
        return self._xml_parser.parse(raw_output)
