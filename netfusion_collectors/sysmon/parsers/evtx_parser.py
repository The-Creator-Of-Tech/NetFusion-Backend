import os
from typing import Any, Dict, List, Union, Optional
from .base import BaseSysmonParser
from .xml_parser import XmlSysmonParser

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    HAS_PYTHON_EVTX = True
except ImportError:
    HAS_PYTHON_EVTX = False


class EvtxSysmonParser(BaseSysmonParser):
    """
    Parser for Microsoft EVTX binary log files or EVTX raw stream content.
    Uses Python Evtx module when available, falling back to XmlSysmonParser for extracted XML logs.
    """

    def __init__(self):
        self._xml_parser = XmlSysmonParser()

    def parse(self, raw_data: Union[str, bytes, List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
        # If passed file path string ending in .evtx or existing file path
        if isinstance(raw_data, str) and (raw_data.lower().endswith(".evtx") or os.path.exists(raw_data)):
            return self.parse_evtx_file(raw_data)

        # If passed list of dicts or XML string/bytes
        if isinstance(raw_data, (list, dict)):
            return self._xml_parser.parse(raw_data)

        if isinstance(raw_data, (str, bytes)):
            # Try XML parser first
            parsed = self._xml_parser.parse(raw_data)
            if parsed:
                return parsed
            
        return []

    def parse_evtx_file(self, file_path: str, max_records: Optional[int] = None) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        if HAS_PYTHON_EVTX:
            try:
                with evtx.Evtx(file_path) as log:
                    count = 0
                    for record in log.records():
                        xml_str = record.xml()
                        events = self._xml_parser.parse(xml_str)
                        results.extend(events)
                        count += 1
                        if max_records and count >= max_records:
                            break
                return results
            except Exception as e:
                # If evtx parsing encounters issue, fallback to reading as binary/string
                pass

        # Alternative fallback read file if plaintext XML or pseudo-xml content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                return self._xml_parser.parse(content)
        except Exception:
            return []
