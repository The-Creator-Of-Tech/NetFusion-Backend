import os
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from netfusion_collector_sdk.subprocess_runner import SubprocessRunner


@dataclass
class NmapHealthReport:
    status: str = "HEALTHY"
    collector_id: str = ""
    binary_available: bool = False
    binary_path: str = "nmap"
    permissions_ok: bool = True
    nse_dir_available: bool = False
    nse_dir_path: Optional[str] = None
    xml_parser_ok: bool = True
    errors: List[str] = field(default_factory=list)


class NmapHealthChecker:
    """Health check probe verifying Nmap executable, NSE scripts, XML parser, and permissions."""

    def __init__(self, binary_path: str = "nmap", nse_dir_path: Optional[str] = None):
        self.binary_path = binary_path
        self.nse_dir_path = nse_dir_path

    def check_binary_available(self) -> bool:
        path = shutil.which(self.binary_path)
        return path is not None or os.path.exists(self.binary_path)

    def check_xml_parser_available(self) -> bool:
        try:
            dummy_xml = "<nmaprun><host><status state='up'/></host></nmaprun>"
            elem = ET.fromstring(dummy_xml)
            return elem.tag == "nmaprun"
        except Exception:
            return False

    def check_nse_dir_available(self) -> Tuple[bool, Optional[str]]:
        if self.nse_dir_path and os.path.exists(self.nse_dir_path):
            return True, self.nse_dir_path

        # Common nse script paths
        candidates = [
            "/usr/share/nmap/scripts",
            "/usr/local/share/nmap/scripts",
            "C:\\Program Files (x86)\\Nmap\\scripts",
            "C:\\Program Files\\Nmap\\scripts",
        ]
        for c in candidates:
            if os.path.exists(c):
                return True, c
        return False, None

    def run_all(self, collector_id: str = "") -> NmapHealthReport:
        report = NmapHealthReport(collector_id=collector_id, binary_path=self.binary_path)

        report.binary_available = self.check_binary_available()
        if not report.binary_available:
            report.errors.append(f"Nmap binary not found at '{self.binary_path}'")

        report.xml_parser_ok = self.check_xml_parser_available()
        if not report.xml_parser_ok:
            report.errors.append("Python xml.etree.ElementTree parser is unavailable or corrupted.")

        nse_ok, nse_path = self.check_nse_dir_available()
        report.nse_dir_available = nse_ok
        report.nse_dir_path = nse_path

        if report.errors:
            report.status = "UNHEALTHY"
        else:
            report.status = "HEALTHY"

        return report
