from enum import Enum
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field
from netfusion_collector_sdk.config import CollectorConfig


class NmapScanType(str, Enum):
    SYN = "SYN"
    CONNECT = "CONNECT"
    UDP = "UDP"
    ACK = "ACK"
    NULL = "NULL"
    FIN = "FIN"
    XMAS = "XMAS"
    PING = "PING"


class NmapTimingTemplate(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"


class NmapOutputFormat(str, Enum):
    XML = "xml"
    JSON = "json"
    GREPABLE = "grepable"


class NmapDNSResolution(str, Enum):
    ALWAYS = "always"
    NEVER = "never"
    DEFAULT = "default"


class NmapConfig(CollectorConfig):
    targets: Union[List[str], str] = Field(
        default_factory=lambda: ["127.0.0.1"],
        description="Target host(s), subnet(s), CIDR ranges, or hostname(s)",
    )
    target_file: Optional[str] = Field(
        default=None,
        description="Path to file containing list of targets (-iL)",
    )
    scan_type: NmapScanType = Field(
        default=NmapScanType.SYN,
        description="Nmap scan technique (-sS, -sT, -sU, -sA, -sN, -sF, -sX, -sn)",
    )
    ports: Optional[str] = Field(
        default=None,
        description="Port specification (e.g. '80,443', '1-1024', 'U:53,T:21-25,80')",
    )
    timing_template: NmapTimingTemplate = Field(
        default=NmapTimingTemplate.T3,
        description="Timing template (-T0 to -T5)",
    )
    skip_host_discovery: bool = Field(
        default=False,
        description="Skip host discovery and treat all hosts as online (-Pn)",
    )
    ping_scan_only: bool = Field(
        default=False,
        description="Host discovery only, disable port scan (-sn)",
    )
    service_version_detection: bool = Field(
        default=True,
        description="Enable service version detection (-sV)",
    )
    version_intensity: Optional[int] = Field(
        default=None,
        ge=0,
        le=9,
        description="Set version scan intensity (0 to 9, --version-intensity)",
    )
    os_detection: bool = Field(
        default=False,
        description="Enable OS fingerprinting detection (-O)",
    )
    os_limit: bool = Field(
        default=False,
        description="Limit OS detection to promising targets (--osscan-limit)",
    )
    script_categories: List[str] = Field(
        default_factory=list,
        description="NSE script categories (e.g. ['default', 'vuln', 'discovery'])",
    )
    scripts: List[str] = Field(
        default_factory=list,
        description="Individual NSE scripts (e.g. ['http-headers', 'ssl-cert'])",
    )
    script_args: Dict[str, str] = Field(
        default_factory=dict,
        description="NSE script arguments (--script-args)",
    )
    output_format: NmapOutputFormat = Field(
        default=NmapOutputFormat.XML,
        description="Output format (xml, json, grepable)",
    )
    ipv6: bool = Field(
        default=False,
        description="Enable IPv6 scanning (-6)",
    )
    dns_resolution: NmapDNSResolution = Field(
        default=NmapDNSResolution.DEFAULT,
        description="DNS resolution controls (-n for never, -R for always)",
    )
    min_rate: Optional[int] = Field(
        default=None,
        ge=1,
        description="Send packets no slower than N per second (--min-rate)",
    )
    max_rate: Optional[int] = Field(
        default=None,
        ge=1,
        description="Send packets no faster than N per second (--max-rate)",
    )
    binary_path: str = Field(
        default="nmap",
        description="Path to nmap executable binary",
    )
    temporary_workspace: str = Field(
        default="/tmp/netfusion",
        description="Directory for temporary scan artifacts",
    )
