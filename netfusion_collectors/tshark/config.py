from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from netfusion_collector_sdk.config import CollectorConfig


class TSharkOutputFormat(str, Enum):
    JSON = "json"
    EK_JSON = "ek"
    PDML = "pdml"
    PSML = "psml"


class TSharkCaptureMode(str, Enum):
    LIVE_CAPTURE = "live"
    OFFLINE_PCAP = "pcap"
    OFFLINE_PCAPNG = "pcapng"
    STREAMING = "streaming"


class TSharkConfig(CollectorConfig):
    capture_interface: Optional[str] = Field(default=None, description="Network interface name (e.g. eth0, Wi-Fi, 1)")
    pcap_filepath: Optional[str] = Field(default=None, description="Path to offline PCAP/PCAPNG file")
    capture_mode: TSharkCaptureMode = Field(default=TSharkCaptureMode.OFFLINE_PCAP)
    capture_duration: Optional[int] = Field(default=None, ge=1, le=86400, description="Duration in seconds (-a duration:N)")
    packet_limit: Optional[int] = Field(default=None, ge=1, description="Max packets to capture/read (-c N)")
    bpf_filter: Optional[str] = Field(default=None, description="Berkeley Packet Filter string (-f filter)")
    promiscuous_mode: bool = Field(default=True, description="Enable promiscuous mode (-p)")
    monitor_mode: bool = Field(default=False, description="Enable monitor mode (-I)")
    output_format: TSharkOutputFormat = Field(default=TSharkOutputFormat.JSON, description="Output format (json, ek, pdml, psml)")
    tshark_path: str = Field(default="tshark", description="Path to tshark executable binary")
    display_filter: Optional[str] = Field(default=None, description="TShark display filter (-Y filter)")
