from enum import Enum
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field
from netfusion_collector_sdk.config import CollectorConfig


class EventSourceType(str, Enum):
    WINDOWS_EVENT_LOG = "WINDOWS_EVENT_LOG"
    EVTX_FILE = "EVTX_FILE"


class CollectionMode(str, Enum):
    LIVE_EVENT_LOG = "LIVE_EVENT_LOG"
    OFFLINE_EVTX = "OFFLINE_EVTX"
    INCREMENTAL = "INCREMENTAL"
    HISTORICAL_REPLAY = "HISTORICAL_REPLAY"
    STREAMING = "STREAMING"


class AuthMode(str, Enum):
    DEFAULT = "DEFAULT"
    KERBEROS = "KERBEROS"
    NTLM = "NTLM"
    NEGOTIATE = "NEGOTIATE"


class HashAlgorithm(str, Enum):
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    IMPHASH = "IMPHASH"
    ANY = "ANY"


DEFAULT_SYSMON_EVENT_IDS = [
    1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26
]


class SysmonConfig(CollectorConfig):
    # General Configuration
    event_source: EventSourceType = Field(
        default=EventSourceType.WINDOWS_EVENT_LOG,
        description="Event source (Windows Event Log or EVTX file)",
    )
    collection_mode: CollectionMode = Field(
        default=CollectionMode.LIVE_EVENT_LOG,
        description="Collection operational mode (LIVE_EVENT_LOG, OFFLINE_EVTX, INCREMENTAL, HISTORICAL_REPLAY, STREAMING)",
    )
    evtx_file_path: Optional[str] = Field(
        default=None,
        description="Path to offline EVTX log file when event_source is EVTX_FILE or mode is OFFLINE_EVTX",
    )
    event_ids: List[int] = Field(
        default_factory=lambda: list(DEFAULT_SYSMON_EVENT_IDS),
        description="List of Sysmon Event IDs to collect",
    )
    start_time: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp filter for collection start time",
    )
    end_time: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp filter for collection end time",
    )
    batch_size: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Number of events per processing batch",
    )
    poll_interval: float = Field(
        default=1.0,
        ge=0.1,
        le=3600.0,
        description="Polling interval in seconds for live / streaming collection",
    )
    bookmark_path: Optional[str] = Field(
        default=None,
        description="Path for persistent bookmark storage for incremental collection",
    )
    persist_bookmark: bool = Field(
        default=True,
        description="Enable stateful bookmark persistence",
    )
    max_events: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum total events to ingest before stopping",
    )

    # Windows Configuration
    channel: str = Field(
        default="Microsoft-Windows-Sysmon/Operational",
        description="Windows Event Log channel name",
    )
    remote_server: Optional[str] = Field(
        default=None,
        description="Remote Windows server hostname or IP address for remote log collection",
    )
    username: Optional[str] = Field(
        default=None,
        description="Username for remote Windows Event Log authentication",
    )
    password: Optional[str] = Field(
        default=None,
        description="Password for remote Windows Event Log authentication",
    )
    domain: Optional[str] = Field(
        default=None,
        description="Domain for remote Windows authentication",
    )
    auth_mode: AuthMode = Field(
        default=AuthMode.DEFAULT,
        description="Authentication mode for remote event log collection",
    )

    # Filtering Options
    filter_host: Optional[str] = Field(
        default=None,
        description="Filter events by host computer name",
    )
    filter_username: Optional[str] = Field(
        default=None,
        description="Filter events by username",
    )
    filter_process_name: Optional[str] = Field(
        default=None,
        description="Filter events by process name (e.g., cmd.exe)",
    )
    filter_parent_process: Optional[str] = Field(
        default=None,
        description="Filter events by parent process name",
    )
    filter_image_path: Optional[str] = Field(
        default=None,
        description="Filter events by process image path",
    )
    filter_command_line: Optional[str] = Field(
        default=None,
        description="Filter events by command line substring",
    )
    filter_event_id: Optional[List[int]] = Field(
        default=None,
        description="Filter events by explicit Event ID list",
    )
    filter_hash_algorithm: Optional[HashAlgorithm] = Field(
        default=None,
        description="Filter events requiring specific hash algorithm presence",
    )
    filter_network_dest: Optional[str] = Field(
        default=None,
        description="Filter network events by destination IP or hostname",
    )
