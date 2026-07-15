"""
Capture Service — live capture lifecycle and PCAP analysis orchestration.

Responsibilities:
  - Manage live tshark capture process (start / stop / state)
  - Track active capture file paths and last analyzed file
  - Orchestrate PCAP analysis: parse → traffic intelligence → assets
  - Expose capture state accessors to route handlers

This module has no knowledge of FastAPI, routes, or HTTP responses.
It coordinates: packet_service → traffic_intelligence_service → build_assets_from_packets
"""

import json
import os
import subprocess
import time

from core.config import TSHARK_PATH
from services import packet_service
from services.asset_service import build_assets_from_packets


# ---------------------------------------------------------------------------
# Module-level capture state  (replaces main.py globals)
# ---------------------------------------------------------------------------

_capture_process: subprocess.Popen = None
_capture_file: str = None
_last_capture_file: str = None
_last_analyzed_file: str = None
_latest_traffic_intelligence: dict = None


# ---------------------------------------------------------------------------
# State accessors (read)
# ---------------------------------------------------------------------------

def get_capture_file() -> str:
    """Return the filename of the currently active (or most recently started) capture."""
    return _capture_file


def get_last_capture_file() -> str:
    """Return the filename of the last completed capture."""
    return _last_capture_file


def get_last_analyzed_file() -> str:
    """Return the path of the last PCAP file that was analyzed."""
    return _last_analyzed_file


def get_latest_traffic_intelligence() -> dict:
    """Return the traffic intelligence dict from the most recent analysis."""
    return _latest_traffic_intelligence


def get_capture_process():
    """Return the active subprocess.Popen capture process, or None."""
    return _capture_process


def is_capture_running() -> bool:
    """Return True if a tshark capture process is currently active."""
    return _capture_process is not None


# ---------------------------------------------------------------------------
# State mutators
# ---------------------------------------------------------------------------

def set_capture_process(proc) -> None:
    global _capture_process
    _capture_process = proc


def set_capture_file(path: str) -> None:
    global _capture_file
    _capture_file = path


def set_last_capture_file(path: str) -> None:
    global _last_capture_file
    _last_capture_file = path


def clear_capture_state() -> None:
    """
    Clear all capture file references without terminating any process.
    Alias for reset_capture_state with no process termination side-effect.
    For a hard reset (including process kill) use reset_capture_state().
    """
    global _capture_file, _last_capture_file
    _capture_file = None
    _last_capture_file = None


# ---------------------------------------------------------------------------
# Live capture lifecycle
# ---------------------------------------------------------------------------

def start_capture(interface_id: str) -> dict:
    """
    Start a tshark live capture on *interface_id*.

    Returns:
        {"status": "started", "interface": interface_id}  on success
        {"error": "Capture already running"}              if already active
    """
    global _capture_process, _capture_file

    if _capture_process:
        return {"error": "Capture already running"}

    _capture_file = rf"C:\Netfusion\NetFusion-Agent\Captured_packets\capture_{int(time.time())}.pcapng"

    _capture_process = subprocess.Popen(
        [TSHARK_PATH, "-i", interface_id, "-w", _capture_file]
    )

    return {
        "status": "started",
        "interface": interface_id,
    }


def stop_capture() -> dict:
    """
    Terminate the running tshark capture process and promote the capture file
    to *last_capture_file*.

    Returns:
        {"stopped": True, "file": filename}   on success
        {"error": "No capture running"}       if nothing is running
    """
    global _capture_process, _last_capture_file

    if not _capture_process:
        return {"error": "No capture running"}

    _capture_process.terminate()
    _capture_process.wait()
    _capture_process = None

    _last_capture_file = _capture_file

    return {
        "stopped": True,
        "file": _capture_file,
    }


def reset_capture_state() -> None:
    """
    Hard-reset all capture state (used by session delete).
    Terminates any running capture process and clears all file references.
    """
    global _capture_process, _capture_file, _last_capture_file

    if _capture_process:
        try:
            _capture_process.terminate()
            _capture_process.wait()
        except Exception:
            pass
        _capture_process = None

    _capture_file = None
    _last_capture_file = None


# ---------------------------------------------------------------------------
# PCAP analysis orchestration
# ---------------------------------------------------------------------------

def _build_traffic_intelligence(packets: list) -> dict:
    """Delegate to traffic_intelligence_service."""
    from services.traffic_intelligence_service import build_traffic_intelligence  # noqa: PLC0415
    return build_traffic_intelligence(packets)


def analyze_pcap(path: str) -> dict:
    """
    Full PCAP analysis pipeline:
      1. Parse packets via packet_service
      2. Generate traffic intelligence
      3. Build asset list
      4. Attach both to the result dict

    Updates the module-level *_last_analyzed_file* and
    *_latest_traffic_intelligence* state.

    Returns the enriched analysis dict, or a dict with an "error" key.
    """
    global _last_analyzed_file, _latest_traffic_intelligence

    _last_analyzed_file = path
    result = packet_service.analyze_pcap_file(path)

    if not isinstance(result, dict) or result.get("error"):
        return result

    packets_full = result.get("packets", [])
    traffic_intel = _build_traffic_intelligence(packets_full)
    _latest_traffic_intelligence = traffic_intel

    try:
        print("=== TRAFFIC INTELLIGENCE ===")
        print("topTalkers:", json.dumps(traffic_intel.get("topTalkers", [])))
        print("topBandwidthConsumers:", json.dumps(traffic_intel.get("topBandwidthConsumers", [])))
        print("trafficSummary:", json.dumps(traffic_intel.get("trafficSummary", {})))
    except Exception:
        print("=== TRAFFIC INTELLIGENCE (could not serialize) ===")

    result["assets"] = build_assets_from_packets(packets_full)
    result["trafficIntelligence"] = traffic_intel
    return result


def analyze_latest_capture() -> dict:
    """
    Analyze the most recently completed capture file.

    Returns the analysis dict, or a dict with an "error" key when no file
    is available or the file cannot be found on disk.
    """
    if not _last_capture_file:
        return {"error": "No capture file available"}
    if not os.path.exists(_last_capture_file):
        return {"error": "Capture file not found"}
    return analyze_pcap(_last_capture_file)


def analyze_active_capture() -> dict:
    """
    Analyze the currently active (in-progress) capture file.

    Returns the analysis dict, or a dict with an "error" key.
    """
    if not _capture_file:
        return {"error": "No active capture file"}
    if not os.path.exists(_capture_file):
        return {"error": "Active capture file not found"}
    return analyze_pcap(_capture_file)
