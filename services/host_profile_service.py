"""
Host Profile Service — per-host profiling and endpoint metadata.

Responsibilities:
  - Retrieve packets for a specific host IP
  - Build a full host profile (protocols, peers, risk score, identity)
  - Build host alerts
  - Build host MITRE mappings
  - Build host communications summary
  - Format endpoint profile metadata

This module has no knowledge of FastAPI routes or HTTP responses.
"""

import os

from identity.resolver import (
    select_best_device_name_from_packets,
    select_best_hostname_from_packets,
)
from services import capture_service, packet_service
from services import timeline_service
from utils.network import lookup_mac_vendor, select_best_mac_for_ip


# ---------------------------------------------------------------------------
# Packet retrieval
# ---------------------------------------------------------------------------

def get_host_packets(ip: str) -> list:
    """Return all packets where *ip* appears as source or destination."""
    _lcf = capture_service.get_last_capture_file()
    if not _lcf or not os.path.exists(_lcf):
        return []
    packets = packet_service.get_packet_list(_lcf)
    return [
        p for p in packets
        if p.get("src") == ip or p.get("dst") == ip
    ]


# ---------------------------------------------------------------------------
# Host profile
# ---------------------------------------------------------------------------

def build_host_profile(ip: str) -> dict:
    """
    Build a complete host profile for *ip* from the current capture file.

    Returns a dict with keys: ip, packet_count, protocols, top_peers,
    risk_score, risk_reasons, packets, macAddress, deviceName, hostname,
    vendor.
    """
    packets = get_host_packets(ip)
    protocols = {}
    peers = {}

    for packet in packets:
        protocol = packet.get("protocol", "")
        if protocol:
            protocols[protocol] = protocols.get(protocol, 0) + 1

        peer = packet.get("dst") if packet.get("src") == ip else packet.get("src")
        if peer:
            peers[peer] = peers.get(peer, 0) + 1

    top_peers = sorted(
        [{"ip": peer, "packets": count} for peer, count in peers.items()],
        key=lambda x: x["packets"],
        reverse=True,
    )

    mac_address = select_best_mac_for_ip(ip, packets)
    device_name = select_best_device_name_from_packets(packets)
    hostname = select_best_hostname_from_packets(packets)
    vendor = lookup_mac_vendor(mac_address) if mac_address else None

    packet_count = len(packets)
    score = 0
    reasons = []

    if "SSL" in protocols:
        score += 30
        reasons.append("Legacy SSL")

    if any(p in protocols for p in {"FTP", "TELNET", "SMB", "HTTP"}):
        score += 20
        reasons.append("IOC Finding")

    if "DNS" in protocols and packet_count > 50:
        score += 15
        reasons.append("Alert Activity")

    if packet_count > 100:
        score += 10
        reasons.append("High Traffic Volume")

    if any(p in protocols for p in {"TELNET", "FTP"}):
        score += 20
        reasons.append("Threat Intel Risk")

    return {
        "ip": ip,
        "packet_count": packet_count,
        "protocols": protocols,
        "top_peers": top_peers,
        "risk_score": score,
        "risk_reasons": reasons,
        "packets": packets,
        "macAddress": mac_address,
        "deviceName": device_name,
        "hostname": hostname,
        "vendor": vendor,
    }


# ---------------------------------------------------------------------------
# Host alerts
# ---------------------------------------------------------------------------

def build_host_alerts(profile: dict) -> list:
    """Build a list of alert dicts from a host profile."""
    alerts = []
    protocols = profile["protocols"]
    packet_count = profile["packet_count"]

    if "HTTP" in protocols:
        alerts.append({
            "severity": "medium",
            "title": "Plaintext HTTP",
            "description": "Host is sending unencrypted HTTP traffic.",
        })

    if "FTP" in protocols:
        alerts.append({
            "severity": "medium",
            "title": "FTP Detected",
            "description": "Host is using FTP.",
        })

    if "TELNET" in protocols:
        alerts.append({
            "severity": "high",
            "title": "Telnet Detected",
            "description": "Host is using Telnet.",
        })

    if "SMB" in protocols:
        alerts.append({
            "severity": "medium",
            "title": "SMB Traffic",
            "description": "Host is using SMB.",
        })

    if "SSL" in protocols:
        alerts.append({
            "severity": "medium",
            "title": "Legacy SSL Usage",
            "description": "Host is using legacy SSL.",
        })

    if "DNS" in protocols and packet_count > 50:
        alerts.append({
            "severity": "info",
            "title": "DNS Activity",
            "description": "Host has high DNS activity.",
        })

    if packet_count > 100:
        alerts.append({
            "severity": "info",
            "title": "High Traffic Volume",
            "description": "Host is responsible for high traffic volume.",
        })

    return alerts


# ---------------------------------------------------------------------------
# Host MITRE mapping
# ---------------------------------------------------------------------------

def build_host_mitre(ip: str, profile: dict) -> dict:
    """Map host alerts to MITRE ATT&CK techniques."""
    from services import mitre_service  # noqa: PLC0415

    iocs = []
    alerts = build_host_alerts(profile)
    correlations = []
    return mitre_service.map_to_mitre(iocs, alerts, correlations)


# ---------------------------------------------------------------------------
# Host timeline (delegates to timeline_service)
# ---------------------------------------------------------------------------

def build_host_timeline(ip: str, profile: dict) -> list:
    """Delegate to timeline_service.build_host_timeline."""
    return timeline_service.build_host_timeline(ip, profile)


# ---------------------------------------------------------------------------
# Host communications
# ---------------------------------------------------------------------------

def build_host_communications(ip: str, profile: dict) -> list:
    """
    Build a sorted list of communication records for *ip*.

    Each record contains: peer, protocol, direction, packets.
    """
    peers = {}

    for packet in profile["packets"]:
        src = packet.get("src", "")
        dst = packet.get("dst", "")
        protocol = packet.get("protocol", "")

        if src == ip:
            peer = dst
            direction = "outbound"
        elif dst == ip:
            peer = src
            direction = "inbound"
        else:
            continue

        if not peer:
            continue

        key = (peer, protocol, direction)
        peers[key] = peers.get(key, 0) + 1

    comms = [
        {
            "peer": peer,
            "protocol": protocol,
            "direction": direction,
            "packets": count,
        }
        for (peer, protocol, direction), count in peers.items()
    ]

    comms.sort(key=lambda x: x["packets"], reverse=True)
    return comms


# ---------------------------------------------------------------------------
# Endpoint profile formatting
# ---------------------------------------------------------------------------

def format_endpoint_profile(asset: dict):
    """Format an asset dict into the endpoint profile response shape."""
    if not asset:
        return None

    return {
        "deviceName": asset.get("deviceName"),
        "hostname": asset.get("hostname"),
        "macAddress": asset.get("macAddress"),
        "vendor": asset.get("vendor"),
        "currentIp": asset.get("currentIp"),
        "previousIPs": asset.get("previousIPs") or [],
        "ssid": asset.get("ssid"),
        "firstSeen": asset.get("firstSeen"),
        "lastSeen": asset.get("lastSeen"),
        "riskScore": asset.get("currentRiskScore"),
    }
