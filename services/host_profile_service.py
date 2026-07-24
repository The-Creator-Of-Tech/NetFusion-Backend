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
    _lcf = (
        capture_service.get_last_capture_file()
        or capture_service.get_capture_file()
        or capture_service.get_last_analyzed_file()
    )
    if not _lcf or not os.path.exists(_lcf):
        return []
    packets = packet_service.get_packet_list(_lcf)
    from parsers.packet_parser import ip_matches_packet
    return [
        p for p in packets
        if ip_matches_packet(ip, p.get("src")) or ip_matches_packet(ip, p.get("dst"))
    ]


# ---------------------------------------------------------------------------
# Host profile
# ---------------------------------------------------------------------------

def build_host_profile(ip: str) -> dict:
    """
    Build a complete host profile for *ip* from the current capture file.

    Returns a dict with keys: ip, packet_count, inbound_packets, outbound_packets,
    total_bytes, inbound_bytes, outbound_bytes, protocols, top_peers, dns_queries,
    http_hosts, tls_snis, observed_domains, risk_score, risk_reasons, packets,
    macAddress, deviceName, hostname, vendor.
    """
    from parsers.packet_parser import ip_matches_packet

    packets = get_host_packets(ip)
    protocols = {}
    peers = {}
    inbound_packets = 0
    outbound_packets = 0
    inbound_bytes = 0
    outbound_bytes = 0
    total_bytes = 0
    dns_queries = set()
    http_hosts = set()
    tls_snis = set()
    unique_ports = set()
    flows = set()

    for packet in packets:
        protocol = packet.get("protocol", "")
        if protocol:
            protocols[protocol] = protocols.get(protocol, 0) + 1

        is_out = ip_matches_packet(ip, packet.get("src"))
        is_in = ip_matches_packet(ip, packet.get("dst"))

        try:
            pkt_len = int(packet.get("length", 0))
        except (ValueError, TypeError):
            pkt_len = 0
        total_bytes += pkt_len

        if is_out:
            outbound_packets += 1
            outbound_bytes += pkt_len
            peer = packet.get("dst")
        elif is_in:
            inbound_packets += 1
            inbound_bytes += pkt_len
            peer = packet.get("src")
        else:
            peer = None

        if peer:
            peers[peer] = peers.get(peer, 0) + 1
            flows.add(f"{peer}|{protocol}")

        # Extract domain evidence
        dq = packet.get("dns_query", "").strip()
        if dq and dq.lower() != "none":
            dns_queries.add(dq)

        hh = packet.get("http_host", "").strip()
        if hh:
            http_hosts.add(hh)

        ts = packet.get("tls_sni", "").strip()
        if ts:
            tls_snis.add(ts)

    top_peers = sorted(
        [{"ip": peer, "packets": count} for peer, count in peers.items()],
        key=lambda x: x["packets"],
        reverse=True,
    )

    observed_domains = sorted(list(dns_queries | http_hosts | tls_snis))

    mac_address = select_best_mac_for_ip(ip, packets)
    device_name = select_best_device_name_from_packets(packets)
    hostname = select_best_hostname_from_packets(packets)
    vendor = lookup_mac_vendor(mac_address) if mac_address else None

    packet_count = len(packets)
    score = 0
    reasons = []

    if "SSL" in protocols or "TLS" in protocols:
        score += 15
        reasons.append("TLS/SSL Traffic")

    if any(p in protocols for p in {"FTP", "TELNET", "SMB", "HTTP"}):
        score += 20
        reasons.append("Plaintext/Insecure Protocols")

    if "DNS" in protocols and packet_count > 50:
        score += 15
        reasons.append("High DNS Activity")

    if packet_count > 100:
        score += 10
        reasons.append("High Traffic Volume")

    return {
        "ip": ip,
        "packet_count": packet_count,
        "inbound_packets": inbound_packets,
        "outbound_packets": outbound_packets,
        "total_bytes": total_bytes,
        "inbound_bytes": inbound_bytes,
        "outbound_bytes": outbound_bytes,
        "protocols": protocols,
        "flows_count": len(flows),
        "top_peers": top_peers,
        "dns_queries": sorted(list(dns_queries)),
        "http_hosts": sorted(list(http_hosts)),
        "tls_snis": sorted(list(tls_snis)),
        "observed_domains": observed_domains,
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
    if hasattr(mitre_service, "map_to_mitre"):
        return mitre_service.map_to_mitre(iocs, alerts, correlations)
    return {"techniques": [], "tactics": [], "mappings": []}


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
