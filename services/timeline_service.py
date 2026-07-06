"""
Timeline Service — timeline generation and enrichment logic.

Responsibilities:
  - Build capture-level timeline events from a packet list
  - Build per-host timeline events from a host profile

This module has no knowledge of FastAPI, routes, or HTTP responses.
"""

from utils.time_utils import local_iso_timestamp


# ---------------------------------------------------------------------------
# Capture-level timeline
# ---------------------------------------------------------------------------

INTERESTING_PROTOCOLS = {
    "DNS",
    "TLSv1.2",
    "TLSv1.3",
    "SSL",
    "QUIC",
    "HTTP",
    "HTTPS",
    "MDNS",
}


def build_capture_timeline(packets: list) -> list:
    """
    Build a list of timeline events from the first 500 packets of a capture.

    Each event contains: packet_number, time, title, protocol, src, dst,
    description.  SSL packets also append a 'finding' sentinel event.

    Args:
        packets: Raw packet list returned by packet_service.get_packet_list().

    Returns:
        List of event dicts, preserving original ordering.
    """
    events = []

    for p in packets[:500]:
        protocol = p.get("protocol", "").strip()
        src = p.get("src", "").strip()
        dst = p.get("dst", "").strip()

        if not protocol:
            continue

        if not src and not dst:
            continue

        if protocol not in INTERESTING_PROTOCOLS:
            continue

        title = ""
        description = ""

        if "TLS" in protocol:
            title = "🔒 Secure Session Established"
            description = "Encrypted communication channel established."
        elif protocol == "DNS":
            title = "🌐 DNS Resolution Activity"
            description = "Host performed a DNS lookup using the configured DNS server."
        elif protocol == "MDNS":
            title = "📡 Local Network Device Discovery"
            description = "Multicast discovery activity observed on the local network."
        elif protocol == "SSL":
            title = "🚨 Legacy SSL Usage"
            description = "Legacy SSL protocol detected. Review recommended."

        events.append({
            "packet_number": p.get("number"),
            "time": p.get("time"),
            "title": title,
            "protocol": protocol,
            "src": src,
            "dst": dst,
            "description": description,
        })

        if protocol == "SSL":
            events.append({
                "type": "finding",
                "time": local_iso_timestamp(),
                "title": "Legacy SSL Usage",
                "severity": "medium",
            })

    return events


# ---------------------------------------------------------------------------
# Per-host timeline
# ---------------------------------------------------------------------------

def build_host_timeline(ip: str, profile: dict) -> list:
    """
    Build a per-host timeline from a host profile dict.

    Args:
        ip:      The host IP address (unused in logic, kept for signature
                 compatibility with callers that pass it).
        profile: Host profile dict containing a 'packets' list.

    Returns:
        List of timeline event dicts.
    """
    timeline = []

    for packet in profile.get("packets", []):
        protocol = packet.get("protocol", "")
        src = packet.get("src", "")
        dst = packet.get("dst", "")
        title = "Network Event"
        description = "Host traffic observed."

        if "TLS" in protocol:
            title = "Secure Session Established"
            description = "Encrypted network session observed."
        elif protocol == "DNS":
            title = "DNS Resolution Activity"
            description = "Host performed a DNS lookup."
        elif protocol == "MDNS":
            title = "Local Network Device Discovery"
            description = "Host issued mDNS discovery traffic."
        elif protocol == "SSL":
            title = "Legacy SSL Usage"
            description = "Host used legacy SSL."
        elif protocol == "HTTP":
            title = "HTTP Traffic"
            description = "Host transmitted HTTP traffic."

        timeline.append({
            "packet_number": packet.get("number"),
            "time": packet.get("time"),
            "protocol": protocol,
            "src": src,
            "dst": dst,
            "title": title,
            "description": description,
        })

    return timeline
