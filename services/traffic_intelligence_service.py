"""
Traffic Intelligence Service — traffic statistics aggregation.

Responsibilities:
  - Aggregate top talkers, bandwidth consumers, protocols
  - Compute internal vs external traffic ratios
  - Summarise DNS and HTTP activity
  - Summarise external communication destinations
  - Produce a single enriched traffic intelligence dict

This module has no knowledge of FastAPI, routes, or HTTP responses.
"""

from utils.network import is_private_ip, is_public_ip


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_traffic_intelligence(packets: list) -> dict:
    """
    Generate actionable traffic statistics from a packet list.

    Returns a dict with keys:
        topTalkers, topBandwidthConsumers, topProtocols,
        topExternalDestinations, topDnsRequesters, topHttpRequesters,
        internalVsExternal, trafficSummary
    """
    if not packets:
        return {
            "topTalkers": [],
            "topBandwidthConsumers": [],
            "topProtocols": [],
            "topExternalDestinations": [],
            "topDnsRequesters": [],
            "topHttpRequesters": [],
            "internalVsExternal": {
                "internalTrafficPercent": 0,
                "externalTrafficPercent": 0,
            },
            "trafficSummary": {
                "totalPackets": 0,
                "totalBytes": 0,
                "uniqueHosts": 0,
                "externalConnections": 0,
            },
        }

    # Aggregation maps
    host_packets = {}
    host_bytes = {}
    protocol_counts = {}
    external_comms = {}
    dns_requesters = {}
    http_requesters = {}
    all_hosts = set()
    internal_packet_count = 0
    external_packet_count = 0
    unique_external_connections = set()

    # Process each packet
    for packet in packets:
        src = str(packet.get("src") or packet.get("src_ip") or "").strip()
        dst = str(packet.get("dst") or packet.get("dst_ip") or "").strip()
        protocol = str(packet.get("protocol") or "").strip()
        length = str(packet.get("length", "0")).strip()

        # Track length as integer
        try:
            pkt_length = int(length) if length else 0
        except Exception:
            pkt_length = 0

        # Count host packet and byte traffic
        for ip in [src, dst]:
            if ip and ip not in ("", "0.0.0.0"):
                all_hosts.add(ip)
                host_packets[ip] = host_packets.get(ip, 0) + 1
                host_bytes[ip] = host_bytes.get(ip, 0) + pkt_length

        # Count protocols
        if protocol:
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        # Count external communications (private -> public)
        if src and dst and is_private_ip(src) and is_public_ip(dst):
            key = f"{src}|{dst}"
            external_comms[key] = external_comms.get(key, 0) + 1
            unique_external_connections.add(key)
            external_packet_count += 1
        elif src and dst and is_public_ip(src) and is_private_ip(dst):
            external_packet_count += 1
        else:
            internal_packet_count += 1

        # Count DNS queries (port 53 or DNS protocol)
        if protocol and "DNS" in protocol.upper():
            if src and not is_public_ip(src):
                dns_requesters[src] = dns_requesters.get(src, 0) + 1

        # Count HTTP requests
        if protocol and "HTTP" in protocol.upper():
            if src and not is_public_ip(src):
                http_requesters[src] = http_requesters.get(src, 0) + 1

    # Build results
    total_packets = len(packets)
    total_bytes = sum(host_bytes.values())

    # 1. Top Talkers (by packet count)
    top_talkers = sorted(
        [{"host": ip, "packets": count} for ip, count in host_packets.items()],
        key=lambda x: x["packets"],
        reverse=True,
    )[:10]

    # 2. Top Bandwidth Consumers
    top_bandwidth = sorted(
        [{"host": ip, "bytes": bytes_count} for ip, bytes_count in host_bytes.items()],
        key=lambda x: x["bytes"],
        reverse=True,
    )[:10]

    # Add traffic percentage
    for item in top_bandwidth:
        if total_bytes > 0:
            item["trafficPercent"] = int((item["bytes"] / total_bytes) * 100)
        else:
            item["trafficPercent"] = 0

    # 3. Top Protocols
    top_protocols = sorted(
        [{"protocol": proto, "packets": count} for proto, count in protocol_counts.items()],
        key=lambda x: x["packets"],
        reverse=True,
    )[:10]

    # Add percentages
    for item in top_protocols:
        if total_packets > 0:
            item["percent"] = int((item["packets"] / total_packets) * 100)
        else:
            item["percent"] = 0

    # 4. External Communications
    top_external = sorted(
        [
            {
                "source": k.split("|")[0],
                "destination": k.split("|")[1],
                "count": v,
            }
            for k, v in external_comms.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # 5. Top DNS Requesters
    top_dns = sorted(
        [{"host": ip, "queries": count} for ip, count in dns_requesters.items()],
        key=lambda x: x["queries"],
        reverse=True,
    )[:10]

    # 6. Top HTTP Requesters
    top_http = sorted(
        [{"host": ip, "requests": count} for ip, count in http_requesters.items()],
        key=lambda x: x["requests"],
        reverse=True,
    )[:10]

    # 7. Internal vs External
    total_traffic = internal_packet_count + external_packet_count
    if total_traffic > 0:
        internal_percent = int((internal_packet_count / total_traffic) * 100)
        external_percent = int((external_packet_count / total_traffic) * 100)
    else:
        internal_percent = 0
        external_percent = 0

    internal_vs_external = {
        "internalTrafficPercent": internal_percent,
        "externalTrafficPercent": external_percent,
    }

    # 8. Traffic Summary
    traffic_summary = {
        "totalPackets": total_packets,
        "totalBytes": total_bytes,
        "uniqueHosts": len(all_hosts),
        "externalConnections": len(unique_external_connections),
    }

    return {
        "topTalkers": top_talkers,
        "topBandwidthConsumers": top_bandwidth,
        "topProtocols": top_protocols,
        "topExternalDestinations": top_external,
        "topDnsRequesters": top_dns,
        "topHttpRequesters": top_http,
        "internalVsExternal": internal_vs_external,
        "trafficSummary": traffic_summary,
    }
