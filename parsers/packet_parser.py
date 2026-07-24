"""Convert raw tshark output into normalized packet dictionaries."""

from typing import List

from identity.resolver import resolve_device_identity
from utils.network import lookup_mac_vendor, normalize_mac

PACKET_FIELD_COUNT = 17


def ip_matches_packet(target_ip: str, packet_ip_field: str) -> bool:
    """Return True if target_ip matches packet_ip_field exactly or within comma-separated list."""
    if not target_ip or not packet_ip_field:
        return False
    target_clean = str(target_ip).strip()
    field_clean = str(packet_ip_field).strip()
    if not target_clean or not field_clean:
        return False
    if field_clean == target_clean:
        return True
    parts = [p.strip() for p in field_clean.split(",")]
    return target_clean in parts


def parse_packet_row(parts: List[str]) -> dict:
    while len(parts) < PACKET_FIELD_COUNT:
        parts.append("")

    src_ip = parts[2].strip() or (parts[14].strip() if len(parts) > 14 else "")
    dst_ip = parts[3].strip() or (parts[15].strip() if len(parts) > 15 else "")
    tls_sni = parts[16].strip() if len(parts) > 16 else ""

    return {
        "number": parts[0],
        "time": parts[1],
        "src": src_ip,
        "dst": dst_ip,
        "mac_src": parts[4],
        "mac_dst": parts[5],
        "protocol": parts[6],
        "length": parts[7],
        "info": parts[8],
        "dhcp_hostname": parts[9],
        "bootp_hostname": "",
        "http_host": parts[10],
        "nbns_name": parts[11],
        "nbns_netbios_name": parts[12],
        "mdns_name": "",
        "llmnr_name": "",
        "dns_ptr": "",
        "dns_query": parts[13],
        "tls_sni": tls_sni,
    }


def enrich_packet(packet: dict) -> dict:
    packet["mac_src"] = normalize_mac(packet.get("mac_src"))
    packet["mac_dst"] = normalize_mac(packet.get("mac_dst"))
    identity = resolve_device_identity(packet)
    packet["identityEvidence"] = identity.get("identityEvidence", [])
    packet["hostname"] = identity.get("hostname")
    packet["deviceName"] = identity.get("deviceName")
    packet["vendor"] = lookup_mac_vendor(packet.get("mac_src")) or lookup_mac_vendor(packet.get("mac_dst"))
    return packet


def extract_mac_and_names_from_packet(packet: dict) -> dict:
    return enrich_packet(packet)


def parse_packets_from_tshark_output(stdout: str) -> List[dict]:
    packets = []

    for line in stdout.splitlines():
        parts = line.split("\t")
        packet = parse_packet_row(parts)
        packet = enrich_packet(packet)
        packets.append(packet)

    return packets


def parse_conversation_line(line: str):
    parts = str(line).split("\t")

    if len(parts) < 3:
        return None

    src = str(parts[0]).strip()
    dst = str(parts[1]).strip()
    protocol = str(parts[2]).strip()

    if not src or not dst:
        return None

    return src, dst, protocol


def parse_http_request_row(line: str):
    parts = str(line).split("\t")

    if len(parts) < 3:
        return None

    host = str(parts[0]).strip()
    method = str(parts[1]).strip()
    uri = str(parts[2]).strip()

    if not host:
        return None

    return host, method, uri


def parse_dns_queries(lines: List[str]):
    domains = []

    for line in lines:
        domain = str(line).strip()

        if domain and domain != "none":
            domains.append(domain)

    return sorted(list(set(domains)))
