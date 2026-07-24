"""Convert raw tshark output into normalized packet dictionaries."""

from typing import List

from identity.resolver import resolve_device_identity
from utils.network import lookup_mac_vendor, normalize_mac

PACKET_FIELD_COUNT = 14


def parse_packet_row(parts: List[str]) -> dict:
    while len(parts) < PACKET_FIELD_COUNT:
        parts.append("")

    return {
        "number": parts[0],
        "time": parts[1],
        "src": parts[2],
        "dst": parts[3],
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
