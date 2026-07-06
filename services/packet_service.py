"""Packet loading and PCAP analysis orchestration."""

import os
from collections import Counter
from typing import List, Optional

from parsers import packet_parser, tshark_parser


def get_packet_list(path: str) -> List[dict]:
    """Return list of packet dicts for a pcapng file at `path`."""
    result = tshark_parser.extract_packet_list_output(path)
    return packet_parser.parse_packets_from_tshark_output(result.stdout)


def analyze_pcap_file(path: str) -> dict:
    """Analyze a pcapng file and return PCAP statistics plus normalized packets."""
    try:
        protocols = tshark_parser.extract_protocol_lines(path)
        protocol_counts = dict(Counter(protocols))

        conversation_map = {}
        for line in tshark_parser.extract_conversation_lines(path):
            parsed = packet_parser.parse_conversation_line(line)
            if not parsed:
                continue

            src, dst, protocol = parsed
            key = f"{src}|{dst}|{protocol}"

            if key not in conversation_map:
                conversation_map[key] = {
                    "src": src,
                    "dst": dst,
                    "protocol": protocol,
                    "packets": 0,
                }

            conversation_map[key]["packets"] += 1

        conversations = sorted(
            conversation_map.values(),
            key=lambda item: item["packets"],
            reverse=True,
        )

        source_map = {}
        destination_map = {}

        for conv in conversations:
            source_map[conv["src"]] = source_map.get(conv["src"], 0) + conv["packets"]
            destination_map[conv["dst"]] = destination_map.get(conv["dst"], 0) + conv["packets"]

        top_sources = sorted(
            [{"ip": ip, "packets": count} for ip, count in source_map.items()],
            key=lambda item: item["packets"],
            reverse=True,
        )

        top_destinations = sorted(
            [{"ip": ip, "packets": count} for ip, count in destination_map.items()],
            key=lambda item: item["packets"],
            reverse=True,
        )

        packets_full = get_packet_list(path)

        return {
            "filename": os.path.basename(path),
            "total_packets": len(protocols),
            "protocols": protocol_counts,
            "conversation_count": len(conversations),
            "conversations": conversations[:100],
            "top_sources": top_sources[:10],
            "top_destinations": top_destinations[:10],
            "packets": packets_full,
        }

    except Exception as e:
        return {
            "error": str(e),
        }


def list_interfaces() -> List[dict]:
    return tshark_parser.list_interfaces()


def get_packet_details(path: str, packet_number: int) -> str:
    result = tshark_parser.get_packet_verbose_details(path, packet_number)
    return result.stdout


def follow_stream(path: str, packet_number: int) -> dict:
    stream_id = tshark_parser.get_tcp_stream_id(path, packet_number)

    if not stream_id:
        return {
            "error": "Packet is not TCP",
        }

    follow_result = tshark_parser.follow_tcp_stream(path, stream_id)

    return {
        "stream_id": stream_id,
        "content": follow_result.stdout,
    }


def get_http_requests(path: str) -> List[dict]:
    requests = []

    for line in tshark_parser.extract_http_request_lines(path):
        parsed = packet_parser.parse_http_request_row(line)
        if parsed:
            requests.append(parsed)

    return requests


def get_dns_queries(path: str) -> dict:
    domains = packet_parser.parse_dns_domains(
        tshark_parser.extract_dns_query_lines(path)
    )

    return {
        "count": len(domains),
        "domains": domains,
    }


def filter_packets_by_ip(packets: List[dict], ip: str) -> List[dict]:
    return [
        packet for packet in packets
        if packet.get("src") == ip or packet.get("dst") == ip
    ]
