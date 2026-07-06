"""Low-level tshark command construction and execution."""

import subprocess
from typing import Iterable, List, Optional

from core.config import TSHARK_PATH

PROTOCOL_FIELD = "_ws.col.Protocol"

PACKET_LIST_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "eth.src",
    "eth.dst",
    "_ws.col.protocol",
    "frame.len",
    "_ws.col.info",
    "dhcp.option.hostname",
    "http.host",
    "nbns.name",
    "nbns.netbios_name",
    "dns.qry.name",
]

CONVERSATION_FIELDS = [
    "ip.src",
    "ip.dst",
    PROTOCOL_FIELD,
]

HTTP_REQUEST_FIELDS = [
    "http.host",
    "http.request.method",
    "http.request.uri",
]

DNS_QUERY_FIELDS = [
    "dns.qry.name",
]


def build_tshark_command(*args: str) -> List[str]:
    return [TSHARK_PATH, *args]


def run_tshark(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        build_tshark_command(*args),
        capture_output=True,
        text=True,
        **kwargs,
    )


def validate_tshark_result(result: subprocess.CompletedProcess) -> None:
    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(f"tshark failed: {result.stderr.strip()}")


def extract_fields(
    path: str,
    fields: Iterable[str],
    display_filter: Optional[str] = None,
) -> subprocess.CompletedProcess:
    args = ["-r", path, "-T", "fields"]
    for field in fields:
        args.extend(["-e", field])
    if display_filter:
        args.extend(["-Y", display_filter])
    return run_tshark(*args)


def list_interfaces() -> List[dict]:
    result = run_tshark("-D")
    interfaces = []

    for line in result.stdout.splitlines():
        if "." not in line:
            continue

        idx, name = line.split(".", 1)
        interfaces.append({
            "id": idx.strip(),
            "name": name.strip(),
        })

    return interfaces


def extract_protocol_lines(path: str) -> List[str]:
    result = extract_fields(path, [PROTOCOL_FIELD])
    protocols = []

    for line in result.stdout.splitlines():
        protocol = line.strip()
        if protocol:
            protocols.append(protocol)

    return protocols


def extract_conversation_lines(path: str) -> List[str]:
    result = extract_fields(path, CONVERSATION_FIELDS)
    return result.stdout.splitlines()


def extract_packet_list_output(path: str) -> subprocess.CompletedProcess:
    result = extract_fields(path, PACKET_LIST_FIELDS)
    validate_tshark_result(result)
    return result


def get_packet_verbose_details(path: str, packet_number: int) -> subprocess.CompletedProcess:
    return run_tshark(
        "-r",
        path,
        "-Y",
        f"frame.number=={packet_number}",
        "-V",
    )


def get_tcp_stream_id(path: str, packet_number: int) -> str:
    result = extract_fields(
        path,
        ["tcp.stream"],
        display_filter=f"frame.number=={packet_number}",
    )
    return result.stdout.strip()


def follow_tcp_stream(path: str, stream_id: str) -> subprocess.CompletedProcess:
    return run_tshark(
        "-r",
        path,
        "-q",
        "-z",
        f"follow,tcp,ascii,{stream_id}",
    )


def extract_http_request_lines(path: str) -> List[str]:
    result = extract_fields(
        path,
        HTTP_REQUEST_FIELDS,
        display_filter="http.request",
    )
    return result.stdout.splitlines()


def extract_dns_query_lines(path: str) -> List[str]:
    result = extract_fields(path, DNS_QUERY_FIELDS)
    return result.stdout.splitlines()
