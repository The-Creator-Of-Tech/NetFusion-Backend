"""
Identity Signal Extraction Engine
==================================
Phase A.2.2.1 — Extract only. No matching. No database. No persistence.

Receives ONE normalized packet dict (as produced by packet_parser.enrich_packet)
and returns a structured IdentitySignal containing every identity attribute
that can be deterministically read from the packet's fields.

Design principles
-----------------
- Pure extraction: reads existing fields, never invents values.
- Deterministic: given the same packet, always returns the same signal.
- No AI / heuristics / scoring.
- No side effects: no DB, no network, no file I/O.
- Extensible: the SourceType enum and extractor registry are the only
  touch-points needed to add future sources (Zeek, Sysmon, Suricata, …).

Packet field reference (from parsers/packet_parser.py + tshark_parser.py)
--------------------------------------------------------------------------
  number            frame.number
  time              frame.time
  src               ip.src
  dst               ip.dst
  mac_src           eth.src  (normalized)
  mac_dst           eth.dst  (normalized)
  protocol          _ws.col.protocol
  length            frame.len
  info              _ws.col.info
  dhcp_hostname     dhcp.option.hostname
  bootp_hostname    bootp.option.hostname  (populated by parser)
  http_host         http.host
  nbns_name         nbns.name
  nbns_netbios_name nbns.netbios_name
  mdns_name         (reserved — tshark field not yet wired, parser sets "")
  llmnr_name        (reserved — tshark field not yet wired, parser sets "")
  dns_ptr           (reserved — tshark field not yet wired, parser sets "")
  dns_query         dns.qry.name
  hostname          resolved by identity_engine.resolve_device_identity
  deviceName        resolved by identity_engine.resolve_device_identity
  vendor            resolved by utils.network.lookup_mac_vendor
  identityEvidence  list[{source, name, confidence}] from identity_engine
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Source type registry
# ---------------------------------------------------------------------------

class SourceType(str, Enum):
    """
    Every possible origin of identity signal data.

    To add a future source (e.g. Zeek, Sysmon), add an entry here and
    register an extractor in _EXTRACTOR_REGISTRY at the bottom of this file.
    """
    PCAP       = "pcap"       # live capture / pcapng file (current)
    NMAP       = "nmap"       # Nmap scan result
    DHCP       = "dhcp"       # DHCP lease / request
    DNS        = "dns"        # DNS query / response / PTR
    MDNS       = "mdns"       # mDNS / Bonjour
    NBNS       = "nbns"       # NetBIOS Name Service
    LLMNR      = "llmnr"      # Link-Local Multicast Name Resolution
    ARP        = "arp"        # ARP table / gratuitous ARP
    MANUAL     = "manual"     # analyst-entered override
    ZEEK       = "zeek"       # future: Zeek / Bro log
    SYSMON     = "sysmon"     # future: Windows Sysmon event
    SURICATA   = "suricata"   # future: Suricata alert / metadata
    WINDOWS    = "windows"    # future: Windows Event Log


# ---------------------------------------------------------------------------
# Evidence item — one observed fact and where it came from
# ---------------------------------------------------------------------------

class SignalEvidence(BaseModel):
    """A single observed identity fact with its provenance."""
    fieldName   : str
    fieldValue  : str
    source      : SourceType
    confidence  : int          = Field(ge=0, le=100)
    packetNumber: Optional[int]   = None
    captureId   : Optional[str]   = None
    observedAt  : Optional[datetime] = None

    class Config:
        use_enum_values = True


# ---------------------------------------------------------------------------
# IdentitySignal — the full extraction result for one packet
# ---------------------------------------------------------------------------

class IdentitySignal(BaseModel):
    """
    All identity attributes extractable from a single normalized packet.

    Fields are populated only when the corresponding data is present in
    the source packet.  Every field is Optional; absent data is None / [].

    This model is the contract between the extraction engine (this file)
    and the Asset Resolution Engine (future phase).
    """

    # ── Packet provenance ─────────────────────────────────────────────────
    packetNumber : Optional[int]      = None
    captureId    : Optional[str]      = None
    observedAt   : Optional[datetime] = None
    sourceType   : SourceType         = SourceType.PCAP

    # ── Layer-2 / MAC ────────────────────────────────────────────────────
    macAddress      : Optional[str] = None   # primary MAC (src)
    sourceMac       : Optional[str] = None   # eth.src normalized
    destinationMac  : Optional[str] = None   # eth.dst normalized

    # ── Layer-3 / IP ─────────────────────────────────────────────────────
    ipAddress       : Optional[str] = None   # primary IP (src)
    sourceIp        : Optional[str] = None   # ip.src
    destinationIp   : Optional[str] = None   # ip.dst

    # ── Name resolution ───────────────────────────────────────────────────
    hostname        : Optional[str]      = None   # best resolved hostname
    hostnames       : List[str]          = Field(default_factory=list)  # all distinct hostnames
    deviceName      : Optional[str]      = None   # best resolved device name

    # ── Protocol-layer name signals ───────────────────────────────────────
    dhcpHostname    : Optional[str] = None   # dhcp.option.hostname
    bootpHostname   : Optional[str] = None   # bootp.option.hostname
    httpHost        : Optional[str] = None   # http.host
    mdnsName        : Optional[str] = None   # mDNS name (field reserved)
    nbnsName        : Optional[str] = None   # nbns.name
    nbnsNetbiosName : Optional[str] = None   # nbns.netbios_name
    llmnrName       : Optional[str] = None   # LLMNR name (field reserved)
    dnsPtr          : Optional[str] = None   # dns PTR record (field reserved)
    dnsNames        : List[str]     = Field(default_factory=list)  # dns.qry.name

    # ── Hardware / OS identity ────────────────────────────────────────────
    vendor          : Optional[str] = None   # OUI-resolved vendor
    operatingSystem : Optional[str] = None   # OS hint (future: nmap, Sysmon)
    userAgent       : Optional[str] = None   # HTTP User-Agent (future: http layer)

    # ── Network observables ───────────────────────────────────────────────
    openPorts  : List[int]  = Field(default_factory=list)  # future: nmap
    services   : List[str]  = Field(default_factory=list)  # future: nmap / banner
    protocols  : List[str]  = Field(default_factory=list)  # protocols seen in packet
    ssid       : Optional[str] = None                      # 802.11 SSID (future: wifi)

    # ── Structured evidence trail ─────────────────────────────────────────
    confidenceHints : List[SignalEvidence] = Field(default_factory=list)

    # ── Extension bag ────────────────────────────────────────────────────
    metadata : Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _str(value: Any) -> Optional[str]:
    """Return stripped non-empty string or None."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _int(value: Any) -> Optional[int]:
    """Return int or None."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items: List[Optional[str]]) -> List[str]:
    """Return ordered deduplicated list of non-None strings (case-insensitive dedup)."""
    seen: set = set()
    result: List[str] = []
    for item in items:
        if item is None:
            continue
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            result.append(item.strip())
    return result


def _make_evidence(
    field_name: str,
    field_value: Optional[str],
    source: SourceType,
    confidence: int,
    packet_number: Optional[int],
    capture_id: Optional[str],
    observed_at: Optional[datetime],
) -> Optional[SignalEvidence]:
    """Build one SignalEvidence entry, or None if field_value is empty."""
    value = _str(field_value)
    if not value:
        return None
    return SignalEvidence(
        fieldName=field_name,
        fieldValue=value,
        source=source,
        confidence=confidence,
        packetNumber=packet_number,
        captureId=capture_id,
        observedAt=observed_at,
    )


# ---------------------------------------------------------------------------
# Core extraction function
# ---------------------------------------------------------------------------

def extract_identity_signals(packet: dict) -> IdentitySignal:
    """
    Extract all identity signals from ONE normalized packet dict.

    Parameters
    ----------
    packet : dict
        A normalized packet as returned by packet_parser.enrich_packet().
        Expected fields are documented at the top of this module.

    Returns
    -------
    IdentitySignal
        Populated with every attribute deterministically readable from
        the packet's fields.  Absent fields are None / [].
        Never raises; missing/malformed values are silently skipped.

    Notes
    -----
    - No matching, no database, no side effects.
    - Confidence values mirror IDENTITY_CONFIDENCE in core/constants.py.
    """

    # ── Provenance ────────────────────────────────────────────────────────
    packet_number = _int(packet.get("number"))
    capture_id    = _str(packet.get("captureId"))   # injected upstream when known
    observed_at   = _parse_observed_at(packet.get("time"))

    # ── Layer-2 ───────────────────────────────────────────────────────────
    source_mac = _str(packet.get("mac_src"))
    dest_mac   = _str(packet.get("mac_dst"))

    # ── Layer-3 ───────────────────────────────────────────────────────────
    source_ip = _str(packet.get("src"))
    dest_ip   = _str(packet.get("dst"))

    # ── Protocol-layer name signals ───────────────────────────────────────
    dhcp_hostname     = _str(packet.get("dhcp_hostname"))
    bootp_hostname    = _str(packet.get("bootp_hostname"))
    http_host         = _str(packet.get("http_host"))
    nbns_name         = _str(packet.get("nbns_name"))
    nbns_netbios_name = _str(packet.get("nbns_netbios_name"))
    mdns_name         = _str(packet.get("mdns_name"))
    llmnr_name        = _str(packet.get("llmnr_name"))
    dns_ptr           = _str(packet.get("dns_ptr"))
    dns_query         = _str(packet.get("dns_query"))

    # ── Pre-resolved fields (from identity_engine / packet_parser) ────────
    resolved_hostname    = _str(packet.get("hostname"))
    resolved_device_name = _str(packet.get("deviceName"))
    vendor               = _str(packet.get("vendor"))

    # ── Protocol observable ───────────────────────────────────────────────
    protocol = _str(packet.get("protocol"))
    protocols = [protocol] if protocol else []

    # ── Build hostname deduped list ───────────────────────────────────────
    # Ordered by IDENTITY_CONFIDENCE precedence (mirrors core/constants.py)
    hostnames = _dedupe([
        dhcp_hostname,
        bootp_hostname,
        nbns_name,
        nbns_netbios_name,
        mdns_name,
        llmnr_name,
        dns_ptr,
        http_host,
        dns_query,
        resolved_hostname,
    ])

    # ── DNS names list ─────────────────────────────────────────────────────
    dns_names = _dedupe([dns_query, dns_ptr])

    # ── Build evidence trail ───────────────────────────────────────────────
    # Each entry maps to a packet field with its known confidence weight.
    ev_args = (packet_number, capture_id, observed_at)
    evidence: List[SignalEvidence] = []

    _add_evidence(evidence, "macAddress",        source_mac,         SourceType.PCAP,  90, *ev_args)
    _add_evidence(evidence, "destinationMac",    dest_mac,           SourceType.PCAP,  70, *ev_args)
    _add_evidence(evidence, "ipAddress",         source_ip,          SourceType.PCAP,  90, *ev_args)
    _add_evidence(evidence, "destinationIp",     dest_ip,            SourceType.PCAP,  70, *ev_args)
    _add_evidence(evidence, "dhcpHostname",      dhcp_hostname,      SourceType.DHCP,  95, *ev_args)
    _add_evidence(evidence, "bootpHostname",     bootp_hostname,     SourceType.DHCP,  92, *ev_args)
    _add_evidence(evidence, "httpHost",          http_host,          SourceType.PCAP,  85, *ev_args)
    _add_evidence(evidence, "nbnsName",          nbns_name,          SourceType.NBNS,  80, *ev_args)
    _add_evidence(evidence, "nbnsNetbiosName",   nbns_netbios_name,  SourceType.NBNS,  80, *ev_args)
    _add_evidence(evidence, "mdnsName",          mdns_name,          SourceType.MDNS,  75, *ev_args)
    _add_evidence(evidence, "llmnrName",         llmnr_name,         SourceType.LLMNR, 70, *ev_args)
    _add_evidence(evidence, "dnsPtr",            dns_ptr,            SourceType.DNS,   72, *ev_args)
    _add_evidence(evidence, "dnsQuery",          dns_query,          SourceType.DNS,   60, *ev_args)
    _add_evidence(evidence, "vendor",            vendor,             SourceType.PCAP,  60, *ev_args)

    # ── Assemble signal ────────────────────────────────────────────────────
    return IdentitySignal(
        # provenance
        packetNumber=packet_number,
        captureId=capture_id,
        observedAt=observed_at,
        sourceType=SourceType.PCAP,

        # layer-2
        macAddress=source_mac,
        sourceMac=source_mac,
        destinationMac=dest_mac,

        # layer-3
        ipAddress=source_ip,
        sourceIp=source_ip,
        destinationIp=dest_ip,

        # name resolution
        hostname=resolved_hostname or (hostnames[0] if hostnames else None),
        hostnames=hostnames,
        deviceName=resolved_device_name,

        # protocol-layer name signals
        dhcpHostname=dhcp_hostname,
        bootpHostname=bootp_hostname,
        httpHost=http_host,
        mdnsName=mdns_name,
        nbnsName=nbns_name,
        nbnsNetbiosName=nbns_netbios_name,
        llmnrName=llmnr_name,
        dnsPtr=dns_ptr,
        dnsNames=dns_names,

        # hardware / OS
        vendor=vendor,
        operatingSystem=None,   # populated by future Nmap / Sysmon extractor
        userAgent=None,         # populated by future HTTP-layer extractor

        # network observables
        openPorts=[],           # populated by future Nmap extractor
        services=[],            # populated by future banner / Nmap extractor
        protocols=protocols,
        ssid=None,              # populated by future 802.11 extractor

        # evidence
        confidenceHints=evidence,

        # extension bag
        metadata={},
    )


# ---------------------------------------------------------------------------
# Internal helpers used by extract_identity_signals
# ---------------------------------------------------------------------------

def _parse_observed_at(time_value: Any) -> Optional[datetime]:
    """
    Best-effort parse of a frame.time string into a UTC datetime.
    Returns None if parsing fails — never raises.
    """
    if time_value is None:
        return None
    s = str(time_value).strip()
    if not s:
        return None
    # tshark default time format: "Jun 29, 2026 14:32:01.123456789 UTC"
    # Attempt ISO 8601 first (future-proof), then tshark format.
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Fall back: return now as a best-effort timestamp
    return None


def _add_evidence(
    evidence_list: List[SignalEvidence],
    field_name: str,
    field_value: Optional[str],
    source: SourceType,
    confidence: int,
    packet_number: Optional[int],
    capture_id: Optional[str],
    observed_at: Optional[datetime],
) -> None:
    """Append a SignalEvidence item only if field_value is non-empty."""
    item = _make_evidence(
        field_name, field_value, source, confidence,
        packet_number, capture_id, observed_at,
    )
    if item:
        evidence_list.append(item)


# ---------------------------------------------------------------------------
# Future extension points
# ---------------------------------------------------------------------------
# To add a new signal source, follow this pattern:
#
#   1.  Add an entry to SourceType (e.g. SourceType.ZEEK = "zeek").
#
#   2.  Create a new extractor function with the signature:
#           def extract_from_<source>(raw: dict) -> IdentitySignal
#       normalise the raw record into the same packet-dict shape
#       (or populate IdentitySignal fields directly), then call
#       extract_identity_signals() or build the IdentitySignal manually.
#
#   3.  Register the extractor in _EXTRACTOR_REGISTRY below.
#
#   4.  The Asset Resolution Engine (future phase) will merge signals
#       from multiple extractors using AssetFieldEvidence.

_EXTRACTOR_REGISTRY: Dict[SourceType, Any] = {
    SourceType.PCAP: extract_identity_signals,
    # SourceType.NMAP:     extract_from_nmap,     # future
    # SourceType.ZEEK:     extract_from_zeek,     # future
    # SourceType.SYSMON:   extract_from_sysmon,   # future
    # SourceType.SURICATA: extract_from_suricata, # future
    # SourceType.WINDOWS:  extract_from_windows,  # future
    # SourceType.DHCP:     extract_from_dhcp,     # future
    # SourceType.MDNS:     extract_from_mdns,     # future
    # SourceType.NBNS:     extract_from_nbns,     # future
    # SourceType.LLMNR:    extract_from_llmnr,    # future
}
