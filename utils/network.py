"""Network address and MAC utility functions."""

import ipaddress
import re
from collections import Counter

from core.constants import DEFAULT_VENDOR, OUI_VENDOR_MAP


def normalize_mac(mac: str):
    if not mac:
        return None
    mac = str(mac).strip()
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) != 12:
        return mac.upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def lookup_mac_vendor(mac: str):
    if not mac:
        return DEFAULT_VENDOR
    normalized = normalize_mac(mac)
    if not normalized or len(normalized) < 8:
        return DEFAULT_VENDOR
    return OUI_VENDOR_MAP.get(normalized[:8], DEFAULT_VENDOR)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private or internal."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except Exception:
        return False


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address is public (not private, loopback, or multicast)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except Exception:
        return False


def extract_ip_from_text(text: str):
    if not text:
        return None
    words = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    for word in words:
        try:
            ipaddress.ip_address(word)
            return word
        except Exception:
            continue
    return None


def select_best_mac_for_ip(ip: str, packets: list):
    if not ip or not packets:
        return None

    mac_counts = Counter()
    for packet in packets:
        if packet.get("src") == ip:
            mac = normalize_mac(packet.get("mac_src"))
            if mac:
                mac_counts[mac] += 1
        if packet.get("dst") == ip:
            mac = normalize_mac(packet.get("mac_dst"))
            if mac:
                mac_counts[mac] += 1

    if not mac_counts:
        return None

    return mac_counts.most_common(1)[0][0]
