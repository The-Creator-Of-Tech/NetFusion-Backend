"""
Asset Repository — storage and retrieval of Asset records.

Responsibilities:
  - Build and cache assets from packet data (in-memory, per capture file)
  - Look up assets by IP, MAC, asset ID, or previous IP
  - No business logic; storage access only.

The asset business logic (risk scoring, identity merging, etc.) lives in
services/asset_service.py.  This repository is only concerned with WHERE
assets are stored and HOW they are retrieved.

Dependency chain: main.py → services → asset_repository → (in-memory / Prisma)
"""

from services.asset_service import build_assets_from_packets, find_asset_by_id, find_asset_by_ip
from services import packet_service


# ---------------------------------------------------------------------------
# In-memory asset cache  (capture_file_path -> list[asset dict])
# ---------------------------------------------------------------------------
_asset_cache: dict = {}


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _load_assets_for_file(capture_file: str) -> list:
    """
    Return the cached asset list for *capture_file*, building it from packets
    if not yet cached.
    """
    if not capture_file:
        return []
    if capture_file not in _asset_cache:
        packets = packet_service.get_packet_list(capture_file)
        _asset_cache[capture_file] = build_assets_from_packets(packets)
    return _asset_cache[capture_file]


def invalidate_cache(capture_file: str = None) -> None:
    """
    Invalidate the asset cache.
    Pass a specific *capture_file* to clear only that entry, or None to clear all.
    """
    if capture_file:
        _asset_cache.pop(capture_file, None)
    else:
        _asset_cache.clear()


# ---------------------------------------------------------------------------
# Lookup queries
# ---------------------------------------------------------------------------

def get_all_assets(capture_file: str) -> list:
    """Return all assets derived from *capture_file*."""
    return _load_assets_for_file(capture_file)


def get_asset_by_ip(ip: str, capture_file: str) -> dict:
    """
    Return the asset whose currentIp or previousIPs matches *ip*,
    built from *capture_file*.  Returns None if not found.
    """
    assets = _load_assets_for_file(capture_file)
    return find_asset_by_ip(ip, assets)


def get_asset_by_id(asset_id: str, capture_file: str) -> dict:
    """
    Return the asset whose assetId or macAddress matches *asset_id*,
    built from *capture_file*.  Returns None if not found.
    """
    assets = _load_assets_for_file(capture_file)
    return find_asset_by_id(asset_id, assets)


def get_asset_by_mac(mac: str, capture_file: str) -> dict:
    """
    Return the asset whose macAddress matches *mac*,
    built from *capture_file*.  Returns None if not found.
    """
    assets = _load_assets_for_file(capture_file)
    for asset in assets:
        if asset.get("macAddress") == mac:
            return asset
    return None


def get_asset_by_previous_ip(ip: str, capture_file: str) -> dict:
    """
    Return the first asset that has *ip* in its previousIPs list.
    """
    assets = _load_assets_for_file(capture_file)
    for asset in assets:
        if ip in asset.get("previousIPs", []):
            return asset
    return None
