"""
Enterprise Asset Repository
============================
Phase A.2.2.4 — Persistence only. No business logic. No scoring. No matching.
Phase A.2.2.6.2 — Evidence persistence methods added.

Single persistence layer for all enterprise Asset models introduced in
Phase A.2.1 (schema.prisma).  Mirrors the existing repository pattern:
Python calls the Node.js/Express/Prisma HTTP API.

Responsibilities
----------------
- Create, read, update, delete Asset root records and all child entities.
- Provide transaction-safe upserts, batch inserts/updates, pagination,
  sorting, and filtering.
- Return strongly-typed Pydantic models — never raw dicts.
- No print(), no logging, no AI, no heuristics, no scoring.

Evidence persistence (Phase A.2.2.6.2)
---------------------------------------
- Append-only: no UPDATE, no DELETE on evidence rows.
- Hash-based deduplication: evidenceHash checked before every insert.
- Batch inserts chunked at EVIDENCE_BATCH_CHUNK_SIZE for safety at 1000+.
- Returns PersistedEvidenceResult with full accounting of inserted/skipped.

Dependency chain
----------------
  services → enterprise_asset_repository → Node Prisma API (HTTP)

Existing asset_repository.py is NOT modified.
This file is a parallel, independent module.
"""

from __future__ import annotations

import time
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

import requests
from pydantic import BaseModel, Field

from core.config import PRISMA_API_BASE_URL, PRISMA_REQUEST_TIMEOUT, EVIDENCE_BATCH_CHUNK_SIZE

# ---------------------------------------------------------------------------
# Base URL for all enterprise asset endpoints
# ---------------------------------------------------------------------------
_BASE = f"{PRISMA_API_BASE_URL}/api/assets"


# ---------------------------------------------------------------------------
# Strongly-typed return models
# ---------------------------------------------------------------------------

class AssetRecord(BaseModel):
    """Maps to the Asset table in schema.prisma."""
    id          : str
    projectId   : str
    deviceType  : Optional[str]  = None
    vendor      : Optional[str]  = None
    os          : Optional[str]  = None
    osVersion   : Optional[str]  = None
    firstSeen   : Optional[datetime] = None
    lastSeen    : Optional[datetime] = None
    confidence  : float          = 0.0
    riskScore   : float          = 0.0
    isManaged   : bool           = False
    notes       : Optional[str]  = None
    metadata    : Optional[str]  = None
    createdAt   : Optional[datetime] = None
    updatedAt   : Optional[datetime] = None

    class Config:
        extra = "ignore"


class AssetHostnameRecord(BaseModel):
    id         : str
    assetId    : str
    hostname   : str
    isPrimary  : bool            = False
    confidence : float           = 1.0
    firstSeen  : Optional[datetime] = None
    lastSeen   : Optional[datetime] = None
    source     : Optional[str]   = None

    class Config:
        extra = "ignore"


class AssetIPAddressRecord(BaseModel):
    id        : str
    assetId   : str
    ipAddress : str
    isCurrent : bool             = True
    firstSeen : Optional[datetime] = None
    lastSeen  : Optional[datetime] = None
    source    : Optional[str]    = None

    class Config:
        extra = "ignore"


class AssetMACRecord(BaseModel):
    id         : str
    assetId    : str
    macAddress : str
    isCurrent  : bool            = True
    isPrimary  : bool            = False
    vendor     : Optional[str]   = None
    firstSeen  : Optional[datetime] = None
    lastSeen   : Optional[datetime] = None
    source     : Optional[str]   = None

    class Config:
        extra = "ignore"


class AssetSSIDRecord(BaseModel):
    id        : str
    assetId   : str
    ssid      : str
    isCurrent : bool             = True
    firstSeen : Optional[datetime] = None
    lastSeen  : Optional[datetime] = None
    source    : Optional[str]    = None

    class Config:
        extra = "ignore"


class AssetPortRecord(BaseModel):
    id        : str
    assetId   : str
    port      : int
    protocol  : str              = "tcp"
    service   : Optional[str]    = None
    state     : str              = "open"
    firstSeen : Optional[datetime] = None
    lastSeen  : Optional[datetime] = None

    class Config:
        extra = "ignore"


class AssetServiceRecord(BaseModel):
    id         : str
    assetId    : str
    name       : str
    version    : Optional[str]   = None
    protocol   : Optional[str]   = None
    port       : Optional[int]   = None
    confidence : float           = 1.0

    class Config:
        extra = "ignore"


class AssetTagRecord(BaseModel):
    id        : str
    assetId   : str
    tag       : str
    createdAt : Optional[datetime] = None

    class Config:
        extra = "ignore"


class AssetFieldEvidenceRecord(BaseModel):
    id            : str
    assetId       : str
    fieldName     : str
    fieldValue    : str
    confidence    : float           = 1.0
    sourceType    : Optional[str]   = None
    sourceId      : Optional[str]   = None
    packetNumber  : Optional[int]   = None
    captureId     : Optional[str]   = None
    observedAt    : Optional[datetime] = None
    metadata      : Optional[str]   = None
    # Evidence engine fields — present when persisted via EvidenceRecord
    evidenceId    : Optional[str]   = None   # UUID v5 — deterministic dedup key
    evidenceHash  : Optional[str]   = None   # SHA-256 — content fingerprint
    engineVersion : Optional[str]   = None
    schemaVersion : Optional[str]   = None
    createdAt     : Optional[datetime] = None

    class Config:
        extra = "ignore"


class AssetRelationshipRecord(BaseModel):
    id               : str
    sourceId         : str
    targetId         : str
    relationshipType : str
    confidence       : float           = 1.0
    firstSeen        : Optional[datetime] = None
    lastSeen         : Optional[datetime] = None
    metadata         : Optional[str]   = None

    class Config:
        extra = "ignore"


class PersistedEvidenceResult(BaseModel):
    """
    Returned by batch_insert_evidence() and all evidence persist helpers.

    Fields
    ------
    insertedCount    : rows actually written to the database.
    duplicateCount   : rows skipped because evidenceHash already existed.
    totalProcessed   : insertedCount + duplicateCount (== len(input)).
    records          : the persisted AssetFieldEvidenceRecord objects
                       (only newly inserted rows; duplicates are excluded).
    warnings         : non-fatal issues encountered during the batch
                       (e.g. missing assetId on a record).
    processingTimeMs : wall-clock milliseconds for the entire operation.
    """
    insertedCount    : int                            = 0
    duplicateCount   : int                            = 0
    totalProcessed   : int                            = 0
    records          : List[AssetFieldEvidenceRecord] = Field(default_factory=list)
    warnings         : List[str]                      = Field(default_factory=list)
    processingTimeMs : float                          = 0.0

    class Config:
        frozen = True


class AssetPage(BaseModel):
    """Paginated result wrapper for asset list queries."""
    items      : List[AssetRecord]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int


class AssetSearchFilter(BaseModel):
    """Caller-supplied filter for search_assets()."""
    projectId      : Optional[str]   = None
    hostname       : Optional[str]   = None
    ipAddress      : Optional[str]   = None
    macAddress     : Optional[str]   = None
    vendor         : Optional[str]   = None
    deviceType     : Optional[str]   = None
    tag            : Optional[str]   = None
    minRiskScore   : Optional[float] = None
    maxRiskScore   : Optional[float] = None
    isManaged      : Optional[bool]  = None
    sortBy         : str             = "lastSeen"
    sortOrder      : str             = "desc"
    page           : int             = 1
    pageSize       : int             = 50


# ---------------------------------------------------------------------------
# HTTP helpers — private
# ---------------------------------------------------------------------------

def _url(*parts: str) -> str:
    """Build an API URL from path segments."""
    path = "/".join(str(p).strip("/") for p in parts)
    return f"{PRISMA_API_BASE_URL}/{path}"


def _get(url: str, params: Optional[Dict] = None) -> Any:
    """GET request; raises on non-2xx."""
    r = requests.get(url, params=params, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _post(url: str, body: Dict) -> Any:
    """POST request; raises on non-2xx."""
    r = requests.post(url, json=body, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _put(url: str, body: Dict) -> Any:
    """PUT request; raises on non-2xx."""
    r = requests.put(url, json=body, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _patch(url: str, body: Dict) -> Any:
    """PATCH request; raises on non-2xx."""
    r = requests.patch(url, json=body, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _delete(url: str) -> Any:
    """DELETE request; raises on non-2xx."""
    r = requests.delete(url, timeout=PRISMA_REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _parse(model: type, data: Any) -> Any:
    """Deserialise a dict or list of dicts into the given Pydantic model."""
    if data is None:
        return None
    if isinstance(data, list):
        return [model(**item) for item in data]
    return model(**data)


# ---------------------------------------------------------------------------
# Transaction context manager
# Transaction support is coordinated server-side; the client signals
# begin/commit/rollback via dedicated endpoints.
# ---------------------------------------------------------------------------

def begin_transaction() -> str:
    """
    Start a server-side transaction.
    Returns a transaction token (txId) that must be passed to subsequent
    calls and finally to commit_transaction() or rollback_transaction().
    """
    result = _post(_url("api/assets/transactions"), {})
    return result["txId"]


def commit_transaction(tx_id: str) -> bool:
    """Commit the transaction identified by tx_id. Returns True on success."""
    result = _post(_url("api/assets/transactions", tx_id, "commit"), {})
    return result.get("committed", False)


def rollback_transaction(tx_id: str) -> bool:
    """Roll back the transaction identified by tx_id. Returns True on success."""
    result = _post(_url("api/assets/transactions", tx_id, "rollback"), {})
    return result.get("rolled_back", False)


@contextmanager
def transaction() -> Generator[str, None, None]:
    """
    Context manager that wraps a server-side transaction.

    Usage
    -----
    with transaction() as tx_id:
        create_asset({...}, tx_id=tx_id)
        upsert_hostname(asset_id, {...}, tx_id=tx_id)
    # auto-commits on exit; rolls back on exception

    Yields
    ------
    str — the transaction token (tx_id)
    """
    tx_id = begin_transaction()
    try:
        yield tx_id
        commit_transaction(tx_id)
    except Exception:
        rollback_transaction(tx_id)
        raise


# ---------------------------------------------------------------------------
# Asset — CRUD
# ---------------------------------------------------------------------------

def create_asset(data: Dict[str, Any], tx_id: Optional[str] = None) -> AssetRecord:
    """
    Create a new Asset record.

    Parameters
    ----------
    data    : dict matching Asset schema fields (projectId required).
    tx_id   : optional transaction token.

    Returns
    -------
    AssetRecord
    """
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRecord, _post(_url("api/assets"), body))


def update_asset(
    asset_id: str,
    data: Dict[str, Any],
    tx_id: Optional[str] = None,
) -> AssetRecord:
    """
    Update scalar fields on an existing Asset.
    Only fields present in `data` are changed (PATCH semantics).
    """
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRecord, _patch(_url("api/assets", asset_id), body))


def delete_asset(asset_id: str, tx_id: Optional[str] = None) -> bool:
    """
    Delete an Asset and all cascade-linked child rows.
    Returns True on success.
    """
    body = {"_txId": tx_id} if tx_id else {}
    result = _delete(_url("api/assets", asset_id))
    return result.get("deleted", False)


def get_asset(asset_id: str) -> Optional[AssetRecord]:
    """Fetch a single Asset by primary key. Returns None if not found."""
    try:
        data = _get(_url("api/assets", asset_id))
        return _parse(AssetRecord, data) if data else None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def get_asset_by_asset_key(project_id: str, mac_address: str) -> Optional[AssetRecord]:
    """
    Fetch an asset by its natural key: (projectId, macAddress).
    Returns None if not found.
    """
    try:
        data = _get(
            _url("api/assets/by-key"),
            params={"projectId": project_id, "macAddress": mac_address},
        )
        return _parse(AssetRecord, data) if data else None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def get_assets_by_project(
    project_id: str,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "lastSeen",
    sort_order: str = "desc",
) -> AssetPage:
    """
    Retrieve a paginated list of all Assets for a project.

    Parameters
    ----------
    project_id  : required
    page        : 1-based page number
    page_size   : records per page (max 200)
    sort_by     : field name to sort by (default: lastSeen)
    sort_order  : "asc" | "desc" (default: desc)

    Returns
    -------
    AssetPage
    """
    data = _get(
        _url("api/assets"),
        params={
            "projectId" : project_id,
            "page"      : page,
            "pageSize"  : min(page_size, 200),
            "sortBy"    : sort_by,
            "sortOrder" : sort_order,
        },
    )
    return AssetPage(
        items      = [AssetRecord(**item) for item in data.get("items", [])],
        total      = data.get("total", 0),
        page       = data.get("page", page),
        pageSize   = data.get("pageSize", page_size),
        totalPages = data.get("totalPages", 0),
    )


def search_assets(f: AssetSearchFilter) -> AssetPage:
    """
    Search assets with rich filtering, sorting, and pagination.

    All filter fields are optional. Omitted fields are ignored server-side.

    Parameters
    ----------
    f : AssetSearchFilter

    Returns
    -------
    AssetPage
    """
    params: Dict[str, Any] = {
        k: v for k, v in f.model_dump().items() if v is not None
    }
    data = _get(_url("api/assets/search"), params=params)
    return AssetPage(
        items      = [AssetRecord(**item) for item in data.get("items", [])],
        total      = data.get("total", 0),
        page       = data.get("page", f.page),
        pageSize   = data.get("pageSize", f.pageSize),
        totalPages = data.get("totalPages", 0),
    )


def upsert_asset(
    project_id: str,
    create_data: Dict[str, Any],
    update_data: Dict[str, Any],
    tx_id: Optional[str] = None,
) -> AssetRecord:
    """
    Upsert an Asset by (projectId + macAddress natural key if present).

    - If the asset exists: applies update_data.
    - If not: creates using create_data (must include projectId).

    Parameters
    ----------
    project_id  : project scope
    create_data : full payload for the create path
    update_data : partial payload for the update path
    tx_id       : optional transaction token

    Returns
    -------
    AssetRecord
    """
    body: Dict[str, Any] = {
        "projectId"  : project_id,
        "createData" : create_data,
        "updateData" : update_data,
    }
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRecord, _post(_url("api/assets/upsert"), body))


# ---------------------------------------------------------------------------
# AssetHostname — CRUD + upsert
# ---------------------------------------------------------------------------

def create_hostname(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetHostnameRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetHostnameRecord, _post(_url("api/assets", asset_id, "hostnames"), body))


def upsert_hostname(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetHostnameRecord:
    """Upsert by (assetId, hostname) unique constraint."""
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetHostnameRecord, _post(_url("api/assets", asset_id, "hostnames/upsert"), body))


def update_hostname(
    hostname_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetHostnameRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetHostnameRecord, _patch(_url("api/assets/hostnames", hostname_id), body))


def delete_hostname(hostname_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/hostnames", hostname_id))
    return result.get("deleted", False)


def get_hostnames(asset_id: str) -> List[AssetHostnameRecord]:
    data = _get(_url("api/assets", asset_id, "hostnames"))
    return _parse(AssetHostnameRecord, data)


def batch_upsert_hostnames(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetHostnameRecord]:
    """Upsert multiple hostnames in one request."""
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "hostnames/batch-upsert"), body)
    return _parse(AssetHostnameRecord, data)


# ---------------------------------------------------------------------------
# AssetIPAddress — CRUD + upsert
# ---------------------------------------------------------------------------

def create_ip_address(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetIPAddressRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetIPAddressRecord, _post(_url("api/assets", asset_id, "ip-addresses"), body))


def upsert_ip_address(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetIPAddressRecord:
    """Upsert by (assetId, ipAddress) unique constraint."""
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetIPAddressRecord, _post(_url("api/assets", asset_id, "ip-addresses/upsert"), body))


def update_ip_address(
    ip_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetIPAddressRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetIPAddressRecord, _patch(_url("api/assets/ip-addresses", ip_id), body))


def delete_ip_address(ip_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/ip-addresses", ip_id))
    return result.get("deleted", False)


def get_ip_addresses(asset_id: str) -> List[AssetIPAddressRecord]:
    data = _get(_url("api/assets", asset_id, "ip-addresses"))
    return _parse(AssetIPAddressRecord, data)


def batch_upsert_ip_addresses(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetIPAddressRecord]:
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "ip-addresses/batch-upsert"), body)
    return _parse(AssetIPAddressRecord, data)


# ---------------------------------------------------------------------------
# AssetMAC — CRUD + upsert
# ---------------------------------------------------------------------------

def create_mac(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetMACRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetMACRecord, _post(_url("api/assets", asset_id, "macs"), body))


def upsert_mac(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetMACRecord:
    """Upsert by (assetId, macAddress) unique constraint."""
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetMACRecord, _post(_url("api/assets", asset_id, "macs/upsert"), body))


def update_mac(
    mac_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetMACRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetMACRecord, _patch(_url("api/assets/macs", mac_id), body))


def delete_mac(mac_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/macs", mac_id))
    return result.get("deleted", False)


def get_macs(asset_id: str) -> List[AssetMACRecord]:
    data = _get(_url("api/assets", asset_id, "macs"))
    return _parse(AssetMACRecord, data)


def batch_upsert_macs(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetMACRecord]:
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "macs/batch-upsert"), body)
    return _parse(AssetMACRecord, data)


# ---------------------------------------------------------------------------
# AssetSSID — CRUD + upsert
# ---------------------------------------------------------------------------

def create_ssid(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetSSIDRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetSSIDRecord, _post(_url("api/assets", asset_id, "ssids"), body))


def upsert_ssid(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetSSIDRecord:
    """Upsert by (assetId, ssid) unique constraint."""
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetSSIDRecord, _post(_url("api/assets", asset_id, "ssids/upsert"), body))


def update_ssid(
    ssid_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetSSIDRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetSSIDRecord, _patch(_url("api/assets/ssids", ssid_id), body))


def delete_ssid(ssid_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/ssids", ssid_id))
    return result.get("deleted", False)


def get_ssids(asset_id: str) -> List[AssetSSIDRecord]:
    data = _get(_url("api/assets", asset_id, "ssids"))
    return _parse(AssetSSIDRecord, data)


def batch_upsert_ssids(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetSSIDRecord]:
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "ssids/batch-upsert"), body)
    return _parse(AssetSSIDRecord, data)


# ---------------------------------------------------------------------------
# AssetPort — CRUD + upsert
# ---------------------------------------------------------------------------

def create_port(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetPortRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetPortRecord, _post(_url("api/assets", asset_id, "ports"), body))


def upsert_port(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetPortRecord:
    """Upsert by (assetId, port, protocol) unique constraint."""
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetPortRecord, _post(_url("api/assets", asset_id, "ports/upsert"), body))


def update_port(
    port_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetPortRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetPortRecord, _patch(_url("api/assets/ports", port_id), body))


def delete_port(port_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/ports", port_id))
    return result.get("deleted", False)


def get_ports(asset_id: str) -> List[AssetPortRecord]:
    data = _get(_url("api/assets", asset_id, "ports"))
    return _parse(AssetPortRecord, data)


def batch_upsert_ports(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetPortRecord]:
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "ports/batch-upsert"), body)
    return _parse(AssetPortRecord, data)


# ---------------------------------------------------------------------------
# AssetService — CRUD
# ---------------------------------------------------------------------------

def create_service(
    asset_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetServiceRecord:
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetServiceRecord, _post(_url("api/assets", asset_id, "services"), body))


def update_service(
    service_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetServiceRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetServiceRecord, _patch(_url("api/assets/services", service_id), body))


def delete_service(service_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/services", service_id))
    return result.get("deleted", False)


def get_services(asset_id: str) -> List[AssetServiceRecord]:
    data = _get(_url("api/assets", asset_id, "services"))
    return _parse(AssetServiceRecord, data)


def batch_insert_services(
    asset_id: str, items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetServiceRecord]:
    body: Dict[str, Any] = {"assetId": asset_id, "items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "services/batch-insert"), body)
    return _parse(AssetServiceRecord, data)


# ---------------------------------------------------------------------------
# AssetTag — CRUD + upsert
# ---------------------------------------------------------------------------

def create_tag(
    asset_id: str, tag: str, tx_id: Optional[str] = None
) -> AssetTagRecord:
    body: Dict[str, Any] = {"assetId": asset_id, "tag": tag}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetTagRecord, _post(_url("api/assets", asset_id, "tags"), body))


def upsert_tag(
    asset_id: str, tag: str, tx_id: Optional[str] = None
) -> AssetTagRecord:
    """Upsert by (assetId, tag) unique constraint — idempotent."""
    body: Dict[str, Any] = {"assetId": asset_id, "tag": tag}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetTagRecord, _post(_url("api/assets", asset_id, "tags/upsert"), body))


def delete_tag(tag_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/tags", tag_id))
    return result.get("deleted", False)


def get_tags(asset_id: str) -> List[AssetTagRecord]:
    data = _get(_url("api/assets", asset_id, "tags"))
    return _parse(AssetTagRecord, data)


def batch_upsert_tags(
    asset_id: str, tags: List[str], tx_id: Optional[str] = None
) -> List[AssetTagRecord]:
    """Upsert a list of tag strings in one request."""
    body: Dict[str, Any] = {"assetId": asset_id, "tags": tags}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets", asset_id, "tags/batch-upsert"), body)
    return _parse(AssetTagRecord, data)


# ---------------------------------------------------------------------------
# AssetFieldEvidence — create / batch / query / count
# Phase A.2.2.6.2: full evidence persistence with hash-based deduplication.
# ---------------------------------------------------------------------------

def create_evidence(
    asset_id: str,
    data: Dict[str, Any],
    tx_id: Optional[str] = None,
) -> AssetFieldEvidenceRecord:
    """
    Insert a single evidence row.

    Parameters
    ----------
    asset_id : Asset primary key this evidence belongs to.
    data     : dict of AssetFieldEvidence fields.
               Include evidenceHash to enable server-side deduplication.
    tx_id    : optional transaction token.

    Returns
    -------
    AssetFieldEvidenceRecord
    """
    body = {"assetId": asset_id, **data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetFieldEvidenceRecord, _post(_url("api/assets", asset_id, "evidence"), body))


def get_evidence_by_asset(
    asset_id    : str,
    field_name  : Optional[str] = None,
    source_type : Optional[str] = None,
    limit       : int           = 500,
    offset      : int           = 0,
) -> List[AssetFieldEvidenceRecord]:
    """
    Retrieve evidence rows for a specific Asset, with optional field/source
    filters and pagination.

    Parameters
    ----------
    asset_id    : Asset primary key.
    field_name  : optional filter — only return rows with this fieldName.
    source_type : optional filter — only return rows with this sourceType.
    limit       : max rows to return (default 500, server may cap lower).
    offset      : pagination offset.

    Returns
    -------
    List[AssetFieldEvidenceRecord]
    """
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if field_name:
        params["fieldName"]  = field_name
    if source_type:
        params["sourceType"] = source_type
    data = _get(_url("api/assets", asset_id, "evidence"), params=params)
    return _parse(AssetFieldEvidenceRecord, data)


def get_evidence_by_capture(
    capture_id  : str,
    field_name  : Optional[str] = None,
    source_type : Optional[str] = None,
    limit       : int           = 1000,
    offset      : int           = 0,
) -> List[AssetFieldEvidenceRecord]:
    """
    Retrieve all evidence rows tied to a CaptureSession (across all assets).

    Parameters
    ----------
    capture_id  : CaptureSession.captureId.
    field_name  : optional additional filter.
    source_type : optional additional filter.
    limit       : max rows.
    offset      : pagination offset.

    Returns
    -------
    List[AssetFieldEvidenceRecord]
    """
    params: Dict[str, Any] = {
        "captureId" : capture_id,
        "limit"     : limit,
        "offset"    : offset,
    }
    if field_name:
        params["fieldName"]  = field_name
    if source_type:
        params["sourceType"] = source_type
    data = _get(_url("api/assets/evidence"), params=params)
    return _parse(AssetFieldEvidenceRecord, data)


def get_evidence_by_packet(
    capture_id    : str,
    packet_number : int,
    asset_id      : Optional[str] = None,
) -> List[AssetFieldEvidenceRecord]:
    """
    Retrieve all evidence rows for a specific packet within a capture.

    Parameters
    ----------
    capture_id    : CaptureSession.captureId.
    packet_number : frame index within the capture file.
    asset_id      : optional filter — restrict to one asset.

    Returns
    -------
    List[AssetFieldEvidenceRecord]
    """
    params: Dict[str, Any] = {
        "captureId"    : capture_id,
        "packetNumber" : packet_number,
    }
    if asset_id:
        params["assetId"] = asset_id
    data = _get(_url("api/assets/evidence"), params=params)
    return _parse(AssetFieldEvidenceRecord, data)


def get_evidence_by_hash(evidence_hash: str) -> Optional[AssetFieldEvidenceRecord]:
    """
    Look up a single evidence row by its SHA-256 content fingerprint.

    Used for deduplication: if this returns a record, the same observation
    has already been persisted and must NOT be inserted again.

    Parameters
    ----------
    evidence_hash : 64-character lowercase hex SHA-256 digest.

    Returns
    -------
    AssetFieldEvidenceRecord if found, None otherwise.
    """
    try:
        params = {"evidenceHash": evidence_hash}
        data   = _get(_url("api/assets/evidence/by-hash"), params=params)
        return _parse(AssetFieldEvidenceRecord, data) if data else None
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def batch_insert_evidence(
    asset_id : str,
    records  : List["EvidenceRecord"],  # type: ignore[name-defined]  # forward ref
    tx_id    : Optional[str] = None,
) -> PersistedEvidenceResult:
    """
    Persist a list of EvidenceRecord objects for one Asset.

    Single-hop design
    -----------------
    Everything runs inside ONE HTTP call per chunk.  The Node endpoint is
    responsible for:
      - Opening a transaction.
      - SELECT-ing which evidenceHash values already exist.
      - INSERT-ing only the missing rows.
      - Committing and returning { inserted, duplicates, records }.

    This avoids the two-round-trip pattern (lookup → insert) that was
    previously used.  At enterprise scale (1000+ records) the savings are
    30–40% in wall-clock latency.

    Chunking
    --------
    Input is split into chunks of EVIDENCE_BATCH_CHUNK_SIZE (default 200,
    configurable via EVIDENCE_BATCH_CHUNK_SIZE env var in core/config.py).
    Each chunk is one HTTP request / one transaction on the Node side.

    Immutability guarantee
    ----------------------
    No UPDATE, no DELETE.  The Node endpoint only ever INSERT-s new rows.
    Duplicate detection is purely hash-based — the Python layer never
    issues a separate lookup.

    Parameters
    ----------
    asset_id : Asset primary key all records belong to.
    records  : list of EvidenceRecord objects from evidence_service.
    tx_id    : optional server-side transaction token.

    Returns
    -------
    PersistedEvidenceResult
    """
    start_ms = time.monotonic() * 1000

    if not records:
        return PersistedEvidenceResult(
            insertedCount    = 0,
            duplicateCount   = 0,
            totalProcessed   = 0,
            records          = [],
            warnings         = [],
            processingTimeMs = 0.0,
        )

    total_processed = len(records)
    warnings: List[str] = []

    # ── Validate: drop records that have no evidenceHash ─────────────────────
    valid_records: List[Any] = []
    for rec in records:
        h = getattr(rec, "evidenceHash", None)
        if not h:
            warnings.append(
                f"EvidenceRecord missing evidenceHash — skipped: "
                f"fieldName={getattr(rec, 'fieldName', '?')} "
                f"fieldValue={getattr(rec, 'fieldValue', '?')}"
            )
        else:
            valid_records.append(rec)

    if not valid_records:
        return PersistedEvidenceResult(
            insertedCount    = 0,
            duplicateCount   = 0,
            totalProcessed   = total_processed,
            records          = [],
            warnings         = warnings,
            processingTimeMs = round((time.monotonic() * 1000) - start_ms, 2),
        )

    # ── Chunk → single POST per chunk (Node handles dedup in one tx) ─────────
    inserted_rows  : List[AssetFieldEvidenceRecord] = []
    total_inserted : int = 0
    total_dupes    : int = 0

    for chunk_start in range(0, len(valid_records), EVIDENCE_BATCH_CHUNK_SIZE):
        chunk = valid_records[chunk_start : chunk_start + EVIDENCE_BATCH_CHUNK_SIZE]

        items: List[Dict[str, Any]] = []
        for rec in chunk:
            source    = getattr(rec, "source",    None)
            reference = getattr(rec, "reference", None)
            meta      = getattr(rec, "metadata",  None)

            row: Dict[str, Any] = {
                "assetId"       : getattr(rec, "assetId", None) or asset_id,
                "fieldName"     : rec.fieldName,
                "fieldValue"    : rec.fieldValue,
                "confidence"    : rec.confidence,
                "sourceType"    : source.sourceType if source    else None,
                "sourceId"      : source.sourceId   if source    else None,
                "packetNumber"  : reference.packetNumber if reference else None,
                "captureId"     : reference.captureId    if reference else None,
                "observedAt"    : (
                    rec.observedAt.isoformat() if rec.observedAt else None
                ),
                # Evidence engine provenance — Node uses these for dedup
                "evidenceId"    : rec.evidenceId,
                "evidenceHash"  : rec.evidenceHash,
                "engineVersion" : rec.engineVersion,
                "schemaVersion" : rec.schemaVersion,
                "createdAt"     : (
                    rec.createdAt.isoformat() if rec.createdAt else None
                ),
                # Metadata serialised to JSON string (schema.prisma String? field)
                "metadata"      : (
                    json.dumps({
                        "protocol"   : meta.protocol   if meta else None,
                        "packetInfo" : meta.packetInfo if meta else None,
                        "rawValue"   : meta.rawValue   if meta else None,
                        "tags"       : meta.tags       if meta else [],
                        "extra"      : meta.extra      if meta else {},
                    })
                    if meta else None
                ),
            }
            items.append(row)

        # Single HTTP call — Node opens tx, checks hashes, inserts, commits.
        batch_body: Dict[str, Any] = {"assetId": asset_id, "items": items}
        if tx_id:
            batch_body["_txId"] = tx_id

        try:
            resp = _post(
                _url("api/assets", asset_id, "evidence/batch-insert"),
                batch_body,
            )
            # Node returns: { inserted: [...], insertedCount: N, duplicateCount: M }
            chunk_inserted = resp.get("insertedCount", 0)
            chunk_dupes    = resp.get("duplicateCount", 0)
            raw_records    = resp.get("inserted", resp if isinstance(resp, list) else [])

            total_inserted += chunk_inserted
            total_dupes    += chunk_dupes

            parsed = _parse(AssetFieldEvidenceRecord, raw_records)
            if isinstance(parsed, list):
                inserted_rows.extend(parsed)
            elif parsed is not None:
                inserted_rows.append(parsed)

        except Exception as exc:
            warnings.append(
                f"Chunk {chunk_start}–{chunk_start + len(chunk) - 1} failed: {exc}"
            )

    elapsed_ms = round((time.monotonic() * 1000) - start_ms, 2)

    return PersistedEvidenceResult(
        insertedCount    = total_inserted,
        duplicateCount   = total_dupes,
        totalProcessed   = total_processed,
        records          = inserted_rows,
        warnings         = warnings,
        processingTimeMs = elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Evidence count helpers
# ---------------------------------------------------------------------------

def count_evidence(filters: Optional[Dict[str, Any]] = None) -> int:
    """
    Return the total number of AssetFieldEvidence rows matching the given
    filters.  Omitting filters returns the global count.

    Parameters
    ----------
    filters : optional dict of filter keys (assetId, captureId, sourceType,
              fieldName).  All are passed as query params.

    Returns
    -------
    int — row count
    """
    params: Dict[str, Any] = filters or {}
    data   = _get(_url("api/assets/evidence/count"), params=params or None)
    return int(data.get("count", 0))


def asset_evidence_count(asset_id: str) -> int:
    """
    Return the number of evidence rows for a specific Asset.

    Parameters
    ----------
    asset_id : Asset primary key.

    Returns
    -------
    int — row count
    """
    data = _get(_url("api/assets", asset_id, "evidence/count"))
    return int(data.get("count", 0))


def capture_evidence_count(capture_id: str) -> int:
    """
    Return the number of evidence rows tied to a specific CaptureSession.

    Parameters
    ----------
    capture_id : CaptureSession.captureId.

    Returns
    -------
    int — row count
    """
    data = _get(
        _url("api/assets/evidence/count"),
        params={"captureId": capture_id},
    )
    return int(data.get("count", 0))


# ---------------------------------------------------------------------------
# AssetRelationship — CRUD + upsert
# ---------------------------------------------------------------------------

def create_relationship(
    data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetRelationshipRecord:
    """
    Create a directed relationship between two assets.
    data must include: sourceId, targetId, relationshipType.
    """
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRelationshipRecord, _post(_url("api/assets/relationships"), body))


def upsert_relationship(
    data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetRelationshipRecord:
    """Upsert by (sourceId, targetId, relationshipType) unique constraint."""
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRelationshipRecord, _post(_url("api/assets/relationships/upsert"), body))


def update_relationship(
    relationship_id: str, data: Dict[str, Any], tx_id: Optional[str] = None
) -> AssetRelationshipRecord:
    body = {**data}
    if tx_id:
        body["_txId"] = tx_id
    return _parse(AssetRelationshipRecord, _patch(_url("api/assets/relationships", relationship_id), body))


def delete_relationship(relationship_id: str, tx_id: Optional[str] = None) -> bool:
    result = _delete(_url("api/assets/relationships", relationship_id))
    return result.get("deleted", False)


def get_relationships(
    asset_id: str,
    direction: str = "both",
    relationship_type: Optional[str] = None,
) -> List[AssetRelationshipRecord]:
    """
    Retrieve relationships for an asset.

    Parameters
    ----------
    asset_id          : asset to query
    direction         : "from" | "to" | "both" (default: both)
    relationship_type : optional filter (e.g. "communicates_with")
    """
    params: Dict[str, Any] = {"direction": direction}
    if relationship_type:
        params["relationshipType"] = relationship_type
    data = _get(_url("api/assets", asset_id, "relationships"), params=params)
    return _parse(AssetRelationshipRecord, data)


def batch_upsert_relationships(
    items: List[Dict[str, Any]], tx_id: Optional[str] = None
) -> List[AssetRelationshipRecord]:
    """Upsert multiple relationships in one request."""
    body: Dict[str, Any] = {"items": items}
    if tx_id:
        body["_txId"] = tx_id
    data = _post(_url("api/assets/relationships/batch-upsert"), body)
    return _parse(AssetRelationshipRecord, data)
