"""
Enterprise Evidence Engine
===========================
Phase A.2.2.6.1 — Foundation models and builders ONLY.
Phase A.2.2.6.2 — Persistence orchestration added.

Standardises evidence objects before persistence.  Every evidence record
that will eventually be written to AssetFieldEvidence must pass through
this engine first so that provenance, confidence, and schema versioning are
applied consistently across all sources.

Design principles
-----------------
- Immutable output: builder functions return NEW objects; they never mutate.
- Deterministic: same inputs always produce the same EvidenceRecord.
- No side effects in builders: no DB, no HTTP, no file I/O, no logging.
- Persistence helpers (persist_*) are the ONLY functions allowed to call
  the repository.  All other functions remain pure.
- No AI, no heuristics.
- All engine/schema versions come from core/constants.py — never hardcoded.
- Reusable helpers are public functions, not private methods.

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  services.identity_signal_service  (SignalEvidence, IdentitySignal, SourceType)
  ← services.evidence_service        (this file)
  ← services.asset_service           (future: calls build_evidence())
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.constants import (
    EVIDENCE_ENGINE_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    SIGNAL_SOURCE_CONFIDENCE,
    SOURCE_TYPE_CONFIDENCE,
)
from services.identity_signal_service import IdentitySignal, SignalEvidence, SourceType


# ---------------------------------------------------------------------------
# Normalisation helpers  (public — used by builders and callers)
# ---------------------------------------------------------------------------

def normalize_field_name(name: str) -> str:
    """
    Normalise a field name to lowerCamelCase.

    Rules
    -----
    - Strip whitespace.
    - Replace spaces, hyphens, and underscores with camelCase boundaries.
    - First character is always lowercase.
    - Empty input returns "unknown".

    Examples
    --------
    "mac_address"  → "macAddress"
    "IP Address"   → "ipAddress"
    "DHCP-Hostname"→ "dhcpHostname"
    """
    s = str(name).strip()
    if not s:
        return "unknown"
    # Split on non-alphanumeric boundaries
    parts = re.split(r"[\s_\-]+", s)
    if not parts:
        return "unknown"
    result = parts[0].lower()
    for part in parts[1:]:
        result += part.capitalize()
    return result


def normalize_source(source: Any) -> str:
    """
    Normalise a source identifier to a lowercase string that matches a
    SOURCE_TYPE_CONFIDENCE key.

    - Accepts SourceType enum, SourceType.value string, or arbitrary string.
    - Falls back to "unknown" for empty / unrecognised values.

    Examples
    --------
    SourceType.DHCP  → "dhcp"
    "PCAP"           → "pcap"
    "bad_source"     → "unknown"  (not in SOURCE_TYPE_CONFIDENCE)
    """
    if isinstance(source, SourceType):
        s = source.value
    else:
        s = str(source).strip().lower() if source else ""

    if not s:
        return "unknown"

    # Accept if it maps to SOURCE_TYPE_CONFIDENCE or SIGNAL_SOURCE_CONFIDENCE
    if s in SOURCE_TYPE_CONFIDENCE or s in SIGNAL_SOURCE_CONFIDENCE:
        return s

    return "unknown"


def merge_metadata(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two metadata dicts without mutating either input.

    Rules
    -----
    - Returns a new dict.
    - Keys in `override` take precedence over `base`.
    - None values in `override` do NOT overwrite existing values in `base`.
    - Nested dicts are shallow-merged (override wins at the key level).

    Parameters
    ----------
    base     : existing metadata dict
    override : new metadata to merge in

    Returns
    -------
    dict — new merged dict
    """
    merged = dict(base or {})
    for k, v in (override or {}).items():
        if v is None and k in merged:
            continue  # preserve existing non-None value
        merged[k] = v
    return merged


# ---------------------------------------------------------------------------
# EvidenceSource — provenance reference
# ---------------------------------------------------------------------------

class EvidenceSource(BaseModel):
    """
    Describes where an observed value came from.

    Attributes
    ----------
    sourceType    : normalised source key (e.g. "pcap", "dhcp", "nmap")
    sourceId      : optional opaque reference (e.g. CaptureSession.id)
    confidence    : base confidence 0–100 from SIGNAL_SOURCE_CONFIDENCE
    """
    sourceType : str
    sourceId   : Optional[str] = None
    confidence : int           = Field(ge=0, le=100, default=0)

    class Config:
        frozen = True   # immutable


# ---------------------------------------------------------------------------
# EvidenceReference — packet / capture / session pointer
# ---------------------------------------------------------------------------

class EvidenceReference(BaseModel):
    """
    Points back to the exact observation that produced an evidence value.

    Attributes
    ----------
    packetNumber  : frame index within the capture file
    captureId     : CaptureSession.captureId (loose FK)
    sessionId     : CaptureSession.id (loose FK)
    observedAt    : UTC datetime of the observation
    """
    packetNumber : Optional[int]      = None
    captureId    : Optional[str]      = None
    sessionId    : Optional[str]      = None
    observedAt   : Optional[datetime] = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# EvidenceMetadata — extension bag
# ---------------------------------------------------------------------------

class EvidenceMetadata(BaseModel):
    """
    Arbitrary key-value extension bag attached to every EvidenceRecord.

    Predefined keys (all optional):
      protocol      : network protocol the value was observed in
      packetInfo    : _ws.col.info value from the packet
      rawValue      : unprocessed original value before normalisation
      tags          : analyst-applied labels
      extra         : catch-all dict for any future fields

    Adding a new key: add it here as an Optional field and update
    build_metadata().  No other changes required.
    """
    protocol    : Optional[str]       = None
    packetInfo  : Optional[str]       = None
    rawValue    : Optional[str]       = None
    tags        : List[str]           = Field(default_factory=list)
    extra       : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# EvidenceRecord — the canonical evidence object
# ---------------------------------------------------------------------------

class EvidenceRecord(BaseModel):
    """
    The canonical, immutable evidence object produced by this engine.

    Every record that will be written to AssetFieldEvidence must first be
    represented as an EvidenceRecord so that provenance, versioning, and
    confidence are applied consistently.

    Fields
    ------
    evidenceId    : stable UUID v5 derived from the evidence hash.
                    Deterministic — same inputs always produce the same ID.
                    Safe to use as a deduplication key in the database.
    evidenceHash  : SHA-256 hex digest over the content-identity tuple:
                    (fieldName, fieldValue, packetNumber, captureId,
                     sourceType, observedAt).
                    Two records with identical hash are the same observation.
                    Used by: deduplication, timeline, AI reference, attack graph.
    fieldName     : normalised camelCase field name (e.g. "macAddress")
    fieldValue    : the observed value (never empty — validated at build time)
    assetId       : target Asset primary key (optional until resolved)
    source        : EvidenceSource — where the value came from
    reference     : EvidenceReference — packet/capture back-pointer
    confidence    : final confidence score 0–100
    engineVersion : EVIDENCE_ENGINE_VERSION at time of creation
    schemaVersion : EVIDENCE_SCHEMA_VERSION at time of creation
    observedAt    : UTC datetime of the original observation
    createdAt     : UTC datetime this EvidenceRecord was constructed
    metadata      : EvidenceMetadata extension bag
    """
    evidenceId    : str                                          # UUID v5 — stable, deterministic
    evidenceHash  : str                                          # SHA-256 hex — content fingerprint
    fieldName     : str
    fieldValue    : str
    assetId       : Optional[str]        = None
    source        : EvidenceSource
    reference     : EvidenceReference    = Field(default_factory=EvidenceReference)
    confidence    : int                  = Field(ge=0, le=100)
    engineVersion : str                  = EVIDENCE_ENGINE_VERSION
    schemaVersion : str                  = EVIDENCE_SCHEMA_VERSION
    observedAt    : Optional[datetime]   = None
    createdAt     : datetime             = Field(
                        default_factory=lambda: datetime.now(timezone.utc)
                    )
    metadata      : EvidenceMetadata     = Field(default_factory=EvidenceMetadata)

    class Config:
        frozen = True   # immutable after construction


# ---------------------------------------------------------------------------
# EvidenceBundle — a collection of EvidenceRecords from one signal
# ---------------------------------------------------------------------------

class EvidenceBundle(BaseModel):
    """
    A group of EvidenceRecords that all originate from the same observation
    event (e.g. one packet, one Nmap scan, one DHCP lease).

    Attributes
    ----------
    assetId       : target Asset (set after resolution; may be None at build time)
    captureId     : capture session that produced this bundle
    packetNumber  : packet index (None for non-packet sources)
    records       : ordered list of EvidenceRecord objects
    engineVersion : EVIDENCE_ENGINE_VERSION
    schemaVersion : EVIDENCE_SCHEMA_VERSION
    createdAt     : UTC datetime this bundle was constructed
    metadata      : arbitrary extension dict
    """
    assetId       : Optional[str]        = None
    captureId     : Optional[str]        = None
    packetNumber  : Optional[int]        = None
    records       : List[EvidenceRecord] = Field(default_factory=list)
    engineVersion : str                  = EVIDENCE_ENGINE_VERSION
    schemaVersion : str                  = EVIDENCE_SCHEMA_VERSION
    createdAt     : datetime             = Field(
                        default_factory=lambda: datetime.now(timezone.utc)
                    )
    metadata      : Dict[str, Any]       = Field(default_factory=dict)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Public helper: compute_evidence_hash()
# ---------------------------------------------------------------------------

# Namespace UUID for evidence ID generation (UUID v5).
# Fixed — never change this value or existing IDs will be invalidated.
_EVIDENCE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL

def compute_evidence_hash(
    field_name    : str,
    field_value   : str,
    source_type   : str,
    packet_number : Optional[int]      = None,
    capture_id    : Optional[str]      = None,
    observed_at   : Optional[datetime] = None,
) -> str:
    """
    Compute a deterministic SHA-256 hash over the content-identity tuple of
    one evidence observation.

    Hash inputs (all coerced to str, joined with "|"):
      fieldName | fieldValue | packetNumber | captureId | sourceType | observedAt

    Two EvidenceRecords with the same hash represent the same observation and
    are safe to deduplicate.  Used by:
      - Deduplication before DB writes
      - Timeline identity (same event → same hash)
      - AI/LLM evidence references
      - Attack graph edge deduplication

    Parameters
    ----------
    field_name    : normalised camelCase field name
    field_value   : observed value
    source_type   : normalised source key (e.g. "pcap", "dhcp")
    packet_number : frame index (None → "")
    capture_id    : CaptureSession.captureId (None → "")
    observed_at   : UTC datetime (None → ""); ISO-formatted before hashing

    Returns
    -------
    str — 64-character lowercase hex SHA-256 digest
    """
    parts = [
        str(field_name).strip().lower(),
        str(field_value).strip(),
        str(packet_number) if packet_number is not None else "",
        str(capture_id).strip() if capture_id else "",
        str(source_type).strip().lower(),
        observed_at.isoformat() if observed_at else "",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _evidence_id_from_hash(evidence_hash: str) -> str:
    """
    Derive a stable UUID v5 from an evidence hash.

    Using UUID v5 (SHA-1 over namespace+name) gives a UUID-format identifier
    that is deterministic, globally unique within our namespace, and
    compatible with Prisma String @id fields.

    Parameters
    ----------
    evidence_hash : 64-char hex SHA-256 digest from compute_evidence_hash()

    Returns
    -------
    str — UUID v5 in canonical hyphenated form (e.g. "550e8400-...")
    """
    return str(uuid.uuid5(_EVIDENCE_NS, evidence_hash))


# ---------------------------------------------------------------------------
# Builder: build_source_reference()
# ---------------------------------------------------------------------------

def build_source_reference(
    source_type : Any,
    source_id   : Optional[str] = None,
    confidence  : Optional[int] = None,
) -> EvidenceSource:
    """
    Build an EvidenceSource from a source type identifier.

    Parameters
    ----------
    source_type : SourceType enum, its .value string, or any string key
                  that exists in SOURCE_TYPE_CONFIDENCE.
    source_id   : optional opaque back-reference (e.g. CaptureSession.id).
    confidence  : explicit confidence override (0–100).
                  If None, the base confidence from SOURCE_TYPE_CONFIDENCE
                  is used.  Falls back to 0 for unknown sources.

    Returns
    -------
    EvidenceSource (frozen / immutable)
    """
    norm = normalize_source(source_type)
    base = SOURCE_TYPE_CONFIDENCE.get(norm, SIGNAL_SOURCE_CONFIDENCE.get(norm, 0))
    final_confidence = max(0, min(100, confidence if confidence is not None else base))
    return EvidenceSource(
        sourceType = norm,
        sourceId   = source_id or None,
        confidence = final_confidence,
    )


# ---------------------------------------------------------------------------
# Builder: build_packet_reference()
# ---------------------------------------------------------------------------

def build_packet_reference(
    packet_number : Optional[int]      = None,
    capture_id    : Optional[str]      = None,
    session_id    : Optional[str]      = None,
    observed_at   : Optional[datetime] = None,
) -> EvidenceReference:
    """
    Build an EvidenceReference that points back to a specific packet.

    Parameters
    ----------
    packet_number : frame.number from tshark output
    capture_id    : CaptureSession.captureId
    session_id    : CaptureSession.id (Prisma primary key)
    observed_at   : UTC datetime of the packet (frame.time)

    Returns
    -------
    EvidenceReference (frozen / immutable)
    """
    return EvidenceReference(
        packetNumber = packet_number,
        captureId    = capture_id,
        sessionId    = session_id,
        observedAt   = observed_at,
    )


# ---------------------------------------------------------------------------
# Builder: build_capture_reference()
# ---------------------------------------------------------------------------

def build_capture_reference(
    capture_id  : Optional[str]      = None,
    session_id  : Optional[str]      = None,
    observed_at : Optional[datetime] = None,
) -> EvidenceReference:
    """
    Build an EvidenceReference for a capture-level observation (no specific
    packet number — e.g. a DHCP lease record or Nmap scan result).

    Returns
    -------
    EvidenceReference (frozen / immutable)
    """
    return EvidenceReference(
        packetNumber = None,
        captureId    = capture_id,
        sessionId    = session_id,
        observedAt   = observed_at,
    )


# ---------------------------------------------------------------------------
# Builder: build_metadata()
# ---------------------------------------------------------------------------

def build_metadata(
    protocol    : Optional[str]  = None,
    packet_info : Optional[str]  = None,
    raw_value   : Optional[str]  = None,
    tags        : Optional[List[str]] = None,
    extra       : Optional[Dict[str, Any]] = None,
) -> EvidenceMetadata:
    """
    Build an EvidenceMetadata object.

    Parameters
    ----------
    protocol    : network protocol (e.g. "DNS", "DHCP", "HTTP")
    packet_info : _ws.col.info value from the packet
    raw_value   : unprocessed value before normalisation
    tags        : analyst or system labels
    extra       : arbitrary key-value pairs for future extensibility

    Returns
    -------
    EvidenceMetadata (frozen / immutable)
    """
    return EvidenceMetadata(
        protocol   = protocol,
        packetInfo = packet_info,
        rawValue   = raw_value,
        tags       = list(tags) if tags else [],
        extra      = dict(extra) if extra else {},
    )


# ---------------------------------------------------------------------------
# Builder: build_evidence()  — core builder
# ---------------------------------------------------------------------------

def build_evidence(
    field_name    : str,
    field_value   : str,
    source_type   : Any,
    *,
    asset_id      : Optional[str]           = None,
    source_id     : Optional[str]           = None,
    confidence    : Optional[int]           = None,
    packet_number : Optional[int]           = None,
    capture_id    : Optional[str]           = None,
    session_id    : Optional[str]           = None,
    observed_at   : Optional[datetime]      = None,
    metadata      : Optional[EvidenceMetadata] = None,
) -> Optional[EvidenceRecord]:
    """
    Build ONE EvidenceRecord from raw field data.

    This is the core builder.  All other builders delegate to this function.

    Parameters
    ----------
    field_name    : logical field name; will be normalised to camelCase.
    field_value   : the observed value; must be non-empty (returns None if empty).
    source_type   : SourceType enum or string key.
    asset_id      : optional Asset primary key (populated after resolution).
    source_id     : optional back-reference to source record (loose FK).
    confidence    : explicit 0–100 override; defaults to source base confidence.
    packet_number : frame index within the capture file.
    capture_id    : CaptureSession.captureId.
    session_id    : CaptureSession.id.
    observed_at   : UTC datetime of the original observation.
    metadata      : EvidenceMetadata; defaults to empty if None.

    Returns
    -------
    EvidenceRecord (frozen / immutable), or None if field_value is empty.

    Notes
    -----
    - Never modifies any input.
    - Never writes to any external system.
    - Deterministic: same inputs always produce structurally equal output
      (modulo createdAt which is always set to utcnow()).
    """
    # Guard — never build evidence for empty values
    value = str(field_value).strip() if field_value else ""
    if not value:
        return None

    norm_field  = normalize_field_name(field_name)
    source      = build_source_reference(source_type, source_id, confidence)
    reference   = build_packet_reference(packet_number, capture_id, session_id, observed_at)
    ev_metadata = metadata if metadata is not None else EvidenceMetadata()

    # Deterministic content fingerprint — same observation → same hash/ID.
    ev_hash = compute_evidence_hash(
        field_name    = norm_field,
        field_value   = value,
        source_type   = source.sourceType,
        packet_number = packet_number,
        capture_id    = capture_id,
        observed_at   = observed_at,
    )
    ev_id = _evidence_id_from_hash(ev_hash)

    return EvidenceRecord(
        evidenceId    = ev_id,
        evidenceHash  = ev_hash,
        fieldName     = norm_field,
        fieldValue    = value,
        assetId       = asset_id,
        source        = source,
        reference     = reference,
        confidence    = source.confidence,
        engineVersion = EVIDENCE_ENGINE_VERSION,
        schemaVersion = EVIDENCE_SCHEMA_VERSION,
        observedAt    = observed_at,
        metadata      = ev_metadata,
    )


# ---------------------------------------------------------------------------
# Builder: build_field_evidence()
# ---------------------------------------------------------------------------

def build_field_evidence(
    field_name  : str,
    field_value : str,
    source_type : Any,
    asset_id    : Optional[str]      = None,
    capture_id  : Optional[str]      = None,
    observed_at : Optional[datetime] = None,
    confidence  : Optional[int]      = None,
    extra       : Optional[Dict[str, Any]] = None,
) -> Optional[EvidenceRecord]:
    """
    Convenience wrapper around build_evidence() for simple field observations.

    Covers the most common case: a single field=value pair observed in a
    capture, with an optional asset binding.

    Parameters
    ----------
    field_name  : e.g. "hostname", "macAddress", "ipAddress"
    field_value : observed value
    source_type : SourceType enum or string key
    asset_id    : optional target Asset.id
    capture_id  : CaptureSession.captureId
    observed_at : UTC datetime
    confidence  : explicit override; defaults to source base confidence
    extra       : arbitrary dict appended to EvidenceMetadata.extra

    Returns
    -------
    EvidenceRecord or None if field_value is empty.
    """
    meta = build_metadata(extra=extra) if extra else None
    return build_evidence(
        field_name  = field_name,
        field_value = field_value,
        source_type = source_type,
        asset_id    = asset_id,
        capture_id  = capture_id,
        observed_at = observed_at,
        confidence  = confidence,
        metadata    = meta,
    )


# ---------------------------------------------------------------------------
# Builder: build_identity_evidence()
# ---------------------------------------------------------------------------

def build_identity_evidence(
    signal      : IdentitySignal,
    asset_id    : Optional[str] = None,
    session_id  : Optional[str] = None,
) -> EvidenceBundle:
    """
    Build an EvidenceBundle from every non-empty SignalEvidence entry in an
    IdentitySignal.

    One EvidenceRecord is created per SignalEvidence item in
    signal.confidenceHints.  Empty values are silently skipped.

    Parameters
    ----------
    signal      : IdentitySignal from identity_signal_service
    asset_id    : optional Asset.id (populated after resolution)
    session_id  : CaptureSession.id for back-reference

    Returns
    -------
    EvidenceBundle — frozen, immutable, never empty (records list may be []).
    """
    records: List[EvidenceRecord] = []

    for ev in signal.confidenceHints:
        record = build_evidence(
            field_name    = ev.fieldName,
            field_value   = ev.fieldValue,
            source_type   = ev.source,
            asset_id      = asset_id,
            confidence    = ev.confidence,
            packet_number = ev.packetNumber or signal.packetNumber,
            capture_id    = ev.captureId or signal.captureId,
            session_id    = session_id,
            observed_at   = ev.observedAt or signal.observedAt,
        )
        if record:
            records.append(record)

    return EvidenceBundle(
        assetId       = asset_id,
        captureId     = signal.captureId,
        packetNumber  = signal.packetNumber,
        records       = records,
        engineVersion = EVIDENCE_ENGINE_VERSION,
        schemaVersion = EVIDENCE_SCHEMA_VERSION,
        metadata      = {
            "signalSource"  : (
                signal.sourceType
                if isinstance(signal.sourceType, str)
                else signal.sourceType.value
            ),
            "totalRecords"  : len(records),
        },
    )


# ---------------------------------------------------------------------------
# Builder: build_packet_evidence_bundle()
# ---------------------------------------------------------------------------

def build_packet_evidence_bundle(
    signal_evidence : List[SignalEvidence],
    packet_number   : Optional[int]      = None,
    capture_id      : Optional[str]      = None,
    session_id      : Optional[str]      = None,
    asset_id        : Optional[str]      = None,
) -> EvidenceBundle:
    """
    Build an EvidenceBundle from a flat list of SignalEvidence items.

    Used when the caller already has a list of SignalEvidence objects but
    does not have a full IdentitySignal (e.g. intermediate processing).

    Parameters
    ----------
    signal_evidence : list of SignalEvidence items
    packet_number   : frame index
    capture_id      : CaptureSession.captureId
    session_id      : CaptureSession.id
    asset_id        : optional Asset.id

    Returns
    -------
    EvidenceBundle (frozen / immutable)
    """
    records: List[EvidenceRecord] = []

    for ev in signal_evidence:
        record = build_evidence(
            field_name    = ev.fieldName,
            field_value   = ev.fieldValue,
            source_type   = ev.source,
            asset_id      = asset_id,
            confidence    = ev.confidence,
            packet_number = ev.packetNumber or packet_number,
            capture_id    = ev.captureId or capture_id,
            session_id    = session_id,
            observed_at   = ev.observedAt,
        )
        if record:
            records.append(record)

    return EvidenceBundle(
        assetId       = asset_id,
        captureId     = capture_id,
        packetNumber  = packet_number,
        records       = records,
        engineVersion = EVIDENCE_ENGINE_VERSION,
        schemaVersion = EVIDENCE_SCHEMA_VERSION,
        metadata      = {"totalRecords": len(records)},
    )


# ---------------------------------------------------------------------------
# Persistence orchestration — Phase A.2.2.6.2
# ---------------------------------------------------------------------------
# These are the ONLY functions in this module that call the repository.
# All builder functions above remain pure (no side effects).
# Import is deferred inside each function to avoid circular imports at
# module load time (evidence_service ← enterprise_asset_repository is safe,
# but keeping the import local makes the dependency explicit and testable).
# ---------------------------------------------------------------------------

def persist_evidence_bundle(
    bundle   : EvidenceBundle,
    asset_id : Optional[str] = None,
    tx_id    : Optional[str] = None,
) -> "PersistedEvidenceResult":  # type: ignore[name-defined]
    """
    Persist all EvidenceRecords in an EvidenceBundle to the database.

    Orchestration
    -------------
    1. Resolve the target asset_id: prefer the explicit parameter, fall back
       to bundle.assetId.  Records without an assetId are skipped with a
       warning (they cannot be written to the append-only evidence table
       without a foreign key).
    2. Delegate to repository.batch_insert_evidence() which handles:
       - Hash-based deduplication (same evidenceHash → skip).
       - Chunked batch inserts (EVIDENCE_BATCH_CHUNK_SIZE rows per request).
       - PersistedEvidenceResult accounting.

    Parameters
    ----------
    bundle   : EvidenceBundle built by any of the build_*_bundle() helpers.
    asset_id : explicit Asset.id override.  Falls back to bundle.assetId.
    tx_id    : optional server-side transaction token.

    Returns
    -------
    PersistedEvidenceResult
    """
    # Lazy import — avoids circular dependency at module load time.
    from repositories.enterprise_asset_repository import (
        batch_insert_evidence,
        PersistedEvidenceResult,
    )

    resolved_asset_id = asset_id or bundle.assetId

    if not resolved_asset_id:
        return PersistedEvidenceResult(
            insertedCount    = 0,
            duplicateCount   = 0,
            totalProcessed   = len(bundle.records),
            records          = [],
            warnings         = [
                "persist_evidence_bundle: no assetId on bundle — all records skipped."
            ],
            processingTimeMs = 0.0,
        )

    if not bundle.records:
        return PersistedEvidenceResult(
            insertedCount    = 0,
            duplicateCount   = 0,
            totalProcessed   = 0,
            records          = [],
            warnings         = [],
            processingTimeMs = 0.0,
        )

    return batch_insert_evidence(
        asset_id = resolved_asset_id,
        records  = list(bundle.records),
        tx_id    = tx_id,
    )


def persist_identity_evidence(
    signal     : IdentitySignal,
    asset_id   : Optional[str] = None,
    session_id : Optional[str] = None,
    tx_id      : Optional[str] = None,
) -> "PersistedEvidenceResult":  # type: ignore[name-defined]
    """
    Build an EvidenceBundle from an IdentitySignal and persist it.

    Convenience wrapper: build_identity_evidence() → persist_evidence_bundle().

    Parameters
    ----------
    signal     : IdentitySignal from identity_signal_service.
    asset_id   : Asset.id (resolved by the identity engine before this call).
    session_id : CaptureSession.id for back-reference.
    tx_id      : optional transaction token.

    Returns
    -------
    PersistedEvidenceResult
    """
    bundle = build_identity_evidence(
        signal     = signal,
        asset_id   = asset_id,
        session_id = session_id,
    )
    return persist_evidence_bundle(bundle=bundle, asset_id=asset_id, tx_id=tx_id)


def persist_field_evidence(
    field_name    : str,
    field_value   : str,
    source_type   : Any,
    asset_id      : str,
    *,
    source_id     : Optional[str]      = None,
    confidence    : Optional[int]      = None,
    packet_number : Optional[int]      = None,
    capture_id    : Optional[str]      = None,
    session_id    : Optional[str]      = None,
    observed_at   : Optional[datetime] = None,
    metadata      : Optional[EvidenceMetadata] = None,
    tx_id         : Optional[str]      = None,
) -> "PersistedEvidenceResult":  # type: ignore[name-defined]
    """
    Build a single EvidenceRecord and persist it.

    Convenience wrapper: build_evidence() → persist_evidence_bundle().
    Skips persistence and returns an empty result if the value is empty.

    Parameters
    ----------
    field_name    : logical field name (normalised to camelCase internally).
    field_value   : observed value — empty string causes early return.
    source_type   : SourceType enum or string key.
    asset_id      : Asset.id — required; evidence cannot be written without it.
    source_id     : optional back-reference to source record.
    confidence    : explicit 0–100 override.
    packet_number : frame index within capture file.
    capture_id    : CaptureSession.captureId.
    session_id    : CaptureSession.id.
    observed_at   : UTC datetime of the original observation.
    metadata      : EvidenceMetadata extension bag.
    tx_id         : optional transaction token.

    Returns
    -------
    PersistedEvidenceResult
    """
    from repositories.enterprise_asset_repository import (
        batch_insert_evidence,
        PersistedEvidenceResult,
    )

    record = build_evidence(
        field_name    = field_name,
        field_value   = field_value,
        source_type   = source_type,
        asset_id      = asset_id,
        source_id     = source_id,
        confidence    = confidence,
        packet_number = packet_number,
        capture_id    = capture_id,
        session_id    = session_id,
        observed_at   = observed_at,
        metadata      = metadata,
    )

    if record is None:
        return PersistedEvidenceResult(
            insertedCount    = 0,
            duplicateCount   = 0,
            totalProcessed   = 0,
            records          = [],
            warnings         = [
                f"persist_field_evidence: empty value for field '{field_name}' — skipped."
            ],
            processingTimeMs = 0.0,
        )

    return batch_insert_evidence(
        asset_id = asset_id,
        records  = [record],
        tx_id    = tx_id,
    )
