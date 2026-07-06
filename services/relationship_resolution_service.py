"""
Relationship Resolution Engine
================================
Phase A.3.2 — Pure decision engine for relationship identity resolution.

Responsibilities
----------------
- Determine whether a new RelationshipSignal belongs to an existing
  Relationship, creates a new one, updates an existing one, marks one
  inactive, or terminates one.
- Score candidate Relationships against an incoming signal.
- Produce frozen, deterministic resolution decisions.

Design constraints
------------------
- PURE: no HTTP, no Prisma, no repositories, no AI calls.
- Immutable output: all models use frozen=True Pydantic config.
- Deterministic: same inputs always produce the same output.
- No circular imports.

Fingerprint
-----------
relationshipFingerprint = SHA-256[:32] of
    sourceAssetId | targetAssetId | relationshipType | protocol | port

Same natural key always produces the same fingerprint.
Used as a fast dedup / lookup key independent of relationshipId.

Scoring (0–100, normalised)
---------------------------
Field weights (primary — dominate score):
    sourceAssetId     : 30
    targetAssetId     : 30
    relationshipType  : 15
    protocol          : 12
    port              : 8
Secondary signals (tie-breakers only):
    direction         : 3
    captureId         : 2
MAX_POSSIBLE_SCORE = 100

Decision thresholds (score >= threshold):
    MATCH             : 95
    LIKELY_MATCH      : 75
    POSSIBLE_MATCH    : 50
    MANUAL_REVIEW     : 25
    CREATE_NEW        :  0

Special rules (override score):
    Exact fingerprint identity        → MATCH
    Same pair, different packet       → UPDATE_EXISTING
    Inactivity > INACTIVITY_THRESHOLD → INACTIVATE
    Explicit termination signal       → TERMINATE
    Multiple candidates near tie      → MANUAL_REVIEW

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  services.relationship_service   (Relationship, RelationshipSignal,
                                   RelationshipState, RelationshipType,
                                   Direction, compute_relationship_key)
  services.relationship_history_service   (RelationshipHistoryBundle)
  ← services.relationship_resolution_service   (this file)
"""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.constants import RELATIONSHIP_ENGINE_VERSION
from services.relationship_service import (
    Direction,
    Relationship,
    RelationshipSignal,
    RelationshipState,
    RelationshipType,
    compute_relationship_key,
)
from services.relationship_history_service import RelationshipHistoryBundle


# ---------------------------------------------------------------------------
# Engine version — bump when algorithm changes.
# ---------------------------------------------------------------------------
RELATIONSHIP_RESOLUTION_ENGINE_VERSION: str = "relationship-resolution-v1"


# ---------------------------------------------------------------------------
# Inactivity threshold (seconds) — relationships older than this without
# new traffic are candidates for INACTIVATE.
# ---------------------------------------------------------------------------
INACTIVITY_THRESHOLD_SECONDS: int = 300   # 5 minutes

# Termination states observed in metadata keys written by callers.
_TERMINATION_REASONS = frozenset({"tcp_fin", "tcp_rst", "explicit_close", "terminated"})


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

# Primary field weights — dominate the score.
_WEIGHT_SOURCE_ASSET_ID     : int = 30
_WEIGHT_TARGET_ASSET_ID     : int = 30
_WEIGHT_RELATIONSHIP_TYPE   : int = 15
_WEIGHT_PROTOCOL            : int = 12
_WEIGHT_PORT                : int = 8

# Secondary field weights — tie-breakers only.
_WEIGHT_DIRECTION           : int = 3
_WEIGHT_CAPTURE_ID          : int = 2

# Sum of all weights — used to normalise raw score to 0–100.
_MAX_POSSIBLE_SCORE: int = (
    _WEIGHT_SOURCE_ASSET_ID
    + _WEIGHT_TARGET_ASSET_ID
    + _WEIGHT_RELATIONSHIP_TYPE
    + _WEIGHT_PROTOCOL
    + _WEIGHT_PORT
    + _WEIGHT_DIRECTION
    + _WEIGHT_CAPTURE_ID
)  # = 100 — already normalised; no division needed.


# ---------------------------------------------------------------------------
# Decision thresholds (inclusive lower bounds, normalised 0–100 score).
# ---------------------------------------------------------------------------
_DECISION_THRESHOLDS: Dict[str, int] = {
    "MATCH"          : 95,
    "LIKELY_MATCH"   : 75,
    "POSSIBLE_MATCH" : 50,
    "MANUAL_REVIEW"  : 25,
    "CREATE_NEW"     :  0,
}

# Ambiguity band — if top-2 candidates are within this margin, → MANUAL_REVIEW.
_AMBIGUITY_BAND: int = 5


# ---------------------------------------------------------------------------
# DecisionLevel
# ---------------------------------------------------------------------------

class DecisionLevel(str, Enum):
    """
    Resolution outcome for a single RelationshipSignal.

    MATCH            : Signal maps exactly to an existing Relationship
                       (fingerprint identity confirmed).
    LIKELY_MATCH     : High-confidence match on primary fields; minor
                       discrepancy in secondary fields.
    POSSIBLE_MATCH   : Partial primary-field match; requires context.
    CREATE_NEW       : No plausible existing Relationship found; create one.
    UPDATE_EXISTING  : Signal belongs to an existing Relationship but carries
                       new packet/byte data (same pair, new observation).
    INACTIVATE       : Existing Relationship has not received traffic for
                       longer than INACTIVITY_THRESHOLD_SECONDS.
    TERMINATE        : Explicit termination signal observed (TCP FIN/RST,
                       explicit_close, or caller-set terminated flag).
    MANUAL_REVIEW    : Two or more candidates are too close to distinguish
                       automatically; hand off to analyst.
    """
    MATCH            = "MATCH"
    LIKELY_MATCH     = "LIKELY_MATCH"
    POSSIBLE_MATCH   = "POSSIBLE_MATCH"
    CREATE_NEW       = "CREATE_NEW"
    UPDATE_EXISTING  = "UPDATE_EXISTING"
    INACTIVATE       = "INACTIVATE"
    TERMINATE        = "TERMINATE"
    MANUAL_REVIEW    = "MANUAL_REVIEW"


# ---------------------------------------------------------------------------
# RelationshipCandidate
# ---------------------------------------------------------------------------

class ResolutionEvidenceItem(BaseModel):
    """
    Per-field evidence entry that explains one field's contribution to
    a candidate's resolution score.

    Future AI can consume this list directly to build a causal explanation
    graph instead of a flat summary string.

    Fields
    ------
    field         : Name of the evaluated field (e.g. "sourceAssetId", "protocol").
    matched       : True if signal value matched the existing relationship's value.
    weight        : The scoring weight this field carries (0–30).
    reason        : Deterministic one-line explanation of the match or conflict
                    (e.g. "Exact asset match", "Protocol changed DNS→HTTPS").
    signalValue   : The value observed in the incoming signal for this field.
                    Stored so future AI never needs a DB round-trip to explain
                    what changed.
    existingValue : The value on the existing Relationship for this field.
                    Paired with signalValue to give the AI a complete before/after
                    picture: Old DNS → New HTTPS, Confidence Impact -12.
    """
    field         : str
    matched       : bool
    weight        : int            = Field(ge=0, le=100)
    reason        : str            = ""
    signalValue   : Optional[Any]  = None
    existingValue : Optional[Any]  = None

    class Config:
        frozen = True


class RelationshipCandidate(BaseModel):
    """
    A scored, ranked candidate Relationship for a given signal.

    Fields
    ------
    relationshipId     : Relationship.relationshipId being evaluated.
    relationshipKey    : Relationship.relationshipKey (SHA-256[:32]).
    score              : normalised 0–100 match score against the signal.
    matchedFields      : field names that contributed positively to score.
    conflictingFields  : field names where signal value differs from existing.
    confidence         : Relationship.confidence at evaluation time.
    reason             : human-readable explanation of the score.
    resolutionEvidence : per-field breakdown — field, matched, weight, reason.
                         Future AI uses this list to build a causal explanation
                         graph without re-parsing the summary string.
    """
    relationshipId     : str
    relationshipKey    : str
    score              : int                       = Field(ge=0, le=100)
    matchedFields      : List[str]                 = Field(default_factory=list)
    conflictingFields  : List[str]                 = Field(default_factory=list)
    confidence         : int                       = Field(ge=0, le=100, default=0)
    reason             : str                       = ""
    resolutionEvidence : List[ResolutionEvidenceItem] = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipResolutionDecision
# ---------------------------------------------------------------------------

class RelationshipResolutionDecision(BaseModel):
    """
    The final resolution decision for one RelationshipSignal.

    Fields
    ------
    decision              : DecisionLevel outcome.
    matchedRelationshipId : relationshipId of the winning candidate, if any.
    matchedRelationshipKey: relationshipKey of the winning candidate, if any.
    score                 : score of the winning candidate (0 if CREATE_NEW).
    reason                : deterministic one-line explanation.
    warnings              : non-fatal observations (e.g. ambiguity detected).
    """
    decision               : DecisionLevel
    matchedRelationshipId  : Optional[str]   = None
    matchedRelationshipKey : Optional[str]   = None
    score                  : int             = Field(ge=0, le=100, default=0)
    reason                 : str             = ""
    warnings               : List[str]       = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipResolutionResult
# ---------------------------------------------------------------------------

class RelationshipResolutionResult(BaseModel):
    """
    Complete output of one resolution pass for a single RelationshipSignal.

    Fields
    ------
    decision         : The RelationshipResolutionDecision (final outcome).
    candidateScores  : All evaluated RelationshipCandidates, sorted by score
                       descending. Empty when decision is CREATE_NEW.
    processingTimeMs : Wall-clock time (ms) taken to compute this result.
    engineVersion    : RELATIONSHIP_RESOLUTION_ENGINE_VERSION at build time.
    """
    decision         : RelationshipResolutionDecision
    candidateScores  : List[RelationshipCandidate]    = Field(default_factory=list)
    processingTimeMs : float                          = 0.0
    engineVersion    : str                            = RELATIONSHIP_RESOLUTION_ENGINE_VERSION

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipFingerprint helper (Mandatory Recommendation)
# ---------------------------------------------------------------------------

def compute_relationship_fingerprint(
    source_asset_id   : str,
    target_asset_id   : str,
    relationship_type : "RelationshipType | str",
    protocol          : str,
    port              : Optional[int],
) -> str:
    """
    Compute a stable SHA-256[:32] fingerprint for a Relationship's
    natural key (sourceAssetId, targetAssetId, relationshipType,
    protocol, port).

    The fingerprint is independent of projectId — it encodes WHAT the
    relationship is, not WHERE it lives.  Use it as a fast dedup /
    cross-project lookup key.

    Parameters
    ----------
    source_asset_id   : originating Asset.id.
    target_asset_id   : receiving Asset.id.
    relationship_type : RelationshipType enum or its .value string.
    protocol          : normalised uppercase protocol (e.g. "DNS").
    port              : destination port; None for ICMP/ARP/DHCP.

    Returns
    -------
    str — 32-character lowercase hex string (first 128 bits of SHA-256).
    """
    rtype_str = (
        relationship_type.value
        if hasattr(relationship_type, "value")
        else str(relationship_type)
    )
    port_str = str(port) if port is not None else ""
    raw = "|".join([
        source_asset_id.strip(),
        target_asset_id.strip(),
        rtype_str.strip().upper(),
        protocol.strip().upper(),
        port_str,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _fingerprint_from_relationship(rel: Relationship) -> str:
    """Derive fingerprint directly from an existing Relationship object."""
    return compute_relationship_fingerprint(
        rel.sourceAssetId,
        rel.targetAssetId,
        rel.relationshipType,
        rel.protocol,
        rel.port,
    )


def _fingerprint_from_signal(
    signal        : RelationshipSignal,
    inferred_type : RelationshipType,
) -> str:
    """Derive fingerprint from a RelationshipSignal + its inferred type."""
    return compute_relationship_fingerprint(
        signal.sourceAssetId,
        signal.targetAssetId,
        inferred_type,
        signal.protocol,
        signal.port,
    )


# ---------------------------------------------------------------------------
# Internal: _infer_type_from_signal()
# ---------------------------------------------------------------------------

def _infer_type_from_signal(signal: RelationshipSignal) -> RelationshipType:
    """
    Map the signal's normalised protocol to a RelationshipType.
    Mirrors the private _infer_relationship_type() in relationship_service
    without importing it (avoids tight coupling to internals).
    """
    _MAP: Dict[str, RelationshipType] = {
        "DNS"     : RelationshipType.DNS_QUERY,
        "MDNS"    : RelationshipType.DNS_QUERY,
        "LLMNR"   : RelationshipType.DNS_QUERY,
        "HTTP"    : RelationshipType.HTTP_REQUEST,
        "HTTPS"   : RelationshipType.HTTPS_REQUEST,
        "TLS"     : RelationshipType.TLS_SESSION,
        "SSL"     : RelationshipType.TLS_SESSION,
        "ARP"     : RelationshipType.ARP,
        "DHCP"    : RelationshipType.DHCP,
        "BOOTP"   : RelationshipType.DHCP,
        "ICMP"    : RelationshipType.ICMP,
        "ICMPV6"  : RelationshipType.ICMP,
        "SMB"     : RelationshipType.SMB,
        "SMB2"    : RelationshipType.SMB,
        "RDP"     : RelationshipType.RDP,
        "SSH"     : RelationshipType.SSH,
        "FTP"     : RelationshipType.FTP,
        "FTP-DATA": RelationshipType.FTP,
    }
    norm = signal.protocol.upper().strip() if signal.protocol else "UNKNOWN"
    return _MAP.get(norm, RelationshipType.COMMUNICATED_WITH)


# ---------------------------------------------------------------------------
# Utility: normalize_relationship_key()
# ---------------------------------------------------------------------------

def normalize_relationship_key(
    source_asset_id   : str,
    target_asset_id   : str,
    relationship_type : "RelationshipType | str",
    protocol          : str,
    port              : Optional[int],
    project_id        : str = "",
) -> str:
    """
    Return the normalised relationship key (SHA-256[:32]) for the given
    natural key components.  Delegates to compute_relationship_key() in
    relationship_service so both engines always agree on the key format.

    Parameters
    ----------
    source_asset_id   : originating Asset.id.
    target_asset_id   : receiving Asset.id.
    relationship_type : RelationshipType enum or its .value string.
    protocol          : protocol string; normalised to uppercase internally.
    port              : destination port; None for ICMP/ARP/DHCP.
    project_id        : project scope (empty string = cross-project key).

    Returns
    -------
    str — 32-character lowercase hex string.
    """
    return compute_relationship_key(
        project_id,
        source_asset_id,
        target_asset_id,
        relationship_type,
        protocol,
        port,
    )


# ---------------------------------------------------------------------------
# Core: calculate_match_score()
# ---------------------------------------------------------------------------

def calculate_match_score(
    existing : Relationship,
    signal   : RelationshipSignal,
) -> RelationshipCandidate:
    """
    Compute a 0–100 match score between an existing Relationship and an
    incoming RelationshipSignal.

    Scoring logic
    -------------
    Primary fields (dominate score):
        sourceAssetId    +30 if exact match
        targetAssetId    +30 if exact match
        relationshipType +15 if signal's inferred type matches
        protocol         +12 if exact match (case-normalised)
        port             + 8 if both present and equal, or both None

    Secondary fields (tie-breakers):
        direction        + 3 if not UNKNOWN and equal
        captureId        + 2 if both present and equal

    Total possible = 100 (already normalised; no division needed).

    Parameters
    ----------
    existing : Relationship being evaluated as a candidate.
    signal   : incoming RelationshipSignal to match against.

    Returns
    -------
    RelationshipCandidate (frozen / immutable)
    """
    matched    : List[str]                  = []
    conflicting: List[str]                  = []
    evidence   : List[ResolutionEvidenceItem] = []
    raw_score  : int                        = 0

    sig_proto = signal.protocol.upper().strip() if signal.protocol else "UNKNOWN"
    sig_type  = _infer_type_from_signal(signal)

    # --- sourceAssetId ---
    if signal.sourceAssetId == existing.sourceAssetId:
        raw_score += _WEIGHT_SOURCE_ASSET_ID
        matched.append("sourceAssetId")
        evidence.append(ResolutionEvidenceItem(
            field="sourceAssetId", matched=True,
            weight=_WEIGHT_SOURCE_ASSET_ID,
            reason="Exact asset match",
            signalValue=signal.sourceAssetId,
            existingValue=existing.sourceAssetId,
        ))
    else:
        conflicting.append("sourceAssetId")
        evidence.append(ResolutionEvidenceItem(
            field="sourceAssetId", matched=False,
            weight=_WEIGHT_SOURCE_ASSET_ID,
            reason=(
                f"Source asset mismatch: "
                f"{signal.sourceAssetId} ≠ {existing.sourceAssetId}"
            ),
            signalValue=signal.sourceAssetId,
            existingValue=existing.sourceAssetId,
        ))

    # --- targetAssetId ---
    if signal.targetAssetId == existing.targetAssetId:
        raw_score += _WEIGHT_TARGET_ASSET_ID
        matched.append("targetAssetId")
        evidence.append(ResolutionEvidenceItem(
            field="targetAssetId", matched=True,
            weight=_WEIGHT_TARGET_ASSET_ID,
            reason="Exact asset match",
            signalValue=signal.targetAssetId,
            existingValue=existing.targetAssetId,
        ))
    else:
        conflicting.append("targetAssetId")
        evidence.append(ResolutionEvidenceItem(
            field="targetAssetId", matched=False,
            weight=_WEIGHT_TARGET_ASSET_ID,
            reason=(
                f"Target asset mismatch: "
                f"{signal.targetAssetId} ≠ {existing.targetAssetId}"
            ),
            signalValue=signal.targetAssetId,
            existingValue=existing.targetAssetId,
        ))

    # --- relationshipType ---
    if sig_type == existing.relationshipType:
        raw_score += _WEIGHT_RELATIONSHIP_TYPE
        matched.append("relationshipType")
        evidence.append(ResolutionEvidenceItem(
            field="relationshipType", matched=True,
            weight=_WEIGHT_RELATIONSHIP_TYPE,
            reason=f"Relationship type matched: {sig_type.value}",
            signalValue=sig_type.value,
            existingValue=existing.relationshipType.value,
        ))
    else:
        conflicting.append("relationshipType")
        evidence.append(ResolutionEvidenceItem(
            field="relationshipType", matched=False,
            weight=_WEIGHT_RELATIONSHIP_TYPE,
            reason=(
                f"Relationship type changed: "
                f"{existing.relationshipType.value}→{sig_type.value}"
            ),
            signalValue=sig_type.value,
            existingValue=existing.relationshipType.value,
        ))

    # --- protocol ---
    if sig_proto == existing.protocol.upper().strip():
        raw_score += _WEIGHT_PROTOCOL
        matched.append("protocol")
        evidence.append(ResolutionEvidenceItem(
            field="protocol", matched=True,
            weight=_WEIGHT_PROTOCOL,
            reason=f"Protocol matched: {sig_proto}",
            signalValue=sig_proto,
            existingValue=existing.protocol,
        ))
    else:
        conflicting.append("protocol")
        evidence.append(ResolutionEvidenceItem(
            field="protocol", matched=False,
            weight=_WEIGHT_PROTOCOL,
            reason=(
                f"Protocol changed: "
                f"{existing.protocol}→{sig_proto}"
            ),
            signalValue=sig_proto,
            existingValue=existing.protocol,
        ))

    # --- port ---
    if signal.port == existing.port:
        raw_score += _WEIGHT_PORT
        matched.append("port")
        port_label = str(signal.port) if signal.port is not None else "None"
        evidence.append(ResolutionEvidenceItem(
            field="port", matched=True,
            weight=_WEIGHT_PORT,
            reason=f"Port matched: {port_label}",
            signalValue=signal.port,
            existingValue=existing.port,
        ))
    else:
        conflicting.append("port")
        evidence.append(ResolutionEvidenceItem(
            field="port", matched=False,
            weight=_WEIGHT_PORT,
            reason=(
                f"Port mismatch: "
                f"{existing.port}→{signal.port}"
            ),
            signalValue=signal.port,
            existingValue=existing.port,
        ))

    # --- direction (secondary) ---
    if (
        signal.direction != Direction.UNKNOWN
        and existing.direction != Direction.UNKNOWN
        and signal.direction == existing.direction
    ):
        raw_score += _WEIGHT_DIRECTION
        matched.append("direction")
        evidence.append(ResolutionEvidenceItem(
            field="direction", matched=True,
            weight=_WEIGHT_DIRECTION,
            reason=f"Direction matched: {signal.direction.value}",
            signalValue=signal.direction.value,
            existingValue=existing.direction.value,
        ))
    else:
        # Direction is secondary — only emit evidence when both are known
        if (
            signal.direction != Direction.UNKNOWN
            and existing.direction != Direction.UNKNOWN
        ):
            evidence.append(ResolutionEvidenceItem(
                field="direction", matched=False,
                weight=_WEIGHT_DIRECTION,
                reason=(
                    f"Direction changed: "
                    f"{existing.direction.value}→{signal.direction.value}"
                ),
                signalValue=signal.direction.value,
                existingValue=existing.direction.value,
            ))

    # --- captureId (secondary) ---
    if signal.captureId and existing.metadata.get("captureId") == signal.captureId:
        raw_score += _WEIGHT_CAPTURE_ID
        matched.append("captureId")
        evidence.append(ResolutionEvidenceItem(
            field="captureId", matched=True,
            weight=_WEIGHT_CAPTURE_ID,
            reason=f"Same capture session: {signal.captureId}",
            signalValue=signal.captureId,
            existingValue=existing.metadata.get("captureId"),
        ))
    elif signal.captureId:
        evidence.append(ResolutionEvidenceItem(
            field="captureId", matched=False,
            weight=_WEIGHT_CAPTURE_ID,
            reason="Different or unknown capture session",
            signalValue=signal.captureId,
            existingValue=existing.metadata.get("captureId"),
        ))

    score = min(100, max(0, raw_score))

    # Build reason string
    if matched:
        reason = f"Matched [{', '.join(matched)}]"
        if conflicting:
            reason += f"; conflict on [{', '.join(conflicting)}]"
    else:
        reason = "No fields matched"

    return RelationshipCandidate(
        relationshipId     = existing.relationshipId,
        relationshipKey    = existing.relationshipKey,
        score              = score,
        matchedFields      = matched,
        conflictingFields  = conflicting,
        confidence         = existing.confidence,
        reason             = reason,
        resolutionEvidence = evidence,
    )


# ---------------------------------------------------------------------------
# Utility: sort_candidates()
# ---------------------------------------------------------------------------

def sort_candidates(
    candidates : List[RelationshipCandidate],
    descending : bool = True,
) -> List[RelationshipCandidate]:
    """
    Sort candidates by score, then by confidence as a tie-breaker.

    Parameters
    ----------
    candidates : list to sort (not mutated).
    descending : True = highest score first (default).

    Returns
    -------
    New sorted List[RelationshipCandidate].
    """
    return sorted(
        candidates,
        key=lambda c: (c.score, c.confidence),
        reverse=descending,
    )


# ---------------------------------------------------------------------------
# Utility: filter_candidates()
# ---------------------------------------------------------------------------

def filter_candidates(
    candidates  : List[RelationshipCandidate],
    min_score   : int = 0,
    max_results : int = 10,
) -> List[RelationshipCandidate]:
    """
    Filter and cap candidates.

    Parameters
    ----------
    candidates  : source list (assumed already sorted descending by score).
    min_score   : discard candidates with score < min_score.
    max_results : return at most this many candidates.

    Returns
    -------
    Filtered List[RelationshipCandidate].
    """
    filtered = [c for c in candidates if c.score >= min_score]
    return filtered[:max_results]


# ---------------------------------------------------------------------------
# Core: score_relationship()
# ---------------------------------------------------------------------------

def score_relationship(
    existing  : Relationship,
    signal    : RelationshipSignal,
) -> RelationshipCandidate:
    """
    Public entry point for scoring one existing Relationship against a signal.

    Thin wrapper around calculate_match_score() — kept separate so callers
    have a stable public symbol to import without coupling to the internal
    scorer.

    Parameters
    ----------
    existing : Relationship being evaluated.
    signal   : incoming RelationshipSignal.

    Returns
    -------
    RelationshipCandidate (frozen / immutable).
    """
    return calculate_match_score(existing, signal)


# ---------------------------------------------------------------------------
# Internal: _detect_termination()
# ---------------------------------------------------------------------------

def _detect_termination(
    signal   : RelationshipSignal,
    existing : Relationship,
) -> bool:
    """
    Return True if the signal carries an explicit termination marker.

    Checks:
    1. signal.metadata contains a key in _TERMINATION_REASONS with a
       truthy value.
    2. existing.state is already TERMINATED.
    """
    if existing.state == RelationshipState.TERMINATED:
        return True
    for reason in _TERMINATION_REASONS:
        if signal.metadata.get(reason):
            return True
    return False


# ---------------------------------------------------------------------------
# Internal: _detect_inactivity()
# ---------------------------------------------------------------------------

def _detect_inactivity(
    existing        : Relationship,
    now_ts          : Optional[float],
    threshold_secs  : int = INACTIVITY_THRESHOLD_SECONDS,
) -> bool:
    """
    Return True if the existing Relationship has been inactive longer than
    threshold_secs seconds.

    Parameters
    ----------
    existing       : Relationship being evaluated.
    now_ts         : current time as POSIX timestamp (seconds).
                     If None, uses time.time().
    threshold_secs : inactivity window in seconds.
    """
    if existing.lastSeen is None:
        return False
    now = now_ts if now_ts is not None else time.time()
    last_seen_ts = existing.lastSeen.timestamp()
    return (now - last_seen_ts) > threshold_secs


# ---------------------------------------------------------------------------
# Internal: _apply_decision_thresholds()
# ---------------------------------------------------------------------------

def _apply_decision_thresholds(score: int) -> DecisionLevel:
    """
    Map a normalised 0–100 score to a DecisionLevel using the configured
    thresholds.  Falls through from highest to lowest.

    Parameters
    ----------
    score : normalised 0–100 candidate score.

    Returns
    -------
    DecisionLevel.
    """
    if score >= _DECISION_THRESHOLDS["MATCH"]:
        return DecisionLevel.MATCH
    if score >= _DECISION_THRESHOLDS["LIKELY_MATCH"]:
        return DecisionLevel.LIKELY_MATCH
    if score >= _DECISION_THRESHOLDS["POSSIBLE_MATCH"]:
        return DecisionLevel.POSSIBLE_MATCH
    if score >= _DECISION_THRESHOLDS["MANUAL_REVIEW"]:
        return DecisionLevel.MANUAL_REVIEW
    return DecisionLevel.CREATE_NEW


# ---------------------------------------------------------------------------
# Core: resolve_relationship()
# ---------------------------------------------------------------------------

def resolve_relationship(
    signal              : RelationshipSignal,
    existing            : Sequence[Relationship],
    history             : Optional[RelationshipHistoryBundle] = None,
    now_ts              : Optional[float]                     = None,
    inactivity_threshold: int = INACTIVITY_THRESHOLD_SECONDS,
) -> RelationshipResolutionDecision:
    """
    Resolve a RelationshipSignal against a pool of existing Relationships.

    Decision rules (in priority order)
    ------------------------------------
    1. TERMINATE   — signal or existing state carries explicit termination.
    2. INACTIVATE  — top candidate has been inactive > inactivity_threshold.
    3. MATCH       — top candidate fingerprint == signal fingerprint (score 100).
    4. UPDATE_EXISTING — top candidate shares sourceAssetId + targetAssetId
                         (same pair, new packet — score >= 60 but < 95).
    5. MANUAL_REVIEW — top-2 candidates are within _AMBIGUITY_BAND of each
                       other at a score that would otherwise be LIKELY_MATCH.
    6. Score threshold — map top candidate's score to DecisionLevel via
                         _apply_decision_thresholds().
    7. CREATE_NEW  — no candidates, or top score < MANUAL_REVIEW threshold.

    Parameters
    ----------
    signal               : incoming RelationshipSignal to resolve.
    existing             : pool of Relationship objects to evaluate.
    history              : optional RelationshipHistoryBundle for context
                           (not used in scoring; available for future rules).
    now_ts               : current POSIX timestamp; defaults to time.time().
    inactivity_threshold : seconds without traffic before INACTIVATE fires.

    Returns
    -------
    RelationshipResolutionDecision (frozen / immutable).
    """
    warnings: List[str] = []

    # --- No existing relationships → CREATE_NEW immediately. ---
    if not existing:
        return RelationshipResolutionDecision(
            decision = DecisionLevel.CREATE_NEW,
            score    = 0,
            reason   = "No existing relationships in pool",
        )

    sig_type        = _infer_type_from_signal(signal)
    sig_fingerprint = _fingerprint_from_signal(signal, sig_type)

    # --- Score all candidates. ---
    candidates: List[RelationshipCandidate] = [
        calculate_match_score(rel, signal) for rel in existing
    ]
    candidates = sort_candidates(candidates)

    top = candidates[0]

    # Locate the matching Relationship object for special-rule checks.
    _rel_by_id: Dict[str, Relationship] = {r.relationshipId: r for r in existing}
    top_rel = _rel_by_id.get(top.relationshipId)

    # ----------------------------------------------------------------
    # Rule 1 — TERMINATE
    # ----------------------------------------------------------------
    if top_rel is not None and _detect_termination(signal, top_rel):
        return RelationshipResolutionDecision(
            decision               = DecisionLevel.TERMINATE,
            matchedRelationshipId  = top.relationshipId,
            matchedRelationshipKey = top.relationshipKey,
            score                  = top.score,
            reason                 = "Explicit termination signal detected",
            warnings               = warnings,
        )

    # ----------------------------------------------------------------
    # Rule 2 — INACTIVATE (only if top candidate would otherwise match)
    # ----------------------------------------------------------------
    if (
        top_rel is not None
        and top.score >= _DECISION_THRESHOLDS["POSSIBLE_MATCH"]
        and _detect_inactivity(top_rel, now_ts, inactivity_threshold)
    ):
        return RelationshipResolutionDecision(
            decision               = DecisionLevel.INACTIVATE,
            matchedRelationshipId  = top.relationshipId,
            matchedRelationshipKey = top.relationshipKey,
            score                  = top.score,
            reason                 = (
                f"Relationship inactive for >{inactivity_threshold}s "
                f"(lastSeen={top_rel.lastSeen})"
            ),
            warnings               = warnings,
        )

    # ----------------------------------------------------------------
    # Rule 3 — MATCH via exact fingerprint identity (score = 100)
    # ----------------------------------------------------------------
    if top_rel is not None:
        existing_fingerprint = _fingerprint_from_relationship(top_rel)
        if existing_fingerprint == sig_fingerprint and top.score >= 95:
            return RelationshipResolutionDecision(
                decision               = DecisionLevel.MATCH,
                matchedRelationshipId  = top.relationshipId,
                matchedRelationshipKey = top.relationshipKey,
                score                  = top.score,
                reason                 = "Exact fingerprint match",
                warnings               = warnings,
            )

    # ----------------------------------------------------------------
    # Rule 4 — UPDATE_EXISTING: same pair (src+tgt match), score 60–94
    # ----------------------------------------------------------------
    same_pair = (
        "sourceAssetId" in top.matchedFields
        and "targetAssetId" in top.matchedFields
    )
    if same_pair and 60 <= top.score < 95:
        return RelationshipResolutionDecision(
            decision               = DecisionLevel.UPDATE_EXISTING,
            matchedRelationshipId  = top.relationshipId,
            matchedRelationshipKey = top.relationshipKey,
            score                  = top.score,
            reason                 = (
                f"Same asset pair with new observation (score={top.score})"
            ),
            warnings               = warnings,
        )

    # ----------------------------------------------------------------
    # Rule 5 — MANUAL_REVIEW: top-2 candidates within ambiguity band
    # ----------------------------------------------------------------
    if (
        len(candidates) >= 2
        and top.score >= _DECISION_THRESHOLDS["LIKELY_MATCH"]
        and (top.score - candidates[1].score) <= _AMBIGUITY_BAND
    ):
        warnings.append(
            f"Top-2 candidates within {_AMBIGUITY_BAND}-pt band "
            f"({top.score} vs {candidates[1].score})"
        )
        return RelationshipResolutionDecision(
            decision               = DecisionLevel.MANUAL_REVIEW,
            matchedRelationshipId  = top.relationshipId,
            matchedRelationshipKey = top.relationshipKey,
            score                  = top.score,
            reason                 = "Ambiguous candidates — manual review required",
            warnings               = warnings,
        )

    # ----------------------------------------------------------------
    # Rule 6 — Score threshold fallback
    # ----------------------------------------------------------------
    level = _apply_decision_thresholds(top.score)

    if level == DecisionLevel.CREATE_NEW:
        return RelationshipResolutionDecision(
            decision = DecisionLevel.CREATE_NEW,
            score    = top.score,
            reason   = f"Best candidate score {top.score} below CREATE_NEW threshold",
            warnings = warnings,
        )

    return RelationshipResolutionDecision(
        decision               = level,
        matchedRelationshipId  = top.relationshipId,
        matchedRelationshipKey = top.relationshipKey,
        score                  = top.score,
        reason                 = top.reason,
        warnings               = warnings,
    )


# ---------------------------------------------------------------------------
# Builder: build_resolution_result()
# ---------------------------------------------------------------------------

def build_resolution_result(
    signal              : RelationshipSignal,
    existing            : Sequence[Relationship],
    history             : Optional[RelationshipHistoryBundle] = None,
    now_ts              : Optional[float]                     = None,
    inactivity_threshold: int = INACTIVITY_THRESHOLD_SECONDS,
) -> RelationshipResolutionResult:
    """
    Full resolution pass for one RelationshipSignal.

    Combines resolve_relationship() with candidate scoring, timing, and
    packaging into a RelationshipResolutionResult.

    Parameters
    ----------
    signal               : incoming RelationshipSignal to resolve.
    existing             : pool of Relationship objects to evaluate.
    history              : optional RelationshipHistoryBundle (context only).
    now_ts               : current POSIX timestamp; defaults to time.time().
    inactivity_threshold : seconds without traffic before INACTIVATE fires.

    Returns
    -------
    RelationshipResolutionResult (frozen / immutable).
    """
    t_start = time.monotonic()

    # Score all candidates (empty list is fine — resolve handles it).
    candidates: List[RelationshipCandidate] = [
        calculate_match_score(rel, signal) for rel in existing
    ]
    sorted_candidates = sort_candidates(candidates)

    decision = resolve_relationship(
        signal               = signal,
        existing             = existing,
        history              = history,
        now_ts               = now_ts,
        inactivity_threshold = inactivity_threshold,
    )

    processing_ms = (time.monotonic() - t_start) * 1000.0

    return RelationshipResolutionResult(
        decision         = decision,
        candidateScores  = sorted_candidates,
        processingTimeMs = round(processing_ms, 3),
        engineVersion    = RELATIONSHIP_RESOLUTION_ENGINE_VERSION,
    )
