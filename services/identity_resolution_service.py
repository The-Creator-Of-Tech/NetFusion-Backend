"""
Identity Resolution Engine
===========================
Phase A.2.2.3 — Resolve only. No persistence. No database. No repositories.

Receives:
  1.  IdentitySignal      — extracted attributes from one packet / event
  2.  IdentityConfidence  — per-field reliability scores for the signal
  3.  List[AssetSummary]  — candidate assets supplied by the CALLER
                            (repository access is the caller's responsibility)

Returns a ResolutionDecision that tells the caller:
  - Whether the signal matches an existing asset
  - Which candidate scored highest and why
  - All scored candidates sorted by score descending
  - Any conflicts or warnings the caller must handle

Design principles
-----------------
- Pure computation: no I/O, no DB, no side effects.
- Deterministic: same inputs always produce the same output.
- No AI, no heuristics, no randomness.
- All weights and thresholds live in core/constants.py — never hardcoded.
- The engine SCORES and DECIDES. It does NOT persist.

Matching priority (descending)
-------------------------------
  MAC Address       100 pts  — hardware-level ground truth, exact match
  Hostname           80 pts  — device self-declared name, normalised compare
  Current IP         70 pts  — IP currently assigned to this asset
  Previous IP        40 pts  — IP previously seen (rotated / released)
  SSID               20 pts  — WiFi SSID association
  Vendor             15 pts  — OUI vendor string
  Operating System   15 pts  — OS fingerprint

Score is normalised to 0–100 by dividing by RESOLUTION_MAX_POSSIBLE_SCORE.

Decision levels
---------------
  MATCH           ≥ 90  — single dominant candidate, high certainty
  LIKELY_MATCH    ≥ 65  — strong partial match, proceed with caution
  POSSIBLE_MATCH  ≥ 35  — weak signal, needs corroboration
  MANUAL_REVIEW   ≥ 10  — ambiguous / conflicting; human review required
  CREATE_NEW      =  0  — no plausible match; create a new asset record
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.constants import (
    IDENTITY_RESOLUTION_ENGINE_VERSION,
    RESOLUTION_DECISION_THRESHOLDS,
    RESOLUTION_FIELD_WEIGHTS,
    RESOLUTION_MAX_POSSIBLE_SCORE,
)
from services.identity_confidence_service import IdentityConfidence
from services.identity_signal_service import IdentitySignal


# ---------------------------------------------------------------------------
# DecisionLevel enum
# ---------------------------------------------------------------------------

class DecisionLevel(str, Enum):
    """
    Resolution outcome tier produced by build_decision().
    Thresholds are defined in core/constants.RESOLUTION_DECISION_THRESHOLDS.
    """
    MATCH          = "MATCH"           # high-confidence single match
    LIKELY_MATCH   = "LIKELY_MATCH"    # probable match, verify before writing
    POSSIBLE_MATCH = "POSSIBLE_MATCH"  # weak match, needs corroboration
    MANUAL_REVIEW  = "MANUAL_REVIEW"   # ambiguous; human must decide
    CREATE_NEW     = "CREATE_NEW"      # no match; create a new Asset row


# ---------------------------------------------------------------------------
# AssetSummary — caller-supplied asset snapshot
# ---------------------------------------------------------------------------

class AssetSummary(BaseModel):
    """
    Minimal projection of a stored Asset supplied by the caller.

    The Resolution Engine never reads the database directly.
    The caller fetches candidates from the repository and passes them here.

    Fields map to the Asset schema (schema.prisma) but only the attributes
    needed for matching are required.  All others are optional.

    Future sources (Nmap, Zeek, …) may populate additional fields — the
    engine ignores unknown fields gracefully.
    """
    assetId         : str
    macAddresses    : List[str]  = Field(default_factory=list)  # AssetMAC.macAddress[]
    currentIps      : List[str]  = Field(default_factory=list)  # AssetIPAddress where isCurrent=True
    previousIps     : List[str]  = Field(default_factory=list)  # AssetIPAddress where isCurrent=False
    hostnames       : List[str]  = Field(default_factory=list)  # AssetHostname.hostname[]
    ssids           : List[str]  = Field(default_factory=list)  # AssetSSID.ssid[]
    vendor          : Optional[str] = None                      # Asset.vendor
    operatingSystem : Optional[str] = None                      # Asset.os
    metadata        : Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# ResolutionReason — per-field match / mismatch detail
# ---------------------------------------------------------------------------

class ResolutionReason(BaseModel):
    """
    Explains why one specific field contributed to (or detracted from)
    a candidate's score.  Intended for SOC analyst explainability.

    Attributes
    ----------
    field        Field name evaluated (e.g. "macAddress").
    signalValue  Value extracted from the IdentitySignal.
    assetValue   Value stored on the AssetSummary (best match found).
    result       "match" | "no_match" | "partial_match" | "missing"
    scoreImpact  Points added (positive) or deducted (negative or zero).
    description  One-sentence plain-English explanation.
    """
    field       : str
    signalValue : Optional[str] = None
    assetValue  : Optional[str] = None
    result      : str           = "missing"   # match | no_match | partial_match | missing
    scoreImpact : int           = 0
    description : str           = ""


# ---------------------------------------------------------------------------
# ResolutionCandidate — one scored asset
# ---------------------------------------------------------------------------

class ResolutionCandidate(BaseModel):
    """
    A single asset candidate with its match score and field-level breakdown.

    Attributes
    ----------
    assetId          Asset primary key.
    score            Normalised score 0–100.
    matchedFields    Fields where signal value matched asset value.
    conflictingFields Fields where signal value DID NOT match asset value.
    confidence       Overall signal confidence (from IdentityConfidence).
    reason           Per-field ResolutionReason list for full explainability.
    """
    assetId          : str
    score            : int               = Field(ge=0, le=100)
    matchedFields    : List[str]         = Field(default_factory=list)
    conflictingFields: List[str]         = Field(default_factory=list)
    confidence       : int               = Field(ge=0, le=100, default=0)
    reason           : List[ResolutionReason] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# ResolutionDecision — the final output of the engine
# ---------------------------------------------------------------------------

class ResolutionDecision(BaseModel):
    """
    Complete output of resolve_identity().

    Attributes
    ----------
    matched          True when a suitable existing asset was found.
    createNewAsset   True when the engine recommends creating a new asset.
    matchedAssetId   Asset ID of the top candidate (None if CREATE_NEW).
    confidence       Overall signal confidence passed through from IdentityConfidence.
    decision         DecisionLevel enum value.
    reason           Plain-English summary of the decision for the SOC analyst.
    candidateScores  All evaluated candidates sorted by score descending.
    conflicts        Field-level conflicts carried over from IdentityConfidence.
    warnings         Quality warnings for the caller.
    metadata         Engine metadata (version, timing, input summary).
    """
    matched         : bool               = False
    createNewAsset  : bool               = False
    matchedAssetId  : Optional[str]      = None
    confidence      : int                = Field(ge=0, le=100, default=0)
    decision        : DecisionLevel      = DecisionLevel.CREATE_NEW
    reason          : str                = ""
    candidateScores : List[ResolutionCandidate] = Field(default_factory=list)
    conflicts       : List[str]          = Field(default_factory=list)
    warnings        : List[str]          = Field(default_factory=list)
    metadata        : Dict[str, Any]     = Field(default_factory=dict)

    class Config:
        use_enum_values = True


# ---------------------------------------------------------------------------
# Public helper: normalize_value()
# ---------------------------------------------------------------------------

def normalize_value(value: Optional[str]) -> Optional[str]:
    """
    Normalize a string value for comparison.

    Rules:
    - Strip whitespace
    - Lowercase
    - Return None for empty/None inputs

    Used by all field comparisons — never compare raw strings directly.
    """
    if value is None:
        return None
    s = str(value).strip().lower()
    return s if s else None


def normalize_values(values: List[Optional[str]]) -> List[str]:
    """Normalize a list of values, dropping None/empty entries."""
    result = []
    for v in values:
        n = normalize_value(v)
        if n:
            result.append(n)
    return result


# ---------------------------------------------------------------------------
# Public helper: score_candidate()
# ---------------------------------------------------------------------------

def score_candidate(
    signal    : IdentitySignal,
    asset     : AssetSummary,
    confidence: IdentityConfidence,
) -> ResolutionCandidate:
    """
    Score one AssetSummary against the IdentitySignal.

    For each field in RESOLUTION_FIELD_WEIGHTS:
      - Extract the signal value
      - Extract the asset value(s)
      - Compare (normalised, case-insensitive)
      - Award points on match; zero on miss
      - Build a ResolutionReason for full explainability

    Returns
    -------
    ResolutionCandidate with raw score, matched fields, conflict fields,
    and per-field reasons.

    Score normalisation
    -------------------
    raw_score = sum of weights for all matched fields
    normalised = round(raw_score / RESOLUTION_MAX_POSSIBLE_SCORE * 100)
    Clamped to [0, 100].
    """
    reasons         : List[ResolutionReason] = []
    matched_fields  : List[str]              = []
    conflict_fields : List[str]              = []
    raw_score       : int                    = 0

    # ── MAC Address ───────────────────────────────────────────────────────
    _eval_field(
        field_name     = "macAddress",
        signal_value   = normalize_value(signal.macAddress),
        asset_values   = normalize_values(asset.macAddresses),
        weight         = RESOLUTION_FIELD_WEIGHTS["macAddress"],
        raw_score_ref  = [raw_score],
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
        reasons        = reasons,
    )
    raw_score = reasons[-1].scoreImpact if reasons else raw_score
    # Accumulate correctly — recompute from reasons
    raw_score = sum(r.scoreImpact for r in reasons)

    # ── Hostname ──────────────────────────────────────────────────────────
    signal_hostnames = normalize_values(signal.hostnames or [signal.hostname])
    asset_hostnames  = normalize_values(asset.hostnames)
    _eval_list_field(
        field_name     = "hostname",
        signal_values  = signal_hostnames,
        asset_values   = asset_hostnames,
        weight         = RESOLUTION_FIELD_WEIGHTS["hostname"],
        reasons        = reasons,
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
    )

    # ── Current IP ────────────────────────────────────────────────────────
    signal_ip = normalize_value(signal.ipAddress)
    _eval_field(
        field_name     = "currentIp",
        signal_value   = signal_ip,
        asset_values   = normalize_values(asset.currentIps),
        weight         = RESOLUTION_FIELD_WEIGHTS["currentIp"],
        raw_score_ref  = None,
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
        reasons        = reasons,
    )

    # ── Previous IP ───────────────────────────────────────────────────────
    # Only score if current IP did NOT already match (avoid double-counting)
    current_ip_matched = any(r.field == "currentIp" and r.result == "match" for r in reasons)
    if not current_ip_matched:
        _eval_field(
            field_name     = "previousIp",
            signal_value   = signal_ip,
            asset_values   = normalize_values(asset.previousIps),
            weight         = RESOLUTION_FIELD_WEIGHTS["previousIp"],
            raw_score_ref  = None,
            matched_fields = matched_fields,
            conflict_fields= conflict_fields,
            reasons        = reasons,
        )

    # ── SSID ──────────────────────────────────────────────────────────────
    _eval_field(
        field_name     = "ssid",
        signal_value   = normalize_value(signal.ssid),
        asset_values   = normalize_values(asset.ssids),
        weight         = RESOLUTION_FIELD_WEIGHTS["ssid"],
        raw_score_ref  = None,
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
        reasons        = reasons,
    )

    # ── Vendor ────────────────────────────────────────────────────────────
    _eval_field(
        field_name     = "vendor",
        signal_value   = normalize_value(signal.vendor),
        asset_values   = [normalize_value(asset.vendor)] if asset.vendor else [],
        weight         = RESOLUTION_FIELD_WEIGHTS["vendor"],
        raw_score_ref  = None,
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
        reasons        = reasons,
    )

    # ── Operating System ──────────────────────────────────────────────────
    _eval_field(
        field_name     = "operatingSystem",
        signal_value   = normalize_value(signal.operatingSystem),
        asset_values   = [normalize_value(asset.operatingSystem)] if asset.operatingSystem else [],
        weight         = RESOLUTION_FIELD_WEIGHTS["operatingSystem"],
        raw_score_ref  = None,
        matched_fields = matched_fields,
        conflict_fields= conflict_fields,
        reasons        = reasons,
    )

    # ── Compute total raw score from reasons ──────────────────────────────
    raw_score = sum(r.scoreImpact for r in reasons)

    # Normalise to 0–100
    normalised = _normalise_score(raw_score)

    return ResolutionCandidate(
        assetId          = asset.assetId,
        score            = normalised,
        matchedFields    = matched_fields,
        conflictingFields= conflict_fields,
        confidence       = confidence.overallConfidence,
        reason           = reasons,
    )


# ---------------------------------------------------------------------------
# Public helper: build_resolution_reason()
# ---------------------------------------------------------------------------

def build_resolution_reason(
    field_name   : str,
    signal_value : Optional[str],
    asset_value  : Optional[str],
    matched      : bool,
    score_impact : int,
) -> ResolutionReason:
    """
    Build one ResolutionReason entry.

    Parameters
    ----------
    field_name   : str
    signal_value : value from IdentitySignal (normalised)
    asset_value  : value from AssetSummary (best match, normalised)
    matched      : True if the comparison succeeded
    score_impact : points awarded (0 on miss)

    Returns
    -------
    ResolutionReason
    """
    if signal_value is None:
        result      = "missing"
        description = f"'{field_name}' not present in signal — no contribution."
    elif asset_value is None:
        result      = "missing"
        description = (
            f"'{field_name}' has signal value '{signal_value}' "
            "but asset has no recorded value — no contribution."
        )
    elif matched:
        result      = "match"
        description = (
            f"'{field_name}' matched: signal '{signal_value}' "
            f"= asset '{asset_value}'. +{score_impact} pts."
        )
    else:
        result      = "no_match"
        description = (
            f"'{field_name}' did not match: signal '{signal_value}' "
            f"≠ asset '{asset_value}'. No contribution."
        )

    return ResolutionReason(
        field       = field_name,
        signalValue = signal_value,
        assetValue  = asset_value,
        result      = result,
        scoreImpact = score_impact if matched else 0,
        description = description,
    )


# ---------------------------------------------------------------------------
# Public helper: sort_candidates()
# ---------------------------------------------------------------------------

def sort_candidates(candidates: List[ResolutionCandidate]) -> List[ResolutionCandidate]:
    """
    Sort candidates by score descending, then by number of matched fields
    descending as a tiebreaker.

    Returns a new sorted list — does not mutate in place.
    """
    return sorted(
        candidates,
        key=lambda c: (-c.score, -len(c.matchedFields)),
    )


# ---------------------------------------------------------------------------
# Public helper: build_decision()
# ---------------------------------------------------------------------------

def build_decision(
    sorted_candidates : List[ResolutionCandidate],
    signal            : IdentitySignal,
    confidence        : IdentityConfidence,
) -> ResolutionDecision:
    """
    Convert a sorted candidate list into a final ResolutionDecision.

    Rules
    -----
    1.  No candidates → CREATE_NEW.
    2.  Top candidate score maps to a DecisionLevel via
        RESOLUTION_DECISION_THRESHOLDS.
    3.  If two candidates are within 10 pts of each other AND both ≥ 35,
        escalate to MANUAL_REVIEW (ambiguous match).
    4.  MATCH and LIKELY_MATCH → matched=True, matchedAssetId=top.assetId.
    5.  CREATE_NEW → createNewAsset=True.
    6.  MANUAL_REVIEW → matched=False, createNewAsset=False.

    Returns
    -------
    ResolutionDecision
    """
    warnings : List[str] = list(confidence.warnings)

    # ── No candidates ─────────────────────────────────────────────────────
    if not sorted_candidates:
        return ResolutionDecision(
            matched        = False,
            createNewAsset = True,
            decision       = DecisionLevel.CREATE_NEW,
            confidence     = confidence.overallConfidence,
            reason         = "No candidate assets supplied. New asset recommended.",
            candidateScores= [],
            conflicts      = [c.description for c in confidence.conflicts],
            warnings       = warnings,
            metadata       = _build_metadata(signal, confidence, candidates_evaluated=0),
        )

    top = sorted_candidates[0]

    # ── Ambiguity check — two candidates too close to each other ──────────
    ambiguous = (
        len(sorted_candidates) >= 2
        and sorted_candidates[1].score >= 35
        and (top.score - sorted_candidates[1].score) <= 10
    )

    # ── Map score → DecisionLevel ─────────────────────────────────────────
    level = _score_to_decision_level(top.score)

    # Escalate to MANUAL_REVIEW if ambiguous, unless score is below POSSIBLE_MATCH
    if ambiguous and level in (
        DecisionLevel.MATCH,
        DecisionLevel.LIKELY_MATCH,
        DecisionLevel.POSSIBLE_MATCH,
    ):
        level = DecisionLevel.MANUAL_REVIEW
        warnings.append(
            f"Two candidates scored within 10 pts of each other "
            f"({top.score} vs {sorted_candidates[1].score}). "
            "Manual review required."
        )

    # ── Build decision flags ──────────────────────────────────────────────
    matched          = level in (DecisionLevel.MATCH, DecisionLevel.LIKELY_MATCH)
    create_new       = level == DecisionLevel.CREATE_NEW
    matched_asset_id = top.assetId if matched else None

    # ── Build human-readable reason ───────────────────────────────────────
    reason = _build_decision_reason(
        level       = level,
        top         = top,
        second      = sorted_candidates[1] if len(sorted_candidates) >= 2 else None,
        total       = len(sorted_candidates),
        ambiguous   = ambiguous,
    )

    return ResolutionDecision(
        matched         = matched,
        createNewAsset  = create_new,
        matchedAssetId  = matched_asset_id,
        confidence      = confidence.overallConfidence,
        decision        = level,
        reason          = reason,
        candidateScores = sorted_candidates,
        conflicts       = [c.description for c in confidence.conflicts],
        warnings        = warnings,
        metadata        = _build_metadata(signal, confidence, candidates_evaluated=len(sorted_candidates)),
    )


# ---------------------------------------------------------------------------
# Core public function: resolve_identity()
# ---------------------------------------------------------------------------

def resolve_identity(
    signal     : IdentitySignal,
    confidence : IdentityConfidence,
    candidates : List[AssetSummary],
) -> ResolutionDecision:
    """
    Determine whether the IdentitySignal matches an existing asset.

    Parameters
    ----------
    signal : IdentitySignal
        Extracted from one packet / event by identity_signal_service.
    confidence : IdentityConfidence
        Field-level reliability scores from identity_confidence_service.
    candidates : List[AssetSummary]
        Possible matching assets supplied by the caller.
        The caller is responsible for pre-filtering (e.g. by projectId)
        before passing candidates here.

    Returns
    -------
    ResolutionDecision
        Contains the decision level, matched asset ID (if any), all
        candidate scores, conflicts, and analyst-facing reasons.

    Notes
    -----
    - Does NOT access any repository or database.
    - Does NOT create or modify Asset rows.
    - Does NOT persist anything.
    - Pure computation — same inputs always produce the same output.
    """
    # Score every candidate
    scored = [
        score_candidate(signal, asset, confidence)
        for asset in candidates
    ]

    # Sort highest → lowest
    ranked = sort_candidates(scored)

    # Build and return the decision
    return build_decision(ranked, signal, confidence)


# ---------------------------------------------------------------------------
# Internal field evaluation helpers
# ---------------------------------------------------------------------------

def _eval_field(
    field_name     : str,
    signal_value   : Optional[str],
    asset_values   : List[str],
    weight         : int,
    raw_score_ref  : Optional[list],   # unused, kept for interface symmetry
    matched_fields : List[str],
    conflict_fields: List[str],
    reasons        : List[ResolutionReason],
) -> None:
    """
    Evaluate one single-value field and append a ResolutionReason.
    Mutates matched_fields / conflict_fields / reasons in place.
    """
    if not signal_value:
        reasons.append(build_resolution_reason(field_name, None, None, False, 0))
        return

    if not asset_values:
        reasons.append(build_resolution_reason(field_name, signal_value, None, False, 0))
        return

    # Check for a match against any of the asset's values
    matched_asset_value = next(
        (av for av in asset_values if av == signal_value),
        None,
    )

    if matched_asset_value:
        matched_fields.append(field_name)
        reasons.append(build_resolution_reason(field_name, signal_value, matched_asset_value, True, weight))
    else:
        conflict_fields.append(field_name)
        reasons.append(build_resolution_reason(field_name, signal_value, asset_values[0], False, 0))


def _eval_list_field(
    field_name     : str,
    signal_values  : List[str],
    asset_values   : List[str],
    weight         : int,
    reasons        : List[ResolutionReason],
    matched_fields : List[str],
    conflict_fields: List[str],
) -> None:
    """
    Evaluate a list-valued field (e.g. hostname).
    A match occurs if ANY signal value intersects with ANY asset value.
    Mutates matched_fields / conflict_fields / reasons in place.
    """
    if not signal_values:
        reasons.append(build_resolution_reason(field_name, None, None, False, 0))
        return

    if not asset_values:
        reasons.append(build_resolution_reason(
            field_name, signal_values[0], None, False, 0
        ))
        return

    signal_set = set(signal_values)
    asset_set  = set(asset_values)
    intersection = signal_set & asset_set

    if intersection:
        best_match = next(iter(intersection))
        matched_fields.append(field_name)
        reasons.append(build_resolution_reason(
            field_name, best_match, best_match, True, weight
        ))
    else:
        conflict_fields.append(field_name)
        reasons.append(build_resolution_reason(
            field_name, signal_values[0], asset_values[0], False, 0
        ))


def _normalise_score(raw: int) -> int:
    """Normalise raw point total to 0–100."""
    if RESOLUTION_MAX_POSSIBLE_SCORE == 0:
        return 0
    normalised = round(raw / RESOLUTION_MAX_POSSIBLE_SCORE * 100)
    return max(0, min(100, normalised))


def _score_to_decision_level(score: int) -> DecisionLevel:
    """
    Map a normalised score (0–100) to a DecisionLevel using
    RESOLUTION_DECISION_THRESHOLDS from core/constants.py.
    """
    for level_name, threshold in sorted(
        RESOLUTION_DECISION_THRESHOLDS.items(), key=lambda kv: -kv[1]
    ):
        if score >= threshold:
            return DecisionLevel(level_name)
    return DecisionLevel.CREATE_NEW


def _build_decision_reason(
    level    : DecisionLevel,
    top      : ResolutionCandidate,
    second   : Optional[ResolutionCandidate],
    total    : int,
    ambiguous: bool,
) -> str:
    """Build a terse plain-English decision summary for the SOC analyst."""
    matched_str = ", ".join(top.matchedFields) if top.matchedFields else "none"

    if level == DecisionLevel.MATCH:
        return (
            f"Strong match with asset '{top.assetId}' "
            f"(score {top.score}/100). "
            f"Matched fields: {matched_str}."
        )
    if level == DecisionLevel.LIKELY_MATCH:
        return (
            f"Likely match with asset '{top.assetId}' "
            f"(score {top.score}/100). "
            f"Matched fields: {matched_str}. Verify before writing."
        )
    if level == DecisionLevel.POSSIBLE_MATCH:
        second_str = f" Runner-up: '{second.assetId}' ({second.score}/100)." if second else ""
        return (
            f"Possible match with asset '{top.assetId}' "
            f"(score {top.score}/100). "
            f"Matched fields: {matched_str}.{second_str} Corroboration needed."
        )
    if level == DecisionLevel.MANUAL_REVIEW:
        if ambiguous and second:
            return (
                f"Ambiguous: '{top.assetId}' ({top.score}/100) and "
                f"'{second.assetId}' ({second.score}/100) are too close to "
                f"resolve automatically. {total} candidate(s) evaluated. Manual review required."
            )
        return (
            f"Low-confidence match with '{top.assetId}' (score {top.score}/100). "
            f"Matched fields: {matched_str}. Manual review required."
        )
    # CREATE_NEW
    if total > 0:
        return (
            f"Best candidate '{top.assetId}' scored only {top.score}/100 "
            f"({total} candidate(s) evaluated). No match. New asset recommended."
        )
    return "No candidates provided. New asset recommended."


def _build_metadata(
    signal    : IdentitySignal,
    confidence: IdentityConfidence,
    candidates_evaluated: int,
) -> Dict[str, Any]:
    """Build the metadata dict for ResolutionDecision."""
    return {
        "engineVersion"       : IDENTITY_RESOLUTION_ENGINE_VERSION,
        "confidenceVersion"   : confidence.metadata.get("engineVersion", "unknown"),
        "candidatesEvaluated" : candidates_evaluated,
        "signalSource"        : (
            signal.sourceType
            if isinstance(signal.sourceType, str)
            else signal.sourceType.value
        ),
        "signalPacketNumber"  : signal.packetNumber,
        "signalCaptureId"     : signal.captureId,
        "overallConfidence"   : confidence.overallConfidence,
        "maxPossibleScore"    : RESOLUTION_MAX_POSSIBLE_SCORE,
    }


# ---------------------------------------------------------------------------
# Future extension points
# ---------------------------------------------------------------------------
# To add a new matching dimension (e.g. TLS certificate fingerprint):
#
#   1.  Add an entry to RESOLUTION_FIELD_WEIGHTS in core/constants.py.
#       Update RESOLUTION_MAX_POSSIBLE_SCORE if you add a new constant.
#
#   2.  Add the new field to AssetSummary (e.g. tlsFingerprints: List[str]).
#
#   3.  Add the new field to IdentitySignal (identity_signal_service.py).
#
#   4.  Add a new _eval_field() / _eval_list_field() call inside
#       score_candidate() for the new field.
#
#   5.  No other changes needed — build_decision() and sort_candidates()
#       are field-agnostic.
#
# To change decision thresholds:
#   Edit RESOLUTION_DECISION_THRESHOLDS in core/constants.py only.
#   Bump IDENTITY_RESOLUTION_ENGINE_VERSION so stored decisions can be
#   identified as using the old algorithm.
