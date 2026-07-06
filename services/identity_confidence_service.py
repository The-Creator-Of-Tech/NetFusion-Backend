"""
Identity Confidence Engine
===========================
Phase A.2.2.2 — Evaluate only. No matching. No database. No persistence.

Receives ONE IdentitySignal (from identity_signal_service) and returns a
structured IdentityConfidence containing:
  - A confidence score per field
  - Which sources contributed to each field
  - Detected conflicts between sources
  - Warnings about data quality
  - An overall confidence score and level

Design principles
-----------------
- Deterministic: same signal → same output every time.
- No AI, no heuristics that depend on packet history.
- No randomness, no side effects, no database.
- All base confidence values come from core/constants.py — never hardcoded.
- Multi-source agreement raises confidence.
- Source conflicts reduce confidence and are surfaced explicitly.
- Reusable helpers are public functions, not private methods.

Confidence formula per field
-----------------------------
1.  Start with the base confidence of the highest-ranked source that
    provided this field's value.
2.  For each additional source that agrees on the SAME value, add
    CONFIDENCE_AGREEMENT_BONUS_PER_SOURCE (capped at
    CONFIDENCE_AGREEMENT_MAX_BONUS).
3.  For each conflicting value (different value, different source), subtract
    CONFIDENCE_CONFLICT_PENALTY.
4.  Clamp final result to [0, 100].

Overall confidence
------------------
Weighted average of all present field scores, weighted by field importance.
Absent fields (None) are excluded from the average.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.constants import (
    CONFIDENCE_AGREEMENT_BONUS_PER_SOURCE,
    CONFIDENCE_AGREEMENT_MAX_BONUS,
    CONFIDENCE_CONFLICT_PENALTY,
    CONFIDENCE_LEVEL_THRESHOLDS,
    IDENTITY_CONFIDENCE_ENGINE_VERSION,
    SOURCE_TYPE_CONFIDENCE,
)
from services.identity_signal_service import IdentitySignal, SignalEvidence


# ---------------------------------------------------------------------------
# ConfidenceLevel enum
# ---------------------------------------------------------------------------

class ConfidenceLevel(str, Enum):
    """
    Human-readable tier derived from an overall confidence score.
    Thresholds are defined in core/constants.CONFIDENCE_LEVEL_THRESHOLDS.
    """
    VERIFIED  = "VERIFIED"    # 100     — verified by authoritative source
    VERY_HIGH = "VERY_HIGH"   # 90–99   — multiple high-trust sources agree
    HIGH      = "HIGH"        # 75–89   — single high-trust source, no conflicts
    MEDIUM    = "MEDIUM"      # 55–74   — moderate-trust or minor conflicts
    LOW       = "LOW"         # 35–54   — low-trust source or conflicts present
    WEAK      = "WEAK"        # 15–34   — very low trust or many conflicts
    UNKNOWN   = "UNKNOWN"     # 0–14    — no usable signal


# ---------------------------------------------------------------------------
# FieldConfidence — confidence result for one identity field
# ---------------------------------------------------------------------------

class FieldConfidence(BaseModel):
    """
    Confidence evaluation for a single identity field (e.g. 'hostname').

    Attributes
    ----------
    fieldName       Name of the evaluated field.
    value           The value that was evaluated (highest-confidence value
                    if multiple candidates exist).
    score           Final confidence score 0–100.
    level           Human-readable tier.
    reason          Plain-English explanation of how the score was derived.
                    Intended for SOC analysts — shows which sources agreed
                    or conflicted, and what adjustments were applied.
                    Example (agreement): "DHCP + NBNS + mDNS agreed on 'alice-laptop'. Base 100, +10 agreement bonus."
                    Example (conflict):  "DHCP says 'alice-laptop', NBNS says 'evil-host'. Base 100, -20 conflict penalty."
    sources         All source type strings that contributed a value.
    agreementCount  Number of sources that agreed on `value`.
    conflictCount   Number of sources that provided a DIFFERENT value.
    bonusApplied    Agreement bonus that was added to the base score.
    penaltyApplied  Conflict penalty that was subtracted from the base score.
    """
    fieldName      : str
    value          : Optional[str]       = None
    score          : int                 = Field(ge=0, le=100)
    level          : ConfidenceLevel     = ConfidenceLevel.UNKNOWN
    reason         : str                 = ""
    sources        : List[str]           = Field(default_factory=list)
    agreementCount : int                 = 0
    conflictCount  : int                 = 0
    bonusApplied   : int                 = 0
    penaltyApplied : int                 = 0

    class Config:
        use_enum_values = True


# ---------------------------------------------------------------------------
# ConflictRecord — a detected disagreement between sources
# ---------------------------------------------------------------------------

class ConflictRecord(BaseModel):
    """
    Records a case where two or more sources provided different values
    for the same logical field.

    The engine does NOT resolve conflicts — it records them for the
    Asset Resolution Engine (future phase) to handle.
    """
    fieldName    : str
    values       : List[str]   # all distinct values seen
    sources      : List[str]   # corresponding source strings
    description  : str         # human-readable summary


# ---------------------------------------------------------------------------
# IdentityConfidence — the full evaluation result for one IdentitySignal
# ---------------------------------------------------------------------------

class IdentityConfidence(BaseModel):
    """
    Full confidence evaluation of one IdentitySignal.

    Produced by calculate_identity_confidence().
    Consumed by the Asset Resolution Engine (future phase).
    """

    # ── Overall score ─────────────────────────────────────────────────────
    overallConfidence : int            = Field(ge=0, le=100)
    overallLevel      : ConfidenceLevel = ConfidenceLevel.UNKNOWN

    # ── Per-field breakdown ───────────────────────────────────────────────
    # Key = field name (str), Value = FieldConfidence
    fieldConfidence   : Dict[str, FieldConfidence] = Field(default_factory=dict)

    # ── Source coverage ───────────────────────────────────────────────────
    # Key = field name, Value = list of source type strings that had a value
    fieldSources      : Dict[str, List[str]]       = Field(default_factory=dict)

    # ── Conflict and quality signals ──────────────────────────────────────
    conflicts  : List[ConflictRecord] = Field(default_factory=list)
    warnings   : List[str]           = Field(default_factory=list)

    # ── Extension bag ────────────────────────────────────────────────────
    metadata   : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        use_enum_values = True


# ---------------------------------------------------------------------------
# Field importance weights (used for overall confidence weighting)
# ---------------------------------------------------------------------------
# Higher weight = field contributes more to overall score.
# Fields not listed default to weight 1.
#
# Rationale:
#   MAC address is a hardware-level ground truth → highest weight.
#   IP is ephemeral but strongly correlated → high weight.
#   Hostname / deviceName are valuable identity signals → medium-high.
#   vendor / OS / SSID are supplementary → lower weight.

_FIELD_WEIGHTS: Dict[str, int] = {
    "macAddress"       : 10,
    "ipAddress"        : 8,
    "hostname"         : 7,
    "deviceName"       : 6,
    "dhcpHostname"     : 6,
    "nbnsName"         : 5,
    "nbnsNetbiosName"  : 5,
    "mdnsName"         : 5,
    "llmnrName"        : 4,
    "dnsPtr"           : 4,
    "httpHost"         : 4,
    "bootpHostname"    : 4,
    "vendor"           : 3,
    "operatingSystem"  : 3,
    "ssid"             : 3,
    "userAgent"        : 2,
    "destinationMac"   : 2,
    "destinationIp"    : 2,
    "sourceIp"         : 2,
    "sourceMac"        : 2,
}

# Fields that, when absent entirely, trigger a warning.
_REQUIRED_FIELDS = ("macAddress", "ipAddress")


# ---------------------------------------------------------------------------
# Public helper: confidence_level()
# ---------------------------------------------------------------------------

def confidence_level(score: int) -> ConfidenceLevel:
    """
    Convert a numeric confidence score (0–100) to a ConfidenceLevel tier.

    Thresholds are read from core/constants.CONFIDENCE_LEVEL_THRESHOLDS.

    Parameters
    ----------
    score : int
        Confidence score, clamped internally to [0, 100].

    Returns
    -------
    ConfidenceLevel
    """
    score = max(0, min(100, score))
    # Walk thresholds from highest to lowest; return first match.
    for level_name, threshold in sorted(
        CONFIDENCE_LEVEL_THRESHOLDS.items(), key=lambda kv: -kv[1]
    ):
        if score >= threshold:
            return ConfidenceLevel(level_name)
    return ConfidenceLevel.UNKNOWN


# ---------------------------------------------------------------------------
# Public helper: calculate_field_confidence()
# ---------------------------------------------------------------------------

def calculate_field_confidence(
    field_name: str,
    candidates: List[tuple],  # list of (value: str, source_type: str)
) -> FieldConfidence:
    """
    Calculate the confidence score for a single identity field given one or
    more (value, source_type) candidates.

    Parameters
    ----------
    field_name : str
        Logical field name (e.g. "hostname", "macAddress").
    candidates : list of (value, source_type) tuples
        Every observed value for this field across all evidence items.
        source_type must be a SourceType.value string.

    Returns
    -------
    FieldConfidence

    Algorithm
    ---------
    1.  Group candidates by value (case-insensitive).
    2.  For each distinct value find the highest base confidence among its
        sources → that is the base score for that value.
    3.  Choose the value whose base score is highest as the "winning" value.
    4.  Count agreeing sources (same value) → agreement bonus.
    5.  Count distinct conflicting values → conflict penalty.
    6.  Final score = base + bonus − penalty, clamped to [0, 100].
    """
    if not candidates:
        return FieldConfidence(
            fieldName=field_name,
            value=None,
            score=0,
            level=ConfidenceLevel.UNKNOWN,
            sources=[],
        )

    # Group by normalised value → {norm_value: [(orig_value, source), …]}
    groups: Dict[str, list] = {}
    for value, source in candidates:
        if not value:
            continue
        key = str(value).strip().lower()
        if key not in groups:
            groups[key] = []
        groups[key].append((str(value).strip(), str(source).strip().lower()))

    if not groups:
        return FieldConfidence(
            fieldName=field_name,
            value=None,
            score=0,
            level=ConfidenceLevel.UNKNOWN,
            sources=[],
        )

    # Find the winning value (highest base confidence for its best source)
    best_norm_key   : str = ""
    best_base_score : int = -1

    for norm_key, pairs in groups.items():
        group_base = max(
            SOURCE_TYPE_CONFIDENCE.get(src, 0)
            for _, src in pairs
        )
        if group_base > best_base_score:
            best_base_score = group_base
            best_norm_key   = norm_key

    winning_pairs   = groups[best_norm_key]
    winning_value   = winning_pairs[0][0]           # original-case value
    agreement_count = len(winning_pairs)             # sources that agree
    conflict_count  = len(groups) - 1               # number of distinct conflicting values

    # Agreement bonus: +N per additional confirming source (cap applies)
    bonus = min(
        (agreement_count - 1) * CONFIDENCE_AGREEMENT_BONUS_PER_SOURCE,
        CONFIDENCE_AGREEMENT_MAX_BONUS,
    )

    # Conflict penalty: subtract for each conflicting distinct value
    penalty = conflict_count * CONFIDENCE_CONFLICT_PENALTY

    final_score = max(0, min(100, best_base_score + bonus - penalty))

    all_sources = [src for pairs in groups.values() for _, src in pairs]

    # ── Build human-readable reason string ────────────────────────────────
    reason = _build_reason(
        winning_value   = winning_value,
        winning_sources = [src for _, src in winning_pairs],
        conflict_groups = {
            norm_key: pairs
            for norm_key, pairs in groups.items()
            if norm_key != best_norm_key
        },
        best_base_score = best_base_score,
        bonus           = bonus,
        penalty         = penalty,
        final_score     = final_score,
    )

    return FieldConfidence(
        fieldName=field_name,
        value=winning_value,
        score=final_score,
        level=confidence_level(final_score),
        reason=reason,
        sources=sorted(set(all_sources)),
        agreementCount=agreement_count,
        conflictCount=conflict_count,
        bonusApplied=bonus,
        penaltyApplied=penalty,
    )


# ---------------------------------------------------------------------------
# Internal helper: _build_reason()
# ---------------------------------------------------------------------------

def _build_reason(
    winning_value   : str,
    winning_sources : List[str],
    conflict_groups : Dict[str, list],   # norm_key → [(orig_value, source), …]
    best_base_score : int,
    bonus           : int,
    penalty         : int,
    final_score     : int,
) -> str:
    """
    Build a plain-English explanation of how a field's confidence score
    was derived.  Output is intentionally terse — one sentence — so it
    renders cleanly in a SOC analyst dashboard or log entry.

    Examples
    --------
    Single source, no conflict:
        "DHCP observed 'alice-laptop'. Base 100."

    Multi-source agreement:
        "DHCP + NBNS + mDNS agreed on 'alice-laptop'. Base 100, +10 agreement bonus."

    Conflict present:
        "DHCP says 'alice-laptop' (base 100). NBNS conflicts with 'evil-host'. -20 conflict penalty. Final 80."

    Mixed agreement + conflict:
        "DHCP + mDNS agreed on 'alice-laptop' (base 100, +5 bonus). NBNS conflicts with 'evil-host'. -20 penalty. Final 85."
    """
    # Format source list as "DHCP + NBNS + mDNS"
    def _fmt_sources(sources: List[str]) -> str:
        return " + ".join(s.upper() for s in sources) if sources else "unknown"

    agreeing_label = _fmt_sources(winning_sources)
    value_quoted   = f"'{winning_value}'"

    # Base clause
    if len(winning_sources) > 1:
        base_clause = f"{agreeing_label} agreed on {value_quoted}. Base {best_base_score}"
    else:
        base_clause = f"{agreeing_label} observed {value_quoted}. Base {best_base_score}"

    # Bonus clause
    bonus_clause = f", +{bonus} agreement bonus" if bonus > 0 else ""

    # Conflict clause(s) — list each conflicting value and its sources
    conflict_parts = []
    for norm_key, pairs in conflict_groups.items():
        conflict_value   = pairs[0][0]
        conflict_sources = _fmt_sources([src for _, src in pairs])
        conflict_parts.append(f"{conflict_sources} conflicts with '{conflict_value}'")

    if conflict_parts:
        conflict_clause = ". " + ". ".join(conflict_parts) + f". -{penalty} conflict penalty"
    else:
        conflict_clause = ""

    # Final score suffix — only add when adjustments were made
    if bonus > 0 or penalty > 0:
        final_clause = f". Final {final_score}."
    else:
        final_clause = "."

    return base_clause + bonus_clause + conflict_clause + final_clause


# ---------------------------------------------------------------------------
# Public helper: merge_source_confidence()
# ---------------------------------------------------------------------------

def merge_source_confidence(scores: List[int]) -> int:
    """
    Merge multiple per-source confidence scores into a single score.

    Uses the highest base score with diminishing bonus for each additional
    confirming source — the same formula as calculate_field_confidence but
    operating on raw ints rather than (value, source) tuples.

    Parameters
    ----------
    scores : list of int
        Individual source confidence scores.

    Returns
    -------
    int — merged score, clamped to [0, 100].
    """
    if not scores:
        return 0
    base  = max(scores)
    bonus = min(
        (len(scores) - 1) * CONFIDENCE_AGREEMENT_BONUS_PER_SOURCE,
        CONFIDENCE_AGREEMENT_MAX_BONUS,
    )
    return max(0, min(100, base + bonus))


# ---------------------------------------------------------------------------
# Public helper: detect_conflicts()
# ---------------------------------------------------------------------------

def detect_conflicts(
    field_name: str,
    candidates: List[tuple],  # (value, source_type)
) -> Optional[ConflictRecord]:
    """
    Detect whether multiple sources provide different values for a field.

    Parameters
    ----------
    field_name : str
    candidates : list of (value, source_type)

    Returns
    -------
    ConflictRecord if two or more distinct values are present, else None.
    """
    if not candidates:
        return None

    # Normalise and group
    value_to_sources: Dict[str, List[str]] = {}
    for value, source in candidates:
        if not value:
            continue
        norm = str(value).strip().lower()
        if norm not in value_to_sources:
            value_to_sources[norm] = []
        value_to_sources[norm].append(str(source))

    if len(value_to_sources) <= 1:
        return None  # no conflict

    # Multiple distinct values — build ConflictRecord
    all_values  = [pairs[0] for pairs in candidates if pairs[0]]
    all_sources = [pairs[1] for pairs in candidates if pairs[0]]
    distinct_values = list(
        dict.fromkeys(str(v).strip() for v, _ in candidates if v)
    )

    return ConflictRecord(
        fieldName=field_name,
        values=distinct_values,
        sources=all_sources,
        description=(
            f"Field '{field_name}' has {len(value_to_sources)} conflicting "
            f"values from {len(all_sources)} source(s): "
            + ", ".join(
                f"'{v}'" for v in distinct_values
            )
        ),
    )


# ---------------------------------------------------------------------------
# Internal: build candidate list from IdentitySignal for one field
# ---------------------------------------------------------------------------

def _candidates_for_field(
    signal: IdentitySignal,
    field_name: str,
) -> List[tuple]:
    """
    Collect all (value, source_type) pairs for `field_name` from the signal's
    confidenceHints evidence list.
    """
    return [
        (ev.fieldValue, ev.source if isinstance(ev.source, str) else ev.source.value)
        for ev in signal.confidenceHints
        if ev.fieldName == field_name and ev.fieldValue
    ]


# ---------------------------------------------------------------------------
# Internal: direct field value extraction from IdentitySignal scalar fields
# ---------------------------------------------------------------------------

# Maps each IdentitySignal attribute name → the SOURCE_TYPE_CONFIDENCE key to
# use when the value is present but has no evidence entry (e.g. pre-resolved).
# Keys MUST exist in SOURCE_TYPE_CONFIDENCE (core/constants.py).
_DIRECT_FIELD_SOURCE_MAP: Dict[str, str] = {
    "macAddress"       : "pcap",    # MAC observed directly in Ethernet frame
    "sourceMac"        : "pcap",
    "destinationMac"   : "pcap",
    "ipAddress"        : "pcap",
    "sourceIp"         : "pcap",
    "destinationIp"    : "pcap",
    "hostname"         : "dhcp",   # pre-resolved by identity_engine (highest-priority source)
    "deviceName"       : "dhcp",   # pre-resolved by identity_engine
    "dhcpHostname"     : "dhcp",
    "bootpHostname"    : "dhcp",
    "httpHost"         : "pcap",   # http.host — observed in pcap
    "mdnsName"         : "mdns",
    "nbnsName"         : "nbns",
    "nbnsNetbiosName"  : "nbns",
    "llmnrName"        : "llmnr",
    "dnsPtr"           : "dns",
    "vendor"           : "pcap",
    "operatingSystem"  : "nmap",
    "userAgent"        : "pcap",   # future HTTP-layer; fallback to pcap
    "ssid"             : "pcap",
}

# All scalar fields we evaluate (excludes list fields like hostnames/dnsNames)
_EVALUATED_FIELDS: List[str] = list(_DIRECT_FIELD_SOURCE_MAP.keys())


def _build_candidates(signal: IdentitySignal, field_name: str) -> List[tuple]:
    """
    Build the full (value, source) candidate list for a field by combining:
    1.  Values from signal.confidenceHints (evidence trail).
    2.  The direct scalar field value from the signal itself (if present and
        not already covered by evidence).

    Special case — 'hostname' and 'deviceName':
        These are resolved aggregates of all name-signal fields. To enable
        cross-source conflict detection (e.g. DHCP says "alice" but NBNS
        says "evil-host"), we include evidence from ALL hostname-contributing
        fields, not just entries labelled "hostname".
    """
    # Fields whose evidence all contributes to the unified hostname concept
    _HOSTNAME_EVIDENCE_FIELDS = {
        "dhcpHostname", "bootpHostname", "nbnsName", "nbnsNetbiosName",
        "mdnsName", "llmnrName", "dnsPtr", "httpHost",
    }

    if field_name in ("hostname", "deviceName"):
        # Gather candidates from every hostname-contributing evidence field
        candidates: List[tuple] = []
        seen_norm: set = set()
        for ev in signal.confidenceHints:
            if ev.fieldName in _HOSTNAME_EVIDENCE_FIELDS and ev.fieldValue:
                candidates.append((
                    ev.fieldValue,
                    ev.source if isinstance(ev.source, str) else ev.source.value,
                ))
        # Also include the pre-resolved hostname/deviceName direct value
        direct_value = getattr(signal, field_name, None)
        if direct_value and isinstance(direct_value, str):
            direct_norm = direct_value.strip().lower()
            already = any(str(v).strip().lower() == direct_norm for v, _ in candidates)
            if not already:
                candidates.append((direct_value.strip(), _DIRECT_FIELD_SOURCE_MAP.get(field_name, "pcap")))
        return candidates

    # Standard case: gather evidence entries labelled with this field name
    candidates = _candidates_for_field(signal, field_name)

    # Add direct scalar value if not already represented
    direct_value = getattr(signal, field_name, None)
    if direct_value and isinstance(direct_value, str):
        direct_norm = direct_value.strip().lower()
        already_present = any(
            str(v).strip().lower() == direct_norm
            for v, _ in candidates
        )
        if not already_present:
            source_key = _DIRECT_FIELD_SOURCE_MAP.get(field_name, "pcap")
            candidates.append((direct_value.strip(), source_key))

    return candidates


# ---------------------------------------------------------------------------
# Core public function: calculate_identity_confidence()
# ---------------------------------------------------------------------------

def calculate_identity_confidence(signal: IdentitySignal) -> IdentityConfidence:
    """
    Evaluate the reliability of every identity field in one IdentitySignal.

    Parameters
    ----------
    signal : IdentitySignal
        Produced by identity_signal_service.extract_identity_signals().

    Returns
    -------
    IdentityConfidence
        Per-field scores, overall score and level, conflicts, warnings.

    Notes
    -----
    - No AI. No randomness. No history. No database.
    - Confidence values come exclusively from core/constants.py.
    - Conflicts are recorded but NOT resolved.
    """

    field_confidence_map : Dict[str, FieldConfidence] = {}
    field_sources_map    : Dict[str, List[str]]        = {}
    conflicts            : List[ConflictRecord]         = []
    warnings             : List[str]                   = []

    # ── Evaluate each scalar identity field ───────────────────────────────
    for field_name in _EVALUATED_FIELDS:
        candidates = _build_candidates(signal, field_name)
        if not candidates:
            continue

        # Field confidence
        fc = calculate_field_confidence(field_name, candidates)
        field_confidence_map[field_name] = fc
        field_sources_map[field_name]    = fc.sources

        # Conflict detection
        conflict = detect_conflicts(field_name, candidates)
        if conflict:
            conflicts.append(conflict)

    # ── Warnings ──────────────────────────────────────────────────────────
    for req_field in _REQUIRED_FIELDS:
        if req_field not in field_confidence_map:
            warnings.append(
                f"Required field '{req_field}' has no observed value. "
                "Asset identity cannot be fully established."
            )

    if not field_confidence_map:
        warnings.append(
            "No identity fields could be evaluated. Signal contains no usable data."
        )

    if len(conflicts) > 0:
        warnings.append(
            f"{len(conflicts)} field conflict(s) detected. "
            "Confidence has been reduced. Manual review recommended."
        )

    # ── Overall confidence (weighted average of present field scores) ──────
    overall = _calculate_overall_confidence(field_confidence_map)

    return IdentityConfidence(
        overallConfidence=overall,
        overallLevel=confidence_level(overall),
        fieldConfidence=field_confidence_map,
        fieldSources=field_sources_map,
        conflicts=conflicts,
        warnings=warnings,
        metadata={
            "engineVersion"   : IDENTITY_CONFIDENCE_ENGINE_VERSION,
            "evaluatedFields" : len(field_confidence_map),
            "conflictCount"   : len(conflicts),
            "warningCount"    : len(warnings),
            "signalSource"    : signal.sourceType
                                if isinstance(signal.sourceType, str)
                                else signal.sourceType.value,
        },
    )


# ---------------------------------------------------------------------------
# Internal: weighted overall confidence
# ---------------------------------------------------------------------------

def _calculate_overall_confidence(
    field_map: Dict[str, FieldConfidence],
) -> int:
    """
    Compute a weighted average confidence score across all evaluated fields.

    Fields with no value are excluded.  Field importance weights come from
    _FIELD_WEIGHTS (default weight = 1 for unlisted fields).

    Returns
    -------
    int — overall score 0–100.
    """
    if not field_map:
        return 0

    total_weight : int = 0
    weighted_sum : int = 0

    for field_name, fc in field_map.items():
        if fc.value is None:
            continue
        weight        = _FIELD_WEIGHTS.get(field_name, 1)
        weighted_sum += fc.score * weight
        total_weight += weight

    if total_weight == 0:
        return 0

    raw = weighted_sum / total_weight
    return max(0, min(100, round(raw)))
