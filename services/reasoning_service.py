"""
Reasoning Engine
================
Phase A4.1.1 — Deterministic, immutable reasoning object assembly.

Responsibilities
----------------
- Build deterministic ReasoningResult objects from forensic engine outputs.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute reasoningFingerprint from all trace fingerprints + evidence IDs.
- Carry structured DecisionExplanation and ReasoningTrace on every result.
- Expose builder functions: build_reasoning, build_reasoning_trace,
  build_reasoning_evidence, build_decision_explanation, build_reasoning_metadata.
- Expose utility functions: sort, filter, group, find, statistics.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No database, no repository, no API, no HTTP, no AI, no LLM, no randomness.
- No uuid4(). No random module.
- Canonical sorting before every hash and every statistic accumulation.
- Pure business logic only.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import REASONING_ENGINE_VERSION

# ── UUIDv5 namespace — fixed; changing it invalidates all stored IDs ────────
_REASONING_NS = uuid.UUID("6ba7b815-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class ReasoningStage(str, Enum):
    OBSERVATION            = "OBSERVATION"
    EVIDENCE_CORRELATION   = "EVIDENCE_CORRELATION"
    RELATIONSHIP_ANALYSIS  = "RELATIONSHIP_ANALYSIS"
    TIMELINE_ANALYSIS      = "TIMELINE_ANALYSIS"
    ATTACK_GRAPH_ANALYSIS  = "ATTACK_GRAPH_ANALYSIS"
    FINDING_CORRELATION    = "FINDING_CORRELATION"
    ALERT_CORRELATION      = "ALERT_CORRELATION"
    RISK_ASSESSMENT        = "RISK_ASSESSMENT"
    CONCLUSION             = "CONCLUSION"


# ===========================================================================
# Immutable models (frozen=True dataclasses)
# ===========================================================================

@dataclass(frozen=True)
class ReasoningEvidence:
    """
    One piece of supporting evidence used within a reasoning step.

    Fields
    ------
    evidenceId  : ID of the linked EvidenceRecord.
    weight      : 0–100 importance weight of this evidence in the step.
    reason      : deterministic rationale for including this evidence.
    sourceType  : source domain (e.g. "pcap", "dhcp", "nmap").
    confidence  : 0–100 confidence in this evidence value.
    """
    evidenceId : str
    weight     : float   # 0–100
    reason     : str
    sourceType : str
    confidence : float   # 0–100


@dataclass(frozen=True)
class ReasoningTrace:
    """
    One immutable step in the reasoning chain.

    Fields
    ------
    stepNumber        : 1-based monotonic position in the trace.
    stage             : ReasoningStage — which analysis phase produced this step.
    inputSummary      : what was fed into this step.
    outputSummary     : what conclusion/output this step produced.
    confidence        : 0–100 confidence in this step's output.
    evidenceIds       : sorted tuple of evidence IDs used.
    findingIds        : sorted tuple of finding IDs referenced.
    alertIds          : sorted tuple of alert IDs referenced.
    relationshipIds   : sorted tuple of relationship IDs referenced.
    timelineEventIds  : sorted tuple of timeline event IDs referenced.
    """
    stepNumber       : int
    stage            : ReasoningStage
    inputSummary     : str
    outputSummary    : str
    confidence       : float            # 0–100
    evidenceIds      : Tuple[str, ...]
    findingIds       : Tuple[str, ...]
    alertIds         : Tuple[str, ...]
    relationshipIds  : Tuple[str, ...]
    timelineEventIds : Tuple[str, ...]


@dataclass(frozen=True)
class DecisionExplanation:
    """
    Structured, human-readable explanation of the final reasoning decision.

    Fields
    ------
    summary              : one-paragraph summary of the decision.
    strengths            : sorted tuple of factors supporting the decision.
    weaknesses           : sorted tuple of factors undermining the decision.
    assumptions          : sorted tuple of assumptions made during reasoning.
    confidenceExplanation: narrative explaining the overall confidence score.
    recommendedNextSteps : sorted tuple of recommended follow-up actions.
    """
    summary               : str
    strengths             : Tuple[str, ...]
    weaknesses            : Tuple[str, ...]
    assumptions           : Tuple[str, ...]
    confidenceExplanation : str
    recommendedNextSteps  : Tuple[str, ...]


@dataclass(frozen=True)
class ReasoningMetadata:
    """
    Provenance and performance metadata for one reasoning run.

    Fields
    ------
    processingTimeMs  : wall-clock time to build the result (ms).
    reasoningDepth    : number of trace steps executed.
    contextCount      : number of context items consumed.
    findingCount      : number of findings analysed.
    alertCount        : number of alerts analysed.
    relationshipCount : number of relationships analysed.
    timelineCount     : number of timeline events analysed.
    evidenceCount     : number of evidence records analysed.
    modelsUsed        : sorted tuple of engine/model identifiers used.
    """
    processingTimeMs  : int
    reasoningDepth    : int
    contextCount      : int
    findingCount      : int
    alertCount        : int
    relationshipCount : int
    timelineCount     : int
    evidenceCount     : int
    modelsUsed        : Tuple[str, ...]


@dataclass(frozen=True)
class ReasoningResult:
    """
    The complete, immutable reasoning result for one analysis scope.

    Identity
    --------
    reasoningId         : UUIDv5(REASONING_NS, reasoningKey) — deterministic.
    reasoningKey        : SHA256(sorted contextIds + sorted findingIds +
                          sorted alertIds + sorted relationshipIds +
                          sorted timelineIds)[:32]
    reasoningFingerprint: SHA256(reasoningKey + all trace fingerprints +
                          all evidenceIds sorted)[:32]

    Sections
    --------
    reasoningTrace      : sorted tuple of ReasoningTrace steps.
    supportingEvidence  : sorted tuple of ReasoningEvidence items.
    decisionExplanation : DecisionExplanation — structured rationale.
    metadata            : ReasoningMetadata — provenance + timings.

    Scoring
    -------
    overallConfidence   : 0–100 aggregate confidence across all stages.
    overallRisk         : 0–100 aggregate risk score.

    Decision
    --------
    decision            : the final human-readable decision string.

    Versioning
    ----------
    engineVersion : REASONING_ENGINE_VERSION — pinned at build time.
    createdAt     : ISO-8601 string (caller-supplied for determinism).
    """
    # ── Identity ─────────────────────────────────────────────────────────
    reasoningId          : str
    reasoningKey         : str
    reasoningFingerprint : str

    # ── Scoring ──────────────────────────────────────────────────────────
    overallConfidence : float   # 0–100
    overallRisk       : float   # 0–100

    # ── Decision ─────────────────────────────────────────────────────────
    decision : str

    # ── Trace & evidence (sorted tuples for immutability + determinism) ──
    reasoningTrace    : Tuple[ReasoningTrace, ...]
    supportingEvidence: Tuple[ReasoningEvidence, ...]

    # ── Explanation & metadata ───────────────────────────────────────────
    decisionExplanation : DecisionExplanation
    metadata            : ReasoningMetadata

    # ── Versioning ───────────────────────────────────────────────────────
    engineVersion : str
    createdAt     : str     # ISO-8601 (caller-supplied)


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_reasoning_key(
    context_ids      : List[str],
    finding_ids      : List[str],
    alert_ids        : List[str],
    relationship_ids : List[str],
    timeline_ids     : List[str],
) -> str:
    """
    reasoningKey = SHA256(
        sorted(contextIds) + sorted(findingIds) + sorted(alertIds) +
        sorted(relationshipIds) + sorted(timelineIds)
    )[:32]

    All ID collections are sorted before hashing — insertion order has no
    effect on the result.  Components are null-byte-separated; IDs within
    each group are separated by \\x01 to prevent cross-field collisions.
    Returns 32 hex characters.
    """
    parts = [
        "\x01".join(sorted(context_ids)),
        "\x01".join(sorted(finding_ids)),
        "\x01".join(sorted(alert_ids)),
        "\x01".join(sorted(relationship_ids)),
        "\x01".join(sorted(timeline_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_reasoning_id(reasoning_key: str) -> str:
    """reasoningId = UUIDv5(REASONING_NS, reasoningKey)."""
    return str(uuid.uuid5(_REASONING_NS, reasoning_key))


def _compute_trace_fingerprint(trace: ReasoningTrace) -> str:
    """
    Deterministic 32-char fingerprint for one ReasoningTrace step.

    SHA256(stepNumber | stage | confidence | sorted evidenceIds |
           sorted findingIds | sorted alertIds | sorted relationshipIds |
           sorted timelineEventIds)[:32]
    """
    parts = [
        str(trace.stepNumber),
        trace.stage.value,
        str(round(trace.confidence, 6)),
        "\x01".join(sorted(trace.evidenceIds)),
        "\x01".join(sorted(trace.findingIds)),
        "\x01".join(sorted(trace.alertIds)),
        "\x01".join(sorted(trace.relationshipIds)),
        "\x01".join(sorted(trace.timelineEventIds)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_reasoning_fingerprint(
    reasoning_key  : str,
    traces         : Tuple[ReasoningTrace, ...],
    evidence_ids   : List[str],
) -> str:
    """
    reasoningFingerprint = SHA256(
        reasoningKey +
        all trace fingerprints (in stepNumber order) +
        all evidenceIds sorted
    )[:32]

    Traces are ordered by stepNumber before fingerprinting.
    Evidence IDs are sorted before fingerprinting.
    Returns 32 hex characters.
    """
    # Sort traces by stepNumber for determinism
    ordered_traces = sorted(traces, key=lambda t: t.stepNumber)
    trace_fps = [_compute_trace_fingerprint(t) for t in ordered_traces]

    parts = [
        reasoning_key,
        "\x01".join(trace_fps),
        "\x01".join(sorted(evidence_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp(v: float) -> float:
    """Clamp a score to [0.0, 100.0]."""
    return float(max(0.0, min(100.0, v)))


def _norm_ids(ids: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort an ID list."""
    if not ids:
        return ()
    return tuple(sorted({i.strip() for i in ids if i and i.strip()}))


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


# ===========================================================================
# Builder: build_reasoning_evidence()
# ===========================================================================

def build_reasoning_evidence(
    evidence_id : str,
    weight      : float,
    reason      : str,
    source_type : str,
    confidence  : float,
) -> ReasoningEvidence:
    """
    Build a single ReasoningEvidence item.

    Parameters
    ----------
    evidence_id : ID of the linked EvidenceRecord.
    weight      : 0–100 importance weight (clamped).
    reason      : deterministic rationale for including this evidence.
    source_type : source domain (e.g. "pcap", "dhcp", "nmap").
    confidence  : 0–100 confidence (clamped).

    Returns
    -------
    ReasoningEvidence (frozen)
    """
    return ReasoningEvidence(
        evidenceId = evidence_id.strip(),
        weight     = _clamp(weight),
        reason     = reason,
        sourceType = source_type.strip().lower() if source_type else "unknown",
        confidence = _clamp(confidence),
    )


# ===========================================================================
# Builder: build_reasoning_trace()
# ===========================================================================

def build_reasoning_trace(
    step_number       : int,
    stage             : ReasoningStage,
    input_summary     : str,
    output_summary    : str,
    confidence        : float,
    evidence_ids      : Optional[List[str]] = None,
    finding_ids       : Optional[List[str]] = None,
    alert_ids         : Optional[List[str]] = None,
    relationship_ids  : Optional[List[str]] = None,
    timeline_event_ids: Optional[List[str]] = None,
) -> ReasoningTrace:
    """
    Build a single ReasoningTrace step.

    All ID collections are deduplicated and sorted.

    Parameters
    ----------
    step_number        : 1-based position in the trace chain.
    stage              : ReasoningStage for this step.
    input_summary      : what was fed into this step.
    output_summary     : what this step concluded / produced.
    confidence         : 0–100 confidence in this step's output (clamped).
    evidence_ids       : EvidenceRecord IDs used (deduped + sorted).
    finding_ids        : Finding IDs referenced (deduped + sorted).
    alert_ids          : Alert IDs referenced (deduped + sorted).
    relationship_ids   : Relationship IDs referenced (deduped + sorted).
    timeline_event_ids : Timeline event IDs referenced (deduped + sorted).

    Returns
    -------
    ReasoningTrace (frozen)
    """
    return ReasoningTrace(
        stepNumber       = step_number,
        stage            = stage,
        inputSummary     = input_summary,
        outputSummary    = output_summary,
        confidence       = _clamp(confidence),
        evidenceIds      = _norm_ids(evidence_ids),
        findingIds       = _norm_ids(finding_ids),
        alertIds         = _norm_ids(alert_ids),
        relationshipIds  = _norm_ids(relationship_ids),
        timelineEventIds = _norm_ids(timeline_event_ids),
    )


# ===========================================================================
# Builder: build_decision_explanation()
# ===========================================================================

def build_decision_explanation(
    summary               : str,
    strengths             : Optional[List[str]] = None,
    weaknesses            : Optional[List[str]] = None,
    assumptions           : Optional[List[str]] = None,
    confidence_explanation: str                 = "",
    recommended_next_steps: Optional[List[str]] = None,
) -> DecisionExplanation:
    """
    Build a DecisionExplanation.

    All list fields are deduplicated and sorted for determinism.

    Parameters
    ----------
    summary                : one-paragraph explanation of the final decision.
    strengths              : factors supporting the decision.
    weaknesses             : factors undermining the decision.
    assumptions            : assumptions made during reasoning.
    confidence_explanation : narrative explaining the confidence score.
    recommended_next_steps : follow-up actions.

    Returns
    -------
    DecisionExplanation (frozen)
    """
    return DecisionExplanation(
        summary               = summary,
        strengths             = _norm_strings(strengths),
        weaknesses            = _norm_strings(weaknesses),
        assumptions           = _norm_strings(assumptions),
        confidenceExplanation = confidence_explanation,
        recommendedNextSteps  = _norm_strings(recommended_next_steps),
    )


# ===========================================================================
# Builder: build_reasoning_metadata()
# ===========================================================================

def build_reasoning_metadata(
    processing_time_ms  : int,
    reasoning_depth     : int,
    context_count       : int,
    finding_count       : int,
    alert_count         : int,
    relationship_count  : int,
    timeline_count      : int,
    evidence_count      : int,
    models_used         : Optional[List[str]] = None,
) -> ReasoningMetadata:
    """
    Build ReasoningMetadata.

    modelsUsed is deduplicated and sorted for determinism.

    Parameters
    ----------
    processing_time_ms  : wall-clock ms to build the result.
    reasoning_depth     : number of trace steps executed.
    context_count       : number of context items consumed.
    finding_count       : number of findings analysed.
    alert_count         : number of alerts analysed.
    relationship_count  : number of relationships analysed.
    timeline_count      : number of timeline events analysed.
    evidence_count      : number of evidence records analysed.
    models_used         : engine/model identifiers (deduped + sorted).

    Returns
    -------
    ReasoningMetadata (frozen)
    """
    return ReasoningMetadata(
        processingTimeMs  = max(0, int(processing_time_ms)),
        reasoningDepth    = max(0, int(reasoning_depth)),
        contextCount      = max(0, int(context_count)),
        findingCount      = max(0, int(finding_count)),
        alertCount        = max(0, int(alert_count)),
        relationshipCount = max(0, int(relationship_count)),
        timelineCount     = max(0, int(timeline_count)),
        evidenceCount     = max(0, int(evidence_count)),
        modelsUsed        = _norm_strings(models_used),
    )


# ===========================================================================
# Primary builder: build_reasoning()
# ===========================================================================

def build_reasoning(
    context_ids       : List[str],
    finding_ids       : List[str],
    alert_ids         : List[str],
    relationship_ids  : List[str],
    timeline_ids      : List[str],
    created_at        : str,
    reasoning_trace   : Optional[List[ReasoningTrace]]    = None,
    supporting_evidence: Optional[List[ReasoningEvidence]] = None,
    decision          : str                               = "",
    overall_confidence: float                             = 0.0,
    overall_risk      : float                             = 0.0,
    explanation       : Optional[DecisionExplanation]     = None,
    metadata          : Optional[ReasoningMetadata]       = None,
) -> ReasoningResult:
    """
    Build a complete, immutable ReasoningResult.

    Parameters
    ----------
    context_ids         : context item IDs consumed (deduped + sorted for key).
    finding_ids         : finding IDs analysed (deduped + sorted for key).
    alert_ids           : alert IDs analysed (deduped + sorted for key).
    relationship_ids    : relationship IDs analysed (deduped + sorted for key).
    timeline_ids        : timeline event IDs analysed (deduped + sorted for key).
    created_at          : ISO-8601 creation timestamp (caller-supplied).
    reasoning_trace     : ordered list of ReasoningTrace steps (sorted by stepNumber).
    supporting_evidence : list of ReasoningEvidence items (sorted by weight DESC then evidenceId).
    decision            : final human-readable decision string.
    overall_confidence  : 0–100 aggregate confidence (clamped).
    overall_risk        : 0–100 aggregate risk score (clamped).
    explanation         : DecisionExplanation; empty default if None.
    metadata            : ReasoningMetadata; empty default if None.

    Returns
    -------
    ReasoningResult (frozen)

    Determinism guarantees
    ----------------------
    - All ID lists sorted before hashing.
    - Trace tuple sorted by stepNumber.
    - Evidence tuple sorted by weight DESC, then evidenceId ASC.
    - reasoningKey, reasoningId, reasoningFingerprint are all deterministic.
    - Same inputs always produce structurally identical output.
    """
    # Normalise raw ID lists — dedup + sort for key computation
    norm_ctx   = sorted({i.strip() for i in context_ids      if i and i.strip()})
    norm_find  = sorted({i.strip() for i in finding_ids      if i and i.strip()})
    norm_alert = sorted({i.strip() for i in alert_ids        if i and i.strip()})
    norm_rel   = sorted({i.strip() for i in relationship_ids if i and i.strip()})
    norm_tl    = sorted({i.strip() for i in timeline_ids     if i and i.strip()})

    # Deterministic key
    key = _compute_reasoning_key(norm_ctx, norm_find, norm_alert, norm_rel, norm_tl)

    # Deterministic ID
    rid = _compute_reasoning_id(key)

    # Sort trace by stepNumber for canonical ordering
    sorted_trace: Tuple[ReasoningTrace, ...] = tuple(
        sorted(reasoning_trace or [], key=lambda t: t.stepNumber)
    )

    # Sort evidence by weight DESC, then evidenceId ASC for determinism
    sorted_evidence: Tuple[ReasoningEvidence, ...] = tuple(
        sorted(
            supporting_evidence or [],
            key=lambda e: (-e.weight, e.evidenceId),
        )
    )

    # Collect all evidence IDs across trace + supporting_evidence for fingerprint
    all_ev_ids: List[str] = []
    for t in sorted_trace:
        all_ev_ids.extend(t.evidenceIds)
    for e in sorted_evidence:
        all_ev_ids.append(e.evidenceId)

    # Deterministic fingerprint
    fingerprint = _compute_reasoning_fingerprint(key, sorted_trace, all_ev_ids)

    # Defaults for optional composite fields
    if explanation is None:
        explanation = build_decision_explanation(summary="No explanation provided.")
    if metadata is None:
        metadata = build_reasoning_metadata(
            processing_time_ms  = 0,
            reasoning_depth     = len(sorted_trace),
            context_count       = len(norm_ctx),
            finding_count       = len(norm_find),
            alert_count         = len(norm_alert),
            relationship_count  = len(norm_rel),
            timeline_count      = len(norm_tl),
            evidence_count      = len(set(all_ev_ids)),
        )

    return ReasoningResult(
        reasoningId          = rid,
        reasoningKey         = key,
        reasoningFingerprint = fingerprint,
        overallConfidence    = _clamp(overall_confidence),
        overallRisk          = _clamp(overall_risk),
        decision             = decision,
        reasoningTrace       = sorted_trace,
        supportingEvidence   = sorted_evidence,
        decisionExplanation  = explanation,
        metadata             = metadata,
        engineVersion        = REASONING_ENGINE_VERSION,
        createdAt            = created_at,
    )


# ===========================================================================
# Utility: sort_reasoning_trace()
# ===========================================================================

def sort_reasoning_trace(
    traces    : List[ReasoningTrace],
    ascending : bool = True,
) -> List[ReasoningTrace]:
    """
    Sort trace steps by stepNumber.

    Parameters
    ----------
    traces    : list of ReasoningTrace objects.
    ascending : True = step 1 first (default); False = last step first.

    Tie-breaking: by stage.value ASC then confidence DESC for full determinism.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        traces,
        key=lambda t: (t.stepNumber, t.stage.value, -t.confidence),
        reverse=not ascending,
    )


# ===========================================================================
# Utility: sort_reasoning_evidence()
# ===========================================================================

def sort_reasoning_evidence(
    evidence  : List[ReasoningEvidence],
    by        : str  = "weight",
    ascending : bool = False,
) -> List[ReasoningEvidence]:
    """
    Sort supporting evidence.

    Parameters
    ----------
    evidence  : list of ReasoningEvidence objects.
    by        : "weight" (default) | "confidence" | "evidenceId" | "sourceType"
    ascending : False = highest weight/confidence first (default).

    Tie-breaking: evidenceId ASC for full determinism.

    Raises ValueError for unknown sort keys.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    _VALID = {"weight", "confidence", "evidenceId", "sourceType"}
    if by not in _VALID:
        raise ValueError(
            f"sort_reasoning_evidence: unknown key '{by}'. Valid: {sorted(_VALID)}"
        )

    def _key(e: ReasoningEvidence) -> tuple:
        if by == "weight":
            primary = e.weight
        elif by == "confidence":
            primary = e.confidence
        elif by == "sourceType":
            primary = e.sourceType
        else:
            primary = e.evidenceId
        return (primary, e.evidenceId)

    return sorted(evidence, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_reasoning_trace()
# ===========================================================================

def filter_reasoning_trace(
    traces          : List[ReasoningTrace],
    stage           : Optional[ReasoningStage] = None,
    min_confidence  : Optional[float]          = None,
    max_confidence  : Optional[float]          = None,
    has_finding_ids : Optional[bool]           = None,
    has_alert_ids   : Optional[bool]           = None,
    has_evidence_ids: Optional[bool]           = None,
) -> List[ReasoningTrace]:
    """
    Filter trace steps by one or more criteria (all ANDed together).

    Parameters
    ----------
    stage           : keep only steps with this ReasoningStage.
    min_confidence  : keep steps with confidence >= min_confidence.
    max_confidence  : keep steps with confidence <= max_confidence.
    has_finding_ids : True = keep steps that reference findings;
                      False = keep steps with no finding references.
    has_alert_ids   : True/False same logic for alerts.
    has_evidence_ids: True/False same logic for evidence.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[ReasoningTrace] = []
    for t in traces:
        if stage           is not None and t.stage != stage:
            continue
        if min_confidence  is not None and t.confidence < min_confidence:
            continue
        if max_confidence  is not None and t.confidence > max_confidence:
            continue
        if has_finding_ids is not None:
            if has_finding_ids and not t.findingIds:
                continue
            if not has_finding_ids and t.findingIds:
                continue
        if has_alert_ids   is not None:
            if has_alert_ids and not t.alertIds:
                continue
            if not has_alert_ids and t.alertIds:
                continue
        if has_evidence_ids is not None:
            if has_evidence_ids and not t.evidenceIds:
                continue
            if not has_evidence_ids and t.evidenceIds:
                continue
        result.append(t)
    return result


# ===========================================================================
# Utility: group_reasoning_trace()
# ===========================================================================

def group_reasoning_trace(
    traces   : List[ReasoningTrace],
    group_by : str = "stage",
) -> Dict[str, List[ReasoningTrace]]:
    """
    Group trace steps by a string attribute.

    Parameters
    ----------
    traces   : list of ReasoningTrace objects.
    group_by : "stage" (default) | any other ReasoningTrace field name.
               Enum values are unwrapped to their .value string.
               Unknown attribute values fall back to key "unknown".

    Each group is sorted chronologically by stepNumber ASC.

    Returns
    -------
    Dict[str, List[ReasoningTrace]] — each group sorted by stepNumber ASC.
    """
    groups: Dict[str, List[ReasoningTrace]] = {}
    for t in traces:
        raw = getattr(t, group_by, None)
        key = raw.value if isinstance(raw, ReasoningStage) else (
            str(raw) if raw is not None else "unknown"
        )
        groups.setdefault(key, []).append(t)

    return {k: sort_reasoning_trace(v) for k, v in groups.items()}


# ===========================================================================
# Utility: calculate_reasoning_statistics()
# ===========================================================================

@dataclass(frozen=True)
class ReasoningStatistics:
    """
    Aggregate statistics over a list of ReasoningResult objects.

    Fields
    ------
    totalResults       : total count of results analysed.
    averageConfidence  : mean overallConfidence (0.0 when empty).
    averageRisk        : mean overallRisk (0.0 when empty).
    tracesByStage      : { ReasoningStage.value → total step count }
    maxDepth           : maximum reasoningDepth across all results.
    minDepth           : minimum reasoningDepth across all results (0 when empty).
    totalEvidenceItems : total supporting evidence items across all results.
    uniqueDecisions    : sorted tuple of distinct decision strings.
    """
    totalResults       : int
    averageConfidence  : float
    averageRisk        : float
    tracesByStage      : Dict[str, int]
    maxDepth           : int
    minDepth           : int
    totalEvidenceItems : int
    uniqueDecisions    : Tuple[str, ...]


def calculate_reasoning_statistics(
    results: List[ReasoningResult],
) -> ReasoningStatistics:
    """
    Compute ReasoningStatistics over a list of ReasoningResults.

    Deterministic: applies canonical sort (by reasoningId ASC) before any
    numeric accumulation so floating-point sums are identical across runs.

    Parameters
    ----------
    results : any list of ReasoningResult objects.

    Returns
    -------
    ReasoningStatistics (frozen)
    """
    if not results:
        return ReasoningStatistics(
            totalResults       = 0,
            averageConfidence  = 0.0,
            averageRisk        = 0.0,
            tracesByStage      = {},
            maxDepth           = 0,
            minDepth           = 0,
            totalEvidenceItems = 0,
            uniqueDecisions    = (),
        )

    # Canonical order for accumulation — deduplicates any non-determinism
    ordered = sorted(results, key=lambda r: r.reasoningId)

    conf_sum   = sum(r.overallConfidence for r in ordered)
    risk_sum   = sum(r.overallRisk       for r in ordered)
    n          = len(ordered)

    traces_by_stage: Dict[str, int] = {}
    depths: List[int] = []
    ev_total = 0
    decisions: set = set()

    for r in ordered:
        depths.append(r.metadata.reasoningDepth)
        ev_total += len(r.supportingEvidence)
        if r.decision:
            decisions.add(r.decision)
        for t in r.reasoningTrace:
            stage_key = t.stage.value
            traces_by_stage[stage_key] = traces_by_stage.get(stage_key, 0) + 1

    return ReasoningStatistics(
        totalResults       = n,
        averageConfidence  = round(conf_sum / n, 4),
        averageRisk        = round(risk_sum  / n, 4),
        tracesByStage      = dict(sorted(traces_by_stage.items())),
        maxDepth           = max(depths) if depths else 0,
        minDepth           = min(depths) if depths else 0,
        totalEvidenceItems = ev_total,
        uniqueDecisions    = tuple(sorted(decisions)),
    )


# ===========================================================================
# Utility: find_reasoning_step()
# ===========================================================================

def find_reasoning_step(
    traces      : List[ReasoningTrace],
    step_number : Optional[int]           = None,
    stage       : Optional[ReasoningStage] = None,
) -> Optional[ReasoningTrace]:
    """
    Return the first trace step matching the supplied lookup criterion.

    Priority order: step_number > stage.
    Returns None if nothing matches or no criterion supplied.

    Parameters
    ----------
    traces      : list of ReasoningTrace objects to search.
    step_number : exact stepNumber to find.
    stage       : ReasoningStage to find (first match in stepNumber order).

    Returns
    -------
    ReasoningTrace or None.
    """
    if step_number is not None:
        for t in traces:
            if t.stepNumber == step_number:
                return t
        return None

    if stage is not None:
        # Sort by stepNumber to return the lowest-numbered matching step
        for t in sorted(traces, key=lambda x: x.stepNumber):
            if t.stage == stage:
                return t
        return None

    return None
