"""
Investigation Narrative Engine
================================
Phase A4.1.3 — Deterministic, immutable investigation narrative generation.

Responsibilities
----------------
- Convert reasoning results, context objects, findings, alerts,
  evidence, relationships, and timeline events into a structured
  NarrativeDocument suitable for any report engine or AI Copilot.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute narrativeFingerprint from all section and timeline fingerprints.
- Generate NarrativeSummary, NarrativeSection, NarrativeTimelineEntry
  objects that are provider-agnostic and reusable by any downstream consumer.
- Expose builder functions: build_narrative_section, build_timeline_entry,
  build_narrative_summary, build_narrative_metadata, build_narrative_document.
- Expose utility functions: sort_sections, sort_timeline, filter_sections,
  group_sections, calculate_narrative_statistics, find_section.

Narrative generation flow
-------------------------
Reasoning → Attack Graph → Timeline → Evidence →
Findings → Alerts → Narrative Summary → Narrative Sections →
Narrative Timeline → NarrativeDocument

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No database, no HTTP, no FastAPI, no Prisma, no LLM calls.
- No OpenAI, no Claude, no Gemini, no Ollama.
- No uuid4(). No random module. No unordered set iteration.
- NarrativeDocument is provider-agnostic and reusable by any consumer.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import INVESTIGATION_NARRATIVE_ENGINE_VERSION

# ── UUIDv5 namespace — fixed; changing it invalidates all stored IDs ────────
_NARRATIVE_NS = uuid.UUID("6ba7b817-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class NarrativeSection(BaseModel):
    """
    One immutable section within a narrative document.

    Fields
    ------
    sectionId            : deterministic 32-char SHA-256 hex key derived from
                           (title + order + content[:64]).
    title                : human-readable section name.
    order                : integer position; lower = earlier in document.
    content              : full rendered text for this section.
    importance           : 0–100 importance score.
    relatedEvidenceIds   : sorted tuple of evidence IDs referenced.
    relatedFindingIds    : sorted tuple of finding IDs referenced.
    relatedAlertIds      : sorted tuple of alert IDs referenced.
    relatedRelationshipIds: sorted tuple of relationship IDs referenced.
    metadata             : arbitrary key→value extension bag.
    """
    sectionId             : str
    title                 : str
    order                 : int
    content               : str
    importance            : float
    relatedEvidenceIds    : Tuple[str, ...] = Field(default_factory=tuple)
    relatedFindingIds     : Tuple[str, ...] = Field(default_factory=tuple)
    relatedAlertIds       : Tuple[str, ...] = Field(default_factory=tuple)
    relatedRelationshipIds: Tuple[str, ...] = Field(default_factory=tuple)
    metadata              : Dict[str, Any]  = Field(default_factory=dict)

    class Config:
        frozen = True


class NarrativeTimelineEntry(BaseModel):
    """
    One immutable chronological event in the narrative timeline.

    Fields
    ------
    eventId     : deterministic 32-char SHA-256 hex key derived from
                  (timestamp + title + content[:32]).
    timestamp   : ISO-8601 string representing when this event occurred.
                  Empty string if unknown (sorts last).
    title       : short human-readable event title.
    description : full description of the event.
    importance  : 0–100 importance score.
    evidenceIds : sorted tuple of evidence IDs supporting this entry.
    metadata    : arbitrary key→value extension bag.
    """
    eventId     : str
    timestamp   : str
    title       : str
    description : str
    importance  : float
    evidenceIds : Tuple[str, ...] = Field(default_factory=tuple)
    metadata    : Dict[str, Any]  = Field(default_factory=dict)

    class Config:
        frozen = True


class NarrativeSummary(BaseModel):
    """
    High-level deterministic summary of the investigation narrative.

    Fields
    ------
    title              : narrative document title.
    overview           : one-paragraph overview of the investigation.
    attackSummary      : concise description of the attack or incident.
    riskSummary        : description of the risk level and affected assets.
    impactSummary      : description of actual or potential impact.
    confidenceSummary  : explanation of the overall confidence level.
    recommendedActions : sorted tuple of concrete recommended actions.
    """
    title             : str
    overview          : str
    attackSummary     : str
    riskSummary       : str
    impactSummary     : str
    confidenceSummary : str
    recommendedActions: Tuple[str, ...]

    class Config:
        frozen = True


class NarrativeMetadata(BaseModel):
    """
    Provenance and performance metadata for one narrative generation run.

    Fields
    ------
    processingTimeMs  : wall-clock ms to generate the narrative.
    sectionCount      : number of sections in the document.
    timelineEventCount: number of timeline entries.
    findingCount      : number of findings referenced.
    alertCount        : number of alerts referenced.
    relationshipCount : number of relationships referenced.
    evidenceCount     : number of evidence records referenced.
    engineVersion     : INVESTIGATION_NARRATIVE_ENGINE_VERSION at build time.
    """
    processingTimeMs  : int
    sectionCount      : int
    timelineEventCount: int
    findingCount      : int
    alertCount        : int
    relationshipCount : int
    evidenceCount     : int
    engineVersion     : str

    class Config:
        frozen = True


class NarrativeDocument(BaseModel):
    """
    The complete, immutable investigation narrative document.

    Provider-agnostic: reusable by any Report Engine or AI Copilot.

    Identity
    --------
    narrativeId          : UUIDv5(NARRATIVE_NS, narrativeKey) — deterministic.
    narrativeKey         : SHA256(reasoningId + contextId + investigationId +
                           sorted(sectionIds) + sorted(timelineEventIds))[:32]
    narrativeFingerprint : SHA256(narrativeKey + summary fingerprint +
                           sorted(section fingerprints) +
                           sorted(timeline fingerprints))[:32]

    Content
    -------
    summary  : NarrativeSummary — high-level overview.
    sections : sorted tuple of NarrativeSection (by order ASC, sectionId ASC).
    timeline : sorted tuple of NarrativeTimelineEntry (by timestamp ASC,
               eventId ASC; empty timestamps sort last).

    Linkage
    -------
    reasoningId     : ID of the ReasoningResult that drove this narrative.
    contextId       : ID of the AIContext that provided the raw data.
    investigationId : ID of the investigation this narrative belongs to.

    Metadata
    --------
    metadata  : NarrativeMetadata — provenance and timings.
    createdAt : ISO-8601 timestamp (caller-supplied for determinism).
    """
    narrativeId          : str
    narrativeKey         : str
    narrativeFingerprint : str
    summary              : NarrativeSummary
    sections             : Tuple[NarrativeSection, ...]
    timeline             : Tuple[NarrativeTimelineEntry, ...]
    reasoningId          : str
    contextId            : str
    investigationId      : str
    metadata             : NarrativeMetadata
    createdAt            : str

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_section_id(title: str, order: int, content: str) -> str:
    """
    sectionId = SHA256(title + order + content[:64])[:32]

    Null-byte-separated to prevent cross-field collisions.
    Returns 32 hex characters.
    """
    raw = f"{title.strip()}\x00{order}\x00{content[:64]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_section_fingerprint(section: NarrativeSection) -> str:
    """
    Deterministic 32-char fingerprint for one NarrativeSection.

    SHA256(sectionId + order + full_content)[:32]
    Changes whenever content changes.
    """
    raw = f"{section.sectionId}\x00{section.order}\x00{section.content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_timeline_entry_id(timestamp: str, title: str, content: str) -> str:
    """
    eventId = SHA256(timestamp + title + content[:32])[:32]

    Null-byte-separated. Returns 32 hex characters.
    """
    raw = f"{timestamp}\x00{title.strip()}\x00{content[:32]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_timeline_fingerprint(entry: NarrativeTimelineEntry) -> str:
    """
    Deterministic 32-char fingerprint for one NarrativeTimelineEntry.

    SHA256(eventId + timestamp + title + description)[:32]
    """
    raw = f"{entry.eventId}\x00{entry.timestamp}\x00{entry.title}\x00{entry.description}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_summary_fingerprint(summary: NarrativeSummary) -> str:
    """
    Deterministic 32-char fingerprint for a NarrativeSummary.

    SHA256(title + overview + attackSummary + riskSummary +
           impactSummary + confidenceSummary +
           sorted(recommendedActions))[:32]
    """
    parts = [
        summary.title,
        summary.overview,
        summary.attackSummary,
        summary.riskSummary,
        summary.impactSummary,
        summary.confidenceSummary,
        "\x01".join(sorted(summary.recommendedActions)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_narrative_key(
    reasoning_id      : str,
    context_id        : str,
    investigation_id  : str,
    section_ids       : List[str],
    timeline_event_ids: List[str],
) -> str:
    """
    narrativeKey = SHA256(
        reasoningId + contextId + investigationId +
        sorted(sectionIds) + sorted(timelineEventIds)
    )[:32]

    All ID collections are sorted before hashing.
    Returns 32 hex characters.
    """
    parts = [
        reasoning_id.strip(),
        context_id.strip(),
        investigation_id.strip(),
        "\x01".join(sorted(section_ids)),
        "\x01".join(sorted(timeline_event_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_narrative_id(narrative_key: str) -> str:
    """narrativeId = UUIDv5(NARRATIVE_NS, narrativeKey)."""
    return str(uuid.uuid5(_NARRATIVE_NS, narrative_key))


def _compute_narrative_fingerprint(
    narrative_key : str,
    summary       : NarrativeSummary,
    sections      : Tuple[NarrativeSection, ...],
    timeline      : Tuple[NarrativeTimelineEntry, ...],
) -> str:
    """
    narrativeFingerprint = SHA256(
        narrativeKey +
        summaryFingerprint +
        sorted(section fingerprints) +
        sorted(timeline fingerprints)
    )[:32]

    All fingerprint lists are sorted before hashing — order-independent.
    Returns 32 hex characters.
    """
    section_fps  = sorted(_compute_section_fingerprint(s)  for s in sections)
    timeline_fps = sorted(_compute_timeline_fingerprint(e) for e in timeline)
    summary_fp   = _compute_summary_fingerprint(summary)

    parts = [
        narrative_key,
        summary_fp,
        "\x01".join(section_fps),
        "\x01".join(timeline_fps),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp(v: float) -> float:
    """Clamp a float to [0.0, 100.0]."""
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
# Builder: build_narrative_section()
# ===========================================================================

def build_narrative_section(
    title                  : str,
    content                : str,
    order                  : int                    = 0,
    importance             : float                  = 50.0,
    related_evidence_ids   : Optional[List[str]]    = None,
    related_finding_ids    : Optional[List[str]]    = None,
    related_alert_ids      : Optional[List[str]]    = None,
    related_relationship_ids: Optional[List[str]]   = None,
    metadata               : Optional[Dict[str, Any]] = None,
) -> NarrativeSection:
    """
    Build a single NarrativeSection with a deterministic sectionId.

    Parameters
    ----------
    title                   : human-readable section title (stripped).
    content                 : full rendered text for this section.
    order                   : integer position in the document (0 = first).
    importance              : 0–100 importance score (clamped).
    related_evidence_ids    : evidence IDs referenced (deduped + sorted).
    related_finding_ids     : finding IDs referenced (deduped + sorted).
    related_alert_ids       : alert IDs referenced (deduped + sorted).
    related_relationship_ids: relationship IDs referenced (deduped + sorted).
    metadata                : arbitrary extension dict.

    Returns
    -------
    NarrativeSection (frozen / immutable)
    """
    clean_title = title.strip()
    section_id  = _compute_section_id(clean_title, order, content)

    return NarrativeSection(
        sectionId             = section_id,
        title                 = clean_title,
        order                 = order,
        content               = content,
        importance            = _clamp(importance),
        relatedEvidenceIds    = _norm_ids(related_evidence_ids),
        relatedFindingIds     = _norm_ids(related_finding_ids),
        relatedAlertIds       = _norm_ids(related_alert_ids),
        relatedRelationshipIds= _norm_ids(related_relationship_ids),
        metadata              = dict(metadata) if metadata else {},
    )


# ===========================================================================
# Builder: build_timeline_entry()
# ===========================================================================

def build_timeline_entry(
    timestamp   : str,
    title       : str,
    description : str,
    importance  : float                  = 50.0,
    evidence_ids: Optional[List[str]]    = None,
    metadata    : Optional[Dict[str, Any]] = None,
) -> NarrativeTimelineEntry:
    """
    Build a single NarrativeTimelineEntry with a deterministic eventId.

    Parameters
    ----------
    timestamp   : ISO-8601 string of the event time (empty = unknown).
    title       : short human-readable event title (stripped).
    description : full description of the event.
    importance  : 0–100 importance score (clamped).
    evidence_ids: supporting evidence IDs (deduped + sorted).
    metadata    : arbitrary extension dict.

    Returns
    -------
    NarrativeTimelineEntry (frozen / immutable)
    """
    clean_title = title.strip()
    event_id    = _compute_timeline_entry_id(timestamp, clean_title, description)

    return NarrativeTimelineEntry(
        eventId     = event_id,
        timestamp   = timestamp,
        title       = clean_title,
        description = description,
        importance  = _clamp(importance),
        evidenceIds = _norm_ids(evidence_ids),
        metadata    = dict(metadata) if metadata else {},
    )


# ===========================================================================
# Builder: build_narrative_summary()
# ===========================================================================

def build_narrative_summary(
    title              : str,
    overview           : str,
    attack_summary     : str,
    risk_summary       : str,
    impact_summary     : str,
    confidence_summary : str,
    recommended_actions: Optional[List[str]] = None,
) -> NarrativeSummary:
    """
    Build a NarrativeSummary.

    recommendedActions is deduplicated and sorted for determinism.

    Parameters
    ----------
    title               : narrative document title.
    overview            : one-paragraph overview.
    attack_summary      : concise description of the attack/incident.
    risk_summary        : description of risk level and affected assets.
    impact_summary      : description of actual or potential impact.
    confidence_summary  : explanation of overall confidence.
    recommended_actions : concrete recommended actions (deduped + sorted).

    Returns
    -------
    NarrativeSummary (frozen / immutable)
    """
    return NarrativeSummary(
        title              = title,
        overview           = overview,
        attackSummary      = attack_summary,
        riskSummary        = risk_summary,
        impactSummary      = impact_summary,
        confidenceSummary  = confidence_summary,
        recommendedActions = _norm_strings(recommended_actions),
    )


# ===========================================================================
# Builder: build_narrative_metadata()
# ===========================================================================

def build_narrative_metadata(
    processing_time_ms  : int,
    sections            : Tuple[NarrativeSection, ...],
    timeline            : Tuple[NarrativeTimelineEntry, ...],
    finding_count       : int = 0,
    alert_count         : int = 0,
    relationship_count  : int = 0,
    evidence_count      : int = 0,
) -> NarrativeMetadata:
    """
    Build NarrativeMetadata from assembly outputs.

    Parameters
    ----------
    processing_time_ms : wall-clock ms to generate the narrative.
    sections           : final tuple of NarrativeSection objects.
    timeline           : final tuple of NarrativeTimelineEntry objects.
    finding_count      : number of findings referenced.
    alert_count        : number of alerts referenced.
    relationship_count : number of relationships referenced.
    evidence_count     : number of evidence records referenced.

    Returns
    -------
    NarrativeMetadata (frozen / immutable)
    """
    return NarrativeMetadata(
        processingTimeMs   = max(0, int(processing_time_ms)),
        sectionCount       = len(sections),
        timelineEventCount = len(timeline),
        findingCount       = max(0, int(finding_count)),
        alertCount         = max(0, int(alert_count)),
        relationshipCount  = max(0, int(relationship_count)),
        evidenceCount      = max(0, int(evidence_count)),
        engineVersion      = INVESTIGATION_NARRATIVE_ENGINE_VERSION,
    )


# ===========================================================================
# Utility: sort_sections()
# ===========================================================================

def sort_sections(
    sections  : List[NarrativeSection],
    ascending : bool = True,
) -> List[NarrativeSection]:
    """
    Sort sections by order ASC (earliest first), tie-broken by sectionId ASC.

    Parameters
    ----------
    sections  : list of NarrativeSection objects.
    ascending : True = lowest order first (default); False = reverse.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        sections,
        key=lambda s: (s.order, s.sectionId),
        reverse=not ascending,
    )


# ===========================================================================
# Utility: sort_timeline()
# ===========================================================================

def sort_timeline(
    entries   : List[NarrativeTimelineEntry],
    ascending : bool = True,
) -> List[NarrativeTimelineEntry]:
    """
    Sort timeline entries chronologically.

    Sort key: (timestamp ASC, eventId ASC).
    Empty timestamps ("") sort LAST (they become "~" for comparison purposes
    so they fall after all ISO-8601 strings which start with a digit).

    Parameters
    ----------
    entries   : list of NarrativeTimelineEntry objects.
    ascending : True = earliest first (default); False = most recent first.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    def _key(e: NarrativeTimelineEntry) -> tuple:
        # Empty timestamp → sort last by using a high sentinel
        ts = e.timestamp if e.timestamp else "\xff"
        return (ts, e.eventId)

    return sorted(entries, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_sections()
# ===========================================================================

def filter_sections(
    sections       : List[NarrativeSection],
    min_order      : Optional[int]   = None,
    max_order      : Optional[int]   = None,
    min_importance : Optional[float] = None,
    title_contains : Optional[str]   = None,
    has_findings   : Optional[bool]  = None,
    has_alerts     : Optional[bool]  = None,
    has_evidence   : Optional[bool]  = None,
) -> List[NarrativeSection]:
    """
    Filter narrative sections by one or more criteria (all ANDed).

    Parameters
    ----------
    min_order      : keep sections with order >= min_order.
    max_order      : keep sections with order <= max_order.
    min_importance : keep sections with importance >= min_importance.
    title_contains : keep sections whose title contains this substring
                     (case-insensitive).
    has_findings   : True = only sections with relatedFindingIds;
                     False = only sections without.
    has_alerts     : same logic for relatedAlertIds.
    has_evidence   : same logic for relatedEvidenceIds.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[NarrativeSection] = []
    needle = title_contains.lower() if title_contains else None

    for s in sections:
        if min_order      is not None and s.order      < min_order:
            continue
        if max_order      is not None and s.order      > max_order:
            continue
        if min_importance is not None and s.importance < min_importance:
            continue
        if needle         is not None and needle not in s.title.lower():
            continue
        if has_findings is not None:
            if has_findings  and not s.relatedFindingIds:
                continue
            if not has_findings and s.relatedFindingIds:
                continue
        if has_alerts is not None:
            if has_alerts    and not s.relatedAlertIds:
                continue
            if not has_alerts and s.relatedAlertIds:
                continue
        if has_evidence is not None:
            if has_evidence  and not s.relatedEvidenceIds:
                continue
            if not has_evidence and s.relatedEvidenceIds:
                continue
        result.append(s)
    return result


# ===========================================================================
# Utility: group_sections()
# ===========================================================================

def group_sections(
    sections : List[NarrativeSection],
    group_by : str = "order",
) -> Dict[str, List[NarrativeSection]]:
    """
    Group sections by an attribute.

    Parameters
    ----------
    sections : list of NarrativeSection objects.
    group_by : "order" (default) | "title" | "sectionId".
               Each group is sorted by order ASC, sectionId ASC.

    Returns
    -------
    Dict[str, List[NarrativeSection]] — each group sorted deterministically.
    """
    _VALID = {"order", "title", "sectionId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_sections: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )
    groups: Dict[str, List[NarrativeSection]] = {}
    for s in sections:
        key = str(getattr(s, group_by))
        groups.setdefault(key, []).append(s)
    return {k: sort_sections(v) for k, v in groups.items()}


# ===========================================================================
# Statistics model and utility: calculate_narrative_statistics()
# ===========================================================================

class NarrativeStatistics(BaseModel):
    """
    Aggregate statistics over a list of NarrativeDocument objects.

    Fields
    ------
    totalDocuments          : total count.
    averageSectionCount     : mean sectionCount (0.0 when empty).
    averageTimelineCount    : mean timelineEventCount (0.0 when empty).
    maxSectionCount         : maximum sectionCount across all documents.
    minSectionCount         : minimum sectionCount (0 when empty).
    uniqueInvestigationIds  : sorted tuple of distinct investigationIds.
    totalFindingsReferenced : sum of findingCount across all documents.
    totalAlertsReferenced   : sum of alertCount across all documents.
    """
    totalDocuments         : int
    averageSectionCount    : float
    averageTimelineCount   : float
    maxSectionCount        : int
    minSectionCount        : int
    uniqueInvestigationIds : Tuple[str, ...]
    totalFindingsReferenced: int
    totalAlertsReferenced  : int

    class Config:
        frozen = True


def calculate_narrative_statistics(
    documents: List[NarrativeDocument],
) -> NarrativeStatistics:
    """
    Compute NarrativeStatistics over a list of NarrativeDocuments.

    Deterministic: canonical sort (by narrativeId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    documents : any list of NarrativeDocument objects.

    Returns
    -------
    NarrativeStatistics (frozen / immutable)
    """
    if not documents:
        return NarrativeStatistics(
            totalDocuments          = 0,
            averageSectionCount     = 0.0,
            averageTimelineCount    = 0.0,
            maxSectionCount         = 0,
            minSectionCount         = 0,
            uniqueInvestigationIds  = (),
            totalFindingsReferenced = 0,
            totalAlertsReferenced   = 0,
        )

    # Canonical order for accumulation
    ordered = sorted(documents, key=lambda d: d.narrativeId)
    n = len(ordered)

    sec_counts  = [d.metadata.sectionCount       for d in ordered]
    tl_counts   = [d.metadata.timelineEventCount  for d in ordered]
    inv_ids     = tuple(sorted({d.investigationId for d in ordered}))
    total_finds = sum(d.metadata.findingCount     for d in ordered)
    total_alerts= sum(d.metadata.alertCount       for d in ordered)

    return NarrativeStatistics(
        totalDocuments          = n,
        averageSectionCount     = round(sum(sec_counts) / n, 4),
        averageTimelineCount    = round(sum(tl_counts)  / n, 4),
        maxSectionCount         = max(sec_counts),
        minSectionCount         = min(sec_counts),
        uniqueInvestigationIds  = inv_ids,
        totalFindingsReferenced = total_finds,
        totalAlertsReferenced   = total_alerts,
    )


# ===========================================================================
# Utility: find_section()
# ===========================================================================

def find_section(
    sections   : List[NarrativeSection],
    section_id : Optional[str] = None,
    title      : Optional[str] = None,
    order      : Optional[int] = None,
) -> Optional[NarrativeSection]:
    """
    Return the first section matching the supplied lookup criterion.

    Priority order: section_id > title (exact match) > order (lowest first).
    Returns None if nothing matches or no criterion is supplied.

    Parameters
    ----------
    sections   : list to search.
    section_id : exact sectionId to find.
    title      : exact title to find (stripped, case-sensitive).
    order      : find the first section with this order value.

    Returns
    -------
    NarrativeSection or None.
    """
    if section_id is not None:
        needle = section_id.strip()
        for s in sections:
            if s.sectionId == needle:
                return s
        return None

    if title is not None:
        needle = title.strip()
        for s in sort_sections(sections):
            if s.title == needle:
                return s
        return None

    if order is not None:
        for s in sort_sections(sections):
            if s.order == order:
                return s
        return None

    return None


# ===========================================================================
# Primary builder: build_narrative_document()
# ===========================================================================

def build_narrative_document(
    reasoning_id      : str,
    context_id        : str,
    investigation_id  : str,
    summary           : NarrativeSummary,
    created_at        : str,
    sections          : Optional[List[NarrativeSection]]      = None,
    timeline          : Optional[List[NarrativeTimelineEntry]] = None,
    finding_count     : int                                    = 0,
    alert_count       : int                                    = 0,
    relationship_count: int                                    = 0,
    evidence_count    : int                                    = 0,
    processing_time_ms: int                                    = 0,
) -> NarrativeDocument:
    """
    Assemble a complete, immutable NarrativeDocument.

    Steps
    -----
    1. Sort sections by order ASC, sectionId ASC.
    2. Sort timeline entries by timestamp ASC, eventId ASC (empty last).
    3. Compute deterministic narrativeKey, narrativeId, narrativeFingerprint.
    4. Build NarrativeMetadata.
    5. Return frozen NarrativeDocument.

    Parameters
    ----------
    reasoning_id       : ReasoningResult.reasoningId that drove this narrative.
    context_id         : AIContext.contextId that provided the data.
    investigation_id   : Investigation.investigationId scope.
    summary            : NarrativeSummary with high-level overview.
    created_at         : ISO-8601 creation timestamp (caller-supplied).
    sections           : list of NarrativeSection objects; sorted internally.
    timeline           : list of NarrativeTimelineEntry; sorted internally.
    finding_count      : number of findings referenced.
    alert_count        : number of alerts referenced.
    relationship_count : number of relationships referenced.
    evidence_count     : number of evidence records referenced.
    processing_time_ms : elapsed wall-clock ms (caller-supplied).

    Returns
    -------
    NarrativeDocument (frozen / immutable)

    Determinism guarantees
    ----------------------
    - Sections sorted by order ASC, sectionId ASC.
    - Timeline sorted by timestamp ASC, eventId ASC; empty timestamps last.
    - narrativeKey, narrativeId, narrativeFingerprint all deterministic.
    - Same inputs always produce structurally identical output.
    """
    # Sort sections and timeline deterministically
    sorted_secs: Tuple[NarrativeSection, ...] = tuple(
        sort_sections(list(sections or []))
    )
    sorted_tl: Tuple[NarrativeTimelineEntry, ...] = tuple(
        sort_timeline(list(timeline or []))
    )

    # Collect IDs for key computation
    section_ids        = [s.sectionId for s in sorted_secs]
    timeline_event_ids = [e.eventId   for e in sorted_tl]

    # Deterministic IDs
    nar_key = _compute_narrative_key(
        reasoning_id, context_id, investigation_id,
        section_ids, timeline_event_ids,
    )
    nar_id  = _compute_narrative_id(nar_key)
    nar_fp  = _compute_narrative_fingerprint(nar_key, summary, sorted_secs, sorted_tl)

    # Metadata
    meta = build_narrative_metadata(
        processing_time_ms = processing_time_ms,
        sections           = sorted_secs,
        timeline           = sorted_tl,
        finding_count      = finding_count,
        alert_count        = alert_count,
        relationship_count = relationship_count,
        evidence_count     = evidence_count,
    )

    return NarrativeDocument(
        narrativeId          = nar_id,
        narrativeKey         = nar_key,
        narrativeFingerprint = nar_fp,
        summary              = summary,
        sections             = sorted_secs,
        timeline             = sorted_tl,
        reasoningId          = reasoning_id.strip(),
        contextId            = context_id.strip(),
        investigationId      = investigation_id.strip(),
        metadata             = meta,
        createdAt            = created_at,
    )
