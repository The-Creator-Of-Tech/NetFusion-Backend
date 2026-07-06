"""
Prompt Assembly Engine
======================
Phase A4.1.2 — Deterministic, immutable prompt package assembly.

Responsibilities
----------------
- Assemble deterministic PromptPackage objects from reasoning results,
  AI context, and investigation scope — ready for any LLM provider.
- Manage token budgets: reserve, track, and compress sections to fit.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compress lower-priority sections when the budget is exceeded, without
  ever removing protected sections (Reasoning Summary, Evidence Summary,
  Final Conclusion, System Prompt).
- Expose builder functions: build_prompt_section, build_prompt_budget,
  build_prompt_metadata, build_prompt_package.
- Expose utility functions: sort_sections, filter_sections, group_sections,
  estimate_tokens, compress_sections, calculate_prompt_statistics.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No database, no HTTP, no FastAPI, no Prisma, no LLM calls.
- No OpenAI, no Claude, no Gemini, no Ollama.
- No uuid4(). No random module. No unordered set iteration.
- PromptPackage is provider-agnostic: reusable by any LLM.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import PROMPT_ASSEMBLY_ENGINE_VERSION

# ── UUIDv5 namespace — fixed; changing it invalidates all stored IDs ────────
_PROMPT_NS = uuid.UUID("6ba7b816-9dad-11d1-80b4-00c04fd430c8")

# ── Protected section titles — never compressed or removed ──────────────────
_PROTECTED_TITLES: frozenset = frozenset({
    "Reasoning Summary",
    "Evidence Summary",
    "Final Conclusion",
    "System Prompt",
})

# ── Approximate chars-per-token ratio (conservative; matches GPT tokeniser) ─
_CHARS_PER_TOKEN: float = 4.0


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class PromptSection(BaseModel):
    """
    One immutable section within a prompt package.

    Fields
    ------
    sectionId      : deterministic 32-char SHA-256 key derived from
                     (title + priority + content[:64]).
    title          : human-readable section name.
    priority       : integer priority; higher = more important.
                     Protected sections are never compressed regardless of
                     their numeric priority value.
    content        : the rendered text content of this section.
    tokenEstimate  : estimated token count for this section's content.
    metadata       : arbitrary key→value extension bag.
    """
    sectionId     : str
    title         : str
    priority      : int
    content       : str
    tokenEstimate : int
    metadata      : Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True


class PromptBudget(BaseModel):
    """
    Token budget for one prompt package.

    Fields
    ------
    maxTokens         : hard upper limit for the entire prompt.
    reservedTokens    : tokens reserved for the LLM's response.
    availableTokens   : maxTokens − reservedTokens.
    usedTokens        : sum of tokenEstimate across all sections.
    remainingTokens   : availableTokens − usedTokens (may be negative).
    compressionRatio  : usedTokens / availableTokens (1.0 = exactly at budget).
    """
    maxTokens        : int
    reservedTokens   : int
    availableTokens  : int
    usedTokens       : int
    remainingTokens  : int
    compressionRatio : float

    class Config:
        frozen = True


class PromptAssemblyMetadata(BaseModel):
    """
    Provenance and performance metadata for one prompt assembly run.

    Fields
    ------
    processingTimeMs  : wall-clock milliseconds to assemble the package.
    sectionCount      : number of sections in the final package.
    estimatedTokens   : total token estimate across all sections.
    compressionApplied: True if any sections were compressed.
    budget            : the PromptBudget in effect during assembly.
    engineVersion     : PROMPT_ASSEMBLY_ENGINE_VERSION at build time.
    """
    processingTimeMs  : int
    sectionCount      : int
    estimatedTokens   : int
    compressionApplied: bool
    budget            : PromptBudget
    engineVersion     : str

    class Config:
        frozen = True


class PromptPackage(BaseModel):
    """
    The complete, immutable prompt package for one LLM call.

    Provider-agnostic: the same PromptPackage can be consumed by
    OpenAI, Claude, Gemini, Ollama, Azure OpenAI, or any future provider.

    Identity
    --------
    packageId          : UUIDv5(PROMPT_NS, packageKey) — deterministic.
    packageKey         : SHA256(reasoningId + contextId + investigationId +
                         sorted(sectionIds))[:32]
    packageFingerprint : SHA256(packageKey + systemPrompt + userPrompt +
                         sorted(section fingerprints))[:32]

    Prompts
    -------
    systemPrompt : full assembled system-role text.
    userPrompt   : full assembled user-role text.

    Sections
    --------
    sections : sorted tuple of PromptSection objects
               (by priority DESC, then sectionId ASC for determinism).

    Linkage
    -------
    reasoningId      : ID of the ReasoningResult that drove this package.
    contextId        : ID of the AIContext that provided the raw data.
    investigationId  : ID of the investigation this package belongs to.

    Metadata
    --------
    metadata  : PromptAssemblyMetadata — provenance, timings, budget.
    createdAt : ISO-8601 timestamp (caller-supplied for determinism).
    """
    packageId          : str
    packageKey         : str
    packageFingerprint : str
    systemPrompt       : str
    userPrompt         : str
    sections           : Tuple[PromptSection, ...]
    reasoningId        : str
    contextId          : str
    investigationId    : str
    metadata           : PromptAssemblyMetadata
    createdAt          : str

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_section_id(title: str, priority: int, content: str) -> str:
    """
    sectionId = SHA256(title + priority + content[:64])[:32]

    Null-byte-separated to prevent cross-field collisions.
    The content is capped at 64 chars so minor trailing edits do not
    change the ID, but meaningful content changes do.
    Returns 32 hex characters.
    """
    raw = f"{title.strip()}\x00{priority}\x00{content[:64]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_section_fingerprint(section: PromptSection) -> str:
    """
    Deterministic 32-char fingerprint for one PromptSection.

    SHA256(sectionId + priority + full_content)[:32]
    Changes whenever content changes, even by one character.
    """
    raw = f"{section.sectionId}\x00{section.priority}\x00{section.content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_package_key(
    reasoning_id    : str,
    context_id      : str,
    investigation_id: str,
    section_ids     : List[str],
) -> str:
    """
    packageKey = SHA256(reasoningId + contextId + investigationId +
                        sorted(sectionIds))[:32]

    All components are null-byte-separated.
    Section IDs are sorted before hashing — insertion order has no effect.
    Returns 32 hex characters.
    """
    parts = [
        reasoning_id.strip(),
        context_id.strip(),
        investigation_id.strip(),
        "\x01".join(sorted(section_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_package_id(package_key: str) -> str:
    """packageId = UUIDv5(PROMPT_NS, packageKey)."""
    return str(uuid.uuid5(_PROMPT_NS, package_key))


def _compute_package_fingerprint(
    package_key    : str,
    system_prompt  : str,
    user_prompt    : str,
    sections       : Tuple[PromptSection, ...],
) -> str:
    """
    packageFingerprint = SHA256(
        packageKey +
        systemPrompt +
        userPrompt +
        sorted(section fingerprints)
    )[:32]

    Section fingerprints are sorted before hashing — order-independent.
    Returns 32 hex characters.
    """
    section_fps = sorted(_compute_section_fingerprint(s) for s in sections)
    parts = [
        package_key,
        system_prompt,
        user_prompt,
        "\x01".join(section_fps),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp_int(v: int, lo: int = 0, hi: int = 10_000_000) -> int:
    return max(lo, min(hi, v))


def _is_protected(title: str) -> bool:
    """Return True if the section title is in the protected set."""
    return title.strip() in _PROTECTED_TITLES


# ===========================================================================
# Utility: estimate_tokens()
# ===========================================================================

def estimate_tokens(text: str) -> int:
    """
    Estimate the token count of a text string.

    Algorithm: len(text) / _CHARS_PER_TOKEN, rounded up.
    Conservative ratio of 4 chars/token matches GPT-style tokenisers well
    for English prose mixed with JSON/code.  Always returns at least 1 for
    non-empty strings; 0 for empty.

    Parameters
    ----------
    text : the string to estimate.

    Returns
    -------
    int — estimated token count (≥ 0).
    """
    if not text:
        return 0
    return max(1, -(-len(text) // int(_CHARS_PER_TOKEN)))   # ceiling division


# ===========================================================================
# Builder: build_prompt_section()
# ===========================================================================

def build_prompt_section(
    title    : str,
    content  : str,
    priority : int                  = 50,
    metadata : Optional[Dict[str, Any]] = None,
) -> PromptSection:
    """
    Build a single PromptSection with a deterministic sectionId.

    Parameters
    ----------
    title    : human-readable section name (stripped before use).
    content  : the rendered text for this section.
    priority : integer importance score; higher = more important.
               Protected section titles are never compressed regardless of
               their numeric priority.
    metadata : arbitrary extension dict; copied, never mutated.

    Returns
    -------
    PromptSection (frozen / immutable)
    """
    clean_title   = title.strip()
    section_id    = _compute_section_id(clean_title, priority, content)
    token_est     = estimate_tokens(content)

    return PromptSection(
        sectionId     = section_id,
        title         = clean_title,
        priority      = priority,
        content       = content,
        tokenEstimate = token_est,
        metadata      = dict(metadata) if metadata else {},
    )


# ===========================================================================
# Builder: build_prompt_budget()
# ===========================================================================

def build_prompt_budget(
    max_tokens      : int,
    reserved_tokens : int,
    used_tokens     : int,
) -> PromptBudget:
    """
    Build a PromptBudget from raw token counts.

    Parameters
    ----------
    max_tokens      : hard upper limit for the entire prompt.
    reserved_tokens : tokens reserved for the LLM's response (completion).
    used_tokens     : sum of tokenEstimate across all sections.

    Returns
    -------
    PromptBudget (frozen / immutable)
    """
    available     = max(0, max_tokens - reserved_tokens)
    remaining     = available - used_tokens
    ratio         = round(used_tokens / available, 6) if available > 0 else 0.0

    return PromptBudget(
        maxTokens        = _clamp_int(max_tokens),
        reservedTokens   = _clamp_int(reserved_tokens),
        availableTokens  = available,
        usedTokens       = _clamp_int(used_tokens),
        remainingTokens  = remaining,
        compressionRatio = ratio,
    )


# ===========================================================================
# Builder: build_prompt_metadata()
# ===========================================================================

def build_prompt_metadata(
    processing_time_ms   : int,
    sections             : Tuple[PromptSection, ...],
    budget               : PromptBudget,
    compression_applied  : bool = False,
) -> PromptAssemblyMetadata:
    """
    Build PromptAssemblyMetadata from assembly outputs.

    Parameters
    ----------
    processing_time_ms  : wall-clock ms elapsed during assembly.
    sections            : the final tuple of PromptSection objects.
    budget              : the PromptBudget computed for this package.
    compression_applied : True if compress_sections() was invoked.

    Returns
    -------
    PromptAssemblyMetadata (frozen / immutable)
    """
    total_tokens = sum(s.tokenEstimate for s in sections)
    return PromptAssemblyMetadata(
        processingTimeMs   = max(0, int(processing_time_ms)),
        sectionCount       = len(sections),
        estimatedTokens    = total_tokens,
        compressionApplied = compression_applied,
        budget             = budget,
        engineVersion      = PROMPT_ASSEMBLY_ENGINE_VERSION,
    )


# ===========================================================================
# Utility: sort_sections()
# ===========================================================================

def sort_sections(
    sections  : List[PromptSection],
    ascending : bool = False,
) -> List[PromptSection]:
    """
    Sort sections by priority DESC (highest first), tie-broken by sectionId ASC.

    Parameters
    ----------
    sections  : list of PromptSection objects.
    ascending : False = highest priority first (default); True = lowest first.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        sections,
        key=lambda s: (-s.priority if not ascending else s.priority, s.sectionId),
    )


# ===========================================================================
# Utility: filter_sections()
# ===========================================================================

def filter_sections(
    sections        : List[PromptSection],
    min_priority    : Optional[int]  = None,
    max_priority    : Optional[int]  = None,
    title_contains  : Optional[str]  = None,
    protected_only  : Optional[bool] = None,
    max_tokens      : Optional[int]  = None,
) -> List[PromptSection]:
    """
    Filter sections by one or more criteria (all ANDed together).

    Parameters
    ----------
    min_priority   : keep sections with priority >= min_priority.
    max_priority   : keep sections with priority <= max_priority.
    title_contains : keep sections whose title contains this substring
                     (case-insensitive).
    protected_only : True = only protected sections;
                     False = only non-protected sections.
    max_tokens     : keep sections with tokenEstimate <= max_tokens.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[PromptSection] = []
    needle = title_contains.lower() if title_contains else None

    for s in sections:
        if min_priority  is not None and s.priority < min_priority:
            continue
        if max_priority  is not None and s.priority > max_priority:
            continue
        if needle        is not None and needle not in s.title.lower():
            continue
        if protected_only is True  and not _is_protected(s.title):
            continue
        if protected_only is False and _is_protected(s.title):
            continue
        if max_tokens    is not None and s.tokenEstimate > max_tokens:
            continue
        result.append(s)
    return result


# ===========================================================================
# Utility: group_sections()
# ===========================================================================

def group_sections(
    sections : List[PromptSection],
    group_by : str = "priority",
) -> Dict[str, List[PromptSection]]:
    """
    Group sections by an attribute.

    Parameters
    ----------
    sections : list of PromptSection objects.
    group_by : "priority" (default) | "title" | "sectionId".
               Groups keyed by str(attribute value).
               Each group is sorted by priority DESC, sectionId ASC.

    Returns
    -------
    Dict[str, List[PromptSection]] — each group sorted deterministically.
    """
    _VALID = {"priority", "title", "sectionId"}
    if group_by not in _VALID:
        raise ValueError(
            f"group_sections: unknown key '{group_by}'. Valid: {sorted(_VALID)}"
        )
    groups: Dict[str, List[PromptSection]] = {}
    for s in sections:
        key = str(getattr(s, group_by))
        groups.setdefault(key, []).append(s)
    return {k: sort_sections(v) for k, v in groups.items()}


# ===========================================================================
# Utility: compress_sections()
# ===========================================================================

def compress_sections(
    sections          : List[PromptSection],
    available_tokens  : int,
    max_content_chars : int = 500,
) -> Tuple[List[PromptSection], bool]:
    """
    Compress sections to fit within the available token budget.

    Compression rules (all deterministic)
    --------------------------------------
    1. Total token estimate is computed.
    2. If total <= available_tokens → return unchanged, compression=False.
    3. Otherwise: sort compressible sections (non-protected) by priority ASC
       (lowest priority compressed first).
    4. Truncate each compressible section's content to max_content_chars,
       appending "... [compressed]" to mark the truncation.
    5. Re-estimate tokens.  Protected sections are NEVER modified.
    6. Always returns the same result for the same inputs (deterministic).

    Never removes sections — only truncates content of non-protected ones.

    Parameters
    ----------
    sections          : list of PromptSection objects.
    available_tokens  : token budget ceiling.
    max_content_chars : character limit applied to each compressed section.

    Returns
    -------
    (compressed_sections, compression_applied)
      compressed_sections : new list of PromptSection objects (rebuilt, not mutated).
      compression_applied : True if any section was actually truncated.
    """
    total = sum(s.tokenEstimate for s in sections)
    if total <= available_tokens:
        return list(sections), False

    # Split into protected and compressible pools
    protected     = [s for s in sections if _is_protected(s.title)]
    compressible  = [s for s in sections if not _is_protected(s.title)]

    # Sort compressible by priority ASC (lowest priority compressed first),
    # tie-broken by sectionId ASC for full determinism
    compressible_sorted = sorted(compressible, key=lambda s: (s.priority, s.sectionId))

    compressed_pool: List[PromptSection] = []
    compression_applied = False

    for s in compressible_sorted:
        if len(s.content) > max_content_chars:
            truncated_content = s.content[:max_content_chars] + "... [compressed]"
            new_section = PromptSection(
                sectionId     = s.sectionId,   # ID is stable — identity doesn't change
                title         = s.title,
                priority      = s.priority,
                content       = truncated_content,
                tokenEstimate = estimate_tokens(truncated_content),
                metadata      = dict(s.metadata),
            )
            compressed_pool.append(new_section)
            compression_applied = True
        else:
            compressed_pool.append(s)

    # Merge back: protected sections are returned unchanged
    # Sort the merged result deterministically (priority DESC, sectionId ASC)
    merged = sort_sections(protected + compressed_pool)
    return merged, compression_applied


# ===========================================================================
# Statistics model and utility: calculate_prompt_statistics()
# ===========================================================================

class PromptStatistics(BaseModel):
    """
    Aggregate statistics over a list of PromptPackage objects.

    Fields
    ------
    totalPackages         : total count.
    averageTokens         : mean estimatedTokens (0.0 when empty).
    maxTokens             : maximum estimatedTokens across all packages.
    minTokens             : minimum estimatedTokens (0 when empty).
    compressionAppliedCount: count of packages where compressionApplied=True.
    averageSectionCount   : mean sectionCount (0.0 when empty).
    uniqueInvestigationIds: sorted tuple of distinct investigationIds.
    """
    totalPackages          : int
    averageTokens          : float
    maxTokens              : int
    minTokens              : int
    compressionAppliedCount: int
    averageSectionCount    : float
    uniqueInvestigationIds : Tuple[str, ...]

    class Config:
        frozen = True


def calculate_prompt_statistics(
    packages: List[PromptPackage],
) -> PromptStatistics:
    """
    Compute PromptStatistics over a list of PromptPackages.

    Deterministic: canonical sort (by packageId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    packages : any list of PromptPackage objects.

    Returns
    -------
    PromptStatistics (frozen / immutable)
    """
    if not packages:
        return PromptStatistics(
            totalPackages           = 0,
            averageTokens           = 0.0,
            maxTokens               = 0,
            minTokens               = 0,
            compressionAppliedCount = 0,
            averageSectionCount     = 0.0,
            uniqueInvestigationIds  = (),
        )

    # Canonical order for accumulation
    ordered = sorted(packages, key=lambda p: p.packageId)
    n = len(ordered)

    token_counts   = [p.metadata.estimatedTokens  for p in ordered]
    section_counts = [p.metadata.sectionCount      for p in ordered]
    compressed     = sum(1 for p in ordered if p.metadata.compressionApplied)
    inv_ids        = tuple(sorted({p.investigationId for p in ordered}))

    return PromptStatistics(
        totalPackages           = n,
        averageTokens           = round(sum(token_counts)   / n, 4),
        maxTokens               = max(token_counts),
        minTokens               = min(token_counts),
        compressionAppliedCount = compressed,
        averageSectionCount     = round(sum(section_counts) / n, 4),
        uniqueInvestigationIds  = inv_ids,
    )


# ===========================================================================
# Primary builder: build_prompt_package()
# ===========================================================================

def build_prompt_package(
    reasoning_id      : str,
    context_id        : str,
    investigation_id  : str,
    system_prompt     : str,
    user_prompt       : str,
    created_at        : str,
    sections          : Optional[List[PromptSection]]  = None,
    max_tokens        : int                            = 8192,
    reserved_tokens   : int                            = 1024,
    processing_time_ms: int                            = 0,
) -> PromptPackage:
    """
    Assemble a complete, immutable PromptPackage.

    Steps
    -----
    1. Sort sections by priority DESC, sectionId ASC.
    2. Compute initial token budget.
    3. If total tokens exceed the available budget, run compress_sections().
    4. Recompute budget with final token counts.
    5. Compute deterministic packageKey, packageId, packageFingerprint.
    6. Build PromptAssemblyMetadata.
    7. Return frozen PromptPackage.

    Parameters
    ----------
    reasoning_id       : ReasoningResult.reasoningId that drove this package.
    context_id         : AIContext.contextId that provided the data.
    investigation_id   : Investigation.investigationId scope.
    system_prompt      : full assembled system-role text.
    user_prompt        : full assembled user-role text.
    created_at         : ISO-8601 creation timestamp (caller-supplied).
    sections           : list of PromptSection objects; sorted internally.
    max_tokens         : hard token limit for the whole prompt.
    reserved_tokens    : tokens reserved for the LLM's completion response.
    processing_time_ms : elapsed wall-clock ms (caller-supplied).

    Returns
    -------
    PromptPackage (frozen / immutable)

    Determinism guarantees
    ----------------------
    - Sections sorted by priority DESC, sectionId ASC before any processing.
    - Compression processes sections in priority ASC (lowest first) — stable.
    - packageKey, packageId, packageFingerprint all deterministic from inputs.
    - Same inputs always produce structurally identical output.
    """
    working: List[PromptSection] = sort_sections(list(sections or []))

    # Compute initial token totals (system + user + sections)
    sys_tokens  = estimate_tokens(system_prompt)
    user_tokens = estimate_tokens(user_prompt)
    sec_tokens  = sum(s.tokenEstimate for s in working)
    total_used  = sys_tokens + user_tokens + sec_tokens

    available = max(0, max_tokens - reserved_tokens)
    compression_applied = False

    # Compress if needed — only section tokens are compressed; prompts are fixed
    if total_used > available:
        section_budget = max(0, available - sys_tokens - user_tokens)
        working, compression_applied = compress_sections(working, section_budget)
        sec_tokens = sum(s.tokenEstimate for s in working)
        total_used = sys_tokens + user_tokens + sec_tokens

    final_sections: Tuple[PromptSection, ...] = tuple(working)

    # Deterministic IDs
    section_ids = [s.sectionId for s in final_sections]
    pkg_key     = _compute_package_key(reasoning_id, context_id, investigation_id, section_ids)
    pkg_id      = _compute_package_id(pkg_key)
    pkg_fp      = _compute_package_fingerprint(pkg_key, system_prompt, user_prompt, final_sections)

    # Budget
    budget = build_prompt_budget(
        max_tokens      = max_tokens,
        reserved_tokens = reserved_tokens,
        used_tokens     = total_used,
    )

    # Metadata
    meta = build_prompt_metadata(
        processing_time_ms  = processing_time_ms,
        sections            = final_sections,
        budget              = budget,
        compression_applied = compression_applied,
    )

    return PromptPackage(
        packageId          = pkg_id,
        packageKey         = pkg_key,
        packageFingerprint = pkg_fp,
        systemPrompt       = system_prompt,
        userPrompt         = user_prompt,
        sections           = final_sections,
        reasoningId        = reasoning_id.strip(),
        contextId          = context_id.strip(),
        investigationId    = investigation_id.strip(),
        metadata           = meta,
        createdAt          = created_at,
    )
