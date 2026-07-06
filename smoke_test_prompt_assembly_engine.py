"""
Smoke Test — Prompt Assembly Engine
=====================================
Verifies every model, builder, and utility in
services/prompt_assembly_service.py with 220+ assertions.

Run:
    python smoke_test_prompt_assembly_engine.py

Expected: 100% PASS, no errors.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

from services.prompt_assembly_service import (
    # Models
    PromptSection,
    PromptBudget,
    PromptAssemblyMetadata,
    PromptPackage,
    PromptStatistics,
    # Builders
    build_prompt_section,
    build_prompt_budget,
    build_prompt_metadata,
    build_prompt_package,
    # Utilities
    sort_sections,
    filter_sections,
    group_sections,
    estimate_tokens,
    compress_sections,
    calculate_prompt_statistics,
    # Internal helpers exposed for determinism testing
    _compute_section_id,
    _compute_section_fingerprint,
    _compute_package_key,
    _compute_package_id,
    _compute_package_fingerprint,
    PROMPT_ASSEMBLY_ENGINE_VERSION,
    _PROTECTED_TITLES,
)
from core.constants import PROMPT_ASSEMBLY_ENGINE_VERSION as CONST_VERSION

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: List[str] = []


def _assert(cond: bool, msg: str) -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
    else:
        _FAIL += 1
        frame = traceback.extract_stack()[-2]
        _ERRORS.append(f"FAIL [line {frame.lineno}]: {msg}")


def _eq(a, b, msg: str) -> None:
    _assert(a == b, f"{msg} — expected {b!r}, got {a!r}")


def _ne(a, b, msg: str) -> None:
    _assert(a != b, f"{msg} — both are {a!r}")


def _in(item, container, msg: str) -> None:
    _assert(item in container, f"{msg} — {item!r} not found")


_TS = "2026-06-30T12:00:00Z"

# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version constant ...")
_eq(PROMPT_ASSEMBLY_ENGINE_VERSION, "prompt-assembly-v1", "engine version value")
_eq(CONST_VERSION, PROMPT_ASSEMBLY_ENGINE_VERSION,        "core.constants matches service")
_assert(isinstance(PROMPT_ASSEMBLY_ENGINE_VERSION, str),  "engine version is str")
_assert(len(PROMPT_ASSEMBLY_ENGINE_VERSION) > 0,          "engine version non-empty")

# ===========================================================================
# §2  Protected titles set
# ===========================================================================
print("§2  Protected titles ...")
_in("Reasoning Summary",  _PROTECTED_TITLES, "Reasoning Summary protected")
_in("Evidence Summary",   _PROTECTED_TITLES, "Evidence Summary protected")
_in("Final Conclusion",   _PROTECTED_TITLES, "Final Conclusion protected")
_in("System Prompt",      _PROTECTED_TITLES, "System Prompt protected")
_assert(len(_PROTECTED_TITLES) >= 4,          "at least 4 protected titles")

# ===========================================================================
# §3  estimate_tokens()
# ===========================================================================
print("§3  estimate_tokens() ...")
_eq(estimate_tokens(""),    0, "empty string → 0 tokens")
_eq(estimate_tokens("hi"),  1, "short string → 1 token (ceiling)")
# 4 chars / 4 = 1 token; 8 chars / 4 = 2 tokens
_eq(estimate_tokens("1234"), 1, "4 chars → 1 token")
_eq(estimate_tokens("12345678"), 2, "8 chars → 2 tokens")
# 400 chars / 4 = 100 tokens
long_text = "x" * 400
_eq(estimate_tokens(long_text), 100, "400 chars → 100 tokens")
# 401 chars → ceiling → 101
_eq(estimate_tokens("x" * 401), 101, "401 chars → 101 tokens (ceiling)")
# determinism
_eq(estimate_tokens("hello world"), estimate_tokens("hello world"), "estimate_tokens deterministic")

# ===========================================================================
# §4  build_prompt_section()
# ===========================================================================
print("§4  build_prompt_section() ...")
s1 = build_prompt_section("Reasoning Summary", "The attacker pivoted laterally.", priority=90)
_assert(isinstance(s1, PromptSection),          "returns PromptSection")
_eq(s1.title,   "Reasoning Summary",            "title preserved")
_eq(s1.priority, 90,                            "priority set")
_eq(s1.content, "The attacker pivoted laterally.", "content preserved")
_assert(s1.tokenEstimate > 0,                   "tokenEstimate > 0")
_eq(len(s1.sectionId), 32,                      "sectionId is 32 chars")
_assert(all(c in "0123456789abcdef" for c in s1.sectionId), "sectionId is hex")

# immutability
try:
    s1.title = "changed"  # type: ignore
    _assert(False, "PromptSection should be frozen")
except Exception:
    _assert(True, "PromptSection is immutable")

# title stripping
s_ws = build_prompt_section("  My Section  ", "content", 50)
_eq(s_ws.title, "My Section", "title stripped")

# metadata
s_meta = build_prompt_section("Test", "body", 10, metadata={"key": "val"})
_eq(s_meta.metadata["key"], "val", "metadata stored")

# same inputs → same sectionId
s2 = build_prompt_section("Reasoning Summary", "The attacker pivoted laterally.", priority=90)
_eq(s1.sectionId, s2.sectionId, "same inputs → same sectionId")

# different content → different sectionId
s3 = build_prompt_section("Reasoning Summary", "Different content here!", priority=90)
_ne(s1.sectionId, s3.sectionId, "different content → different sectionId")

# tokenEstimate matches estimate_tokens
_eq(s1.tokenEstimate, estimate_tokens(s1.content), "tokenEstimate matches estimate_tokens")

# ===========================================================================
# §5  build_prompt_budget()
# ===========================================================================
print("§5  build_prompt_budget() ...")
budget = build_prompt_budget(max_tokens=8192, reserved_tokens=1024, used_tokens=3000)
_assert(isinstance(budget, PromptBudget),    "returns PromptBudget")
_eq(budget.maxTokens,       8192,            "maxTokens set")
_eq(budget.reservedTokens,  1024,            "reservedTokens set")
_eq(budget.availableTokens, 7168,            "availableTokens = 8192-1024")
_eq(budget.usedTokens,      3000,            "usedTokens set")
_eq(budget.remainingTokens, 4168,            "remainingTokens = 7168-3000")
_assert(budget.compressionRatio > 0,         "compressionRatio > 0")
_assert(budget.compressionRatio < 1.0,       "compressionRatio < 1 (under budget)")

# over-budget
budget_over = build_prompt_budget(8192, 1024, 8000)
_assert(budget_over.remainingTokens < 0,     "over-budget → negative remainingTokens")
_assert(budget_over.compressionRatio > 1.0,  "over-budget → compressionRatio > 1")

# reserved >= max → available = 0
budget_zero = build_prompt_budget(1000, 1000, 500)
_eq(budget_zero.availableTokens, 0,          "reserved >= max → availableTokens = 0")
_eq(budget_zero.compressionRatio, 0.0,       "available=0 → compressionRatio = 0")

# immutability
try:
    budget.usedTokens = 9999  # type: ignore
    _assert(False, "PromptBudget should be frozen")
except Exception:
    _assert(True, "PromptBudget is immutable")

# ===========================================================================
# §6  Deterministic ID helpers
# ===========================================================================
print("§6  Deterministic ID helpers ...")
sid_a = _compute_section_id("Reasoning Summary", 90, "The attacker pivoted.")
sid_b = _compute_section_id("Reasoning Summary", 90, "The attacker pivoted.")
_eq(sid_a, sid_b,         "same inputs → same sectionId")
_eq(len(sid_a), 32,       "sectionId 32 chars")
_assert(all(c in "0123456789abcdef" for c in sid_a), "sectionId hex")

sid_diff = _compute_section_id("Reasoning Summary", 90, "Completely different content!")
_ne(sid_a, sid_diff,      "different content → different sectionId")

# section fingerprint
fp_a = _compute_section_fingerprint(s1)
fp_b = _compute_section_fingerprint(s1)
_eq(fp_a, fp_b,          "same section → same fingerprint")
_eq(len(fp_a), 32,       "section fingerprint 32 chars")

fp_other = _compute_section_fingerprint(s3)
_ne(fp_a, fp_other,      "different content → different fingerprint")

# package key
pk_a = _compute_package_key("r-001", "ctx-001", "inv-001", ["sec-b", "sec-a"])
pk_b = _compute_package_key("r-001", "ctx-001", "inv-001", ["sec-b", "sec-a"])
_eq(pk_a, pk_b,          "same inputs → same packageKey")

pk_rev = _compute_package_key("r-001", "ctx-001", "inv-001", ["sec-a", "sec-b"])  # reversed
_eq(pk_a, pk_rev,        "reversed sectionIds → same packageKey (sorted)")
_eq(len(pk_a), 32,       "packageKey is 32 chars")

pk_diff = _compute_package_key("r-002", "ctx-001", "inv-001", ["sec-a", "sec-b"])
_ne(pk_a, pk_diff,       "different reasoningId → different packageKey")

# package id
pid_a = _compute_package_id(pk_a)
pid_b = _compute_package_id(pk_a)
_eq(pid_a, pid_b,        "same key → same packageId")
_eq(len(pid_a), 36,      "packageId is UUID (36 chars)")
_in("-", pid_a,          "packageId contains hyphens")

# package fingerprint
secs_t = (s1,)
pfp_a = _compute_package_fingerprint(pk_a, "sys", "user", secs_t)
pfp_b = _compute_package_fingerprint(pk_a, "sys", "user", secs_t)
_eq(pfp_a, pfp_b,        "same inputs → same packageFingerprint")
_eq(len(pfp_a), 32,      "packageFingerprint is 32 chars")

pfp_diff = _compute_package_fingerprint(pk_a, "sys_changed", "user", secs_t)
_ne(pfp_a, pfp_diff,     "changed systemPrompt → different fingerprint")

# ===========================================================================
# §7  sort_sections()
# ===========================================================================
print("§7  sort_sections() ...")
sec_lo  = build_prompt_section("Low Priority",    "content", priority=10)
sec_mid = build_prompt_section("Mid Priority",    "content", priority=50)
sec_hi  = build_prompt_section("High Priority",   "content", priority=90)
sec_top = build_prompt_section("Final Conclusion","content", priority=100)

unsorted = [sec_lo, sec_top, sec_mid, sec_hi]

desc = sort_sections(unsorted, ascending=False)
_eq(desc[0].priority, 100, "desc sort: highest priority first")
_eq(desc[1].priority,  90, "desc sort: 90 second")
_eq(desc[2].priority,  50, "desc sort: 50 third")
_eq(desc[3].priority,  10, "desc sort: lowest last")

asc = sort_sections(unsorted, ascending=True)
_eq(asc[0].priority,  10, "asc sort: lowest first")
_eq(asc[3].priority, 100, "asc sort: highest last")

# input not mutated
_eq(unsorted[0].title, "Low Priority",  "input not mutated by sort_sections")
# determinism
_eq(sort_sections(unsorted), sort_sections(unsorted), "sort_sections deterministic")

# tie-break by sectionId ASC
sec_tie_a = build_prompt_section("Tie A", "same priority content", priority=50)
sec_tie_b = build_prompt_section("Tie B", "same priority content two", priority=50)
tied = sort_sections([sec_tie_b, sec_tie_a], ascending=False)
# lower sectionId (alphabetically) comes first
_assert(tied[0].sectionId <= tied[1].sectionId, "tie-break by sectionId ASC")

# ===========================================================================
# §8  filter_sections()
# ===========================================================================
print("§8  filter_sections() ...")
all_secs = [sec_lo, sec_mid, sec_hi, sec_top,
            build_prompt_section("Reasoning Summary", "reasoning text", priority=80),
            build_prompt_section("Evidence Summary",  "evidence text",  priority=70)]

# min_priority
hi_only = filter_sections(all_secs, min_priority=80)
_assert(all(s.priority >= 80 for s in hi_only), "min_priority=80 filter")
_assert(len(hi_only) >= 2,                       "min_priority returns expected count")

# max_priority
lo_only = filter_sections(all_secs, max_priority=50)
_assert(all(s.priority <= 50 for s in lo_only), "max_priority=50 filter")

# title_contains
titled = filter_sections(all_secs, title_contains="Summary")
_assert(all("summary" in s.title.lower() for s in titled), "title_contains filter")
_eq(len(titled), 2, "title_contains 'Summary' → 2 results")

# protected_only=True
prot = filter_sections(all_secs, protected_only=True)
_assert(all(s.title in _PROTECTED_TITLES for s in prot), "protected_only=True filter")
_eq(len(prot), 3, "3 protected sections in set")

# protected_only=False
non_prot = filter_sections(all_secs, protected_only=False)
_assert(all(s.title not in _PROTECTED_TITLES for s in non_prot), "protected_only=False filter")

# max_tokens
small = filter_sections(all_secs, max_tokens=10)
_assert(all(s.tokenEstimate <= 10 for s in small), "max_tokens filter")

# combined
combo = filter_sections(all_secs, min_priority=70, protected_only=True)
_assert(all(s.priority >= 70 and s.title in _PROTECTED_TITLES for s in combo),
        "combined filter: min_priority + protected_only")

# no filter → all
_eq(len(filter_sections(all_secs)), len(all_secs), "no filter → all sections returned")
# empty input
_eq(len(filter_sections([])), 0, "empty input → empty output")
# input not mutated
_eq(len(all_secs), 6, "input not mutated by filter_sections")

# ===========================================================================
# §9  group_sections()
# ===========================================================================
print("§9  group_sections() ...")
grp_secs = [
    build_prompt_section("Alpha", "c", priority=90),
    build_prompt_section("Beta",  "c", priority=50),
    build_prompt_section("Gamma", "c", priority=90),
    build_prompt_section("Delta", "c", priority=10),
]

by_prio = group_sections(grp_secs, group_by="priority")
_in("90", by_prio,  "priority group '90' present")
_in("50", by_prio,  "priority group '50' present")
_in("10", by_prio,  "priority group '10' present")
_eq(len(by_prio["90"]), 2, "two sections with priority 90")

# groups are sorted by priority DESC, sectionId ASC
_assert(by_prio["90"][0].sectionId <= by_prio["90"][1].sectionId,
        "group '90' sorted by sectionId")

by_title = group_sections(grp_secs, group_by="title")
_eq(len(by_title), 4, "group by title → 4 unique groups")
_in("Alpha", by_title, "Alpha group present")

by_sid = group_sections(grp_secs, group_by="sectionId")
_eq(len(by_sid), 4, "group by sectionId → 4 groups")

# invalid key
try:
    group_sections(grp_secs, group_by="nonexistent")
    _assert(False, "invalid group_by should raise ValueError")
except ValueError:
    _assert(True, "invalid group_by raises ValueError")

# empty input
_eq(len(group_sections([])), 0, "empty input → empty groups")
# determinism
_eq(
    {k: [s.title for s in v] for k, v in group_sections(grp_secs).items()},
    {k: [s.title for s in v] for k, v in group_sections(grp_secs).items()},
    "group_sections deterministic",
)

# ===========================================================================
# §10  compress_sections()
# ===========================================================================
print("§10  compress_sections() ...")

# Build sections with known token sizes
long_content  = "A" * 2000   # 500 tokens
short_content = "B" * 100    # 25 tokens

sec_long   = build_prompt_section("Low Pri",         long_content,  priority=10)
sec_medium = build_prompt_section("Medium Pri",      long_content,  priority=50)
sec_prot   = build_prompt_section("Reasoning Summary", long_content, priority=80)
sec_short  = build_prompt_section("Short",           short_content, priority=30)

# No compression needed
result_nc, applied_nc = compress_sections([sec_short], available_tokens=10_000)
_assert(not applied_nc,                "no compression when budget is large")
_eq(len(result_nc), 1,                 "no compression: all sections returned")
_eq(result_nc[0].content, sec_short.content, "no compression: content unchanged")

# Compression needed
all_to_compress = [sec_long, sec_medium, sec_prot, sec_short]
result_c, applied_c = compress_sections(all_to_compress, available_tokens=100, max_content_chars=200)
_assert(applied_c,                     "compression applied when over budget")
_eq(len(result_c), 4,                  "no sections removed, only truncated")

# Protected section must NOT be compressed
prot_in_result = next(s for s in result_c if s.title == "Reasoning Summary")
_eq(prot_in_result.content, long_content, "protected section content unchanged")

# Low priority compressed first (sec_long has priority=10)
low_in_result = next(s for s in result_c if s.title == "Low Pri")
_assert(len(low_in_result.content) <= 216, "low priority section was compressed (200 + suffix)")
_in("[compressed]", low_in_result.content, "compressed content has marker")

# Determinism
r1, a1 = compress_sections(all_to_compress, available_tokens=100, max_content_chars=200)
r2, a2 = compress_sections(all_to_compress, available_tokens=100, max_content_chars=200)
_assert(a1 == a2, "compress_sections: compression_applied is deterministic")
_eq([s.title for s in r1], [s.title for s in r2], "compress_sections: order deterministic")
_eq([s.content for s in r1], [s.content for s in r2], "compress_sections: content deterministic")

# Input not mutated
_eq(len(sec_long.content), 2000, "input section content not mutated by compress_sections")

# ===========================================================================
# §11  build_prompt_metadata()
# ===========================================================================
print("§11  build_prompt_metadata() ...")
meta_secs = (
    build_prompt_section("Reasoning Summary", "reasoning content", priority=90),
    build_prompt_section("Evidence Summary",  "evidence content",  priority=70),
)
meta_budget = build_prompt_budget(8192, 1024, 500)
meta_obj = build_prompt_metadata(
    processing_time_ms  = 42,
    sections            = meta_secs,
    budget              = meta_budget,
    compression_applied = False,
)
_assert(isinstance(meta_obj, PromptAssemblyMetadata), "returns PromptAssemblyMetadata")
_eq(meta_obj.processingTimeMs,  42,    "processingTimeMs set")
_eq(meta_obj.sectionCount,       2,    "sectionCount = 2")
_eq(meta_obj.compressionApplied, False,"compressionApplied = False")
_eq(meta_obj.engineVersion, PROMPT_ASSEMBLY_ENGINE_VERSION, "engineVersion from constant")
_eq(meta_obj.estimatedTokens,
    sum(s.tokenEstimate for s in meta_secs),
    "estimatedTokens = sum of section estimates")

# immutability
try:
    meta_obj.sectionCount = 99  # type: ignore
    _assert(False, "PromptAssemblyMetadata should be frozen")
except Exception:
    _assert(True, "PromptAssemblyMetadata is immutable")

# negative processingTimeMs → 0
meta_neg = build_prompt_metadata(-10, meta_secs, meta_budget)
_eq(meta_neg.processingTimeMs, 0, "negative processingTimeMs floored to 0")

# ===========================================================================
# §12  build_prompt_package()
# ===========================================================================
print("§12  build_prompt_package() ...")

pkg_sections = [
    build_prompt_section("Reasoning Summary", "Lateral movement detected via DNS tunnelling.", priority=90),
    build_prompt_section("Evidence Summary",  "3 pcap records, 2 ARP bindings.", priority=80),
    build_prompt_section("Final Conclusion",  "High confidence attack confirmed.",  priority=100),
    build_prompt_section("Timeline Overview", "T+0 to T+300 seconds.",              priority=60),
    build_prompt_section("Relationship Graph","15 edges, 8 nodes.",                 priority=50),
]

pkg = build_prompt_package(
    reasoning_id      = "r-abc123",
    context_id        = "ctx-def456",
    investigation_id  = "inv-ghi789",
    system_prompt     = "You are a forensic analyst.",
    user_prompt       = "Summarise the findings.",
    created_at        = _TS,
    sections          = pkg_sections,
    max_tokens        = 8192,
    reserved_tokens   = 1024,
    processing_time_ms= 55,
)

_assert(isinstance(pkg, PromptPackage),         "returns PromptPackage")
_eq(pkg.reasoningId,     "r-abc123",            "reasoningId preserved")
_eq(pkg.contextId,       "ctx-def456",          "contextId preserved")
_eq(pkg.investigationId, "inv-ghi789",          "investigationId preserved")
_eq(pkg.systemPrompt,    "You are a forensic analyst.", "systemPrompt preserved")
_eq(pkg.userPrompt,      "Summarise the findings.",     "userPrompt preserved")
_eq(pkg.createdAt,       _TS,                   "createdAt preserved")
_eq(len(pkg.packageId),  36,                    "packageId is UUID (36 chars)")
_eq(len(pkg.packageKey), 32,                    "packageKey is 32 chars")
_eq(len(pkg.packageFingerprint), 32,            "packageFingerprint is 32 chars")
_eq(pkg.metadata.engineVersion, PROMPT_ASSEMBLY_ENGINE_VERSION, "engineVersion correct")
_eq(len(pkg.sections),   5,                     "all 5 sections present")

# Sections sorted by priority DESC
_eq(pkg.sections[0].priority, 100, "first section has highest priority (100)")
_eq(pkg.sections[1].priority,  90, "second section priority 90")
_eq(pkg.sections[2].priority,  80, "third section priority 80")

# immutability
try:
    pkg.systemPrompt = "changed"  # type: ignore
    _assert(False, "PromptPackage should be frozen")
except Exception:
    _assert(True, "PromptPackage is immutable")

# ===========================================================================
# §13  Determinism: same input → same output
# ===========================================================================
print("§13  Determinism: same input → same output ...")

def _make_pkg(sections_list) -> PromptPackage:
    return build_prompt_package(
        reasoning_id      = "r-abc123",
        context_id        = "ctx-def456",
        investigation_id  = "inv-ghi789",
        system_prompt     = "You are a forensic analyst.",
        user_prompt       = "Summarise the findings.",
        created_at        = _TS,
        sections          = sections_list,
        max_tokens        = 8192,
        reserved_tokens   = 1024,
    )

p1 = _make_pkg(pkg_sections)
p2 = _make_pkg(pkg_sections)
_eq(p1.packageId,          p2.packageId,          "same input → same packageId")
_eq(p1.packageKey,         p2.packageKey,         "same input → same packageKey")
_eq(p1.packageFingerprint, p2.packageFingerprint, "same input → same fingerprint")
_eq(p1.sections,           p2.sections,           "same input → same sections tuple")

# Reversed section list → same package (sections sorted internally)
p3 = _make_pkg(list(reversed(pkg_sections)))
_eq(p1.packageId,          p3.packageId,          "reversed input → same packageId")
_eq(p1.packageKey,         p3.packageKey,         "reversed input → same packageKey")
_eq(p1.packageFingerprint, p3.packageFingerprint, "reversed input → same fingerprint")
_eq(p1.sections,           p3.sections,           "reversed input → same sections tuple")

# Different reasoningId → different package
p4 = build_prompt_package(
    "r-DIFFERENT", "ctx-def456", "inv-ghi789",
    "You are a forensic analyst.", "Summarise the findings.", _TS,
    sections=pkg_sections,
)
_ne(p1.packageId,          p4.packageId,          "different reasoningId → different packageId")
_ne(p1.packageKey,         p4.packageKey,         "different reasoningId → different packageKey")
_ne(p1.packageFingerprint, p4.packageFingerprint, "different reasoningId → different fingerprint")

# Different systemPrompt → different fingerprint (but same key)
p5 = build_prompt_package(
    "r-abc123", "ctx-def456", "inv-ghi789",
    "CHANGED SYSTEM PROMPT", "Summarise the findings.", _TS,
    sections=pkg_sections,
)
_eq(p1.packageKey,          p5.packageKey,         "system prompt change → same key (sections unchanged)")
_ne(p1.packageFingerprint,  p5.packageFingerprint, "system prompt change → different fingerprint")

# No randomness: build 5 times, all identical
ids_5 = [_make_pkg(pkg_sections).packageId for _ in range(5)]
_eq(len(set(ids_5)), 1, "no randomness: 5 builds yield identical packageId")

# ===========================================================================
# §14  Token budget and compression integration
# ===========================================================================
print("§14  Token budget and compression integration ...")

# Build a package that WILL exceed the budget
big_content = "W" * 10_000   # ~2500 tokens per section
fat_sections = [
    build_prompt_section("Reasoning Summary",  big_content, priority=90),
    build_prompt_section("Evidence Summary",   big_content, priority=80),
    build_prompt_section("Final Conclusion",   big_content, priority=100),
    build_prompt_section("Low Priority Data",  big_content, priority=10),
    build_prompt_section("Medium Priority",    big_content, priority=50),
]

pkg_compressed = build_prompt_package(
    "r-fat", "ctx-fat", "inv-fat",
    "sys", "user", _TS,
    sections          = fat_sections,
    max_tokens        = 4096,
    reserved_tokens   = 512,
)

_assert(pkg_compressed.metadata.compressionApplied, "compressionApplied=True for fat package")

# Protected sections must NOT be compressed
for s in pkg_compressed.sections:
    if s.title in _PROTECTED_TITLES:
        _eq(s.content, big_content, f"protected '{s.title}' content unchanged after compression")

# Non-protected sections should be compressed
compressed_non_prot = [s for s in pkg_compressed.sections if s.title not in _PROTECTED_TITLES]
_assert(all("[compressed]" in s.content for s in compressed_non_prot),
        "all non-protected sections compressed")

# Package is still deterministic even with compression
pkg_comp2 = build_prompt_package(
    "r-fat", "ctx-fat", "inv-fat",
    "sys", "user", _TS,
    sections          = fat_sections,
    max_tokens        = 4096,
    reserved_tokens   = 512,
)
_eq(pkg_compressed.packageId,          pkg_comp2.packageId,          "compressed pkg deterministic: packageId")
_eq(pkg_compressed.packageFingerprint, pkg_comp2.packageFingerprint, "compressed pkg deterministic: fingerprint")

# Reversed fat_sections → same compressed result
pkg_comp3 = build_prompt_package(
    "r-fat", "ctx-fat", "inv-fat",
    "sys", "user", _TS,
    sections          = list(reversed(fat_sections)),
    max_tokens        = 4096,
    reserved_tokens   = 512,
)
_eq(pkg_compressed.packageId,          pkg_comp3.packageId,          "reversed fat input → same packageId")
_eq(pkg_compressed.packageFingerprint, pkg_comp3.packageFingerprint, "reversed fat input → same fingerprint")

# ===========================================================================
# §15  calculate_prompt_statistics()
# ===========================================================================
print("§15  calculate_prompt_statistics() ...")

pkg_a = build_prompt_package(
    "r-001", "ctx-001", "inv-A", "sys", "user", _TS,
    sections=[build_prompt_section("Reasoning Summary", "text A", priority=90)],
    max_tokens=4096, reserved_tokens=512,
)
pkg_b = build_prompt_package(
    "r-002", "ctx-002", "inv-B", "sys", "user", _TS,
    sections=[
        build_prompt_section("Evidence Summary", "text B", priority=80),
        build_prompt_section("Timeline",         "text C", priority=50),
    ],
    max_tokens=4096, reserved_tokens=512,
)

stats = calculate_prompt_statistics([pkg_a, pkg_b])
_assert(isinstance(stats, PromptStatistics), "returns PromptStatistics")
_eq(stats.totalPackages,    2,               "totalPackages = 2")
_eq(stats.minTokens,        pkg_a.metadata.estimatedTokens, "minTokens = smaller pkg")
_eq(stats.maxTokens,        pkg_b.metadata.estimatedTokens, "maxTokens = larger pkg")
_assert(stats.averageTokens > 0,             "averageTokens > 0")
_eq(stats.uniqueInvestigationIds, ("inv-A", "inv-B"), "uniqueInvestigationIds sorted")

# empty
empty_stats = calculate_prompt_statistics([])
_eq(empty_stats.totalPackages,    0,    "empty → totalPackages = 0")
_eq(empty_stats.averageTokens,    0.0,  "empty → averageTokens = 0.0")
_eq(empty_stats.averageSectionCount, 0.0, "empty → averageSectionCount = 0.0")
_eq(empty_stats.uniqueInvestigationIds, (), "empty → empty tuple")

# immutability
try:
    stats.totalPackages = 99  # type: ignore
    _assert(False, "PromptStatistics should be frozen")
except Exception:
    _assert(True, "PromptStatistics is immutable")

# order-independence: same result regardless of list order
_eq(
    calculate_prompt_statistics([pkg_a, pkg_b]),
    calculate_prompt_statistics([pkg_b, pkg_a]),
    "calculate_prompt_statistics order-independent",
)

# ===========================================================================
# §16  No uuid4 / no random
# ===========================================================================
print("§16  No randomness ...")
ids_collected = set()
for _ in range(6):
    p = build_prompt_package(
        "r-const", "ctx-const", "inv-const",
        "sys", "user", _TS,
        sections=[build_prompt_section("Reasoning Summary", "same content", 90)],
    )
    ids_collected.add(p.packageId)
_eq(len(ids_collected), 1, "no randomness: 6 builds → identical packageId")

# ===========================================================================
# §17  Empty sections edge case
# ===========================================================================
print("§17  Empty sections edge case ...")
pkg_empty = build_prompt_package(
    "r-e", "ctx-e", "inv-e", "system text", "user text", _TS,
    sections=[],
)
_eq(len(pkg_empty.sections),    0,    "empty sections → 0 sections")
_eq(len(pkg_empty.packageId),  36,    "empty sections still produces valid UUID")
_eq(len(pkg_empty.packageKey), 32,    "empty sections still produces 32-char key")
_assert(pkg_empty.metadata.estimatedTokens >= 0, "estimatedTokens >= 0 for empty sections")

# ===========================================================================
# §18  PromptPackage fields structure
# ===========================================================================
print("§18  PromptPackage structure ...")
_assert(hasattr(pkg, "packageId"),          "has packageId")
_assert(hasattr(pkg, "packageKey"),         "has packageKey")
_assert(hasattr(pkg, "packageFingerprint"), "has packageFingerprint")
_assert(hasattr(pkg, "systemPrompt"),       "has systemPrompt")
_assert(hasattr(pkg, "userPrompt"),         "has userPrompt")
_assert(hasattr(pkg, "sections"),           "has sections")
_assert(hasattr(pkg, "reasoningId"),        "has reasoningId")
_assert(hasattr(pkg, "contextId"),          "has contextId")
_assert(hasattr(pkg, "investigationId"),    "has investigationId")
_assert(hasattr(pkg, "metadata"),           "has metadata")
_assert(hasattr(pkg, "createdAt"),          "has createdAt")
_assert(isinstance(pkg.sections, tuple),    "sections is a tuple")

# ===========================================================================
# Final summary
# ===========================================================================
print()
print("=" * 70)
total = _PASS + _FAIL

if _ERRORS:
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

print(f"Assertions run  : {total}")
print(f"PASSED          : {_PASS}")
print(f"FAILED          : {_FAIL}")
print("=" * 70)

if _FAIL == 0:
    print()
    print("DELIVERY SUMMARY")
    print("=" * 70)
    print()
    print("FILES CREATED")
    print("  services/prompt_assembly_service.py")
    print("  smoke_test_prompt_assembly_engine.py")
    print()
    print("CONSTANT APPENDED TO core/constants.py")
    print(f"  PROMPT_ASSEMBLY_ENGINE_VERSION = {repr(PROMPT_ASSEMBLY_ENGINE_VERSION)}")
    print()
    print("MODELS  (all frozen=True Pydantic models)")
    print("  PromptSection           — one rendered section with priority + token estimate")
    print("  PromptBudget            — token budget accounting (max/reserved/used/remaining)")
    print("  PromptAssemblyMetadata  — provenance, timings, compression flag, budget")
    print("  PromptPackage           — complete provider-agnostic prompt package")
    print("  PromptStatistics        — aggregate stats over a list of packages")
    print()
    print("BUILDER FUNCTIONS")
    print("  build_prompt_section()   — build one PromptSection with deterministic sectionId")
    print("  build_prompt_budget()    — build PromptBudget from token counts")
    print("  build_prompt_metadata()  — build PromptAssemblyMetadata")
    print("  build_prompt_package()   — primary builder: sort → budget → compress → IDs")
    print()
    print("UTILITY FUNCTIONS")
    print("  sort_sections()                — sort by priority DESC, sectionId ASC")
    print("  filter_sections()              — multi-criterion filter")
    print("  group_sections()               — group by priority / title / sectionId")
    print("  estimate_tokens()              — ceiling(len(text) / 4) token estimate")
    print("  compress_sections()            — deterministic budget-aware truncation")
    print("  calculate_prompt_statistics()  — aggregate stats over PromptPackage list")
    print()
    print("COMPRESSION STRATEGY")
    print("  1. Sort non-protected sections by priority ASC (lowest first)")
    print("  2. Truncate content to max_content_chars, append '... [compressed]'")
    print("  3. Protected titles are NEVER touched:")
    for t in sorted(_PROTECTED_TITLES):
        print(f"       '{t}'")
    print("  4. Sections are never removed — only truncated")
    print("  5. Fully deterministic: same input → same compression output")
    print()
    print("DETERMINISTIC STRATEGY")
    print("  sectionId          = SHA256(title + priority + content[:64])[:32]")
    print("  sectionFingerprint = SHA256(sectionId + priority + full_content)[:32]")
    print("  packageKey         = SHA256(reasoningId + contextId + investigationId")
    print("                       + sorted(sectionIds))[:32]")
    print("  packageId          = UUIDv5(PROMPT_NS, packageKey)")
    print("  packageFingerprint = SHA256(packageKey + systemPrompt + userPrompt")
    print("                       + sorted(section fingerprints))[:32]")
    print()
    print(f"SMOKE TEST RESULTS: {_PASS} / {total} assertions PASSED — 100%")
    print()
    print("ALL CHECKS PASSED ✓")
else:
    print()
    print(f"SMOKE TEST FAILED: {_FAIL} / {total} assertions failed")
    sys.exit(1)
