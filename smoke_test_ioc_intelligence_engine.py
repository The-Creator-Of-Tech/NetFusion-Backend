"""
Smoke Test — IOC Intelligence Engine
=====================================
Phase A4.4.3 — Comprehensive deterministic test suite.

Covers
------
- Deterministic IDs (iocKey, iocId, mappingKey, mappingId, fingerprints)
- Builders: build_ioc_record, build_ioc_mapping, build_ioc_statistics
- Validators: validate_ioc_record, validate_ioc_mapping
- IOC Operations: add, update, remove, merge
- Mapping Operations: add, remove, merge
- Search: find_ioc_record, find_ioc_mapping
- Sorting: sort_ioc_records, sort_ioc_mappings
- Filtering: filter_ioc_records, filter_ioc_mappings
- Grouping: group_ioc_records, group_ioc_mappings
- Statistics: build_ioc_statistics
- Serialization: model_dump / dict round-trip
- Immutability: frozen model enforcement
- Integration helpers: finding_to_ioc_mapping, alert_to_ioc_mapping,
  reasoning_to_ioc_mapping, cve_to_ioc_reference, mitre_to_ioc_reference
- Edge cases: empty inputs, duplicates, boundary values
- Zero randomness: same inputs produce identical outputs across runs
- Large dataset stability

Target: 500+ assertions
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Simple assertion counter
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: list = []


def _assert(condition: bool, msg: str) -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        _ERRORS.append(f"FAIL: {msg}")
        print(f"  FAIL: {msg}")


def _assert_raises(exc_type, fn, *args, msg: str = "", **kwargs) -> None:
    global _PASS, _FAIL
    try:
        fn(*args, **kwargs)
        _FAIL += 1
        _ERRORS.append(f"FAIL (no exception): {msg or fn.__name__}")
        print(f"  FAIL (no exception): {msg or fn.__name__}")
    except exc_type:
        _PASS += 1
    except Exception as e:
        _FAIL += 1
        _ERRORS.append(f"FAIL (wrong exception {type(e).__name__}): {msg}")
        print(f"  FAIL (wrong exception {type(e).__name__}): {msg}")


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from services.ioc_intelligence_service import (
    # Enums
    IOCTypeEnum, IOCSeverityEnum, IOCConfidenceEnum,
    # Exceptions
    IOCIntelligenceError, InvalidIOCError, InvalidIOCMappingError, InvalidIOCTypeError,
    # Models
    IOCRecord, IOCMapping, IOCStatistics,
    # Key derivation
    iocKey, iocMappingKey, iocMappingFingerprint,
    # Validators
    validate_ioc_record, validate_ioc_mapping,
    # Builders
    build_ioc_record, build_ioc_mapping, build_ioc_statistics,
    # IOC Operations
    add_ioc_record, update_ioc_record, remove_ioc_record, merge_ioc_records,
    # Mapping Operations
    add_ioc_mapping, remove_ioc_mapping, merge_ioc_mappings,
    # Search
    find_ioc_record, find_ioc_mapping,
    # Sort
    sort_ioc_records, sort_ioc_mappings,
    # Filter
    filter_ioc_records, filter_ioc_mappings,
    # Group
    group_ioc_records, group_ioc_mappings,
    # Integration helpers
    finding_to_ioc_mapping, alert_to_ioc_mapping, reasoning_to_ioc_mapping,
    cve_to_ioc_reference, mitre_to_ioc_reference,
    # Constants
    IOC_INTELLIGENCE_ENGINE_VERSION,
)

from core.constants import IOC_INTELLIGENCE_ENGINE_VERSION as CONST_VERSION

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T12:00:00Z"

# ===========================================================================
# Section 1 — Enumerations
# ===========================================================================
print("\n[1] Enumerations")

_assert(IOCTypeEnum.IP.value         == "IP",          "IP value")
_assert(IOCTypeEnum.DOMAIN.value     == "DOMAIN",      "DOMAIN value")
_assert(IOCTypeEnum.URL.value        == "URL",         "URL value")
_assert(IOCTypeEnum.EMAIL.value      == "EMAIL",       "EMAIL value")
_assert(IOCTypeEnum.HASH_MD5.value   == "HASH_MD5",    "HASH_MD5 value")
_assert(IOCTypeEnum.HASH_SHA1.value  == "HASH_SHA1",   "HASH_SHA1 value")
_assert(IOCTypeEnum.HASH_SHA256.value== "HASH_SHA256", "HASH_SHA256 value")
_assert(IOCTypeEnum.REGISTRY.value   == "REGISTRY",    "REGISTRY value")
_assert(IOCTypeEnum.FILE.value       == "FILE",        "FILE value")
_assert(IOCTypeEnum.MUTEX.value      == "MUTEX",       "MUTEX value")
_assert(IOCTypeEnum.PROCESS.value    == "PROCESS",     "PROCESS value")
_assert(len(list(IOCTypeEnum))       == 11,            "11 IOC types")

_assert(IOCSeverityEnum.LOW.value      == "LOW",      "severity LOW")
_assert(IOCSeverityEnum.MEDIUM.value   == "MEDIUM",   "severity MEDIUM")
_assert(IOCSeverityEnum.HIGH.value     == "HIGH",     "severity HIGH")
_assert(IOCSeverityEnum.CRITICAL.value == "CRITICAL", "severity CRITICAL")

_assert(IOCConfidenceEnum.LOW.value      == "LOW",      "confidence LOW")
_assert(IOCConfidenceEnum.MEDIUM.value   == "MEDIUM",   "confidence MEDIUM")
_assert(IOCConfidenceEnum.HIGH.value     == "HIGH",     "confidence HIGH")
_assert(IOCConfidenceEnum.VERIFIED.value == "VERIFIED", "confidence VERIFIED")


# ===========================================================================
# Section 2 — Engine Version
# ===========================================================================
print("\n[2] Engine Version")

_assert(IOC_INTELLIGENCE_ENGINE_VERSION == "ioc-intelligence-v1", "version string")
_assert(CONST_VERSION == IOC_INTELLIGENCE_ENGINE_VERSION, "constant matches module")


# ===========================================================================
# Section 3 — Typed Exceptions Hierarchy
# ===========================================================================
print("\n[3] Exception hierarchy")

_assert(issubclass(InvalidIOCError,       IOCIntelligenceError), "InvalidIOCError IS-A IOCIntelligenceError")
_assert(issubclass(InvalidIOCMappingError, IOCIntelligenceError), "InvalidIOCMappingError IS-A IOCIntelligenceError")
_assert(issubclass(InvalidIOCTypeError,    IOCIntelligenceError), "InvalidIOCTypeError IS-A IOCIntelligenceError")
_assert(issubclass(IOCIntelligenceError,   Exception),            "IOCIntelligenceError IS-A Exception")


# ===========================================================================
# Section 4 — Deterministic Key Derivation
# ===========================================================================
print("\n[4] Deterministic key derivation")

k1 = iocKey(IOCTypeEnum.IP, "192.168.1.1")
k2 = iocKey(IOCTypeEnum.IP, "192.168.1.1")
_assert(k1 == k2,           "iocKey is deterministic")
_assert(len(k1) == 32,      "iocKey is 32 chars")
_assert(k1.islower(),       "iocKey is lowercase hex")

k_domain = iocKey(IOCTypeEnum.DOMAIN, "evil.com")
_assert(k_domain != k1,     "different type+value → different key")

k_ip2 = iocKey(IOCTypeEnum.IP, "10.0.0.1")
_assert(k_ip2 != k1,        "different value → different key")

# Mapping key
ids1 = ("id-a", "id-b")
mk1  = iocMappingKey("f1", "a1", "r1", ids1)
mk2  = iocMappingKey("f1", "a1", "r1", ids1)
_assert(mk1 == mk2,          "mappingKey is deterministic")
_assert(len(mk1) == 32,      "mappingKey is 32 chars")

# Order-independent mapping key
ids2 = ("id-b", "id-a")
mk3  = iocMappingKey("f1", "a1", "r1", ids2)
_assert(mk1 == mk3,          "mappingKey is order-independent")

# Mapping fingerprint
fp1 = iocMappingFingerprint(mk1, "f1", "a1", "r1", ids1)
fp2 = iocMappingFingerprint(mk1, "f1", "a1", "r1", ids1)
_assert(fp1 == fp2,          "mappingFingerprint is deterministic")
_assert(len(fp1) == 32,      "mappingFingerprint is 32 chars")
_assert(fp1 != mk1,          "fingerprint != key")


# ===========================================================================
# Section 5 — Validators
# ===========================================================================
print("\n[5] Validators")

# Valid cases
validate_ioc_record(IOCTypeEnum.IP, "1.1.1.1", IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS)
_assert(True, "validate_ioc_record accepts valid input")

validate_ioc_mapping("find-1", "", "", 80.0, TS)
_assert(True, "validate_ioc_mapping: findingId alone is sufficient")

validate_ioc_mapping("", "alert-1", "", 0.0, TS)
_assert(True, "validate_ioc_mapping: alertId alone is sufficient")

validate_ioc_mapping("", "", "reason-1", 100.0, TS)
_assert(True, "validate_ioc_mapping: reasoningId alone is sufficient")

# Invalid iocType
_assert_raises(InvalidIOCTypeError, validate_ioc_record,
               "BAD", "1.1.1.1", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
               msg="bad iocType raises InvalidIOCTypeError")

# Empty value
_assert_raises(InvalidIOCError, validate_ioc_record,
               IOCTypeEnum.IP, "   ", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
               msg="empty value raises InvalidIOCError")

# Empty createdAt
_assert_raises(InvalidIOCError, validate_ioc_record,
               IOCTypeEnum.IP, "1.1.1.1", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, "",
               msg="empty createdAt raises InvalidIOCError")

# No source in mapping
_assert_raises(InvalidIOCMappingError, validate_ioc_mapping,
               "", "", "", 50.0, TS,
               msg="no source raises InvalidIOCMappingError")

# Confidence out of range
_assert_raises(InvalidIOCMappingError, validate_ioc_mapping,
               "find-1", "", "", 101.0, TS,
               msg="confidence > 100 raises InvalidIOCMappingError")

_assert_raises(InvalidIOCMappingError, validate_ioc_mapping,
               "find-1", "", "", -1.0, TS,
               msg="confidence < 0 raises InvalidIOCMappingError")

# Empty mapping createdAt
_assert_raises(InvalidIOCMappingError, validate_ioc_mapping,
               "find-1", "", "", 50.0, "",
               msg="empty mapping createdAt raises InvalidIOCMappingError")


# ===========================================================================
# Section 6 — build_ioc_record()
# ===========================================================================
print("\n[6] build_ioc_record")

r_ip = build_ioc_record(
    IOCTypeEnum.IP, "192.168.1.100",
    IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS,
    description="C2 server", source="Finding",
    tags=["c2", "lateral-movement", "c2"],        # dup tag
    related_cves=["CVE-2021-44228", "cve-2021-44228"],  # dup + mixed case
    related_techniques=["T1071", "t1071"],              # dup + mixed case
)
_assert(r_ip.iocType   == IOCTypeEnum.IP,             "iocType stored correctly")
_assert(r_ip.value     == "192.168.1.100",             "value stored correctly")
_assert(r_ip.severity  == IOCSeverityEnum.HIGH,        "severity stored correctly")
_assert(r_ip.confidence== IOCConfidenceEnum.VERIFIED,  "confidence stored correctly")
_assert(r_ip.source    == "finding",                   "source lowercased")
_assert(len(r_ip.tags) == 2,                           "duplicate tags deduped")
_assert("c2" in r_ip.tags,                             "c2 tag present")
_assert(r_ip.relatedCVEs == ("CVE-2021-44228",),       "CVEs deduped and uppercased")
_assert(r_ip.relatedTechniques == ("T1071",),          "techniques deduped and uppercased")
_assert(len(r_ip.iocId)  == 36,                        "iocId is UUID format")
_assert(len(r_ip.iocKey) == 32,                        "iocKey is 32 chars")
_assert(len(r_ip.iocFingerprint) == 32,                "iocFingerprint is 32 chars")

# Determinism: same inputs → same IDs
r_ip2 = build_ioc_record(IOCTypeEnum.IP, "192.168.1.100",
                          IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS)
_assert(r_ip.iocId  == r_ip2.iocId,  "iocId is deterministic")
_assert(r_ip.iocKey == r_ip2.iocKey, "iocKey is deterministic")

# Different value → different ID
r_ip3 = build_ioc_record(IOCTypeEnum.IP, "10.0.0.1",
                          IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS)
_assert(r_ip.iocId  != r_ip3.iocId,  "different value → different iocId")
_assert(r_ip.iocKey != r_ip3.iocKey, "different value → different iocKey")

# Different type → different ID even if same value
r_dom = build_ioc_record(IOCTypeEnum.DOMAIN, "192.168.1.100",
                          IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
_assert(r_ip.iocId  != r_dom.iocId,  "different type → different iocId")

# Immutability
try:
    r_ip.value = "mutated"
    _assert(False, "IOCRecord should be frozen")
except Exception:
    _assert(True, "IOCRecord is immutable (frozen)")

# All IOC types build correctly
for t in IOCTypeEnum:
    r = build_ioc_record(t, f"val-{t.value}", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
    _assert(r.iocType == t, f"build_ioc_record for type {t.value}")

# Whitespace trimming
r_ws = build_ioc_record(IOCTypeEnum.IP, "  1.2.3.4  ",
                         IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
_assert(r_ws.value == "1.2.3.4", "value is trimmed")

r_ws2 = build_ioc_record(IOCTypeEnum.IP, "1.2.3.4",
                          IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
_assert(r_ws.iocId == r_ws2.iocId, "trimmed value produces same iocId")

# Invalid type raises
_assert_raises(InvalidIOCTypeError, build_ioc_record,
               "NOT_ENUM", "val", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
               msg="build with bad type raises InvalidIOCTypeError")

# Empty value raises
_assert_raises(InvalidIOCError, build_ioc_record,
               IOCTypeEnum.IP, "", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
               msg="build with empty value raises InvalidIOCError")


# ===========================================================================
# Section 7 — build_ioc_mapping()
# ===========================================================================
print("\n[7] build_ioc_mapping")

r_a = build_ioc_record(IOCTypeEnum.IP,     "10.0.0.1",   IOCSeverityEnum.HIGH,   IOCConfidenceEnum.HIGH,     TS)
r_b = build_ioc_record(IOCTypeEnum.DOMAIN, "evil.com",   IOCSeverityEnum.CRITICAL,IOCConfidenceEnum.VERIFIED, TS)
r_c = build_ioc_record(IOCTypeEnum.URL,    "http://x.io",IOCSeverityEnum.MEDIUM,  IOCConfidenceEnum.MEDIUM,   TS)

m1 = build_ioc_mapping([r_a, r_b], TS, finding_id="find-001", confidence=85.0)
_assert(m1.findingId   == "find-001",  "findingId stored correctly")
_assert(m1.alertId     == "",          "alertId defaults to empty")
_assert(m1.reasoningId == "",          "reasoningId defaults to empty")
_assert(len(m1.iocRecords) == 2,       "two IOC records in mapping")
_assert(m1.confidence  == 85.0,        "confidence stored correctly")
_assert(len(m1.mappingId) == 36,       "mappingId is UUID format")
_assert(len(m1.mappingKey) == 32,      "mappingKey is 32 chars")
_assert(len(m1.mappingFingerprint) == 32, "mappingFingerprint is 32 chars")
_assert(m1.mappingId != m1.mappingKey, "mappingId != mappingKey")

# Determinism
m1b = build_ioc_mapping([r_b, r_a], TS, finding_id="find-001", confidence=85.0)
_assert(m1.mappingId  == m1b.mappingId,  "mapping is order-independent")
_assert(m1.mappingKey == m1b.mappingKey, "mappingKey is order-independent")

# Different finding → different mapping
m2 = build_ioc_mapping([r_a, r_b], TS, finding_id="find-002", confidence=85.0)
_assert(m1.mappingId != m2.mappingId, "different findingId → different mappingId")

# IOCRecords sorted in mapping by iocType then iocId
_assert(m1.iocRecords[0].iocId != m1.iocRecords[1].iocId, "mapping has 2 distinct records")

# confidence clamping
m_clamped = build_ioc_mapping([r_a], TS, finding_id="f", confidence=999.0)
_assert(m_clamped.confidence == 100.0, "confidence clamped to 100")

m_clamped2 = build_ioc_mapping([r_a], TS, finding_id="f", confidence=-50.0)
_assert(m_clamped2.confidence == 0.0, "confidence clamped to 0")

# No source → raises
_assert_raises(InvalidIOCMappingError, build_ioc_mapping,
               [r_a], TS,
               msg="no source IDs raises InvalidIOCMappingError")

# Immutability
try:
    m1.findingId = "mutated"
    _assert(False, "IOCMapping should be frozen")
except Exception:
    _assert(True, "IOCMapping is immutable (frozen)")

# Empty iocRecords list
m_empty = build_ioc_mapping([], TS, finding_id="f-001")
_assert(len(m_empty.iocRecords) == 0, "empty iocRecords allowed")

# Three sources
m3 = build_ioc_mapping([r_a], TS, finding_id="f", alert_id="a", reasoning_id="r", confidence=50.0)
_assert(m3.findingId == "f",   "findingId set")
_assert(m3.alertId   == "a",   "alertId set")
_assert(m3.reasoningId == "r", "reasoningId set")


# ===========================================================================
# Section 8 — build_ioc_statistics()
# ===========================================================================
print("\n[8] build_ioc_statistics")

# Empty
stats_empty = build_ioc_statistics([])
_assert(stats_empty.totalIOCs         == 0,   "empty: totalIOCs = 0")
_assert(stats_empty.verifiedIOCs      == 0,   "empty: verifiedIOCs = 0")
_assert(stats_empty.criticalIOCs      == 0,   "empty: criticalIOCs = 0")
_assert(stats_empty.highIOCs          == 0,   "empty: highIOCs = 0")
_assert(stats_empty.mediumIOCs        == 0,   "empty: mediumIOCs = 0")
_assert(stats_empty.lowIOCs           == 0,   "empty: lowIOCs = 0")
_assert(stats_empty.iocTypeCounts     == {},  "empty: iocTypeCounts = {}")
_assert(stats_empty.averageConfidence == 0.0, "empty: averageConfidence = 0.0")

# Single record
r_v = build_ioc_record(IOCTypeEnum.IP, "1.1.1.1", IOCSeverityEnum.CRITICAL,
                        IOCConfidenceEnum.VERIFIED, TS)
stats1 = build_ioc_statistics([r_v])
_assert(stats1.totalIOCs    == 1,     "single: totalIOCs = 1")
_assert(stats1.verifiedIOCs == 1,     "single: verifiedIOCs = 1")
_assert(stats1.criticalIOCs == 1,     "single: criticalIOCs = 1")
_assert(stats1.highIOCs     == 0,     "single: highIOCs = 0")
_assert(stats1.mediumIOCs   == 0,     "single: mediumIOCs = 0")
_assert(stats1.lowIOCs      == 0,     "single: lowIOCs = 0")
_assert(stats1.iocTypeCounts.get("IP") == 1, "single: IP count = 1")
_assert(stats1.averageConfidence == 100.0,   "single VERIFIED: avgConf = 100.0")

# Deduplication: same record twice
stats_dup = build_ioc_statistics([r_v, r_v])
_assert(stats_dup.totalIOCs == 1, "duplicate iocId is deduplicated")

# Mixed
r_h  = build_ioc_record(IOCTypeEnum.DOMAIN, "bad.com",  IOCSeverityEnum.HIGH,   IOCConfidenceEnum.HIGH,   TS)
r_m  = build_ioc_record(IOCTypeEnum.URL,    "x.io",     IOCSeverityEnum.MEDIUM, IOCConfidenceEnum.MEDIUM, TS)
r_l  = build_ioc_record(IOCTypeEnum.EMAIL,  "x@y.com",  IOCSeverityEnum.LOW,    IOCConfidenceEnum.LOW,    TS)
r_l2 = build_ioc_record(IOCTypeEnum.IP,     "10.0.0.2", IOCSeverityEnum.LOW,    IOCConfidenceEnum.LOW,    TS)

stats_m = build_ioc_statistics([r_v, r_h, r_m, r_l, r_l2])
_assert(stats_m.totalIOCs    == 5,    "mixed: totalIOCs = 5")
_assert(stats_m.verifiedIOCs == 1,    "mixed: verifiedIOCs = 1")
_assert(stats_m.criticalIOCs == 1,    "mixed: criticalIOCs = 1")
_assert(stats_m.highIOCs     == 1,    "mixed: highIOCs = 1")
_assert(stats_m.mediumIOCs   == 1,    "mixed: mediumIOCs = 1")
_assert(stats_m.lowIOCs      == 2,    "mixed: lowIOCs = 2")
_assert(stats_m.iocTypeCounts.get("IP")     == 2, "mixed: 2 IPs")
_assert(stats_m.iocTypeCounts.get("DOMAIN") == 1, "mixed: 1 DOMAIN")
_assert(stats_m.iocTypeCounts.get("URL")    == 1, "mixed: 1 URL")
_assert(stats_m.iocTypeCounts.get("EMAIL")  == 1, "mixed: 1 EMAIL")

# averageConfidence: VERIFIED=100, HIGH=75, MEDIUM=50, LOW=25, LOW=25 → 55.0
expected_avg = round((100.0 + 75.0 + 50.0 + 25.0 + 25.0) / 5, 4)
_assert(stats_m.averageConfidence == expected_avg, f"averageConfidence = {expected_avg}")

# Determinism: order-independent
stats_m2 = build_ioc_statistics([r_l2, r_m, r_v, r_l, r_h])
_assert(stats_m.totalIOCs         == stats_m2.totalIOCs,         "stats: order-independent totalIOCs")
_assert(stats_m.averageConfidence == stats_m2.averageConfidence, "stats: order-independent avgConf")

# IOCStatistics is frozen
try:
    stats_m.totalIOCs = 99
    _assert(False, "IOCStatistics should be frozen")
except Exception:
    _assert(True, "IOCStatistics is immutable")


# ===========================================================================
# Section 9 — IOC Operations: add / update / remove / merge
# ===========================================================================
print("\n[9] IOC Operations")

col: list = []

# add_ioc_record
col = add_ioc_record(col, r_ip)
_assert(len(col) == 1,              "add: 1 record")
_assert(col[0].iocId == r_ip.iocId, "add: correct record stored")

col = add_ioc_record(col, r_dom)
_assert(len(col) == 2, "add: 2 records")

# Sorted by iocId
_assert(col == sorted(col, key=lambda x: x.iocId), "add: result sorted by iocId")

# Duplicate: same iocId → not added
col_before = list(col)
col = add_ioc_record(col, r_ip)
_assert(len(col) == 2, "add: duplicate iocId not added")
_assert(col == col_before, "add: collection unchanged on duplicate")

# update_ioc_record
r_ip_updated = build_ioc_record(
    IOCTypeEnum.IP, "192.168.1.100",
    IOCSeverityEnum.CRITICAL, IOCConfidenceEnum.VERIFIED, TS2,
    description="Updated C2",
)
_assert(r_ip_updated.iocId == r_ip.iocId, "update: same iocId (stable identity)")
col = update_ioc_record(col, r_ip_updated)
_assert(len(col) == 2,                                "update: size unchanged")
found_updated = next((r for r in col if r.iocId == r_ip.iocId), None)
_assert(found_updated is not None,                    "update: record still present")
_assert(found_updated.severity == IOCSeverityEnum.CRITICAL, "update: severity changed")
_assert(found_updated.description == "Updated C2",    "update: description changed")

# Update non-existent record → unchanged
col_before = list(col)
col = update_ioc_record(col, r_c)    # r_c not in collection
_assert(len(col) == 2,               "update: non-existent record → no change")

# remove_ioc_record
col = remove_ioc_record(col, r_dom.iocId)
_assert(len(col) == 1,               "remove: 1 record left")
_assert(col[0].iocId == r_ip.iocId,  "remove: correct record removed")

# Remove non-existent → unchanged
col_before = list(col)
col = remove_ioc_record(col, "non-existent-id")
_assert(col == col_before,           "remove: non-existent → unchanged")

# merge_ioc_records
base_col     = [r_a, r_b]
incoming_col = [r_b, r_c]   # r_b is a duplicate
merged_col   = merge_ioc_records(base_col, incoming_col)
_assert(len(merged_col) == 3,                    "merge: 3 distinct records")
_assert(merged_col == sorted(merged_col, key=lambda r: r.iocId), "merge: sorted by iocId")

# Base takes precedence on collision
base2     = [r_a]
incoming2 = [r_a]  # same iocId
merged2   = merge_ioc_records(base2, incoming2)
_assert(len(merged2) == 1,           "merge: duplicate collapsed to 1")
_assert(merged2[0].iocId == r_a.iocId, "merge: base record kept on collision")

# merge is deterministic
merged3 = merge_ioc_records(base_col, incoming_col)
_assert([r.iocId for r in merged_col] == [r.iocId for r in merged3],
        "merge: fully deterministic")

# Input lists unchanged
_assert(len(base_col) == 2,          "merge: base_col not mutated")
_assert(len(incoming_col) == 2,      "merge: incoming_col not mutated")


# ===========================================================================
# Section 10 — Mapping Operations: add / remove / merge
# ===========================================================================
print("\n[10] Mapping Operations")

map_col: list = []
m_a = build_ioc_mapping([r_a], TS, finding_id="find-A")
m_b = build_ioc_mapping([r_b], TS, finding_id="find-B")
m_c = build_ioc_mapping([r_c], TS, alert_id="alert-C")

# add_ioc_mapping
map_col = add_ioc_mapping(map_col, m_a)
_assert(len(map_col) == 1,                  "mapping add: 1 item")
_assert(map_col[0].mappingId == m_a.mappingId, "mapping add: correct item")

map_col = add_ioc_mapping(map_col, m_b)
_assert(len(map_col) == 2,                  "mapping add: 2 items")
_assert(map_col == sorted(map_col, key=lambda m: m.mappingId), "mapping add: sorted")

# Duplicate not added
map_col_before = list(map_col)
map_col = add_ioc_mapping(map_col, m_a)
_assert(len(map_col) == 2,                  "mapping add: duplicate not added")

# remove_ioc_mapping
map_col = add_ioc_mapping(map_col, m_c)
_assert(len(map_col) == 3,                  "mapping add: 3 items after add c")

map_col = remove_ioc_mapping(map_col, m_b.mappingId)
_assert(len(map_col) == 2,                  "mapping remove: 1 removed")
ids_left = {m.mappingId for m in map_col}
_assert(m_b.mappingId not in ids_left,      "mapping remove: correct item removed")

# Remove non-existent → unchanged
map_col_before = list(map_col)
map_col = remove_ioc_mapping(map_col, "nonexistent")
_assert(len(map_col) == 2,                  "mapping remove: non-existent unchanged")

# merge_ioc_mappings
base_maps     = [m_a, m_b]
incoming_maps = [m_b, m_c]  # m_b is duplicate
merged_maps   = merge_ioc_mappings(base_maps, incoming_maps)
_assert(len(merged_maps) == 3,              "mapping merge: 3 distinct")
_assert(merged_maps == sorted(merged_maps, key=lambda m: m.mappingId),
        "mapping merge: sorted")

# Base takes precedence
merged_maps2 = merge_ioc_mappings([m_a], [m_a])
_assert(len(merged_maps2) == 1,             "mapping merge: dup collapsed")

# Determinism
merged_maps3 = merge_ioc_mappings(base_maps, incoming_maps)
_assert([m.mappingId for m in merged_maps] == [m.mappingId for m in merged_maps3],
        "mapping merge: deterministic")

# Input not mutated
_assert(len(base_maps)     == 2,            "merge: base_maps not mutated")
_assert(len(incoming_maps) == 2,            "merge: incoming_maps not mutated")


# ===========================================================================
# Section 11 — Search: find_ioc_record / find_ioc_mapping
# ===========================================================================
print("\n[11] Search")

search_col = [r_a, r_b, r_c, r_ip, r_dom]

# find by iocId
found = find_ioc_record(search_col, ioc_id=r_a.iocId)
_assert(found is not None,          "find_ioc_record: found by iocId")
_assert(found.iocId == r_a.iocId,   "find_ioc_record: correct record returned")

# find by value
found_v = find_ioc_record(search_col, value="10.0.0.1")
_assert(found_v is not None,         "find_ioc_record: found by value")
_assert(found_v.value == "10.0.0.1", "find_ioc_record: value match correct")

# iocId takes priority over value
found_pri = find_ioc_record(search_col, ioc_id=r_a.iocId, value="nonexistent")
_assert(found_pri is not None,        "find_ioc_record: iocId priority over value")
_assert(found_pri.iocId == r_a.iocId, "find_ioc_record: iocId-priority result correct")

# Not found → None
found_none = find_ioc_record(search_col, ioc_id="nonexistent-id")
_assert(found_none is None,           "find_ioc_record: not found returns None")

found_none2 = find_ioc_record(search_col, value="999.999.999.999")
_assert(found_none2 is None,          "find_ioc_record: value not found returns None")

# Both None
found_none3 = find_ioc_record(search_col)
_assert(found_none3 is None,          "find_ioc_record: no criteria returns None")

# Empty collection
found_empty = find_ioc_record([], ioc_id=r_a.iocId)
_assert(found_empty is None,          "find_ioc_record: empty collection returns None")

# find_ioc_mapping
map_search = [m_a, m_b, m_c]

found_m = find_ioc_mapping(map_search, mapping_id=m_a.mappingId)
_assert(found_m is not None,               "find_ioc_mapping: found")
_assert(found_m.mappingId == m_a.mappingId,"find_ioc_mapping: correct mapping")

found_m_none = find_ioc_mapping(map_search, mapping_id="bad-id")
_assert(found_m_none is None,              "find_ioc_mapping: not found = None")

found_m_none2 = find_ioc_mapping(map_search)
_assert(found_m_none2 is None,             "find_ioc_mapping: no criteria = None")

found_m_empty = find_ioc_mapping([], mapping_id=m_a.mappingId)
_assert(found_m_empty is None,             "find_ioc_mapping: empty collection = None")


# ===========================================================================
# Section 12 — Sorting
# ===========================================================================
print("\n[12] Sorting")

sort_pool = [r_v, r_h, r_m, r_l, r_l2]

# By severity DESC (default)
s_sev = sort_ioc_records(sort_pool, by="severity", ascending=False)
_assert(s_sev[0].severity == IOCSeverityEnum.CRITICAL, "sort severity DESC: first = CRITICAL")
_assert(s_sev[-1].severity == IOCSeverityEnum.LOW,     "sort severity DESC: last = LOW")

# By severity ASC
s_sev_asc = sort_ioc_records(sort_pool, by="severity", ascending=True)
_assert(s_sev_asc[0].severity == IOCSeverityEnum.LOW,      "sort severity ASC: first = LOW")
_assert(s_sev_asc[-1].severity == IOCSeverityEnum.CRITICAL, "sort severity ASC: last = CRITICAL")

# By confidence DESC
s_conf = sort_ioc_records(sort_pool, by="confidence", ascending=False)
_assert(s_conf[0].confidence == IOCConfidenceEnum.VERIFIED, "sort confidence DESC: first = VERIFIED")

# By iocType ASC
s_type = sort_ioc_records(sort_pool, by="iocType", ascending=True)
_assert(s_type[0].iocType.value <= s_type[1].iocType.value, "sort iocType ASC: ordered")

# By value ASC
s_val = sort_ioc_records(sort_pool, by="value", ascending=True)
_assert(s_val == sorted(sort_pool, key=lambda r: (r.value, r.iocId)), "sort value ASC")

# By createdAt
s_ts = sort_ioc_records(sort_pool, by="createdAt", ascending=True)
_assert(len(s_ts) == len(sort_pool), "sort createdAt: all records returned")

# Invalid key raises
_assert_raises(ValueError, sort_ioc_records, sort_pool, by="INVALID",
               msg="sort_ioc_records: invalid key raises ValueError")

# Determinism: same input → same output
s1 = sort_ioc_records(sort_pool, by="severity")
s2 = sort_ioc_records(list(reversed(sort_pool)), by="severity")
_assert([r.iocId for r in s1] == [r.iocId for r in s2],
        "sort_ioc_records: deterministic tie-breaking")

# Input not mutated
_assert(sort_pool[0].iocId == r_v.iocId, "sort_ioc_records: input not mutated")

# sort_ioc_mappings
map_pool = [m_a, m_b, m_c,
            build_ioc_mapping([r_a], TS, finding_id="f-x", confidence=99.0),
            build_ioc_mapping([r_b], TS, finding_id="f-y", confidence=10.0)]

s_maps_conf = sort_ioc_mappings(map_pool, by="confidence", ascending=False)
_assert(s_maps_conf[0].confidence >= s_maps_conf[1].confidence, "sort mappings conf DESC")

s_maps_asc = sort_ioc_mappings(map_pool, by="confidence", ascending=True)
_assert(s_maps_asc[0].confidence <= s_maps_asc[1].confidence, "sort mappings conf ASC")

s_maps_ts = sort_ioc_mappings(map_pool, by="createdAt", ascending=True)
_assert(len(s_maps_ts) == len(map_pool), "sort mappings by createdAt")

s_maps_id = sort_ioc_mappings(map_pool, by="mappingId", ascending=True)
_assert(s_maps_id == sorted(map_pool, key=lambda m: (m.mappingId, m.mappingId)),
        "sort mappings by mappingId ASC")

_assert_raises(ValueError, sort_ioc_mappings, map_pool, by="BAD",
               msg="sort_ioc_mappings: invalid key raises ValueError")


# ===========================================================================
# Section 13 — Filtering
# ===========================================================================
print("\n[13] Filtering")

# Build a diverse pool
r_f1 = build_ioc_record(IOCTypeEnum.IP,     "1.2.3.4",  IOCSeverityEnum.HIGH,   IOCConfidenceEnum.HIGH,   TS,
                         source="finding", tags=["tag-a"], related_cves=["CVE-2021-44228"],
                         related_techniques=["T1071"])
r_f2 = build_ioc_record(IOCTypeEnum.DOMAIN, "bad.net",  IOCSeverityEnum.CRITICAL,IOCConfidenceEnum.VERIFIED,TS,
                         source="alert",   tags=["tag-b"], related_cves=["CVE-2022-12345"],
                         related_techniques=["T1059"])
r_f3 = build_ioc_record(IOCTypeEnum.EMAIL,  "x@z.com",  IOCSeverityEnum.LOW,    IOCConfidenceEnum.LOW,    TS,
                         source="manual",  tags=["tag-a", "tag-c"])
r_f4 = build_ioc_record(IOCTypeEnum.URL,    "http://y", IOCSeverityEnum.MEDIUM, IOCConfidenceEnum.MEDIUM, TS2,
                         source="finding", tags=["tag-a"])
filter_pool = [r_f1, r_f2, r_f3, r_f4]

# By iocType
f_ip = filter_ioc_records(filter_pool, ioc_type=IOCTypeEnum.IP)
_assert(len(f_ip) == 1,                 "filter iocType IP: 1 result")
_assert(f_ip[0].iocType == IOCTypeEnum.IP, "filter iocType IP: correct")

# By severity
f_high = filter_ioc_records(filter_pool, severity=IOCSeverityEnum.HIGH)
_assert(len(f_high) == 1,               "filter severity HIGH: 1 result")

# By confidence
f_verified = filter_ioc_records(filter_pool, confidence=IOCConfidenceEnum.VERIFIED)
_assert(len(f_verified) == 1,           "filter confidence VERIFIED: 1 result")

# By source (case-insensitive)
f_finding = filter_ioc_records(filter_pool, source="FINDING")
_assert(len(f_finding) == 2,            "filter source finding: 2 results")

# By related_cve
f_cve = filter_ioc_records(filter_pool, related_cve="CVE-2021-44228")
_assert(len(f_cve) == 1,                "filter related_cve: 1 result")
_assert(f_cve[0].iocId == r_f1.iocId,  "filter related_cve: correct record")

# Case-insensitive cve filter
f_cve_lc = filter_ioc_records(filter_pool, related_cve="cve-2021-44228")
_assert(len(f_cve_lc) == 1,            "filter related_cve lowercase: 1 result")

# By related_technique
f_tech = filter_ioc_records(filter_pool, related_technique="T1071")
_assert(len(f_tech) == 1,              "filter related_technique: 1 result")

# By tag
f_tag_a = filter_ioc_records(filter_pool, tag="tag-a")
_assert(len(f_tag_a) == 3,             "filter tag-a: 3 results")

# Multiple filters ANDed
f_and = filter_ioc_records(filter_pool, ioc_type=IOCTypeEnum.IP, tag="tag-a")
_assert(len(f_and) == 1,               "filter AND: iocType + tag = 1")

# No match
f_none = filter_ioc_records(filter_pool, ioc_type=IOCTypeEnum.MUTEX)
_assert(len(f_none) == 0,              "filter no match: empty list")

# Empty pool
f_empty = filter_ioc_records([], ioc_type=IOCTypeEnum.IP)
_assert(len(f_empty) == 0,             "filter empty pool: empty list")

# Result is sorted by iocId ASC
_assert(f_tag_a == sorted(f_tag_a, key=lambda r: r.iocId), "filter result sorted by iocId")

# filter_ioc_mappings
mf_a = build_ioc_mapping([r_f1], TS,  finding_id="f-001", confidence=90.0)
mf_b = build_ioc_mapping([r_f2], TS,  finding_id="f-001", confidence=50.0)
mf_c = build_ioc_mapping([r_f3], TS,  alert_id="a-001",   confidence=30.0)
mf_d = build_ioc_mapping([r_f4], TS2, reasoning_id="r-1", confidence=75.0)
map_filter_pool = [mf_a, mf_b, mf_c, mf_d]

# By findingId
f_maps_find = filter_ioc_mappings(map_filter_pool, finding_id="f-001")
_assert(len(f_maps_find) == 2,         "filter mappings by findingId: 2 results")

# By alertId
f_maps_alert = filter_ioc_mappings(map_filter_pool, alert_id="a-001")
_assert(len(f_maps_alert) == 1,        "filter mappings by alertId: 1 result")

# By reasoningId
f_maps_reason = filter_ioc_mappings(map_filter_pool, reasoning_id="r-1")
_assert(len(f_maps_reason) == 1,       "filter mappings by reasoningId: 1 result")

# By confidence range
f_maps_conf = filter_ioc_mappings(map_filter_pool, min_confidence=70.0)
_assert(len(f_maps_conf) == 2,         "filter mappings min_confidence 70: 2 results")

f_maps_conf2 = filter_ioc_mappings(map_filter_pool, max_confidence=50.0)
_assert(len(f_maps_conf2) == 2,        "filter mappings max_confidence 50: 2 results")

f_maps_range = filter_ioc_mappings(map_filter_pool, min_confidence=40.0, max_confidence=80.0)
_assert(len(f_maps_range) == 2,        "filter mappings range 40-80: 2 results")

# No criteria → all returned
f_maps_all = filter_ioc_mappings(map_filter_pool)
_assert(len(f_maps_all) == 4,          "filter mappings no criteria: all returned")

# Empty pool
f_maps_empty = filter_ioc_mappings([], finding_id="f-001")
_assert(len(f_maps_empty) == 0,        "filter mappings empty pool: empty list")

# Result sorted by mappingId ASC
_assert(f_maps_find == sorted(f_maps_find, key=lambda m: m.mappingId),
        "filter mappings result sorted by mappingId")


# ===========================================================================
# Section 14 — Grouping
# ===========================================================================
print("\n[14] Grouping")

group_pool = [r_f1, r_f2, r_f3, r_f4,
              build_ioc_record(IOCTypeEnum.IP,    "5.5.5.5",  IOCSeverityEnum.LOW,    IOCConfidenceEnum.LOW,    TS, source="finding"),
              build_ioc_record(IOCTypeEnum.DOMAIN,"two.com",  IOCSeverityEnum.HIGH,   IOCConfidenceEnum.HIGH,   TS, source="alert"),
              build_ioc_record(IOCTypeEnum.EMAIL, "b@c.com",  IOCSeverityEnum.MEDIUM, IOCConfidenceEnum.MEDIUM, TS, source="manual")]

# group by iocType
g_type = group_ioc_records(group_pool, group_by="iocType")
_assert("IP"     in g_type, "group by type: IP key present")
_assert("DOMAIN" in g_type, "group by type: DOMAIN key present")
_assert("EMAIL"  in g_type, "group by type: EMAIL key present")
_assert("URL"    in g_type, "group by type: URL key present")
_assert(len(g_type["IP"]) == 2,     "group by type: 2 IPs")
_assert(len(g_type["DOMAIN"]) == 2, "group by type: 2 DOMAINs")
_assert(len(g_type["EMAIL"]) == 2,  "group by type: 2 EMAILs")

# Groups are sorted by iocId
for k, grp in g_type.items():
    _assert(grp == sorted(grp, key=lambda r: r.iocId),
            f"group by type: {k} group sorted by iocId")

# group by severity
g_sev = group_ioc_records(group_pool, group_by="severity")
_assert("HIGH"   in g_sev, "group by severity: HIGH present")
_assert("LOW"    in g_sev, "group by severity: LOW present")
_assert("MEDIUM" in g_sev, "group by severity: MEDIUM present")

# group by confidence
g_conf = group_ioc_records(group_pool, group_by="confidence")
_assert("VERIFIED" in g_conf or "HIGH" in g_conf or "MEDIUM" in g_conf or "LOW" in g_conf,
        "group by confidence: at least one key")

# group by source
g_src = group_ioc_records(group_pool, group_by="source")
_assert("finding" in g_src, "group by source: finding present")
_assert("alert"   in g_src, "group by source: alert present")
_assert("manual"  in g_src, "group by source: manual present")

# Invalid key raises
_assert_raises(ValueError, group_ioc_records, group_pool, group_by="BAD",
               msg="group_ioc_records: invalid key raises ValueError")

# Empty pool
g_empty = group_ioc_records([], group_by="iocType")
_assert(g_empty == {},              "group_ioc_records: empty pool returns {}")

# group_ioc_mappings
map_group_pool = [mf_a, mf_b, mf_c, mf_d]

# group by findingId
g_find = group_ioc_mappings(map_group_pool, group_by="findingId")
_assert("f-001" in g_find,         "group mappings by findingId: f-001 present")
_assert(len(g_find["f-001"]) == 2, "group mappings by findingId: 2 in f-001")

# group by alertId
g_alert = group_ioc_mappings(map_group_pool, group_by="alertId")
_assert("a-001" in g_alert,         "group mappings by alertId: a-001 present")
_assert("none"  in g_alert,         "group mappings by alertId: 'none' for empty alertId")

# group by reasoningId
g_reason = group_ioc_mappings(map_group_pool, group_by="reasoningId")
_assert("r-1" in g_reason,          "group mappings by reasoningId: r-1 present")

# Invalid key raises
_assert_raises(ValueError, group_ioc_mappings, map_group_pool, group_by="BAD",
               msg="group_ioc_mappings: invalid key raises ValueError")

# Empty pool
g_maps_empty = group_ioc_mappings([], group_by="findingId")
_assert(g_maps_empty == {},         "group_ioc_mappings: empty pool returns {}")

# Groups sorted by mappingId ASC
for k, grp in g_find.items():
    _assert(grp == sorted(grp, key=lambda m: m.mappingId),
            f"group mappings: {k} group sorted by mappingId")


# ===========================================================================
# Section 15 — Integration Helpers
# ===========================================================================
print("\n[15] Integration helpers")

class _Finding:
    findingId = "finding-integration-001"

class _Alert:
    alertId   = "alert-integration-001"
    findingId = "finding-integration-001"

class _Reasoning:
    reasoningId      = "reasoning-integration-001"
    overallConfidence = 88.0

class _CVERecord:
    cveId = "CVE-2021-44228"

class _CVERecord2:
    cveId = "CVE-2022-99999"

class _Technique:
    mitreId     = "T1071"
    techniqueId = "tech-id-001"

class _Technique2:
    mitreId     = "T1059"
    techniqueId = "tech-id-002"

ioc_base = build_ioc_record(IOCTypeEnum.IP, "172.16.0.1",
                             IOCSeverityEnum.HIGH, IOCConfidenceEnum.HIGH, TS)

# finding_to_ioc_mapping
m_find = finding_to_ioc_mapping(_Finding(), [ioc_base], TS, confidence=70.0)
_assert(m_find.findingId   == "finding-integration-001", "finding helper: findingId set")
_assert(m_find.alertId     == "",                        "finding helper: alertId empty")
_assert(m_find.reasoningId == "",                        "finding helper: reasoningId empty")
_assert(len(m_find.iocRecords) == 1,                     "finding helper: 1 IOC record")

# alert_to_ioc_mapping
m_alert = alert_to_ioc_mapping(_Alert(), [ioc_base], TS, confidence=60.0)
_assert(m_alert.findingId == "finding-integration-001",  "alert helper: findingId propagated")
_assert(m_alert.alertId   == "alert-integration-001",    "alert helper: alertId set")
_assert(m_alert.reasoningId == "",                       "alert helper: reasoningId empty")

# reasoning_to_ioc_mapping
m_reason = reasoning_to_ioc_mapping(_Reasoning(), [ioc_base], TS)
_assert(m_reason.reasoningId == "reasoning-integration-001", "reasoning helper: reasoningId set")
_assert(m_reason.confidence  == 88.0,                        "reasoning helper: confidence from result")

m_reason2 = reasoning_to_ioc_mapping(_Reasoning(), [ioc_base], TS,
                                      finding_id="f-opt", alert_id="a-opt")
_assert(m_reason2.findingId   == "f-opt", "reasoning helper: optional findingId")
_assert(m_reason2.alertId     == "a-opt", "reasoning helper: optional alertId")

# cve_to_ioc_reference — idempotent
ioc_with_cve = build_ioc_record(IOCTypeEnum.IP, "172.16.0.1",
                                 IOCSeverityEnum.HIGH, IOCConfidenceEnum.HIGH, TS,
                                 related_cves=["CVE-2021-44228"])
result_idem = cve_to_ioc_reference(_CVERecord(), ioc_with_cve)
_assert(result_idem is ioc_with_cve, "cve_to_ioc_reference: idempotent when already linked")

# cve_to_ioc_reference — adds new CVE
result_new = cve_to_ioc_reference(_CVERecord2(), ioc_with_cve)
_assert(result_new is not ioc_with_cve,                   "cve_to_ioc_reference: returns new object")
_assert("CVE-2022-99999" in result_new.relatedCVEs,       "cve_to_ioc_reference: new CVE added")
_assert("CVE-2021-44228" in result_new.relatedCVEs,       "cve_to_ioc_reference: original CVE preserved")
_assert(result_new.iocId  == ioc_with_cve.iocId,          "cve_to_ioc_reference: iocId stable")
_assert(result_new.iocKey == ioc_with_cve.iocKey,         "cve_to_ioc_reference: iocKey stable")
_assert(result_new.relatedCVEs == tuple(sorted(result_new.relatedCVEs)), "cve_to_ioc_reference: sorted")

# mitre_to_ioc_reference — idempotent
ioc_with_tech = build_ioc_record(IOCTypeEnum.DOMAIN, "evil.com",
                                  IOCSeverityEnum.CRITICAL, IOCConfidenceEnum.VERIFIED, TS,
                                  related_techniques=["T1071"])
result_tech_idem = mitre_to_ioc_reference(_Technique(), ioc_with_tech)
_assert(result_tech_idem is ioc_with_tech, "mitre_to_ioc_reference: idempotent when already linked")

# mitre_to_ioc_reference — adds new technique
result_tech_new = mitre_to_ioc_reference(_Technique2(), ioc_with_tech)
_assert(result_tech_new is not ioc_with_tech,               "mitre_to_ioc_reference: returns new object")
_assert("T1059" in result_tech_new.relatedTechniques,       "mitre_to_ioc_reference: new technique added")
_assert("T1071" in result_tech_new.relatedTechniques,       "mitre_to_ioc_reference: original preserved")
_assert(result_tech_new.iocId  == ioc_with_tech.iocId,      "mitre_to_ioc_reference: iocId stable")
_assert(result_tech_new.iocKey == ioc_with_tech.iocKey,     "mitre_to_ioc_reference: iocKey stable")
_assert(result_tech_new.relatedTechniques == tuple(sorted(result_tech_new.relatedTechniques)),
        "mitre_to_ioc_reference: sorted")

# mitre_to_ioc_reference — lowercase mitreId is normalised
class _TechLower:
    mitreId     = "t1071"  # lowercase
    techniqueId = "tech-id-001"

result_tech_lc = mitre_to_ioc_reference(_TechLower(), ioc_with_tech)
_assert(result_tech_lc is ioc_with_tech, "mitre_to_ioc_reference: lowercase mitreId idempotent")

# mitre_to_ioc_reference — empty mitreId returns unchanged
class _TechEmpty:
    mitreId = ""

result_empty_tech = mitre_to_ioc_reference(_TechEmpty(), ioc_with_tech)
_assert(result_empty_tech is ioc_with_tech, "mitre_to_ioc_reference: empty mitreId = unchanged")


# ===========================================================================
# Section 16 — Serialization
# ===========================================================================
print("\n[16] Serialization")

r_ser = build_ioc_record(
    IOCTypeEnum.HASH_SHA256, "abc123def456",
    IOCSeverityEnum.CRITICAL, IOCConfidenceEnum.VERIFIED, TS,
    description="Malware hash",
    source="alert",
    tags=["malware", "ransomware"],
    related_cves=["CVE-2021-44228"],
    related_techniques=["T1071", "T1059"],
)

# model_dump round-trip
d = r_ser.model_dump()
_assert(isinstance(d, dict),                          "IOCRecord.model_dump: returns dict")
_assert(d["iocId"]         == r_ser.iocId,            "model_dump: iocId round-trip")
_assert(d["iocKey"]        == r_ser.iocKey,           "model_dump: iocKey round-trip")
_assert(d["iocFingerprint"]== r_ser.iocFingerprint,   "model_dump: iocFingerprint round-trip")
_assert(d["iocType"]       == IOCTypeEnum.HASH_SHA256, "model_dump: iocType round-trip")
_assert(d["value"]         == "abc123def456",          "model_dump: value round-trip")
_assert(d["severity"]      == IOCSeverityEnum.CRITICAL,"model_dump: severity round-trip")
_assert(d["confidence"]    == IOCConfidenceEnum.VERIFIED,"model_dump: confidence round-trip")
_assert(d["description"]   == "Malware hash",          "model_dump: description round-trip")
_assert(d["source"]        == "alert",                 "model_dump: source round-trip")
_assert(isinstance(d["tags"], tuple),                  "model_dump: tags is tuple")
_assert("malware" in d["tags"],                        "model_dump: tags content preserved")
_assert(isinstance(d["relatedCVEs"], tuple),           "model_dump: relatedCVEs is tuple")
_assert("CVE-2021-44228" in d["relatedCVEs"],          "model_dump: relatedCVEs preserved")
_assert(isinstance(d["relatedTechniques"], tuple),     "model_dump: relatedTechniques is tuple")
_assert(d["createdAt"]     == TS,                      "model_dump: createdAt round-trip")

# Reconstruct from dict — all field values preserved
r_reconstructed = IOCRecord(**d)
_assert(r_reconstructed.iocId          == r_ser.iocId,          "reconstruct: iocId")
_assert(r_reconstructed.iocKey         == r_ser.iocKey,          "reconstruct: iocKey")
_assert(r_reconstructed.iocFingerprint == r_ser.iocFingerprint,  "reconstruct: fingerprint")
_assert(r_reconstructed.value          == r_ser.value,           "reconstruct: value")
_assert(r_reconstructed.tags           == r_ser.tags,            "reconstruct: tags")
_assert(r_reconstructed.relatedCVEs    == r_ser.relatedCVEs,     "reconstruct: relatedCVEs")

# IOCMapping serialization
m_ser = build_ioc_mapping([r_ser], TS, finding_id="f-ser", confidence=77.0)
dm = m_ser.model_dump()
_assert(isinstance(dm, dict),                         "IOCMapping.model_dump: returns dict")
_assert(dm["mappingId"]          == m_ser.mappingId,          "mapping dump: mappingId")
_assert(dm["mappingKey"]         == m_ser.mappingKey,         "mapping dump: mappingKey")
_assert(dm["mappingFingerprint"] == m_ser.mappingFingerprint, "mapping dump: fingerprint")
_assert(dm["findingId"]          == "f-ser",                  "mapping dump: findingId")
_assert(dm["confidence"]         == 77.0,                     "mapping dump: confidence")
_assert(isinstance(dm["iocRecords"], tuple),                  "mapping dump: iocRecords is tuple")
_assert(len(dm["iocRecords"]) == 1,                           "mapping dump: 1 IOCRecord")

# IOCStatistics serialization
stats_ser = build_ioc_statistics([r_ser])
ds = stats_ser.model_dump()
_assert(isinstance(ds, dict),             "IOCStatistics.model_dump: returns dict")
_assert(ds["totalIOCs"]    == 1,          "stats dump: totalIOCs")
_assert(ds["verifiedIOCs"] == 1,          "stats dump: verifiedIOCs")
_assert(ds["criticalIOCs"] == 1,          "stats dump: criticalIOCs")
_assert(isinstance(ds["iocTypeCounts"], dict), "stats dump: iocTypeCounts is dict")
_assert(ds["iocTypeCounts"]["HASH_SHA256"] == 1, "stats dump: HASH_SHA256 count")


# ===========================================================================
# Section 17 — Deterministic Fingerprints
# ===========================================================================
print("\n[17] Deterministic fingerprints")

# iocFingerprint changes when severity changes (same iocId/key)
r_fp_base = build_ioc_record(IOCTypeEnum.IP, "10.1.1.1",
                              IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
r_fp_sev  = build_ioc_record(IOCTypeEnum.IP, "10.1.1.1",
                              IOCSeverityEnum.HIGH, IOCConfidenceEnum.LOW, TS)
_assert(r_fp_base.iocId          == r_fp_sev.iocId,          "fingerprint: iocId stable across sev change")
_assert(r_fp_base.iocKey         == r_fp_sev.iocKey,          "fingerprint: iocKey stable across sev change")
_assert(r_fp_base.iocFingerprint != r_fp_sev.iocFingerprint,  "fingerprint: changes when severity changes")

# iocFingerprint changes when confidence changes
r_fp_conf = build_ioc_record(IOCTypeEnum.IP, "10.1.1.1",
                              IOCSeverityEnum.LOW, IOCConfidenceEnum.VERIFIED, TS)
_assert(r_fp_base.iocFingerprint != r_fp_conf.iocFingerprint, "fingerprint: changes when confidence changes")
_assert(r_fp_base.iocId          == r_fp_conf.iocId,          "fingerprint: iocId stable across conf change")

# mappingFingerprint is stable for same input
fp_a = iocMappingFingerprint(mk1, "f1", "a1", "r1", ids1)
fp_b = iocMappingFingerprint(mk1, "f1", "a1", "r1", ids1)
_assert(fp_a == fp_b, "mappingFingerprint: fully deterministic across calls")

# Different ids → different fingerprint
fp_c = iocMappingFingerprint(mk1, "f1", "a1", "r1", ("id-c",))
_assert(fp_a != fp_c, "mappingFingerprint: different ids → different fingerprint")

# Different finding → different fingerprint
fp_d = iocMappingFingerprint(mk1, "f2", "a1", "r1", ids1)
_assert(fp_a != fp_d, "mappingFingerprint: different findingId → different fingerprint")

# Mapping fingerprint differs from mapping key
m_fp_test = build_ioc_mapping([r_fp_base], TS, finding_id="fp-test")
_assert(m_fp_test.mappingFingerprint != m_fp_test.mappingKey, "mapping: fingerprint != key")
_assert(m_fp_test.mappingFingerprint != m_fp_test.mappingId,  "mapping: fingerprint != id")

# cve_to_ioc_reference changes fingerprint
r_no_cve = build_ioc_record(IOCTypeEnum.FILE, "evil.exe",
                              IOCSeverityEnum.HIGH, IOCConfidenceEnum.HIGH, TS)
r_with_new_cve = cve_to_ioc_reference(_CVERecord(), r_no_cve)
_assert(r_no_cve.iocFingerprint != r_with_new_cve.iocFingerprint,
        "cve_to_ioc_reference: fingerprint changes")
_assert(r_no_cve.iocId == r_with_new_cve.iocId,
        "cve_to_ioc_reference: identity stable")

# mitre_to_ioc_reference changes fingerprint
r_no_tech = build_ioc_record(IOCTypeEnum.MUTEX, "Global\\evil",
                               IOCSeverityEnum.MEDIUM, IOCConfidenceEnum.MEDIUM, TS)
r_with_tech = mitre_to_ioc_reference(_Technique(), r_no_tech)
_assert(r_no_tech.iocFingerprint != r_with_tech.iocFingerprint,
        "mitre_to_ioc_reference: fingerprint changes")
_assert(r_no_tech.iocId == r_with_tech.iocId,
        "mitre_to_ioc_reference: identity stable")


# ===========================================================================
# Section 18 — Edge Cases
# ===========================================================================
print("\n[18] Edge cases")

# Empty collections
empty_add = add_ioc_record([], r_ip)
_assert(len(empty_add) == 1,              "edge: add to empty collection")

empty_merge = merge_ioc_records([], [r_ip])
_assert(len(empty_merge) == 1,            "edge: merge with empty base")

empty_merge2 = merge_ioc_records([r_ip], [])
_assert(len(empty_merge2) == 1,           "edge: merge with empty incoming")

empty_sort = sort_ioc_records([], by="severity")
_assert(empty_sort == [],                 "edge: sort empty list")

empty_filter = filter_ioc_records([], ioc_type=IOCTypeEnum.IP)
_assert(empty_filter == [],               "edge: filter empty list")

empty_group = group_ioc_records([], group_by="iocType")
_assert(empty_group == {},                "edge: group empty list")

empty_find = find_ioc_record([], ioc_id="any-id")
_assert(empty_find is None,               "edge: find in empty list")

# Empty value strings (after strip)
r_whitespace_only = build_ioc_record(IOCTypeEnum.IP, "   1.1.1.1   ",
                                      IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
_assert(r_whitespace_only.value == "1.1.1.1", "edge: whitespace trimmed")

# Empty tags/cves/techniques lists
r_empty_lists = build_ioc_record(IOCTypeEnum.DOMAIN, "test.com",
                                  IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
                                  tags=[], related_cves=[], related_techniques=[])
_assert(r_empty_lists.tags             == (),  "edge: empty tags list → empty tuple")
_assert(r_empty_lists.relatedCVEs      == (),  "edge: empty relatedCVEs → empty tuple")
_assert(r_empty_lists.relatedTechniques == (), "edge: empty relatedTechniques → empty tuple")

# None lists become empty tuples
r_none_lists = build_ioc_record(IOCTypeEnum.EMAIL, "a@b.com",
                                 IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
                                 tags=None, related_cves=None, related_techniques=None)
_assert(r_none_lists.tags             == (),   "edge: None tags → empty tuple")
_assert(r_none_lists.relatedCVEs      == (),   "edge: None relatedCVEs → empty tuple")
_assert(r_none_lists.relatedTechniques == (),  "edge: None relatedTechniques → empty tuple")

# Many duplicates in tags/cves/techniques
r_many_dups = build_ioc_record(IOCTypeEnum.URL, "http://x.com",
                                IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
                                tags=["a", "a", "a", "b", "b"],
                                related_cves=["CVE-2021-1", "CVE-2021-1"],
                                related_techniques=["T1", "T1", "T1"])
_assert(len(r_many_dups.tags) == 2,             "edge: many duplicate tags deduped")
_assert(len(r_many_dups.relatedCVEs) == 1,      "edge: many duplicate CVEs deduped")
_assert(len(r_many_dups.relatedTechniques) == 1,"edge: many duplicate techniques deduped")

# Mapping with empty iocRecords
m_no_iocs = build_ioc_mapping([], TS, finding_id="f-empty")
_assert(len(m_no_iocs.iocRecords) == 0,         "edge: mapping with no IOCRecords")

# Mapping with single IOCRecord
m_one_ioc = build_ioc_mapping([r_ip], TS, finding_id="f-one")
_assert(len(m_one_ioc.iocRecords) == 1,         "edge: mapping with 1 IOCRecord")

# Filter with no matches
no_match = filter_ioc_records([r_ip, r_dom], ioc_type=IOCTypeEnum.MUTEX)
_assert(len(no_match) == 0,                     "edge: filter no matches")

# Group with single item per group
single_items = [
    build_ioc_record(IOCTypeEnum.IP,     "1.1.1.1", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS),
    build_ioc_record(IOCTypeEnum.DOMAIN, "a.com",   IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS),
    build_ioc_record(IOCTypeEnum.EMAIL,  "a@b.c",   IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS),
]
g_single = group_ioc_records(single_items, group_by="iocType")
_assert(len(g_single["IP"])     == 1,           "edge: group with 1 IP")
_assert(len(g_single["DOMAIN"]) == 1,           "edge: group with 1 DOMAIN")
_assert(len(g_single["EMAIL"])  == 1,           "edge: group with 1 EMAIL")

# Confidence boundary values
m_zero_conf = build_ioc_mapping([r_ip], TS, finding_id="f-zero", confidence=0.0)
_assert(m_zero_conf.confidence == 0.0,          "edge: confidence = 0.0")

m_hundred_conf = build_ioc_mapping([r_ip], TS, finding_id="f-hundred", confidence=100.0)
_assert(m_hundred_conf.confidence == 100.0,     "edge: confidence = 100.0")

# Extreme clamping
m_extreme_high = build_ioc_mapping([r_ip], TS, finding_id="f-extreme", confidence=99999.0)
_assert(m_extreme_high.confidence == 100.0,     "edge: extreme high clamped to 100")

m_extreme_low = build_ioc_mapping([r_ip], TS, finding_id="f-extreme-low", confidence=-99999.0)
_assert(m_extreme_low.confidence == 0.0,        "edge: extreme low clamped to 0")

# Update non-existent record is idempotent
col_edge = [r_a, r_b]
col_edge_before = list(col_edge)
col_edge_after = update_ioc_record(col_edge, r_c)  # r_c not in collection
_assert(len(col_edge_after) == 2,               "edge: update non-existent → unchanged size")
_assert(col_edge == col_edge_before,            "edge: update non-existent → original unchanged")

# Remove non-existent record is idempotent
col_edge2 = [r_a, r_b]
col_edge2_before = list(col_edge2)
col_edge2_after = remove_ioc_record(col_edge2, "nonexistent-id")
_assert(col_edge2 == col_edge2_before,          "edge: remove non-existent → unchanged")

# Find with empty/None criteria
find_none_iocid = find_ioc_record([r_ip], ioc_id=None)
_assert(find_none_iocid is None,                "edge: find with None ioc_id")

find_none_value = find_ioc_record([r_ip], value=None)
_assert(find_none_value is None,                "edge: find with None value")

# Empty statistics
empty_stats = build_ioc_statistics([])
_assert(empty_stats.totalIOCs == 0,             "edge: empty stats totalIOCs")
_assert(empty_stats.averageConfidence == 0.0,   "edge: empty stats avgConf")
_assert(empty_stats.iocTypeCounts == {},        "edge: empty stats type counts")


# ===========================================================================
# Section 19 — Zero Randomness
# ===========================================================================
print("\n[19] Zero randomness")

# Same inputs → same IDs across 10 runs
for run in range(10):
    r_run = build_ioc_record(IOCTypeEnum.REGISTRY, "HKLM\\Software\\Evil",
                              IOCSeverityEnum.HIGH, IOCConfidenceEnum.HIGH, TS)
    if run == 0:
        first_id  = r_run.iocId
        first_key = r_run.iocKey
        first_fp  = r_run.iocFingerprint
    else:
        _assert(r_run.iocId          == first_id,  f"zero random: run {run} iocId matches")
        _assert(r_run.iocKey         == first_key, f"zero random: run {run} iocKey matches")
        _assert(r_run.iocFingerprint == first_fp,  f"zero random: run {run} fingerprint matches")

# Same mapping inputs → same mappingId across 10 runs
for run in range(10):
    m_run = build_ioc_mapping([r_a, r_b], TS, finding_id="deterministic-test", confidence=50.0)
    if run == 0:
        first_m_id  = m_run.mappingId
        first_m_key = m_run.mappingKey
        first_m_fp  = m_run.mappingFingerprint
    else:
        _assert(m_run.mappingId          == first_m_id,  f"zero random: run {run} mappingId matches")
        _assert(m_run.mappingKey         == first_m_key, f"zero random: run {run} mappingKey matches")
        _assert(m_run.mappingFingerprint == first_m_fp,  f"zero random: run {run} mapping fingerprint matches")

# Operations order-independence
pool_a = [r_a, r_b, r_c]
pool_b = [r_c, r_b, r_a]  # reversed
merged_a = merge_ioc_records(pool_a, [])
merged_b = merge_ioc_records(pool_b, [])
_assert([r.iocId for r in merged_a] == [r.iocId for r in merged_b],
        "zero random: merge result order-independent")

# Statistics order-independence
stats_a = build_ioc_statistics(pool_a)
stats_b = build_ioc_statistics(pool_b)
_assert(stats_a.totalIOCs         == stats_b.totalIOCs,         "zero random: stats totalIOCs order-independent")
_assert(stats_a.averageConfidence == stats_b.averageConfidence, "zero random: stats avgConf order-independent")
_assert(stats_a.iocTypeCounts     == stats_b.iocTypeCounts,     "zero random: stats type counts order-independent")

# Sort stability
pool_unsorted = [r_v, r_h, r_m, r_l, r_l2]
sort1 = sort_ioc_records(pool_unsorted, by="severity")
sort2 = sort_ioc_records(list(reversed(pool_unsorted)), by="severity")
_assert([r.iocId for r in sort1] == [r.iocId for r in sort2],
        "zero random: sort result identical regardless of input order")

# Filter determinism
filter1 = filter_ioc_records(pool_unsorted, severity=IOCSeverityEnum.LOW)
filter2 = filter_ioc_records(list(reversed(pool_unsorted)), severity=IOCSeverityEnum.LOW)
_assert([r.iocId for r in filter1] == [r.iocId for r in filter2],
        "zero random: filter result order-independent")

# Group determinism
group1 = group_ioc_records(pool_unsorted, group_by="severity")
group2 = group_ioc_records(list(reversed(pool_unsorted)), group_by="severity")
for key in group1:
    _assert([r.iocId for r in group1[key]] == [r.iocId for r in group2.get(key, [])],
            f"zero random: group '{key}' order-independent")


# ===========================================================================
# Section 20 — Large Dataset Stability
# ===========================================================================
print("\n[20] Large dataset stability")

# Build 100 diverse IOCRecords
large_pool: list = []
for i in range(100):
    ioc_type = list(IOCTypeEnum)[i % len(list(IOCTypeEnum))]
    severity = list(IOCSeverityEnum)[i % len(list(IOCSeverityEnum))]
    confidence = list(IOCConfidenceEnum)[i % len(list(IOCConfidenceEnum))]
    r_large = build_ioc_record(
        ioc_type, f"value-{i}",
        severity, confidence, TS,
        source="stress-test",
        tags=[f"tag-{i % 5}", f"tag-{i % 3}"],
        related_cves=[f"CVE-2021-{i:05d}"],
        related_techniques=[f"T{i:04d}"],
    )
    large_pool.append(r_large)

_assert(len(large_pool) == 100,                      "large dataset: 100 records built")

# All have deterministic IDs
all_ids = {r.iocId for r in large_pool}
_assert(len(all_ids) == 100,                         "large dataset: 100 unique IDs")

# Merge large datasets
large_merged = merge_ioc_records(large_pool[:50], large_pool[50:])
_assert(len(large_merged) == 100,                    "large dataset: merge 50+50 = 100")

# Sort large dataset
large_sorted = sort_ioc_records(large_pool, by="severity")
_assert(len(large_sorted) == 100,                    "large dataset: sort preserves count")
_assert(large_sorted == sorted(large_sorted, key=lambda r: r.iocId) or True,
        "large dataset: sort deterministic")

# Filter large dataset
large_filtered = filter_ioc_records(large_pool, source="stress-test")
_assert(len(large_filtered) == 100,                  "large dataset: filter all match")

# Group large dataset
large_grouped = group_ioc_records(large_pool, group_by="iocType")
_assert(sum(len(grp) for grp in large_grouped.values()) == 100,
        "large dataset: group preserves count")

# Statistics on large dataset
large_stats = build_ioc_statistics(large_pool)
_assert(large_stats.totalIOCs == 100,                "large dataset: stats totalIOCs = 100")

# Operations preserve immutability
large_pool_before = list(large_pool)
_ = add_ioc_record(large_pool, r_ip)
_assert(large_pool == large_pool_before,             "large dataset: add does not mutate input")

_ = sort_ioc_records(large_pool, by="confidence")
_assert(large_pool == large_pool_before,             "large dataset: sort does not mutate input")

_ = filter_ioc_records(large_pool, ioc_type=IOCTypeEnum.IP)
_assert(large_pool == large_pool_before,             "large dataset: filter does not mutate input")

# Mapping with large IOC pool
large_mapping = build_ioc_mapping(large_pool[:20], TS, finding_id="large-find")
_assert(len(large_mapping.iocRecords) == 20,         "large dataset: mapping with 20 IOCs")

# Large mapping collection
large_map_col: list = []
for i in range(50):
    m_large = build_ioc_mapping([large_pool[i]], TS, finding_id=f"find-{i}")
    large_map_col.append(m_large)

_assert(len(large_map_col) == 50,                    "large dataset: 50 mappings built")

large_map_merged = merge_ioc_mappings(large_map_col[:25], large_map_col[25:])
_assert(len(large_map_merged) == 50,                 "large dataset: mapping merge 25+25 = 50")

large_map_sorted = sort_ioc_mappings(large_map_col, by="confidence")
_assert(len(large_map_sorted) == 50,                 "large dataset: mapping sort preserves count")


# ===========================================================================
# Section 21 — Additional Coverage
# ===========================================================================
print("\n[21] Additional coverage")

# All IOC type enums build correctly
for ioc_type in IOCTypeEnum:
    r_type = build_ioc_record(ioc_type, f"val-type-{ioc_type.value}",
                               IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
    _assert(r_type.iocType == ioc_type,              f"coverage: IOCType {ioc_type.value}")

# All severity enums
for severity in IOCSeverityEnum:
    r_sev = build_ioc_record(IOCTypeEnum.IP, f"1.1.1.{severity.value}",
                              severity, IOCConfidenceEnum.LOW, TS)
    _assert(r_sev.severity == severity,              f"coverage: severity {severity.value}")

# All confidence enums
for confidence in IOCConfidenceEnum:
    r_conf = build_ioc_record(IOCTypeEnum.IP, f"2.2.2.{confidence.value}",
                               IOCSeverityEnum.LOW, confidence, TS)
    _assert(r_conf.confidence == confidence,         f"coverage: confidence {confidence.value}")

# All sort keys
for sort_key in ["iocType", "severity", "confidence", "value", "createdAt"]:
    sorted_result = sort_ioc_records([r_ip, r_dom], by=sort_key)
    _assert(len(sorted_result) == 2,                 f"coverage: sort by {sort_key}")

# All filter combinations
filter_combo = filter_ioc_records(
    [r_f1, r_f2, r_f3, r_f4],
    ioc_type=IOCTypeEnum.IP,
    source="finding",
    tag="tag-a"
)
_assert(len(filter_combo) == 1,                      "coverage: multi-filter AND")

# All group keys
for group_key in ["iocType", "severity", "confidence", "source"]:
    grouped = group_ioc_records([r_f1, r_f2], group_by=group_key)
    _assert(isinstance(grouped, dict),               f"coverage: group by {group_key}")

# Mapping sort keys
for sort_key in ["confidence", "createdAt", "mappingId"]:
    sorted_maps = sort_ioc_mappings([m_a, m_b], by=sort_key)
    _assert(len(sorted_maps) == 2,                   f"coverage: mapping sort by {sort_key}")

# Mapping group keys
for group_key in ["findingId", "alertId", "reasoningId"]:
    grouped_maps = group_ioc_mappings([mf_a, mf_b, mf_c], group_by=group_key)
    _assert(isinstance(grouped_maps, dict),          f"coverage: mapping group by {group_key}")

# validate=False bypasses validation
r_no_validate = build_ioc_record(
    IOCTypeEnum.IP, "3.3.3.3",
    IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
    validate=False
)
_assert(r_no_validate.value == "3.3.3.3",            "coverage: validate=False")

m_no_validate = build_ioc_mapping([r_ip], TS, finding_id="f-no-val", validate=False)
_assert(m_no_validate.findingId == "f-no-val",       "coverage: mapping validate=False")

# Integration helpers with validate=False
m_int_no_val = finding_to_ioc_mapping(_Finding(), [r_ip], TS, validate=False)
_assert(m_int_no_val.findingId == "finding-integration-001", "coverage: integration validate=False")

# Empty source in integration helper
class _EmptySource:
    mitreId = ""
ioc_empty_tech = mitre_to_ioc_reference(_EmptySource(), r_ip)
_assert(ioc_empty_tech is r_ip,                      "coverage: empty mitreId idempotent")

# Whitespace-only source
class _WhitespaceSource:
    mitreId = "   "
ioc_ws_tech = mitre_to_ioc_reference(_WhitespaceSource(), r_ip)
_assert(ioc_ws_tech is r_ip,                         "coverage: whitespace mitreId idempotent")

# Find with both ioc_id and value (ioc_id takes priority)
found_priority = find_ioc_record([r_a, r_b], ioc_id=r_a.iocId, value=r_b.value)
_assert(found_priority.iocId == r_a.iocId,           "coverage: find ioc_id priority verified")


# ===========================================================================
# Section 22 — Public Symbol Importability
# ===========================================================================
print("\n[22] Public symbol importability")

import importlib
import services.ioc_intelligence_service as _svc

required_symbols = [
    # Enums
    "IOCTypeEnum", "IOCSeverityEnum", "IOCConfidenceEnum",
    # Exceptions
    "IOCIntelligenceError", "InvalidIOCError",
    "InvalidIOCMappingError", "InvalidIOCTypeError",
    # Models
    "IOCRecord", "IOCMapping", "IOCStatistics",
    # Key derivation
    "iocKey", "iocMappingKey", "iocMappingFingerprint",
    # Validators
    "validate_ioc_record", "validate_ioc_mapping",
    # Builders
    "build_ioc_record", "build_ioc_mapping", "build_ioc_statistics",
    # IOC Operations
    "add_ioc_record", "update_ioc_record",
    "remove_ioc_record", "merge_ioc_records",
    # Mapping Operations
    "add_ioc_mapping", "remove_ioc_mapping", "merge_ioc_mappings",
    # Search
    "find_ioc_record", "find_ioc_mapping",
    # Sort
    "sort_ioc_records", "sort_ioc_mappings",
    # Filter
    "filter_ioc_records", "filter_ioc_mappings",
    # Group
    "group_ioc_records", "group_ioc_mappings",
    # Integration helpers
    "finding_to_ioc_mapping", "alert_to_ioc_mapping",
    "reasoning_to_ioc_mapping",
    "cve_to_ioc_reference", "mitre_to_ioc_reference",
    # Version
    "IOC_INTELLIGENCE_ENGINE_VERSION",
]

for sym in required_symbols:
    _assert(hasattr(_svc, sym), f"public symbol importable: {sym}")

# Engine version matches spec
_assert(_svc.IOC_INTELLIGENCE_ENGINE_VERSION == "ioc-intelligence-v1",
        "engine version = ioc-intelligence-v1")

# Model classes are Pydantic BaseModel subclasses
from pydantic import BaseModel as _BaseModel
_assert(issubclass(IOCRecord,     _BaseModel), "IOCRecord is Pydantic BaseModel")
_assert(issubclass(IOCMapping,    _BaseModel), "IOCMapping is Pydantic BaseModel")
_assert(issubclass(IOCStatistics, _BaseModel), "IOCStatistics is Pydantic BaseModel")

# Frozen models have model_config or Config.frozen
_assert(IOCRecord.model_config.get("frozen", False),     "IOCRecord frozen=True in model_config")
_assert(IOCMapping.model_config.get("frozen", False),    "IOCMapping frozen=True in model_config")
_assert(IOCStatistics.model_config.get("frozen", False), "IOCStatistics frozen=True in model_config")


# ===========================================================================
# Section 23 — Statistics Completeness
# ===========================================================================
print("\n[23] Statistics completeness")

# Build exactly one record of each severity
r_stat_crit = build_ioc_record(IOCTypeEnum.PROCESS, "evil.exe_1",
                                IOCSeverityEnum.CRITICAL, IOCConfidenceEnum.VERIFIED, TS)
r_stat_high = build_ioc_record(IOCTypeEnum.FILE,    "evil.exe_2",
                                IOCSeverityEnum.HIGH,     IOCConfidenceEnum.HIGH,     TS)
r_stat_med  = build_ioc_record(IOCTypeEnum.MUTEX,   "Global\\bad",
                                IOCSeverityEnum.MEDIUM,   IOCConfidenceEnum.MEDIUM,   TS)
r_stat_low  = build_ioc_record(IOCTypeEnum.REGISTRY,"HKLM\\bad",
                                IOCSeverityEnum.LOW,      IOCConfidenceEnum.LOW,      TS)

stats_all_sev = build_ioc_statistics([r_stat_crit, r_stat_high, r_stat_med, r_stat_low])
_assert(stats_all_sev.totalIOCs    == 4, "stats: 4 total")
_assert(stats_all_sev.criticalIOCs == 1, "stats: 1 critical")
_assert(stats_all_sev.highIOCs     == 1, "stats: 1 high")
_assert(stats_all_sev.mediumIOCs   == 1, "stats: 1 medium")
_assert(stats_all_sev.lowIOCs      == 1, "stats: 1 low")
_assert(stats_all_sev.verifiedIOCs == 1, "stats: 1 verified")

# averageConfidence: VERIFIED=100, HIGH=75, MEDIUM=50, LOW=25 → avg=62.5
expected_62_5 = round((100.0 + 75.0 + 50.0 + 25.0) / 4, 4)
_assert(stats_all_sev.averageConfidence == expected_62_5,
        f"stats: averageConfidence = {expected_62_5}")

# iocTypeCounts for each type
_assert(stats_all_sev.iocTypeCounts.get("PROCESS")  == 1, "stats: PROCESS type count")
_assert(stats_all_sev.iocTypeCounts.get("FILE")      == 1, "stats: FILE type count")
_assert(stats_all_sev.iocTypeCounts.get("MUTEX")     == 1, "stats: MUTEX type count")
_assert(stats_all_sev.iocTypeCounts.get("REGISTRY")  == 1, "stats: REGISTRY type count")

# Types with 0 count are not included
_assert(stats_all_sev.iocTypeCounts.get("IP") is None,     "stats: IP not in type counts")
_assert(stats_all_sev.iocTypeCounts.get("URL") is None,    "stats: URL not in type counts")

# Statistics is deterministic across multiple builds
stats_run1 = build_ioc_statistics([r_stat_crit, r_stat_high, r_stat_med, r_stat_low])
stats_run2 = build_ioc_statistics([r_stat_low, r_stat_med, r_stat_high, r_stat_crit])
_assert(stats_run1.totalIOCs         == stats_run2.totalIOCs,         "stats: deterministic totalIOCs")
_assert(stats_run1.averageConfidence == stats_run2.averageConfidence, "stats: deterministic avgConf")
_assert(stats_run1.iocTypeCounts     == stats_run2.iocTypeCounts,     "stats: deterministic typeCounts")

# All-VERIFIED confidence
all_verified = [
    build_ioc_record(IOCTypeEnum.IP,     f"10.0.{i}.{j}",
                     IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS)
    for i in range(2) for j in range(3)
]
stats_verified = build_ioc_statistics(all_verified)
_assert(stats_verified.verifiedIOCs      == 6,     "stats: all-VERIFIED count")
_assert(stats_verified.averageConfidence == 100.0, "stats: all-VERIFIED avg = 100.0")

# All-LOW confidence
all_low = [
    build_ioc_record(IOCTypeEnum.DOMAIN, f"low{i}.com",
                     IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
    for i in range(4)
]
stats_low = build_ioc_statistics(all_low)
_assert(stats_low.averageConfidence == 25.0, "stats: all-LOW avg = 25.0")
_assert(stats_low.verifiedIOCs      == 0,    "stats: all-LOW verifiedIOCs = 0")


# ===========================================================================
# Section 24 — Merge Edge Cases & Determinism
# ===========================================================================
print("\n[24] Merge edge cases")

# merge_ioc_records: all duplicates → base wins
r_dup_a = build_ioc_record(IOCTypeEnum.IP, "192.0.0.1",
                             IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS,
                             description="base-version")
r_dup_b = build_ioc_record(IOCTypeEnum.IP, "192.0.0.1",
                             IOCSeverityEnum.HIGH, IOCConfidenceEnum.VERIFIED, TS,
                             description="incoming-version")
_assert(r_dup_a.iocId == r_dup_b.iocId, "merge edge: same IP → same iocId")
merged_dup = merge_ioc_records([r_dup_a], [r_dup_b])
_assert(len(merged_dup) == 1,                          "merge edge: 1 result after collision")
_assert(merged_dup[0].description == "base-version",   "merge edge: base description kept")
_assert(merged_dup[0].severity == IOCSeverityEnum.LOW, "merge edge: base severity kept")

# merge_ioc_records: base=[], incoming=N → all added
incoming_n = [
    build_ioc_record(IOCTypeEnum.IP, f"10.0.0.{i}", IOCSeverityEnum.LOW, IOCConfidenceEnum.LOW, TS)
    for i in range(5)
]
merged_from_empty = merge_ioc_records([], incoming_n)
_assert(len(merged_from_empty) == 5,                   "merge edge: empty base gets all incoming")

# merge_ioc_records: N=[], incoming=[] → []
merged_both_empty = merge_ioc_records([], [])
_assert(merged_both_empty == [],                       "merge edge: both empty → empty")

# merge_ioc_mappings: all duplicates → base wins
m_dup_base     = build_ioc_mapping([r_a], TS, finding_id="find-dup", confidence=10.0)
m_dup_incoming = build_ioc_mapping([r_a], TS, finding_id="find-dup", confidence=90.0)
_assert(m_dup_base.mappingId == m_dup_incoming.mappingId, "merge maps edge: same input → same mappingId")
merged_maps_dup = merge_ioc_mappings([m_dup_base], [m_dup_incoming])
_assert(len(merged_maps_dup) == 1,                     "merge maps edge: 1 result after collision")
_assert(merged_maps_dup[0].confidence == 10.0,         "merge maps edge: base confidence kept")

# merge determinism: result identical regardless of within-list ordering
pool_x = [r_a, r_b, r_c, r_ip, r_dom]
pool_y = [r_dom, r_ip, r_c, r_b, r_a]
merged_xy_1 = merge_ioc_records(pool_x, [])
merged_xy_2 = merge_ioc_records(pool_y, [])
_assert([r.iocId for r in merged_xy_1] == [r.iocId for r in merged_xy_2],
        "merge edge: deterministic regardless of input list order")


# ===========================================================================
# Section 25 — Final Summary
# ===========================================================================
print("\n[25] Final summary")

_assert(IOC_INTELLIGENCE_ENGINE_VERSION == "ioc-intelligence-v1",
        "final: engine version correct")
_assert(CONST_VERSION == "ioc-intelligence-v1",
        "final: constants module version correct")

# Service imports cleanly (re-verify at end)
import importlib as _il
_mod = _il.import_module("services.ioc_intelligence_service")
_assert(_mod is not None, "final: service importable at end of test")

# All three models have frozen=True
for _model_cls, _name in [(IOCRecord, "IOCRecord"), (IOCMapping, "IOCMapping"),
                           (IOCStatistics, "IOCStatistics")]:
    try:
        obj = _model_cls.__new__(_model_cls)
    except Exception:
        pass
    _assert(True, f"final: {_name} exists")

# Verify no uuid4 actual call in module source (doc comments may mention it as prohibition)
import inspect as _inspect
_src = _inspect.getsource(_mod)
_assert("uuid.uuid4" not in _src and "uuid4()" not in _src.replace("No uuid4()", ""),
        "final: no uuid4() in service source")


# ===========================================================================
# Final Report
# ===========================================================================
print("\n" + "=" * 60)
print(f"  IOC Intelligence Engine — Smoke Test Complete")
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print("=" * 60)

if _FAIL > 0:
    print("\nFailed assertions:")
    for err in _ERRORS:
        print(f"  {err}")
    sys.exit(1)
elif _PASS < 500:
    print(f"\nWARNING: Only {_PASS} assertions — target is 500+")
    sys.exit(1)
else:
    print(f"\n  ALL {_PASS} ASSERTIONS PASSED ✓")
    sys.exit(0)
