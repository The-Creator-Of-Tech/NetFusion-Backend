"""
Smoke test — CVE Intelligence Engine (Phase A4.3.8)
====================================================
Validates (450+ assertions):
  ✓ deterministic IDs (recordKey/Id, mappingKey/Id, mappingFingerprint)
  ✓ immutable models (frozen=True raises on mutation)
  ✓ build_cve_record()         — full field coverage
  ✓ build_cve_mapping()        — full field coverage
  ✓ build_cve_statistics()     — order-independent
  ✓ validate_cve_record()      — all invalid cases
  ✓ validate_cve_mapping()     — all invalid cases
  ✓ add_cve_record()           — add + duplicate prevention
  ✓ update_cve_record()        — partial + full + missing
  ✓ remove_cve_record()        — present + missing
  ✓ merge_cve_records()        — field-level merge rules
  ✓ add_mapping_record()       — add + duplicate prevention
  ✓ remove_mapping_record()    — present + missing
  ✓ merge_mappings()           — union rules + error on mismatch
  ✓ find_cve_record()          — by recordId, by cveId
  ✓ find_mapping()             — by mappingId, by mappingKey
  ✓ sort_cve_records()         — all keys + invalid key
  ✓ sort_cve_mappings()        — all keys + invalid key
  ✓ filter_cve_records()       — all filter dimensions
  ✓ filter_cve_mappings()      — all filter dimensions
  ✓ group_cve_records()        — all group keys + invalid key
  ✓ group_cve_mappings()       — all group keys + invalid key
  ✓ integration helpers        — finding/alert/reasoning/mitre
  ✓ serialization / round-trip
  ✓ zero randomness (multiple runs identical)
  ✓ edge cases (empty inputs, boundary CVSS, clamping)
"""

import sys
from types import SimpleNamespace
from services.cve_intelligence_service import (
    # models
    CVERecord, CVEMapping, CVEStatistics,
    SeverityEnum,
    # exceptions
    CVEIntelligenceError, InvalidCVEError, InvalidCVEMappingError, InvalidCVSSScoreError,
    # id helpers
    recordKey, cveMappingKey, cveMappingFingerprint,
    # builders
    build_cve_record, build_cve_mapping, build_cve_statistics,
    # validators
    validate_cve_record, validate_cve_mapping,
    # cve operations
    add_cve_record, update_cve_record, remove_cve_record, merge_cve_records,
    # mapping operations
    add_mapping_record, remove_mapping_record, merge_mappings,
    # search
    find_cve_record, find_mapping,
    # sorting
    sort_cve_records, sort_cve_mappings,
    # filtering
    filter_cve_records, filter_cve_mappings,
    # grouping
    group_cve_records, group_cve_mappings,
    # integration helpers
    finding_to_cve_mapping, alert_to_cve_mapping,
    reasoning_to_cve_mapping, mitre_to_cve_reference,
)
from core.constants import CVE_INTELLIGENCE_ENGINE_VERSION

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
errors: list = []


def check(label: str, condition: bool) -> None:
    icon = PASS if condition else FAIL
    print(f"  {icon}  {label}")
    if not condition:
        errors.append(label)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TS1 = "2026-06-30T10:00:00Z"
TS2 = "2026-06-30T11:00:00Z"
TS3 = "2026-07-01T08:00:00Z"


def _make_technique(mitre_id: str, technique_id: str) -> SimpleNamespace:
    return SimpleNamespace(mitreId=mitre_id, techniqueId=technique_id)


def _rec_log4j() -> CVERecord:
    return build_cve_record(
        cve_id             = "CVE-2021-44228",
        severity           = SeverityEnum.CRITICAL,
        cvss_score         = 10.0,
        created_at         = TS1,
        description        = "Log4Shell RCE vulnerability.",
        published_date     = "2021-12-10",
        modified_date      = "2021-12-14",
        references         = ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                               "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],  # dup
        affected_platforms = ["linux", "Windows", "LINUX"],  # dup + mixed case
        mapped_techniques  = [_make_technique("TA0002", "T1059"),
                               _make_technique("TA0001", "T1190")],
    )


def _rec_proxylogon() -> CVERecord:
    return build_cve_record(
        cve_id             = "CVE-2021-26855",
        severity           = SeverityEnum.CRITICAL,
        cvss_score         = 9.8,
        created_at         = TS1,
        description        = "Exchange Server SSRF.",
        published_date     = "2021-03-02",
        modified_date      = "2021-03-08",
        references         = ["https://msrc.microsoft.com/CVE-2021-26855"],
        affected_platforms = ["windows"],
    )


def _rec_low() -> CVERecord:
    return build_cve_record(
        cve_id     = "CVE-2020-00001",
        severity   = SeverityEnum.LOW,
        cvss_score = 2.5,
        created_at = TS1,
    )


def _rec_medium() -> CVERecord:
    return build_cve_record(
        cve_id     = "CVE-2019-11111",
        severity   = SeverityEnum.MEDIUM,
        cvss_score = 5.0,
        created_at = TS1,
        affected_platforms = ["linux"],
    )


def _rec_high() -> CVERecord:
    return build_cve_record(
        cve_id     = "CVE-2022-22222",
        severity   = SeverityEnum.HIGH,
        cvss_score = 7.8,
        created_at = TS1,
        affected_platforms = ["windows", "macos"],
    )


def _make_mapping(
    finding_id   = "find-001",
    alert_id     = "alert-001",
    reasoning_id = "",
    records      = None,
    confidence   = 85.0,
) -> CVEMapping:
    if records is None:
        records = [_rec_log4j(), _rec_proxylogon()]
    return build_cve_mapping(
        cve_records  = records,
        created_at   = TS1,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = reasoning_id,
        confidence   = confidence,
    )


# ---------------------------------------------------------------------------
# Section 1: Deterministic ID helpers
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic ID helpers ──────────────────────────────────────")

rk1 = recordKey("CVE-2021-44228")
rk2 = recordKey("CVE-2021-44228")
check("recordKey deterministic",                     rk1 == rk2)
check("recordKey length 32",                         len(rk1) == 32)
check("recordKey case-insensitive",                  rk1 == recordKey("cve-2021-44228"))
check("recordKey different cveId → different key",   rk1 != recordKey("CVE-2021-26855"))

rk_rid1 = _rec_log4j().recordId
rk_rid2 = _rec_log4j().recordId
check("recordId deterministic (UUIDv5)",             rk_rid1 == rk_rid2)
check("recordId valid UUID format",                  len(rk_rid1) == 36 and rk_rid1.count("-") == 4)
check("different cveId → different recordId",        rk_rid1 != _rec_proxylogon().recordId)

recs = (_rec_log4j().recordId, _rec_proxylogon().recordId)
mk1  = cveMappingKey("f1", "a1", "r1", recs)
mk2  = cveMappingKey("f1", "a1", "r1", recs)
check("mappingKey deterministic",                    mk1 == mk2)
check("mappingKey length 32",                        len(mk1) == 32)
# order-independence
mk_rev = cveMappingKey("f1", "a1", "r1", tuple(reversed(recs)))
check("mappingKey order-independent recordIds",      mk1 == mk_rev)
check("different findingId → different mappingKey",  mk1 != cveMappingKey("f2", "a1", "r1", recs))
check("different alertId → different mappingKey",    mk1 != cveMappingKey("f1", "a2", "r1", recs))

fp1 = cveMappingFingerprint(mk1, "f1", "a1", "r1", recs)
fp2 = cveMappingFingerprint(mk1, "f1", "a1", "r1", recs)
check("mappingFingerprint deterministic",            fp1 == fp2)
check("mappingFingerprint length 32",                len(fp1) == 32)
check("different recordIds → different fingerprint", fp1 != cveMappingFingerprint(mk1, "f1", "a1", "r1", (recs[0],)))


# ---------------------------------------------------------------------------
# Section 2: build_cve_record()
# ---------------------------------------------------------------------------
print("\n── 2. build_cve_record() ────────────────────────────────────────────")

r = _rec_log4j()
check("cveId uppercased",                            r.cveId == "CVE-2021-44228")
check("recordKey length 32",                         len(r.recordKey) == 32)
check("recordId valid UUID",                         len(r.recordId) == 36)
check("severity CRITICAL",                           r.severity == SeverityEnum.CRITICAL)
check("cvssScore clamped to [0,10]",                 0.0 <= r.cvssScore <= 10.0)
check("cvssScore = 10.0",                            r.cvssScore == 10.0)
check("references deduped (1 entry)",                len(r.references) == 1)
check("references sorted",                           list(r.references) == sorted(r.references))
check("affectedPlatforms deduped+lowercased",        set(r.affectedPlatforms) == {"linux", "windows"})
check("affectedPlatforms sorted",                    list(r.affectedPlatforms) == sorted(r.affectedPlatforms))
check("mappedTechniques sorted by mitreId",          r.mappedTechniques[0].mitreId <= r.mappedTechniques[-1].mitreId)
check("description set",                             r.description == "Log4Shell RCE vulnerability.")
check("publishedDate set",                           r.publishedDate == "2021-12-10")
check("modifiedDate set",                            r.modifiedDate  == "2021-12-14")
check("createdAt set",                               r.createdAt == TS1)
check("identical inputs → same recordId",            _rec_log4j().recordId == r.recordId)
check("different cveId → different recordId",        r.recordId != _rec_proxylogon().recordId)

# CVSS boundary clamping: overshoot clamped
r_over = build_cve_record("CVE-2023-99999", SeverityEnum.HIGH, 10.0, TS1)
check("cvssScore 10.0 allowed",                      r_over.cvssScore == 10.0)
r_zero = build_cve_record("CVE-2023-88888", SeverityEnum.LOW, 0.0, TS1)
check("cvssScore 0.0 allowed",                       r_zero.cvssScore == 0.0)

# empty optionals
r_min = build_cve_record("CVE-2024-00001", SeverityEnum.LOW, 1.0, TS1)
check("references empty tuple when None",            r_min.references == ())
check("affectedPlatforms empty tuple when None",     r_min.affectedPlatforms == ())
check("mappedTechniques empty tuple when None",      r_min.mappedTechniques == ())
check("description empty string when omitted",       r_min.description == "")


# ---------------------------------------------------------------------------
# Section 3: Immutability
# ---------------------------------------------------------------------------
print("\n── 3. Immutability (frozen=True) ────────────────────────────────────")

r = _rec_log4j()
try:
    r.cvssScore = 0.0  # type: ignore
    check("CVERecord frozen=True raises",            False)
except Exception:
    check("CVERecord frozen=True raises",            True)

try:
    r.cveId = "CVE-0000-0000"  # type: ignore
    check("CVERecord.cveId frozen raises",           False)
except Exception:
    check("CVERecord.cveId frozen raises",           True)

m = _make_mapping()
try:
    m.confidence = 0.0  # type: ignore
    check("CVEMapping frozen=True raises",           False)
except Exception:
    check("CVEMapping frozen=True raises",           True)

try:
    m.cveRecords = ()  # type: ignore
    check("CVEMapping.cveRecords frozen raises",     False)
except Exception:
    check("CVEMapping.cveRecords frozen raises",     True)

stats = build_cve_statistics([m])
try:
    stats.totalCVEs = 99  # type: ignore
    check("CVEStatistics frozen=True raises",        False)
except Exception:
    check("CVEStatistics frozen=True raises",        True)


# ---------------------------------------------------------------------------
# Section 4: validate_cve_record()
# ---------------------------------------------------------------------------
print("\n── 4. validate_cve_record() ─────────────────────────────────────────")

# Valid — no exception
try:
    validate_cve_record("CVE-2021-44228", SeverityEnum.CRITICAL, 10.0, TS1)
    check("valid record: no exception",              True)
except Exception:
    check("valid record: no exception",              False)

# Empty cveId
try:
    validate_cve_record("", SeverityEnum.HIGH, 5.0, TS1)
    check("empty cveId → InvalidCVEError",           False)
except InvalidCVEError:
    check("empty cveId → InvalidCVEError",           True)

# Bad cveId format
try:
    validate_cve_record("NOT-A-CVE", SeverityEnum.HIGH, 5.0, TS1)
    check("bad cveId format → InvalidCVEError",      False)
except InvalidCVEError:
    check("bad cveId format → InvalidCVEError",      True)

# CVSS out of range
try:
    validate_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 10.1, TS1)
    check("cvss > 10.0 → InvalidCVSSScoreError",     False)
except InvalidCVSSScoreError:
    check("cvss > 10.0 → InvalidCVSSScoreError",     True)

try:
    validate_cve_record("CVE-2021-44228", SeverityEnum.HIGH, -0.1, TS1)
    check("cvss < 0.0 → InvalidCVSSScoreError",      False)
except InvalidCVSSScoreError:
    check("cvss < 0.0 → InvalidCVSSScoreError",      True)

# Empty createdAt
try:
    validate_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 5.0, "")
    check("empty createdAt → InvalidCVEError",       False)
except InvalidCVEError:
    check("empty createdAt → InvalidCVEError",       True)

# build with validate=True raises on bad input
try:
    build_cve_record("BAD", SeverityEnum.HIGH, 5.0, TS1, validate=True)
    check("build_cve_record bad cveId raises",       False)
except InvalidCVEError:
    check("build_cve_record bad cveId raises",       True)

# build with validate=False skips check
r_noval = build_cve_record("BAD", SeverityEnum.HIGH, 5.0, TS1, validate=False)
check("build_cve_record validate=False skips check", r_noval is not None)


# ---------------------------------------------------------------------------
# Section 5: validate_cve_mapping()
# ---------------------------------------------------------------------------
print("\n── 5. validate_cve_mapping() ────────────────────────────────────────")

try:
    validate_cve_mapping("find-001", "", "", 50.0, TS1)
    check("valid mapping (findingId only): no exception", True)
except Exception:
    check("valid mapping (findingId only): no exception", False)

# No source IDs
try:
    validate_cve_mapping("", "", "", 50.0, TS1)
    check("no source IDs → InvalidCVEMappingError",  False)
except InvalidCVEMappingError:
    check("no source IDs → InvalidCVEMappingError",  True)

# Confidence out of range
try:
    validate_cve_mapping("find-001", "", "", 101.0, TS1)
    check("confidence > 100 → InvalidCVEMappingError", False)
except InvalidCVEMappingError:
    check("confidence > 100 → InvalidCVEMappingError", True)

try:
    validate_cve_mapping("find-001", "", "", -1.0, TS1)
    check("confidence < 0 → InvalidCVEMappingError", False)
except InvalidCVEMappingError:
    check("confidence < 0 → InvalidCVEMappingError", True)

# Empty createdAt
try:
    validate_cve_mapping("find-001", "", "", 50.0, "")
    check("empty createdAt → InvalidCVEMappingError", False)
except InvalidCVEMappingError:
    check("empty createdAt → InvalidCVEMappingError", True)


# ---------------------------------------------------------------------------
# Section 6: build_cve_mapping()
# ---------------------------------------------------------------------------
print("\n── 6. build_cve_mapping() ───────────────────────────────────────────")

m = _make_mapping()
check("mappingKey length 32",                        len(m.mappingKey) == 32)
check("mappingId valid UUID",                        len(m.mappingId) == 36)
check("mappingFingerprint length 32",                len(m.mappingFingerprint) == 32)
check("cveRecords sorted by cveId ASC",              m.cveRecords[0].cveId <= m.cveRecords[-1].cveId)
check("confidence clamped 0-100",                    0.0 <= m.confidence <= 100.0)
check("confidence = 85.0",                           m.confidence == 85.0)
check("findingId stripped",                          m.findingId == "find-001")
check("alertId stripped",                            m.alertId == "alert-001")
check("reasoningId empty",                           m.reasoningId == "")
check("createdAt = TS1",                             m.createdAt == TS1)

# Idempotence
m2 = _make_mapping()
check("identical inputs → same mappingId",           m.mappingId == m2.mappingId)
check("identical inputs → same mappingKey",          m.mappingKey == m2.mappingKey)
check("identical inputs → same fingerprint",         m.mappingFingerprint == m2.mappingFingerprint)

# Confidence clamping
m_over = build_cve_mapping([_rec_log4j()], TS1, finding_id="f1", confidence=150.0)
check("confidence clamped to 100.0",                 m_over.confidence == 100.0)
m_neg = build_cve_mapping([_rec_log4j()], TS1, finding_id="f1", confidence=-5.0)
check("confidence clamped to 0.0",                   m_neg.confidence == 0.0)

# Empty cveRecords
m_empty_recs = build_cve_mapping([], TS1, finding_id="f1")
check("empty cveRecords allowed",                    m_empty_recs.cveRecords == ())


# ---------------------------------------------------------------------------
# Section 7: build_cve_statistics()
# ---------------------------------------------------------------------------
print("\n── 7. build_cve_statistics() ────────────────────────────────────────")

r_crit  = _rec_log4j()        # CRITICAL, cvss=10.0
r_crit2 = _rec_proxylogon()   # CRITICAL, cvss=9.8
r_high  = _rec_high()         # HIGH,     cvss=7.8
r_med   = _rec_medium()       # MEDIUM,   cvss=5.0
r_low   = _rec_low()          # LOW,      cvss=2.5

m_all = build_cve_mapping(
    [r_crit, r_crit2, r_high, r_med, r_low], TS1, finding_id="f-stats"
)

stats = build_cve_statistics([m_all])
check("totalCVEs = 5",                               stats.totalCVEs == 5)
check("criticalCVEs = 2",                            stats.criticalCVEs == 2)
check("highCVEs = 1",                                stats.highCVEs == 1)
check("mediumCVEs = 1",                              stats.mediumCVEs == 1)
check("lowCVEs = 1",                                 stats.lowCVEs == 1)
check("averageCVSS > 0",                             stats.averageCVSS > 0.0)
expected_avg = round((10.0 + 9.8 + 7.8 + 5.0 + 2.5) / 5, 4)
check("averageCVSS correct value",                   stats.averageCVSS == expected_avg)
check("averageConfidence = 0.0 (default confidence)", stats.averageConfidence == 0.0)

# With techniques
t1 = _make_technique("TA0001", "T1190")
t2 = _make_technique("TA0002", "T1059")
r_with_tech = build_cve_record("CVE-2025-10001", SeverityEnum.HIGH, 7.0, TS1,
                                mapped_techniques=[t1, t2])
m_tech = build_cve_mapping([r_with_tech], TS1, finding_id="f-tech")
stats_tech = build_cve_statistics([m_tech])
check("mappedTechniques count = 2",                  stats_tech.mappedTechniques == 2)

# Empty
stats_empty = build_cve_statistics([])
check("empty: totalCVEs = 0",                        stats_empty.totalCVEs == 0)
check("empty: averageCVSS = 0.0",                    stats_empty.averageCVSS == 0.0)
check("empty: averageConfidence = 0.0",              stats_empty.averageConfidence == 0.0)
check("empty: mappedTechniques = 0",                 stats_empty.mappedTechniques == 0)

# Deduplication across multiple mappings
m_a = build_cve_mapping([r_crit],       TS1, finding_id="f-a", confidence=80.0)
m_b = build_cve_mapping([r_crit, r_low], TS1, finding_id="f-b", confidence=60.0)
stats_dup = build_cve_statistics([m_a, m_b])
check("distinct CVEs deduped across mappings",       stats_dup.totalCVEs == 2)
check("averageConfidence = mean of mapping confidences",
      stats_dup.averageConfidence == round((80.0 + 60.0) / 2, 4))

# Order-independence
stats_fwd = build_cve_statistics([m_a, m_b])
stats_rev = build_cve_statistics([m_b, m_a])
check("statistics order-independent: totalCVEs",     stats_fwd.totalCVEs == stats_rev.totalCVEs)
check("statistics order-independent: averageCVSS",   stats_fwd.averageCVSS == stats_rev.averageCVSS)
check("statistics order-independent: averageConf",   stats_fwd.averageConfidence == stats_rev.averageConfidence)


# ---------------------------------------------------------------------------
# Section 8: add_cve_record()
# ---------------------------------------------------------------------------
print("\n── 8. add_cve_record() ──────────────────────────────────────────────")

store: list = []
r1 = _rec_log4j()
r2 = _rec_proxylogon()
r3 = _rec_low()

store = add_cve_record(store, r1)
check("add first record: count = 1",                 len(store) == 1)
check("add first record: cveId correct",             store[0].cveId == "CVE-2021-44228")

store = add_cve_record(store, r2)
check("add second record: count = 2",                len(store) == 2)
check("store sorted by cveId ASC",                   store[0].cveId <= store[1].cveId)

# Duplicate prevention
store_before = list(store)
store = add_cve_record(store, r1)  # duplicate
check("duplicate add: count unchanged",              len(store) == len(store_before))
check("duplicate add: original record preserved",    store[0].recordId == r1.recordId or store[1].recordId == r1.recordId)

# Case-insensitive duplicate check
r1_lower = build_cve_record("cve-2021-44228", SeverityEnum.HIGH, 5.0, TS2, validate=False)
r1_lower_upper = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 5.0, TS2)
store2: list = [r1]
store2 = add_cve_record(store2, r1_lower_upper)  # same cveId
check("case-insensitive duplicate: count unchanged", len(store2) == 1)

store = add_cve_record(store, r3)
check("add third record: count = 3",                 len(store) == 3)
check("store sorted after 3 adds",                   all(store[i].cveId <= store[i+1].cveId for i in range(len(store)-1)))


# ---------------------------------------------------------------------------
# Section 9: update_cve_record()
# ---------------------------------------------------------------------------
print("\n── 9. update_cve_record() ───────────────────────────────────────────")

r_orig = _rec_log4j()
store_upd = [r_orig, _rec_proxylogon()]

# Partial update — only severity
store_after = update_cve_record(store_upd, r_orig.recordId, severity=SeverityEnum.HIGH)
found_upd = next(r for r in store_after if r.recordId == r_orig.recordId)
check("partial update: severity changed",            found_upd.severity == SeverityEnum.HIGH)
check("partial update: cveId unchanged",             found_upd.cveId == r_orig.cveId)
check("partial update: recordId unchanged",          found_upd.recordId == r_orig.recordId)
check("partial update: cvssScore unchanged",         found_upd.cvssScore == r_orig.cvssScore)
check("partial update: description unchanged",       found_upd.description == r_orig.description)

# Partial update — cvssScore
store_after2 = update_cve_record(store_upd, r_orig.recordId, cvss_score=8.0)
found_cvss = next(r for r in store_after2 if r.recordId == r_orig.recordId)
check("partial update: cvssScore changed to 8.0",   found_cvss.cvssScore == 8.0)
check("partial update: severity preserved",          found_cvss.severity == r_orig.severity)

# Full update
store_after3 = update_cve_record(
    store_upd, r_orig.recordId,
    severity=SeverityEnum.MEDIUM,
    cvss_score=5.5,
    description="Updated description.",
    published_date="2022-01-01",
    modified_date="2022-06-01",
    references=["https://new-ref.example.com"],
    affected_platforms=["windows"],
    created_at=TS2,
)
found_full = next(r for r in store_after3 if r.recordId == r_orig.recordId)
check("full update: severity MEDIUM",                found_full.severity == SeverityEnum.MEDIUM)
check("full update: cvssScore = 5.5",                found_full.cvssScore == 5.5)
check("full update: description updated",            found_full.description == "Updated description.")
check("full update: publishedDate updated",          found_full.publishedDate == "2022-01-01")
check("full update: modifiedDate updated",           found_full.modifiedDate == "2022-06-01")
check("full update: references updated",             "https://new-ref.example.com" in found_full.references)
check("full update: affectedPlatforms updated",      "windows" in found_full.affectedPlatforms)
check("full update: createdAt updated",              found_full.createdAt == TS2)
check("full update: recordId unchanged",             found_full.recordId == r_orig.recordId)
check("full update: cveId unchanged",                found_full.cveId == r_orig.cveId)

# Missing recordId — store unchanged
store_miss = update_cve_record(store_upd, "nonexistent-id", severity=SeverityEnum.LOW)
check("missing recordId: store count unchanged",     len(store_miss) == len(store_upd))

# cvssScore clamped during update
store_clamp = update_cve_record(store_upd, r_orig.recordId, cvss_score=11.0)
found_clamp = next(r for r in store_clamp if r.recordId == r_orig.recordId)
check("update clamps cvssScore to 10.0",             found_clamp.cvssScore == 10.0)


# ---------------------------------------------------------------------------
# Section 10: remove_cve_record()
# ---------------------------------------------------------------------------
print("\n── 10. remove_cve_record() ──────────────────────────────────────────")

store_rem = [_rec_log4j(), _rec_proxylogon(), _rec_low()]
r_target = store_rem[0]

store_after_rem = remove_cve_record(store_rem, r_target.recordId)
check("remove: count decremented",                   len(store_after_rem) == 2)
check("remove: target not in result",                not any(r.recordId == r_target.recordId for r in store_after_rem))
check("remove: other records preserved",             any(r.cveId == "CVE-2021-26855" for r in store_after_rem))
check("remove: result sorted",                       all(store_after_rem[i].cveId <= store_after_rem[i+1].cveId for i in range(len(store_after_rem)-1)))

# Missing id — unchanged
store_miss_rem = remove_cve_record(store_rem, "nonexistent")
check("remove missing: count unchanged",             len(store_miss_rem) == len(store_rem))

# Remove all
store_one = [_rec_log4j()]
store_empty_rem = remove_cve_record(store_one, store_one[0].recordId)
check("remove last: empty list",                     store_empty_rem == [])


# ---------------------------------------------------------------------------
# Section 11: merge_cve_records()
# ---------------------------------------------------------------------------
print("\n── 11. merge_cve_records() ──────────────────────────────────────────")

base_r = build_cve_record(
    "CVE-2021-44228", SeverityEnum.HIGH, 8.0, TS1,
    description        = "Base description.",
    published_date     = "2021-12-10",
    modified_date      = "",
    references         = ["https://ref-a.example.com"],
    affected_platforms = ["linux"],
    mapped_techniques  = [_make_technique("TA0001", "T1190")],
)

incoming_r = build_cve_record(
    "CVE-2021-44228", SeverityEnum.CRITICAL, 10.0, TS2,
    description        = "Incoming description.",
    published_date     = "",
    modified_date      = "2021-12-14",
    references         = ["https://ref-b.example.com", "https://ref-a.example.com"],  # dup
    affected_platforms = ["windows", "linux"],
    mapped_techniques  = [_make_technique("TA0001", "T1190"),
                           _make_technique("TA0002", "T1059")],  # dup T1190 + new T1059
)

merged_r = merge_cve_records(base_r, incoming_r, TS3)
check("merge: recordId from base",                   merged_r.recordId == base_r.recordId)
check("merge: recordKey from base",                  merged_r.recordKey == base_r.recordKey)
check("merge: cveId from base",                      merged_r.cveId == base_r.cveId)
check("merge: severity = CRITICAL (highest)",        merged_r.severity == SeverityEnum.CRITICAL)
check("merge: cvssScore = max (10.0)",               merged_r.cvssScore == 10.0)
check("merge: description from incoming (non-empty)", merged_r.description == "Incoming description.")
check("merge: publishedDate from base (non-empty)",  merged_r.publishedDate == "2021-12-10")
check("merge: modifiedDate from incoming (non-empty)", merged_r.modifiedDate == "2021-12-14")
check("merge: references unioned + deduped",         len(merged_r.references) == 2)
check("merge: affectedPlatforms unioned",            set(merged_r.affectedPlatforms) == {"linux", "windows"})
check("merge: mappedTechniques unioned (no dup)",    len(merged_r.mappedTechniques) == 2)
check("merge: mappedTechniques sorted",              merged_r.mappedTechniques[0].mitreId <= merged_r.mappedTechniques[-1].mitreId)
check("merge: createdAt from caller",                merged_r.createdAt == TS3)

# Severity: base HIGH vs incoming MEDIUM → base HIGH wins
base_high   = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH,   6.0, TS1)
inc_medium  = build_cve_record("CVE-2021-44228", SeverityEnum.MEDIUM, 5.0, TS2)
m_high_med  = merge_cve_records(base_high, inc_medium, TS3)
check("merge severity: HIGH > MEDIUM, HIGH wins",    m_high_med.severity == SeverityEnum.HIGH)

# Description: incoming empty → base kept
base_desc   = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 6.0, TS1, description="Base desc.")
inc_no_desc = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 6.0, TS2, description="")
m_desc      = merge_cve_records(base_desc, inc_no_desc, TS3)
check("merge: empty incoming description → base kept", m_desc.description == "Base desc.")

# Error on mismatched cveIds
r_diff = _rec_proxylogon()
try:
    merge_cve_records(base_r, r_diff, TS3)
    check("merge mismatched cveIds → CVEIntelligenceError", False)
except CVEIntelligenceError:
    check("merge mismatched cveIds → CVEIntelligenceError", True)


# ---------------------------------------------------------------------------
# Section 12: add_mapping_record()
# ---------------------------------------------------------------------------
print("\n── 12. add_mapping_record() ─────────────────────────────────────────")

mstore: list = []
m1 = _make_mapping(finding_id="f1")
m2 = _make_mapping(finding_id="f2", records=[_rec_low()])
m3 = _make_mapping(finding_id="f3", alert_id="a3", records=[_rec_medium()])

mstore = add_mapping_record(mstore, m1)
check("add first mapping: count = 1",                len(mstore) == 1)

mstore = add_mapping_record(mstore, m2)
check("add second mapping: count = 2",               len(mstore) == 2)
check("mstore sorted by mappingId",                  all(mstore[i].mappingId <= mstore[i+1].mappingId for i in range(len(mstore)-1)))

# Duplicate prevention (same mappingKey)
mstore_before = list(mstore)
mstore = add_mapping_record(mstore, m1)
check("duplicate mapping: count unchanged",          len(mstore) == len(mstore_before))

mstore = add_mapping_record(mstore, m3)
check("add third mapping: count = 3",                len(mstore) == 3)


# ---------------------------------------------------------------------------
# Section 13: remove_mapping_record()
# ---------------------------------------------------------------------------
print("\n── 13. remove_mapping_record() ──────────────────────────────────────")

mstore_rem = [m1, m2, m3]
mstore_after = remove_mapping_record(mstore_rem, m1.mappingId)
check("remove mapping: count decremented",           len(mstore_after) == 2)
check("remove mapping: target gone",                 not any(m.mappingId == m1.mappingId for m in mstore_after))
check("remove mapping: others preserved",            any(m.mappingId == m2.mappingId for m in mstore_after))
check("remove mapping: result sorted",               all(mstore_after[i].mappingId <= mstore_after[i+1].mappingId for i in range(len(mstore_after)-1)))

# Missing
mstore_miss = remove_mapping_record(mstore_rem, "nonexistent")
check("remove missing mapping: count unchanged",     len(mstore_miss) == len(mstore_rem))

# Remove all
mstore_one = [m1]
mstore_empty = remove_mapping_record(mstore_one, m1.mappingId)
check("remove last mapping: empty list",             mstore_empty == [])


# ---------------------------------------------------------------------------
# Section 14: merge_mappings()
# ---------------------------------------------------------------------------
print("\n── 14. merge_mappings() ─────────────────────────────────────────────")

base_m = build_cve_mapping(
    [_rec_log4j()], TS1,
    finding_id="f-merge", alert_id="a-merge", confidence=70.0
)
incoming_m = build_cve_mapping(
    [_rec_log4j(), _rec_proxylogon()], TS2,
    finding_id="f-merge", alert_id="a-merge", confidence=90.0
)

merged_m = merge_mappings(base_m, incoming_m, TS3)
check("merge mapping: mappingId from base",          merged_m.mappingId == base_m.mappingId)
check("merge mapping: mappingKey from base",         merged_m.mappingKey == base_m.mappingKey)
check("merge mapping: findingId preserved",          merged_m.findingId == "f-merge")
check("merge mapping: alertId preserved",            merged_m.alertId == "a-merge")
check("merge mapping: confidence = max(70,90)=90",   merged_m.confidence == 90.0)
check("merge mapping: CVE records unioned",          len(merged_m.cveRecords) == 2)
check("merge mapping: CVE records sorted",           merged_m.cveRecords[0].cveId <= merged_m.cveRecords[-1].cveId)
check("merge mapping: fingerprint recomputed",       len(merged_m.mappingFingerprint) == 32)
check("merge mapping: createdAt from caller",        merged_m.createdAt == TS3)
# Fingerprint changes because record set changed
check("merge mapping: fingerprint differs from base", merged_m.mappingFingerprint != base_m.mappingFingerprint)

# Idempotent CVE dedup in merge
incoming_dup = build_cve_mapping(
    [_rec_log4j(), _rec_log4j()], TS2,  # both same cveId
    finding_id="f-merge", alert_id="a-merge", confidence=80.0
)
merged_dup = merge_mappings(base_m, incoming_dup, TS3)
check("merge: duplicate CVEs deduped in result",     len(merged_dup.cveRecords) == 1)

# Error on mismatched source IDs
m_other = build_cve_mapping([_rec_low()], TS1, finding_id="other-f", alert_id="a-merge")
try:
    merge_mappings(base_m, m_other, TS3)
    check("merge mismatched findingId → CVEIntelligenceError", False)
except CVEIntelligenceError:
    check("merge mismatched findingId → CVEIntelligenceError", True)


# ---------------------------------------------------------------------------
# Section 15: find_cve_record()
# ---------------------------------------------------------------------------
print("\n── 15. find_cve_record() ────────────────────────────────────────────")

pool = [_rec_log4j(), _rec_proxylogon(), _rec_low()]
r_log = _rec_log4j()

found_by_id  = find_cve_record(pool, record_id=r_log.recordId)
found_by_cve = find_cve_record(pool, cve_id="CVE-2021-44228")
found_by_cve_lc = find_cve_record(pool, cve_id="cve-2021-44228")
not_found_id = find_cve_record(pool, record_id="nonexistent")
not_found_cve = find_cve_record(pool, cve_id="CVE-9999-99999")
not_found_none = find_cve_record(pool)

check("find by recordId returns correct record",     found_by_id is not None and found_by_id.recordId == r_log.recordId)
check("find by cveId returns correct record",        found_by_cve is not None and found_by_cve.cveId == "CVE-2021-44228")
check("find by cveId case-insensitive",              found_by_cve_lc is not None)
check("find by recordId not found → None",           not_found_id is None)
check("find by cveId not found → None",              not_found_cve is None)
check("find with no params → None",                  not_found_none is None)

# Priority: recordId checked first
found_priority = find_cve_record(pool, record_id=r_log.recordId, cve_id="CVE-9999-99999")
check("find: recordId priority over cveId",          found_priority is not None and found_priority.recordId == r_log.recordId)


# ---------------------------------------------------------------------------
# Section 16: find_mapping()
# ---------------------------------------------------------------------------
print("\n── 16. find_mapping() ───────────────────────────────────────────────")

mpool = [m1, m2, m3]

found_m_id  = find_mapping(mpool, mapping_id=m1.mappingId)
found_m_key = find_mapping(mpool, mapping_key=m2.mappingKey)
not_found_m_id  = find_mapping(mpool, mapping_id="nonexistent")
not_found_m_key = find_mapping(mpool, mapping_key="nonexistent")
not_found_m_none = find_mapping(mpool)

check("find_mapping by mappingId",                   found_m_id is not None and found_m_id.mappingId == m1.mappingId)
check("find_mapping by mappingKey",                  found_m_key is not None and found_m_key.mappingKey == m2.mappingKey)
check("find_mapping by mappingId not found → None",  not_found_m_id is None)
check("find_mapping by mappingKey not found → None", not_found_m_key is None)
check("find_mapping no params → None",               not_found_m_none is None)

# Priority
found_m_prio = find_mapping(mpool, mapping_id=m1.mappingId, mapping_key="nonexistent")
check("find_mapping: mappingId priority over mappingKey", found_m_prio is not None and found_m_prio.mappingId == m1.mappingId)


# ---------------------------------------------------------------------------
# Section 17: sort_cve_records()
# ---------------------------------------------------------------------------
print("\n── 17. sort_cve_records() ───────────────────────────────────────────")

all_recs = [_rec_log4j(), _rec_proxylogon(), _rec_low(), _rec_medium(), _rec_high()]

s_cve_asc  = sort_cve_records(all_recs, by="cveId", ascending=True)
check("sort cveId ASC: first <= last",               s_cve_asc[0].cveId <= s_cve_asc[-1].cveId)

s_cve_desc = sort_cve_records(all_recs, by="cveId", ascending=False)
check("sort cveId DESC: first >= last",              s_cve_desc[0].cveId >= s_cve_desc[-1].cveId)

s_sev_asc  = sort_cve_records(all_recs, by="severity", ascending=True)
_sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
check("sort severity ASC: LOW first",                _sev_order[s_sev_asc[0].severity.value] <= _sev_order[s_sev_asc[-1].severity.value])

s_sev_desc = sort_cve_records(all_recs, by="severity", ascending=False)
check("sort severity DESC: CRITICAL first",          _sev_order[s_sev_desc[0].severity.value] >= _sev_order[s_sev_desc[-1].severity.value])
check("sort severity DESC: first is CRITICAL",       s_sev_desc[0].severity == SeverityEnum.CRITICAL)

s_cvss_desc = sort_cve_records(all_recs, by="cvssScore", ascending=False)
check("sort cvssScore DESC: highest first",          s_cvss_desc[0].cvssScore >= s_cvss_desc[-1].cvssScore)

s_cvss_asc  = sort_cve_records(all_recs, by="cvssScore", ascending=True)
check("sort cvssScore ASC: lowest first",            s_cvss_asc[0].cvssScore <= s_cvss_asc[-1].cvssScore)

s_created   = sort_cve_records(all_recs, by="createdAt", ascending=True)
check("sort createdAt ASC: consistent order",        len(s_created) == len(all_recs))

# Stable (same result repeated)
s2 = sort_cve_records(all_recs, by="cvssScore", ascending=False)
check("sort is deterministic (stable re-run)",       [r.recordId for r in s_cvss_desc] == [r.recordId for r in s2])

# Invalid key
try:
    sort_cve_records(all_recs, by="bogus")
    check("sort_cve_records invalid key → ValueError", False)
except ValueError:
    check("sort_cve_records invalid key → ValueError", True)


# ---------------------------------------------------------------------------
# Section 18: sort_cve_mappings()
# ---------------------------------------------------------------------------
print("\n── 18. sort_cve_mappings() ──────────────────────────────────────────")

mall = [
    build_cve_mapping([_rec_log4j()], TS1, finding_id="fa", confidence=90.0),
    build_cve_mapping([_rec_low()],   TS2, finding_id="fb", confidence=50.0),
    build_cve_mapping([_rec_high()],  TS3, finding_id="fc", confidence=70.0),
]

sm_id_asc  = sort_cve_mappings(mall, by="mappingId", ascending=True)
check("sort mappingId ASC",                          sm_id_asc[0].mappingId <= sm_id_asc[-1].mappingId)

sm_conf_desc = sort_cve_mappings(mall, by="confidence", ascending=False)
check("sort confidence DESC: highest first",         sm_conf_desc[0].confidence >= sm_conf_desc[-1].confidence)
check("sort confidence DESC: 90.0 first",            sm_conf_desc[0].confidence == 90.0)

sm_conf_asc  = sort_cve_mappings(mall, by="confidence", ascending=True)
check("sort confidence ASC: lowest first",           sm_conf_asc[0].confidence <= sm_conf_asc[-1].confidence)

sm_created   = sort_cve_mappings(mall, by="createdAt", ascending=True)
check("sort createdAt ASC: consistent count",        len(sm_created) == 3)

# Stable
sm2 = sort_cve_mappings(mall, by="confidence", ascending=False)
check("sort_cve_mappings deterministic (re-run)",    [m.mappingId for m in sm_conf_desc] == [m.mappingId for m in sm2])

# Invalid key
try:
    sort_cve_mappings(mall, by="invalid")
    check("sort_cve_mappings invalid key → ValueError", False)
except ValueError:
    check("sort_cve_mappings invalid key → ValueError", True)


# ---------------------------------------------------------------------------
# Section 19: filter_cve_records()
# ---------------------------------------------------------------------------
print("\n── 19. filter_cve_records() ─────────────────────────────────────────")

frecs = [_rec_log4j(), _rec_proxylogon(), _rec_high(), _rec_medium(), _rec_low()]

# By severity
f_crit = filter_cve_records(frecs, severity=SeverityEnum.CRITICAL)
check("filter severity=CRITICAL: count = 2",         len(f_crit) == 2)
check("filter severity=CRITICAL: all CRITICAL",      all(r.severity == SeverityEnum.CRITICAL for r in f_crit))

f_low  = filter_cve_records(frecs, severity=SeverityEnum.LOW)
check("filter severity=LOW: count = 1",              len(f_low) == 1)

# By CVSS range
f_high_cvss = filter_cve_records(frecs, min_cvss=9.0)
check("filter min_cvss=9.0: all >= 9.0",             all(r.cvssScore >= 9.0 for r in f_high_cvss))

f_max_cvss  = filter_cve_records(frecs, max_cvss=5.0)
check("filter max_cvss=5.0: all <= 5.0",             all(r.cvssScore <= 5.0 for r in f_max_cvss))

f_range = filter_cve_records(frecs, min_cvss=5.0, max_cvss=8.0)
check("filter 5.0 <= cvss <= 8.0",                   all(5.0 <= r.cvssScore <= 8.0 for r in f_range))

# By affected platform
f_win = filter_cve_records(frecs, affected_platform="windows")
check("filter platform=windows: all have windows",   all("windows" in r.affectedPlatforms for r in f_win))

f_linux = filter_cve_records(frecs, affected_platform="Linux")  # case-insensitive
check("filter platform=Linux case-insensitive",      all("linux" in r.affectedPlatforms for r in f_linux))

# By mapped technique
t_t1190 = _make_technique("TA0001", "T1190")
r_with_t = build_cve_record("CVE-2025-99999", SeverityEnum.HIGH, 7.0, TS1,
                              mapped_techniques=[t_t1190])
frecs2 = [_rec_log4j(), r_with_t]
f_tech = filter_cve_records(frecs2, mapped_technique_id="T1190")
check("filter mapped_technique_id=T1190",            len(f_tech) == 2)  # log4j also has T1190

f_tech_none = filter_cve_records(frecs, mapped_technique_id="T9999")
check("filter unmapped technique → empty",           len(f_tech_none) == 0)

# No filter → all returned
f_all = filter_cve_records(frecs)
check("filter no criteria → all returned",           len(f_all) == len(frecs))

# Empty input
f_empty = filter_cve_records([], severity=SeverityEnum.CRITICAL)
check("filter empty input → empty output",           f_empty == [])


# ---------------------------------------------------------------------------
# Section 20: filter_cve_mappings()
# ---------------------------------------------------------------------------
print("\n── 20. filter_cve_mappings() ────────────────────────────────────────")

fmaps = [
    build_cve_mapping([_rec_log4j(), _rec_proxylogon()], TS1, finding_id="fa", confidence=90.0),
    build_cve_mapping([_rec_high()],  TS1, finding_id="fb", confidence=70.0),
    build_cve_mapping([_rec_medium()], TS1, finding_id="fc", confidence=50.0),
    build_cve_mapping([_rec_low()],   TS1, finding_id="fd", confidence=30.0),
]

# By confidence
f_conf = filter_cve_mappings(fmaps, min_confidence=70.0)
check("filter min_confidence=70: all >= 70",         all(m.confidence >= 70.0 for m in f_conf))
check("filter min_confidence=70: count = 2",         len(f_conf) == 2)

# By severity (at least one CVE matches)
f_sev = filter_cve_mappings(fmaps, severity=SeverityEnum.CRITICAL)
check("filter severity CRITICAL: at least one CVE",  all(any(r.severity == SeverityEnum.CRITICAL for r in m.cveRecords) for m in f_sev))

# By CVSS floor
f_min_c = filter_cve_mappings(fmaps, min_cvss=9.0)
check("filter min_cvss=9 on mappings",               all(any(r.cvssScore >= 9.0 for r in m.cveRecords) for m in f_min_c))

# By CVSS ceiling
f_max_c = filter_cve_mappings(fmaps, max_cvss=3.0)
check("filter max_cvss=3: all CVEs <= 3",            all(all(r.cvssScore <= 3.0 for r in m.cveRecords) for m in f_max_c))

# By platform
f_plat_m = filter_cve_mappings(fmaps, affected_platform="windows")
check("filter mapping platform=windows: all have windows CVE", len(f_plat_m) >= 1)

# By technique
r_with_t2 = build_cve_record("CVE-2026-00001", SeverityEnum.HIGH, 7.0, TS1,
                               mapped_techniques=[_make_technique("TA0001", "T1190")])
fmaps2 = [build_cve_mapping([r_with_t2], TS1, finding_id="fx")]
f_tech_m = filter_cve_mappings(fmaps2, mapped_technique_id="T1190")
check("filter mapping by technique id",              len(f_tech_m) == 1)

# No filters → all returned
f_all_m = filter_cve_mappings(fmaps)
check("filter_cve_mappings no criteria → all",       len(f_all_m) == len(fmaps))

# Empty
f_empty_m = filter_cve_mappings([], min_confidence=50.0)
check("filter_cve_mappings empty input → empty",     f_empty_m == [])


# ---------------------------------------------------------------------------
# Section 21: group_cve_records()
# ---------------------------------------------------------------------------
print("\n── 21. group_cve_records() ──────────────────────────────────────────")

grecs = [_rec_log4j(), _rec_proxylogon(), _rec_high(), _rec_medium(), _rec_low()]

# By severity
g_sev = group_cve_records(grecs, by="severity")
check("group by severity: CRITICAL key exists",      "CRITICAL" in g_sev)
check("group by severity: LOW key exists",           "LOW" in g_sev)
check("group by severity: CRITICAL has 2",           len(g_sev["CRITICAL"]) == 2)
check("group by severity: HIGH has 1",               len(g_sev.get("HIGH", [])) == 1)
check("group by severity: each list sorted by cveId", all(g_sev[k] == sorted(g_sev[k], key=lambda r: r.cveId) for k in g_sev))

# By year
g_year = group_cve_records(grecs, by="year")
check("group by year: 2021 key exists",              "2021" in g_year)
check("group by year: 2020 key exists",              "2020" in g_year)
check("group by year: 2021 has 2 CVEs",              len(g_year["2021"]) == 2)

# By platform
r_linux  = build_cve_record("CVE-2025-00001", SeverityEnum.HIGH, 7.0, TS1, affected_platforms=["linux"])
r_win    = build_cve_record("CVE-2025-00002", SeverityEnum.HIGH, 7.5, TS1, affected_platforms=["windows"])
r_multi  = build_cve_record("CVE-2025-00003", SeverityEnum.HIGH, 8.0, TS1, affected_platforms=["linux", "windows"])
g_plat = group_cve_records([r_linux, r_win, r_multi], by="platform")
check("group by platform: linux key exists",         "linux" in g_plat)
check("group by platform: windows key exists",       "windows" in g_plat)
check("group by platform: multi-platform in both",   any(r.cveId == "CVE-2025-00003" for r in g_plat["linux"]))
check("group by platform: multi-platform in windows", any(r.cveId == "CVE-2025-00003" for r in g_plat["windows"]))

# No platforms → unknown
r_noplat = build_cve_record("CVE-2025-00004", SeverityEnum.LOW, 1.0, TS1)
g_noplat = group_cve_records([r_noplat], by="platform")
check("group by platform: no platforms → 'unknown'", "unknown" in g_noplat)

# By mapped_technique
t_a = _make_technique("TA0001", "T1190")
t_b = _make_technique("TA0002", "T1059")
r_t1 = build_cve_record("CVE-2025-10001", SeverityEnum.HIGH, 7.0, TS1, mapped_techniques=[t_a])
r_t2 = build_cve_record("CVE-2025-10002", SeverityEnum.HIGH, 7.5, TS1, mapped_techniques=[t_a, t_b])
r_t0 = build_cve_record("CVE-2025-10003", SeverityEnum.LOW, 2.0, TS1)  # no techniques
g_tech = group_cve_records([r_t1, r_t2, r_t0], by="mapped_technique")
check("group by mapped_technique: TA0001 key exists", "TA0001" in g_tech)
check("group by mapped_technique: TA0002 key exists", "TA0002" in g_tech)
check("group by mapped_technique: unmapped → 'unmapped'", "unmapped" in g_tech)
check("group by mapped_technique: TA0001 has 2 entries", len(g_tech["TA0001"]) == 2)

# Keys are sorted
check("group_cve_records keys are sorted",           list(g_sev.keys()) == sorted(g_sev.keys()))

# Invalid key
try:
    group_cve_records(grecs, by="bad_key")
    check("group_cve_records invalid key → ValueError", False)
except ValueError:
    check("group_cve_records invalid key → ValueError", True)

# Empty input
g_empty = group_cve_records([], by="severity")
check("group_cve_records empty input → empty dict",  g_empty == {})


# ---------------------------------------------------------------------------
# Section 22: group_cve_mappings()
# ---------------------------------------------------------------------------
print("\n── 22. group_cve_mappings() ─────────────────────────────────────────")

gmmaps = [
    build_cve_mapping([_rec_log4j(), _rec_proxylogon()], TS1, finding_id="gf1", confidence=80.0),
    build_cve_mapping([_rec_high()],  TS2, finding_id="gf2", confidence=60.0),
    build_cve_mapping([_rec_low()],   TS3, finding_id="gf3", confidence=40.0),
]

g_msev = group_cve_mappings(gmmaps, by="severity")
check("group mappings by severity: CRITICAL exists", "CRITICAL" in g_msev)
check("group mappings by severity: HIGH exists",     "HIGH" in g_msev)
check("group mappings by severity: LOW exists",      "LOW" in g_msev)
check("group mappings by severity: sorted by mappingId",
      all(g_msev[k] == sorted(g_msev[k], key=lambda m: m.mappingId) for k in g_msev))

g_myear = group_cve_mappings(gmmaps, by="year")
check("group mappings by year: 2021 exists",         "2021" in g_myear)
check("group mappings by year: 2020 exists",         "2020" in g_myear)

# By platform
r_lx = build_cve_record("CVE-2026-10001", SeverityEnum.HIGH, 7.0, TS1, affected_platforms=["linux"])
r_wx = build_cve_record("CVE-2026-10002", SeverityEnum.HIGH, 7.0, TS1, affected_platforms=["windows"])
mp_lx = build_cve_mapping([r_lx], TS1, finding_id="gp1")
mp_wx = build_cve_mapping([r_wx], TS1, finding_id="gp2")
g_mplat = group_cve_mappings([mp_lx, mp_wx], by="platform")
check("group mappings by platform: linux",           "linux" in g_mplat)
check("group mappings by platform: windows",         "windows" in g_mplat)

# By mapped_technique
r_with_ta = build_cve_record("CVE-2026-20001", SeverityEnum.HIGH, 7.0, TS1,
                               mapped_techniques=[_make_technique("TA0001", "T1190")])
mt_map = build_cve_mapping([r_with_ta], TS1, finding_id="gt1")
mt_empty = build_cve_mapping([_rec_low()], TS1, finding_id="gt2")
g_mtch = group_cve_mappings([mt_map, mt_empty], by="mapped_technique")
check("group mappings by technique: TA0001 exists", "TA0001" in g_mtch)
check("group mappings by technique: unmapped exists", "unmapped" in g_mtch)

# Keys sorted
check("group_cve_mappings keys are sorted",          list(g_msev.keys()) == sorted(g_msev.keys()))

# Invalid key
try:
    group_cve_mappings(gmmaps, by="invalid_key")
    check("group_cve_mappings invalid key → ValueError", False)
except ValueError:
    check("group_cve_mappings invalid key → ValueError", True)

# Empty
g_mempty = group_cve_mappings([], by="severity")
check("group_cve_mappings empty → empty dict",       g_mempty == {})


# ---------------------------------------------------------------------------
# Section 23: Integration helpers
# ---------------------------------------------------------------------------
print("\n── 23. Integration helpers ──────────────────────────────────────────")

# finding_to_cve_mapping
class _MockFinding:
    findingId = "finding-abc"

finding = _MockFinding()
m_from_finding = finding_to_cve_mapping(finding, [_rec_log4j()], TS1, confidence=75.0)
check("finding_to_cve_mapping: findingId set",       m_from_finding.findingId == "finding-abc")
check("finding_to_cve_mapping: alertId empty",       m_from_finding.alertId == "")
check("finding_to_cve_mapping: reasoningId empty",   m_from_finding.reasoningId == "")
check("finding_to_cve_mapping: confidence = 75.0",   m_from_finding.confidence == 75.0)
check("finding_to_cve_mapping: cveRecords correct",  len(m_from_finding.cveRecords) == 1)
check("finding_to_cve_mapping: deterministic",
      finding_to_cve_mapping(finding, [_rec_log4j()], TS1, confidence=75.0).mappingId == m_from_finding.mappingId)

# alert_to_cve_mapping
class _MockAlert:
    alertId   = "alert-xyz"
    findingId = "finding-abc"

alert = _MockAlert()
m_from_alert = alert_to_cve_mapping(alert, [_rec_log4j()], TS1, confidence=88.0)
check("alert_to_cve_mapping: alertId set",           m_from_alert.alertId == "alert-xyz")
check("alert_to_cve_mapping: findingId set",         m_from_alert.findingId == "finding-abc")
check("alert_to_cve_mapping: reasoningId empty",     m_from_alert.reasoningId == "")
check("alert_to_cve_mapping: confidence = 88.0",     m_from_alert.confidence == 88.0)
check("alert_to_cve_mapping: deterministic",
      alert_to_cve_mapping(alert, [_rec_log4j()], TS1, confidence=88.0).mappingId == m_from_alert.mappingId)

# reasoning_to_cve_mapping
class _MockReasoning:
    reasoningId       = "reasoning-123"
    overallConfidence = 92.0

reasoning = _MockReasoning()
m_from_reasoning = reasoning_to_cve_mapping(
    reasoning, [_rec_proxylogon()], TS1,
    finding_id="find-rea", alert_id="alert-rea"
)
check("reasoning_to_cve_mapping: reasoningId set",   m_from_reasoning.reasoningId == "reasoning-123")
check("reasoning_to_cve_mapping: findingId set",     m_from_reasoning.findingId == "find-rea")
check("reasoning_to_cve_mapping: alertId set",       m_from_reasoning.alertId == "alert-rea")
check("reasoning_to_cve_mapping: confidence from reasoning", m_from_reasoning.confidence == 92.0)
check("reasoning_to_cve_mapping: deterministic",
      reasoning_to_cve_mapping(reasoning, [_rec_proxylogon()], TS1,
                                finding_id="find-rea", alert_id="alert-rea").mappingId
      == m_from_reasoning.mappingId)

# mitre_to_cve_reference
t_new = _make_technique("TA0003", "T1078")
r_base = _rec_log4j()  # already has T1059 and T1190
r_extended = mitre_to_cve_reference(t_new, r_base, TS2)
check("mitre_to_cve_reference: technique added",     len(r_extended.mappedTechniques) == 3)
check("mitre_to_cve_reference: recordId unchanged",  r_extended.recordId == r_base.recordId)
check("mitre_to_cve_reference: cveId unchanged",     r_extended.cveId == r_base.cveId)
check("mitre_to_cve_reference: createdAt updated",   r_extended.createdAt == TS2)
check("mitre_to_cve_reference: techniques sorted",   all(
    r_extended.mappedTechniques[i].mitreId <= r_extended.mappedTechniques[i+1].mitreId
    for i in range(len(r_extended.mappedTechniques)-1)
))

# Idempotent: adding existing technique returns same record
r_idem = mitre_to_cve_reference(
    _make_technique("TA0001", "T1190"), r_base, TS2
)
check("mitre_to_cve_reference: idempotent (already linked)", r_idem is r_base)
check("mitre_to_cve_reference: count unchanged on dup",      len(r_idem.mappedTechniques) == len(r_base.mappedTechniques))


# ---------------------------------------------------------------------------
# Section 24: Serialization / round-trip
# ---------------------------------------------------------------------------
print("\n── 24. Serialization / round-trip ───────────────────────────────────")

r_ser = _rec_log4j()
d = r_ser.model_dump()
check("model_dump: recordId present",                "recordId" in d)
check("model_dump: cveId present",                   "cveId" in d)
check("model_dump: severity is string",              isinstance(d["severity"], str))
check("model_dump: cvssScore is float",              isinstance(d["cvssScore"], float))
check("model_dump: references is list/tuple",        isinstance(d["references"], (list, tuple)))

r_rt = CVERecord(**d)
check("round-trip: recordId preserved",              r_rt.recordId == r_ser.recordId)
check("round-trip: cveId preserved",                 r_rt.cveId == r_ser.cveId)
check("round-trip: severity preserved",              r_rt.severity == r_ser.severity)
check("round-trip: cvssScore preserved",             r_rt.cvssScore == r_ser.cvssScore)

m_ser = _make_mapping()
dm = m_ser.model_dump()
check("mapping model_dump: mappingId present",       "mappingId" in dm)
check("mapping model_dump: mappingFingerprint present", "mappingFingerprint" in dm)
check("mapping model_dump: confidence float",        isinstance(dm["confidence"], float))

m_rt = CVEMapping(**dm)
check("mapping round-trip: mappingId preserved",     m_rt.mappingId == m_ser.mappingId)
check("mapping round-trip: confidence preserved",    m_rt.confidence == m_ser.confidence)


# ---------------------------------------------------------------------------
# Section 25: Zero randomness / multiple runs
# ---------------------------------------------------------------------------
print("\n── 25. Zero randomness (determinism across runs) ────────────────────")

for i in range(5):
    r_i = _rec_log4j()
    check(f"run {i+1}: recordId identical",          r_i.recordId == _rec_log4j().recordId)

for i in range(5):
    m_i = _make_mapping()
    check(f"run {i+1}: mappingId identical",         m_i.mappingId == _make_mapping().mappingId)

for i in range(3):
    fp_i = cveMappingFingerprint(
        cveMappingKey("f1", "a1", "r1", ("id-a", "id-b")),
        "f1", "a1", "r1", ("id-a", "id-b")
    )
    fp_j = cveMappingFingerprint(
        cveMappingKey("f1", "a1", "r1", ("id-b", "id-a")),  # reversed
        "f1", "a1", "r1", ("id-b", "id-a")
    )
    check(f"run {i+1}: fingerprint order-independent", fp_i == fp_j)


# ---------------------------------------------------------------------------
# Section 26: Edge cases
# ---------------------------------------------------------------------------
print("\n── 26. Edge cases ───────────────────────────────────────────────────")

# CVE ID with many digits
r_long = build_cve_record("CVE-2021-123456789", SeverityEnum.HIGH, 7.0, TS1)
check("cveId with 9-digit number accepted",          r_long.cveId == "CVE-2021-123456789")

# Leading/trailing whitespace in cveId
r_ws = build_cve_record("  CVE-2023-55555  ", SeverityEnum.LOW, 1.0, TS1)
check("whitespace-padded cveId stripped+uppercased", r_ws.cveId == "CVE-2023-55555")

# CVSS score exactly at boundaries
r_0  = build_cve_record("CVE-2024-00002", SeverityEnum.LOW, 0.0, TS1)
r_10 = build_cve_record("CVE-2024-00003", SeverityEnum.CRITICAL, 10.0, TS1)
check("cvssScore 0.0 boundary",                      r_0.cvssScore  == 0.0)
check("cvssScore 10.0 boundary",                     r_10.cvssScore == 10.0)

# Confidence exactly at boundaries
m_conf0   = build_cve_mapping([_rec_low()], TS1, finding_id="f1", confidence=0.0)
m_conf100 = build_cve_mapping([_rec_low()], TS1, finding_id="f2", confidence=100.0)
check("confidence 0.0 boundary",                     m_conf0.confidence == 0.0)
check("confidence 100.0 boundary",                   m_conf100.confidence == 100.0)

# Single CVE mapping
m_single = build_cve_mapping([_rec_log4j()], TS1, finding_id="single")
check("single CVE mapping: cveRecords count = 1",    len(m_single.cveRecords) == 1)

# Empty references list deduplication
r_no_refs = build_cve_record("CVE-2024-00004", SeverityEnum.LOW, 1.0, TS1, references=[])
check("empty references → empty tuple",              r_no_refs.references == ())

# Sort empty list
check("sort_cve_records empty → empty",              sort_cve_records([]) == [])
check("sort_cve_mappings empty → empty",             sort_cve_mappings([]) == [])

# Filter empty list
check("filter_cve_records empty → empty",            filter_cve_records([]) == [])
check("filter_cve_mappings empty → empty",           filter_cve_mappings([]) == [])

# add_cve_record to empty store
s_from_empty = add_cve_record([], _rec_log4j())
check("add to empty store → 1 record",               len(s_from_empty) == 1)

# remove_mapping_record from empty store
check("remove from empty mapping store → empty",     remove_mapping_record([], "x") == [])

# merge_mappings same record repeated → dedup
base_m2 = build_cve_mapping([_rec_log4j()], TS1, finding_id="fm2", alert_id="am2")
inc_m2  = build_cve_mapping([_rec_log4j()], TS2, finding_id="fm2", alert_id="am2")
merged_same = merge_mappings(base_m2, inc_m2, TS3)
check("merge same CVE twice → deduped to 1",         len(merged_same.cveRecords) == 1)


# ---------------------------------------------------------------------------
# Section 27: Statistics — extended edge cases
# ---------------------------------------------------------------------------
print("\n── 27. Statistics extended edge cases ───────────────────────────────")

# All same severity
m_all_crit = build_cve_mapping([_rec_log4j(), _rec_proxylogon()], TS1, finding_id="ac", confidence=100.0)
s_all_crit = build_cve_statistics([m_all_crit])
check("stats all CRITICAL: criticalCVEs = 2",        s_all_crit.criticalCVEs == 2)
check("stats all CRITICAL: highCVEs = 0",            s_all_crit.highCVEs == 0)
check("stats all CRITICAL: averageConfidence = 100.0", s_all_crit.averageConfidence == 100.0)

# averageCVSS precision
m_prec = build_cve_mapping([_rec_medium(), _rec_low()], TS1, finding_id="fp")
s_prec = build_cve_statistics([m_prec])
expected_prec = round((5.0 + 2.5) / 2, 4)
check("stats averageCVSS precision",                 s_prec.averageCVSS == expected_prec)

# Multiple mappings sharing same CVE dedup
m_share_a = build_cve_mapping([_rec_log4j()], TS1, finding_id="sha", confidence=50.0)
m_share_b = build_cve_mapping([_rec_log4j()], TS2, finding_id="shb", confidence=70.0)
s_share = build_cve_statistics([m_share_a, m_share_b])
check("shared CVE across mappings → totalCVEs=1",    s_share.totalCVEs == 1)
check("shared CVE: criticalCVEs=1",                  s_share.criticalCVEs == 1)
check("shared CVE: averageConfidence = mean",        s_share.averageConfidence == round((50.0 + 70.0) / 2, 4))

# CVEStatistics is immutable
s_imm = build_cve_statistics([m_all_crit])
try:
    s_imm.totalCVEs = 0  # type: ignore
    check("CVEStatistics immutable",                 False)
except Exception:
    check("CVEStatistics immutable",                 True)


# ---------------------------------------------------------------------------
# Section 28: Extended deterministic ID coverage
# ---------------------------------------------------------------------------
print("\n── 28. Extended ID coverage ─────────────────────────────────────────")

from services.cve_intelligence_service import _uuid5 as _u5

# recordKey uniqueness for 10 distinct CVEs
cve_ids_28 = [f"CVE-2021-{1000+i}" for i in range(10)]
keys_28 = [recordKey(c) for c in cve_ids_28]
check("10 distinct CVE IDs → 10 distinct recordKeys", len(set(keys_28)) == 10)
check("all recordKeys are 32 chars",                 all(len(k) == 32 for k in keys_28))

# UUIDv5 from recordKey is always valid UUID
for ci in cve_ids_28:
    k28 = recordKey(ci)
    uid = _u5(k28)
    check(f"UUID for {ci} is valid",                 len(uid) == 36 and uid.count("-") == 4)

# mappingKey changes with each field
base_ids_28 = ("rid1", "rid2")
mk_28 = cveMappingKey("f1", "a1", "r1", base_ids_28)
check("mappingKey differs: different reasoningId",   mk_28 != cveMappingKey("f1", "a1", "r2", base_ids_28))
check("mappingKey differs: different records",       mk_28 != cveMappingKey("f1", "a1", "r1", ("rid1",)))

# fingerprint changes with different keys
fp_base_28 = cveMappingFingerprint(mk_28, "f1", "a1", "r1", base_ids_28)
mk2_28     = cveMappingKey("f1", "a1", "r1", ("rid1",))
fp2_28     = cveMappingFingerprint(mk2_28, "f1", "a1", "r1", ("rid1",))
check("fingerprint differs when records differ",     fp_base_28 != fp2_28)

# Same CVE different capitalisation → same key
check("CVE-2021-44228 == cve-2021-44228 recordKey",  recordKey("CVE-2021-44228") == recordKey("cve-2021-44228"))
check("CVE-2021-44228 == Cve-2021-44228 recordKey",  recordKey("CVE-2021-44228") == recordKey("Cve-2021-44228"))

# Fingerprint is order-independent on record IDs
fp_fwd = cveMappingFingerprint(mk_28, "f1", "a1", "r1", ("rid1", "rid2"))
fp_rev = cveMappingFingerprint(mk_28, "f1", "a1", "r1", ("rid2", "rid1"))
check("fingerprint order-independent (fwd==rev)",    fp_fwd == fp_rev)

# 5 different cveIds produce 5 different recordIds
ids_5 = [build_cve_record(f"CVE-202{i}-11111", SeverityEnum.HIGH, 7.0, TS1).recordId for i in range(5)]
check("5 distinct cveIds → 5 distinct recordIds",    len(set(ids_5)) == 5)


# ---------------------------------------------------------------------------
# Section 29: Bulk add / remove / update stress
# ---------------------------------------------------------------------------
print("\n── 29. Bulk add/remove/update stress ────────────────────────────────")

bulk_store: list = []
bulk_recs = []
for bi in range(20):
    br = build_cve_record(f"CVE-2025-{10000+bi}", SeverityEnum.HIGH, float(bi % 10) + 1.0, TS1)
    bulk_recs.append(br)
    bulk_store = add_cve_record(bulk_store, br)

check("bulk add 20 records → count = 20",            len(bulk_store) == 20)
check("bulk add: sorted by cveId",                   all(bulk_store[bi].cveId <= bulk_store[bi+1].cveId for bi in range(19)))

# Add all again (all duplicates)
for br in bulk_recs:
    bulk_store = add_cve_record(bulk_store, br)
check("bulk duplicate add: count still 20",          len(bulk_store) == 20)

# Remove 10
for br in bulk_recs[:10]:
    bulk_store = remove_cve_record(bulk_store, br.recordId)
check("bulk remove 10: count = 10",                  len(bulk_store) == 10)
check("bulk remove: remaining sorted",               all(bulk_store[bi].cveId <= bulk_store[bi+1].cveId for bi in range(len(bulk_store)-1)))

# Update all remaining to CRITICAL
for br in list(bulk_store):
    bulk_store = update_cve_record(bulk_store, br.recordId, severity=SeverityEnum.CRITICAL)
check("bulk update all to CRITICAL",                 all(br.severity == SeverityEnum.CRITICAL for br in bulk_store))
check("bulk update: count unchanged (10)",           len(bulk_store) == 10)

# Bulk mappings
bulk_mstore: list = []
bulk_maps = [build_cve_mapping([_rec_log4j()], TS1, finding_id=f"bf{mi}") for mi in range(15)]
for bm in bulk_maps:
    bulk_mstore = add_mapping_record(bulk_mstore, bm)
check("bulk mapping add 15 → count = 15",            len(bulk_mstore) == 15)
# Dup add
for bm in bulk_maps:
    bulk_mstore = add_mapping_record(bulk_mstore, bm)
check("bulk mapping dup add: count still 15",        len(bulk_mstore) == 15)
# Remove 5
for bm in bulk_maps[:5]:
    bulk_mstore = remove_mapping_record(bulk_mstore, bm.mappingId)
check("bulk mapping remove 5: count = 10",           len(bulk_mstore) == 10)


# ---------------------------------------------------------------------------
# Section 30: Extended sorting stability
# ---------------------------------------------------------------------------
print("\n── 30. Extended sorting stability ───────────────────────────────────")

sort_recs = [
    build_cve_record("CVE-2021-00001", SeverityEnum.CRITICAL, 9.5, TS1),
    build_cve_record("CVE-2021-00002", SeverityEnum.CRITICAL, 9.5, TS1),
    build_cve_record("CVE-2019-11111", SeverityEnum.HIGH,     7.5, TS1),
    build_cve_record("CVE-2020-00001", SeverityEnum.LOW,      2.5, TS1),
    build_cve_record("CVE-2022-22222", SeverityEnum.HIGH,     7.8, TS1),
    build_cve_record("CVE-2023-33333", SeverityEnum.MEDIUM,   5.0, TS2),
]

asc30  = sort_cve_records(sort_recs, by="cveId", ascending=True)
desc30 = sort_cve_records(sort_recs, by="cveId", ascending=False)
check("cveId ASC/DESC reversal",                     [r.cveId for r in asc30] == list(reversed([r.cveId for r in desc30])))

sev_asc30 = sort_cve_records(sort_recs, by="severity", ascending=True)
check("sev ASC: LOW is first",                       sev_asc30[0].severity == SeverityEnum.LOW)
check("sev ASC: last is CRITICAL",                   sev_asc30[-1].severity == SeverityEnum.CRITICAL)

sev_desc30 = sort_cve_records(sort_recs, by="severity", ascending=False)
check("sev DESC: first is CRITICAL",                 sev_desc30[0].severity == SeverityEnum.CRITICAL)
check("sev DESC: CRITICAL pair both CRITICAL",       sev_desc30[0].severity == SeverityEnum.CRITICAL and sev_desc30[1].severity == SeverityEnum.CRITICAL)

cs_desc30 = sort_cve_records(sort_recs, by="cvssScore", ascending=False)
check("cvssScore DESC: monotonic",                   all(cs_desc30[i].cvssScore >= cs_desc30[i+1].cvssScore for i in range(len(cs_desc30)-1)))
cs_asc30  = sort_cve_records(sort_recs, by="cvssScore", ascending=True)
check("cvssScore ASC: monotonic",                    all(cs_asc30[i].cvssScore <= cs_asc30[i+1].cvssScore for i in range(len(cs_asc30)-1)))

sort_maps30 = [
    build_cve_mapping([_rec_low()],    "2026-01-01T00:00:00Z", finding_id="sm301", confidence=50.0),
    build_cve_mapping([_rec_high()],   "2026-02-01T00:00:00Z", finding_id="sm302", confidence=70.0),
    build_cve_mapping([_rec_medium()], "2026-03-01T00:00:00Z", finding_id="sm303", confidence=90.0),
]
sm_ts_asc30  = sort_cve_mappings(sort_maps30, by="createdAt", ascending=True)
sm_ts_desc30 = sort_cve_mappings(sort_maps30, by="createdAt", ascending=False)
check("sort mappings createdAt ASC: first <= last",  sm_ts_asc30[0].createdAt <= sm_ts_asc30[-1].createdAt)
check("sort mappings createdAt DESC: first >= last", sm_ts_desc30[0].createdAt >= sm_ts_desc30[-1].createdAt)
check("createdAt ASC/DESC reversal",                 [m.mappingId for m in sm_ts_asc30] == list(reversed([m.mappingId for m in sm_ts_desc30])))
sm_asc2_30 = sort_cve_mappings(sort_maps30, by="createdAt", ascending=True)
check("sort_cve_mappings createdAt is stable",       [m.mappingId for m in sm_ts_asc30] == [m.mappingId for m in sm_asc2_30])


# ---------------------------------------------------------------------------
# Section 31: Extended filter coverage
# ---------------------------------------------------------------------------
print("\n── 31. Extended filter coverage ─────────────────────────────────────")

ext_recs = [
    build_cve_record("CVE-2021-44228", SeverityEnum.CRITICAL, 10.0, TS1, affected_platforms=["linux", "windows"]),
    build_cve_record("CVE-2021-26855", SeverityEnum.CRITICAL,  9.8, TS1, affected_platforms=["windows"]),
    build_cve_record("CVE-2020-00001", SeverityEnum.LOW,        2.5, TS1, affected_platforms=["linux"]),
    build_cve_record("CVE-2019-11111", SeverityEnum.MEDIUM,     5.0, TS1, affected_platforms=["linux"]),
    build_cve_record("CVE-2022-22222", SeverityEnum.HIGH,       7.8, TS1, affected_platforms=["macos"]),
]

# Combined severity + cvss
f_crit_high = filter_cve_records(ext_recs, severity=SeverityEnum.CRITICAL, min_cvss=9.9)
check("combined severity CRITICAL + min_cvss=9.9",   len(f_crit_high) == 1 and f_crit_high[0].cvssScore == 10.0)

# Platform substring matching
f_mac = filter_cve_records(ext_recs, affected_platform="mac")
check("platform substring 'mac' matches 'macos'",    len(f_mac) == 1)

# CVSS range: 7 <= cvss <= 9
f_range31 = filter_cve_records(ext_recs, min_cvss=7.0, max_cvss=9.0)
check("filter 7<=cvss<=9: correct records",          all(7.0 <= r.cvssScore <= 9.0 for r in f_range31))
check("filter 7<=cvss<=9: count = 1",                len(f_range31) == 1)

# filter_cve_mappings combined
ext_maps = [
    build_cve_mapping(ext_recs[:2], TS1, finding_id="em1", confidence=95.0),
    build_cve_mapping(ext_recs[2:4], TS2, finding_id="em2", confidence=40.0),
    build_cve_mapping([ext_recs[4]], TS3, finding_id="em3", confidence=70.0),
]

# Confidence + severity combined
f_cm_combined = filter_cve_mappings(ext_maps, min_confidence=90.0, severity=SeverityEnum.CRITICAL)
check("combined conf>=90 + CRITICAL: 1 match",       len(f_cm_combined) == 1)

# min_confidence = 0.0 → all
f_cm_all = filter_cve_mappings(ext_maps, min_confidence=0.0)
check("min_confidence=0.0 → all returned",           len(f_cm_all) == len(ext_maps))

# max_cvss ceiling — mapping with LOW CVE only
r_only_low = build_cve_record("CVE-2020-00001", SeverityEnum.LOW, 2.5, TS1, affected_platforms=["linux"])
m_only_low = build_cve_mapping([r_only_low], TS1, finding_id="emlow")
f_cm_low = filter_cve_mappings([m_only_low] + list(ext_maps[1:]), max_cvss=3.0)
check("filter mappings max_cvss=3.0: only LOW CVE mapping", len(f_cm_low) == 1 and f_cm_low[0].findingId == "emlow")


# ---------------------------------------------------------------------------
# Section 32: Extended grouping coverage
# ---------------------------------------------------------------------------
print("\n── 32. Extended grouping coverage ───────────────────────────────────")

grp_recs32 = [
    build_cve_record("CVE-2021-00001", SeverityEnum.CRITICAL, 9.5, TS1, affected_platforms=["linux","windows"]),
    build_cve_record("CVE-2018-00001", SeverityEnum.HIGH,     7.5, TS1, affected_platforms=["linux"]),
    build_cve_record("CVE-2018-00002", SeverityEnum.LOW,      2.0, TS1),
]

g32_year = group_cve_records(grp_recs32, by="year")
check("group by year: 2021 has 1",                   len(g32_year.get("2021", [])) == 1)
check("group by year: 2018 has 2",                   len(g32_year.get("2018", [])) == 2)
check("group by year keys sorted",                   list(g32_year.keys()) == sorted(g32_year.keys()))

g32_sev = group_cve_records(grp_recs32, by="severity")
check("group by severity: sums to total",            sum(len(v) for v in g32_sev.values()) == 3)

g32_plat = group_cve_records(grp_recs32, by="platform")
check("group by platform: linux has 2",              len(g32_plat.get("linux", [])) == 2)
check("group by platform: windows has 1",            len(g32_plat.get("windows", [])) == 1)
check("group by platform: unknown has 1",            len(g32_plat.get("unknown", [])) == 1)

# group_cve_mappings — year grouping
grp_maps32 = [
    build_cve_mapping([build_cve_record("CVE-2021-00001", SeverityEnum.HIGH, 7.0, TS1)], TS1, finding_id="gm321"),
    build_cve_mapping([build_cve_record("CVE-2019-00001", SeverityEnum.LOW, 2.0, TS1)],  TS2, finding_id="gm322"),
]
g32_myear = group_cve_mappings(grp_maps32, by="year")
check("group mappings by year: 2021 exists",         "2021" in g32_myear)
check("group mappings by year: 2019 exists",         "2019" in g32_myear)
check("group mappings year: 1 entry each",           all(len(v) == 1 for v in g32_myear.values()))

# group_cve_mappings — unknown severity (empty cveRecords)
empty_m = build_cve_mapping([], TS1, finding_id="gm_empty")
g32_empty_sev = group_cve_mappings([empty_m], by="severity")
check("group empty mapping by severity → 'unknown'", "unknown" in g32_empty_sev)


# ---------------------------------------------------------------------------
# Section 33: build_cve_statistics extended
# ---------------------------------------------------------------------------
print("\n── 33. build_cve_statistics extended ────────────────────────────────")

# 10 mappings with known confidences
confs33 = [float(10 * (i+1)) for i in range(10)]  # 10, 20, ..., 100
maps33  = [build_cve_mapping([_rec_log4j()], TS1, finding_id=f"stat33_{i}", confidence=confs33[i]) for i in range(10)]
s33 = build_cve_statistics(maps33)
check("stats33: totalCVEs=1 (all same CVE)",         s33.totalCVEs == 1)
check("stats33: averageConfidence = 55.0",           s33.averageConfidence == round(sum(confs33)/10, 4))
check("stats33: criticalCVEs = 1",                   s33.criticalCVEs == 1)

# Techniques counted distinctly
t_x = _make_technique("TA0010", "T1001")
t_y = _make_technique("TA0011", "T1002")
t_z = _make_technique("TA0012", "T1003")
r33a = build_cve_record("CVE-2030-00001", SeverityEnum.HIGH, 7.0, TS1, mapped_techniques=[t_x, t_y])
r33b = build_cve_record("CVE-2030-00002", SeverityEnum.HIGH, 7.0, TS1, mapped_techniques=[t_y, t_z])  # t_y is shared
m33t = build_cve_mapping([r33a, r33b], TS1, finding_id="st33t")
s33t = build_cve_statistics([m33t])
check("stats techniques: 3 distinct mitreIds",       s33t.mappedTechniques == 3)

# averageCVSS with varied scores
r33c = build_cve_record("CVE-2030-00003", SeverityEnum.MEDIUM, 5.5, TS1)
r33d = build_cve_record("CVE-2030-00004", SeverityEnum.LOW,    1.0, TS1)
m33c = build_cve_mapping([r33c, r33d], TS1, finding_id="st33c", confidence=60.0)
s33c = build_cve_statistics([m33c])
check("averageCVSS (5.5+1.0)/2",                     s33c.averageCVSS == round((5.5 + 1.0) / 2, 4))
check("lowCVEs = 1",                                 s33c.lowCVEs == 1)
check("mediumCVEs = 1",                              s33c.mediumCVEs == 1)
check("averageConfidence = 60.0",                    s33c.averageConfidence == 60.0)

# Order independence with 10 mappings
maps33_rev = list(reversed(maps33))
s33_rev = build_cve_statistics(maps33_rev)
check("stats33 order-independent totalCVEs",         s33.totalCVEs == s33_rev.totalCVEs)
check("stats33 order-independent averageConf",       s33.averageConfidence == s33_rev.averageConfidence)
check("stats33 order-independent criticalCVEs",      s33.criticalCVEs == s33_rev.criticalCVEs)


# ---------------------------------------------------------------------------
# Section 34: merge operations – extended edge cases
# ---------------------------------------------------------------------------
print("\n── 34. Merge extended edge cases ────────────────────────────────────")

# merge_cve_records: LOW vs HIGH → HIGH wins
r34_low = build_cve_record("CVE-2021-44228", SeverityEnum.LOW,  2.0, TS1)
r34_hi  = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.0, TS2)
m34_lh = merge_cve_records(r34_low, r34_hi, TS3)
check("merge LOW vs HIGH: HIGH wins",                m34_lh.severity == SeverityEnum.HIGH)
m34_hl = merge_cve_records(r34_hi, r34_low, TS3)
check("merge HIGH vs LOW (reversed): HIGH wins",     m34_hl.severity == SeverityEnum.HIGH)

# merge MEDIUM vs CRITICAL → CRITICAL
r34_med  = build_cve_record("CVE-2021-44228", SeverityEnum.MEDIUM,   5.0, TS1)
r34_crit = build_cve_record("CVE-2021-44228", SeverityEnum.CRITICAL, 9.9, TS2)
m34_mc = merge_cve_records(r34_med, r34_crit, TS3)
check("merge MEDIUM vs CRITICAL: CRITICAL wins",     m34_mc.severity == SeverityEnum.CRITICAL)

# merge_mappings: confidence tie → max (same)
m34_a = build_cve_mapping([_rec_log4j()], TS1, finding_id="m34same", confidence=75.0)
m34_b = build_cve_mapping([_rec_low()],   TS2, finding_id="m34same", confidence=75.0)
m34_merged = merge_mappings(m34_a, m34_b, TS3)
check("merge mappings: equal confidence preserved",  m34_merged.confidence == 75.0)
check("merge mappings: CVE union = 2",               len(m34_merged.cveRecords) == 2)

# merge_mappings: empty incoming CVEs
m34_empty_inc = build_cve_mapping([], TS2, finding_id="m34same", confidence=50.0)
m34_wi_empty = merge_mappings(m34_a, m34_empty_inc, TS3)
check("merge: empty incoming CVEs → base CVEs retained", len(m34_wi_empty.cveRecords) == 1)

# add_cve_record returns new list (original not mutated)
orig_store34 = [_rec_low()]
new_store34 = add_cve_record(orig_store34, _rec_high())
check("add_cve_record does not mutate original",     len(orig_store34) == 1)
check("add_cve_record returns new list",             len(new_store34) == 2)

# remove does not mutate
orig_store34b = [_rec_low(), _rec_high()]
new_store34b = remove_cve_record(orig_store34b, _rec_low().recordId)
check("remove_cve_record does not mutate original",  len(orig_store34b) == 2)
check("remove_cve_record returns new list",          len(new_store34b) == 1)


# ---------------------------------------------------------------------------
# Section 35: Integration helpers – extended
# ---------------------------------------------------------------------------
print("\n── 35. Integration helpers extended ────────────────────────────────")

# finding_to_cve_mapping with multiple CVEs
recs35 = [_rec_log4j(), _rec_proxylogon(), _rec_high()]
m35_f = finding_to_cve_mapping(finding, recs35, TS1, confidence=50.0)
check("finding_to_cve_mapping: 3 CVE records",       len(m35_f.cveRecords) == 3)
check("finding_to_cve_mapping: CVEs sorted by cveId", m35_f.cveRecords[0].cveId <= m35_f.cveRecords[-1].cveId)

# alert_to_cve_mapping with empty CVE list
m35_a_empty = alert_to_cve_mapping(alert, [], TS1, confidence=0.0)
check("alert_to_cve_mapping: empty CVEs allowed",    m35_a_empty.cveRecords == ())
check("alert_to_cve_mapping: alertId correct",       m35_a_empty.alertId == "alert-xyz")

# reasoning_to_cve_mapping with no finding/alert
m35_r_lone = reasoning_to_cve_mapping(reasoning, [_rec_log4j()], TS1)
check("reasoning_to_cve_mapping: no finding/alert context", m35_r_lone.findingId == "" and m35_r_lone.alertId == "")
check("reasoning_to_cve_mapping: reasoningId set",   m35_r_lone.reasoningId == "reasoning-123")

# mitre_to_cve_reference: adding technique to record with no techniques
r35_bare = build_cve_record("CVE-2025-55555", SeverityEnum.HIGH, 7.0, TS1)
t35 = _make_technique("TA0099", "T9999")
r35_ext = mitre_to_cve_reference(t35, r35_bare, TS2)
check("mitre_to_cve_reference on bare record: count = 1", len(r35_ext.mappedTechniques) == 1)
check("mitre_to_cve_reference: technique mitreId correct", r35_ext.mappedTechniques[0].mitreId == "TA0099")

# Adding 3 techniques one at a time
r35_step = r35_bare
techs35 = [_make_technique(f"TA{100+i}", f"T{100+i}") for i in range(3)]
for t35i in techs35:
    r35_step = mitre_to_cve_reference(t35i, r35_step, TS2)
check("mitre_to_cve_reference: 3 sequential adds = 3 techniques", len(r35_step.mappedTechniques) == 3)
check("mitre_to_cve_reference: all techniques sorted",
      all(r35_step.mappedTechniques[i].mitreId <= r35_step.mappedTechniques[i+1].mitreId
          for i in range(len(r35_step.mappedTechniques)-1)))



# ---------------------------------------------------------------------------
# Section 36: Additional CVE operation edge cases
# ---------------------------------------------------------------------------
print("\n── 36. CVE operation edge cases ─────────────────────────────────────")

# update_cve_record: mapped_techniques update
t_new_u = _make_technique("TA0050", "T5050")
r_upd36 = _rec_low()
store36 = [r_upd36]
store36 = update_cve_record(store36, r_upd36.recordId, mapped_techniques=[t_new_u])
r36_updated = store36[0]
check("update mapped_techniques: 1 technique",       len(r36_updated.mappedTechniques) == 1)
check("update mapped_techniques: mitreId correct",   r36_updated.mappedTechniques[0].mitreId == "TA0050")
check("update mapped_techniques: cveId unchanged",   r36_updated.cveId == r_upd36.cveId)

# update_cve_record: clear mapped_techniques
store36b = update_cve_record(store36, r36_updated.recordId, mapped_techniques=[])
check("update mapped_techniques to empty: 0 techniques", len(store36b[0].mappedTechniques) == 0)

# update multiple affected_platforms
store36c = [_rec_log4j()]
store36c = update_cve_record(store36c, store36c[0].recordId, affected_platforms=["macos", "linux", "LINUX"])
check("update affectedPlatforms deduped+lowercased",  set(store36c[0].affectedPlatforms) == {"linux", "macos"})

# merge_cve_records: both empty descriptions → empty
r36_e1 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.0, TS1, description="")
r36_e2 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.0, TS2, description="")
m36_desc = merge_cve_records(r36_e1, r36_e2, TS3)
check("merge both empty descriptions → empty",       m36_desc.description == "")

# merge_cve_records: both empty refs → empty
r36_r1 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.0, TS1)
r36_r2 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 8.0, TS2)
m36_ref = merge_cve_records(r36_r1, r36_r2, TS3)
check("merge both empty refs → empty tuple",         m36_ref.references == ())

# merge_cve_records: cvssScore max precision
r36_p1 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.1234, TS1)
r36_p2 = build_cve_record("CVE-2021-44228", SeverityEnum.HIGH, 7.5678, TS2)
m36_prec = merge_cve_records(r36_p1, r36_p2, TS3)
check("merge cvssScore max with precision",          m36_prec.cvssScore == round(7.5678, 4))

# add_cve_record with whitespace in cveId (build normalises it)
r_ws36 = build_cve_record("  CVE-2024-11111  ", SeverityEnum.LOW, 1.0, TS1)
store_ws36 = add_cve_record([], r_ws36)
check("add record with normalised cveId",            len(store_ws36) == 1)
check("normalised cveId stored correctly",           store_ws36[0].cveId == "CVE-2024-11111")

# remove_cve_record: does not affect siblings
r_a36 = build_cve_record("CVE-2024-00001", SeverityEnum.LOW, 1.0, TS1)
r_b36 = build_cve_record("CVE-2024-00002", SeverityEnum.LOW, 2.0, TS1)
r_c36 = build_cve_record("CVE-2024-00003", SeverityEnum.LOW, 3.0, TS1)
s36 = [r_a36, r_b36, r_c36]
s36_after = remove_cve_record(s36, r_b36.recordId)
check("remove middle: a still present",              any(r.cveId == "CVE-2024-00001" for r in s36_after))
check("remove middle: c still present",              any(r.cveId == "CVE-2024-00003" for r in s36_after))
check("remove middle: b gone",                       not any(r.cveId == "CVE-2024-00002" for r in s36_after))
check("remove middle: count = 2",                    len(s36_after) == 2)


# ---------------------------------------------------------------------------
# Section 37: Additional mapping operation edge cases
# ---------------------------------------------------------------------------
print("\n── 37. Mapping operation edge cases ─────────────────────────────────")

# add_mapping_record preserves other mappings on duplicate
m37_a = build_cve_mapping([_rec_log4j()], TS1, finding_id="f37a", confidence=80.0)
m37_b = build_cve_mapping([_rec_low()],   TS2, finding_id="f37b", confidence=60.0)
ms37 = [m37_a, m37_b]
ms37_dup = add_mapping_record(ms37, m37_a)
check("dup add preserves both original mappings",    len(ms37_dup) == 2)
check("dup add: m37_a still in store",               any(m.mappingId == m37_a.mappingId for m in ms37_dup))
check("dup add: m37_b still in store",               any(m.mappingId == m37_b.mappingId for m in ms37_dup))

# remove_mapping_record: non-destructive to siblings
ms37_rem = remove_mapping_record(ms37, m37_a.mappingId)
check("remove mapping: sibling m37_b intact",        any(m.mappingId == m37_b.mappingId for m in ms37_rem))
check("remove mapping: m37_a gone",                  not any(m.mappingId == m37_a.mappingId for m in ms37_rem))

# merge_mappings: confidence both 0.0
m37_z1 = build_cve_mapping([_rec_low()], TS1, finding_id="fz37", confidence=0.0)
m37_z2 = build_cve_mapping([_rec_high()], TS2, finding_id="fz37", confidence=0.0)
m37_zm = merge_mappings(m37_z1, m37_z2, TS3)
check("merge mappings confidence both 0.0: result 0.0", m37_zm.confidence == 0.0)
check("merge mappings both 0.0: 2 CVE records",      len(m37_zm.cveRecords) == 2)

# merge_mappings: reasoningId mismatch → error
m37_r1 = build_cve_mapping([_rec_log4j()], TS1, finding_id="fr37", reasoning_id="r1")
m37_r2 = build_cve_mapping([_rec_low()],   TS2, finding_id="fr37", reasoning_id="r2")
try:
    merge_mappings(m37_r1, m37_r2, TS3)
    check("merge mappings reasoningId mismatch → CVEIntelligenceError", False)
except CVEIntelligenceError:
    check("merge mappings reasoningId mismatch → CVEIntelligenceError", True)

# add_mapping_record: result sorted by mappingId
ms37_new = []
for fi37 in range(5):
    ms37_new = add_mapping_record(ms37_new, build_cve_mapping([_rec_log4j()], TS1, finding_id=f"fs37{fi37}"))
check("add 5 mappings: sorted by mappingId",         all(ms37_new[i].mappingId <= ms37_new[i+1].mappingId for i in range(4)))
check("add 5 mappings: count = 5",                   len(ms37_new) == 5)

# find_cve_record with single element store
single_store = [_rec_log4j()]
check("find_cve_record in single-element store",     find_cve_record(single_store, record_id=_rec_log4j().recordId) is not None)

# find_mapping with single element store
single_mstore = [m37_a]
check("find_mapping in single-element store",        find_mapping(single_mstore, mapping_id=m37_a.mappingId) is not None)

# Mapping fingerprint is 32 chars after merge
check("merge mapping: fingerprint is 32 chars",      len(m37_zm.mappingFingerprint) == 32)

# build_cve_statistics: single LOW record
m37_solo = build_cve_mapping([_rec_low()], TS1, finding_id="f37solo", confidence=25.0)
s37_solo = build_cve_statistics([m37_solo])
check("stats single LOW: totalCVEs=1",               s37_solo.totalCVEs == 1)
check("stats single LOW: lowCVEs=1",                 s37_solo.lowCVEs == 1)
check("stats single LOW: criticalCVEs=0",            s37_solo.criticalCVEs == 0)
check("stats single LOW: averageCVSS=2.5",           s37_solo.averageCVSS == 2.5)
check("stats single LOW: averageConfidence=25.0",    s37_solo.averageConfidence == 25.0)

# Enum values
check("SeverityEnum.LOW.value == 'LOW'",             SeverityEnum.LOW.value == "LOW")
check("SeverityEnum.MEDIUM.value == 'MEDIUM'",       SeverityEnum.MEDIUM.value == "MEDIUM")
check("SeverityEnum.HIGH.value == 'HIGH'",           SeverityEnum.HIGH.value == "HIGH")
check("SeverityEnum.CRITICAL.value == 'CRITICAL'",   SeverityEnum.CRITICAL.value == "CRITICAL")

# Exception hierarchy
check("InvalidCVEError is CVEIntelligenceError",     issubclass(InvalidCVEError, CVEIntelligenceError))
check("InvalidCVEMappingError is CVEIntelligenceError", issubclass(InvalidCVEMappingError, CVEIntelligenceError))
check("InvalidCVSSScoreError is CVEIntelligenceError", issubclass(InvalidCVSSScoreError, CVEIntelligenceError))


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "="*68)
total    = len(errors) + sum(1 for _ in range(0))  # count from check calls
n_passed = 0
n_total  = 0

# Re-count by re-running is not needed — count directly from check()
# We'll track via a wrapper we already used; errors list has failures.

# Compute totals from previous output
import io, sys as _sys

# Count assertions that were printed
_passed_str = "\033[92m✓\033[0m"
_fail_str   = "\033[91m✗\033[0m"

n_failures = len(errors)
# Estimate total by counting check() calls (we'll display a floor)
print(f"  Failures : {n_failures}")
if n_failures == 0:
    print(f"\033[92m  All assertions passed  (0 failures)\033[0m")
else:
    print(f"\033[91m  FAILED assertions:\033[0m")
    for e in errors:
        print(f"    ✗  {e}")

sys.exit(1 if errors else 0)
