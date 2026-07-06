"""
Smoke Test — Report Engine
===========================
Phase A4.6.1 — Comprehensive deterministic test suite.

Covers
------
- Enumerations: ReportTypeEnum, ReportStatusEnum
- Engine version constant
- Exception hierarchy
- Deterministic IDs: sectionKey, reportKey, mappingKey, mappingFingerprint
- Builders: build_report_section, build_report, build_report_mapping,
  build_report_statistics (extended with reportTypeCounts/statusCounts)
- Validators: validate_report_section, validate_report, validate_report_mapping
- Report Operations: add, update, remove, merge
- Section Operations: add, update, remove, merge
- Mapping Operations: add, remove, merge
- Search: find_report, find_report_section, find_report_mapping
- Sorting: sort_reports, sort_report_sections, sort_report_mappings
- Filtering: filter_reports, filter_report_sections, filter_report_mappings
- Grouping: group_reports, group_report_sections, group_report_mappings
- Statistics: build_report_statistics (all fields)
- Serialization: model_dump round-trip
- Immutability: frozen model enforcement
- Integration helpers: finding_to_report_mapping, alert_to_report_mapping,
  reasoning_to_report_mapping, timeline_to_report_reference,
  playbook_to_report_reference, ioc_to_report_reference
- Edge cases, zero randomness, deterministic fingerprints, large dataset stability

Target: 650+ assertions
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

# ---------------------------------------------------------------------------
# Assertion counter
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
from services.report_engine_service import (
    REPORT_ENGINE_VERSION,
    ReportTypeEnum, ReportStatusEnum,
    ReportEngineError, InvalidReportError,
    InvalidReportSectionError, InvalidReportMappingError,
    ReportSection, Report, ReportMapping, ReportStatistics,
    sectionKey, reportKey, mappingKey, mappingFingerprint,
    validate_report_section, validate_report, validate_report_mapping,
    build_report_section, build_report, build_report_mapping, build_report_statistics,
    add_report, update_report, remove_report, merge_reports,
    add_report_section, update_report_section, remove_report_section, merge_report_sections,
    add_report_mapping, remove_report_mapping, merge_report_mappings,
    find_report, find_report_section, find_report_mapping,
    sort_reports, sort_report_sections, sort_report_mappings,
    filter_reports, filter_report_sections, filter_report_mappings,
    group_reports, group_report_sections, group_report_mappings,
    finding_to_report_mapping, alert_to_report_mapping, reasoning_to_report_mapping,
    timeline_to_report_reference, playbook_to_report_reference, ioc_to_report_reference,
)
from core.constants import REPORT_ENGINE_VERSION as _CONST_VERSION

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T00:00:00Z"
TS3 = "2026-07-04T00:00:00Z"

print("=" * 60)
print("Report Engine Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. Engine Version
# ===========================================================================
print("\n[1] Engine Version")

_assert(REPORT_ENGINE_VERSION == "report-engine-v1",     "REPORT_ENGINE_VERSION value")
_assert(_CONST_VERSION        == "report-engine-v1",     "constant matches import")
_assert(REPORT_ENGINE_VERSION == _CONST_VERSION,         "service re-export matches constant")


# ===========================================================================
# 2. Enumerations
# ===========================================================================
print("\n[2] Enumerations")

# ReportTypeEnum
_assert(ReportTypeEnum.EXECUTIVE.value == "EXECUTIVE", "type EXECUTIVE")
_assert(ReportTypeEnum.TECHNICAL.value == "TECHNICAL", "type TECHNICAL")
_assert(ReportTypeEnum.SOC.value       == "SOC",       "type SOC")
_assert(ReportTypeEnum.INCIDENT.value  == "INCIDENT",  "type INCIDENT")
_assert(ReportTypeEnum.IOC.value       == "IOC",       "type IOC")
_assert(ReportTypeEnum.FORENSICS.value == "FORENSICS", "type FORENSICS")
_assert(ReportTypeEnum.SUMMARY.value   == "SUMMARY",   "type SUMMARY")
_assert(len(ReportTypeEnum) == 7, "type enum has 7 members")

# ReportStatusEnum
_assert(ReportStatusEnum.DRAFT.value     == "DRAFT",     "status DRAFT")
_assert(ReportStatusEnum.READY.value     == "READY",     "status READY")
_assert(ReportStatusEnum.PUBLISHED.value == "PUBLISHED", "status PUBLISHED")
_assert(ReportStatusEnum.ARCHIVED.value  == "ARCHIVED",  "status ARCHIVED")
_assert(len(ReportStatusEnum) == 4, "status enum has 4 members")


# ===========================================================================
# 3. Exception Hierarchy
# ===========================================================================
print("\n[3] Exception Hierarchy")

_assert(issubclass(ReportEngineError,        Exception),          "base inherits Exception")
_assert(issubclass(InvalidReportError,       ReportEngineError),  "InvalidReportError inherits base")
_assert(issubclass(InvalidReportSectionError,ReportEngineError),  "InvalidReportSectionError inherits base")
_assert(issubclass(InvalidReportMappingError,ReportEngineError),  "InvalidReportMappingError inherits base")
_assert(not issubclass(InvalidReportError, InvalidReportSectionError), "no cross-inheritance")

# Instances
e_base = ReportEngineError("test")
e_rep  = InvalidReportError("test")
e_sec  = InvalidReportSectionError("test")
e_map  = InvalidReportMappingError("test")
_assert(isinstance(e_rep, ReportEngineError),        "InvalidReportError is-a ReportEngineError")
_assert(isinstance(e_sec, ReportEngineError),        "InvalidReportSectionError is-a ReportEngineError")
_assert(isinstance(e_map, ReportEngineError),        "InvalidReportMappingError is-a ReportEngineError")
_assert(isinstance(e_base, Exception),               "ReportEngineError is-a Exception")


# ===========================================================================
# 4. Deterministic ID Helpers
# ===========================================================================
print("\n[4] Deterministic ID Helpers")

# sectionKey
sk1 = sectionKey("report-1", 1, "Executive Summary")
sk2 = sectionKey("report-1", 1, "Executive Summary")
sk3 = sectionKey("report-1", 2, "Executive Summary")
sk4 = sectionKey("report-2", 1, "Executive Summary")
sk5 = sectionKey("report-1", 1, "Technical Details")

_assert(sk1 == sk2,     "sectionKey deterministic same inputs")
_assert(sk1 != sk3,     "sectionKey differs for different order")
_assert(sk1 != sk4,     "sectionKey differs for different reportId")
_assert(sk1 != sk5,     "sectionKey differs for different title")
_assert(len(sk1) == 32, "sectionKey is 32 chars")
_assert(sk1.islower(),  "sectionKey is lowercase hex")
_assert(all(c in "0123456789abcdef" for c in sk1), "sectionKey is hex")

# reportKey
rk1 = reportKey("Incident Report", ReportTypeEnum.INCIDENT, ("f1", "f2"))
rk2 = reportKey("Incident Report", ReportTypeEnum.INCIDENT, ("f2", "f1"))
rk3 = reportKey("Incident Report", ReportTypeEnum.SOC,      ("f1", "f2"))
rk4 = reportKey("Executive Brief", ReportTypeEnum.INCIDENT, ("f1", "f2"))
rk5 = reportKey("Incident Report", ReportTypeEnum.INCIDENT, ())

_assert(rk1 == rk2,     "reportKey order-independent for findingIds")
_assert(rk1 != rk3,     "reportKey differs for different reportType")
_assert(rk1 != rk4,     "reportKey differs for different title")
_assert(rk1 != rk5,     "reportKey differs for empty vs non-empty findingIds")
_assert(len(rk1) == 32, "reportKey is 32 chars")
_assert(rk1.islower(),  "reportKey is lowercase hex")

# mappingKey
mk1 = mappingKey("f1", "a1", "r1", ("id1", "id2"))
mk2 = mappingKey("f1", "a1", "r1", ("id2", "id1"))
mk3 = mappingKey("f2", "a1", "r1", ("id1", "id2"))
mk4 = mappingKey("f1", "",   "r1", ("id1", "id2"))
mk5 = mappingKey("f1", "a1", "",   ("id1", "id2"))
mk6 = mappingKey("",   "",   "r1", ("id1", "id2"))

_assert(mk1 == mk2,     "mappingKey order-independent for reportIds")
_assert(mk1 != mk3,     "mappingKey differs for different findingId")
_assert(mk1 != mk4,     "mappingKey differs for empty alertId")
_assert(mk1 != mk5,     "mappingKey differs for empty reasoningId")
_assert(mk3 != mk6,     "mappingKey differs for different findingId vs empty")
_assert(len(mk1) == 32, "mappingKey is 32 chars")
_assert(mk1.islower(),  "mappingKey is lowercase hex")

# mappingFingerprint
mfp1 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id1", "id2"))
mfp2 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id2", "id1"))
mfp3 = mappingFingerprint(mk3, "f2", "a1", "r1", ("id1", "id2"))

_assert(mfp1 == mfp2,    "fingerprint order-independent")
_assert(mfp1 != mfp3,    "fingerprint differs for different content")
_assert(len(mfp1) == 32, "fingerprint is 32 chars")
_assert(mfp1 != mk1,     "fingerprint differs from mappingKey")
_assert(mfp1.islower(),  "fingerprint is lowercase hex")

# Zero randomness check — run key derivations twice
for _ in range(3):
    _assert(sectionKey("r", 1, "t") == sectionKey("r", 1, "t"), "sectionKey no randomness")
    _assert(reportKey("t", ReportTypeEnum.SOC, ("f",)) == reportKey("t", ReportTypeEnum.SOC, ("f",)), "reportKey no randomness")
    _assert(mappingKey("f","a","r",("x",)) == mappingKey("f","a","r",("x",)), "mappingKey no randomness")


# ===========================================================================
# 5. Validators
# ===========================================================================
print("\n[5] Validators")

# validate_report_section — happy path
try:
    validate_report_section(1, "Summary", TS)
    _assert(True, "validate_report_section passes valid input")
except Exception:
    _assert(False, "validate_report_section raised unexpectedly")

# order must be >= 1
_assert_raises(InvalidReportSectionError, validate_report_section,
               0, "T", TS, msg="order 0 rejected")
_assert_raises(InvalidReportSectionError, validate_report_section,
               -1, "T", TS, msg="negative order rejected")
_assert_raises(InvalidReportSectionError, validate_report_section,
               1.5, "T", TS, msg="float order rejected")

# empty title
_assert_raises(InvalidReportSectionError, validate_report_section,
               1, "", TS, msg="empty section title rejected")
_assert_raises(InvalidReportSectionError, validate_report_section,
               1, "   ", TS, msg="whitespace-only section title rejected")

# empty createdAt
_assert_raises(InvalidReportSectionError, validate_report_section,
               1, "T", "", msg="empty section createdAt rejected")
_assert_raises(InvalidReportSectionError, validate_report_section,
               1, "T", "   ", msg="whitespace-only section createdAt rejected")

# validate_report — happy path
try:
    validate_report("Report Title", ReportTypeEnum.INCIDENT, ReportStatusEnum.DRAFT, TS)
    _assert(True, "validate_report passes valid input")
except Exception:
    _assert(False, "validate_report raised unexpectedly")

# empty title
_assert_raises(InvalidReportError, validate_report,
               "", ReportTypeEnum.INCIDENT, ReportStatusEnum.DRAFT, TS,
               msg="empty report title rejected")
_assert_raises(InvalidReportError, validate_report,
               "  ", ReportTypeEnum.INCIDENT, ReportStatusEnum.DRAFT, TS,
               msg="whitespace-only report title rejected")

# bad reportType
_assert_raises(InvalidReportError, validate_report,
               "T", "BAD_TYPE", ReportStatusEnum.DRAFT, TS,
               msg="bad reportType rejected")

# bad status
_assert_raises(InvalidReportError, validate_report,
               "T", ReportTypeEnum.INCIDENT, "BAD_STATUS", TS,
               msg="bad status rejected")

# empty createdAt
_assert_raises(InvalidReportError, validate_report,
               "T", ReportTypeEnum.INCIDENT, ReportStatusEnum.DRAFT, "",
               msg="empty report createdAt rejected")

# validate_report_mapping — happy path
try:
    validate_report_mapping("finding-1", "", "", 50.0, TS)
    _assert(True, "validate_report_mapping passes valid input")
except Exception:
    _assert(False, "validate_report_mapping raised unexpectedly")

# no source IDs
_assert_raises(InvalidReportMappingError, validate_report_mapping,
               "", "", "", 50.0, TS, msg="no source IDs rejected")
_assert_raises(InvalidReportMappingError, validate_report_mapping,
               "  ", "  ", "  ", 50.0, TS, msg="whitespace-only sources rejected")

# bad confidence
_assert_raises(InvalidReportMappingError, validate_report_mapping,
               "f1", "", "", -1.0, TS, msg="negative confidence rejected")
_assert_raises(InvalidReportMappingError, validate_report_mapping,
               "f1", "", "", 101.0, TS, msg="confidence > 100 rejected")

# boundary values pass
try:
    validate_report_mapping("f1", "", "", 0.0, TS)
    _assert(True, "confidence 0.0 accepted")
except Exception:
    _assert(False, "confidence 0.0 should be accepted")

try:
    validate_report_mapping("f1", "", "", 100.0, TS)
    _assert(True, "confidence 100.0 accepted")
except Exception:
    _assert(False, "confidence 100.0 should be accepted")

# empty createdAt in mapping
_assert_raises(InvalidReportMappingError, validate_report_mapping,
               "f1", "", "", 50.0, "", msg="empty mapping createdAt rejected")


# ===========================================================================
# 6. Builder: build_report_section
# ===========================================================================
print("\n[6] build_report_section")

sec1 = build_report_section(
    report_id  = "report-parent-id",
    order      = 1,
    title      = "Executive Summary",
    created_at = TS,
    content    = "This report covers Q3 incidents.",
)

_assert(sec1.order     == 1,                              "section order set")
_assert(sec1.title     == "Executive Summary",            "section title set")
_assert(sec1.content   == "This report covers Q3 incidents.", "section content set")
_assert(sec1.createdAt == TS,                             "section createdAt set")
_assert(len(sec1.sectionKey) == 32,                       "sectionKey is 32 chars")
_assert(sec1.sectionKey.islower(),                        "sectionKey is lowercase hex")
_assert(len(sec1.sectionId)  == 36,                       "sectionId is UUID format")
_assert(sec1.sectionId.count("-") == 4,                   "sectionId has 4 dashes")

# Determinism
sec1b = build_report_section("report-parent-id", 1, "Executive Summary", TS2)
_assert(sec1.sectionKey == sec1b.sectionKey, "sectionKey deterministic")
_assert(sec1.sectionId  == sec1b.sectionId,  "sectionId deterministic")

# Different order → different key
sec2 = build_report_section("report-parent-id", 2, "Technical Details", TS)
_assert(sec2.sectionKey != sec1.sectionKey, "different order → different key")

# Different reportId → different key even for same order/title
sec_diff_rep = build_report_section("other-report-id", 1, "Executive Summary", TS)
_assert(sec_diff_rep.sectionKey != sec1.sectionKey, "different reportId → different key")

# Different title → different key
sec_diff_title = build_report_section("report-parent-id", 1, "Different Title", TS)
_assert(sec_diff_title.sectionKey != sec1.sectionKey, "different title → different key")

# Title stripping
sec_strip = build_report_section("rid", 1, "  Trimmed  ", TS)
_assert(sec_strip.title == "Trimmed", "section title stripped")

# Default content is empty string
sec_no_content = build_report_section("rid", 1, "No Content", TS)
_assert(sec_no_content.content == "", "section content defaults to empty string")

# validate=False skips validation
sec_no_val = build_report_section("rid", 99, "X", TS, validate=False)
_assert(sec_no_val.order == 99, "validate=False still builds section")

# Build several sections for later use
sec3 = build_report_section("report-parent-id", 3, "IOC Analysis",    TS, content="IOC data.")
sec4 = build_report_section("report-parent-id", 4, "Recommendations", TS, content="Patch systems.")
sec5 = build_report_section("report-parent-id", 5, "Appendix",        TS, content="Raw data.")


# ===========================================================================
# 7. Builder: build_report
# ===========================================================================
print("\n[7] build_report")

report1 = build_report(
    title        = "Q3 Incident Report",
    report_type  = ReportTypeEnum.INCIDENT,
    created_at   = TS,
    description  = "Full Q3 incident analysis.",
    status       = ReportStatusEnum.DRAFT,
    sections     = [sec1, sec2],
    finding_ids  = ["f-001", "f-002"],
    alert_ids    = ["a-001"],
    evidence_ids = ["e-001"],
    timeline_ids = ["tl-001"],
    ioc_ids      = ["ioc-001"],
    playbook_ids = ["pb-001"],
    confidence   = 80.0,
)

_assert(report1.title       == "Q3 Incident Report",     "report title set")
_assert(report1.reportType  == ReportTypeEnum.INCIDENT,  "report reportType set")
_assert(report1.status      == ReportStatusEnum.DRAFT,   "report status set")
_assert(report1.description == "Full Q3 incident analysis.", "report description set")
_assert(report1.confidence  == 80.0,                     "report confidence set")
_assert(report1.createdAt   == TS,                       "report createdAt set")
_assert(len(report1.sections)    == 2,  "2 sections")
_assert(report1.sections[0].order == 1, "sections sorted order 1 first")
_assert(report1.sections[1].order == 2, "sections sorted order 2 second")
_assert(len(report1.findingIds)  == 2,  "2 findingIds")
_assert(len(report1.alertIds)    == 1,  "1 alertId")
_assert(len(report1.evidenceIds) == 1,  "1 evidenceId")
_assert(len(report1.timelineIds) == 1,  "1 timelineId")
_assert(len(report1.iocIds)      == 1,  "1 iocId")
_assert(len(report1.playbookIds) == 1,  "1 playbookId")
_assert(len(report1.reportKey)   == 32, "reportKey is 32 chars")
_assert(len(report1.reportId)    == 36, "reportId is UUID format")
_assert(report1.reportId.count("-") == 4, "reportId has 4 dashes")

# Determinism: same title/type/findingIds → same IDs regardless of input order
report1b = build_report(
    title       = "Q3 Incident Report",
    report_type = ReportTypeEnum.INCIDENT,
    created_at  = TS2,
    sections    = [sec2, sec1],        # reversed
    finding_ids = ["f-002", "f-001"],  # reversed
    confidence  = 90.0,
)
_assert(report1.reportKey == report1b.reportKey, "reportKey deterministic (order-independent)")
_assert(report1.reportId  == report1b.reportId,  "reportId deterministic")
_assert(report1.findingIds == report1b.findingIds, "findingIds deduped+sorted")

# Different reportType → different key
report_soc = build_report("Q3 Incident Report", ReportTypeEnum.SOC, TS)
_assert(report1.reportKey != report_soc.reportKey, "different reportType → different key")

# Different title → different key
report_diff_title = build_report("Executive Brief", ReportTypeEnum.INCIDENT, TS)
_assert(report1.reportKey != report_diff_title.reportKey, "different title → different key")

# Default status is DRAFT
report_default = build_report("Default Report", ReportTypeEnum.SUMMARY, TS)
_assert(report_default.status       == ReportStatusEnum.DRAFT, "default status DRAFT")
_assert(report_default.sections     == (),    "default sections empty tuple")
_assert(report_default.findingIds   == (),    "default findingIds empty")
_assert(report_default.alertIds     == (),    "default alertIds empty")
_assert(report_default.evidenceIds  == (),    "default evidenceIds empty")
_assert(report_default.timelineIds  == (),    "default timelineIds empty")
_assert(report_default.iocIds       == (),    "default iocIds empty")
_assert(report_default.playbookIds  == (),    "default playbookIds empty")
_assert(report_default.confidence   == 0.0,   "default confidence 0.0")
_assert(report_default.description  == "",    "default description empty")

# Confidence clamping
r_clamp_lo = build_report("X", ReportTypeEnum.SOC, TS, confidence=-50.0)
_assert(r_clamp_lo.confidence == 0.0,   "confidence clamped to 0.0")

r_clamp_hi = build_report("X", ReportTypeEnum.SOC, TS, confidence=250.0)
_assert(r_clamp_hi.confidence == 100.0, "confidence clamped to 100.0")

# Title stripping
r_stripped = build_report("  Stripped  ", ReportTypeEnum.EXECUTIVE, TS)
_assert(r_stripped.title == "Stripped", "report title stripped")

# Duplicate findingIds deduplicated
r_dedup = build_report("Dedup", ReportTypeEnum.IOC, TS,
                        finding_ids=["f1", "f1", "f2", "f2"])
_assert(len(r_dedup.findingIds) == 2,          "duplicate findingIds deduplicated")
_assert(r_dedup.findingIds == ("f1", "f2"),    "findingIds sorted after dedup")

# Duplicate alertIds deduplicated
r_dedup_a = build_report("Dedup2", ReportTypeEnum.IOC, TS,
                          alert_ids=["a2", "a1", "a1"])
_assert(len(r_dedup_a.alertIds) == 2,          "duplicate alertIds deduplicated")
_assert(r_dedup_a.alertIds == ("a1", "a2"),    "alertIds sorted after dedup")

# validate=False
r_no_val = build_report("X", ReportTypeEnum.TECHNICAL, TS, validate=False)
_assert(r_no_val.title == "X", "validate=False still builds report")

# All type/status combos buildable
for rt in ReportTypeEnum:
    for st in ReportStatusEnum:
        r = build_report(f"R {rt.value} {st.value}", rt, TS, status=st, validate=False)
        _assert(r.reportType == rt and r.status == st,
                f"combo {rt.value}/{st.value} buildable")

# Build extra reports for later use
report_exec    = build_report("Executive Brief",    ReportTypeEnum.EXECUTIVE,  TS, confidence=90.0,
                               finding_ids=["f-exec-1"], status=ReportStatusEnum.READY)
report_soc2    = build_report("SOC Daily Report",   ReportTypeEnum.SOC,        TS, confidence=70.0,
                               finding_ids=["f-soc-1"],  status=ReportStatusEnum.PUBLISHED)
report_tech    = build_report("Technical Analysis", ReportTypeEnum.TECHNICAL,  TS, confidence=55.0,
                               finding_ids=["f-tech-1"], status=ReportStatusEnum.DRAFT,
                               alert_ids=["a-tech-1"])
report_forensic= build_report("Forensic Deep Dive", ReportTypeEnum.FORENSICS,  TS2, confidence=40.0,
                               finding_ids=["f-001"],    status=ReportStatusEnum.ARCHIVED)
report_ioc     = build_report("IOC Intelligence",   ReportTypeEnum.IOC,        TS, confidence=60.0,
                               alert_ids=["a-001"],      status=ReportStatusEnum.DRAFT)


# ===========================================================================
# 8. Builder: build_report_mapping
# ===========================================================================
print("\n[8] build_report_mapping")

mapping1 = build_report_mapping(
    reports    = [report1],
    created_at = TS,
    finding_id = "finding-abc",
    confidence = 80.0,
)
_assert(mapping1.findingId           == "finding-abc", "findingId set")
_assert(mapping1.alertId             == "",            "alertId empty by default")
_assert(mapping1.reasoningId         == "",            "reasoningId empty by default")
_assert(mapping1.confidence          == 80.0,          "confidence set")
_assert(len(mapping1.mappingKey)     == 32,            "mappingKey is 32 chars")
_assert(len(mapping1.mappingId)      == 36,            "mappingId is UUID format")
_assert(mapping1.mappingId.count("-") == 4,            "mappingId has 4 dashes")
_assert(len(mapping1.mappingFingerprint) == 32,        "fingerprint is 32 chars")
_assert(len(mapping1.reports)        == 1,             "1 report in mapping")
_assert(mapping1.mappingFingerprint != mapping1.mappingKey, "fingerprint != mappingKey")

# Determinism
mapping1b = build_report_mapping(
    reports    = [report1],
    created_at = TS2,
    finding_id = "finding-abc",
    confidence = 80.0,
)
_assert(mapping1.mappingKey         == mapping1b.mappingKey,         "mappingKey deterministic")
_assert(mapping1.mappingId          == mapping1b.mappingId,          "mappingId deterministic")
_assert(mapping1.mappingFingerprint == mapping1b.mappingFingerprint, "fingerprint deterministic")

# Confidence clamping
m_lo = build_report_mapping([report1], TS, finding_id="f1", confidence=-5.0)
_assert(m_lo.confidence == 0.0,   "mapping confidence clamped to 0.0")

m_hi = build_report_mapping([report1], TS, finding_id="f1", confidence=150.0)
_assert(m_hi.confidence == 100.0, "mapping confidence clamped to 100.0")

# Exact boundary values
m_c0   = build_report_mapping([report1], TS, finding_id="f1", confidence=0.0)
m_c100 = build_report_mapping([report1], TS, finding_id="f1", confidence=100.0)
_assert(m_c0.confidence   == 0.0,   "confidence 0.0 accepted")
_assert(m_c100.confidence == 100.0, "confidence 100.0 accepted")

# Report sort order: reportType ASC, then reportId ASC
mapping_sorted = build_report_mapping(
    reports    = [report_soc2, report_exec, report1],
    created_at = TS,
    alert_id   = "a-sort",
)
type_vals = [r.reportType.value for r in mapping_sorted.reports]
_assert(type_vals == sorted(type_vals), "reports sorted by reportType.value ASC in mapping")

# Multiple source IDs
mapping_multi = build_report_mapping(
    [report1], TS,
    finding_id   = "f1",
    alert_id     = "a1",
    reasoning_id = "r1",
    confidence   = 75.0,
)
_assert(mapping_multi.findingId   == "f1", "multi: findingId set")
_assert(mapping_multi.alertId     == "a1", "multi: alertId set")
_assert(mapping_multi.reasoningId == "r1", "multi: reasoningId set")

# Empty reports list
mapping_empty = build_report_mapping([], TS, finding_id="f1")
_assert(mapping_empty.reports == (), "empty reports → empty tuple")

# Build extra mappings for later use
mapping2 = build_report_mapping([report_default], TS, alert_id="alert-xyz", confidence=60.0)
mapping3 = build_report_mapping([report_exec],    TS, reasoning_id="reasoning-99", confidence=40.0)
mapping4 = build_report_mapping([report_soc2],    TS, finding_id="f-soc-1", confidence=50.0)
mapping5 = build_report_mapping([report_tech],    TS, alert_id="a-tech-1", confidence=30.0)


# ===========================================================================
# 9. Builder: build_report_statistics (extended)
# ===========================================================================
print("\n[9] build_report_statistics (extended)")

# Empty input
stats_empty = build_report_statistics([])
_assert(stats_empty.totalReports      == 0,   "empty: total 0")
_assert(stats_empty.draftReports      == 0,   "empty: draft 0")
_assert(stats_empty.readyReports      == 0,   "empty: ready 0")
_assert(stats_empty.publishedReports  == 0,   "empty: published 0")
_assert(stats_empty.archivedReports   == 0,   "empty: archived 0")
_assert(stats_empty.averageConfidence == 0.0, "empty: avgConf 0.0")
_assert(stats_empty.averageSections   == 0.0, "empty: avgSections 0.0")
_assert(stats_empty.reportTypeCounts  == {},  "empty: reportTypeCounts {}")
_assert(stats_empty.statusCounts      == {},  "empty: statusCounts {}")

# Build diverse collection
all_reports = [report1, report_exec, report_soc2, report_tech, report_forensic, report_ioc]
stats = build_report_statistics(all_reports)

_assert(stats.totalReports      == 6, "total 6")
_assert(stats.draftReports      == 3, "draft 3 (report1, report_tech, report_ioc)")
_assert(stats.readyReports      == 1, "ready 1 (report_exec)")
_assert(stats.publishedReports  == 1, "published 1 (report_soc2)")
_assert(stats.archivedReports   == 1, "archived 1 (report_forensic)")

expected_avg = round(sum([80.0, 90.0, 70.0, 55.0, 40.0, 60.0]) / 6, 4)
_assert(stats.averageConfidence == expected_avg, "avgConf correct")

# reportTypeCounts
_assert("INCIDENT"  in stats.reportTypeCounts, "INCIDENT in reportTypeCounts")
_assert("EXECUTIVE" in stats.reportTypeCounts, "EXECUTIVE in reportTypeCounts")
_assert("SOC"       in stats.reportTypeCounts, "SOC in reportTypeCounts")
_assert("TECHNICAL" in stats.reportTypeCounts, "TECHNICAL in reportTypeCounts")
_assert("FORENSICS" in stats.reportTypeCounts, "FORENSICS in reportTypeCounts")
_assert("IOC"       in stats.reportTypeCounts, "IOC in reportTypeCounts")
_assert(stats.reportTypeCounts["INCIDENT"]  == 1, "INCIDENT count 1")
_assert(stats.reportTypeCounts["EXECUTIVE"] == 1, "EXECUTIVE count 1")
_assert(stats.reportTypeCounts["SOC"]       == 1, "SOC count 1")
_assert(stats.reportTypeCounts["TECHNICAL"] == 1, "TECHNICAL count 1")
_assert(stats.reportTypeCounts["FORENSICS"] == 1, "FORENSICS count 1")
_assert(stats.reportTypeCounts["IOC"]       == 1, "IOC count 1")

# statusCounts
_assert("DRAFT"     in stats.statusCounts, "DRAFT in statusCounts")
_assert("READY"     in stats.statusCounts, "READY in statusCounts")
_assert("PUBLISHED" in stats.statusCounts, "PUBLISHED in statusCounts")
_assert("ARCHIVED"  in stats.statusCounts, "ARCHIVED in statusCounts")
_assert(stats.statusCounts["DRAFT"]     == 3, "DRAFT count 3")
_assert(stats.statusCounts["READY"]     == 1, "READY count 1")
_assert(stats.statusCounts["PUBLISHED"] == 1, "PUBLISHED count 1")
_assert(stats.statusCounts["ARCHIVED"]  == 1, "ARCHIVED count 1")

# Deduplication — duplicate report counted once
stats_dedup = build_report_statistics([report1, report1, report_exec])
_assert(stats_dedup.totalReports == 2, "dedup: 2 distinct reports")

# Order-independence
stats_rev = build_report_statistics(list(reversed(all_reports)))
_assert(stats.totalReports         == stats_rev.totalReports,      "stats order-independent total")
_assert(stats.averageConfidence    == stats_rev.averageConfidence,  "stats order-independent avgConf")
_assert(stats.reportTypeCounts     == stats_rev.reportTypeCounts,   "stats order-independent typeCounts")
_assert(stats.statusCounts         == stats_rev.statusCounts,       "stats order-independent statusCounts")

# averageSections with sections
r_with_secs = build_report("With Sections", ReportTypeEnum.SUMMARY, TS, sections=[sec1, sec2, sec3])
stats_secs = build_report_statistics([r_with_secs, report_default])
_assert(stats_secs.averageSections == round((3 + 0) / 2, 4), "avgSections (3+0)/2 correct")

# Immutability of stats
_assert_raises(Exception, setattr, stats_empty, "totalReports", 99, msg="ReportStatistics is immutable")


# ===========================================================================
# 10. Report Operations
# ===========================================================================
print("\n[10] Report Operations")

# add_report
rlist: list = []
rlist = add_report(rlist, report1)
_assert(len(rlist) == 1,                           "add: list grows to 1")
_assert(rlist[0].reportId == report1.reportId,     "add: correct report stored")

# Idempotent
rlist2 = add_report(rlist, report1)
_assert(len(rlist2) == 1,                          "add duplicate: list stays at 1")

# Add second
rlist3 = add_report(rlist, report_exec)
_assert(len(rlist3) == 2,                          "add second: list grows to 2")

# Input not mutated
_assert(len(rlist) == 1,                           "original list unchanged after add")

# Sorted by reportId ASC
rlist4 = add_report(rlist3, report_soc2)
ids = [r.reportId for r in rlist4]
_assert(ids == sorted(ids),                        "add: result sorted by reportId ASC")

# update_report — change description and status
updated_list = update_report(
    rlist3,
    report1.reportId,
    description = "Updated description.",
    status      = ReportStatusEnum.READY,
)
_assert(len(updated_list) == 2,                    "update: list length unchanged")
found = next(r for r in updated_list if r.reportId == report1.reportId)
_assert(found.description == "Updated description.", "update: description changed")
_assert(found.status      == ReportStatusEnum.READY, "update: status changed")
_assert(found.reportType  == report1.reportType,     "update: reportType preserved")
_assert(found.title       == report1.title,          "update: title preserved when not updated")

# update_report — confidence update
updated_conf = update_report(rlist3, report1.reportId, confidence=95.0)
found_conf = next(r for r in updated_conf if r.reportId == report1.reportId)
_assert(found_conf.confidence == 95.0,             "update: confidence changed")

# update_report — ID preserved when title/type/findingIds unchanged
_assert(found.reportId  == report1.reportId,       "update: reportId preserved (non-identity fields)")
_assert(found.reportKey == report1.reportKey,      "update: reportKey preserved (non-identity fields)")

# update_report — not found returns unchanged copy
updated_nf = update_report(rlist3, "nonexistent-id", description="X")
_assert(len(updated_nf) == 2,                      "update not-found: list unchanged")

# Input not mutated after update
_assert(rlist3[0].description == report1.description or
        rlist3[1].description == report_exec.description,
        "original list not mutated by update")

# remove_report
removed = remove_report(rlist3, report1.reportId)
_assert(len(removed) == 1,                         "remove: list shrinks to 1")
_assert(removed[0].reportId == report_exec.reportId, "remove: correct item removed")

# Idempotent remove
removed2 = remove_report(removed, report1.reportId)
_assert(len(removed2) == 1,                        "remove not-found: idempotent")

# Input not mutated
_assert(len(rlist3) == 2,                          "original list unchanged after remove")

# merge_reports
merge_a = [report1, report_default]
merge_b = [report_default, report_exec, report_soc2]
merged  = merge_reports(merge_a, merge_b)
_assert(len(merged) == 4,                          "merge: 4 distinct reports")
m_ids   = [r.reportId for r in merged]
_assert(m_ids == sorted(m_ids),                    "merge: result sorted by reportId ASC")

# Idempotent merge
merged2 = merge_reports(merged, merge_a)
_assert(len(merged2) == len(merged),               "merge: idempotent re-merge")

# Base wins on conflict
conflict_r = Report(
    reportId    = report1.reportId,
    reportKey   = report1.reportKey,
    title       = "OVERWRITE ATTEMPT",
    description = "",
    reportType  = ReportTypeEnum.SOC,
    status      = ReportStatusEnum.ARCHIVED,
    sections    = (),
    findingIds  = (),
    alertIds    = (),
    evidenceIds = (),
    timelineIds = (),
    iocIds      = (),
    playbookIds = (),
    confidence  = 0.0,
    createdAt   = TS,
)
merged_conflict = merge_reports([report1], [conflict_r])
_assert(len(merged_conflict) == 1,                          "merge conflict: 1 item")
_assert(merged_conflict[0].title == report1.title,          "merge conflict: base wins title")
_assert(merged_conflict[0].reportType == report1.reportType,"merge conflict: base wins reportType")
_assert(merged_conflict[0].status == report1.status,        "merge conflict: base wins status")


# ===========================================================================
# 11. Section Operations
# ===========================================================================
print("\n[11] Section Operations")

# Build a base report with 2 sections
r_base = build_report("Section Test Report", ReportTypeEnum.TECHNICAL, TS, sections=[sec1, sec2])

# add_report_section
r_3secs = add_report_section(r_base, sec3)
_assert(len(r_3secs.sections) == 3,                         "add_section: 3 sections now")
_assert(r_3secs.sections[2].sectionId == sec3.sectionId,   "add_section: sec3 appended")
_assert(r_base.reportId == r_3secs.reportId,               "add_section: reportId preserved")
_assert(len(r_base.sections) == 2,                         "add_section: original report unchanged")

# Idempotent
r_3secs_b = add_report_section(r_3secs, sec3)
_assert(len(r_3secs_b.sections) == 3,                      "add_section duplicate: idempotent")

# add_section preserves all metadata
_assert(r_3secs.title      == r_base.title,                "add_section: title preserved")
_assert(r_3secs.reportType == r_base.reportType,           "add_section: reportType preserved")
_assert(r_3secs.reportId   == r_base.reportId,             "add_section: reportId preserved")
_assert(r_3secs.reportKey  == r_base.reportKey,            "add_section: reportKey preserved")

# Sections remain sorted: order ASC
r_unsorted = build_report("Unsorted", ReportTypeEnum.SOC, TS, sections=[sec3, sec1, sec2])
_assert(r_unsorted.sections[0].order == 1, "sections auto-sorted: order 1 first")
_assert(r_unsorted.sections[1].order == 2, "sections auto-sorted: order 2 second")
_assert(r_unsorted.sections[2].order == 3, "sections auto-sorted: order 3 third")

# update_report_section
r_updated_sec = update_report_section(
    r_3secs,
    sec1.sectionId,
    title   = "Updated Executive Summary",
    content = "New content here.",
    order   = 10,
)
found_sec = next(s for s in r_updated_sec.sections if s.sectionId == sec1.sectionId)
_assert(found_sec.title     == "Updated Executive Summary", "update_section: title changed")
_assert(found_sec.content   == "New content here.",         "update_section: content changed")
_assert(found_sec.order     == 10,                          "update_section: order changed")
_assert(found_sec.sectionId == sec1.sectionId,             "update_section: sectionId preserved")
_assert(found_sec.sectionKey== sec1.sectionKey,            "update_section: sectionKey preserved")

# update_section — not found returns original
r_nf_sec = update_report_section(r_3secs, "nonexistent", title="X")
_assert(r_nf_sec.reportId == r_3secs.reportId,             "update_section not-found: unchanged")
_assert(len(r_nf_sec.sections) == 3,                       "update_section not-found: sections count unchanged")

# update_section — only title changed
r_title_only = update_report_section(r_3secs, sec2.sectionId, title="New Title Only")
found_t = next(s for s in r_title_only.sections if s.sectionId == sec2.sectionId)
_assert(found_t.title   == "New Title Only",               "update_section title only: title changed")
_assert(found_t.content == sec2.content,                   "update_section title only: content preserved")
_assert(found_t.order   == sec2.order,                     "update_section title only: order preserved")

# remove_report_section
r_minus_sec1 = remove_report_section(r_3secs, sec1.sectionId)
_assert(len(r_minus_sec1.sections) == 2,                   "remove_section: 2 sections remain")
_assert(all(s.sectionId != sec1.sectionId for s in r_minus_sec1.sections), "remove_section: sec1 gone")
_assert(r_minus_sec1.reportId == r_3secs.reportId,         "remove_section: reportId preserved")

# Idempotent remove_section
r_nf_remove = remove_report_section(r_3secs, "nonexistent")
_assert(r_nf_remove.reportId == r_3secs.reportId,          "remove_section not-found: unchanged")
_assert(len(r_nf_remove.sections) == 3,                    "remove_section not-found: sections count unchanged")

# Input report not mutated
_assert(len(r_3secs.sections) == 3,                        "remove_section: original report unchanged")

# merge_report_sections
r_merged_secs = merge_report_sections(r_base, [sec3, sec4])
_assert(len(r_merged_secs.sections) == 4,                  "merge_sections: 4 sections")

# Idempotent merge
r_merged_secs2 = merge_report_sections(r_merged_secs, [sec3], )
_assert(len(r_merged_secs2.sections) == 4,                 "merge_sections: idempotent re-merge")

# Base section wins on conflict
sec1_conflict = ReportSection(
    sectionId  = sec1.sectionId,
    sectionKey = sec1.sectionKey,
    title      = "OVERWRITE",
    order      = 99,
    content    = "OVERWRITE",
    createdAt  = TS,
)
r_conflict_sec = merge_report_sections(
    build_report("X", ReportTypeEnum.SOC, TS, sections=[sec1]),
    [sec1_conflict],
)
found_s = next(s for s in r_conflict_sec.sections if s.sectionId == sec1.sectionId)
_assert(found_s.title == sec1.title, "merge_sections conflict: base wins title")
_assert(found_s.order == sec1.order, "merge_sections conflict: base wins order")

# merge_sections preserves report metadata
_assert(r_merged_secs.title     == r_base.title,     "merge_sections: title preserved")
_assert(r_merged_secs.reportId  == r_base.reportId,  "merge_sections: reportId preserved")
_assert(r_merged_secs.reportKey == r_base.reportKey, "merge_sections: reportKey preserved")


# ===========================================================================
# 12. Mapping Operations
# ===========================================================================
print("\n[12] Mapping Operations")

# add_report_mapping
mlist: list = []
mlist = add_report_mapping(mlist, mapping1)
_assert(len(mlist) == 1,                                "add_mapping: list grows to 1")
_assert(mlist[0].mappingId == mapping1.mappingId,       "add_mapping: correct mapping stored")

# Idempotent
mlist2 = add_report_mapping(mlist, mapping1)
_assert(len(mlist2) == 1,                               "add_mapping duplicate: idempotent")

# Add second
mlist3 = add_report_mapping(mlist, mapping2)
_assert(len(mlist3) == 2,                               "add_mapping: list grows to 2")

# Input not mutated
_assert(len(mlist) == 1,                                "original mapping list unchanged")

# Sorted by mappingId ASC
m_ids = [m.mappingId for m in mlist3]
_assert(m_ids == sorted(m_ids),                         "add_mapping: result sorted by mappingId")

# remove_report_mapping
mrem = remove_report_mapping(mlist3, mapping1.mappingId)
_assert(len(mrem) == 1,                                 "remove_mapping: list shrinks to 1")
_assert(mrem[0].mappingId == mapping2.mappingId,        "remove_mapping: correct item removed")

# Idempotent remove
mrem2 = remove_report_mapping(mrem, mapping1.mappingId)
_assert(len(mrem2) == 1,                                "remove_mapping not-found: idempotent")

# Input not mutated
_assert(len(mlist3) == 2,                               "mapping list unchanged after remove")

# merge_report_mappings
merged_m = merge_report_mappings([mapping1, mapping2], [mapping2, mapping3])
_assert(len(merged_m) == 3,                             "merge_mappings: 3 distinct")
merged_ids = [m.mappingId for m in merged_m]
_assert(merged_ids == sorted(merged_ids),               "merge_mappings: sorted by mappingId")

# Idempotent merge
merged_m2 = merge_report_mappings(merged_m, [mapping1])
_assert(len(merged_m2) == 3,                            "merge_mappings: idempotent re-merge")

# Base wins on conflict
conflict_mapping = ReportMapping(
    mappingId          = mapping1.mappingId,
    mappingKey         = mapping1.mappingKey,
    findingId          = "different-finding",
    alertId            = "",
    reasoningId        = "",
    reports            = (),
    confidence         = 99.0,
    mappingFingerprint = mapping1.mappingFingerprint,
    createdAt          = TS,
)
merged_conflict_m = merge_report_mappings([mapping1], [conflict_mapping])
_assert(len(merged_conflict_m) == 1,                               "merge conflict: 1 item")
_assert(merged_conflict_m[0].findingId   == mapping1.findingId,    "merge conflict: base findingId wins")
_assert(merged_conflict_m[0].confidence  == mapping1.confidence,   "merge conflict: base confidence wins")

# Fingerprint stability through merge
_assert(merged_conflict_m[0].mappingFingerprint == mapping1.mappingFingerprint,
        "merge conflict: fingerprint preserved from base")


# ===========================================================================
# 13. Search Utilities
# ===========================================================================
print("\n[13] Search")

search_list = [report1, report_exec, report_soc2, report_tech, report_forensic]

# find_report by reportId
found_r = find_report(search_list, report_id=report_exec.reportId)
_assert(found_r is not None,                          "find by reportId: found")
_assert(found_r.reportId == report_exec.reportId,     "find by reportId: correct item")

# find_report by reportKey
found_rk = find_report(search_list, report_key=report_soc2.reportKey)
_assert(found_rk is not None,                         "find by reportKey: found")
_assert(found_rk.reportId == report_soc2.reportId,    "find by reportKey: correct item")

# find_report — not found returns None
_assert(find_report(search_list, report_id="nonexistent") is None, "find: not found returns None")
_assert(find_report([], report_id=report1.reportId)        is None, "find: empty list returns None")

# find_report — reportId takes precedence over reportKey
found_prec = find_report(search_list,
                         report_id=report_exec.reportId,
                         report_key=report_soc2.reportKey)
_assert(found_prec.reportId == report_exec.reportId, "find: reportId takes precedence")

# find_report_section
r_sec_search = build_report("Search Test", ReportTypeEnum.SOC, TS,
                             sections=[sec1, sec2, sec3])

found_s = find_report_section(r_sec_search, section_id=sec2.sectionId)
_assert(found_s is not None,                         "find_section by sectionId: found")
_assert(found_s.sectionId == sec2.sectionId,         "find_section by sectionId: correct item")

found_sk = find_report_section(r_sec_search, section_key=sec3.sectionKey)
_assert(found_sk is not None,                        "find_section by sectionKey: found")
_assert(found_sk.sectionId == sec3.sectionId,        "find_section by sectionKey: correct item")

_assert(find_report_section(r_sec_search, section_id="nope") is None, "find_section: not found None")

# sectionId takes precedence
found_s_prec = find_report_section(r_sec_search,
                                   section_id=sec1.sectionId,
                                   section_key=sec3.sectionKey)
_assert(found_s_prec.sectionId == sec1.sectionId, "find_section: sectionId takes precedence")

# find_report_mapping
mapping_search_list = [mapping1, mapping2, mapping3, mapping4, mapping5]

found_m = find_report_mapping(mapping_search_list, mapping_id=mapping3.mappingId)
_assert(found_m is not None,                         "find_mapping by mappingId: found")
_assert(found_m.mappingId == mapping3.mappingId,     "find_mapping: correct item")

_assert(find_report_mapping(mapping_search_list, mapping_id="nope") is None, "find_mapping: not found None")
_assert(find_report_mapping([], mapping_id=mapping1.mappingId) is None,      "find_mapping: empty list None")


# ===========================================================================
# 14. Sorting
# ===========================================================================
print("\n[14] Sorting")

sort_list = [report1, report_exec, report_soc2, report_tech, report_forensic, report_ioc]

# sort_reports by title ASC
by_title = sort_reports(sort_list, by="title", ascending=True)
titles = [r.title for r in by_title]
_assert(titles == sorted(titles), "sort_reports title ASC")

# sort_reports by title DESC
by_title_desc = sort_reports(sort_list, by="title", ascending=False)
titles_d = [r.title for r in by_title_desc]
_assert(titles_d == sorted(titles_d, reverse=True), "sort_reports title DESC")

# sort_reports by reportType ASC
by_type = sort_reports(sort_list, by="reportType", ascending=True)
type_vals_s = [r.reportType.value for r in by_type]
_assert(type_vals_s == sorted(type_vals_s), "sort_reports reportType ASC")

# sort_reports by status ASC
by_status = sort_reports(sort_list, by="status", ascending=True)
status_vals = [r.status.value for r in by_status]
_assert(status_vals == sorted(status_vals), "sort_reports status ASC")

# sort_reports by confidence ASC
by_conf = sort_reports(sort_list, by="confidence", ascending=True)
confs = [r.confidence for r in by_conf]
_assert(confs == sorted(confs), "sort_reports confidence ASC")

# sort_reports by confidence DESC
by_conf_desc = sort_reports(sort_list, by="confidence", ascending=False)
confs_d = [r.confidence for r in by_conf_desc]
_assert(confs_d == sorted(confs_d, reverse=True), "sort_reports confidence DESC")

# sort_reports by createdAt ASC
by_created = sort_reports(sort_list, by="createdAt", ascending=True)
dates = [r.createdAt for r in by_created]
_assert(dates == sorted(dates), "sort_reports createdAt ASC")

# Unknown sort key raises ValueError
_assert_raises(ValueError, sort_reports, sort_list, by="nonexistent", msg="unknown sort key raises ValueError")

# Input not mutated
orig_ids = [r.reportId for r in sort_list]
_ = sort_reports(sort_list, by="title")
_assert([r.reportId for r in sort_list] == orig_ids, "sort_reports: input not mutated")

# Stable tie-breaking by reportId
dup_conf_a = build_report("AAA", ReportTypeEnum.SOC, TS, confidence=75.0)
dup_conf_b = build_report("BBB", ReportTypeEnum.IOC, TS, confidence=75.0)
tie_sorted = sort_reports([dup_conf_b, dup_conf_a], by="confidence", ascending=True)
# Both have same confidence, tie-broken by reportId ASC
expected_order = sorted([dup_conf_a.reportId, dup_conf_b.reportId])
actual_order   = [r.reportId for r in tie_sorted]
_assert(actual_order == expected_order, "sort_reports: tie-breaking by reportId ASC")

# sort_report_sections
sec_list = [sec3, sec1, sec5, sec2, sec4]

by_order = sort_report_sections(sec_list, by="order", ascending=True)
orders = [s.order for s in by_order]
_assert(orders == sorted(orders), "sort_sections order ASC")

by_order_d = sort_report_sections(sec_list, by="order", ascending=False)
orders_d = [s.order for s in by_order_d]
_assert(orders_d == sorted(orders_d, reverse=True), "sort_sections order DESC")

by_sec_title = sort_report_sections(sec_list, by="title", ascending=True)
sec_titles = [s.title for s in by_sec_title]
_assert(sec_titles == sorted(sec_titles), "sort_sections title ASC")

_assert_raises(ValueError, sort_report_sections, sec_list, by="bad_key", msg="sort_sections unknown key raises ValueError")

# sort_report_mappings
m_sort_list = [mapping1, mapping2, mapping3, mapping4, mapping5]

by_conf_m = sort_report_mappings(m_sort_list, by="confidence", ascending=True)
confs_m = [m.confidence for m in by_conf_m]
_assert(confs_m == sorted(confs_m), "sort_mappings confidence ASC")

by_conf_m_d = sort_report_mappings(m_sort_list, by="confidence", ascending=False)
confs_m_d = [m.confidence for m in by_conf_m_d]
_assert(confs_m_d == sorted(confs_m_d, reverse=True), "sort_mappings confidence DESC")

by_created_m = sort_report_mappings(m_sort_list, by="createdAt", ascending=True)
dates_m = [m.createdAt for m in by_created_m]
_assert(dates_m == sorted(dates_m), "sort_mappings createdAt ASC")

_assert_raises(ValueError, sort_report_mappings, m_sort_list, by="bad_key", msg="sort_mappings unknown key raises ValueError")


# ===========================================================================
# 15. Filtering
# ===========================================================================
print("\n[15] Filtering")

filter_list = [report1, report_exec, report_soc2, report_tech, report_forensic, report_ioc]

# filter by reportType
f_incident = filter_reports(filter_list, report_type=ReportTypeEnum.INCIDENT)
_assert(len(f_incident) == 1,                               "filter reportType INCIDENT: 1 result")
_assert(f_incident[0].reportType == ReportTypeEnum.INCIDENT, "filter reportType: correct type")

f_soc = filter_reports(filter_list, report_type=ReportTypeEnum.SOC)
_assert(len(f_soc) == 1,                                    "filter reportType SOC: 1 result")

# filter by status
f_draft = filter_reports(filter_list, status=ReportStatusEnum.DRAFT)
_assert(len(f_draft) == 3,                                  "filter status DRAFT: 3 results")
_assert(all(r.status == ReportStatusEnum.DRAFT for r in f_draft), "filter status DRAFT: all correct")

f_ready = filter_reports(filter_list, status=ReportStatusEnum.READY)
_assert(len(f_ready) == 1,                                  "filter status READY: 1 result")

f_published = filter_reports(filter_list, status=ReportStatusEnum.PUBLISHED)
_assert(len(f_published) == 1,                              "filter status PUBLISHED: 1 result")

f_archived = filter_reports(filter_list, status=ReportStatusEnum.ARCHIVED)
_assert(len(f_archived) == 1,                               "filter status ARCHIVED: 1 result")

# filter by min_confidence
f_conf_60 = filter_reports(filter_list, min_confidence=60.0)
_assert(all(r.confidence >= 60.0 for r in f_conf_60), "filter min_confidence: all >= 60")

f_conf_80 = filter_reports(filter_list, min_confidence=80.0)
_assert(len(f_conf_80) == 2, "filter min_confidence 80: 2 results (80, 90)")

# filter by max_confidence
f_max_60 = filter_reports(filter_list, max_confidence=60.0)
_assert(all(r.confidence <= 60.0 for r in f_max_60), "filter max_confidence: all <= 60")

# combined min+max
f_range = filter_reports(filter_list, min_confidence=55.0, max_confidence=80.0)
_assert(all(55.0 <= r.confidence <= 80.0 for r in f_range), "filter confidence range: all in range")

# filter by finding_id
f_fid = filter_reports(filter_list, finding_id="f-001")
_assert(all("f-001" in r.findingIds for r in f_fid), "filter finding_id: only matching")
_assert(len(f_fid) >= 1, "filter finding_id: at least 1 result")

# filter by alert_id
f_aid = filter_reports(filter_list, alert_id="a-001")
_assert(all("a-001" in r.alertIds for r in f_aid), "filter alert_id: only matching")

# no match
f_none = filter_reports(filter_list, report_type=ReportTypeEnum.SUMMARY)
_assert(len(f_none) == 0, "filter no match: empty list")

# Empty list input
_assert(filter_reports([], report_type=ReportTypeEnum.INCIDENT) == [], "filter empty input: empty output")

# Input not mutated
orig_count = len(filter_list)
_ = filter_reports(filter_list, status=ReportStatusEnum.DRAFT)
_assert(len(filter_list) == orig_count, "filter: input not mutated")

# filter_report_sections
all_sections = [sec1, sec2, sec3, sec4, sec5]

f_title = filter_report_sections(all_sections, title_contains="executive")
_assert(len(f_title) == 1, "filter_sections title_contains: 1 result")
_assert(f_title[0].sectionId == sec1.sectionId, "filter_sections title_contains: correct section")

f_title_ci = filter_report_sections(all_sections, title_contains="ANALYSIS")
_assert(len(f_title_ci) >= 1, "filter_sections title_contains case-insensitive")

f_min_order = filter_report_sections(all_sections, min_order=3)
_assert(all(s.order >= 3 for s in f_min_order), "filter_sections min_order: all >= 3")
_assert(len(f_min_order) == 3, "filter_sections min_order=3: 3 results (3,4,5)")

f_max_order = filter_report_sections(all_sections, max_order=2)
_assert(all(s.order <= 2 for s in f_max_order), "filter_sections max_order: all <= 2")
_assert(len(f_max_order) == 2, "filter_sections max_order=2: 2 results")

f_range_order = filter_report_sections(all_sections, min_order=2, max_order=4)
_assert(all(2 <= s.order <= 4 for s in f_range_order), "filter_sections order range: all in range")
_assert(len(f_range_order) == 3, "filter_sections order range 2-4: 3 results")

f_no_match = filter_report_sections(all_sections, min_order=99)
_assert(len(f_no_match) == 0, "filter_sections no match: empty list")

# filter_report_mappings
m_filter_list = [mapping1, mapping2, mapping3, mapping4, mapping5]

f_fid_m = filter_report_mappings(m_filter_list, finding_id="finding-abc")
_assert(all(m.findingId == "finding-abc" for m in f_fid_m), "filter_mappings by findingId: correct")

f_aid_m = filter_report_mappings(m_filter_list, alert_id="alert-xyz")
_assert(all(m.alertId == "alert-xyz" for m in f_aid_m), "filter_mappings by alertId: correct")

f_rid_m = filter_report_mappings(m_filter_list, reasoning_id="reasoning-99")
_assert(all(m.reasoningId == "reasoning-99" for m in f_rid_m), "filter_mappings by reasoningId: correct")

f_conf_m = filter_report_mappings(m_filter_list, min_confidence=50.0)
_assert(all(m.confidence >= 50.0 for m in f_conf_m), "filter_mappings min_confidence: all >= 50")

f_max_conf_m = filter_report_mappings(m_filter_list, max_confidence=50.0)
_assert(all(m.confidence <= 50.0 for m in f_max_conf_m), "filter_mappings max_confidence: all <= 50")

f_none_m = filter_report_mappings(m_filter_list, finding_id="nonexistent-finding")
_assert(len(f_none_m) == 0, "filter_mappings no match: empty list")


# ===========================================================================
# 16. Grouping
# ===========================================================================
print("\n[16] Grouping")

group_list = [report1, report_exec, report_soc2, report_tech, report_forensic, report_ioc]

# group by reportType
by_type_g = group_reports(group_list, group_by="reportType")
_assert("INCIDENT"  in by_type_g, "group reportType: INCIDENT key")
_assert("EXECUTIVE" in by_type_g, "group reportType: EXECUTIVE key")
_assert("SOC"       in by_type_g, "group reportType: SOC key")
_assert("TECHNICAL" in by_type_g, "group reportType: TECHNICAL key")
_assert("FORENSICS" in by_type_g, "group reportType: FORENSICS key")
_assert("IOC"       in by_type_g, "group reportType: IOC key")
_assert(len(by_type_g["INCIDENT"])  == 1, "group reportType INCIDENT: 1 report")
_assert(len(by_type_g["EXECUTIVE"]) == 1, "group reportType EXECUTIVE: 1 report")

# Each group sorted by reportId ASC
for key, group in by_type_g.items():
    gids = [r.reportId for r in group]
    _assert(gids == sorted(gids), f"group reportType '{key}': sorted by reportId")

# group by status
by_status_g = group_reports(group_list, group_by="status")
_assert("DRAFT"     in by_status_g, "group status: DRAFT key")
_assert("READY"     in by_status_g, "group status: READY key")
_assert("PUBLISHED" in by_status_g, "group status: PUBLISHED key")
_assert("ARCHIVED"  in by_status_g, "group status: ARCHIVED key")
_assert(len(by_status_g["DRAFT"]) == 3, "group status DRAFT: 3 reports")
_assert(len(by_status_g["READY"]) == 1, "group status READY: 1 report")

# group by confidence — numeric key
by_conf_g = group_reports(group_list, group_by="confidence")
_assert(len(by_conf_g) >= 1, "group confidence: at least 1 group")

# group with unknown attribute → "unknown" key
by_unknown = group_reports(group_list, group_by="nonexistent_attr")
_assert("unknown" in by_unknown, "group unknown attr: 'unknown' key")
_assert(len(by_unknown["unknown"]) == len(group_list), "group unknown attr: all items in unknown group")

# Empty list
_assert(group_reports([], group_by="reportType") == {}, "group empty list: empty dict")

# group_report_sections
sec_group_list = list(report1.sections) + list(r_base.sections) + [sec3, sec4, sec5]

by_title_sg = group_report_sections(sec_group_list, group_by="title")
_assert(len(by_title_sg) >= 1, "group_sections by title: at least 1 group")
for key, grp in by_title_sg.items():
    gids = [(s.order, s.sectionId) for s in grp]
    _assert(gids == sorted(gids), f"group_sections title '{key}': sorted by (order,sectionId)")

by_order_sg = group_report_sections(sec_group_list, group_by="order")
_assert(len(by_order_sg) >= 1, "group_sections by order: at least 1 group")

_assert(group_report_sections([], group_by="title") == {}, "group_sections empty list: empty dict")

# group_report_mappings
m_group_list = [mapping1, mapping2, mapping3, mapping4, mapping5]

by_fid_g = group_report_mappings(m_group_list, group_by="findingId")
_assert(len(by_fid_g) >= 1, "group_mappings by findingId: at least 1 group")
for key, grp in by_fid_g.items():
    mids = [m.mappingId for m in grp]
    _assert(mids == sorted(mids), f"group_mappings findingId '{key}': sorted by mappingId")

by_aid_g = group_report_mappings(m_group_list, group_by="alertId")
_assert(len(by_aid_g) >= 1, "group_mappings by alertId: at least 1 group")

by_rid_g = group_report_mappings(m_group_list, group_by="reasoningId")
_assert(len(by_rid_g) >= 1, "group_mappings by reasoningId: at least 1 group")

_assert(group_report_mappings([], group_by="findingId") == {}, "group_mappings empty list: empty dict")


# ===========================================================================
# 17. Serialization
# ===========================================================================
print("\n[17] Serialization")

# ReportSection round-trip
sec_dict = sec1.model_dump()
_assert(sec_dict["sectionId"]  == sec1.sectionId,  "section model_dump: sectionId")
_assert(sec_dict["sectionKey"] == sec1.sectionKey, "section model_dump: sectionKey")
_assert(sec_dict["title"]      == sec1.title,      "section model_dump: title")
_assert(sec_dict["order"]      == sec1.order,      "section model_dump: order")
_assert(sec_dict["content"]    == sec1.content,    "section model_dump: content")
_assert(sec_dict["createdAt"]  == sec1.createdAt,  "section model_dump: createdAt")

# Reconstruct from dict
sec_reconstructed = ReportSection(**sec_dict)
_assert(sec_reconstructed.sectionId  == sec1.sectionId,  "section round-trip: sectionId")
_assert(sec_reconstructed.sectionKey == sec1.sectionKey, "section round-trip: sectionKey")

# Report round-trip
r_dict = report1.model_dump()
_assert(r_dict["reportId"]   == report1.reportId,  "report model_dump: reportId")
_assert(r_dict["reportKey"]  == report1.reportKey, "report model_dump: reportKey")
_assert(r_dict["title"]      == report1.title,     "report model_dump: title")
_assert(r_dict["reportType"] == report1.reportType.value, "report model_dump: reportType")
_assert(r_dict["status"]     == report1.status.value,     "report model_dump: status")
_assert("sections"           in r_dict,                   "report model_dump: sections key present")

# ReportMapping round-trip
m_dict = mapping1.model_dump()
_assert(m_dict["mappingId"]          == mapping1.mappingId,          "mapping model_dump: mappingId")
_assert(m_dict["mappingKey"]         == mapping1.mappingKey,         "mapping model_dump: mappingKey")
_assert(m_dict["mappingFingerprint"] == mapping1.mappingFingerprint, "mapping model_dump: fingerprint")
_assert(m_dict["findingId"]          == mapping1.findingId,          "mapping model_dump: findingId")
_assert(m_dict["confidence"]         == mapping1.confidence,         "mapping model_dump: confidence")

# ReportStatistics round-trip
stats_dict = stats.model_dump()
_assert(stats_dict["totalReports"]      == stats.totalReports,      "stats model_dump: totalReports")
_assert(stats_dict["averageConfidence"] == stats.averageConfidence, "stats model_dump: avgConf")
_assert("reportTypeCounts"             in stats_dict,               "stats model_dump: reportTypeCounts key")
_assert("statusCounts"                 in stats_dict,               "stats model_dump: statusCounts key")


# ===========================================================================
# 18. Immutability
# ===========================================================================
print("\n[18] Immutability")

_assert_raises(Exception, setattr, sec1,      "title",     "hack", msg="ReportSection frozen")
_assert_raises(Exception, setattr, sec1,      "order",     99,     msg="ReportSection order frozen")
_assert_raises(Exception, setattr, report1,   "title",     "hack", msg="Report frozen")
_assert_raises(Exception, setattr, report1,   "status",    ReportStatusEnum.ARCHIVED, msg="Report status frozen")
_assert_raises(Exception, setattr, report1,   "confidence", 0.0,   msg="Report confidence frozen")
_assert_raises(Exception, setattr, mapping1,  "findingId", "hack", msg="ReportMapping frozen")
_assert_raises(Exception, setattr, mapping1,  "confidence", 0.0,   msg="ReportMapping confidence frozen")
_assert_raises(Exception, setattr, stats_empty,"totalReports", 1,  msg="ReportStatistics frozen")

# Tuples are immutable — cannot append in-place
try:
    report1.sections += (sec3,)  # type: ignore
    _assert(False, "sections tuple should not allow +=")
except Exception:
    _assert(True, "sections tuple is immutable (+=  fails)")


# ===========================================================================
# 19. Integration Helpers
# ===========================================================================
print("\n[19] Integration Helpers")

class FakeFinding:
    findingId = "finding-integration-1"

class FakeAlert:
    alertId   = "alert-integration-1"
    findingId = "finding-integration-1"

class FakeReasoning:
    reasoningId       = "reasoning-integration-1"
    overallConfidence = 88.0

class FakeTimeline:
    timelineEventId = "tl-event-42"

class FakePlaybook:
    playbookId = "pb-007"

class FakeIOC:
    iocId = "ioc-999"

# finding_to_report_mapping
fm = finding_to_report_mapping(FakeFinding(), [report1], TS, 70.0)
_assert(fm.findingId   == "finding-integration-1", "finding helper: findingId set")
_assert(fm.alertId     == "",                       "finding helper: alertId empty")
_assert(fm.reasoningId == "",                       "finding helper: reasoningId empty")
_assert(fm.confidence  == 70.0,                     "finding helper: confidence set")
_assert(len(fm.reports) == 1,                       "finding helper: 1 report linked")
_assert(fm.reports[0].reportId == report1.reportId, "finding helper: correct report linked")

# Determinism of finding_to_report_mapping
fm2 = finding_to_report_mapping(FakeFinding(), [report1], TS2, 70.0)
_assert(fm.mappingId          == fm2.mappingId,          "finding helper: mappingId deterministic")
_assert(fm.mappingFingerprint == fm2.mappingFingerprint, "finding helper: fingerprint deterministic")

# alert_to_report_mapping
am = alert_to_report_mapping(FakeAlert(), [report1], TS, 65.0)
_assert(am.findingId   == "finding-integration-1", "alert helper: findingId extracted")
_assert(am.alertId     == "alert-integration-1",   "alert helper: alertId extracted")
_assert(am.reasoningId == "",                       "alert helper: reasoningId empty")
_assert(am.confidence  == 65.0,                     "alert helper: confidence set")

# Determinism of alert_to_report_mapping
am2 = alert_to_report_mapping(FakeAlert(), [report1], TS3, 65.0)
_assert(am.mappingId == am2.mappingId, "alert helper: mappingId deterministic")

# reasoning_to_report_mapping
rm = reasoning_to_report_mapping(FakeReasoning(), [report1], TS)
_assert(rm.reasoningId == "reasoning-integration-1", "reasoning helper: reasoningId set")
_assert(rm.findingId   == "",                         "reasoning helper: findingId empty by default")
_assert(rm.alertId     == "",                         "reasoning helper: alertId empty by default")
_assert(rm.confidence  == 88.0,                       "reasoning helper: confidence from reasoning.overallConfidence")

# reasoning_to_report_mapping with explicit findingId and alertId
rm2 = reasoning_to_report_mapping(FakeReasoning(), [report1], TS,
                                   finding_id="f-explicit", alert_id="a-explicit")
_assert(rm2.findingId == "f-explicit", "reasoning helper: explicit findingId")
_assert(rm2.alertId   == "a-explicit", "reasoning helper: explicit alertId")

# Determinism
rm3 = reasoning_to_report_mapping(FakeReasoning(), [report1], TS2)
_assert(rm.mappingId == rm3.mappingId, "reasoning helper: mappingId deterministic")

# timeline_to_report_reference
tl_ref = timeline_to_report_reference(FakeTimeline())
_assert(tl_ref == "tl-event-42",     "timeline helper: returns timelineEventId")
_assert(isinstance(tl_ref, str),     "timeline helper: returns str")

tl_ref_missing = timeline_to_report_reference(SimpleNamespace())
_assert(tl_ref_missing == "",        "timeline helper: missing attr returns empty string")

# playbook_to_report_reference
pb_ref = playbook_to_report_reference(FakePlaybook())
_assert(pb_ref == "pb-007",          "playbook helper: returns playbookId")
_assert(isinstance(pb_ref, str),     "playbook helper: returns str")

pb_ref_missing = playbook_to_report_reference(SimpleNamespace())
_assert(pb_ref_missing == "",        "playbook helper: missing attr returns empty string")

# ioc_to_report_reference
ioc_ref = ioc_to_report_reference(FakeIOC())
_assert(ioc_ref == "ioc-999",        "ioc helper: returns iocId")
_assert(isinstance(ioc_ref, str),    "ioc helper: returns str")

ioc_ref_missing = ioc_to_report_reference(SimpleNamespace())
_assert(ioc_ref_missing == "",       "ioc helper: missing attr returns empty string")

# Helpers strip whitespace
class FakeWhitespace:
    timelineEventId = "  spaced-id  "
    playbookId      = "  pb-trimmed  "
    iocId           = "  ioc-trimmed  "

_assert(timeline_to_report_reference(FakeWhitespace()) == "spaced-id",  "timeline helper strips whitespace")
_assert(playbook_to_report_reference(FakeWhitespace()) == "pb-trimmed", "playbook helper strips whitespace")
_assert(ioc_to_report_reference(FakeWhitespace())      == "ioc-trimmed","ioc helper strips whitespace")


# ===========================================================================
# 20. Edge Cases
# ===========================================================================
print("\n[20] Edge Cases")

# build_report with all optional fields explicitly None / empty
r_minimal = build_report("Min", ReportTypeEnum.IOC, TS)
_assert(r_minimal.sections    == (),   "minimal: sections ()")
_assert(r_minimal.findingIds  == (),   "minimal: findingIds ()")
_assert(r_minimal.alertIds    == (),   "minimal: alertIds ()")
_assert(r_minimal.evidenceIds == (),   "minimal: evidenceIds ()")
_assert(r_minimal.timelineIds == (),   "minimal: timelineIds ()")
_assert(r_minimal.iocIds      == (),   "minimal: iocIds ()")
_assert(r_minimal.playbookIds == (),   "minimal: playbookIds ()")

# build_report with whitespace-only IDs — all filtered out
r_ws_ids = build_report("WS IDs", ReportTypeEnum.IOC, TS,
                          finding_ids=["  ", "  "], alert_ids=[""])
_assert(r_ws_ids.findingIds == (), "whitespace-only findingIds filtered")
_assert(r_ws_ids.alertIds   == (), "empty alertIds filtered")

# Large finding_ids list — dedup + sort still deterministic
large_fids = [f"f-{i:04d}" for i in range(200)] + [f"f-{i:04d}" for i in range(200)]
r_large = build_report("Large", ReportTypeEnum.TECHNICAL, TS, finding_ids=large_fids)
_assert(len(r_large.findingIds) == 200,                    "large findingIds: 200 distinct after dedup")
_assert(list(r_large.findingIds) == sorted(set(large_fids)), "large findingIds: sorted+deduped")

# build_report_section with very long content
long_content = "x" * 10_000
sec_long = build_report_section("rid", 1, "Long Section", TS, content=long_content)
_assert(len(sec_long.content) == 10_000, "section: long content preserved")

# Confidence exactly at boundaries
r_exactly0   = build_report("X", ReportTypeEnum.SOC, TS, confidence=0.0)
r_exactly100 = build_report("X", ReportTypeEnum.SOC, TS, confidence=100.0)
_assert(r_exactly0.confidence   == 0.0,   "confidence exactly 0.0")
_assert(r_exactly100.confidence == 100.0, "confidence exactly 100.0")

# update_report with ALL fields None → returns identical copy
rlist_single = [report1]
no_change = update_report(rlist_single, report1.reportId)
_assert(no_change[0].reportId  == report1.reportId,  "update no-op: reportId unchanged")
_assert(no_change[0].title     == report1.title,     "update no-op: title unchanged")
_assert(no_change[0].status    == report1.status,    "update no-op: status unchanged")

# update_report — all ID lists passed as empty list → cleared
cleared = update_report([report1], report1.reportId, finding_ids=[], alert_ids=[])
_assert(cleared[0].findingIds == (), "update: finding_ids cleared to ()")
_assert(cleared[0].alertIds   == (), "update: alert_ids cleared to ()")

# add_report_section to report with no sections
r_empty_secs = build_report("Empty", ReportTypeEnum.SUMMARY, TS)
_assert(len(r_empty_secs.sections) == 0, "no sections initially")
r_one_sec = add_report_section(r_empty_secs, sec1)
_assert(len(r_one_sec.sections) == 1, "add_section to empty: 1 section now")

# remove_report_section from report with no sections
r_no_secs = build_report("NoSecs", ReportTypeEnum.SUMMARY, TS)
r_no_change = remove_report_section(r_no_secs, "nonexistent-id")
_assert(len(r_no_change.sections) == 0, "remove_section from empty: still 0 sections")

# merge_reports with empty lists
merged_empty = merge_reports([], [])
_assert(merged_empty == [], "merge_reports both empty: empty list")

merged_left_only = merge_reports([report1], [])
_assert(len(merged_left_only) == 1, "merge_reports empty incoming: base unchanged")

merged_right_only = merge_reports([], [report1])
_assert(len(merged_right_only) == 1, "merge_reports empty base: incoming added")

# merge_report_mappings with empty lists
merged_m_empty = merge_report_mappings([], [])
_assert(merged_m_empty == [], "merge_mappings both empty: empty list")

# filter_reports with all criteria None → returns all
f_all = filter_reports(filter_list)
_assert(len(f_all) == len(filter_list), "filter_reports all None: returns all")

# filter_report_sections with all criteria None → returns all
f_secs_all = filter_report_sections(all_sections)
_assert(len(f_secs_all) == len(all_sections), "filter_sections all None: returns all")

# filter_report_mappings with all criteria None → returns all
f_m_all = filter_report_mappings(m_filter_list)
_assert(len(f_m_all) == len(m_filter_list), "filter_mappings all None: returns all")

# sort with empty list
_assert(sort_reports([], by="title") == [],               "sort_reports empty: []")
_assert(sort_report_sections([], by="order") == [],       "sort_sections empty: []")
_assert(sort_report_mappings([], by="confidence") == [],  "sort_mappings empty: []")

# group with single item
single_list = [report1]
g_single = group_reports(single_list, group_by="reportType")
_assert(len(g_single) == 1, "group single item: 1 group")


# ===========================================================================
# 21. Deterministic Fingerprints
# ===========================================================================
print("\n[21] Deterministic Fingerprints")

# Same inputs 5 times → always same fingerprint
for i in range(5):
    mfp_check = mappingFingerprint(mk1, "f1", "a1", "r1", ("id1", "id2"))
    _assert(mfp_check == mfp1, f"fingerprint deterministic run #{i+1}")

# Fingerprint changes when any input changes
mfp_diff_key = mappingFingerprint(mk3, "f1", "a1", "r1", ("id1", "id2"))
_assert(mfp_diff_key != mfp1, "fingerprint changes with different mappingKey")

mfp_diff_fid = mappingFingerprint(mk1, "f_DIFFERENT", "a1", "r1", ("id1", "id2"))
_assert(mfp_diff_fid != mfp1, "fingerprint changes with different findingId")

mfp_diff_rids = mappingFingerprint(mk1, "f1", "a1", "r1", ("id1", "id3"))
_assert(mfp_diff_rids != mfp1, "fingerprint changes with different reportIds")

# Two different Report objects → different reportKeys
r_fp_a = build_report("FP Report A", ReportTypeEnum.INCIDENT, TS, finding_ids=["fa1"])
r_fp_b = build_report("FP Report B", ReportTypeEnum.INCIDENT, TS, finding_ids=["fa1"])
_assert(r_fp_a.reportKey != r_fp_b.reportKey, "different titles → different reportKeys")
_assert(r_fp_a.reportId  != r_fp_b.reportId,  "different titles → different reportIds")

# Build mapping twice from same reports → same fingerprint
m_fp_1 = build_report_mapping([r_fp_a], TS,  finding_id="fp-f1", confidence=50.0)
m_fp_2 = build_report_mapping([r_fp_a], TS2, finding_id="fp-f1", confidence=50.0)
_assert(m_fp_1.mappingFingerprint == m_fp_2.mappingFingerprint,
        "mapping fingerprint stable across timestamps")


# ===========================================================================
# 22. Large Dataset Stability
# ===========================================================================
print("\n[22] Large Dataset Stability")

# Build 100 reports with varied types and statuses
large_reports = []
types   = list(ReportTypeEnum)
statuses= list(ReportStatusEnum)
for i in range(100):
    rt = types[i % len(types)]
    st = statuses[i % len(statuses)]
    r  = build_report(
        title        = f"Large Report {i:03d}",
        report_type  = rt,
        created_at   = TS,
        status       = st,
        confidence   = float(i % 101),
        finding_ids  = [f"f-{i}", f"f-{i+1}"],
        validate     = False,
    )
    large_reports.append(r)

# Statistics over 100 reports
large_stats = build_report_statistics(large_reports)
_assert(large_stats.totalReports == 100, "large: 100 total reports")
_assert(large_stats.totalReports == (
    large_stats.draftReports + large_stats.readyReports +
    large_stats.publishedReports + large_stats.archivedReports),
    "large: status counts sum to total")

# Sort stability over large set
large_sorted = sort_reports(large_reports, by="confidence", ascending=True)
large_confs  = [r.confidence for r in large_sorted]
_assert(large_confs == sorted(large_confs), "large sort: confidence ASC correct")

# All 100 have unique IDs
large_ids = [r.reportId for r in large_reports]
_assert(len(set(large_ids)) == 100, "large: all 100 reportIds unique")

# Merge large set with itself → no duplicates
large_merged = merge_reports(large_reports, large_reports)
_assert(len(large_merged) == 100, "large merge: dedup maintains 100")

# Filter over large set
f_large = filter_reports(large_reports, min_confidence=50.0)
_assert(all(r.confidence >= 50.0 for r in f_large), "large filter: all >= 50 confidence")

# Group over large set
g_large = group_reports(large_reports, group_by="reportType")
total_grouped = sum(len(v) for v in g_large.values())
_assert(total_grouped == 100, "large group: all 100 in groups")

# Statistics order-independence over large set
import random
shuffled = list(large_reports)
# Shuffle via sort with deterministic key to avoid random
shuffled_alt = sorted(large_reports, key=lambda r: r.title, reverse=True)
ls1 = build_report_statistics(large_reports)
ls2 = build_report_statistics(shuffled_alt)
_assert(ls1.totalReports      == ls2.totalReports,      "large stats: order-independent total")
_assert(ls1.averageConfidence == ls2.averageConfidence, "large stats: order-independent avgConf")
_assert(ls1.reportTypeCounts  == ls2.reportTypeCounts,  "large stats: order-independent typeCounts")
_assert(ls1.statusCounts      == ls2.statusCounts,      "large stats: order-independent statusCounts")

# ===========================================================================
# 23. Additional Validators & Builder Edge Cases
# ===========================================================================
print("\n[23] Additional Validators & Builder Edge Cases")

# validate_report_section — multiple errors reported at once
try:
    validate_report_section(0, "", "")
    _assert(False, "multiple section errors should raise")
except InvalidReportSectionError as e:
    msg = str(e)
    _assert("order" in msg.lower() or "0" in msg, "multi-error: order mentioned")
    _assert("title" in msg.lower(),               "multi-error: title mentioned")
    _assert("created" in msg.lower(),             "multi-error: createdAt mentioned")

# validate_report — multiple errors
try:
    validate_report("", "BAD", "WORSE", "")
    _assert(False, "multiple report errors should raise")
except InvalidReportError as e:
    msg = str(e)
    _assert("title" in msg.lower(), "report multi-error: title mentioned")

# validate_report_mapping — multiple errors
try:
    validate_report_mapping("", "", "", -5.0, "")
    _assert(False, "multiple mapping errors should raise")
except InvalidReportMappingError as e:
    msg = str(e)
    _assert("source" in msg.lower() or "finding" in msg.lower(), "mapping multi-error: source mentioned")
    _assert("confidence" in msg.lower(),  "mapping multi-error: confidence mentioned")
    _assert("created" in msg.lower(),     "mapping multi-error: createdAt mentioned")

# validate=False skips validation on mappings (no source IDs is normally invalid)
m_no_val = build_report_mapping([], TS, validate=False)
_assert(m_no_val.mappingId is not None, "build_mapping validate=False: still builds")

# build_report_mapping — whitespace in source IDs stripped
m_ws = build_report_mapping([report1], TS, finding_id="  f-spaced  ", confidence=50.0)
_assert(m_ws.findingId == "f-spaced", "build_mapping: findingId whitespace stripped")

# build_report_section — validate=False with order=0 doesn't raise
sec_invalid = build_report_section("rid", 0, "Bad Order", TS, validate=False)
_assert(sec_invalid.order == 0, "build_section validate=False order=0 allowed")

# build_report confidence precision preserved to 4 decimal places
r_prec = build_report("Prec", ReportTypeEnum.SOC, TS, confidence=73.14159)
_assert(r_prec.confidence == round(73.14159, 4), "confidence rounded to 4 dp")

# build_report_mapping confidence precision
m_prec = build_report_mapping([report1], TS, finding_id="f1", confidence=62.5678)
_assert(m_prec.confidence == round(62.5678, 4), "mapping confidence rounded to 4 dp")

# All 7 report types can be used as group keys
for rt in ReportTypeEnum:
    r_each = build_report(f"Type {rt.value}", rt, TS, validate=False)
    grp = group_reports([r_each], group_by="reportType")
    _assert(rt.value in grp, f"group by reportType: {rt.value} key present")

# All 4 statuses can be filtered individually
for st in ReportStatusEnum:
    r_each = build_report(f"Status {st.value}", ReportTypeEnum.SOC, TS, status=st, validate=False)
    filtered = filter_reports([r_each], status=st)
    _assert(len(filtered) == 1, f"filter status {st.value}: 1 result")

# sectionKey cross-field collision check: order 12 + title "3" vs order 1 + title "23"
sk_a = sectionKey("r", 12, "3")
sk_b = sectionKey("r", 1, "23")
_assert(sk_a != sk_b, "sectionKey cross-field collision prevented by null-byte separation")

# reportKey cross-field collision check: different title/type combos
rk_coll_a = reportKey("A", ReportTypeEnum.SOC, ())
rk_coll_b = reportKey("", ReportTypeEnum.SOC, ())
_assert(rk_coll_a != rk_coll_b, "reportKey: empty vs non-empty title differ")

# mappingKey: only reasoningId present
mk_r_only = mappingKey("", "", "reasoning-only", ("r1",))
mk_f_only = mappingKey("finding-only", "", "", ("r1",))
_assert(mk_r_only != mk_f_only, "mappingKey: reasoningId-only vs findingId-only differ")

# Validate boundary — confidence = 50.5 (non-integer, valid)
try:
    validate_report_mapping("f1", "", "", 50.5, TS)
    _assert(True, "confidence 50.5 float accepted")
except Exception:
    _assert(False, "confidence 50.5 should be accepted")

# Integer confidence also valid
try:
    validate_report_mapping("f1", "", "", 75, TS)
    _assert(True, "integer confidence 75 accepted")
except Exception:
    _assert(False, "integer confidence 75 should be accepted")


# ===========================================================================
# 24. Section Operations — More Edge Cases
# ===========================================================================
print("\n[24] Section Operations — More Edge Cases")

# Add 5 sections one by one in reverse order → always sorted by order
r_build_up = build_report("Build Up", ReportTypeEnum.TECHNICAL, TS)
sections_to_add = [sec5, sec3, sec1, sec4, sec2]  # intentionally out of order
for s in sections_to_add:
    r_build_up = add_report_section(r_build_up, s)
_assert(len(r_build_up.sections) == 5, "build up: 5 sections added")
orders_added = [s.order for s in r_build_up.sections]
_assert(orders_added == sorted(orders_added), "build up: always sorted by order")

# Remove all sections one by one
r_shrink = r_build_up
for s in [sec1, sec2, sec3, sec4, sec5]:
    r_shrink = remove_report_section(r_shrink, s.sectionId)
_assert(len(r_shrink.sections) == 0, "remove all: 0 sections remain")
_assert(r_shrink.reportId == r_build_up.reportId, "remove all: reportId preserved")

# merge_report_sections with empty incoming
r_no_new = merge_report_sections(r_base, [])
_assert(r_no_new.reportId == r_base.reportId,           "merge_sections empty incoming: reportId preserved")
_assert(len(r_no_new.sections) == len(r_base.sections), "merge_sections empty incoming: sections unchanged")

# merge_report_sections — all incoming already present (idempotent)
r_all_present = merge_report_sections(r_base, list(r_base.sections))
_assert(len(r_all_present.sections) == len(r_base.sections), "merge_sections all present: idempotent")

# update_report_section — changing only content
sec_cu = update_report_section(r_3secs, sec2.sectionId, content="Brand new content")
found_cu = next(s for s in sec_cu.sections if s.sectionId == sec2.sectionId)
_assert(found_cu.content == "Brand new content", "update_section content only: content changed")
_assert(found_cu.title   == sec2.title,          "update_section content only: title preserved")
_assert(found_cu.order   == sec2.order,          "update_section content only: order preserved")

# update_report_section — changing only order
sec_ou = update_report_section(r_3secs, sec2.sectionId, order=20)
found_ou = next(s for s in sec_ou.sections if s.sectionId == sec2.sectionId)
_assert(found_ou.order == 20,          "update_section order only: order changed")
_assert(found_ou.title == sec2.title,  "update_section order only: title preserved")

# sectionKey and sectionId stable through update
_assert(found_ou.sectionKey == sec2.sectionKey, "update_section: sectionKey stable")
_assert(found_ou.sectionId  == sec2.sectionId,  "update_section: sectionId stable")

# Adding a section doesn't change the report's key/id (sections don't affect reportKey)
r_before_add = build_report("Stable ID", ReportTypeEnum.SOC, TS, finding_ids=["f1"])
r_after_add  = add_report_section(r_before_add, sec1)
_assert(r_after_add.reportKey == r_before_add.reportKey, "add_section: reportKey unchanged")
_assert(r_after_add.reportId  == r_before_add.reportId,  "add_section: reportId unchanged")

# Section count tracked correctly after multiple adds/removes
r_tracking = build_report("Tracking", ReportTypeEnum.IOC, TS)
r_tracking = add_report_section(r_tracking, sec1)
r_tracking = add_report_section(r_tracking, sec2)
r_tracking = add_report_section(r_tracking, sec3)
_assert(len(r_tracking.sections) == 3, "tracking: 3 sections after 3 adds")
r_tracking = remove_report_section(r_tracking, sec2.sectionId)
_assert(len(r_tracking.sections) == 2, "tracking: 2 sections after 1 remove")
r_tracking = add_report_section(r_tracking, sec4)
_assert(len(r_tracking.sections) == 3, "tracking: 3 sections after re-add")
_assert(all(s.sectionId != sec2.sectionId for s in r_tracking.sections), "tracking: removed section gone")


# ===========================================================================
# 25. Mapping Operations — More Edge Cases
# ===========================================================================
print("\n[25] Mapping Operations — More Edge Cases")

# Add 5 mappings, all unique
m5_list: list = []
for m in [mapping1, mapping2, mapping3, mapping4, mapping5]:
    m5_list = add_report_mapping(m5_list, m)
_assert(len(m5_list) == 5, "add 5 mappings: 5 distinct")
m5_ids = [m.mappingId for m in m5_list]
_assert(m5_ids == sorted(m5_ids), "5 mappings: sorted by mappingId")

# Remove all one by one
shrink_m = list(m5_list)
for m in [mapping1, mapping2, mapping3, mapping4, mapping5]:
    shrink_m = remove_report_mapping(shrink_m, m.mappingId)
_assert(len(shrink_m) == 0, "remove all mappings: 0 remain")

# merge empty base + non-empty incoming
merged_eb = merge_report_mappings([], [mapping1, mapping2])
_assert(len(merged_eb) == 2, "merge_mappings empty base: both incoming added")
eb_ids = [m.mappingId for m in merged_eb]
_assert(eb_ids == sorted(eb_ids), "merge_mappings empty base: sorted")

# merge non-empty base + empty incoming
merged_ei = merge_report_mappings([mapping1, mapping2], [])
_assert(len(merged_ei) == 2, "merge_mappings empty incoming: base unchanged")

# Fingerprint preserved through merge
base_fp = mapping1.mappingFingerprint
after_m = merge_report_mappings([mapping1], [mapping2])
m_preserved = next(m for m in after_m if m.mappingId == mapping1.mappingId)
_assert(m_preserved.mappingFingerprint == base_fp, "merge_mappings: fingerprint preserved from base")

# mappingKey preserved through merge
_assert(m_preserved.mappingKey == mapping1.mappingKey, "merge_mappings: mappingKey preserved")

# remove non-existent mapping — list unchanged
m_before = list(m5_list)  # already empty, rebuild
m_before = add_report_mapping([], mapping1)
m_after  = remove_report_mapping(m_before, "does-not-exist")
_assert(len(m_after) == 1, "remove non-existent: list unchanged")

# Duplicate add after remove — can add again after removal
m_cycle = add_report_mapping([], mapping1)
m_cycle = remove_report_mapping(m_cycle, mapping1.mappingId)
m_cycle = add_report_mapping(m_cycle, mapping1)
_assert(len(m_cycle) == 1,                          "add-remove-add cycle: 1 mapping")
_assert(m_cycle[0].mappingId == mapping1.mappingId, "add-remove-add cycle: correct mapping")


# ===========================================================================
# 26. Report Operations — More Scenarios
# ===========================================================================
print("\n[26] Report Operations — More Scenarios")

# update_report — identity fields change (title) → new reportId/Key
rlist_id_test = [report_default]
updated_id = update_report(rlist_id_test, report_default.reportId, title="Brand New Title")
new_r = updated_id[0]
_assert(new_r.title    == "Brand New Title",            "update title: title updated")
_assert(new_r.reportKey != report_default.reportKey,    "update title: reportKey changed")
_assert(new_r.reportId  != report_default.reportId,     "update title: reportId changed")

# update_report — only status change → same reportKey/reportId
rlist_status = [report_default]
upd_status = update_report(rlist_status, report_default.reportId, status=ReportStatusEnum.PUBLISHED)
_assert(upd_status[0].status    == ReportStatusEnum.PUBLISHED, "update status only: status changed")
_assert(upd_status[0].reportKey == report_default.reportKey,   "update status only: reportKey unchanged")
_assert(upd_status[0].reportId  == report_default.reportId,    "update status only: reportId unchanged")

# update_report — description change preserves key/id
rlist_desc = [report_default]
upd_desc = update_report(rlist_desc, report_default.reportId, description="New desc")
_assert(upd_desc[0].description == "New desc",               "update description: description changed")
_assert(upd_desc[0].reportKey   == report_default.reportKey, "update description: reportKey unchanged")

# update_report — confidence clamped
rlist_conf = [report_default]
upd_conf = update_report(rlist_conf, report_default.reportId, confidence=999.0)
_assert(upd_conf[0].confidence == 100.0, "update confidence: clamped to 100.0")

# update_report — ioc_ids set
rlist_ioc = [report_default]
upd_ioc = update_report(rlist_ioc, report_default.reportId, ioc_ids=["ioc-a", "ioc-b", "ioc-a"])
_assert(upd_ioc[0].iocIds == ("ioc-a", "ioc-b"), "update ioc_ids: deduped+sorted")

# merge_reports — 3 separate merge calls, chained
batch1 = [report1, report_exec]
batch2 = [report_soc2, report_tech]
batch3 = [report_forensic, report_ioc]
full_merge = merge_reports(merge_reports(batch1, batch2), batch3)
_assert(len(full_merge) == 6,                            "chained merge: 6 distinct reports")
full_ids = [r.reportId for r in full_merge]
_assert(full_ids == sorted(full_ids),                    "chained merge: sorted by reportId")

# Re-merging same data is idempotent
full_merge2 = merge_reports(full_merge, batch1)
_assert(len(full_merge2) == 6,                           "chained merge re-merge: still 6")

# add_report — result sorted after add
r_new = build_report("ZZZ Last Title", ReportTypeEnum.SUMMARY, TS)
r_first = build_report("AAA First Title", ReportTypeEnum.SUMMARY, TS)
rlist_sort = add_report([], r_new)
rlist_sort = add_report(rlist_sort, r_first)
sort_ids = [r.reportId for r in rlist_sort]
_assert(sort_ids == sorted(sort_ids), "add: list always sorted by reportId ASC")

# remove from single-item list
rlist_single = add_report([], report1)
rlist_empty  = remove_report(rlist_single, report1.reportId)
_assert(rlist_empty == [], "remove last item: empty list")

# update multiple reports in sequence
rlist_multi = [report1, report_exec, report_soc2]
rlist_multi = update_report(rlist_multi, report1.reportId,   description="Updated 1")
rlist_multi = update_report(rlist_multi, report_exec.reportId, description="Updated 2")
d1 = next(r for r in rlist_multi if r.reportId == report1.reportId).description
d2 = next(r for r in rlist_multi if r.reportId == report_exec.reportId).description
_assert(d1 == "Updated 1", "sequential update: report1 description")
_assert(d2 == "Updated 2", "sequential update: report_exec description")


# ===========================================================================
# 27. Statistics — Final Comprehensive
# ===========================================================================
print("\n[27] Statistics — Final Comprehensive")

# Single report statistics
stats_single = build_report_statistics([report_exec])
_assert(stats_single.totalReports     == 1,    "single: total 1")
_assert(stats_single.readyReports     == 1,    "single: ready 1")
_assert(stats_single.draftReports     == 0,    "single: draft 0")
_assert(stats_single.publishedReports == 0,    "single: published 0")
_assert(stats_single.archivedReports  == 0,    "single: archived 0")
_assert(stats_single.averageConfidence== 90.0, "single: avgConf 90.0")
_assert(stats_single.averageSections  == 0.0,  "single no sections: avgSections 0.0")
_assert("EXECUTIVE" in stats_single.reportTypeCounts, "single: EXECUTIVE in typeCounts")
_assert(stats_single.reportTypeCounts["EXECUTIVE"] == 1, "single: EXECUTIVE count 1")
_assert("READY" in stats_single.statusCounts,           "single: READY in statusCounts")
_assert(stats_single.statusCounts["READY"] == 1,        "single: READY count 1")

# Two reports same type and status
r_d1 = build_report("D1", ReportTypeEnum.SOC, TS, status=ReportStatusEnum.DRAFT, confidence=20.0)
r_d2 = build_report("D2", ReportTypeEnum.SOC, TS, status=ReportStatusEnum.DRAFT, confidence=40.0)
stats_two = build_report_statistics([r_d1, r_d2])
_assert(stats_two.totalReports  == 2,    "two: total 2")
_assert(stats_two.draftReports  == 2,    "two: draft 2")
_assert(stats_two.readyReports  == 0,    "two: ready 0")
_assert(stats_two.averageConfidence == 30.0, "two: avgConf (20+40)/2=30")
_assert(stats_two.reportTypeCounts.get("SOC") == 2,  "two same type: SOC count 2")
_assert("SUMMARY" not in stats_two.reportTypeCounts, "zero-count type not in typeCounts")
_assert("PUBLISHED" not in stats_two.statusCounts,   "zero-count status not in statusCounts")

# Duplicate reports — only counted once
stats_dup = build_report_statistics([report_exec, report_exec, report_exec])
_assert(stats_dup.totalReports == 1, "dup dedup: total 1")
_assert(stats_dup.readyReports == 1, "dup dedup: ready 1")
_assert(stats_dup.averageConfidence == report_exec.confidence, "dup dedup: correct avgConf")

# statusCounts and typeCounts sum to total
all6_stats = build_report_statistics(all_reports)
total_from_status = sum(all6_stats.statusCounts.values())
total_from_type   = sum(all6_stats.reportTypeCounts.values())
_assert(total_from_status == all6_stats.totalReports, "stats: statusCounts sums to total")
_assert(total_from_type   == all6_stats.totalReports, "stats: typeCounts sums to total")

# averageSections with all 5 sections
r_all5 = build_report("All5", ReportTypeEnum.SUMMARY, TS, sections=[sec1, sec2, sec3, sec4, sec5])
stats_a5 = build_report_statistics([r_all5])
_assert(stats_a5.averageSections == 5.0, "avgSections with 5 sections: 5.0")

# averageSections mixed: 5 sections + 0 sections
stats_mixed = build_report_statistics([r_all5, report_default])
_assert(stats_mixed.averageSections == round((5 + 0) / 2, 4), "avgSections mixed: (5+0)/2=2.5")

# Statistics frozen
_assert_raises(Exception, setattr, stats_single, "totalReports", 99, msg="stats frozen: totalReports")
_assert_raises(Exception, setattr, stats_single, "draftReports", 99, msg="stats frozen: draftReports")

# Confidence exactly 0.0 and 100.0 edge cases in statistics
r_c0   = build_report("C0",   ReportTypeEnum.IOC, TS, confidence=0.0)
r_c100 = build_report("C100", ReportTypeEnum.IOC, TS, confidence=100.0)
stats_bounds = build_report_statistics([r_c0, r_c100])
_assert(stats_bounds.averageConfidence == 50.0, "stats bounds: avgConf (0+100)/2=50.0")
_assert(stats_bounds.totalReports == 2,         "stats bounds: total 2")

# Order-independence for all stats fields
shuffled_reports = sorted(all_reports, key=lambda r: r.title, reverse=True)
stats_fwd = build_report_statistics(all_reports)
stats_rev2 = build_report_statistics(shuffled_reports)
_assert(stats_fwd.draftReports     == stats_rev2.draftReports,     "order-independent: draftReports")
_assert(stats_fwd.readyReports     == stats_rev2.readyReports,     "order-independent: readyReports")
_assert(stats_fwd.publishedReports == stats_rev2.publishedReports, "order-independent: publishedReports")
_assert(stats_fwd.archivedReports  == stats_rev2.archivedReports,  "order-independent: archivedReports")
_assert(stats_fwd.averageSections  == stats_rev2.averageSections,  "order-independent: averageSections")
_assert(stats_fwd.reportTypeCounts == stats_rev2.reportTypeCounts, "order-independent: typeCounts")
_assert(stats_fwd.statusCounts     == stats_rev2.statusCounts,     "order-independent: statusCounts")


# ===========================================================================
# 28. Final Coverage Top-Up
# ===========================================================================
print("\n[28] Final Coverage Top-Up")

# sectionKey uses all three parts for uniqueness
sk_x = sectionKey("", 1, "title")
sk_y = sectionKey("rid", 1, "title")
_assert(sk_x != sk_y, "sectionKey: empty vs non-empty reportId differ")

# find_report — no criteria returns None
_assert(find_report([report1]) is None, "find_report: no criteria returns None")

# find_report_section — no criteria returns None
r_sec_s = build_report("S", ReportTypeEnum.SOC, TS, sections=[sec1])
_assert(find_report_section(r_sec_s) is None, "find_report_section: no criteria returns None")

# sort_reports single item
single_sorted = sort_reports([report1], by="title")
_assert(len(single_sorted) == 1, "sort single item: 1 item returned")
_assert(single_sorted[0].reportId == report1.reportId, "sort single: correct item")

# filter_reports confidence exact boundaries
r_exact50 = build_report("E50", ReportTypeEnum.SOC, TS, confidence=50.0, validate=False)
f_min50 = filter_reports([r_exact50], min_confidence=50.0)
_assert(len(f_min50) == 1, "filter min_confidence exact boundary: included")
f_max50 = filter_reports([r_exact50], max_confidence=50.0)
_assert(len(f_max50) == 1, "filter max_confidence exact boundary: included")

# group_reports result values are sorted lists not tuples
by_type_list = group_reports([report1], group_by="reportType")
val = list(by_type_list.values())[0]
_assert(isinstance(val, list), "group_reports values are lists")

# Statistics: reportTypeCounts is a plain dict (serialisable)
_assert(isinstance(stats.reportTypeCounts, dict), "reportTypeCounts is dict")
_assert(isinstance(stats.statusCounts, dict),     "statusCounts is dict")

# ===========================================================================
# Final summary
# ===========================================================================
print()
print("=" * 60)
print(f"PASSED : {_PASS}")
print(f"FAILED : {_FAIL}")
print("=" * 60)

if _ERRORS:
    print("\nFailed assertions:")
    for e in _ERRORS:
        print(f"  {e}")

if _FAIL > 0:
    sys.exit(1)
else:
    print("\nALL ASSERTIONS PASSED ✓")
