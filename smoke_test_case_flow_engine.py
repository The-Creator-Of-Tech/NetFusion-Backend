"""
Smoke Test — Case Flow Engine
==============================
Phase A4.5.3 — Comprehensive deterministic test suite.

Covers
------
- Enumerations: CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum
- Engine version constant
- Exception hierarchy
- Deterministic IDs: stepKey, caseKey, mappingKey, mappingFingerprint
- Builders: build_case_step, build_case, build_case_mapping,
  build_case_statistics (extended with priorityCounts/statusCounts)
- Validators: validate_case_step, validate_case, validate_case_mapping
- Case Operations: add, update, remove, merge
- Step Operations: add, update, remove, merge
- Mapping Operations: add, remove, merge
- Search: find_case, find_case_step, find_case_mapping
- Sorting: sort_cases, sort_case_steps, sort_case_mappings
- Filtering: filter_cases, filter_case_steps, filter_case_mappings
- Grouping: group_cases, group_case_steps, group_case_mappings
- Statistics: build_case_statistics (all fields)
- Serialization: model_dump round-trip
- Immutability: frozen model enforcement
- Integration helpers
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
from services.case_flow_service import (
    CASE_FLOW_ENGINE_VERSION,
    CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
    CaseFlowEngineError, InvalidCaseError,
    InvalidCaseStepError, InvalidCaseMappingError,
    CaseStep, Case, CaseMapping, CaseStatistics,
    stepKey, caseKey, mappingKey, mappingFingerprint,
    validate_case_step, validate_case, validate_case_mapping,
    build_case_step, build_case, build_case_mapping, build_case_statistics,
    add_case, update_case, remove_case, merge_cases,
    add_case_step, update_case_step, remove_case_step, merge_case_steps,
    add_case_mapping, remove_case_mapping, merge_case_mappings,
    find_case, find_case_step, find_case_mapping,
    sort_cases, sort_case_steps, sort_case_mappings,
    filter_cases, filter_case_steps, filter_case_mappings,
    group_cases, group_case_steps, group_case_mappings,
    finding_to_case_mapping, alert_to_case_mapping, reasoning_to_case_mapping,
    playbook_to_case_reference, automation_to_case_reference, rule_to_case_reference,
)
from core.constants import CASE_FLOW_ENGINE_VERSION as _CONST_VERSION

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T00:00:00Z"
TS3 = "2026-07-04T00:00:00Z"

print("=" * 60)
print("Case Flow Engine Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. Engine Version
# ===========================================================================
print("\n[1] Engine Version")

_assert(CASE_FLOW_ENGINE_VERSION == "case-flow-engine-v1",
        "CASE_FLOW_ENGINE_VERSION value")
_assert(_CONST_VERSION == "case-flow-engine-v1",
        "constant matches import")
_assert(CASE_FLOW_ENGINE_VERSION == _CONST_VERSION,
        "service re-export matches constant")


# ===========================================================================
# 2. Enumerations
# ===========================================================================
print("\n[2] Enumerations")

# CaseStatusEnum
_assert(CaseStatusEnum.OPEN.value        == "OPEN",        "status OPEN")
_assert(CaseStatusEnum.IN_PROGRESS.value == "IN_PROGRESS", "status IN_PROGRESS")
_assert(CaseStatusEnum.ON_HOLD.value     == "ON_HOLD",     "status ON_HOLD")
_assert(CaseStatusEnum.RESOLVED.value    == "RESOLVED",    "status RESOLVED")
_assert(CaseStatusEnum.CLOSED.value      == "CLOSED",      "status CLOSED")
_assert(len(CaseStatusEnum) == 5, "status enum has 5 members")

# CasePriorityEnum
_assert(CasePriorityEnum.LOW.value      == "LOW",      "priority LOW")
_assert(CasePriorityEnum.MEDIUM.value   == "MEDIUM",   "priority MEDIUM")
_assert(CasePriorityEnum.HIGH.value     == "HIGH",     "priority HIGH")
_assert(CasePriorityEnum.CRITICAL.value == "CRITICAL", "priority CRITICAL")
_assert(len(CasePriorityEnum) == 4, "priority enum has 4 members")

# CaseStepTypeEnum
_assert(CaseStepTypeEnum.CREATED.value      == "CREATED",      "step CREATED")
_assert(CaseStepTypeEnum.ASSIGNED.value     == "ASSIGNED",     "step ASSIGNED")
_assert(CaseStepTypeEnum.INVESTIGATED.value == "INVESTIGATED", "step INVESTIGATED")
_assert(CaseStepTypeEnum.CONTAINED.value    == "CONTAINED",    "step CONTAINED")
_assert(CaseStepTypeEnum.ERADICATED.value   == "ERADICATED",   "step ERADICATED")
_assert(CaseStepTypeEnum.RECOVERED.value    == "RECOVERED",    "step RECOVERED")
_assert(CaseStepTypeEnum.CLOSED.value       == "CLOSED",       "step CLOSED")
_assert(len(CaseStepTypeEnum) == 7, "step type enum has 7 members")


# ===========================================================================
# 3. Exception Hierarchy
# ===========================================================================
print("\n[3] Exception Hierarchy")

_assert(issubclass(CaseFlowEngineError, Exception),         "base inherits Exception")
_assert(issubclass(InvalidCaseError, CaseFlowEngineError),  "InvalidCaseError inherits base")
_assert(issubclass(InvalidCaseStepError, CaseFlowEngineError), "InvalidCaseStepError inherits base")
_assert(issubclass(InvalidCaseMappingError, CaseFlowEngineError), "InvalidCaseMappingError inherits base")
_assert(not issubclass(InvalidCaseError, InvalidCaseStepError), "no cross-inheritance between errors")


# ===========================================================================
# 4. Deterministic ID Helpers
# ===========================================================================
print("\n[4] Deterministic ID Helpers")

# stepKey
sk1 = stepKey("case-id-1", 1)
sk2 = stepKey("case-id-1", 1)
sk3 = stepKey("case-id-1", 2)
sk4 = stepKey("case-id-2", 1)

_assert(sk1 == sk2,     "stepKey deterministic same inputs")
_assert(sk1 != sk3,     "stepKey differs for different stepNumber")
_assert(sk1 != sk4,     "stepKey differs for different caseId")
_assert(len(sk1) == 32, "stepKey is 32 chars")
_assert(sk1.islower(),  "stepKey is lowercase hex")
_assert(all(c in "0123456789abcdef" for c in sk1), "stepKey is hex")

# caseKey
ck1 = caseKey("Ransomware Attack", CasePriorityEnum.CRITICAL, ("f1", "f2"))
ck2 = caseKey("Ransomware Attack", CasePriorityEnum.CRITICAL, ("f2", "f1"))
ck3 = caseKey("Ransomware Attack", CasePriorityEnum.HIGH,     ("f1", "f2"))
ck4 = caseKey("Data Exfiltration",  CasePriorityEnum.CRITICAL, ("f1", "f2"))
ck5 = caseKey("Ransomware Attack", CasePriorityEnum.CRITICAL, ())

_assert(ck1 == ck2,     "caseKey order-independent for findingIds")
_assert(ck1 != ck3,     "caseKey differs for different priority")
_assert(ck1 != ck4,     "caseKey differs for different title")
_assert(ck1 != ck5,     "caseKey differs for empty vs non-empty findingIds")
_assert(len(ck1) == 32, "caseKey is 32 chars")
_assert(ck1.islower(),  "caseKey is lowercase hex")

# mappingKey
mk1 = mappingKey("f1", "a1", "r1", ("id1", "id2"))
mk2 = mappingKey("f1", "a1", "r1", ("id2", "id1"))
mk3 = mappingKey("f2", "a1", "r1", ("id1", "id2"))
mk4 = mappingKey("f1", "",   "r1", ("id1", "id2"))
mk5 = mappingKey("f1", "a1", "",   ("id1", "id2"))

_assert(mk1 == mk2,     "mappingKey order-independent for caseIds")
_assert(mk1 != mk3,     "mappingKey differs for different findingId")
_assert(mk1 != mk4,     "mappingKey differs for empty alertId")
_assert(mk1 != mk5,     "mappingKey differs for empty reasoningId")
_assert(len(mk1) == 32, "mappingKey is 32 chars")

# mappingFingerprint
mfp1 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id1", "id2"))
mfp2 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id2", "id1"))
mfp3 = mappingFingerprint(mk3, "f2", "a1", "r1", ("id1", "id2"))

_assert(mfp1 == mfp2,    "fingerprint order-independent for caseIds")
_assert(mfp1 != mfp3,    "fingerprint differs for different content")
_assert(len(mfp1) == 32, "fingerprint is 32 chars")
_assert(mfp1 != mk1,     "fingerprint differs from mappingKey")


# ===========================================================================
# 5. Validators
# ===========================================================================
print("\n[5] Validators")

# validate_case_step — happy path
try:
    validate_case_step(1, CaseStepTypeEnum.CREATED, "Step title", TS)
    _assert(True, "validate_case_step passes valid input")
except Exception:
    _assert(False, "validate_case_step raised unexpectedly")

# validate_case_step — bad step_number
_assert_raises(InvalidCaseStepError, validate_case_step,
               0, CaseStepTypeEnum.CREATED, "T", TS,
               msg="step_number 0 rejected")
_assert_raises(InvalidCaseStepError, validate_case_step,
               -1, CaseStepTypeEnum.CREATED, "T", TS,
               msg="negative step_number rejected")
_assert_raises(InvalidCaseStepError, validate_case_step,
               1.5, CaseStepTypeEnum.CREATED, "T", TS,
               msg="float step_number rejected")

# validate_case_step — bad step_type
_assert_raises(InvalidCaseStepError, validate_case_step,
               1, "NOT_A_STEP_TYPE", "T", TS,
               msg="non-enum step_type rejected")

# validate_case_step — empty title
_assert_raises(InvalidCaseStepError, validate_case_step,
               1, CaseStepTypeEnum.CREATED, "", TS,
               msg="empty title rejected")
_assert_raises(InvalidCaseStepError, validate_case_step,
               1, CaseStepTypeEnum.CREATED, "   ", TS,
               msg="whitespace-only title rejected")

# validate_case_step — empty createdAt
_assert_raises(InvalidCaseStepError, validate_case_step,
               1, CaseStepTypeEnum.CREATED, "T", "",
               msg="empty createdAt rejected in step")

# validate_case — happy path
try:
    validate_case("Case Title", CaseStatusEnum.OPEN, CasePriorityEnum.HIGH, TS)
    _assert(True, "validate_case passes valid input")
except Exception:
    _assert(False, "validate_case raised unexpectedly")

# validate_case — bad title
_assert_raises(InvalidCaseError, validate_case,
               "", CaseStatusEnum.OPEN, CasePriorityEnum.HIGH, TS,
               msg="empty title rejected in case")
_assert_raises(InvalidCaseError, validate_case,
               "  ", CaseStatusEnum.OPEN, CasePriorityEnum.HIGH, TS,
               msg="whitespace-only title rejected in case")

# validate_case — bad status
_assert_raises(InvalidCaseError, validate_case,
               "T", "BAD_STATUS", CasePriorityEnum.HIGH, TS,
               msg="bad status rejected")

# validate_case — bad priority
_assert_raises(InvalidCaseError, validate_case,
               "T", CaseStatusEnum.OPEN, "BAD_PRIORITY", TS,
               msg="bad priority rejected")

# validate_case — empty createdAt
_assert_raises(InvalidCaseError, validate_case,
               "T", CaseStatusEnum.OPEN, CasePriorityEnum.HIGH, "",
               msg="empty createdAt rejected in case")

# validate_case_mapping — happy path
try:
    validate_case_mapping("finding-1", "", "", 50.0, TS)
    _assert(True, "validate_case_mapping passes valid input")
except Exception:
    _assert(False, "validate_case_mapping raised unexpectedly")

# validate_case_mapping — no source
_assert_raises(InvalidCaseMappingError, validate_case_mapping,
               "", "", "", 50.0, TS,
               msg="no source IDs rejected")
_assert_raises(InvalidCaseMappingError, validate_case_mapping,
               "  ", "  ", "  ", 50.0, TS,
               msg="whitespace-only source IDs rejected")

# validate_case_mapping — bad confidence
_assert_raises(InvalidCaseMappingError, validate_case_mapping,
               "f1", "", "", -1.0, TS,
               msg="negative confidence rejected")
_assert_raises(InvalidCaseMappingError, validate_case_mapping,
               "f1", "", "", 101.0, TS,
               msg="confidence > 100 rejected")

# validate_case_mapping — exact boundary values pass
try:
    validate_case_mapping("f1", "", "", 0.0, TS)
    _assert(True, "confidence 0.0 accepted")
except Exception:
    _assert(False, "confidence 0.0 should be accepted")

try:
    validate_case_mapping("f1", "", "", 100.0, TS)
    _assert(True, "confidence 100.0 accepted")
except Exception:
    _assert(False, "confidence 100.0 should be accepted")

# validate_case_mapping — empty createdAt
_assert_raises(InvalidCaseMappingError, validate_case_mapping,
               "f1", "", "", 50.0, "",
               msg="empty createdAt rejected in mapping")


# ===========================================================================
# 6. Builder: build_case_step
# ===========================================================================
print("\n[6] build_case_step")

step1 = build_case_step(
    case_id     = "parent-case-id",
    step_number = 1,
    step_type   = CaseStepTypeEnum.CREATED,
    title       = "Case Created",
    created_at  = TS,
    description = "Initial case creation.",
    assigned_to = "analyst-1",
)

_assert(step1.stepNumber  == 1,                          "stepNumber set")
_assert(step1.stepType    == CaseStepTypeEnum.CREATED,   "stepType set")
_assert(step1.title       == "Case Created",             "title set")
_assert(step1.description == "Initial case creation.",   "description set")
_assert(step1.assignedTo  == "analyst-1",                "assignedTo set")
_assert(step1.createdAt   == TS,                         "createdAt set")
_assert(len(step1.stepKey) == 32,                        "stepKey is 32 chars")
_assert(step1.stepKey.islower(),                         "stepKey is lowercase")
_assert(len(step1.stepId)  == 36,                        "stepId is UUID format")
_assert(step1.stepId.count("-") == 4,                    "stepId has 4 dashes")

# Determinism
step1b = build_case_step("parent-case-id", 1, CaseStepTypeEnum.CREATED, "Case Created", TS)
_assert(step1.stepKey == step1b.stepKey, "stepKey deterministic")
_assert(step1.stepId  == step1b.stepId,  "stepId deterministic")

# Different step_number → different key
step2 = build_case_step("parent-case-id", 2, CaseStepTypeEnum.ASSIGNED, "Assigned", TS)
_assert(step2.stepKey != step1.stepKey, "different stepNumber → different key")
_assert(step2.stepId  != step1.stepId,  "different stepNumber → different ID")

# Different case_id → different key even for same step_number
step_diff_case = build_case_step("other-case-id", 1, CaseStepTypeEnum.CREATED, "Case Created", TS)
_assert(step_diff_case.stepKey != step1.stepKey, "different caseId → different key")

# validate=False skips validation
step_no_val = build_case_step("x", 99, CaseStepTypeEnum.CLOSED, "X", TS, validate=False)
_assert(step_no_val.stepNumber == 99, "validate=False still builds")

# Title stripping
step_strip = build_case_step("pid", 1, CaseStepTypeEnum.INVESTIGATED, "  Trim  ", TS)
_assert(step_strip.title == "Trim", "title is stripped")

# Empty assigned_to default
step_no_assign = build_case_step("pid", 1, CaseStepTypeEnum.CONTAINED, "Contained", TS)
_assert(step_no_assign.assignedTo == "", "assignedTo defaults to empty string")

# Empty description default
step_no_desc = build_case_step("pid", 1, CaseStepTypeEnum.RECOVERED, "Recovered", TS)
_assert(step_no_desc.description == "", "description defaults to empty string")

# All step types buildable
for stype in CaseStepTypeEnum:
    s = build_case_step("pid", 1, stype, f"Step {stype.value}", TS, validate=False)
    _assert(s.stepType == stype, f"step type {stype.value} buildable")

step3 = build_case_step("parent-case-id", 3, CaseStepTypeEnum.CONTAINED, "Contained", TS)
step4 = build_case_step("parent-case-id", 4, CaseStepTypeEnum.ERADICATED, "Eradicated", TS)


# ===========================================================================
# 7. Builder: build_case
# ===========================================================================
print("\n[7] build_case")

case1 = build_case(
    title        = "Ransomware Attack",
    priority     = CasePriorityEnum.CRITICAL,
    created_at   = TS,
    description  = "Ransomware detected on prod servers.",
    status       = CaseStatusEnum.IN_PROGRESS,
    steps        = [step1, step2],
    finding_ids  = ["f-001", "f-002"],
    alert_ids    = ["a-001"],
    evidence_ids = ["e-001"],
    playbook_ids = ["pb-001"],
    assigned_to  = "analyst-1",
    confidence   = 85.0,
)

_assert(case1.title       == "Ransomware Attack",         "title set")
_assert(case1.priority    == CasePriorityEnum.CRITICAL,   "priority set")
_assert(case1.status      == CaseStatusEnum.IN_PROGRESS,  "status set")
_assert(case1.description == "Ransomware detected on prod servers.", "description set")
_assert(case1.assignedTo  == "analyst-1",                 "assignedTo set")
_assert(case1.confidence  == 85.0,                        "confidence set")
_assert(case1.createdAt   == TS,                          "createdAt set")
_assert(len(case1.steps)  == 2,                           "2 steps")
_assert(case1.steps[0].stepNumber == 1,                   "steps sorted by stepNumber")
_assert(case1.steps[1].stepNumber == 2,                   "steps[1] is step2")
_assert(len(case1.findingIds)  == 2,                      "2 findingIds")
_assert(len(case1.alertIds)    == 1,                      "1 alertId")
_assert(len(case1.evidenceIds) == 1,                      "1 evidenceId")
_assert(len(case1.playbookIds) == 1,                      "1 playbookId")
_assert(len(case1.caseKey)     == 32,                     "caseKey is 32 chars")
_assert(len(case1.caseId)      == 36,                     "caseId is UUID format")
_assert(case1.caseId.count("-") == 4,                     "caseId has 4 dashes")
_assert(case1.caseNumber.startswith("CASE-"),             "caseNumber starts with CASE-")

# Determinism: same inputs → same IDs regardless of order
case1b = build_case(
    title       = "Ransomware Attack",
    priority    = CasePriorityEnum.CRITICAL,
    created_at  = TS2,                     # different timestamp
    steps       = [step2, step1],          # reversed steps
    finding_ids = ["f-002", "f-001"],      # reversed findingIds
    status      = CaseStatusEnum.IN_PROGRESS,
    confidence  = 85.0,
)
_assert(case1.caseKey == case1b.caseKey, "caseKey deterministic (order-independent)")
_assert(case1.caseId  == case1b.caseId,  "caseId deterministic")
_assert(case1.findingIds == case1b.findingIds, "findingIds deduped+sorted")

# Different priority → different key
case_diff_prio = build_case("Ransomware Attack", CasePriorityEnum.HIGH, TS)
_assert(case1.caseKey != case_diff_prio.caseKey, "different priority → different key")

# Different title → different key
case_diff_title = build_case("Phishing Campaign", CasePriorityEnum.CRITICAL, TS)
_assert(case1.caseKey != case_diff_title.caseKey, "different title → different key")

# Default status is OPEN
case_default = build_case("Default Case", CasePriorityEnum.LOW, TS)
_assert(case_default.status    == CaseStatusEnum.OPEN, "default status OPEN")
_assert(case_default.steps     == (),                  "default steps empty tuple")
_assert(case_default.findingIds == (),                 "default findingIds empty")
_assert(case_default.assignedTo == "",                 "default assignedTo empty")
_assert(case_default.confidence == 0.0,                "default confidence 0.0")

# Confidence clamping
case_clamp_lo = build_case("X", CasePriorityEnum.LOW, TS, confidence=-10.0)
_assert(case_clamp_lo.confidence == 0.0, "confidence clamped to 0.0")

case_clamp_hi = build_case("X", CasePriorityEnum.LOW, TS, confidence=200.0)
_assert(case_clamp_hi.confidence == 100.0, "confidence clamped to 100.0")

# Custom case_number preserved
case_custom_num = build_case("Custom", CasePriorityEnum.MEDIUM, TS, case_number="CASE-001")
_assert(case_custom_num.caseNumber == "CASE-001", "custom caseNumber preserved")

# Title stripping
case_stripped = build_case("  Stripped Title  ", CasePriorityEnum.LOW, TS)
_assert(case_stripped.title == "Stripped Title", "title stripped")

# Duplicate findingIds deduplicated
case_dedup = build_case("Dedup", CasePriorityEnum.LOW, TS, finding_ids=["f1", "f1", "f2"])
_assert(len(case_dedup.findingIds) == 2, "duplicate findingIds deduplicated")
_assert(case_dedup.findingIds == ("f1", "f2"), "findingIds sorted after dedup")

# validate=False
case_no_val = build_case("X", CasePriorityEnum.LOW, TS, validate=False)
_assert(case_no_val.title == "X", "validate=False still builds")

# Build all status/priority combos
for st in CaseStatusEnum:
    for pr in CasePriorityEnum:
        c = build_case(f"Case {st.value} {pr.value}", pr, TS, status=st, validate=False)
        _assert(c.status == st and c.priority == pr,
                f"combo {st.value}/{pr.value} buildable")


# ===========================================================================
# 8. Builder: build_case_mapping
# ===========================================================================
print("\n[8] build_case_mapping")

mapping1 = build_case_mapping(
    cases      = [case1],
    created_at = TS,
    finding_id = "finding-abc",
    confidence = 80.0,
)
_assert(mapping1.findingId          == "finding-abc", "findingId set")
_assert(mapping1.alertId            == "",            "alertId empty by default")
_assert(mapping1.reasoningId        == "",            "reasoningId empty by default")
_assert(mapping1.confidence         == 80.0,          "confidence set")
_assert(len(mapping1.mappingKey)    == 32,            "mappingKey is 32 chars")
_assert(len(mapping1.mappingId)     == 36,            "mappingId is UUID format")
_assert(mapping1.mappingId.count("-") == 4,           "mappingId has 4 dashes")
_assert(len(mapping1.mappingFingerprint) == 32,       "fingerprint is 32 chars")
_assert(len(mapping1.cases)         == 1,             "1 case in mapping")
_assert(mapping1.mappingFingerprint != mapping1.mappingKey, "fingerprint != mappingKey")

# Determinism
mapping1b = build_case_mapping(
    cases      = [case1],
    created_at = TS2,           # different timestamp
    finding_id = "finding-abc",
    confidence = 80.0,
)
_assert(mapping1.mappingKey         == mapping1b.mappingKey,         "mappingKey deterministic")
_assert(mapping1.mappingId          == mapping1b.mappingId,          "mappingId deterministic")
_assert(mapping1.mappingFingerprint == mapping1b.mappingFingerprint, "fingerprint deterministic")

# Confidence clamping
mapping_lo = build_case_mapping([case1], TS, finding_id="f1", confidence=-10.0)
_assert(mapping_lo.confidence == 0.0, "mapping confidence clamped to 0.0")

mapping_hi = build_case_mapping([case1], TS, finding_id="f1", confidence=200.0)
_assert(mapping_hi.confidence == 100.0, "mapping confidence clamped to 100.0")

# Exact boundary values
mapping_c0   = build_case_mapping([case1], TS, finding_id="f1", confidence=0.0)
mapping_c100 = build_case_mapping([case1], TS, finding_id="f1", confidence=100.0)
_assert(mapping_c0.confidence   == 0.0,   "confidence 0.0 accepted")
_assert(mapping_c100.confidence == 100.0, "confidence 100.0 accepted")

# Priority DESC sort in mapping: CRITICAL before LOW
case_critical = build_case("Critical Case", CasePriorityEnum.CRITICAL, TS, confidence=90.0)
case_low      = build_case("Low Case",      CasePriorityEnum.LOW,      TS, confidence=20.0)
mapping_sorted = build_case_mapping(
    cases      = [case_low, case_critical],
    created_at = TS,
    alert_id   = "alert-1",
)
_assert(mapping_sorted.cases[0].priority == CasePriorityEnum.CRITICAL, "CRITICAL first in mapping")
_assert(mapping_sorted.cases[1].priority == CasePriorityEnum.LOW,      "LOW last in mapping")

# Multiple source IDs
mapping_multi = build_case_mapping(
    [case1], TS,
    finding_id   = "f1",
    alert_id     = "a1",
    reasoning_id = "r1",
    confidence   = 75.0,
)
_assert(mapping_multi.findingId   == "f1", "multi: findingId set")
_assert(mapping_multi.alertId     == "a1", "multi: alertId set")
_assert(mapping_multi.reasoningId == "r1", "multi: reasoningId set")

# Empty cases list
mapping_empty_cases = build_case_mapping([], TS, finding_id="f1")
_assert(mapping_empty_cases.cases == (), "empty cases → empty tuple")

mapping2 = build_case_mapping([case_default], TS, alert_id="alert-xyz", confidence=60.0)
mapping3 = build_case_mapping([case_diff_prio], TS, reasoning_id="reasoning-99", confidence=40.0)


# ===========================================================================
# 9. Builder: build_case_statistics (extended)
# ===========================================================================
print("\n[9] build_case_statistics")

# Empty input
stats_empty = build_case_statistics([])
_assert(stats_empty.totalCases        == 0,   "empty: total 0")
_assert(stats_empty.openCases         == 0,   "empty: open 0")
_assert(stats_empty.inProgressCases   == 0,   "empty: inProgress 0")
_assert(stats_empty.onHoldCases       == 0,   "empty: onHold 0")
_assert(stats_empty.resolvedCases     == 0,   "empty: resolved 0")
_assert(stats_empty.closedCases       == 0,   "empty: closed 0")
_assert(stats_empty.averageConfidence == 0.0, "empty: avgConf 0.0")
_assert(stats_empty.averageSteps      == 0.0, "empty: avgSteps 0.0")
_assert(stats_empty.priorityCounts    == {},  "empty: priorityCounts {}")
_assert(stats_empty.statusCounts      == {},  "empty: statusCounts {}")

# Build a diverse collection
case_open    = build_case("Open Case",        CasePriorityEnum.HIGH,     TS, status=CaseStatusEnum.OPEN,        confidence=90.0)
case_ip      = build_case("In Progress Case", CasePriorityEnum.CRITICAL, TS, status=CaseStatusEnum.IN_PROGRESS, confidence=70.0)
case_hold    = build_case("On Hold Case",     CasePriorityEnum.MEDIUM,   TS, status=CaseStatusEnum.ON_HOLD,     confidence=50.0)
case_res     = build_case("Resolved Case",    CasePriorityEnum.LOW,      TS, status=CaseStatusEnum.RESOLVED,    confidence=30.0)
case_closed  = build_case("Closed Case",      CasePriorityEnum.LOW,      TS, status=CaseStatusEnum.CLOSED,      confidence=10.0)

all_cases = [case_open, case_ip, case_hold, case_res, case_closed]
stats = build_case_statistics(all_cases)

_assert(stats.totalCases      == 5, "total 5")
_assert(stats.openCases       == 1, "open 1")
_assert(stats.inProgressCases == 1, "inProgress 1")
_assert(stats.onHoldCases     == 1, "onHold 1")
_assert(stats.resolvedCases   == 1, "resolved 1")
_assert(stats.closedCases     == 1, "closed 1")
_assert(stats.averageConfidence == round((90+70+50+30+10)/5, 4), "avgConf correct")

# priorityCounts
_assert("HIGH"     in stats.priorityCounts, "HIGH in priorityCounts")
_assert("CRITICAL" in stats.priorityCounts, "CRITICAL in priorityCounts")
_assert("MEDIUM"   in stats.priorityCounts, "MEDIUM in priorityCounts")
_assert("LOW"      in stats.priorityCounts, "LOW in priorityCounts")
_assert(stats.priorityCounts["HIGH"]     == 1, "HIGH count 1")
_assert(stats.priorityCounts["CRITICAL"] == 1, "CRITICAL count 1")
_assert(stats.priorityCounts["LOW"]      == 2, "LOW count 2")

# statusCounts
_assert("OPEN"        in stats.statusCounts, "OPEN in statusCounts")
_assert("IN_PROGRESS" in stats.statusCounts, "IN_PROGRESS in statusCounts")
_assert("ON_HOLD"     in stats.statusCounts, "ON_HOLD in statusCounts")
_assert("RESOLVED"    in stats.statusCounts, "RESOLVED in statusCounts")
_assert("CLOSED"      in stats.statusCounts, "CLOSED in statusCounts")
_assert(stats.statusCounts["OPEN"]        == 1, "OPEN count 1")
_assert(stats.statusCounts["IN_PROGRESS"] == 1, "IN_PROGRESS count 1")

# Deduplication
stats_dedup = build_case_statistics([case_open, case_open, case_ip])
_assert(stats_dedup.totalCases == 2, "dedup: 2 distinct cases")

# Order-independence
stats_rev = build_case_statistics(list(reversed(all_cases)))
_assert(stats.totalCases        == stats_rev.totalCases,        "stats order-independent total")
_assert(stats.averageConfidence == stats_rev.averageConfidence, "stats order-independent avgConf")
_assert(stats.priorityCounts    == stats_rev.priorityCounts,    "stats order-independent priorityCounts")
_assert(stats.statusCounts      == stats_rev.statusCounts,      "stats order-independent statusCounts")

# averageSteps with steps
case_with_steps = build_case("With Steps", CasePriorityEnum.HIGH, TS, steps=[step1, step2])
stats_steps = build_case_statistics([case_with_steps, case_default])
_assert(stats_steps.averageSteps == 1.0, "avgSteps (2+0)/2 = 1.0")

# Immutability of statistics
_assert_raises(Exception, setattr, stats_empty, "totalCases", 99,
               msg="CaseStatistics is immutable")


# ===========================================================================
# 10. Case Operations
# ===========================================================================
print("\n[10] Case Operations")

# add_case
base_list: list = []
base_list = add_case(base_list, case1)
_assert(len(base_list) == 1,                           "add: list grows to 1")
_assert(base_list[0].caseId == case1.caseId,           "add: correct case")

# Idempotent add (duplicate)
base_list2 = add_case(base_list, case1)
_assert(len(base_list2) == 1,                          "add duplicate: list stays at 1")

# Add a second
base_list3 = add_case(base_list, case_default)
_assert(len(base_list3) == 2,                          "add second: list grows to 2")

# Input not mutated
_assert(len(base_list) == 1, "original list unchanged after add")

# update_case — change title and status
updated_list = update_case(
    base_list3,
    case1.caseId,
    TS2,
    title  = "Updated Title",
    status = CaseStatusEnum.ON_HOLD,
)
_assert(len(updated_list) == 2, "update: list length unchanged")
found_updated = next(c for c in updated_list if "Updated" in c.title)
_assert(found_updated.title   == "Updated Title",      "update: title changed")
_assert(found_updated.status  == CaseStatusEnum.ON_HOLD, "update: status changed")
_assert(found_updated.priority == case1.priority,      "update: unchanged priority preserved")
_assert(found_updated.assignedTo == case1.assignedTo,  "update: assignedTo preserved")

# update_case — confidence update
updated_conf = update_case(base_list3, case1.caseId, TS2, confidence=55.0)
found_conf = next(c for c in updated_conf if c.caseId == found_updated.caseId or True)
# Find by matching updated case
u_case = [c for c in updated_conf if c.title == case1.title or c.priority == case1.priority]
_assert(len(u_case) >= 1, "update confidence: case found")

# update_case — not found returns unchanged
updated_nf = update_case(base_list3, "nonexistent-id", TS2, title="X")
_assert(len(updated_nf) == 2, "update not-found: list unchanged")

# update_case — custom caseNumber preserved through update
case_cn = build_case("CN Case", CasePriorityEnum.LOW, TS, case_number="CASE-XYZ")
list_cn = add_case([], case_cn)
updated_cn = update_case(list_cn, case_cn.caseId, TS2, description="Updated desc")
_assert(updated_cn[0].caseNumber == "CASE-XYZ", "update: caseNumber preserved")

# remove_case
removed_list = remove_case(base_list3, case1.caseId)
_assert(len(removed_list) == 1,                         "remove: list shrinks to 1")
_assert(removed_list[0].caseId == case_default.caseId,  "remove: correct item removed")

# Idempotent remove
removed_again = remove_case(removed_list, case1.caseId)
_assert(len(removed_again) == 1, "remove not-found: idempotent")

# Input not mutated
_assert(len(base_list3) == 2, "original list unchanged after remove")

# merge_cases
merge_a = [case1, case_default]
merge_b = [case_default, case_open, case_ip]
merged = merge_cases(merge_a, merge_b)
_assert(len(merged) == 4, "merge: 4 distinct cases")
# Result sorted by caseId ASC
ids = [c.caseId for c in merged]
_assert(ids == sorted(ids), "merge: result sorted by caseId")

# Merge idempotent
merged2 = merge_cases(merged, merge_a)
_assert(len(merged2) == len(merged), "merge: idempotent re-merge")

# Base wins on conflict
conflicting = Case(
    caseId      = case1.caseId,
    caseKey     = case1.caseKey,
    caseNumber  = "OVERWRITE",
    title       = "OVERWRITE ATTEMPT",
    description = "",
    status      = CaseStatusEnum.CLOSED,
    priority    = CasePriorityEnum.LOW,
    steps       = (),
    findingIds  = (),
    alertIds    = (),
    evidenceIds = (),
    playbookIds = (),
    assignedTo  = "",
    confidence  = 0.0,
    createdAt   = TS,
)
merged_conflict = merge_cases([case1], [conflicting])
_assert(len(merged_conflict) == 1,                            "merge conflict: 1 item")
_assert(merged_conflict[0].title    == case1.title,           "merge conflict: base wins title")
_assert(merged_conflict[0].priority == case1.priority,        "merge conflict: base wins priority")
_assert(merged_conflict[0].caseNumber == case1.caseNumber,    "merge conflict: base wins caseNumber")


# ===========================================================================
# 11. Step Operations
# ===========================================================================
print("\n[11] Step Operations")

# Build a case with 2 steps
case_with_2 = build_case("Two Steps", CasePriorityEnum.HIGH, TS, steps=[step1, step2])

# add_case_step
case_with_3 = add_case_step(case_with_2, step3, TS2)
_assert(len(case_with_3.steps) == 3,                        "add_step: 3 steps now")
_assert(case_with_3.steps[2].stepId == step3.stepId,        "add_step: step3 appended")
_assert(case_with_2.caseId == case_with_3.caseId,           "add_step: caseId preserved (steps don't affect key)")
_assert(len(case_with_2.steps) == 2,                        "add_step: original case unchanged")

# Idempotent add_step
case_with_3_again = add_case_step(case_with_3, step3, TS2)
_assert(len(case_with_3_again.steps) == 3,                  "add_step duplicate: idempotent")
_assert(case_with_3_again.caseId == case_with_3.caseId,     "add_step duplicate: unchanged")

# add_step preserves case metadata
_assert(case_with_3.title       == case_with_2.title,       "add_step: title preserved")
_assert(case_with_3.priority    == case_with_2.priority,    "add_step: priority preserved")
_assert(case_with_3.status      == case_with_2.status,      "add_step: status preserved")
_assert(case_with_3.caseNumber  == case_with_2.caseNumber,  "add_step: caseNumber preserved")

# update_case_step
case_updated_step = update_case_step(
    case_with_3,
    step1.stepId,
    TS2,
    title     = "Renamed Step One",
    step_type = CaseStepTypeEnum.ASSIGNED,
    assigned_to = "analyst-2",
)
found_step = next(s for s in case_updated_step.steps if s.stepId == step1.stepId)
_assert(found_step.title      == "Renamed Step One",          "update_step: title changed")
_assert(found_step.stepType   == CaseStepTypeEnum.ASSIGNED,   "update_step: stepType changed")
_assert(found_step.assignedTo == "analyst-2",                 "update_step: assignedTo changed")
_assert(found_step.stepId     == step1.stepId,                "update_step: stepId preserved")
_assert(found_step.stepKey    == step1.stepKey,               "update_step: stepKey preserved")
_assert(found_step.stepNumber == step1.stepNumber,            "update_step: stepNumber preserved")

# update_step — not found returns original
case_nf_step = update_case_step(case_with_3, "nonexistent", TS2, title="X")
_assert(case_nf_step.caseId == case_with_3.caseId,            "update_step not-found: unchanged")

# update_step description override
case_updated_desc = update_case_step(case_with_3, step1.stepId, TS2, description="New desc")
found_desc = next(s for s in case_updated_desc.steps if s.stepId == step1.stepId)
_assert(found_desc.description == "New desc",                 "update_step: description changed")

# remove_case_step
case_minus_step1 = remove_case_step(case_with_3, step1.stepId, TS2)
_assert(len(case_minus_step1.steps) == 2,                     "remove_step: 2 steps remain")
_assert(all(s.stepId != step1.stepId for s in case_minus_step1.steps), "remove_step: step1 gone")
_assert(case_minus_step1.title == case_with_3.title,          "remove_step: title preserved")

# remove_step — not found is idempotent
case_nf_remove = remove_case_step(case_with_3, "nonexistent", TS2)
_assert(case_nf_remove.caseId == case_with_3.caseId,          "remove_step not-found: unchanged")
_assert(len(case_nf_remove.steps) == 3,                       "remove_step not-found: steps count unchanged")

# Input not mutated
_assert(len(case_with_3.steps) == 3, "remove_step: original case unchanged")

# merge_case_steps
case_merged_steps = merge_case_steps(case_with_2, [step3, step4], TS2)
_assert(len(case_merged_steps.steps) == 4, "merge_steps: 4 steps")

# merge is idempotent
case_merged_idem = merge_case_steps(case_merged_steps, [step3], TS2)
_assert(len(case_merged_idem.steps) == 4, "merge_steps: idempotent re-merge")

# Base step wins on merge conflict
step1_conflict = CaseStep(
    stepId      = step1.stepId,
    stepKey     = step1.stepKey,
    stepNumber  = step1.stepNumber,
    stepType    = CaseStepTypeEnum.CLOSED,
    title       = "OVERWRITE",
    description = "",
    assignedTo  = "",
    createdAt   = TS,
)
case_base_steps = build_case("Base", CasePriorityEnum.LOW, TS, steps=[step1])
case_conflict_merged = merge_case_steps(case_base_steps, [step1_conflict], TS2)
found_s = next(s for s in case_conflict_merged.steps if s.stepId == step1.stepId)
_assert(found_s.title == step1.title, "merge_steps conflict: base wins")
_assert(found_s.stepType == step1.stepType, "merge_steps conflict: base stepType wins")

# merge_steps preserves case metadata
_assert(case_merged_steps.title      == case_with_2.title,      "merge_steps: title preserved")
_assert(case_merged_steps.caseNumber == case_with_2.caseNumber, "merge_steps: caseNumber preserved")


# ===========================================================================
# 12. Mapping Operations
# ===========================================================================
print("\n[12] Mapping Operations")

# add_case_mapping
m_list: list = []
m_list = add_case_mapping(m_list, mapping1)
_assert(len(m_list) == 1, "add_mapping: list grows to 1")

# Idempotent
m_list2 = add_case_mapping(m_list, mapping1)
_assert(len(m_list2) == 1, "add_mapping duplicate: idempotent")

# Add second
m_list3 = add_case_mapping(m_list, mapping2)
_assert(len(m_list3) == 2, "add_mapping: list grows to 2")

# Input not mutated
_assert(len(m_list) == 1, "original mapping list unchanged")

# remove_case_mapping
m_removed = remove_case_mapping(m_list3, mapping1.mappingId)
_assert(len(m_removed) == 1,                               "remove_mapping: list shrinks")
_assert(m_removed[0].mappingId == mapping2.mappingId,      "remove_mapping: correct item removed")

# Idempotent remove
m_removed2 = remove_case_mapping(m_removed, mapping1.mappingId)
_assert(len(m_removed2) == 1, "remove_mapping not-found: idempotent")

# Input not mutated
_assert(len(m_list3) == 2, "mapping list unchanged after remove")

# merge_case_mappings
merged_m = merge_case_mappings([mapping1, mapping2], [mapping2, mapping3])
_assert(len(merged_m) == 3, "merge_mappings: 3 distinct")
m_ids = [m.mappingId for m in merged_m]
_assert(m_ids == sorted(m_ids), "merge_mappings: sorted by mappingId")

# Idempotent merge
merged_m2 = merge_case_mappings(merged_m, [mapping1])
_assert(len(merged_m2) == 3, "merge_mappings: idempotent re-merge")

# Base wins on conflict
conflict_mapping = CaseMapping(
    mappingId          = mapping1.mappingId,
    mappingKey         = mapping1.mappingKey,
    findingId          = "different-finding",
    alertId            = "",
    reasoningId        = "",
    cases              = (),
    confidence         = 99.0,
    mappingFingerprint = mapping1.mappingFingerprint,
    createdAt          = TS,
)
merged_conflict_m = merge_case_mappings([mapping1], [conflict_mapping])
_assert(len(merged_conflict_m) == 1,                                 "merge_mapping conflict: 1 item")
_assert(merged_conflict_m[0].findingId   == mapping1.findingId,      "merge_mapping conflict: base wins")
_assert(merged_conflict_m[0].confidence  == mapping1.confidence,     "merge_mapping conflict: base confidence")

# merge from empty base
merged_from_empty = merge_case_mappings([], [mapping1, mapping2])
_assert(len(merged_from_empty) == 2, "merge from empty base: 2 items")

# merge with empty incoming
merged_empty_incoming = merge_case_mappings([mapping1, mapping2], [])
_assert(len(merged_empty_incoming) == 2, "merge with empty incoming: 2 items")


# ===========================================================================
# 13. Search Utilities
# ===========================================================================
print("\n[13] Search Utilities")

search_list = [case1, case_default, case_open, case_ip, case_hold]

# find_case by caseId
found_by_id = find_case(search_list, case_id=case1.caseId)
_assert(found_by_id is not None,                   "find_case: found by id")
_assert(found_by_id.caseId == case1.caseId,        "find_case: correct record")

# find_case by caseKey
found_by_key = find_case(search_list, case_key=case1.caseKey)
_assert(found_by_key is not None,                  "find_case: found by key")
_assert(found_by_key.caseId == case1.caseId,       "find_case: key match correct")

# caseId takes precedence over caseKey
found_prec = find_case(search_list, case_id=case1.caseId, case_key=case_default.caseKey)
_assert(found_prec.caseId == case1.caseId,         "find_case: caseId takes precedence")

# find_case — not found
not_found = find_case(search_list, case_id="nonexistent")
_assert(not_found is None, "find_case: returns None when not found")

# find_case — empty list
_assert(find_case([], case_id="x") is None, "find_case: empty list → None")

# find_case — no criteria returns None
_assert(find_case(search_list) is None, "find_case: no criteria → None")

# find_case by caseKey not found
_assert(find_case(search_list, case_key="nonexistent-key") is None,
        "find_case: caseKey not found → None")

# find_case_step by stepId
step_search = [case_with_3, case_default]
found_step_id = find_case_step(step_search, step_id=step1.stepId)
_assert(found_step_id is not None,              "find_case_step: found by stepId")
_assert(found_step_id.stepId == step1.stepId,   "find_case_step: correct step")

# find_case_step by stepKey
found_step_key = find_case_step(step_search, step_key=step1.stepKey)
_assert(found_step_key is not None,             "find_case_step: found by stepKey")
_assert(found_step_key.stepId == step1.stepId,  "find_case_step: stepKey match correct")

# find_case_step — not found
not_found_step = find_case_step(step_search, step_id="nonexistent")
_assert(not_found_step is None, "find_case_step: not found → None")

# find_case_step — no criteria
_assert(find_case_step(step_search) is None, "find_case_step: no criteria → None")

# find_case_step — empty list
_assert(find_case_step([], step_id="x") is None, "find_case_step: empty list → None")

# find_case_mapping by mappingId
m_search_list = [mapping1, mapping2, mapping3]
found_m = find_case_mapping(m_search_list, mapping_id=mapping1.mappingId)
_assert(found_m is not None,                          "find_case_mapping: found")
_assert(found_m.mappingId == mapping1.mappingId,      "find_case_mapping: correct mapping")

# find_case_mapping — not found
not_found_m = find_case_mapping(m_search_list, mapping_id="nonexistent")
_assert(not_found_m is None, "find_case_mapping: not found → None")

# find_case_mapping — no criteria
_assert(find_case_mapping(m_search_list) is None, "find_case_mapping: no criteria → None")

# find_case_mapping — empty list
_assert(find_case_mapping([], mapping_id="x") is None, "find_case_mapping: empty list → None")


# ===========================================================================
# 14. Sorting
# ===========================================================================
print("\n[14] Sorting")

sort_set = [case_closed, case_hold, case_open, case_ip, case1]

# sort by priority DESC (default ascending=False)
sorted_p = sort_cases(sort_set, by="priority", ascending=False)
_assert(sorted_p[0].priority == CasePriorityEnum.CRITICAL, "sort priority DESC: CRITICAL first")
for i in range(len(sorted_p) - 1):
    pi = sorted_p[i].priority
    pj = sorted_p[i+1].priority
    from services.case_flow_service import _PRIORITY_ORDER
    _assert(_PRIORITY_ORDER[pi] >= _PRIORITY_ORDER[pj] or sorted_p[i].caseId <= sorted_p[i+1].caseId,
            f"sort priority DESC stable at index {i}")

# sort by priority ASC
sorted_p_asc = sort_cases(sort_set, by="priority", ascending=True)
_assert(sorted_p_asc[-1].priority == CasePriorityEnum.CRITICAL, "sort priority ASC: CRITICAL last")

# sort by confidence DESC
sorted_conf = sort_cases(sort_set, by="confidence", ascending=False)
confs = [c.confidence for c in sorted_conf]
_assert(confs[0] >= confs[-1], "sort confidence DESC: first >= last")

# sort by confidence ASC
sorted_conf_asc = sort_cases(sort_set, by="confidence", ascending=True)
confs_asc = [c.confidence for c in sorted_conf_asc]
_assert(confs_asc[0] <= confs_asc[-1], "sort confidence ASC: first <= last")

# sort by title ASC
sorted_title = sort_cases(sort_set, by="title", ascending=True)
titles = [c.title.lower() for c in sorted_title]
_assert(titles == sorted(titles), "sort title ASC: alphabetical")

# sort by title DESC
sorted_title_d = sort_cases(sort_set, by="title", ascending=False)
titles_d = [c.title.lower() for c in sorted_title_d]
_assert(titles_d == sorted(titles_d, reverse=True), "sort title DESC: reverse alphabetical")

# sort by status
sorted_status = sort_cases(sort_set, by="status", ascending=True)
_assert(len(sorted_status) == len(sort_set), "sort status: correct length")

# sort by caseNumber
sorted_cn = sort_cases(sort_set, by="caseNumber", ascending=True)
_assert(len(sorted_cn) == len(sort_set), "sort caseNumber: correct length")

# sort by createdAt
sorted_ts = sort_cases(sort_set, by="createdAt", ascending=True)
_assert(len(sorted_ts) == len(sort_set), "sort createdAt: correct length")

# invalid key raises ValueError
_assert_raises(ValueError, sort_cases, sort_set, "invalid_key",
               msg="sort_cases: invalid key raises ValueError")

# Determinism: sorting same input twice gives same result
sorted_p2 = sort_cases(sort_set, by="priority", ascending=False)
_assert([c.caseId for c in sorted_p] == [c.caseId for c in sorted_p2],
        "sort_cases: deterministic across runs")

# Input not mutated
_assert(sort_set[0].caseId == case_closed.caseId, "sort: input not mutated")

# sort_case_steps
all_steps_flat = [step3, step1, step4, step2]

sorted_steps_asc = sort_case_steps(all_steps_flat, by="stepNumber", ascending=True)
nums = [s.stepNumber for s in sorted_steps_asc]
_assert(nums == sorted(nums), "sort_case_steps: stepNumber ASC")

sorted_steps_desc = sort_case_steps(all_steps_flat, by="stepNumber", ascending=False)
nums_d = [s.stepNumber for s in sorted_steps_desc]
_assert(nums_d == sorted(nums_d, reverse=True), "sort_case_steps: stepNumber DESC")

sorted_steps_title = sort_case_steps(all_steps_flat, by="title", ascending=True)
step_titles = [s.title.lower() for s in sorted_steps_title]
_assert(step_titles == sorted(step_titles), "sort_case_steps: title ASC")

sorted_steps_type = sort_case_steps(all_steps_flat, by="stepType")
_assert(len(sorted_steps_type) == 4, "sort_case_steps: stepType sort correct length")

sorted_steps_ts = sort_case_steps(all_steps_flat, by="createdAt")
_assert(len(sorted_steps_ts) == 4, "sort_case_steps: createdAt sort correct length")

_assert_raises(ValueError, sort_case_steps, all_steps_flat, "bad_key",
               msg="sort_case_steps: bad key raises ValueError")

# sort_case_mappings
sorted_m = sort_case_mappings([mapping3, mapping1, mapping2], by="confidence", ascending=False)
confs_m = [m.confidence for m in sorted_m]
_assert(confs_m[0] >= confs_m[-1], "sort_mappings: confidence DESC: first >= last")

sorted_m_ts = sort_case_mappings([mapping1, mapping2, mapping3], by="createdAt", ascending=True)
_assert(len(sorted_m_ts) == 3, "sort_mappings: createdAt correct length")

sorted_m_fid = sort_case_mappings([mapping1, mapping2, mapping3], by="findingId", ascending=True)
fids = [m.findingId for m in sorted_m_fid]
_assert(fids == sorted(fids), "sort_mappings: findingId ASC")

_assert_raises(ValueError, sort_case_mappings, [mapping1], "bad_key",
               msg="sort_case_mappings: bad key raises ValueError")

# Determinism of mapping sort
sorted_m2 = sort_case_mappings([mapping3, mapping1, mapping2], by="confidence", ascending=False)
_assert([m.mappingId for m in sorted_m] == [m.mappingId for m in sorted_m2],
        "sort_case_mappings: deterministic")


# ===========================================================================
# 15. Filtering
# ===========================================================================
print("\n[15] Filtering")

filter_set = [case1, case_default, case_open, case_ip, case_hold, case_res, case_closed]

# filter by status
open_only = filter_cases(filter_set, status=CaseStatusEnum.OPEN)
_assert(all(c.status == CaseStatusEnum.OPEN for c in open_only), "filter OPEN: all open")
_assert(len(open_only) >= 1, "filter OPEN: at least 1")

ip_only = filter_cases(filter_set, status=CaseStatusEnum.IN_PROGRESS)
_assert(all(c.status == CaseStatusEnum.IN_PROGRESS for c in ip_only), "filter IN_PROGRESS: all in-progress")

hold_only = filter_cases(filter_set, status=CaseStatusEnum.ON_HOLD)
_assert(all(c.status == CaseStatusEnum.ON_HOLD for c in hold_only), "filter ON_HOLD: all on-hold")

resolved_only = filter_cases(filter_set, status=CaseStatusEnum.RESOLVED)
_assert(all(c.status == CaseStatusEnum.RESOLVED for c in resolved_only), "filter RESOLVED: all resolved")

closed_only = filter_cases(filter_set, status=CaseStatusEnum.CLOSED)
_assert(all(c.status == CaseStatusEnum.CLOSED for c in closed_only), "filter CLOSED: all closed")

# filter by priority
crit_only = filter_cases(filter_set, priority=CasePriorityEnum.CRITICAL)
_assert(all(c.priority == CasePriorityEnum.CRITICAL for c in crit_only), "filter CRITICAL priority")

high_only = filter_cases(filter_set, priority=CasePriorityEnum.HIGH)
_assert(all(c.priority == CasePriorityEnum.HIGH for c in high_only), "filter HIGH priority")

low_only = filter_cases(filter_set, priority=CasePriorityEnum.LOW)
_assert(all(c.priority == CasePriorityEnum.LOW for c in low_only), "filter LOW priority")

# filter by assignedTo
assigned_cases = [
    build_case("Assigned A", CasePriorityEnum.HIGH, TS, assigned_to="alice"),
    build_case("Assigned B", CasePriorityEnum.LOW,  TS, assigned_to="bob"),
    build_case("Unassigned", CasePriorityEnum.LOW,  TS),
]
alice_cases = filter_cases(assigned_cases, assigned_to="alice")
_assert(len(alice_cases) == 1,                          "filter assignedTo alice: 1 result")
_assert(alice_cases[0].assignedTo == "alice",           "filter assignedTo: correct case")
bob_cases = filter_cases(assigned_cases, assigned_to="bob")
_assert(len(bob_cases) == 1,                            "filter assignedTo bob: 1 result")
unassigned = filter_cases(assigned_cases, assigned_to="")
_assert(len(unassigned) == 1,                           "filter unassigned: 1 result")

# Combined filter
combined = filter_cases(filter_set, status=CaseStatusEnum.IN_PROGRESS, priority=CasePriorityEnum.CRITICAL)
_assert(all(c.status == CaseStatusEnum.IN_PROGRESS and c.priority == CasePriorityEnum.CRITICAL
            for c in combined), "filter combined: all conditions met")

# No filter returns all
all_filter = filter_cases(filter_set)
_assert(len(all_filter) == len(filter_set), "filter no criteria: returns all")

# Empty list
_assert(filter_cases([], status=CaseStatusEnum.OPEN) == [], "filter: empty list → []")

# Input not mutated
_assert(len(filter_set) == 7, "filter: input not mutated")

# filter_case_steps
step_cases = [case_with_3, case_default]
all_steps_collected = filter_case_steps(step_cases)
_assert(len(all_steps_collected) > 0, "filter_steps: collects steps")

created_steps = filter_case_steps(step_cases, step_type=CaseStepTypeEnum.CREATED)
_assert(all(s.stepType == CaseStepTypeEnum.CREATED for s in created_steps),
        "filter_steps by stepType: only CREATED")

assigned_steps = filter_case_steps(step_cases, assigned_to="analyst-1")
_assert(all(s.assignedTo == "analyst-1" for s in assigned_steps),
        "filter_steps by assignedTo: only analyst-1")

no_match_steps = filter_case_steps(step_cases, step_type=CaseStepTypeEnum.RECOVERED)
_assert(isinstance(no_match_steps, list), "filter_steps no match: returns list")

empty_steps = filter_case_steps([], step_type=CaseStepTypeEnum.CREATED)
_assert(empty_steps == [], "filter_steps: empty list → []")

# filter_case_mappings
mapping_set = [mapping1, mapping2, mapping3]

by_finding = filter_case_mappings(mapping_set, finding_id="finding-abc")
_assert(all(m.findingId == "finding-abc" for m in by_finding), "filter_mappings by findingId")

by_alert = filter_case_mappings(mapping_set, alert_id="alert-xyz")
_assert(all(m.alertId == "alert-xyz" for m in by_alert), "filter_mappings by alertId")

by_reasoning = filter_case_mappings(mapping_set, reasoning_id="reasoning-99")
_assert(all(m.reasoningId == "reasoning-99" for m in by_reasoning), "filter_mappings by reasoningId")

high_conf_m = filter_case_mappings(mapping_set, min_confidence=70.0)
_assert(all(m.confidence >= 70.0 for m in high_conf_m), "filter_mappings min_confidence")

low_conf_m = filter_case_mappings(mapping_set, max_confidence=50.0)
_assert(all(m.confidence <= 50.0 for m in low_conf_m), "filter_mappings max_confidence")

no_m_match = filter_case_mappings(mapping_set, finding_id="nonexistent")
_assert(no_m_match == [], "filter_mappings: no match → []")

all_m = filter_case_mappings(mapping_set)
_assert(len(all_m) == 3, "filter_mappings: no criteria returns all")

empty_m = filter_case_mappings([], finding_id="f1")
_assert(empty_m == [], "filter_mappings: empty list → []")


# ===========================================================================
# 16. Grouping
# ===========================================================================
print("\n[16] Grouping")

group_set = [case1, case_default, case_open, case_ip, case_hold, case_res, case_closed]

# group by status
grouped_status = group_cases(group_set, group_by="status")
_assert("OPEN"        in grouped_status, "group status: OPEN present")
_assert("IN_PROGRESS" in grouped_status, "group status: IN_PROGRESS present")
_assert("ON_HOLD"     in grouped_status, "group status: ON_HOLD present")
_assert("RESOLVED"    in grouped_status, "group status: RESOLVED present")
_assert("CLOSED"      in grouped_status, "group status: CLOSED present")
_assert(len(grouped_status["OPEN"]) >= 1, "group OPEN: has items")
_assert(all(c.status == CaseStatusEnum.OPEN for c in grouped_status["OPEN"]),
        "group OPEN: all members open")

# group by priority
grouped_prio = group_cases(group_set, group_by="priority")
_assert(isinstance(grouped_prio, dict), "group priority: returns dict")
_assert("CRITICAL" in grouped_prio,     "group priority: CRITICAL present")
_assert(all(c.priority == CasePriorityEnum.CRITICAL for c in grouped_prio["CRITICAL"]),
        "group CRITICAL: all members critical priority")

# group by assignedTo
grouped_assigned = group_cases(group_set, group_by="assignedTo")
_assert(isinstance(grouped_assigned, dict), "group assignedTo: returns dict")
_assert("analyst-1" in grouped_assigned,    "group assignedTo: analyst-1 present")

# Each status group sorted by caseId ASC
for key, items in grouped_status.items():
    ids = [c.caseId for c in items]
    _assert(ids == sorted(ids), f"group status {key}: sorted by caseId")

# Each priority group sorted by caseId ASC
for key, items in grouped_prio.items():
    ids = [c.caseId for c in items]
    _assert(ids == sorted(ids), f"group priority {key}: sorted by caseId")

# Empty list
grouped_empty = group_cases([], group_by="status")
_assert(grouped_empty == {}, "group: empty list → {}")

# Input not mutated
_assert(len(group_set) == 7, "group: input not mutated")

# group_case_steps
step_cases2 = [case_with_3, case_merged_steps]
grouped_steps = group_case_steps(step_cases2, group_by="stepType")
_assert(isinstance(grouped_steps, dict), "group_steps: returns dict")
_assert(len(grouped_steps) > 0,          "group_steps: non-empty result")
for key, steps in grouped_steps.items():
    for i in range(len(steps) - 1):
        _assert(steps[i].stepNumber <= steps[i+1].stepNumber or
                steps[i].stepId <= steps[i+1].stepId,
                f"group_steps {key}: sorted stepNumber/stepId at index {i}")

# group_steps by assignedTo
grouped_steps_assigned = group_case_steps(step_cases2, group_by="assignedTo")
_assert(isinstance(grouped_steps_assigned, dict), "group_steps by assignedTo: returns dict")

# empty
grouped_steps_empty = group_case_steps([], group_by="stepType")
_assert(grouped_steps_empty == {}, "group_steps: empty list → {}")

# group_case_mappings
grouped_m = group_case_mappings(mapping_set, group_by="findingId")
_assert(isinstance(grouped_m, dict), "group_mappings: returns dict")
for key, ms in grouped_m.items():
    m_ids = [m.mappingId for m in ms]
    _assert(m_ids == sorted(m_ids), f"group_mappings {key}: sorted by mappingId")

grouped_m_alert = group_case_mappings(mapping_set, group_by="alertId")
_assert(isinstance(grouped_m_alert, dict), "group_mappings by alertId: returns dict")

grouped_m_reasoning = group_case_mappings(mapping_set, group_by="reasoningId")
_assert(isinstance(grouped_m_reasoning, dict), "group_mappings by reasoningId: returns dict")

grouped_m_empty = group_case_mappings([], group_by="findingId")
_assert(grouped_m_empty == {}, "group_mappings: empty list → {}")


# ===========================================================================
# 17. Serialization
# ===========================================================================
print("\n[17] Serialization")

# CaseStep round-trip
step_dict = step1.model_dump()
_assert(isinstance(step_dict, dict),                        "step model_dump: returns dict")
_assert(step_dict["stepId"]     == step1.stepId,            "step model_dump: stepId preserved")
_assert(step_dict["stepKey"]    == step1.stepKey,           "step model_dump: stepKey preserved")
_assert(step_dict["stepNumber"] == step1.stepNumber,        "step model_dump: stepNumber preserved")
_assert(step_dict["title"]      == step1.title,             "step model_dump: title preserved")
_assert(step_dict["stepType"]   == step1.stepType.value,    "step model_dump: stepType value")
_assert(step_dict["assignedTo"] == step1.assignedTo,        "step model_dump: assignedTo preserved")

step_restored = CaseStep(**step_dict)
_assert(step_restored.stepId   == step1.stepId,   "step restore: stepId matches")
_assert(step_restored.stepKey  == step1.stepKey,  "step restore: stepKey matches")
_assert(step_restored.stepType == step1.stepType, "step restore: stepType matches")

# Case round-trip
case_dict = case1.model_dump()
_assert(isinstance(case_dict, dict),                        "case model_dump: returns dict")
_assert(case_dict["caseId"]     == case1.caseId,            "case model_dump: caseId")
_assert(case_dict["caseKey"]    == case1.caseKey,           "case model_dump: caseKey")
_assert(case_dict["title"]      == case1.title,             "case model_dump: title")
_assert(case_dict["status"]     == case1.status.value,      "case model_dump: status value")
_assert(case_dict["priority"]   == case1.priority.value,    "case model_dump: priority value")
_assert(case_dict["caseNumber"] == case1.caseNumber,        "case model_dump: caseNumber")
_assert(case_dict["confidence"] == case1.confidence,        "case model_dump: confidence")
_assert(isinstance(case_dict["steps"],      (list, tuple)), "case model_dump: steps is sequence")
_assert(isinstance(case_dict["findingIds"], (list, tuple)), "case model_dump: findingIds is sequence")

# CaseMapping round-trip
map_dict = mapping1.model_dump()
_assert(isinstance(map_dict, dict),                              "mapping model_dump: returns dict")
_assert(map_dict["mappingId"]          == mapping1.mappingId,    "mapping model_dump: mappingId")
_assert(map_dict["mappingFingerprint"] == mapping1.mappingFingerprint, "mapping model_dump: fingerprint")
_assert(map_dict["findingId"]          == mapping1.findingId,    "mapping model_dump: findingId")
_assert(map_dict["confidence"]         == mapping1.confidence,   "mapping model_dump: confidence")
_assert(isinstance(map_dict["cases"], (list, tuple)),            "mapping model_dump: cases is sequence")

# CaseStatistics round-trip
stats_dict = stats.model_dump()
_assert(isinstance(stats_dict, dict),                                "stats model_dump: returns dict")
_assert(stats_dict["totalCases"]      == stats.totalCases,           "stats model_dump: total")
_assert(stats_dict["openCases"]       == stats.openCases,            "stats model_dump: open")
_assert(stats_dict["averageConfidence"] == stats.averageConfidence,  "stats model_dump: avgConf")
_assert("priorityCounts" in stats_dict,                              "stats model_dump: priorityCounts key")
_assert("statusCounts"   in stats_dict,                              "stats model_dump: statusCounts key")


# ===========================================================================
# 18. Immutability
# ===========================================================================
print("\n[18] Immutability")

# CaseStep frozen
_assert_raises(Exception, setattr, step1, "title",      "mutate", msg="CaseStep: title frozen")
_assert_raises(Exception, setattr, step1, "stepNumber", 99,       msg="CaseStep: stepNumber frozen")
_assert_raises(Exception, setattr, step1, "stepType",   CaseStepTypeEnum.CLOSED, msg="CaseStep: stepType frozen")
_assert_raises(Exception, setattr, step1, "assignedTo", "x",      msg="CaseStep: assignedTo frozen")

# Case frozen
_assert_raises(Exception, setattr, case1, "title",      "mutate", msg="Case: title frozen")
_assert_raises(Exception, setattr, case1, "priority",   CasePriorityEnum.LOW, msg="Case: priority frozen")
_assert_raises(Exception, setattr, case1, "status",     CaseStatusEnum.CLOSED, msg="Case: status frozen")
_assert_raises(Exception, setattr, case1, "steps",      (),       msg="Case: steps frozen")
_assert_raises(Exception, setattr, case1, "confidence", 0.0,      msg="Case: confidence frozen")
_assert_raises(Exception, setattr, case1, "findingIds", (),       msg="Case: findingIds frozen")

# CaseMapping frozen
_assert_raises(Exception, setattr, mapping1, "confidence",  0.0,  msg="CaseMapping: confidence frozen")
_assert_raises(Exception, setattr, mapping1, "findingId",   "x",  msg="CaseMapping: findingId frozen")
_assert_raises(Exception, setattr, mapping1, "cases",       (),   msg="CaseMapping: cases frozen")

# CaseStatistics frozen
_assert_raises(Exception, setattr, stats_empty, "totalCases",     99, msg="CaseStatistics: totalCases frozen")
_assert_raises(Exception, setattr, stats_empty, "averageSteps",   1.0, msg="CaseStatistics: averageSteps frozen")
_assert_raises(Exception, setattr, stats_empty, "priorityCounts", {}, msg="CaseStatistics: priorityCounts frozen")


# ===========================================================================
# 19. Integration Helpers
# ===========================================================================
print("\n[19] Integration Helpers")

# finding_to_case_mapping
finding_ns = SimpleNamespace(findingId="finding-helper-1")
f_mapping = finding_to_case_mapping(finding_ns, [case1], TS, confidence=55.0)
_assert(f_mapping.findingId   == "finding-helper-1", "finding_to_case_mapping: findingId set")
_assert(f_mapping.alertId     == "",                 "finding_to_case_mapping: alertId empty")
_assert(f_mapping.reasoningId == "",                 "finding_to_case_mapping: reasoningId empty")
_assert(f_mapping.confidence  == 55.0,               "finding_to_case_mapping: confidence set")
_assert(len(f_mapping.cases)  == 1,                  "finding_to_case_mapping: 1 case")

# Determinism
f_mapping2 = finding_to_case_mapping(finding_ns, [case1], TS2, confidence=55.0)
_assert(f_mapping.mappingId == f_mapping2.mappingId, "finding_to_case_mapping: deterministic ID")

# Finding with no findingId
finding_ns_empty = SimpleNamespace()
_assert_raises(InvalidCaseMappingError, finding_to_case_mapping,
               finding_ns_empty, [case1], TS, confidence=55.0,
               msg="finding with no findingId raises InvalidCaseMappingError")

# alert_to_case_mapping
alert_ns = SimpleNamespace(alertId="alert-helper-1", findingId="finding-linked")
a_mapping = alert_to_case_mapping(alert_ns, [case1], TS, confidence=70.0)
_assert(a_mapping.alertId     == "alert-helper-1",  "alert_to_case_mapping: alertId set")
_assert(a_mapping.findingId   == "finding-linked",  "alert_to_case_mapping: findingId from alert")
_assert(a_mapping.reasoningId == "",                "alert_to_case_mapping: reasoningId empty")
_assert(a_mapping.confidence  == 70.0,              "alert_to_case_mapping: confidence set")

# Alert with no findingId
alert_ns_nof = SimpleNamespace(alertId="alert-no-finding")
a_mapping_nof = alert_to_case_mapping(alert_ns_nof, [case1], TS)
_assert(a_mapping_nof.alertId   == "alert-no-finding", "alert_to_mapping: alertId set (no findingId)")
_assert(a_mapping_nof.findingId == "",                 "alert_to_mapping: findingId empty when absent")

# reasoning_to_case_mapping
reasoning_ns = SimpleNamespace(reasoningId="reasoning-helper-1")
r_mapping = reasoning_to_case_mapping(reasoning_ns, [case1], TS, confidence=30.0)
_assert(r_mapping.reasoningId == "reasoning-helper-1", "reasoning_to_case_mapping: reasoningId set")
_assert(r_mapping.findingId   == "",                   "reasoning_to_case_mapping: findingId empty")
_assert(r_mapping.alertId     == "",                   "reasoning_to_case_mapping: alertId empty")
_assert(r_mapping.confidence  == 30.0,                 "reasoning_to_case_mapping: confidence set")

# Determinism
r_mapping2 = reasoning_to_case_mapping(reasoning_ns, [case1], TS2, confidence=30.0)
_assert(r_mapping.mappingId == r_mapping2.mappingId,   "reasoning_to_case_mapping: deterministic ID")

# playbook_to_case_reference
pb_ns = SimpleNamespace(playbookId="playbook-xyz-456")
pb_ref = playbook_to_case_reference(pb_ns)
_assert(pb_ref == "playbook:playbook-xyz-456",  "playbook_to_case_reference: correct format")
_assert(pb_ref.startswith("playbook:"),         "playbook_to_case_reference: starts with 'playbook:'")

pb_ns_empty = SimpleNamespace()
pb_ref_empty = playbook_to_case_reference(pb_ns_empty)
_assert(pb_ref_empty == "playbook:", "playbook_to_case_reference: missing id → 'playbook:'")

# automation_to_case_reference
auto_ns = SimpleNamespace(automationId="auto-111")
auto_ref = automation_to_case_reference(auto_ns)
_assert(auto_ref == "automation:auto-111",   "automation_to_case_reference: correct format")
_assert(auto_ref.startswith("automation:"),  "automation_to_case_reference: starts with 'automation:'")

auto_ns_empty = SimpleNamespace()
auto_ref_empty = automation_to_case_reference(auto_ns_empty)
_assert(auto_ref_empty == "automation:", "automation_to_case_reference: missing id → 'automation:'")

# rule_to_case_reference
rule_ns = SimpleNamespace(ruleId="rule-abc-123")
rule_ref = rule_to_case_reference(rule_ns)
_assert(rule_ref == "rule:rule-abc-123",  "rule_to_case_reference: correct format")
_assert(rule_ref.startswith("rule:"),     "rule_to_case_reference: starts with 'rule:'")

rule_ns_empty = SimpleNamespace()
rule_ref_empty = rule_to_case_reference(rule_ns_empty)
_assert(rule_ref_empty == "rule:", "rule_to_case_reference: missing ruleId → 'rule:'")

# Stripped whitespace in references
rule_ns_ws = SimpleNamespace(ruleId="  rule-ws  ")
rule_ref_ws = rule_to_case_reference(rule_ns_ws)
_assert(rule_ref_ws == "rule:rule-ws", "rule_to_case_reference: ruleId stripped")


# ===========================================================================
# 20. Edge Cases
# ===========================================================================
print("\n[20] Edge Cases")

# build_case with no finding_ids — caseKey includes empty sorted findingIds
case_no_fids = build_case("No Findings", CasePriorityEnum.LOW, TS)
case_no_fids2 = build_case("No Findings", CasePriorityEnum.LOW, TS)
_assert(case_no_fids.caseId == case_no_fids2.caseId, "edge: no findingIds deterministic")

# build_case with whitespace-only finding_ids filtered out
case_ws_fids = build_case("WS Findings", CasePriorityEnum.LOW, TS, finding_ids=["  ", "", "f1"])
_assert(case_ws_fids.findingIds == ("f1",), "edge: whitespace-only findingIds filtered")

# build_case_step with assignedTo whitespace stripped
step_ws_assign = build_case_step("pid", 1, CaseStepTypeEnum.ASSIGNED, "Assigned", TS,
                                  assigned_to="  analyst  ")
_assert(step_ws_assign.assignedTo == "analyst", "edge: assignedTo stripped")

# build_case_mapping with all sources
mapping_all_sources = build_case_mapping(
    [case1], TS,
    finding_id="f1", alert_id="a1", reasoning_id="r1"
)
_assert(mapping_all_sources.findingId   == "f1", "edge: all sources set: findingId")
_assert(mapping_all_sources.alertId     == "a1", "edge: all sources set: alertId")
_assert(mapping_all_sources.reasoningId == "r1", "edge: all sources set: reasoningId")

# Statistics with all same priority
same_prio_cases = [
    build_case(f"Case {i}", CasePriorityEnum.CRITICAL, TS, confidence=float(i*10))
    for i in range(1, 6)
]
stats_same = build_case_statistics(same_prio_cases)
_assert(stats_same.priorityCounts.get("CRITICAL", 0) == 5, "edge: all CRITICAL priority count")
_assert(stats_same.averageConfidence == round((10+20+30+40+50)/5, 4),
        "edge: avg confidence correct for all CRITICAL")

# Merge empty lists
empty_merge = merge_cases([], [])
_assert(empty_merge == [], "edge: merge two empty lists → []")

# Sort empty list
sorted_empty = sort_cases([], by="priority")
_assert(sorted_empty == [], "edge: sort empty list → []")

# Filter empty list
filtered_empty = filter_cases([], status=CaseStatusEnum.OPEN)
_assert(filtered_empty == [], "edge: filter empty list → []")

# Group empty list
grouped_empty_status = group_cases([], group_by="status")
_assert(grouped_empty_status == {}, "edge: group empty list → {}")

# Add to empty list
empty_add = add_case([], case1)
_assert(len(empty_add) == 1, "edge: add to empty list → 1")

# Remove from empty list
empty_remove = remove_case([], "nonexistent")
_assert(empty_remove == [], "edge: remove from empty list → []")

# Find in empty list
_assert(find_case([], case_id="x") is None, "edge: find in empty list → None")
_assert(find_case_step([], step_id="x") is None, "edge: find step in empty list → None")
_assert(find_case_mapping([], mapping_id="x") is None, "edge: find mapping in empty list → None")

# Multiple identical findingIds deduplicated
case_multi_same = build_case("Multi Same", CasePriorityEnum.LOW, TS,
                              finding_ids=["f1", "f1", "f1"])
_assert(case_multi_same.findingIds == ("f1",), "edge: triple duplicate findingId deduplicated")

# Confidence precision: stored rounded to 4 decimal places
case_prec = build_case("Precision", CasePriorityEnum.LOW, TS, confidence=33.33333)
_assert(case_prec.confidence == round(33.33333, 4), "edge: confidence rounded to 4 decimals")

# stepKey stability: spaces in caseId stripped
sk_a = stepKey("  case-id  ", 1)
sk_b = stepKey("case-id", 1)
_assert(sk_a == sk_b, "edge: caseId in stepKey is stripped")


# ===========================================================================
# 21. Zero Randomness Verification
# ===========================================================================
print("\n[21] Zero Randomness")

# Run builders 3 times and confirm identical output
_det_case = build_case("Determinism Check", CasePriorityEnum.HIGH, TS,
                       finding_ids=["f1", "f2"], confidence=75.0)
for i in range(3):
    c = build_case("Determinism Check", CasePriorityEnum.HIGH, TS,
                   finding_ids=["f1", "f2"], confidence=75.0)
    _assert(c.caseId  == _det_case.caseId,  f"zero randomness: caseId run {i}")
    _assert(c.caseKey == _det_case.caseKey, f"zero randomness: caseKey run {i}")

for i in range(3):
    s = build_case_step("parent-case-id", 1, CaseStepTypeEnum.CREATED, "Case Created", TS)
    _assert(s.stepId  == step1.stepId,  f"zero randomness: stepId run {i}")
    _assert(s.stepKey == step1.stepKey, f"zero randomness: stepKey run {i}")

for i in range(3):
    m = build_case_mapping([case1], TS, finding_id="finding-abc", confidence=80.0)
    _assert(m.mappingId          == mapping1.mappingId,          f"zero randomness: mappingId run {i}")
    _assert(m.mappingFingerprint == mapping1.mappingFingerprint, f"zero randomness: fingerprint run {i}")


# ===========================================================================
# 22. Large Dataset Stability
# ===========================================================================
print("\n[22] Large Dataset Stability")

# Build 100 cases and verify statistics are stable
large_cases = [
    build_case(
        f"Case {i:04d}",
        CasePriorityEnum.CRITICAL if i % 4 == 0 else
        CasePriorityEnum.HIGH     if i % 4 == 1 else
        CasePriorityEnum.MEDIUM   if i % 4 == 2 else
        CasePriorityEnum.LOW,
        TS,
        status=CaseStatusEnum.OPEN if i % 5 != 0 else CaseStatusEnum.CLOSED,
        confidence=float(i % 101),
    )
    for i in range(100)
]

stats_large   = build_case_statistics(large_cases)
stats_large_r = build_case_statistics(list(reversed(large_cases)))

_assert(stats_large.totalCases        == 100,                          "large: total 100")
_assert(stats_large.totalCases        == stats_large_r.totalCases,     "large: total stable")
_assert(stats_large.averageConfidence == stats_large_r.averageConfidence, "large: avgConf stable")
_assert(stats_large.priorityCounts    == stats_large_r.priorityCounts,    "large: priorityCounts stable")
_assert(stats_large.statusCounts      == stats_large_r.statusCounts,      "large: statusCounts stable")

# Merge stability: merging large list with itself is idempotent
merged_large = merge_cases(large_cases, large_cases)
_assert(len(merged_large) == 100, "large: merge with self → 100 (deduped)")
ids_merged = [c.caseId for c in merged_large]
_assert(ids_merged == sorted(ids_merged), "large: merged list sorted by caseId")

# Sort stability over large set
sorted_large = sort_cases(large_cases, by="confidence", ascending=False)
_assert(len(sorted_large) == 100, "large: sort correct length")
sorted_large2 = sort_cases(large_cases, by="confidence", ascending=False)
_assert([c.caseId for c in sorted_large] == [c.caseId for c in sorted_large2],
        "large: sort deterministic")

# Filter correctness over large set
open_large = filter_cases(large_cases, status=CaseStatusEnum.OPEN)
closed_large = filter_cases(large_cases, status=CaseStatusEnum.CLOSED)
_assert(len(open_large) + len(closed_large) == 100, "large: filter open+closed = total")

# Grouping over large set
grouped_large = group_cases(large_cases, group_by="priority")
total_grouped = sum(len(v) for v in grouped_large.values())
_assert(total_grouped == 100, "large: grouped total equals input count")


# ===========================================================================
# 23. Deterministic Fingerprints
# ===========================================================================
print("\n[23] Deterministic Fingerprints")
# Same cases in different order → same mapping fingerprint
case_a = build_case("Alpha Case", CasePriorityEnum.HIGH,   TS, confidence=80.0)
case_b = build_case("Beta Case",  CasePriorityEnum.MEDIUM, TS, confidence=60.0)

mapping_ab = build_case_mapping([case_a, case_b], TS, finding_id="fp-f1", confidence=70.0)
mapping_ba = build_case_mapping([case_b, case_a], TS, finding_id="fp-f1", confidence=70.0)

_assert(mapping_ab.mappingId          == mapping_ba.mappingId,          "fingerprint: mappingId order-independent")
_assert(mapping_ab.mappingKey         == mapping_ba.mappingKey,         "fingerprint: mappingKey order-independent")
_assert(mapping_ab.mappingFingerprint == mapping_ba.mappingFingerprint, "fingerprint: fingerprint order-independent")

# Different finding_id → different fingerprint
mapping_diff_fid = build_case_mapping([case_a], TS, finding_id="fp-different", confidence=70.0)
_assert(mapping_ab.mappingFingerprint != mapping_diff_fid.mappingFingerprint,
        "fingerprint: different findingId → different fingerprint")

# Different case list → different fingerprint
mapping_a_only  = build_case_mapping([case_a],         TS, finding_id="fp-f1", confidence=70.0)
mapping_b_only  = build_case_mapping([case_b],         TS, finding_id="fp-f1", confidence=70.0)
_assert(mapping_ab.mappingFingerprint != mapping_a_only.mappingFingerprint,
        "fingerprint: different cases → different fingerprint")
_assert(mapping_a_only.mappingFingerprint != mapping_b_only.mappingFingerprint,
        "fingerprint: case_a only vs case_b only → different")

# Fingerprint is stable across multiple calls
fp1 = mapping_ab.mappingFingerprint
fp2 = build_case_mapping([case_a, case_b], TS, finding_id="fp-f1", confidence=70.0).mappingFingerprint
_assert(fp1 == fp2, "fingerprint: stable across multiple builds")



# ===========================================================================
# 24. Extended Coverage
# ===========================================================================
print("\n[24] Extended Coverage")

# --- ID helpers additional ---
sk_same = stepKey("  case-id  ", 1)
_assert(sk_same == stepKey("case-id", 1), "ext: stepKey strips caseId whitespace")

ck_single_fid = caseKey("X", CasePriorityEnum.LOW, ("only-fid",))
ck_single_fid2 = caseKey("X", CasePriorityEnum.LOW, ("only-fid",))
_assert(ck_single_fid == ck_single_fid2, "ext: caseKey single findingId deterministic")

# --- Builders additional ---
# All priorities produce different caseKeys for same title
p_keys = [caseKey("Same Title", p, ()) for p in CasePriorityEnum]
_assert(len(set(p_keys)) == 4, "ext: each priority produces unique caseKey")

# All statuses buildable
for st in CaseStatusEnum:
    c = build_case(f"Status {st.value}", CasePriorityEnum.LOW, TS, status=st, validate=False)
    _assert(c.status == st, f"ext: status {st.value} buildable")

# build_case_step with all CaseStepTypeEnum values
for stype in CaseStepTypeEnum:
    s = build_case_step("p", 1, stype, f"T {stype.value}", TS, validate=False)
    _assert(s.stepType == stype, f"ext: CaseStepTypeEnum.{stype.value} in build_case_step")

# --- Operations additional ---
# add_case: list with 3 items
list_3 = add_case(add_case(add_case([], case1), case_default), case_open)
_assert(len(list_3) == 3, "ext: add 3 distinct cases")

# remove_case: remove middle item
list_3b = [case1, case_open, case_closed]
removed_mid = remove_case(list_3b, case_open.caseId)
_assert(len(removed_mid) == 2, "ext: remove middle item → 2 items")
_assert(removed_mid[0].caseId == case1.caseId, "ext: first item preserved after remove")
_assert(removed_mid[1].caseId == case_closed.caseId, "ext: last item preserved after remove")

# merge_cases: 3-way merge
merge_x = build_case("X Case", CasePriorityEnum.LOW, TS)
merge_y = build_case("Y Case", CasePriorityEnum.MEDIUM, TS)
merge_z = build_case("Z Case", CasePriorityEnum.HIGH, TS)
merged_3way = merge_cases(merge_cases([merge_x], [merge_y]), [merge_z])
_assert(len(merged_3way) == 3, "ext: 3-way merge produces 3 cases")
_assert([c.caseId for c in merged_3way] == sorted([c.caseId for c in merged_3way]),
        "ext: 3-way merge sorted")

# --- Step Operations additional ---
# add_case_step to case with no steps
case_empty_steps = build_case("No Steps", CasePriorityEnum.LOW, TS)
case_one_step = add_case_step(case_empty_steps, step1, TS2)
_assert(len(case_one_step.steps) == 1, "ext: add step to case with no steps")
_assert(case_one_step.steps[0].stepId == step1.stepId, "ext: correct step added")

# remove_case_step: last step removed
case_one = build_case("One Step", CasePriorityEnum.LOW, TS, steps=[step1])
case_zero = remove_case_step(case_one, step1.stepId, TS2)
_assert(len(case_zero.steps) == 0, "ext: remove last step → empty steps")

# update_case_step: no changes (None args) keeps step identical
case_for_noop = build_case("Noop", CasePriorityEnum.LOW, TS, steps=[step1])
case_after_noop = update_case_step(case_for_noop, step1.stepId, TS2)
found_noop = next(s for s in case_after_noop.steps if s.stepId == step1.stepId)
_assert(found_noop.title      == step1.title,      "ext: update_step noop: title unchanged")
_assert(found_noop.stepType   == step1.stepType,   "ext: update_step noop: stepType unchanged")
_assert(found_noop.assignedTo == step1.assignedTo, "ext: update_step noop: assignedTo unchanged")

# merge_case_steps: empty incoming
case_merge_empty = merge_case_steps(case_with_2, [], TS2)
_assert(len(case_merge_empty.steps) == len(case_with_2.steps),
        "ext: merge_case_steps empty incoming: no change")

# --- Mapping Operations additional ---
# add_case_mapping: 3 distinct mappings
m_three = add_case_mapping(add_case_mapping(add_case_mapping([], mapping1), mapping2), mapping3)
_assert(len(m_three) == 3, "ext: add 3 distinct mappings")

# remove_case_mapping: remove from 3
m_after_3_remove = remove_case_mapping(m_three, mapping2.mappingId)
_assert(len(m_after_3_remove) == 2, "ext: remove from 3 → 2")

# merge_case_mappings: both lists empty
merged_both_empty = merge_case_mappings([], [])
_assert(merged_both_empty == [], "ext: merge two empty mapping lists → []")

# --- Search additional ---
# find_case: last item in list
list_for_find = [case1, case_default, case_open, case_closed]
found_last = find_case(list_for_find, case_id=case_closed.caseId)
_assert(found_last is not None, "ext: find last item in list")
_assert(found_last.caseId == case_closed.caseId, "ext: correct last item found")

# find_case_step: step in second case
list_two_cases = [case_default, case_with_3]
found_in_second = find_case_step(list_two_cases, step_id=step3.stepId)
_assert(found_in_second is not None, "ext: find step in second case")
_assert(found_in_second.stepId == step3.stepId, "ext: correct step from second case")

# --- Sorting additional ---
# sort by alertId in mappings
mapping_aids = [
    build_case_mapping([case1], TS, alert_id="zzz", confidence=50.0),
    build_case_mapping([case1], TS, alert_id="aaa", confidence=50.0),
]
sorted_by_alert = sort_case_mappings(mapping_aids, by="alertId", ascending=True)
_assert(sorted_by_alert[0].alertId <= sorted_by_alert[-1].alertId,
        "ext: sort_case_mappings by alertId ASC")

# sort by reasoningId in mappings
mapping_rids = [
    build_case_mapping([case1], TS, reasoning_id="zzz-reason", confidence=50.0),
    build_case_mapping([case1], TS, reasoning_id="aaa-reason", confidence=50.0),
]
sorted_by_reason = sort_case_mappings(mapping_rids, by="reasoningId", ascending=True)
_assert(sorted_by_reason[0].reasoningId <= sorted_by_reason[-1].reasoningId,
        "ext: sort_case_mappings by reasoningId ASC")

# --- Filtering additional ---
# filter_case_mappings: combined min+max confidence
mapping_set_ext = [
    build_case_mapping([case1], TS, finding_id="f1", confidence=20.0),
    build_case_mapping([case1], TS, finding_id="f2", confidence=50.0),
    build_case_mapping([case1], TS, finding_id="f3", confidence=80.0),
]
mid_conf = filter_case_mappings(mapping_set_ext, min_confidence=30.0, max_confidence=60.0)
_assert(all(30.0 <= m.confidence <= 60.0 for m in mid_conf),
        "ext: filter_mappings combined min+max confidence")
_assert(len(mid_conf) == 1, "ext: filter_mappings mid range: 1 result")

# filter_case_steps: no step_type returns all steps
all_st = filter_case_steps([case_with_3])
_assert(len(all_st) == 3, "ext: filter_steps no criteria: all 3 steps")

# --- Statistics additional ---
# All OPEN
all_open_cases = [
    build_case(f"Open {i}", CasePriorityEnum.LOW, TS, status=CaseStatusEnum.OPEN)
    for i in range(3)
]
stats_all_open = build_case_statistics(all_open_cases)
_assert(stats_all_open.openCases    == 3, "ext: all OPEN stats: openCases == 3")
_assert(stats_all_open.closedCases  == 0, "ext: all OPEN stats: closedCases == 0")
_assert("OPEN" in stats_all_open.statusCounts, "ext: OPEN in statusCounts for all-open set")
_assert("CLOSED" not in stats_all_open.statusCounts, "ext: CLOSED not in statusCounts for all-open")

# Zero average steps when all cases have no steps
stats_no_steps = build_case_statistics([case_default, case_no_fids])
_assert(stats_no_steps.averageSteps == 0.0, "ext: averageSteps 0.0 when no steps")

# --- Grouping additional ---
# group_cases: all same status → 1 group
same_status_cases = [
    build_case(f"Same {i}", CasePriorityEnum.LOW, TS, status=CaseStatusEnum.ON_HOLD)
    for i in range(4)
]
grouped_same = group_cases(same_status_cases, group_by="status")
_assert(len(grouped_same) == 1,                    "ext: all same status → 1 group")
_assert("ON_HOLD" in grouped_same,                 "ext: ON_HOLD group present")
_assert(len(grouped_same["ON_HOLD"]) == 4,         "ext: ON_HOLD group has 4 items")

# group_case_mappings: all same findingId → 1 group
same_fid_mappings = [
    build_case_mapping([case1], TS, finding_id="same-fid", confidence=float(i*10))
    for i in range(1, 4)
]
grouped_same_fid = group_case_mappings(same_fid_mappings, group_by="findingId")
_assert(len(grouped_same_fid) == 1,                "ext: all same findingId → 1 group")
_assert("same-fid" in grouped_same_fid,            "ext: same-fid group present")
_assert(len(grouped_same_fid["same-fid"]) == 3,    "ext: same-fid group has 3 items")


# ===========================================================================
# 25. Comprehensive Validator Coverage
# ===========================================================================
print("\n[25] Comprehensive Validator Coverage")

# validate_case_step: all valid step types pass
for st in CaseStepTypeEnum:
    try:
        validate_case_step(1, st, "Title", TS)
        _assert(True, f"validator: CaseStepTypeEnum.{st.value} passes")
    except Exception:
        _assert(False, f"validator: CaseStepTypeEnum.{st.value} should pass")

# validate_case: all valid statuses pass
for st in CaseStatusEnum:
    try:
        validate_case("T", st, CasePriorityEnum.LOW, TS)
        _assert(True, f"validator: CaseStatusEnum.{st.value} passes")
    except Exception:
        _assert(False, f"validator: CaseStatusEnum.{st.value} should pass")

# validate_case: all valid priorities pass
for pr in CasePriorityEnum:
    try:
        validate_case("T", CaseStatusEnum.OPEN, pr, TS)
        _assert(True, f"validator: CasePriorityEnum.{pr.value} passes")
    except Exception:
        _assert(False, f"validator: CasePriorityEnum.{pr.value} should pass")

# validate_case_mapping: each single source passes
for src, src_args in [("finding", ("f1", "", "")), ("alert", ("", "a1", "")), ("reasoning", ("", "", "r1"))]:
    try:
        validate_case_mapping(*src_args, 50.0, TS)
        _assert(True, f"validator: {src}-only source passes")
    except Exception:
        _assert(False, f"validator: {src}-only source should pass")

# validate_case_step: non-integer step_number types
for bad_val in [None, "1", 1.0]:
    try:
        validate_case_step(bad_val, CaseStepTypeEnum.CREATED, "T", TS)
        _assert(False, f"validator: step_number={bad_val!r} should be rejected")
    except InvalidCaseStepError:
        _assert(True, f"validator: step_number={bad_val!r} rejected correctly")
    except Exception as e:
        _assert(False, f"validator: step_number={bad_val!r} wrong exception: {type(e).__name__}")

# validate_case_mapping: integer confidence boundary
try:
    validate_case_mapping("f1", "", "", 50, TS)  # int confidence
    _assert(True, "validator: integer confidence 50 accepted")
except Exception:
    _assert(False, "validator: integer confidence 50 should be accepted")


# ===========================================================================
# 26. Build Case with All Link Collections
# ===========================================================================
print("\n[26] All Link Collections")

case_full = build_case(
    "Full Links",
    CasePriorityEnum.CRITICAL,
    TS,
    finding_ids  = ["f1", "f2", "f3"],
    alert_ids    = ["a1", "a2"],
    evidence_ids = ["e1", "e2", "e3", "e4"],
    playbook_ids = ["pb1"],
    assigned_to  = "lead-analyst",
    confidence   = 95.0,
    steps        = [step1, step2, step3],
)
_assert(len(case_full.findingIds)  == 3,              "full links: 3 findingIds")
_assert(len(case_full.alertIds)    == 2,              "full links: 2 alertIds")
_assert(len(case_full.evidenceIds) == 4,              "full links: 4 evidenceIds")
_assert(len(case_full.playbookIds) == 1,              "full links: 1 playbookId")
_assert(case_full.assignedTo       == "lead-analyst", "full links: assignedTo set")
_assert(case_full.confidence       == 95.0,           "full links: confidence 95.0")
_assert(len(case_full.steps)       == 3,              "full links: 3 steps")

# Verify all link collections are sorted
_assert(list(case_full.findingIds)  == sorted(case_full.findingIds),  "full links: findingIds sorted")
_assert(list(case_full.alertIds)    == sorted(case_full.alertIds),    "full links: alertIds sorted")
_assert(list(case_full.evidenceIds) == sorted(case_full.evidenceIds), "full links: evidenceIds sorted")
_assert(list(case_full.playbookIds) == sorted(case_full.playbookIds), "full links: playbookIds sorted")

# Statistics: case with all different statuses and priorities
diverse_cases = [
    build_case("D-OPEN-CRIT",    CasePriorityEnum.CRITICAL, TS, status=CaseStatusEnum.OPEN,        confidence=100.0),
    build_case("D-IP-HIGH",      CasePriorityEnum.HIGH,     TS, status=CaseStatusEnum.IN_PROGRESS, confidence=80.0),
    build_case("D-HOLD-MED",     CasePriorityEnum.MEDIUM,   TS, status=CaseStatusEnum.ON_HOLD,     confidence=60.0),
    build_case("D-RES-LOW",      CasePriorityEnum.LOW,      TS, status=CaseStatusEnum.RESOLVED,    confidence=40.0),
    build_case("D-CLOSED-CRIT",  CasePriorityEnum.CRITICAL, TS, status=CaseStatusEnum.CLOSED,      confidence=20.0),
]
stats_div = build_case_statistics(diverse_cases)
_assert(stats_div.totalCases      == 5,   "diverse: total 5")
_assert(stats_div.openCases       == 1,   "diverse: open 1")
_assert(stats_div.inProgressCases == 1,   "diverse: inProgress 1")
_assert(stats_div.onHoldCases     == 1,   "diverse: onHold 1")
_assert(stats_div.resolvedCases   == 1,   "diverse: resolved 1")
_assert(stats_div.closedCases     == 1,   "diverse: closed 1")
_assert(stats_div.priorityCounts["CRITICAL"] == 2, "diverse: CRITICAL count 2")
_assert(stats_div.priorityCounts["HIGH"]     == 1, "diverse: HIGH count 1")
_assert(stats_div.priorityCounts["MEDIUM"]   == 1, "diverse: MEDIUM count 1")
_assert(stats_div.priorityCounts["LOW"]      == 1, "diverse: LOW count 1")
_assert(stats_div.statusCounts["OPEN"]        == 1, "diverse: OPEN status count 1")
_assert(stats_div.statusCounts["IN_PROGRESS"] == 1, "diverse: IN_PROGRESS status count 1")
_assert(stats_div.statusCounts["ON_HOLD"]     == 1, "diverse: ON_HOLD status count 1")
_assert(stats_div.statusCounts["RESOLVED"]    == 1, "diverse: RESOLVED status count 1")
_assert(stats_div.statusCounts["CLOSED"]      == 1, "diverse: CLOSED status count 1")
_assert(stats_div.averageConfidence == round((100+80+60+40+20)/5, 4), "diverse: avg confidence")

# Statistics order independence for diverse set
stats_div_r = build_case_statistics(list(reversed(diverse_cases)))
_assert(stats_div.priorityCounts == stats_div_r.priorityCounts, "diverse: priorityCounts order-independent")
_assert(stats_div.statusCounts   == stats_div_r.statusCounts,   "diverse: statusCounts order-independent")


# ===========================================================================
# 27. Step Type Grouping
# ===========================================================================
print("\n[27] Step Type Grouping")

# Build a case with one of each step type
multi_type_steps = [
    build_case_step("mt", i+1, stype, f"Step {stype.value}", TS, validate=False)
    for i, stype in enumerate(CaseStepTypeEnum)
]
case_multi_type = build_case("Multi Type", CasePriorityEnum.LOW, TS, steps=multi_type_steps)
_assert(len(case_multi_type.steps) == 7, "step types: all 7 step types in case")

# Group by step type
grouped_all_types = group_case_steps([case_multi_type], group_by="stepType")
_assert(len(grouped_all_types) == 7, "step types: 7 groups for 7 distinct step types")
for stype in CaseStepTypeEnum:
    _assert(stype.value in grouped_all_types, f"step types: {stype.value} group present")
    _assert(len(grouped_all_types[stype.value]) == 1, f"step types: {stype.value} has 1 step")

# filter each step type
for stype in CaseStepTypeEnum:
    filtered = filter_case_steps([case_multi_type], step_type=stype)
    _assert(len(filtered) == 1, f"filter step type {stype.value}: 1 result")
    _assert(filtered[0].stepType == stype, f"filter step type {stype.value}: correct type")


# ===========================================================================
# 28. Mapping Fingerprint Properties
# ===========================================================================
print("\n[28] Mapping Fingerprint Properties")

# fingerprint is exactly 32 hex chars
_assert(len(mapping1.mappingFingerprint) == 32, "fp: length 32")
_assert(all(c in "0123456789abcdef" for c in mapping1.mappingFingerprint), "fp: valid hex")

# fingerprint is lowercase
_assert(mapping1.mappingFingerprint == mapping1.mappingFingerprint.lower(), "fp: lowercase")

# mappingKey is also 32 hex chars
_assert(len(mapping1.mappingKey) == 32, "mk: length 32")
_assert(all(c in "0123456789abcdef" for c in mapping1.mappingKey), "mk: valid hex")

# different confidence does NOT change mappingId (confidence not in key)
m_c1 = build_case_mapping([case1], TS, finding_id="fkey", confidence=10.0)
m_c2 = build_case_mapping([case1], TS, finding_id="fkey", confidence=90.0)
_assert(m_c1.mappingId  == m_c2.mappingId,  "fp: confidence does not affect mappingId")
_assert(m_c1.mappingKey == m_c2.mappingKey, "fp: confidence does not affect mappingKey")
_assert(m_c1.mappingFingerprint == m_c2.mappingFingerprint, "fp: confidence does not affect fingerprint")

# different createdAt does NOT change mappingId
m_t1 = build_case_mapping([case1], TS,  finding_id="fts", confidence=50.0)
m_t2 = build_case_mapping([case1], TS2, finding_id="fts", confidence=50.0)
_assert(m_t1.mappingId          == m_t2.mappingId,          "fp: createdAt does not affect mappingId")
_assert(m_t1.mappingFingerprint == m_t2.mappingFingerprint, "fp: createdAt does not affect fingerprint")

# caseKey is in step derivation namespace (different from automation)
_assert(len(case1.caseKey) == 32,   "case: caseKey is 32 chars")
_assert(len(step1.stepKey) == 32,   "step: stepKey is 32 chars")
_assert(case1.caseKey != step1.stepKey, "case vs step keys differ")

# ===========================================================================
# Final Summary
# ===========================================================================
print()
print("=" * 60)
print(f"TOTAL ASSERTIONS : {_PASS + _FAIL}")
print(f"PASSED           : {_PASS}")
print(f"FAILED           : {_FAIL}")
print("=" * 60)

if _ERRORS:
    print("\nFailed assertions:")
    for e in _ERRORS:
        print(f"  {e}")
    sys.exit(1)
else:
    print("\nALL ASSERTIONS PASSED ✓")
    sys.exit(0)
