"""
Smoke Test — Automation Engine
================================
Phase A4.5.2 — Comprehensive deterministic test suite.

Covers
------
- Enumerations: AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum
- Engine version constant
- Exception hierarchy
- Deterministic IDs: stepKey, automationKey, mappingKey, mappingFingerprint
- Builders: build_automation_step, build_automation, build_automation_mapping,
  build_automation_statistics
- Validators: validate_automation_step, validate_automation,
  validate_automation_mapping
- Automation Operations: add, update, remove, merge
- Step Operations: add, update, remove, merge
- Mapping Operations: add, remove, merge
- Search: find_automation, find_automation_step, find_automation_mapping
- Sorting: sort_automations, sort_automation_steps, sort_automation_mappings
- Filtering: filter_automations, filter_automation_steps, filter_automation_mappings
- Grouping: group_automations, group_automation_steps, group_automation_mappings
- Statistics: build_automation_statistics (extended with triggerCounts/actionCounts)
- Serialization: model_dump round-trip
- Immutability: frozen model enforcement
- Integration helpers
- Edge cases, zero randomness, deterministic fingerprints, large dataset stability

Target: 500+ assertions
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
from services.automation_engine_service import (
    # Engine version
    AUTOMATION_ENGINE_VERSION,
    # Enums
    AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
    # Exceptions
    AutomationEngineError, InvalidAutomationError,
    InvalidAutomationStepError, InvalidAutomationMappingError,
    # Models
    AutomationStep, Automation, AutomationMapping, AutomationStatistics,
    # Key derivation
    stepKey, automationKey, mappingKey, mappingFingerprint,
    # Validators
    validate_automation_step, validate_automation, validate_automation_mapping,
    # Builders
    build_automation_step, build_automation, build_automation_mapping,
    build_automation_statistics,
    # Automation operations
    add_automation, update_automation, remove_automation, merge_automations,
    # Step operations
    add_automation_step, update_automation_step,
    remove_automation_step, merge_automation_steps,
    # Mapping operations
    add_automation_mapping, remove_automation_mapping, merge_automation_mappings,
    # Search
    find_automation, find_automation_step, find_automation_mapping,
    # Sorting
    sort_automations, sort_automation_steps, sort_automation_mappings,
    # Filtering
    filter_automations, filter_automation_steps, filter_automation_mappings,
    # Grouping
    group_automations, group_automation_steps, group_automation_mappings,
    # Integration helpers
    rule_to_automation_reference, playbook_to_automation_reference,
    finding_to_automation_mapping, alert_to_automation_mapping,
    reasoning_to_automation_mapping,
)
from core.constants import AUTOMATION_ENGINE_VERSION as _CONST_VERSION

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T00:00:00Z"
TS3 = "2026-07-04T00:00:00Z"

print("=" * 60)
print("Automation Engine Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. Engine Version
# ===========================================================================
print("\n[1] Engine Version")

_assert(AUTOMATION_ENGINE_VERSION == "automation-engine-v1",
        "AUTOMATION_ENGINE_VERSION value")
_assert(_CONST_VERSION == "automation-engine-v1",
        "constant matches import")
_assert(AUTOMATION_ENGINE_VERSION == _CONST_VERSION,
        "service re-export matches constant")


# ===========================================================================
# 2. Enumerations
# ===========================================================================
print("\n[2] Enumerations")

# Status
_assert(AutomationStatusEnum.DRAFT.value    == "DRAFT",    "status DRAFT")
_assert(AutomationStatusEnum.ACTIVE.value   == "ACTIVE",   "status ACTIVE")
_assert(AutomationStatusEnum.DISABLED.value == "DISABLED", "status DISABLED")
_assert(AutomationStatusEnum.ARCHIVED.value == "ARCHIVED", "status ARCHIVED")
_assert(len(AutomationStatusEnum) == 4, "status enum has 4 members")

# Trigger
_assert(AutomationTriggerEnum.FINDING_CREATED.value   == "FINDING_CREATED",   "trigger FINDING_CREATED")
_assert(AutomationTriggerEnum.ALERT_CREATED.value     == "ALERT_CREATED",     "trigger ALERT_CREATED")
_assert(AutomationTriggerEnum.RULE_MATCHED.value      == "RULE_MATCHED",      "trigger RULE_MATCHED")
_assert(AutomationTriggerEnum.PLAYBOOK_SELECTED.value == "PLAYBOOK_SELECTED", "trigger PLAYBOOK_SELECTED")
_assert(AutomationTriggerEnum.TIMELINE_EVENT.value    == "TIMELINE_EVENT",    "trigger TIMELINE_EVENT")
_assert(AutomationTriggerEnum.MANUAL.value            == "MANUAL",            "trigger MANUAL")
_assert(len(AutomationTriggerEnum) == 6, "trigger enum has 6 members")

# Action
_assert(AutomationActionEnum.CREATE_ALERT.value          == "CREATE_ALERT",          "action CREATE_ALERT")
_assert(AutomationActionEnum.CREATE_TIMELINE_EVENT.value == "CREATE_TIMELINE_EVENT", "action CREATE_TIMELINE_EVENT")
_assert(AutomationActionEnum.START_PLAYBOOK.value        == "START_PLAYBOOK",        "action START_PLAYBOOK")
_assert(AutomationActionEnum.UPDATE_FINDING.value        == "UPDATE_FINDING",        "action UPDATE_FINDING")
_assert(AutomationActionEnum.UPDATE_ALERT.value          == "UPDATE_ALERT",          "action UPDATE_ALERT")
_assert(AutomationActionEnum.TAG_INVESTIGATION.value     == "TAG_INVESTIGATION",     "action TAG_INVESTIGATION")
_assert(len(AutomationActionEnum) == 6, "action enum has 6 members")


# ===========================================================================
# 3. Exception Hierarchy
# ===========================================================================
print("\n[3] Exception Hierarchy")

_assert(issubclass(AutomationEngineError, Exception),           "base inherits Exception")
_assert(issubclass(InvalidAutomationError, AutomationEngineError),
        "InvalidAutomationError inherits base")
_assert(issubclass(InvalidAutomationStepError, AutomationEngineError),
        "InvalidAutomationStepError inherits base")
_assert(issubclass(InvalidAutomationMappingError, AutomationEngineError),
        "InvalidAutomationMappingError inherits base")


# ===========================================================================
# 4. Deterministic ID Helpers
# ===========================================================================
print("\n[4] Deterministic ID Helpers")

# stepKey
sk1 = stepKey("auto-id-1", 1)
sk2 = stepKey("auto-id-1", 1)
sk3 = stepKey("auto-id-1", 2)
sk4 = stepKey("auto-id-2", 1)

_assert(sk1 == sk2,        "stepKey deterministic same inputs")
_assert(sk1 != sk3,        "stepKey differs for different stepNumber")
_assert(sk1 != sk4,        "stepKey differs for different automationId")
_assert(len(sk1) == 32,    "stepKey is 32 chars")
_assert(sk1.islower(),     "stepKey is lowercase hex")

# automationKey
ak1 = automationKey("Alert on Finding", AutomationTriggerEnum.FINDING_CREATED, ("s1", "s2"))
ak2 = automationKey("Alert on Finding", AutomationTriggerEnum.FINDING_CREATED, ("s2", "s1"))
ak3 = automationKey("Alert on Finding", AutomationTriggerEnum.ALERT_CREATED,   ("s1", "s2"))
ak4 = automationKey("Different name",   AutomationTriggerEnum.FINDING_CREATED, ("s1", "s2"))

_assert(ak1 == ak2,     "automationKey order-independent for stepIds")
_assert(ak1 != ak3,     "automationKey differs for different trigger")
_assert(ak1 != ak4,     "automationKey differs for different name")
_assert(len(ak1) == 32, "automationKey is 32 chars")

# mappingKey
mk1 = mappingKey("f1", "a1", "r1", ("id1", "id2"))
mk2 = mappingKey("f1", "a1", "r1", ("id2", "id1"))
mk3 = mappingKey("f2", "a1", "r1", ("id1", "id2"))
mk4 = mappingKey("f1", "",   "r1", ("id1", "id2"))

_assert(mk1 == mk2,     "mappingKey order-independent for automationIds")
_assert(mk1 != mk3,     "mappingKey differs for different findingId")
_assert(mk1 != mk4,     "mappingKey differs for empty alertId")
_assert(len(mk1) == 32, "mappingKey is 32 chars")

# mappingFingerprint
mfp1 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id1", "id2"))
mfp2 = mappingFingerprint(mk1, "f1", "a1", "r1", ("id2", "id1"))
mfp3 = mappingFingerprint(mk3, "f2", "a1", "r1", ("id1", "id2"))

_assert(mfp1 == mfp2,      "fingerprint order-independent for automationIds")
_assert(mfp1 != mfp3,      "fingerprint differs for different content")
_assert(len(mfp1) == 32,   "fingerprint is 32 chars")
_assert(mfp1 != mk1,       "fingerprint differs from mappingKey")


# ===========================================================================
# 5. Validators
# ===========================================================================
print("\n[5] Validators")

# validate_automation_step — happy path
try:
    validate_automation_step(1, "Step One", AutomationActionEnum.CREATE_ALERT, TS)
    _assert(True, "validate_automation_step passes valid input")
except Exception:
    _assert(False, "validate_automation_step raised unexpectedly")

# validate_automation_step — bad step_number
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               0, "Step", AutomationActionEnum.CREATE_ALERT, TS,
               msg="step_number 0 rejected")
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               -1, "Step", AutomationActionEnum.CREATE_ALERT, TS,
               msg="negative step_number rejected")

# validate_automation_step — empty name
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               1, "", AutomationActionEnum.CREATE_ALERT, TS,
               msg="empty name rejected")
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               1, "   ", AutomationActionEnum.CREATE_ALERT, TS,
               msg="whitespace-only name rejected")

# validate_automation_step — bad action type
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               1, "Step", "NOT_AN_ENUM", TS,
               msg="non-enum action rejected")

# validate_automation_step — empty createdAt
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               1, "Step", AutomationActionEnum.CREATE_ALERT, "",
               msg="empty createdAt rejected")

# validate_automation — happy path
try:
    validate_automation("Name", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, 10, TS)
    _assert(True, "validate_automation passes valid input")
except Exception:
    _assert(False, "validate_automation raised unexpectedly")

# validate_automation — bad name
_assert_raises(InvalidAutomationError, validate_automation,
               "", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, 10, TS,
               msg="empty name rejected")

# validate_automation — bad status
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", "BAD_STATUS", AutomationTriggerEnum.MANUAL, 10, TS,
               msg="bad status rejected")

# validate_automation — bad trigger
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", AutomationStatusEnum.DRAFT, "BAD_TRIGGER", 10, TS,
               msg="bad trigger rejected")

# validate_automation — bad priority
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, 0, TS,
               msg="priority 0 rejected")
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, -5, TS,
               msg="negative priority rejected")

# validate_automation — empty createdAt
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, 1, "",
               msg="empty createdAt rejected in validate_automation")

# validate_automation_mapping — happy path
try:
    validate_automation_mapping("finding-1", "", "", 50.0, TS)
    _assert(True, "validate_automation_mapping passes valid input")
except Exception:
    _assert(False, "validate_automation_mapping raised unexpectedly")

# validate_automation_mapping — no source
_assert_raises(InvalidAutomationMappingError, validate_automation_mapping,
               "", "", "", 50.0, TS,
               msg="no source IDs rejected")

# validate_automation_mapping — bad confidence
_assert_raises(InvalidAutomationMappingError, validate_automation_mapping,
               "f1", "", "", -1.0, TS,
               msg="negative confidence rejected")
_assert_raises(InvalidAutomationMappingError, validate_automation_mapping,
               "f1", "", "", 101.0, TS,
               msg="confidence > 100 rejected")

# validate_automation_mapping — empty createdAt
_assert_raises(InvalidAutomationMappingError, validate_automation_mapping,
               "f1", "", "", 50.0, "",
               msg="empty createdAt rejected in validate_automation_mapping")


# ===========================================================================
# 6. Builder: build_automation_step
# ===========================================================================
print("\n[6] build_automation_step")

step1 = build_automation_step(
    automation_id = "parent-id",
    step_number   = 1,
    name          = "Create Alert",
    action        = AutomationActionEnum.CREATE_ALERT,
    created_at    = TS,
    description   = "Creates a new alert.",
    parameters    = {"severity": "HIGH"},
)

_assert(step1.stepNumber  == 1,                           "stepNumber set")
_assert(step1.name        == "Create Alert",              "name set")
_assert(step1.action      == AutomationActionEnum.CREATE_ALERT, "action set")
_assert(step1.description == "Creates a new alert.",      "description set")
_assert(step1.parameters  == {"severity": "HIGH"},        "parameters set")
_assert(step1.createdAt   == TS,                          "createdAt set")
_assert(len(step1.stepKey) == 32,                         "stepKey is 32 chars")
_assert(step1.stepKey.islower(),                          "stepKey is lowercase")
_assert(len(step1.stepId) == 36,                          "stepId is UUID format")
_assert(step1.stepId.count("-") == 4,                     "stepId has 4 dashes")

# Determinism
step1b = build_automation_step(
    automation_id = "parent-id",
    step_number   = 1,
    name          = "Create Alert",
    action        = AutomationActionEnum.CREATE_ALERT,
    created_at    = TS,
)
_assert(step1.stepKey == step1b.stepKey, "stepKey deterministic")
_assert(step1.stepId  == step1b.stepId,  "stepId deterministic")

# Different step_number → different key
step2 = build_automation_step(
    automation_id = "parent-id",
    step_number   = 2,
    name          = "Tag Investigation",
    action        = AutomationActionEnum.TAG_INVESTIGATION,
    created_at    = TS,
)
_assert(step2.stepKey != step1.stepKey, "different stepNumber → different key")
_assert(step2.stepId  != step1.stepId,  "different stepNumber → different ID")

# validate=False skips validation
step_no_val = build_automation_step(
    automation_id = "x",
    step_number   = 99,
    name          = "X",
    action        = AutomationActionEnum.UPDATE_ALERT,
    created_at    = TS,
    validate      = False,
)
_assert(step_no_val.stepNumber == 99, "validate=False still builds")

# Empty parameters default
step_no_params = build_automation_step("pid", 1, "S", AutomationActionEnum.START_PLAYBOOK, TS)
_assert(step_no_params.parameters == {}, "parameters default to empty dict")

# Name stripping
step_strip = build_automation_step("pid", 1, "  Trim Me  ", AutomationActionEnum.UPDATE_FINDING, TS)
_assert(step_strip.name == "Trim Me", "name is stripped")


# ===========================================================================
# 7. Builder: build_automation
# ===========================================================================
print("\n[7] build_automation")

auto1 = build_automation(
    name        = "Alert on Finding",
    trigger     = AutomationTriggerEnum.FINDING_CREATED,
    created_at  = TS,
    description = "Creates an alert when a finding is created.",
    status      = AutomationStatusEnum.ACTIVE,
    steps       = [step1, step2],
    priority    = 10,
)

_assert(auto1.name        == "Alert on Finding",                    "name set")
_assert(auto1.trigger     == AutomationTriggerEnum.FINDING_CREATED, "trigger set")
_assert(auto1.status      == AutomationStatusEnum.ACTIVE,           "status set")
_assert(auto1.priority    == 10,                                    "priority set")
_assert(auto1.description == "Creates an alert when a finding is created.", "description set")
_assert(auto1.createdAt   == TS,                                    "createdAt set")
_assert(len(auto1.steps)  == 2,                                     "2 steps")
_assert(auto1.steps[0].stepNumber == 1,                             "steps sorted by stepNumber")
_assert(auto1.steps[1].stepNumber == 2,                             "steps[1] is step2")
_assert(len(auto1.automationKey) == 32,                             "automationKey is 32 chars")
_assert(len(auto1.automationId)  == 36,                             "automationId is UUID format")
_assert(auto1.automationId.count("-") == 4,                         "automationId has 4 dashes")

# Determinism: same inputs → same IDs
auto1b = build_automation(
    name       = "Alert on Finding",
    trigger    = AutomationTriggerEnum.FINDING_CREATED,
    created_at = TS2,  # different timestamp — IDs still same
    steps      = [step2, step1],  # reversed order — key still same
    status     = AutomationStatusEnum.ACTIVE,
    priority   = 10,
)
_assert(auto1.automationKey == auto1b.automationKey, "automationKey deterministic (order-independent steps)")
_assert(auto1.automationId  == auto1b.automationId,  "automationId deterministic")

# Different trigger → different key
auto_diff_trigger = build_automation(
    name    = "Alert on Finding",
    trigger = AutomationTriggerEnum.ALERT_CREATED,
    created_at = TS,
)
_assert(auto1.automationKey != auto_diff_trigger.automationKey, "different trigger → different key")

# No steps → empty tuple
auto_no_steps = build_automation("No Steps", AutomationTriggerEnum.MANUAL, TS)
_assert(auto_no_steps.steps == (), "no steps → empty tuple")
_assert(auto_no_steps.status   == AutomationStatusEnum.DRAFT, "default status DRAFT")
_assert(auto_no_steps.priority == 100,                        "default priority 100")

# validate=False skips validation
auto_no_val = build_automation("X", AutomationTriggerEnum.MANUAL, TS, validate=False)
_assert(auto_no_val.name == "X", "validate=False still builds")

# Name stripping
auto_strip = build_automation("  Trimmed  ", AutomationTriggerEnum.MANUAL, TS)
_assert(auto_strip.name == "Trimmed", "name is stripped")


# ===========================================================================
# 8. Builder: build_automation_mapping
# ===========================================================================
print("\n[8] build_automation_mapping")

mapping1 = build_automation_mapping(
    automations  = [auto1],
    created_at   = TS,
    finding_id   = "finding-abc",
    confidence   = 80.0,
)
_assert(mapping1.findingId          == "finding-abc",  "findingId set")
_assert(mapping1.alertId            == "",             "alertId empty by default")
_assert(mapping1.reasoningId        == "",             "reasoningId empty by default")
_assert(mapping1.confidence         == 80.0,           "confidence set")
_assert(len(mapping1.mappingKey)    == 32,             "mappingKey is 32 chars")
_assert(len(mapping1.mappingId)     == 36,             "mappingId is UUID format")
_assert(len(mapping1.mappingFingerprint) == 32,        "fingerprint is 32 chars")
_assert(mapping1.mappingId.count("-") == 4,            "mappingId has 4 dashes")
_assert(len(mapping1.automations)   == 1,              "1 automation in mapping")

# Determinism
mapping1b = build_automation_mapping(
    automations  = [auto1],
    created_at   = TS2,
    finding_id   = "finding-abc",
    confidence   = 80.0,
)
_assert(mapping1.mappingKey         == mapping1b.mappingKey,         "mappingKey deterministic")
_assert(mapping1.mappingId          == mapping1b.mappingId,          "mappingId deterministic")
_assert(mapping1.mappingFingerprint == mapping1b.mappingFingerprint, "fingerprint deterministic")

# Confidence clamping
mapping_clamp_lo = build_automation_mapping([auto1], TS, finding_id="f1", confidence=-10.0)
_assert(mapping_clamp_lo.confidence == 0.0, "confidence clamped to 0.0")

mapping_clamp_hi = build_automation_mapping([auto1], TS, finding_id="f1", confidence=200.0)
_assert(mapping_clamp_hi.confidence == 100.0, "confidence clamped to 100.0")

# Confidence boundary exact values
mapping_conf0   = build_automation_mapping([auto1], TS, finding_id="f1", confidence=0.0)
mapping_conf100 = build_automation_mapping([auto1], TS, finding_id="f1", confidence=100.0)
_assert(mapping_conf0.confidence   == 0.0,   "confidence 0.0 accepted")
_assert(mapping_conf100.confidence == 100.0, "confidence 100.0 accepted")

# Sorted by priority then automationId
auto_p5  = build_automation("P5",  AutomationTriggerEnum.MANUAL, TS, priority=5)
auto_p1  = build_automation("P1",  AutomationTriggerEnum.MANUAL, TS, priority=1)
mapping_sorted = build_automation_mapping(
    automations = [auto_p5, auto_p1],
    created_at  = TS,
    alert_id    = "alert-1",
)
_assert(mapping_sorted.automations[0].priority == 1,  "lowest priority first in mapping")
_assert(mapping_sorted.automations[1].priority == 5,  "highest priority last in mapping")

# fingerprint != mappingKey
_assert(mapping1.mappingFingerprint != mapping1.mappingKey, "fingerprint differs from key")


# ===========================================================================
# 9. Builder: build_automation_statistics (extended)
# ===========================================================================
print("\n[9] build_automation_statistics")

# Empty input
stats_empty = build_automation_statistics([])
_assert(stats_empty.totalAutomations    == 0,   "empty: total 0")
_assert(stats_empty.activeAutomations   == 0,   "empty: active 0")
_assert(stats_empty.draftAutomations    == 0,   "empty: draft 0")
_assert(stats_empty.disabledAutomations == 0,   "empty: disabled 0")
_assert(stats_empty.archivedAutomations == 0,   "empty: archived 0")
_assert(stats_empty.averagePriority     == 0.0, "empty: avgPriority 0.0")
_assert(stats_empty.triggerCounts       == {},  "empty: triggerCounts {}")
_assert(stats_empty.actionCounts        == {},  "empty: actionCounts {}")

# Build a collection
auto_draft    = build_automation("Draft Auto",    AutomationTriggerEnum.MANUAL,          TS, status=AutomationStatusEnum.DRAFT,    priority=100)
auto_active   = build_automation("Active Auto",   AutomationTriggerEnum.FINDING_CREATED, TS, status=AutomationStatusEnum.ACTIVE,   priority=10,  steps=[step1])
auto_disabled = build_automation("Disabled Auto", AutomationTriggerEnum.ALERT_CREATED,   TS, status=AutomationStatusEnum.DISABLED, priority=50)
auto_archived = build_automation("Archived Auto", AutomationTriggerEnum.RULE_MATCHED,    TS, status=AutomationStatusEnum.ARCHIVED, priority=200)

all_autos = [auto_draft, auto_active, auto_disabled, auto_archived]
stats = build_automation_statistics(all_autos)

_assert(stats.totalAutomations    == 4,   "total 4")
_assert(stats.activeAutomations   == 1,   "active 1")
_assert(stats.draftAutomations    == 1,   "draft 1")
_assert(stats.disabledAutomations == 1,   "disabled 1")
_assert(stats.archivedAutomations == 1,   "archived 1")
_assert(stats.averagePriority     == 90.0, "avgPriority (100+10+50+200)/4=90")

# triggerCounts
_assert("MANUAL"          in stats.triggerCounts, "MANUAL in triggerCounts")
_assert("FINDING_CREATED" in stats.triggerCounts, "FINDING_CREATED in triggerCounts")
_assert("ALERT_CREATED"   in stats.triggerCounts, "ALERT_CREATED in triggerCounts")
_assert("RULE_MATCHED"    in stats.triggerCounts, "RULE_MATCHED in triggerCounts")
_assert(stats.triggerCounts["MANUAL"]          == 1, "MANUAL count 1")
_assert(stats.triggerCounts["FINDING_CREATED"] == 1, "FINDING_CREATED count 1")

# actionCounts — auto_active has step1 (CREATE_ALERT)
_assert("CREATE_ALERT" in stats.actionCounts,   "CREATE_ALERT in actionCounts")
_assert(stats.actionCounts["CREATE_ALERT"] == 1, "CREATE_ALERT count 1")

# Deduplication in statistics
stats_dedup = build_automation_statistics([auto_active, auto_active, auto_draft])
_assert(stats_dedup.totalAutomations == 2, "dedup: 2 distinct automations")

# Order-independence
stats_rev = build_automation_statistics(list(reversed(all_autos)))
_assert(stats.totalAutomations == stats_rev.totalAutomations, "stats order-independent total")
_assert(stats.averagePriority  == stats_rev.averagePriority,  "stats order-independent avg")

# Immutability of statistics
_assert_raises(Exception, setattr, stats_empty, "totalAutomations", 99,
               msg="AutomationStatistics is immutable")


# ===========================================================================
# 10. Automation Operations
# ===========================================================================
print("\n[10] Automation Operations")

# add_automation
base_list: list = []
base_list = add_automation(base_list, auto1)
_assert(len(base_list) == 1, "add: list grows to 1")
_assert(base_list[0].automationId == auto1.automationId, "add: correct automation")

# Idempotent add (duplicate)
base_list2 = add_automation(base_list, auto1)
_assert(len(base_list2) == 1, "add duplicate: list stays at 1")

# Add a second
base_list3 = add_automation(base_list, auto_draft)
_assert(len(base_list3) == 2, "add second: list grows to 2")

# Input not mutated
_assert(len(base_list) == 1, "original list unchanged after add")

# update_automation — change name and status
updated_list = update_automation(
    base_list3,
    auto1.automationId,
    TS2,
    name   = "Renamed Auto",
    status = AutomationStatusEnum.DISABLED,
)
_assert(len(updated_list) == 2, "update: list length unchanged")
found_updated = next(a for a in updated_list if "Renamed" in a.name)
_assert(found_updated.name   == "Renamed Auto",            "update: name changed")
_assert(found_updated.status == AutomationStatusEnum.DISABLED, "update: status changed")
_assert(found_updated.priority == auto1.priority,          "update: unchanged fields preserved")

# update_automation — not found returns unchanged
updated_nf = update_automation(base_list3, "nonexistent-id", TS2, name="X")
_assert(len(updated_nf) == 2, "update not-found: list unchanged")

# remove_automation
removed_list = remove_automation(base_list3, auto1.automationId)
_assert(len(removed_list) == 1, "remove: list shrinks to 1")
_assert(removed_list[0].automationId == auto_draft.automationId, "remove: correct item removed")

# Idempotent remove
removed_again = remove_automation(removed_list, auto1.automationId)
_assert(len(removed_again) == 1, "remove not-found: idempotent")

# Input not mutated
_assert(len(base_list3) == 2, "original list unchanged after remove")

# merge_automations
merge_a = [auto1, auto_draft]
merge_b = [auto_draft, auto_disabled, auto_archived]
merged = merge_automations(merge_a, merge_b)
_assert(len(merged) == 4, "merge: 4 distinct automations")
# Result sorted by automationId ASC
ids = [a.automationId for a in merged]
_assert(ids == sorted(ids), "merge: result sorted by automationId")

# merge is idempotent
merged2 = merge_automations(merged, merge_a)
_assert(len(merged2) == len(merged), "merge: idempotent re-merge")

# base wins in merge
conflicting = Automation(
    automationId  = auto1.automationId,
    automationKey = auto1.automationKey,
    name          = "OVERWRITE ATTEMPT",
    description   = "",
    status        = AutomationStatusEnum.ARCHIVED,
    trigger       = AutomationTriggerEnum.MANUAL,
    steps         = (),
    priority      = 999,
    createdAt     = TS,
)
merged_conflict = merge_automations([auto1], [conflicting])
_assert(len(merged_conflict) == 1,                     "merge conflict: 1 item")
_assert(merged_conflict[0].name == auto1.name,         "merge conflict: base wins name")
_assert(merged_conflict[0].priority == auto1.priority, "merge conflict: base wins priority")


# ===========================================================================
# 11. Step Operations
# ===========================================================================
print("\n[11] Step Operations")

step3 = build_automation_step("pid", 3, "Step Three", AutomationActionEnum.START_PLAYBOOK, TS)

# add_automation_step
auto_with_2 = build_automation("Two Steps", AutomationTriggerEnum.MANUAL, TS, steps=[step1, step2])
auto_with_3 = add_automation_step(auto_with_2, step3, TS2)
_assert(len(auto_with_3.steps) == 3, "add_step: 3 steps now")
_assert(auto_with_3.steps[2].stepId == step3.stepId, "add_step: step3 appended")
# automationKey recomputed because step set changed
_assert(auto_with_2.automationKey != auto_with_3.automationKey, "add_step: key recomputed")
# original unchanged
_assert(len(auto_with_2.steps) == 2, "add_step: original automation unchanged")

# Idempotent add_step
auto_with_3_again = add_automation_step(auto_with_3, step3, TS2)
_assert(len(auto_with_3_again.steps) == 3, "add_step duplicate: idempotent")
_assert(auto_with_3_again.automationId == auto_with_3.automationId, "add_step duplicate: unchanged")

# update_automation_step
auto_updated_step = update_automation_step(
    auto_with_3,
    step1.stepId,
    TS2,
    name   = "Renamed Step One",
    action = AutomationActionEnum.UPDATE_ALERT,
)
found_step = next(s for s in auto_updated_step.steps if s.stepId == step1.stepId)
_assert(found_step.name   == "Renamed Step One",            "update_step: name changed")
_assert(found_step.action == AutomationActionEnum.UPDATE_ALERT, "update_step: action changed")
_assert(found_step.stepId == step1.stepId,                  "update_step: stepId preserved")
_assert(found_step.stepKey == step1.stepKey,                "update_step: stepKey preserved")
_assert(found_step.stepNumber == step1.stepNumber,          "update_step: stepNumber preserved")

# update_automation_step — not found returns original
auto_nf_step = update_automation_step(auto_with_3, "nonexistent", TS2, name="X")
_assert(auto_nf_step.automationId == auto_with_3.automationId, "update_step not-found: unchanged")

# update_step parameters override
auto_updated_params = update_automation_step(
    auto_with_3, step1.stepId, TS2, parameters={"key": "value"}
)
found_p = next(s for s in auto_updated_params.steps if s.stepId == step1.stepId)
_assert(found_p.parameters == {"key": "value"}, "update_step: parameters changed")

# remove_automation_step
auto_minus_step1 = remove_automation_step(auto_with_3, step1.stepId, TS2)
_assert(len(auto_minus_step1.steps) == 2, "remove_step: 2 steps remain")
_assert(all(s.stepId != step1.stepId for s in auto_minus_step1.steps), "remove_step: step1 gone")
# Key recomputed
_assert(auto_with_3.automationKey != auto_minus_step1.automationKey, "remove_step: key recomputed")

# remove_step — not found is idempotent
auto_nf_remove = remove_automation_step(auto_with_3, "nonexistent", TS2)
_assert(auto_nf_remove.automationId == auto_with_3.automationId, "remove_step not-found: unchanged")

# merge_automation_steps
step4 = build_automation_step("pid", 4, "Step Four", AutomationActionEnum.TAG_INVESTIGATION, TS)
auto_merged_steps = merge_automation_steps(auto_with_2, [step3, step4], TS2)
_assert(len(auto_merged_steps.steps) == 4, "merge_steps: 4 steps")

# merge is idempotent
auto_merged_idempotent = merge_automation_steps(auto_merged_steps, [step3], TS2)
_assert(len(auto_merged_idempotent.steps) == 4, "merge_steps: idempotent re-merge")

# base step wins on merge conflict
step1_conflict = AutomationStep(
    stepId      = step1.stepId,
    stepKey     = step1.stepKey,
    stepNumber  = step1.stepNumber,
    name        = "OVERWRITE",
    description = "",
    action      = AutomationActionEnum.TAG_INVESTIGATION,
    parameters  = {},
    createdAt   = TS,
)
auto_base = build_automation("Base", AutomationTriggerEnum.MANUAL, TS, steps=[step1])
auto_conflict_merged = merge_automation_steps(auto_base, [step1_conflict], TS2)
found_s = next(s for s in auto_conflict_merged.steps if s.stepId == step1.stepId)
_assert(found_s.name == step1.name, "merge_steps conflict: base wins")


# ===========================================================================
# 12. Mapping Operations
# ===========================================================================
print("\n[12] Mapping Operations")

mapping2 = build_automation_mapping([auto_draft], TS, alert_id="alert-xyz", confidence=60.0)
mapping3 = build_automation_mapping([auto_disabled], TS, reasoning_id="reasoning-99", confidence=40.0)

# add_automation_mapping
m_list: list = []
m_list = add_automation_mapping(m_list, mapping1)
_assert(len(m_list) == 1, "add_mapping: list grows to 1")

# Idempotent
m_list2 = add_automation_mapping(m_list, mapping1)
_assert(len(m_list2) == 1, "add_mapping duplicate: idempotent")

# Add second
m_list3 = add_automation_mapping(m_list, mapping2)
_assert(len(m_list3) == 2, "add_mapping: list grows to 2")

# Input not mutated
_assert(len(m_list) == 1, "original mapping list unchanged")

# remove_automation_mapping
m_removed = remove_automation_mapping(m_list3, mapping1.mappingId)
_assert(len(m_removed) == 1,                                "remove_mapping: list shrinks")
_assert(m_removed[0].mappingId == mapping2.mappingId,       "remove_mapping: correct item removed")

# Idempotent remove
m_removed2 = remove_automation_mapping(m_removed, mapping1.mappingId)
_assert(len(m_removed2) == 1, "remove_mapping not-found: idempotent")

# Input not mutated
_assert(len(m_list3) == 2, "mapping list unchanged after remove")

# merge_automation_mappings
merged_m = merge_automation_mappings([mapping1, mapping2], [mapping2, mapping3])
_assert(len(merged_m) == 3, "merge_mappings: 3 distinct")
m_ids = [m.mappingId for m in merged_m]
_assert(m_ids == sorted(m_ids), "merge_mappings: sorted by mappingId")

# Idempotent merge
merged_m2 = merge_automation_mappings(merged_m, [mapping1])
_assert(len(merged_m2) == 3, "merge_mappings: idempotent re-merge")

# base wins on conflict
conflict_mapping = AutomationMapping(
    mappingId          = mapping1.mappingId,
    mappingKey         = mapping1.mappingKey,
    findingId          = "different-finding",
    alertId            = "",
    reasoningId        = "",
    automations        = (),
    confidence         = 99.0,
    mappingFingerprint = mapping1.mappingFingerprint,
    createdAt          = TS,
)
merged_conflict_m = merge_automation_mappings([mapping1], [conflict_mapping])
_assert(len(merged_conflict_m) == 1,                              "merge_mapping conflict: 1 item")
_assert(merged_conflict_m[0].findingId == mapping1.findingId,     "merge_mapping conflict: base wins")
_assert(merged_conflict_m[0].confidence == mapping1.confidence,   "merge_mapping conflict: base confidence")


# ===========================================================================
# 13. Search Utilities
# ===========================================================================
print("\n[13] Search Utilities")

search_list = [auto1, auto_draft, auto_active, auto_disabled, auto_archived]

# find_automation by automationId
found_by_id = find_automation(search_list, automation_id=auto1.automationId)
_assert(found_by_id is not None,                      "find_automation: found by id")
_assert(found_by_id.automationId == auto1.automationId, "find_automation: correct record")

# find_automation by automationKey
found_by_key = find_automation(search_list, automation_key=auto1.automationKey)
_assert(found_by_key is not None,                       "find_automation: found by key")
_assert(found_by_key.automationId == auto1.automationId, "find_automation: key match correct")

# find_automation — not found
not_found = find_automation(search_list, automation_id="nonexistent")
_assert(not_found is None, "find_automation: returns None when not found")

# find_automation — empty list
_assert(find_automation([], automation_id="x") is None, "find_automation: empty list → None")

# find_automation — no criteria
_assert(find_automation(search_list) is None, "find_automation: no criteria → None")

# find_automation_step by stepId
step_search_list = [auto_with_3, auto_draft]
found_step_id = find_automation_step(step_search_list, step_id=step1.stepId)
_assert(found_step_id is not None,                  "find_automation_step: found by stepId")
_assert(found_step_id.stepId == step1.stepId,       "find_automation_step: correct step")

# find_automation_step by stepKey
found_step_key = find_automation_step(step_search_list, step_key=step1.stepKey)
_assert(found_step_key is not None,                  "find_automation_step: found by stepKey")
_assert(found_step_key.stepId == step1.stepId,       "find_automation_step: stepKey match correct")

# find_automation_step — not found
not_found_step = find_automation_step(step_search_list, step_id="nonexistent")
_assert(not_found_step is None, "find_automation_step: not found → None")

# find_automation_step — no criteria
_assert(find_automation_step(step_search_list) is None, "find_automation_step: no criteria → None")

# find_automation_mapping by mappingId
m_search_list = [mapping1, mapping2, mapping3]
found_m = find_automation_mapping(m_search_list, mapping_id=mapping1.mappingId)
_assert(found_m is not None,                          "find_automation_mapping: found")
_assert(found_m.mappingId == mapping1.mappingId,      "find_automation_mapping: correct mapping")

# find_automation_mapping — not found
not_found_m = find_automation_mapping(m_search_list, mapping_id="nonexistent")
_assert(not_found_m is None, "find_automation_mapping: not found → None")

# find_automation_mapping — no criteria
_assert(find_automation_mapping(m_search_list) is None, "find_automation_mapping: no criteria → None")


# ===========================================================================
# 14. Sorting
# ===========================================================================
print("\n[14] Sorting")

sort_set = [auto_archived, auto_disabled, auto_active, auto_draft, auto1]

# sort by priority ASC (default)
sorted_p = sort_automations(sort_set, by="priority", ascending=True)
_assert(sorted_p[0].priority <= sorted_p[1].priority, "sort priority ASC: first <= second")
for i in range(len(sorted_p) - 1):
    _assert(sorted_p[i].priority <= sorted_p[i+1].priority or
            sorted_p[i].automationId <= sorted_p[i+1].automationId,
            f"sort priority ASC stable at index {i}")

# sort by priority DESC
sorted_p_desc = sort_automations(sort_set, by="priority", ascending=False)
_assert(sorted_p_desc[0].priority >= sorted_p_desc[-1].priority, "sort priority DESC: first >= last")

# sort by name ASC
sorted_name = sort_automations(sort_set, by="name", ascending=True)
names = [a.name.lower() for a in sorted_name]
_assert(names == sorted(names), "sort name ASC: alphabetical")

# sort by name DESC
sorted_name_d = sort_automations(sort_set, by="name", ascending=False)
names_d = [a.name.lower() for a in sorted_name_d]
_assert(names_d == sorted(names_d, reverse=True), "sort name DESC: reverse alphabetical")

# sort by status
sorted_status = sort_automations(sort_set, by="status", ascending=True)
_assert(len(sorted_status) == len(sort_set), "sort status: correct length")

# sort by trigger
sorted_trigger = sort_automations(sort_set, by="trigger", ascending=True)
_assert(len(sorted_trigger) == len(sort_set), "sort trigger: correct length")

# sort by createdAt
sorted_ts = sort_automations(sort_set, by="createdAt", ascending=True)
_assert(len(sorted_ts) == len(sort_set), "sort createdAt: correct length")

# sort_automations invalid key raises
_assert_raises(ValueError, sort_automations, sort_set, "invalid_key",
               msg="sort_automations: invalid key raises ValueError")

# Determinism: sorting same input twice gives same result
sorted_p2 = sort_automations(sort_set, by="priority", ascending=True)
_assert([a.automationId for a in sorted_p] == [a.automationId for a in sorted_p2],
        "sort_automations: deterministic across runs")

# Input not mutated
_assert(sort_set[0].automationId == auto_archived.automationId, "sort: input not mutated")

# sort_automation_steps
all_steps = [step3, step1, step2, step4]
sorted_steps = sort_automation_steps(all_steps, by="stepNumber", ascending=True)
nums = [s.stepNumber for s in sorted_steps]
_assert(nums == sorted(nums), "sort_automation_steps: stepNumber ASC")

sorted_steps_d = sort_automation_steps(all_steps, by="stepNumber", ascending=False)
nums_d = [s.stepNumber for s in sorted_steps_d]
_assert(nums_d == sorted(nums_d, reverse=True), "sort_automation_steps: stepNumber DESC")

sorted_steps_name = sort_automation_steps(all_steps, by="name", ascending=True)
step_names = [s.name.lower() for s in sorted_steps_name]
_assert(step_names == sorted(step_names), "sort_automation_steps: name ASC")

sorted_steps_action = sort_automation_steps(all_steps, by="action")
_assert(len(sorted_steps_action) == 4, "sort_automation_steps: action sort correct length")

_assert_raises(ValueError, sort_automation_steps, all_steps, "bad_key",
               msg="sort_automation_steps: bad key raises ValueError")

# sort_automation_mappings
sorted_m = sort_automation_mappings([mapping3, mapping1, mapping2], by="confidence", ascending=False)
confs = [m.confidence for m in sorted_m]
_assert(confs[0] >= confs[-1], "sort_mappings: confidence DESC: first >= last")

sorted_m_ts = sort_automation_mappings([mapping1, mapping2, mapping3], by="createdAt", ascending=True)
_assert(len(sorted_m_ts) == 3, "sort_mappings: createdAt correct length")

_assert_raises(ValueError, sort_automation_mappings, [mapping1], "bad_key",
               msg="sort_automation_mappings: bad key raises ValueError")


# ===========================================================================
# 15. Filtering
# ===========================================================================
print("\n[15] Filtering")

filter_set = [auto1, auto_draft, auto_active, auto_disabled, auto_archived]

# filter by status
active_only = filter_automations(filter_set, status=AutomationStatusEnum.ACTIVE)
_assert(all(a.status == AutomationStatusEnum.ACTIVE for a in active_only), "filter status ACTIVE: all active")
_assert(len(active_only) >= 1, "filter status ACTIVE: at least 1")

draft_only = filter_automations(filter_set, status=AutomationStatusEnum.DRAFT)
_assert(all(a.status == AutomationStatusEnum.DRAFT for a in draft_only), "filter status DRAFT: all draft")

disabled_only = filter_automations(filter_set, status=AutomationStatusEnum.DISABLED)
_assert(all(a.status == AutomationStatusEnum.DISABLED for a in disabled_only), "filter status DISABLED")

archived_only = filter_automations(filter_set, status=AutomationStatusEnum.ARCHIVED)
_assert(all(a.status == AutomationStatusEnum.ARCHIVED for a in archived_only), "filter status ARCHIVED")

# filter by trigger
finding_trigger = filter_automations(filter_set, trigger=AutomationTriggerEnum.FINDING_CREATED)
_assert(all(a.trigger == AutomationTriggerEnum.FINDING_CREATED for a in finding_trigger),
        "filter trigger FINDING_CREATED")

manual_trigger = filter_automations(filter_set, trigger=AutomationTriggerEnum.MANUAL)
_assert(all(a.trigger == AutomationTriggerEnum.MANUAL for a in manual_trigger),
        "filter trigger MANUAL")

# filter by priority range
high_prio = filter_automations(filter_set, min_priority=1, max_priority=50)
_assert(all(1 <= a.priority <= 50 for a in high_prio), "filter priority range 1-50")

low_prio = filter_automations(filter_set, min_priority=100)
_assert(all(a.priority >= 100 for a in low_prio), "filter min_priority >= 100")

# Combined filter
combined = filter_automations(
    filter_set,
    status      = AutomationStatusEnum.ACTIVE,
    trigger     = AutomationTriggerEnum.FINDING_CREATED,
    max_priority = 50,
)
_assert(all(
    a.status == AutomationStatusEnum.ACTIVE
    and a.trigger == AutomationTriggerEnum.FINDING_CREATED
    and a.priority <= 50
    for a in combined
), "filter combined: all conditions met")

# No filter returns all
all_filter = filter_automations(filter_set)
_assert(len(all_filter) == len(filter_set), "filter no criteria: returns all")

# Empty list
_assert(filter_automations([], status=AutomationStatusEnum.ACTIVE) == [], "filter: empty list → []")

# Input not mutated
_assert(len(filter_set) == 5, "filter: input not mutated")

# filter_automation_steps
step_autos = [auto_with_3, auto_active]
all_steps_flat = filter_automation_steps(step_autos)
_assert(len(all_steps_flat) > 0, "filter_steps: returns steps")

create_alert_steps = filter_automation_steps(step_autos, action=AutomationActionEnum.CREATE_ALERT)
_assert(all(s.action == AutomationActionEnum.CREATE_ALERT for s in create_alert_steps),
        "filter_steps by action: only CREATE_ALERT")

no_match_steps = filter_automation_steps(step_autos, action=AutomationActionEnum.UPDATE_FINDING)
_assert(isinstance(no_match_steps, list), "filter_steps no match: returns list")

# filter_automation_mappings
mapping_set = [mapping1, mapping2, mapping3]

by_finding = filter_automation_mappings(mapping_set, finding_id="finding-abc")
_assert(all(m.findingId == "finding-abc" for m in by_finding), "filter_mappings by findingId")

by_alert = filter_automation_mappings(mapping_set, alert_id="alert-xyz")
_assert(all(m.alertId == "alert-xyz" for m in by_alert), "filter_mappings by alertId")

by_reasoning = filter_automation_mappings(mapping_set, reasoning_id="reasoning-99")
_assert(all(m.reasoningId == "reasoning-99" for m in by_reasoning), "filter_mappings by reasoningId")

high_conf = filter_automation_mappings(mapping_set, min_confidence=70.0)
_assert(all(m.confidence >= 70.0 for m in high_conf), "filter_mappings min_confidence")

low_conf = filter_automation_mappings(mapping_set, max_confidence=50.0)
_assert(all(m.confidence <= 50.0 for m in low_conf), "filter_mappings max_confidence")

no_mapping_match = filter_automation_mappings(mapping_set, finding_id="nonexistent")
_assert(no_mapping_match == [], "filter_mappings: no match → []")

all_mappings = filter_automation_mappings(mapping_set)
_assert(len(all_mappings) == 3, "filter_mappings: no criteria returns all")


# ===========================================================================
# 16. Grouping
# ===========================================================================
print("\n[16] Grouping")

group_set = [auto1, auto_draft, auto_active, auto_disabled, auto_archived]

# group by status
grouped_status = group_automations(group_set, group_by="status")
_assert("ACTIVE" in grouped_status,   "group status: ACTIVE present")
_assert("DRAFT" in grouped_status,    "group status: DRAFT present")
_assert("DISABLED" in grouped_status, "group status: DISABLED present")
_assert("ARCHIVED" in grouped_status, "group status: ARCHIVED present")
_assert(len(grouped_status["ACTIVE"]) >= 1, "group status: ACTIVE group has items")
_assert(all(a.status == AutomationStatusEnum.ACTIVE for a in grouped_status["ACTIVE"]),
        "group status ACTIVE: all members active")

# group by trigger
grouped_trigger = group_automations(group_set, group_by="trigger")
_assert("FINDING_CREATED" in grouped_trigger or "MANUAL" in grouped_trigger,
        "group trigger: at least one trigger group present")
if "MANUAL" in grouped_trigger:
    _assert(all(a.trigger == AutomationTriggerEnum.MANUAL for a in grouped_trigger["MANUAL"]),
            "group trigger MANUAL: all members have MANUAL trigger")

# group by priority
grouped_priority = group_automations(group_set, group_by="priority")
_assert(isinstance(grouped_priority, dict), "group priority: returns dict")
_assert(all(isinstance(k, str) for k in grouped_priority.keys()), "group priority: keys are strings")

# Each group sorted by automationId
for key, items in grouped_status.items():
    ids = [a.automationId for a in items]
    _assert(ids == sorted(ids), f"group status {key}: sorted by automationId")

# Empty list
grouped_empty = group_automations([], group_by="status")
_assert(grouped_empty == {}, "group: empty list → {}")

# Input not mutated
_assert(len(group_set) == 5, "group: input not mutated")

# group_automation_steps
step_group_autos = [auto_with_3, auto_active]
grouped_steps = group_automation_steps(step_group_autos, group_by="action")
_assert(isinstance(grouped_steps, dict), "group_steps: returns dict")
for key, steps in grouped_steps.items():
    nums = [s.stepNumber for s in steps]
    ids  = [s.stepId for s in steps]
    _assert(all(steps[i].stepNumber <= steps[i+1].stepNumber or
                steps[i].stepId <= steps[i+1].stepId
                for i in range(len(steps)-1) if len(steps) > 1),
            f"group_steps {key}: sorted by stepNumber then stepId")

# Empty
grouped_steps_empty = group_automation_steps([], group_by="action")
_assert(grouped_steps_empty == {}, "group_steps: empty list → {}")

# group_automation_mappings
grouped_m = group_automation_mappings(mapping_set, group_by="findingId")
_assert(isinstance(grouped_m, dict), "group_mappings: returns dict")
for key, mappings in grouped_m.items():
    m_ids = [m.mappingId for m in mappings]
    _assert(m_ids == sorted(m_ids), f"group_mappings {key}: sorted by mappingId")

grouped_m_alert = group_automation_mappings(mapping_set, group_by="alertId")
_assert(isinstance(grouped_m_alert, dict), "group_mappings by alertId: returns dict")

grouped_m_empty = group_automation_mappings([], group_by="findingId")
_assert(grouped_m_empty == {}, "group_mappings: empty list → {}")


# ===========================================================================
# 17. Serialization
# ===========================================================================
print("\n[17] Serialization")

# AutomationStep round-trip
step_dict = step1.model_dump()
_assert(isinstance(step_dict, dict),          "step model_dump: returns dict")
_assert(step_dict["stepId"]     == step1.stepId,     "step model_dump: stepId preserved")
_assert(step_dict["stepKey"]    == step1.stepKey,     "step model_dump: stepKey preserved")
_assert(step_dict["stepNumber"] == step1.stepNumber,  "step model_dump: stepNumber preserved")
_assert(step_dict["name"]       == step1.name,        "step model_dump: name preserved")
_assert(step_dict["action"]     == step1.action.value, "step model_dump: action value")

step_restored = AutomationStep(**step_dict)
_assert(step_restored.stepId  == step1.stepId,  "step restore: stepId matches")
_assert(step_restored.stepKey == step1.stepKey, "step restore: stepKey matches")

# Automation round-trip
auto_dict = auto1.model_dump()
_assert(isinstance(auto_dict, dict),               "automation model_dump: returns dict")
_assert(auto_dict["automationId"]  == auto1.automationId,  "automation model_dump: automationId")
_assert(auto_dict["automationKey"] == auto1.automationKey, "automation model_dump: automationKey")
_assert(auto_dict["name"]          == auto1.name,          "automation model_dump: name")
_assert(auto_dict["trigger"]       == auto1.trigger.value, "automation model_dump: trigger value")
_assert(auto_dict["status"]        == auto1.status.value,  "automation model_dump: status value")
_assert(isinstance(auto_dict["steps"], (list, tuple)),         "automation model_dump: steps is sequence")

# AutomationMapping round-trip
map_dict = mapping1.model_dump()
_assert(isinstance(map_dict, dict),                          "mapping model_dump: returns dict")
_assert(map_dict["mappingId"]          == mapping1.mappingId,          "mapping model_dump: mappingId")
_assert(map_dict["mappingFingerprint"] == mapping1.mappingFingerprint, "mapping model_dump: fingerprint")
_assert(map_dict["findingId"]          == mapping1.findingId,          "mapping model_dump: findingId")
_assert(map_dict["confidence"]         == mapping1.confidence,         "mapping model_dump: confidence")

# AutomationStatistics round-trip
stats_dict = stats.model_dump()
_assert(isinstance(stats_dict, dict),                         "stats model_dump: returns dict")
_assert(stats_dict["totalAutomations"] == stats.totalAutomations, "stats model_dump: total")
_assert("triggerCounts" in stats_dict,                        "stats model_dump: triggerCounts key")
_assert("actionCounts"  in stats_dict,                        "stats model_dump: actionCounts key")


# ===========================================================================
# 18. Immutability
# ===========================================================================
print("\n[18] Immutability")

# AutomationStep frozen
_assert_raises(Exception, setattr, step1, "name", "mutate", msg="AutomationStep: name frozen")
_assert_raises(Exception, setattr, step1, "stepNumber", 99,  msg="AutomationStep: stepNumber frozen")
_assert_raises(Exception, setattr, step1, "action", AutomationActionEnum.UPDATE_ALERT, msg="AutomationStep: action frozen")

# Automation frozen
_assert_raises(Exception, setattr, auto1, "name",     "mutate", msg="Automation: name frozen")
_assert_raises(Exception, setattr, auto1, "priority", 999,      msg="Automation: priority frozen")
_assert_raises(Exception, setattr, auto1, "status",   AutomationStatusEnum.ARCHIVED, msg="Automation: status frozen")
_assert_raises(Exception, setattr, auto1, "steps",    (),        msg="Automation: steps frozen")

# AutomationMapping frozen
_assert_raises(Exception, setattr, mapping1, "confidence",  0.0, msg="AutomationMapping: confidence frozen")
_assert_raises(Exception, setattr, mapping1, "findingId",   "x", msg="AutomationMapping: findingId frozen")
_assert_raises(Exception, setattr, mapping1, "automations", (), msg="AutomationMapping: automations frozen")


# ===========================================================================
# 19. Integration Helpers
# ===========================================================================
print("\n[19] Integration Helpers")

# rule_to_automation_reference
rule_ns = SimpleNamespace(ruleId="rule-abc-123")
rule_ref = rule_to_automation_reference(rule_ns)
_assert(rule_ref == "rule:rule-abc-123", "rule_to_automation_reference: correct format")
_assert(rule_ref.startswith("rule:"),   "rule_to_automation_reference: starts with 'rule:'")

# rule with no ruleId
rule_ns_empty = SimpleNamespace()
rule_ref_empty = rule_to_automation_reference(rule_ns_empty)
_assert(rule_ref_empty == "rule:", "rule_to_automation_reference: missing ruleId → 'rule:'")

# playbook_to_automation_reference
pb_ns = SimpleNamespace(playbookId="playbook-xyz-456")
pb_ref = playbook_to_automation_reference(pb_ns)
_assert(pb_ref == "playbook:playbook-xyz-456", "playbook_to_automation_reference: correct format")
_assert(pb_ref.startswith("playbook:"),        "playbook_to_automation_reference: starts with 'playbook:'")

# playbook with no playbookId
pb_ns_empty = SimpleNamespace()
pb_ref_empty = playbook_to_automation_reference(pb_ns_empty)
_assert(pb_ref_empty == "playbook:", "playbook_to_automation_reference: missing id → 'playbook:'")

# finding_to_automation_mapping
finding_ns = SimpleNamespace(findingId="finding-helper-1")
f_mapping = finding_to_automation_mapping(finding_ns, [auto1], TS, confidence=55.0)
_assert(f_mapping.findingId   == "finding-helper-1", "finding_to_automation_mapping: findingId set")
_assert(f_mapping.alertId     == "",                 "finding_to_automation_mapping: alertId empty")
_assert(f_mapping.reasoningId == "",                 "finding_to_automation_mapping: reasoningId empty")
_assert(f_mapping.confidence  == 55.0,               "finding_to_automation_mapping: confidence set")
_assert(len(f_mapping.automations) == 1,             "finding_to_automation_mapping: 1 automation")

# Determinism of finding_to_automation_mapping
f_mapping2 = finding_to_automation_mapping(finding_ns, [auto1], TS2, confidence=55.0)
_assert(f_mapping.mappingId == f_mapping2.mappingId, "finding_to_automation_mapping: deterministic ID")

# alert_to_automation_mapping
alert_ns = SimpleNamespace(alertId="alert-helper-1", findingId="finding-linked")
a_mapping = alert_to_automation_mapping(alert_ns, [auto1], TS, confidence=70.0)
_assert(a_mapping.alertId    == "alert-helper-1",  "alert_to_automation_mapping: alertId set")
_assert(a_mapping.findingId  == "finding-linked",  "alert_to_automation_mapping: findingId from alert")
_assert(a_mapping.reasoningId == "",               "alert_to_automation_mapping: reasoningId empty")
_assert(a_mapping.confidence  == 70.0,             "alert_to_automation_mapping: confidence set")

# alert_to_automation_mapping — no findingId on alert
alert_ns_nof = SimpleNamespace(alertId="alert-no-finding")
a_mapping_nof = alert_to_automation_mapping(alert_ns_nof, [auto1], TS)
_assert(a_mapping_nof.alertId   == "alert-no-finding", "alert_to_mapping: alertId set (no findingId)")
_assert(a_mapping_nof.findingId == "",                 "alert_to_mapping: findingId empty when absent")

# reasoning_to_automation_mapping
reasoning_ns = SimpleNamespace(reasoningId="reasoning-helper-1")
r_mapping = reasoning_to_automation_mapping(reasoning_ns, [auto1], TS, confidence=30.0)
_assert(r_mapping.reasoningId == "reasoning-helper-1", "reasoning_to_automation_mapping: reasoningId set")
_assert(r_mapping.findingId   == "",                   "reasoning_to_automation_mapping: findingId empty")
_assert(r_mapping.alertId     == "",                   "reasoning_to_automation_mapping: alertId empty")
_assert(r_mapping.confidence  == 30.0,                 "reasoning_to_automation_mapping: confidence set")

# Determinism
r_mapping2 = reasoning_to_automation_mapping(reasoning_ns, [auto1], TS2, confidence=30.0)
_assert(r_mapping.mappingId == r_mapping2.mappingId, "reasoning_to_automation_mapping: deterministic")


# ===========================================================================
# 20. Edge Cases
# ===========================================================================
print("\n[20] Edge Cases")

# build_automation with duplicate steps deduped at sort level (same stepId)
step_dup = build_automation_step("dup-parent", 1, "Step", AutomationActionEnum.CREATE_ALERT, TS)
auto_dup_steps = build_automation(
    "Dup Steps Test", AutomationTriggerEnum.MANUAL, TS, steps=[step_dup, step_dup]
)
# The steps tuple may contain both (sort does not deduplicate), but IDs are same
_assert(len(auto_dup_steps.steps) == 2, "duplicate steps: both present (sort doesn't dedup)")

# build_automation_mapping with empty automations list
mapping_empty_autos = build_automation_mapping([], TS, finding_id="f-edge-1")
_assert(len(mapping_empty_autos.automations) == 0, "mapping: empty automations list accepted")
_assert(len(mapping_empty_autos.mappingKey)  == 32, "mapping: empty autos still has 32-char key")

# build_automation_step with whitespace-only description
step_ws = build_automation_step("pid", 1, "WS Step", AutomationActionEnum.UPDATE_ALERT, TS, description="   ")
_assert(step_ws.description == "   ", "step: whitespace description preserved as-is")

# build_automation with all status values
for status in AutomationStatusEnum:
    a = build_automation(f"Auto-{status.value}", AutomationTriggerEnum.MANUAL, TS, status=status)
    _assert(a.status == status, f"build_automation: status {status.value} round-trips")

# build_automation with all trigger values
for trigger in AutomationTriggerEnum:
    a = build_automation(f"Auto-{trigger.value}", trigger, TS)
    _assert(a.trigger == trigger, f"build_automation: trigger {trigger.value} round-trips")

# build_automation_step with all action values
for action in AutomationActionEnum:
    s = build_automation_step("pid", 1, f"Step-{action.value}", action, TS)
    _assert(s.action == action, f"build_step: action {action.value} round-trips")

# mappingKey stable regardless of automation order
auto_x = build_automation("X", AutomationTriggerEnum.MANUAL, TS, priority=1)
auto_y = build_automation("Y", AutomationTriggerEnum.MANUAL, TS, priority=2)
mk_xy = mappingKey("f1", "", "", (auto_x.automationId, auto_y.automationId))
mk_yx = mappingKey("f1", "", "", (auto_y.automationId, auto_x.automationId))
_assert(mk_xy == mk_yx, "mappingKey: order-independent for automations")

# find returns None on empty list
_assert(find_automation([]) is None, "find_automation: empty list no criteria → None")

# filter on empty list returns empty list
_assert(filter_automations([]) == [], "filter_automations: empty list → []")

# merge of two empty lists
merged_empty = merge_automations([], [])
_assert(merged_empty == [], "merge_automations: empty + empty → []")

# merge of empty mappings
merged_empty_m = merge_automation_mappings([], [])
_assert(merged_empty_m == [], "merge_mappings: empty + empty → []")

# remove from empty list
removed_empty = remove_automation([], "any-id")
_assert(removed_empty == [], "remove_automation: empty list → []")

# Priority boundary: exactly 1
a_p1 = build_automation("P1", AutomationTriggerEnum.MANUAL, TS, priority=1)
_assert(a_p1.priority == 1, "automation: priority=1 accepted")

# Large parameters dict
big_params = {f"key_{i}": f"value_{i}" for i in range(100)}
step_big = build_automation_step("pid", 1, "BigParams", AutomationActionEnum.CREATE_ALERT, TS,
                                  parameters=big_params)
_assert(len(step_big.parameters) == 100, "step: large parameters dict preserved")

# Parameters dict is a copy (not reference to input)
original_params = {"mutable": "original"}
step_param_copy = build_automation_step("pid", 1, "ParamCopy", AutomationActionEnum.UPDATE_ALERT, TS,
                                         parameters=original_params)
original_params["mutable"] = "changed"
_assert(step_param_copy.parameters["mutable"] == "original", "step: parameters are a copy, not reference")


# ===========================================================================
# 21. Zero Randomness / Deterministic Fingerprints
# ===========================================================================
print("\n[21] Zero Randomness / Deterministic Fingerprints")

# Build same automation 10 times — IDs and keys must be identical
_zr_ref = build_automation(
    name       = "Repeatable Auto",
    trigger    = AutomationTriggerEnum.FINDING_CREATED,
    created_at = TS,
    steps      = [step1, step2],
    priority   = 42,
    status     = AutomationStatusEnum.ACTIVE,
)
for i in range(10):
    a = build_automation(
        name    = "Repeatable Auto",
        trigger = AutomationTriggerEnum.FINDING_CREATED,
        created_at = TS,
        steps   = [step1, step2],
        priority = 42,
        status   = AutomationStatusEnum.ACTIVE,
    )
    _assert(a.automationId  == _zr_ref.automationId,  f"zero-randomness run {i}: automationId stable")
    _assert(a.automationKey == _zr_ref.automationKey, f"zero-randomness run {i}: automationKey stable")

# Build same mapping 5 times
for i in range(5):
    m = build_automation_mapping([auto1], TS, finding_id="finding-abc", confidence=80.0)
    _assert(m.mappingId          == mapping1.mappingId,          f"zero-randomness mapping {i}: mappingId stable")
    _assert(m.mappingFingerprint == mapping1.mappingFingerprint, f"zero-randomness mapping {i}: fingerprint stable")

# Build same step 5 times
for i in range(5):
    s = build_automation_step("parent-id", 1, "Create Alert", AutomationActionEnum.CREATE_ALERT, TS)
    _assert(s.stepId  == step1.stepId,  f"zero-randomness step {i}: stepId stable")
    _assert(s.stepKey == step1.stepKey, f"zero-randomness step {i}: stepKey stable")

# Fingerprint changes when content changes
mapping_changed = build_automation_mapping([auto1], TS, finding_id="finding-DIFFERENT", confidence=80.0)
_assert(mapping1.mappingFingerprint != mapping_changed.mappingFingerprint,
        "fingerprint changes on content change")


# ===========================================================================
# 22. Large Dataset Stability
# ===========================================================================
print("\n[22] Large Dataset Stability")

large_autos: list = []
for i in range(200):
    step_l = build_automation_step(f"parent-{i}", 1, f"Step-{i}", AutomationActionEnum.CREATE_ALERT, TS)
    auto_l = build_automation(
        name       = f"Automation-{i:04d}",
        trigger    = AutomationTriggerEnum.FINDING_CREATED,
        created_at = TS,
        steps      = [step_l],
        priority   = (i % 100) + 1,
        status     = AutomationStatusEnum.ACTIVE if i % 2 == 0 else AutomationStatusEnum.DRAFT,
    )
    large_autos.append(auto_l)

_assert(len(large_autos) == 200, "large dataset: 200 automations built")

# All IDs unique
all_ids = [a.automationId for a in large_autos]
_assert(len(set(all_ids)) == 200, "large dataset: all 200 IDs unique")

# Statistics on large dataset
large_stats = build_automation_statistics(large_autos)
_assert(large_stats.totalAutomations == 200,  "large stats: total 200")
_assert(large_stats.activeAutomations == 100, "large stats: active 100")
_assert(large_stats.draftAutomations  == 100, "large stats: draft 100")
_assert(large_stats.averagePriority   == round(sum(a.priority for a in large_autos) / 200, 4),
        "large stats: averagePriority correct")

# Sort large dataset
sorted_large = sort_automations(large_autos, by="priority", ascending=True)
_assert(len(sorted_large) == 200, "large sort: 200 items")
for i in range(len(sorted_large) - 1):
    _assert(
        sorted_large[i].priority < sorted_large[i+1].priority or
        (sorted_large[i].priority == sorted_large[i+1].priority and
         sorted_large[i].automationId <= sorted_large[i+1].automationId),
        f"large sort: stable order at index {i}"
    )

# Filter large dataset
active_large = filter_automations(large_autos, status=AutomationStatusEnum.ACTIVE)
_assert(len(active_large) == 100, "large filter: 100 active")

# Merge large dataset with itself (idempotent)
merged_large = merge_automations(large_autos, large_autos)
_assert(len(merged_large) == 200, "large merge: deduplication preserves 200")

# Group large dataset
grouped_large = group_automations(large_autos, group_by="status")
_assert(len(grouped_large["ACTIVE"]) == 100, "large group: ACTIVE has 100")
_assert(len(grouped_large["DRAFT"])  == 100, "large group: DRAFT has 100")

# Large mapping merge
large_mappings = [
    build_automation_mapping([auto_l], TS, finding_id=f"finding-{i}", confidence=float(i % 101))
    for i, auto_l in enumerate(large_autos[:50])
]
merged_large_m = merge_automation_mappings(large_mappings, large_mappings)
_assert(len(merged_large_m) == 50, "large mapping merge: 50 distinct")


# ===========================================================================
# 23. Additional Coverage — Validators edge cases
# ===========================================================================
print("\n[23] Additional Coverage")

# validate_automation_mapping — whitespace source IDs treated as empty
_assert_raises(InvalidAutomationMappingError, validate_automation_mapping,
               "  ", "  ", "  ", 50.0, TS,
               msg="whitespace-only source IDs rejected")

# validate_automation_step — non-integer step_number
_assert_raises(InvalidAutomationStepError, validate_automation_step,
               1.5, "Step", AutomationActionEnum.CREATE_ALERT, TS,
               msg="float step_number rejected")

# validate_automation — non-integer priority
_assert_raises(InvalidAutomationError, validate_automation,
               "Name", AutomationStatusEnum.DRAFT, AutomationTriggerEnum.MANUAL, 1.5, TS,
               msg="float priority rejected")

# validate_automation_mapping — integer confidence (should pass, it's castable)
try:
    validate_automation_mapping("f1", "", "", 50, TS)
    _assert(True, "validate_automation_mapping: int confidence accepted")
except Exception:
    _assert(False, "validate_automation_mapping: int confidence should be accepted")

# update_automation — change only description
updated_desc = update_automation(base_list3, auto1.automationId, TS2, description="New Desc")
found_desc = next((a for a in updated_desc if "Renamed" not in a.name and a.description == "New Desc"), None)
_assert(found_desc is not None, "update_automation: description-only change works")

# update_automation — change only priority
updated_prio = update_automation(base_list3, auto1.automationId, TS2, priority=5)
found_prio = next((a for a in updated_prio if a.priority == 5), None)
_assert(found_prio is not None, "update_automation: priority-only change works")

# add_automation preserves order (new item at end before any sort)
list_order = [auto_draft]
list_order2 = add_automation(list_order, auto1)
list_order3 = add_automation(list_order2, auto_active)
_assert(list_order3[0].automationId == auto_draft.automationId,  "add_automation: preserves order [0]")
_assert(list_order3[1].automationId == auto1.automationId,       "add_automation: preserves order [1]")
_assert(list_order3[2].automationId == auto_active.automationId, "add_automation: preserves order [2]")

# remove_automation_step — automation with zero steps after removal
auto_one_step = build_automation("One Step", AutomationTriggerEnum.MANUAL, TS, steps=[step1])
auto_zero_steps = remove_automation_step(auto_one_step, step1.stepId, TS2)
_assert(len(auto_zero_steps.steps) == 0, "remove_step: automation with 0 steps valid")

# merge_automations — empty base, non-empty incoming
merged_from_empty = merge_automations([], [auto1, auto_draft])
_assert(len(merged_from_empty) == 2, "merge: empty base + incoming = incoming")

# merge_automations — non-empty base, empty incoming
merged_to_empty = merge_automations([auto1, auto_draft], [])
_assert(len(merged_to_empty) == 2, "merge: base + empty incoming = base")

# Confidence precision
mapping_precise = build_automation_mapping([auto1], TS, finding_id="f1", confidence=75.1234)
_assert(mapping_precise.confidence == 75.1234, "confidence 4 decimal places preserved")

mapping_rounded = build_automation_mapping([auto1], TS, finding_id="f1", confidence=75.12345678)
_assert(isinstance(mapping_rounded.confidence, float), "confidence: float type maintained")

# stepKey uses str(step_number) — different ints produce different keys
for n in range(1, 11):
    sk = stepKey("same-parent", n)
    _assert(len(sk) == 32, f"stepKey stepNumber={n}: 32 chars")
    for m in range(1, 11):
        if m != n:
            _assert(sk != stepKey("same-parent", m), f"stepKey: {n} != {m} produces different keys")
            break


# ===========================================================================
# 24. Model Field Presence
# ===========================================================================
print("\n[24] Model Field Presence")

# AutomationStep fields
_assert(hasattr(step1, "stepId"),      "AutomationStep has stepId")
_assert(hasattr(step1, "stepKey"),     "AutomationStep has stepKey")
_assert(hasattr(step1, "stepNumber"),  "AutomationStep has stepNumber")
_assert(hasattr(step1, "name"),        "AutomationStep has name")
_assert(hasattr(step1, "description"), "AutomationStep has description")
_assert(hasattr(step1, "action"),      "AutomationStep has action")
_assert(hasattr(step1, "parameters"),  "AutomationStep has parameters")
_assert(hasattr(step1, "createdAt"),   "AutomationStep has createdAt")

# Automation fields
_assert(hasattr(auto1, "automationId"),  "Automation has automationId")
_assert(hasattr(auto1, "automationKey"), "Automation has automationKey")
_assert(hasattr(auto1, "name"),          "Automation has name")
_assert(hasattr(auto1, "description"),   "Automation has description")
_assert(hasattr(auto1, "status"),        "Automation has status")
_assert(hasattr(auto1, "trigger"),       "Automation has trigger")
_assert(hasattr(auto1, "steps"),         "Automation has steps")
_assert(hasattr(auto1, "priority"),      "Automation has priority")
_assert(hasattr(auto1, "createdAt"),     "Automation has createdAt")

# AutomationMapping fields
_assert(hasattr(mapping1, "mappingId"),          "AutomationMapping has mappingId")
_assert(hasattr(mapping1, "mappingKey"),         "AutomationMapping has mappingKey")
_assert(hasattr(mapping1, "findingId"),          "AutomationMapping has findingId")
_assert(hasattr(mapping1, "alertId"),            "AutomationMapping has alertId")
_assert(hasattr(mapping1, "reasoningId"),        "AutomationMapping has reasoningId")
_assert(hasattr(mapping1, "automations"),        "AutomationMapping has automations")
_assert(hasattr(mapping1, "confidence"),         "AutomationMapping has confidence")
_assert(hasattr(mapping1, "mappingFingerprint"), "AutomationMapping has mappingFingerprint")
_assert(hasattr(mapping1, "createdAt"),          "AutomationMapping has createdAt")

# AutomationStatistics fields
_assert(hasattr(stats_empty, "totalAutomations"),    "AutomationStatistics has totalAutomations")
_assert(hasattr(stats_empty, "activeAutomations"),   "AutomationStatistics has activeAutomations")
_assert(hasattr(stats_empty, "draftAutomations"),    "AutomationStatistics has draftAutomations")
_assert(hasattr(stats_empty, "disabledAutomations"), "AutomationStatistics has disabledAutomations")
_assert(hasattr(stats_empty, "archivedAutomations"), "AutomationStatistics has archivedAutomations")
_assert(hasattr(stats_empty, "averagePriority"),     "AutomationStatistics has averagePriority")
_assert(hasattr(stats_empty, "triggerCounts"),       "AutomationStatistics has triggerCounts")
_assert(hasattr(stats_empty, "actionCounts"),        "AutomationStatistics has actionCounts")


# ===========================================================================
# Final Report
# ===========================================================================
print()
print("=" * 60)
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print(f"  TOTAL  : {_PASS + _FAIL}")
print("=" * 60)

if _ERRORS:
    print("\nFailed assertions:")
    for e in _ERRORS:
        print(f"  {e}")

if _FAIL == 0:
    print("\nALL ASSERTIONS PASSED ✓")
    sys.exit(0)
else:
    print(f"\n{_FAIL} ASSERTION(S) FAILED ✗")
    sys.exit(1)
