"""
Smoke Test — Playbook Engine
==============================
Phase A4.4.5 — Comprehensive deterministic test suite.

Covers
------
- Enumerations: PlaybookSeverityEnum, PlaybookStatusEnum, PlaybookStepTypeEnum
- Engine version constant
- Exception hierarchy
- Deterministic IDs: stepKey, playbookKey, mappingKey, mappingFingerprint
- Builders: build_playbook_step, build_playbook, build_playbook_mapping,
  build_playbook_statistics
- Validators: validate_playbook_step, validate_playbook, validate_playbook_mapping
- Playbook Operations: add, update, remove, merge
- Step Operations: add, update, remove, merge
- Mapping Operations: add, remove, merge
- Search: find_playbook, find_playbook_step, find_playbook_mapping
- Sorting: sort_playbooks, sort_playbook_steps, sort_playbook_mappings
- Filtering: filter_playbooks, filter_playbook_steps, filter_playbook_mappings
- Grouping: group_playbooks, group_playbook_steps, group_playbook_mappings
- Statistics: build_playbook_statistics (extended fields)
- Serialization: model_dump round-trip
- Immutability: frozen model enforcement
- Integration helpers
- Edge cases, zero randomness, deterministic fingerprints, large dataset stability

Target: 550+ assertions
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
from services.playbook_service import (
    # Engine version
    PLAYBOOK_ENGINE_VERSION,
    # Enums
    PlaybookSeverityEnum, PlaybookStatusEnum, PlaybookStepTypeEnum,
    # Exceptions
    PlaybookEngineError, InvalidPlaybookError,
    InvalidPlaybookStepError, InvalidPlaybookMappingError,
    # Models
    PlaybookStep, Playbook, PlaybookMapping, PlaybookStatistics,
    # Key derivation
    stepKey, playbookKey, mappingKey, mappingFingerprint,
    # Validators
    validate_playbook_step, validate_playbook, validate_playbook_mapping,
    # Builders
    build_playbook_step, build_playbook, build_playbook_mapping,
    build_playbook_statistics,
    # Playbook operations
    add_playbook, update_playbook, remove_playbook, merge_playbooks,
    # Step operations
    add_playbook_step, update_playbook_step,
    remove_playbook_step, merge_playbook_steps,
    # Mapping operations
    add_playbook_mapping, remove_playbook_mapping, merge_playbook_mappings,
    # Search
    find_playbook, find_playbook_step, find_playbook_mapping,
    # Sorting
    sort_playbooks, sort_playbook_steps, sort_playbook_mappings,
    # Filtering
    filter_playbooks, filter_playbook_steps, filter_playbook_mappings,
    # Grouping
    group_playbooks, group_playbook_steps, group_playbook_mappings,
    # Integration helpers
    mitre_to_playbook_reference, cve_to_playbook_reference,
    ioc_to_playbook_reference, threat_to_playbook_reference,
    finding_to_playbook_mapping, alert_to_playbook_mapping,
    reasoning_to_playbook_mapping,
)

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T00:00:00Z"

print("=" * 60)
print("Playbook Engine Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. Engine Version
# ===========================================================================
print("\n[1] Engine Version")
_assert(PLAYBOOK_ENGINE_VERSION == "playbook-engine-v1", "engine version value")
_assert(isinstance(PLAYBOOK_ENGINE_VERSION, str), "engine version is str")

# ===========================================================================
# 2. Enumerations
# ===========================================================================
print("\n[2] Enumerations")
_assert(PlaybookSeverityEnum.LOW.value      == "LOW",      "sev LOW")
_assert(PlaybookSeverityEnum.MEDIUM.value   == "MEDIUM",   "sev MEDIUM")
_assert(PlaybookSeverityEnum.HIGH.value     == "HIGH",     "sev HIGH")
_assert(PlaybookSeverityEnum.CRITICAL.value == "CRITICAL", "sev CRITICAL")

_assert(PlaybookStatusEnum.DRAFT.value      == "DRAFT",      "status DRAFT")
_assert(PlaybookStatusEnum.ACTIVE.value     == "ACTIVE",     "status ACTIVE")
_assert(PlaybookStatusEnum.DEPRECATED.value == "DEPRECATED", "status DEPRECATED")
_assert(PlaybookStatusEnum.ARCHIVED.value   == "ARCHIVED",   "status ARCHIVED")

_assert(PlaybookStepTypeEnum.MANUAL.value        == "MANUAL",        "type MANUAL")
_assert(PlaybookStepTypeEnum.AUTOMATED.value     == "AUTOMATED",     "type AUTOMATED")
_assert(PlaybookStepTypeEnum.VERIFICATION.value  == "VERIFICATION",  "type VERIFICATION")
_assert(PlaybookStepTypeEnum.CONTAINMENT.value   == "CONTAINMENT",   "type CONTAINMENT")
_assert(PlaybookStepTypeEnum.ERADICATION.value   == "ERADICATION",   "type ERADICATION")
_assert(PlaybookStepTypeEnum.RECOVERY.value      == "RECOVERY",      "type RECOVERY")

_assert(len(list(PlaybookSeverityEnum))  == 4, "4 severity values")
_assert(len(list(PlaybookStatusEnum))    == 4, "4 status values")
_assert(len(list(PlaybookStepTypeEnum))  == 6, "6 step type values")

# ===========================================================================
# 3. Exception Hierarchy
# ===========================================================================
print("\n[3] Exception Hierarchy")
_assert(issubclass(InvalidPlaybookError,        PlaybookEngineError), "InvalidPlaybookError is subclass")
_assert(issubclass(InvalidPlaybookStepError,    PlaybookEngineError), "InvalidPlaybookStepError is subclass")
_assert(issubclass(InvalidPlaybookMappingError, PlaybookEngineError), "InvalidPlaybookMappingError is subclass")
_assert(issubclass(PlaybookEngineError,         Exception),           "PlaybookEngineError is subclass of Exception")


# ===========================================================================
# 4. Deterministic ID Helpers
# ===========================================================================
print("\n[4] Deterministic ID Helpers")

PB_ID_SEED = "test-playbook-id-seed"
sk1 = stepKey(PB_ID_SEED, 1)
sk2 = stepKey(PB_ID_SEED, 1)
sk3 = stepKey(PB_ID_SEED, 2)
_assert(sk1 == sk2,       "stepKey deterministic")
_assert(sk1 != sk3,       "stepKey different stepNumbers differ")
_assert(len(sk1) == 32,   "stepKey length 32")
_assert(sk1.islower(),    "stepKey lowercase hex")

pk1 = playbookKey("Ransomware Response", PlaybookSeverityEnum.CRITICAL, ("id-a", "id-b"))
pk2 = playbookKey("Ransomware Response", PlaybookSeverityEnum.CRITICAL, ("id-b", "id-a"))  # order-independent
pk3 = playbookKey("Ransomware Response", PlaybookSeverityEnum.HIGH,     ("id-a", "id-b"))
_assert(pk1 == pk2,     "playbookKey order-independent")
_assert(pk1 != pk3,     "playbookKey different severity differs")
_assert(len(pk1) == 32, "playbookKey length 32")

mk1 = mappingKey("fid-1", "aid-1", "rid-1", ("pb-a", "pb-b"))
mk2 = mappingKey("fid-1", "aid-1", "rid-1", ("pb-b", "pb-a"))  # order-independent
mk3 = mappingKey("fid-2", "aid-1", "rid-1", ("pb-a", "pb-b"))
_assert(mk1 == mk2,     "mappingKey order-independent")
_assert(mk1 != mk3,     "mappingKey different findingId differs")
_assert(len(mk1) == 32, "mappingKey length 32")

fp1 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("pb-a", "pb-b"))
fp2 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("pb-b", "pb-a"))
fp3 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("pb-a", "pb-c"))
_assert(fp1 == fp2,     "mappingFingerprint order-independent")
_assert(fp1 != fp3,     "mappingFingerprint different ids differ")
_assert(len(fp1) == 32, "mappingFingerprint length 32")
_assert(mk1 != fp1,     "mappingKey and mappingFingerprint differ")


# ===========================================================================
# 5. Validators
# ===========================================================================
print("\n[5] Validators")

# validate_playbook_step — happy path
validate_playbook_step(1, "Isolate", PlaybookStepTypeEnum.CONTAINMENT, TS)
_assert(True, "validate_playbook_step happy path")

# validate_playbook_step — bad step_number
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, 0, "T", PlaybookStepTypeEnum.MANUAL, TS,
               msg="stepNumber 0 rejected")
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, -1, "T", PlaybookStepTypeEnum.MANUAL, TS,
               msg="stepNumber -1 rejected")
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, 1, "", PlaybookStepTypeEnum.MANUAL, TS,
               msg="empty title rejected")
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, 1, "T", "NOT_AN_ENUM", TS,
               msg="bad step_type rejected")
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, 1, "T", PlaybookStepTypeEnum.MANUAL, "",
               msg="empty createdAt rejected")

# validate_playbook — happy path
validate_playbook("Test", PlaybookSeverityEnum.HIGH, PlaybookStatusEnum.DRAFT, TS)
_assert(True, "validate_playbook happy path")

_assert_raises(InvalidPlaybookError, validate_playbook, "", PlaybookSeverityEnum.HIGH, PlaybookStatusEnum.DRAFT, TS,
               msg="empty name rejected")
_assert_raises(InvalidPlaybookError, validate_playbook, "X", "BAD", PlaybookStatusEnum.DRAFT, TS,
               msg="bad severity rejected")
_assert_raises(InvalidPlaybookError, validate_playbook, "X", PlaybookSeverityEnum.HIGH, "BAD", TS,
               msg="bad status rejected")
_assert_raises(InvalidPlaybookError, validate_playbook, "X", PlaybookSeverityEnum.HIGH, PlaybookStatusEnum.DRAFT, "",
               msg="empty createdAt rejected")

# validate_playbook_mapping — happy path
validate_playbook_mapping("fid-1", "", "", 50.0, TS)
_assert(True, "validate_playbook_mapping happy path")

_assert_raises(InvalidPlaybookMappingError, validate_playbook_mapping, "", "", "", 50.0, TS,
               msg="all empty sources rejected")
_assert_raises(InvalidPlaybookMappingError, validate_playbook_mapping, "fid", "", "", -1.0, TS,
               msg="confidence -1 rejected")
_assert_raises(InvalidPlaybookMappingError, validate_playbook_mapping, "fid", "", "", 101.0, TS,
               msg="confidence 101 rejected")
_assert_raises(InvalidPlaybookMappingError, validate_playbook_mapping, "fid", "", "", 50.0, "",
               msg="empty createdAt rejected")


# ===========================================================================
# 6. Builder: build_playbook_step
# ===========================================================================
print("\n[6] build_playbook_step")

step_a = build_playbook_step(
    playbook_id        = "pb-001",
    step_number        = 1,
    title              = "Isolate Host",
    step_type          = PlaybookStepTypeEnum.CONTAINMENT,
    created_at         = TS,
    description        = "Remove from network",
    expected_outcome   = "Host offline",
    related_techniques = ["T1021", "t1078", "T1021"],   # dupes + mixed case
    related_cves       = ["CVE-2021-44228", "cve-2021-44228"],  # dupes
    related_iocs       = ["192.168.1.100", "malware.exe"],
)
step_a2 = build_playbook_step(
    playbook_id="pb-001", step_number=1, title="Isolate Host",
    step_type=PlaybookStepTypeEnum.CONTAINMENT, created_at=TS,
    description="Remove from network", expected_outcome="Host offline",
    related_techniques=["t1078", "T1021"],
    related_cves=["CVE-2021-44228"],
    related_iocs=["192.168.1.100", "malware.exe"],
)

_assert(isinstance(step_a, PlaybookStep),       "step is PlaybookStep")
_assert(step_a.stepId  == step_a2.stepId,       "stepId deterministic")
_assert(step_a.stepKey == step_a2.stepKey,       "stepKey deterministic")
_assert(len(step_a.stepId)  == 36,              "stepId is UUID")
_assert(len(step_a.stepKey) == 32,              "stepKey is 32 chars")
_assert(step_a.stepNumber   == 1,               "stepNumber preserved")
_assert(step_a.title        == "Isolate Host",  "title stripped")
_assert(step_a.stepType     == PlaybookStepTypeEnum.CONTAINMENT, "stepType preserved")
_assert(step_a.relatedTechniques == ("T1021", "T1078"), "techniques deduped+upper+sorted")
_assert(step_a.relatedCVEs  == ("CVE-2021-44228",),     "CVEs deduped+upper")
_assert(step_a.relatedIOCs  == ("192.168.1.100", "malware.exe"), "IOCs sorted")
_assert(step_a.createdAt    == TS,              "createdAt preserved")

# Different step number → different key
step_b = build_playbook_step("pb-001", 2, "Eradicate", PlaybookStepTypeEnum.ERADICATION, TS)
_assert(step_b.stepId  != step_a.stepId,  "different stepNumber → different ID")
_assert(step_b.stepKey != step_a.stepKey, "different stepNumber → different key")

# Different playbook_id → different key
step_c = build_playbook_step("pb-002", 1, "Isolate Host", PlaybookStepTypeEnum.CONTAINMENT, TS)
_assert(step_c.stepId  != step_a.stepId,  "different playbookId → different stepId")

# Validation via validate=False
step_noval = build_playbook_step("pb-001", 1, "T", PlaybookStepTypeEnum.MANUAL, TS, validate=False)
_assert(step_noval.stepNumber == 1, "validate=False still builds")

# validate=True with bad args raises
_assert_raises(InvalidPlaybookStepError, build_playbook_step, "pb-001", 0, "T", PlaybookStepTypeEnum.MANUAL, TS,
               msg="build_playbook_step validates stepNumber")


# ===========================================================================
# 7. Builder: build_playbook
# ===========================================================================
print("\n[7] build_playbook")

pb1 = build_playbook(
    name                  = "Ransomware Response",
    severity              = PlaybookSeverityEnum.CRITICAL,
    created_at            = TS,
    description           = "Full ransomware containment and recovery procedure.",
    status                = PlaybookStatusEnum.ACTIVE,
    steps                 = [step_a, step_b],
    related_threat_actors = ["APT28", "Wizard Spider", "APT28"],  # dupes
    related_campaigns     = ["NotPetya", "Ryuk"],
    confidence            = 92.5,
)
pb1_dup = build_playbook(
    name="Ransomware Response", severity=PlaybookSeverityEnum.CRITICAL,
    created_at=TS, steps=[step_b, step_a],   # reversed order
    status=PlaybookStatusEnum.ACTIVE,
    related_threat_actors=["Wizard Spider", "APT28"],
    related_campaigns=["Ryuk", "NotPetya"],
    confidence=92.5,
)

_assert(isinstance(pb1, Playbook),              "pb1 is Playbook")
_assert(pb1.playbookId  == pb1_dup.playbookId,  "playbookId deterministic")
_assert(pb1.playbookKey == pb1_dup.playbookKey, "playbookKey deterministic")
_assert(len(pb1.playbookId)  == 36,             "playbookId is UUID")
_assert(len(pb1.playbookKey) == 32,             "playbookKey is 32 chars")
_assert(pb1.name        == "Ransomware Response", "name preserved")
_assert(pb1.severity    == PlaybookSeverityEnum.CRITICAL, "severity preserved")
_assert(pb1.status      == PlaybookStatusEnum.ACTIVE,     "status preserved")
_assert(pb1.confidence  == 92.5,                "confidence preserved")
_assert(pb1.createdAt   == TS,                  "createdAt preserved")
_assert(pb1.steps[0].stepNumber == 1,           "steps sorted by stepNumber")
_assert(pb1.steps[1].stepNumber == 2,           "steps[1] stepNumber=2")
_assert(pb1.relatedThreatActors == ("APT28", "Wizard Spider"), "threat actors deduped+sorted")
_assert(pb1.relatedCampaigns    == ("NotPetya", "Ryuk"),        "campaigns sorted")

# Confidence clamping
pb_clamp_hi = build_playbook("X", PlaybookSeverityEnum.LOW, TS, confidence=200.0)
pb_clamp_lo = build_playbook("X", PlaybookSeverityEnum.LOW, TS, confidence=-50.0)
_assert(pb_clamp_hi.confidence == 100.0, "confidence clamped to 100")
_assert(pb_clamp_lo.confidence == 0.0,   "confidence clamped to 0")

# Default status is DRAFT
pb_draft = build_playbook("DraftPB", PlaybookSeverityEnum.MEDIUM, TS)
_assert(pb_draft.status == PlaybookStatusEnum.DRAFT, "default status DRAFT")

# Empty steps
pb_empty = build_playbook("EmptySteps", PlaybookSeverityEnum.LOW, TS)
_assert(len(pb_empty.steps) == 0, "empty steps tuple")
_assert(pb_empty.steps == (),     "steps is empty tuple")

# Validation error
_assert_raises(InvalidPlaybookError, build_playbook, "", PlaybookSeverityEnum.HIGH, TS,
               msg="build_playbook validates name")


# ===========================================================================
# 8. Builder: build_playbook_mapping
# ===========================================================================
print("\n[8] build_playbook_mapping")

pb2 = build_playbook("Phishing Response", PlaybookSeverityEnum.HIGH, TS,
                     status=PlaybookStatusEnum.ACTIVE, confidence=75.0)

m1 = build_playbook_mapping(
    playbooks    = [pb1, pb2],
    created_at   = TS,
    finding_id   = "fid-001",
    alert_id     = "aid-001",
    confidence   = 80.0,
)
m1_dup = build_playbook_mapping(
    playbooks=[pb2, pb1],  # reversed
    created_at=TS, finding_id="fid-001", alert_id="aid-001", confidence=80.0,
)

_assert(isinstance(m1, PlaybookMapping),          "m1 is PlaybookMapping")
_assert(m1.mappingId  == m1_dup.mappingId,        "mappingId deterministic")
_assert(m1.mappingKey == m1_dup.mappingKey,        "mappingKey deterministic")
_assert(m1.mappingFingerprint == m1_dup.mappingFingerprint, "mappingFingerprint deterministic")
_assert(len(m1.mappingId)          == 36, "mappingId is UUID")
_assert(len(m1.mappingKey)         == 32, "mappingKey is 32 chars")
_assert(len(m1.mappingFingerprint) == 32, "mappingFingerprint is 32 chars")
_assert(m1.findingId  == "fid-001",  "findingId preserved")
_assert(m1.alertId    == "aid-001",  "alertId preserved")
_assert(m1.reasoningId == "",        "reasoningId empty when not supplied")
_assert(m1.confidence == 80.0,       "confidence preserved")
_assert(len(m1.playbooks) == 2,      "both playbooks in mapping")
# CRITICAL playbook (pb1) should come first (severity DESC)
_assert(m1.playbooks[0].playbookId == pb1.playbookId, "CRITICAL pb sorted first")
_assert(m1.mappingKey != m1.mappingFingerprint, "key and fingerprint differ")

# Different content → different fingerprint
m2 = build_playbook_mapping([pb2], TS, finding_id="fid-001", alert_id="aid-001", confidence=80.0)
_assert(m1.mappingFingerprint != m2.mappingFingerprint, "different playbooks → different fingerprint")

# Validation: no source
_assert_raises(InvalidPlaybookMappingError,
               build_playbook_mapping, [pb1], TS,
               msg="no finding/alert/reasoning rejected")

# Confidence boundaries
m_100 = build_playbook_mapping([pb1], TS, finding_id="f", confidence=100.0)
m_0   = build_playbook_mapping([pb1], TS, finding_id="f", confidence=0.0)
_assert(m_100.confidence == 100.0, "confidence 100 accepted")
_assert(m_0.confidence   == 0.0,   "confidence 0 accepted")


# ===========================================================================
# 9. Playbook Operations
# ===========================================================================
print("\n[9] Playbook Operations")

pb3 = build_playbook("Insider Threat", PlaybookSeverityEnum.MEDIUM, TS,
                     status=PlaybookStatusEnum.DRAFT)
pb4 = build_playbook("Supply Chain Attack", PlaybookSeverityEnum.HIGH, TS,
                     status=PlaybookStatusEnum.DEPRECATED)

# add_playbook
pl = []
pl = add_playbook(pl, pb1)
_assert(len(pl) == 1, "add first playbook")
pl = add_playbook(pl, pb2)
_assert(len(pl) == 2, "add second playbook")
pl_dup = add_playbook(pl, pb1)  # duplicate
_assert(len(pl_dup) == 2, "duplicate not added")
_assert(pl_dup[0].playbookId == pl[0].playbookId, "duplicate add preserves existing")

# Result is sorted by playbookId
_assert(pl[0].playbookId <= pl[1].playbookId, "add_playbook returns sorted list")

# remove_playbook
pl2 = remove_playbook(pl, pb1.playbookId)
_assert(len(pl2) == 1,                         "playbook removed")
_assert(pl2[0].playbookId == pb2.playbookId,   "correct playbook remains")
# Idempotent remove
pl3 = remove_playbook(pl2, pb1.playbookId)
_assert(len(pl3) == 1, "remove non-existent is idempotent")

# update_playbook — change description only
pl4 = add_playbook([], pb1)
pl5 = update_playbook(pl4, pb1.playbookId, TS2, description="Updated description")
_assert(len(pl5) == 1,                          "update returns same count")
_assert(pl5[0].description == "Updated description", "description updated")
_assert(pl5[0].playbookId  == pb1.playbookId,   "playbookId preserved when name/severity unchanged")
_assert(pl5[0].name        == pb1.name,          "name unchanged")

# update_playbook — change name → new ID
pl6 = update_playbook(pl4, pb1.playbookId, TS2, name="New Playbook Name")
_assert(pl6[0].name == "New Playbook Name",      "name updated")
_assert(pl6[0].playbookId != pb1.playbookId,     "playbookId recomputed on name change")

# update_playbook — not found
pl_nf = update_playbook(pl4, "non-existent-id", TS2, description="X")
_assert(len(pl_nf) == 1,             "update not-found returns unchanged list")
_assert(pl_nf[0].playbookId == pb1.playbookId, "original preserved on not-found")

# update_playbook — status
pl7 = update_playbook(pl4, pb1.playbookId, TS2, status=PlaybookStatusEnum.ARCHIVED)
_assert(pl7[0].status == PlaybookStatusEnum.ARCHIVED, "status updated")

# update_playbook — confidence
pl8 = update_playbook(pl4, pb1.playbookId, TS2, confidence=55.0)
_assert(pl8[0].confidence == 55.0, "confidence updated")


# merge_playbooks
base_pbs     = [pb1, pb3]
incoming_pbs = [pb3, pb4]   # pb3 is duplicate
merged_pbs   = merge_playbooks(base_pbs, incoming_pbs)
_assert(len(merged_pbs) == 3,            "merge: 3 unique playbooks")
ids_in_merge = {p.playbookId for p in merged_pbs}
_assert(pb1.playbookId in ids_in_merge,  "merge: pb1 present")
_assert(pb3.playbookId in ids_in_merge,  "merge: pb3 present (base wins)")
_assert(pb4.playbookId in ids_in_merge,  "merge: pb4 added from incoming")
# Base wins for duplicate
base_pb3 = next(p for p in merged_pbs if p.playbookId == pb3.playbookId)
_assert(base_pb3.name == pb3.name,       "merge: base version preserved for duplicate")
# Sorted
_assert(all(merged_pbs[i].playbookId <= merged_pbs[i+1].playbookId
            for i in range(len(merged_pbs)-1)), "merge result sorted")

# merge empty
_assert(len(merge_playbooks([], [])) == 0,         "merge empty+empty")
_assert(len(merge_playbooks([pb1], [])) == 1,       "merge base+empty")
_assert(len(merge_playbooks([], [pb1])) == 1,       "merge empty+incoming")


# ===========================================================================
# 10. Step Operations
# ===========================================================================
print("\n[10] Step Operations")

step_x = build_playbook_step(pb_empty.playbookId, 1, "Step X", PlaybookStepTypeEnum.MANUAL, TS)
step_y = build_playbook_step(pb_empty.playbookId, 2, "Step Y", PlaybookStepTypeEnum.AUTOMATED, TS)
step_z = build_playbook_step(pb_empty.playbookId, 3, "Step Z", PlaybookStepTypeEnum.VERIFICATION, TS)

# add_playbook_step
pb_with_x = add_playbook_step(pb_empty, step_x)
_assert(len(pb_with_x.steps) == 1,               "step added")
_assert(pb_with_x.steps[0].stepId == step_x.stepId, "correct step added")
_assert(pb_with_x.playbookId != pb_empty.playbookId, "playbookId recomputed after add")

pb_with_xy = add_playbook_step(pb_with_x, step_y)
_assert(len(pb_with_xy.steps) == 2, "second step added")
_assert(pb_with_xy.steps[0].stepNumber == 1, "steps sorted stepNumber")

# Idempotent add
pb_with_x_dup = add_playbook_step(pb_with_x, step_x)
_assert(len(pb_with_x_dup.steps) == 1,              "duplicate step not added")
_assert(pb_with_x_dup.playbookId == pb_with_x.playbookId, "playbookId unchanged on dup add")

# remove_playbook_step
pb_x_removed = remove_playbook_step(pb_with_xy, step_x.stepId)
_assert(len(pb_x_removed.steps) == 1,              "step removed")
_assert(pb_x_removed.steps[0].stepId == step_y.stepId, "correct step remains")
_assert(pb_x_removed.playbookId != pb_with_xy.playbookId, "playbookId recomputed after remove")
# Idempotent
pb_x_removed2 = remove_playbook_step(pb_x_removed, step_x.stepId)
_assert(len(pb_x_removed2.steps) == 1, "remove non-existent idempotent")
_assert(pb_x_removed2.playbookId == pb_x_removed.playbookId, "playbookId unchanged on noop remove")

# update_playbook_step
pb_updated_step = update_playbook_step(
    pb_with_xy, step_x.stepId,
    title="Step X Updated",
    description="New desc",
    step_type=PlaybookStepTypeEnum.ERADICATION,
    related_techniques=["T1059"],
)
updated_sx = pb_updated_step.steps[0]  # stepNumber 1
_assert(updated_sx.stepId    == step_x.stepId,          "stepId preserved on update")
_assert(updated_sx.stepKey   == step_x.stepKey,          "stepKey preserved on update")
_assert(updated_sx.title     == "Step X Updated",        "title updated")
_assert(updated_sx.description == "New desc",            "description updated")
_assert(updated_sx.stepType  == PlaybookStepTypeEnum.ERADICATION, "stepType updated")
_assert(updated_sx.relatedTechniques == ("T1059",),      "techniques updated")
# playbookId stable (step identity unchanged, only content changed)
_assert(pb_updated_step.playbookId == pb_with_xy.playbookId, "playbookId stable on step content update")

# update not-found
pb_nf_step = update_playbook_step(pb_with_xy, "non-existent-step-id", title="X")
_assert(pb_nf_step.playbookId == pb_with_xy.playbookId, "update not-found returns original")


# merge_playbook_steps
pb_xyz = add_playbook_step(add_playbook_step(pb_with_xy, step_z), step_z)  # last add is dup
pb_xyz = add_playbook_step(pb_with_xy, step_z)
_assert(len(pb_xyz.steps) == 3, "three steps added")

# Merge: pb_with_x has step_x, incoming has step_x (dup) + step_z (new)
pb_merged_steps = merge_playbook_steps(pb_with_x, [step_x, step_z])
_assert(len(pb_merged_steps.steps) == 2,                      "merge_steps: 2 unique steps")
_assert(pb_merged_steps.playbookId != pb_with_x.playbookId,   "merge_steps recomputes ID")
step_ids_merged = {s.stepId for s in pb_merged_steps.steps}
_assert(step_x.stepId in step_ids_merged,  "merge_steps: step_x present")
_assert(step_z.stepId in step_ids_merged,  "merge_steps: step_z added")

# Merge with no new steps is idempotent
pb_no_new = merge_playbook_steps(pb_with_x, [step_x])
_assert(pb_no_new.playbookId == pb_with_x.playbookId, "merge_steps noop is idempotent")


# ===========================================================================
# 11. Mapping Operations
# ===========================================================================
print("\n[11] Mapping Operations")

m_a = build_playbook_mapping([pb1], TS, finding_id="fid-a", confidence=70.0)
m_b = build_playbook_mapping([pb2], TS, finding_id="fid-b", confidence=60.0)
m_c = build_playbook_mapping([pb3], TS, alert_id="aid-c",   confidence=55.0)

# add_playbook_mapping
ml = []
ml = add_playbook_mapping(ml, m_a)
_assert(len(ml) == 1, "first mapping added")
ml = add_playbook_mapping(ml, m_b)
_assert(len(ml) == 2, "second mapping added")
ml_dup = add_playbook_mapping(ml, m_a)
_assert(len(ml_dup) == 2, "duplicate mapping not added")
_assert(ml[0].mappingId <= ml[1].mappingId, "mappings sorted by mappingId")

# remove_playbook_mapping
ml2 = remove_playbook_mapping(ml, m_a.mappingId)
_assert(len(ml2) == 1,                       "mapping removed")
_assert(ml2[0].mappingId == m_b.mappingId,   "correct mapping remains")
ml3 = remove_playbook_mapping(ml2, m_a.mappingId)
_assert(len(ml3) == 1, "remove non-existent idempotent")

# merge_playbook_mappings
base_ml     = [m_a, m_b]
incoming_ml = [m_b, m_c]  # m_b is dup
merged_ml   = merge_playbook_mappings(base_ml, incoming_ml)
_assert(len(merged_ml) == 3,              "merge: 3 unique mappings")
mid_set = {m.mappingId for m in merged_ml}
_assert(m_a.mappingId in mid_set,         "merge: m_a present")
_assert(m_b.mappingId in mid_set,         "merge: m_b present")
_assert(m_c.mappingId in mid_set,         "merge: m_c added")
_assert(all(merged_ml[i].mappingId <= merged_ml[i+1].mappingId
            for i in range(len(merged_ml)-1)), "merged mappings sorted")

# Merge empty
_assert(len(merge_playbook_mappings([], []))    == 0, "merge empty+empty")
_assert(len(merge_playbook_mappings([m_a], [])) == 1, "merge base+empty")
_assert(len(merge_playbook_mappings([], [m_a])) == 1, "merge empty+incoming")


# ===========================================================================
# 12. Search Utilities
# ===========================================================================
print("\n[12] Search Utilities")

all_pbs = [pb1, pb2, pb3, pb4]

# find_playbook by playbookId
found_pb = find_playbook(all_pbs, playbook_id=pb1.playbookId)
_assert(found_pb is not None,                  "find by playbookId found")
_assert(found_pb.playbookId == pb1.playbookId, "find by playbookId correct")

found_pb_key = find_playbook(all_pbs, playbook_key=pb2.playbookKey)
_assert(found_pb_key is not None,                  "find by playbookKey found")
_assert(found_pb_key.playbookId == pb2.playbookId, "find by playbookKey correct")

not_found = find_playbook(all_pbs, playbook_id="non-existent")
_assert(not_found is None, "find returns None for missing id")

not_found2 = find_playbook(all_pbs)  # no criteria
_assert(not_found2 is None, "find with no criteria returns None")

# find_playbook_step
pbs_with_steps = [pb1, pb_with_xy]
found_step = find_playbook_step(pbs_with_steps, step_id=step_a.stepId)
_assert(found_step is not None,                "find_playbook_step by stepId found")
_assert(found_step.stepId == step_a.stepId,    "find_playbook_step correct step")

found_step_key = find_playbook_step(pbs_with_steps, step_key=step_a.stepKey)
_assert(found_step_key is not None,               "find_playbook_step by stepKey found")
_assert(found_step_key.stepId == step_a.stepId,   "find_playbook_step by stepKey correct")

not_found_step = find_playbook_step(pbs_with_steps, step_id="nope")
_assert(not_found_step is None, "find_playbook_step returns None for missing")

# find_playbook_mapping
all_ml = [m_a, m_b, m_c]
found_m = find_playbook_mapping(all_ml, mapping_id=m_b.mappingId)
_assert(found_m is not None,               "find_playbook_mapping found")
_assert(found_m.mappingId == m_b.mappingId,"find_playbook_mapping correct")

not_found_m = find_playbook_mapping(all_ml, mapping_id="nope")
_assert(not_found_m is None, "find_playbook_mapping returns None")

not_found_m2 = find_playbook_mapping(all_ml)  # no criteria
_assert(not_found_m2 is None, "find_playbook_mapping no criteria returns None")


# ===========================================================================
# 13. Sorting
# ===========================================================================
print("\n[13] Sorting")

all_pbs_sort = [pb1, pb2, pb3, pb4]
# pb1=CRITICAL/ACTIVE, pb2=HIGH/ACTIVE, pb3=MEDIUM/DRAFT, pb4=HIGH/DEPRECATED

# sort_playbooks by severity DESC (default)
sorted_sev = sort_playbooks(all_pbs_sort, by="severity", ascending=False)
_assert(sorted_sev[0].severity == PlaybookSeverityEnum.CRITICAL, "severity sort: CRITICAL first")
_assert(sorted_sev[-1].severity == PlaybookSeverityEnum.MEDIUM,  "severity sort: MEDIUM last")

# sort_playbooks by severity ASC
sorted_sev_asc = sort_playbooks(all_pbs_sort, by="severity", ascending=True)
_assert(sorted_sev_asc[0].severity == PlaybookSeverityEnum.MEDIUM,   "severity ASC: MEDIUM first")
_assert(sorted_sev_asc[-1].severity == PlaybookSeverityEnum.CRITICAL, "severity ASC: CRITICAL last")

# sort_playbooks by name
sorted_name = sort_playbooks(all_pbs_sort, by="name", ascending=True)
names = [p.name for p in sorted_name]
_assert(names == sorted(names), "name sort ascending")

# sort_playbooks by status
sorted_status = sort_playbooks(all_pbs_sort, by="status", ascending=False)
_assert(sorted_status[0].status == PlaybookStatusEnum.ACTIVE,     "status sort: ACTIVE first")

# sort_playbooks by confidence DESC
sorted_conf = sort_playbooks(all_pbs_sort, by="confidence", ascending=False)
confs = [p.confidence for p in sorted_conf]
_assert(confs == sorted(confs, reverse=True), "confidence sort descending")

# Invalid sort key raises ValueError
_assert_raises(ValueError, sort_playbooks, all_pbs_sort, "invalid_key",
               msg="invalid sort key raises ValueError")

# Determinism: same result on repeated calls
s1 = sort_playbooks(all_pbs_sort, by="severity")
s2 = sort_playbooks(all_pbs_sort, by="severity")
_assert([p.playbookId for p in s1] == [p.playbookId for p in s2], "sort deterministic")

# sort_playbook_steps
all_steps = [step_b, step_a, step_z, step_y]
sorted_steps_num = sort_playbook_steps(all_steps, by="stepNumber", ascending=True)
_assert(sorted_steps_num[0].stepNumber == 1, "stepNumber sort ASC: step 1 first")
_assert(sorted_steps_num[-1].stepNumber == max(s.stepNumber for s in all_steps),
        "stepNumber sort ASC: highest last")

sorted_steps_desc = sort_playbook_steps(all_steps, by="stepNumber", ascending=False)
_assert(sorted_steps_desc[0].stepNumber == max(s.stepNumber for s in all_steps),
        "stepNumber sort DESC")

sorted_steps_type = sort_playbook_steps(all_steps, by="stepType", ascending=True)
types = [s.stepType.value for s in sorted_steps_type]
_assert(types == sorted(types), "stepType sort ascending")

_assert_raises(ValueError, sort_playbook_steps, all_steps, "bad_key",
               msg="invalid step sort key raises")

# sort_playbook_mappings
all_ml_sort = [m_a, m_b, m_c]
sorted_ml = sort_playbook_mappings(all_ml_sort, by="confidence", ascending=False)
confs_ml = [m.confidence for m in sorted_ml]
_assert(confs_ml == sorted(confs_ml, reverse=True), "mapping sort confidence DESC")

sorted_ml_asc = sort_playbook_mappings(all_ml_sort, by="confidence", ascending=True)
confs_ml_asc = [m.confidence for m in sorted_ml_asc]
_assert(confs_ml_asc == sorted(confs_ml_asc), "mapping sort confidence ASC")

_assert_raises(ValueError, sort_playbook_mappings, all_ml_sort, "bad_key",
               msg="invalid mapping sort key raises")


# ===========================================================================
# 14. Filtering
# ===========================================================================
print("\n[14] Filtering")

# Build richer playbooks for filter tests
step_t1 = build_playbook_step("pb-f1", 1, "Detect T1059", PlaybookStepTypeEnum.VERIFICATION,
                               TS, related_techniques=["T1059"], related_cves=["CVE-2021-44228"])
step_t2 = build_playbook_step("pb-f2", 1, "Detect T1078", PlaybookStepTypeEnum.MANUAL,
                               TS, related_techniques=["T1078"], related_iocs=["malware.exe"])

pb_f1 = build_playbook("Filter PB 1", PlaybookSeverityEnum.CRITICAL, TS,
                        status=PlaybookStatusEnum.ACTIVE, steps=[step_t1],
                        related_threat_actors=["APT28"], related_campaigns=["Ryuk"],
                        confidence=90.0)
pb_f2 = build_playbook("Filter PB 2", PlaybookSeverityEnum.HIGH, TS,
                        status=PlaybookStatusEnum.DRAFT, steps=[step_t2],
                        related_threat_actors=["Lazarus"], related_campaigns=["NotPetya"],
                        confidence=60.0)
pb_f3 = build_playbook("Filter PB 3", PlaybookSeverityEnum.MEDIUM, TS,
                        status=PlaybookStatusEnum.ARCHIVED,
                        related_threat_actors=["APT28"], related_campaigns=["Ryuk"],
                        confidence=40.0)

filter_pool = [pb_f1, pb_f2, pb_f3]

# filter by severity
r = filter_playbooks(filter_pool, severity=PlaybookSeverityEnum.CRITICAL)
_assert(len(r) == 1 and r[0].playbookId == pb_f1.playbookId, "filter by severity CRITICAL")

r = filter_playbooks(filter_pool, severity=PlaybookSeverityEnum.LOW)
_assert(len(r) == 0, "filter severity no match → empty")

# filter by status
r = filter_playbooks(filter_pool, status=PlaybookStatusEnum.DRAFT)
_assert(len(r) == 1 and r[0].playbookId == pb_f2.playbookId, "filter by status DRAFT")

# filter by confidence range
r = filter_playbooks(filter_pool, min_confidence=70.0)
_assert(len(r) == 1 and r[0].playbookId == pb_f1.playbookId, "filter min_confidence=70")

r = filter_playbooks(filter_pool, max_confidence=50.0)
_assert(len(r) == 1 and r[0].playbookId == pb_f3.playbookId, "filter max_confidence=50")

r = filter_playbooks(filter_pool, min_confidence=50.0, max_confidence=70.0)
_assert(len(r) == 1 and r[0].playbookId == pb_f2.playbookId, "filter confidence range")

# filter by technique
r = filter_playbooks(filter_pool, technique="T1059")
_assert(len(r) == 1 and r[0].playbookId == pb_f1.playbookId, "filter by technique T1059")
r = filter_playbooks(filter_pool, technique="t1059")  # case-insensitive
_assert(len(r) == 1, "filter technique case-insensitive")

# filter by CVE
r = filter_playbooks(filter_pool, cve="CVE-2021-44228")
_assert(len(r) == 1 and r[0].playbookId == pb_f1.playbookId, "filter by CVE")
r = filter_playbooks(filter_pool, cve="cve-2021-44228")  # case-insensitive
_assert(len(r) == 1, "filter CVE case-insensitive")

# filter by IOC
r = filter_playbooks(filter_pool, ioc="malware.exe")
_assert(len(r) == 1 and r[0].playbookId == pb_f2.playbookId, "filter by IOC")

# filter by threat actor
r = filter_playbooks(filter_pool, threat_actor="APT28")
_assert(len(r) == 2, "filter threat_actor APT28 matches 2")
r = filter_playbooks(filter_pool, threat_actor="apt28")  # case-insensitive
_assert(len(r) == 2, "filter threat_actor case-insensitive")

# filter by campaign
r = filter_playbooks(filter_pool, campaign="Ryuk")
_assert(len(r) == 2, "filter campaign Ryuk matches 2")

# combined filter
r = filter_playbooks(filter_pool, severity=PlaybookSeverityEnum.CRITICAL, threat_actor="APT28")
_assert(len(r) == 1 and r[0].playbookId == pb_f1.playbookId, "filter combined AND")

# No match
r = filter_playbooks(filter_pool, threat_actor="Unknown Actor XYZ")
_assert(len(r) == 0, "filter no match → empty")

# Empty input
_assert(len(filter_playbooks([], severity=PlaybookSeverityEnum.CRITICAL)) == 0, "filter empty input")


# filter_playbook_steps
step_pool = [step_t1, step_t2, step_x, step_y, step_z]

r = filter_playbook_steps(step_pool, step_type=PlaybookStepTypeEnum.MANUAL)
_assert(len(r) == 2, "filter steps by MANUAL type (step_t2 + step_x)")

r = filter_playbook_steps(step_pool, technique="T1059")
_assert(len(r) == 1 and r[0].stepId == step_t1.stepId, "filter steps by technique")

r = filter_playbook_steps(step_pool, cve="CVE-2021-44228")
_assert(len(r) == 1 and r[0].stepId == step_t1.stepId, "filter steps by CVE")

r = filter_playbook_steps(step_pool, ioc="malware.exe")
_assert(len(r) == 1 and r[0].stepId == step_t2.stepId, "filter steps by IOC")

r = filter_playbook_steps(step_pool, min_step_number=2, max_step_number=2)
_assert(all(s.stepNumber == 2 for s in r), "filter steps by step number range")

r = filter_playbook_steps(step_pool, min_step_number=10)
_assert(len(r) == 0, "filter steps: min_step_number too high → empty")

# filter_playbook_mappings
m_pool = [m_a, m_b, m_c]  # m_a: finding=fid-a,conf=70; m_b: finding=fid-b,conf=60; m_c: alert=aid-c,conf=55

r = filter_playbook_mappings(m_pool, finding_id="fid-a")
_assert(len(r) == 1 and r[0].mappingId == m_a.mappingId, "filter mapping by findingId")

r = filter_playbook_mappings(m_pool, alert_id="aid-c")
_assert(len(r) == 1 and r[0].mappingId == m_c.mappingId, "filter mapping by alertId")

r = filter_playbook_mappings(m_pool, min_confidence=65.0)
_assert(len(r) == 1 and r[0].mappingId == m_a.mappingId, "filter mapping min_confidence")

r = filter_playbook_mappings(m_pool, max_confidence=60.0)
_assert(len(r) == 2, "filter mapping max_confidence=60")

r = filter_playbook_mappings(m_pool, severity=PlaybookSeverityEnum.CRITICAL)
# pb1=CRITICAL is in m_a only
_assert(len(r) == 1, "filter mapping by severity")

r = filter_playbook_mappings([], finding_id="fid-a")
_assert(len(r) == 0, "filter mappings empty input")


# ===========================================================================
# 15. Grouping
# ===========================================================================
print("\n[15] Grouping")

group_pool = [pb_f1, pb_f2, pb_f3]
# pb_f1: CRITICAL/ACTIVE/APT28/Ryuk
# pb_f2: HIGH/DRAFT/Lazarus/NotPetya
# pb_f3: MEDIUM/ARCHIVED/APT28/Ryuk

# group by severity
g_sev = group_playbooks(group_pool, group_by="severity")
_assert("CRITICAL" in g_sev,                           "group_sev has CRITICAL")
_assert("HIGH"     in g_sev,                           "group_sev has HIGH")
_assert("MEDIUM"   in g_sev,                           "group_sev has MEDIUM")
_assert(len(g_sev["CRITICAL"]) == 1,                   "CRITICAL group has 1")
_assert(g_sev["CRITICAL"][0].playbookId == pb_f1.playbookId, "CRITICAL group correct")

# group by status
g_st = group_playbooks(group_pool, group_by="status")
_assert("ACTIVE"   in g_st, "group_status has ACTIVE")
_assert("DRAFT"    in g_st, "group_status has DRAFT")
_assert("ARCHIVED" in g_st, "group_status has ARCHIVED")
_assert(len(g_st["ACTIVE"]) == 1, "ACTIVE group has 1")

# group by threat_actor (multi-group)
g_ta = group_playbooks(group_pool, group_by="threat_actor")
_assert("APT28"   in g_ta, "group_ta has APT28")
_assert("Lazarus" in g_ta, "group_ta has Lazarus")
_assert(len(g_ta["APT28"])   == 2, "APT28 appears in 2 playbooks")
_assert(len(g_ta["Lazarus"]) == 1, "Lazarus appears in 1 playbook")

# group by campaign
g_camp = group_playbooks(group_pool, group_by="campaign")
_assert("Ryuk"     in g_camp, "group_camp has Ryuk")
_assert("NotPetya" in g_camp, "group_camp has NotPetya")
_assert(len(g_camp["Ryuk"]) == 2, "Ryuk campaign group has 2")

# Each group is sorted by playbookId
for key, grp in g_ta.items():
    ids = [p.playbookId for p in grp]
    _assert(ids == sorted(ids), f"group_ta[{key}] sorted by playbookId")

# Playbook with no threat actors → "unknown" group
pb_no_actor = build_playbook("No Actor", PlaybookSeverityEnum.LOW, TS)
g_ta2 = group_playbooks([pb_no_actor], group_by="threat_actor")
_assert("unknown" in g_ta2, "no threat actor → unknown group")

# group_playbook_steps
step_pool_g = [step_t1, step_t2, step_x, step_y, step_z, step_a]
g_type = group_playbook_steps(step_pool_g, group_by="stepType")
_assert("MANUAL"       in g_type, "group_steps MANUAL present")
_assert("VERIFICATION" in g_type, "group_steps VERIFICATION present")
_assert("CONTAINMENT"  in g_type, "group_steps CONTAINMENT present")
_assert("AUTOMATED"    in g_type, "group_steps AUTOMATED present")

# Each group sorted by stepNumber
for key, grp in g_type.items():
    nums = [s.stepNumber for s in grp]
    _assert(nums == sorted(nums), f"group_steps[{key}] sorted by stepNumber")

# group_playbook_mappings
m_pool_g = [m_a, m_b, m_c]
# m_a → pb1(CRITICAL), m_b → pb2(HIGH), m_c → pb3(MEDIUM)
g_msev = group_playbook_mappings(m_pool_g, group_by="severity")
_assert("CRITICAL" in g_msev, "group_mappings has CRITICAL")
_assert("HIGH"     in g_msev, "group_mappings has HIGH")
_assert("MEDIUM"   in g_msev, "group_mappings has MEDIUM")

g_mst = group_playbook_mappings(m_pool_g, group_by="status")
_assert("ACTIVE" in g_mst, "group_mappings has ACTIVE status")

# group with no playbooks → "unknown"
m_empty_pbs = build_playbook_mapping([], TS, finding_id="fid-empty", validate=False)
g_empty = group_playbook_mappings([m_empty_pbs], group_by="severity")
_assert("unknown" in g_empty, "mapping with no playbooks → unknown group")


# ===========================================================================
# 16. Statistics (Extended)
# ===========================================================================
print("\n[16] Statistics")

# Empty
stats_empty = build_playbook_statistics([])
_assert(stats_empty.totalPlaybooks      == 0,  "empty stats: total=0")
_assert(stats_empty.activePlaybooks     == 0,  "empty stats: active=0")
_assert(stats_empty.draftPlaybooks      == 0,  "empty stats: draft=0")
_assert(stats_empty.deprecatedPlaybooks == 0,  "empty stats: deprecated=0")
_assert(stats_empty.archivedPlaybooks   == 0,  "empty stats: archived=0")
_assert(stats_empty.averageConfidence   == 0.0,"empty stats: avgConf=0")
_assert(stats_empty.averageSteps        == 0.0,"empty stats: avgSteps=0")
_assert(stats_empty.severityCounts      == {}, "empty stats: severityCounts={}")
_assert(stats_empty.statusCounts        == {}, "empty stats: statusCounts={}")

# Normal pool: pb_f1=CRITICAL/ACTIVE/conf=90/1step,
#              pb_f2=HIGH/DRAFT/conf=60/1step,
#              pb_f3=MEDIUM/ARCHIVED/conf=40/0steps
stat_pool = [pb_f1, pb_f2, pb_f3]
stats = build_playbook_statistics(stat_pool)
_assert(stats.totalPlaybooks      == 3,   "stats total=3")
_assert(stats.activePlaybooks     == 1,   "stats active=1")
_assert(stats.draftPlaybooks      == 1,   "stats draft=1")
_assert(stats.deprecatedPlaybooks == 0,   "stats deprecated=0")
_assert(stats.archivedPlaybooks   == 1,   "stats archived=1")
_assert(abs(stats.averageConfidence - round((90+60+40)/3, 4)) < 0.001, "stats avgConf")
_assert(abs(stats.averageSteps - round((1+1+0)/3, 4)) < 0.001,         "stats avgSteps")

# severityCounts
_assert("CRITICAL" in stats.severityCounts, "severityCounts has CRITICAL")
_assert("HIGH"     in stats.severityCounts, "severityCounts has HIGH")
_assert("MEDIUM"   in stats.severityCounts, "severityCounts has MEDIUM")
_assert("LOW"  not in stats.severityCounts, "severityCounts omits LOW (count=0)")
_assert(stats.severityCounts["CRITICAL"] == 1, "CRITICAL count=1")
_assert(stats.severityCounts["HIGH"]     == 1, "HIGH count=1")
_assert(stats.severityCounts["MEDIUM"]   == 1, "MEDIUM count=1")

# statusCounts
_assert("ACTIVE"   in stats.statusCounts, "statusCounts has ACTIVE")
_assert("DRAFT"    in stats.statusCounts, "statusCounts has DRAFT")
_assert("ARCHIVED" in stats.statusCounts, "statusCounts has ARCHIVED")
_assert("DEPRECATED" not in stats.statusCounts, "statusCounts omits DEPRECATED (count=0)")

# Deduplication
stats_dup = build_playbook_statistics([pb_f1, pb_f1, pb_f2])
_assert(stats_dup.totalPlaybooks == 2,  "stats dedup: 2 distinct")
_assert(stats_dup.activePlaybooks == 1, "stats dedup: 1 active")
_assert(stats_dup.draftPlaybooks  == 1, "stats dedup: 1 draft")

# Determinism — order-independent
stats_a = build_playbook_statistics([pb_f1, pb_f2, pb_f3])
stats_b = build_playbook_statistics([pb_f3, pb_f1, pb_f2])
_assert(stats_a.totalPlaybooks    == stats_b.totalPlaybooks,    "stats order-independent total")
_assert(stats_a.averageConfidence == stats_b.averageConfidence, "stats order-independent avgConf")
_assert(stats_a.severityCounts    == stats_b.severityCounts,    "stats order-independent severityCounts")
_assert(stats_a.statusCounts      == stats_b.statusCounts,      "stats order-independent statusCounts")


# ===========================================================================
# 17. Serialization (model_dump round-trip)
# ===========================================================================
print("\n[17] Serialization")

# PlaybookStep round-trip
d_step = step_a.model_dump()
_assert(isinstance(d_step, dict),                  "step.model_dump() returns dict")
_assert(d_step["stepId"]  == step_a.stepId,        "step dump stepId")
_assert(d_step["stepKey"] == step_a.stepKey,        "step dump stepKey")
_assert(d_step["stepType"] == "CONTAINMENT",        "step dump stepType value")
_assert(isinstance(d_step["relatedTechniques"], (list, tuple)), "step dump relatedTechniques is sequence")

# Playbook round-trip
d_pb = pb1.model_dump()
_assert(isinstance(d_pb, dict),                    "pb.model_dump() returns dict")
_assert(d_pb["playbookId"] == pb1.playbookId,       "pb dump playbookId")
_assert(d_pb["severity"]   == "CRITICAL",           "pb dump severity value")
_assert(d_pb["status"]     == "ACTIVE",             "pb dump status value")
_assert(isinstance(d_pb["steps"], (list, tuple)),            "pb dump steps is sequence")
_assert(len(d_pb["steps"]) == len(pb1.steps),       "pb dump steps length matches")

# PlaybookMapping round-trip
d_m = m1.model_dump()
_assert(isinstance(d_m, dict),                      "mapping.model_dump() returns dict")
_assert(d_m["mappingId"]          == m1.mappingId,  "mapping dump mappingId")
_assert(d_m["mappingFingerprint"] == m1.mappingFingerprint, "mapping dump fingerprint")
_assert(isinstance(d_m["playbooks"], (list, tuple)),         "mapping dump playbooks is sequence")

# PlaybookStatistics round-trip
d_stats = stats.model_dump()
_assert(isinstance(d_stats, dict),                   "stats.model_dump() returns dict")
_assert(d_stats["totalPlaybooks"] == 3,              "stats dump totalPlaybooks")
_assert(isinstance(d_stats["severityCounts"], dict), "stats dump severityCounts is dict")
_assert(isinstance(d_stats["statusCounts"],   dict), "stats dump statusCounts is dict")

# model_dump() → model reconstruction
step_from_dict = PlaybookStep(**d_step)
_assert(step_from_dict.stepId == step_a.stepId,      "step round-trip from dict")

pb_from_dict = Playbook(**d_pb)
_assert(pb_from_dict.playbookId == pb1.playbookId,   "pb round-trip from dict")


# ===========================================================================
# 18. Immutability
# ===========================================================================
print("\n[18] Immutability")

try:
    step_a.title = "mutated"  # type: ignore
    _assert(False, "PlaybookStep should be immutable")
except Exception:
    _assert(True, "PlaybookStep is immutable (frozen)")

try:
    pb1.name = "mutated"  # type: ignore
    _assert(False, "Playbook should be immutable")
except Exception:
    _assert(True, "Playbook is immutable (frozen)")

try:
    m1.confidence = 99.0  # type: ignore
    _assert(False, "PlaybookMapping should be immutable")
except Exception:
    _assert(True, "PlaybookMapping is immutable (frozen)")

try:
    stats.totalPlaybooks = 999  # type: ignore
    _assert(False, "PlaybookStatistics should be immutable")
except Exception:
    _assert(True, "PlaybookStatistics is immutable (frozen)")

# Operations return NEW objects, not mutations
original_steps = pb_with_xy.steps
new_pb = add_playbook_step(pb_with_xy, step_z)
_assert(pb_with_xy.steps == original_steps, "add_playbook_step does not mutate original")

original_list = [pb1, pb2]
_ = add_playbook(original_list, pb3)
_assert(len(original_list) == 2, "add_playbook does not mutate input list")

original_ml = [m_a, m_b]
_ = add_playbook_mapping(original_ml, m_c)
_assert(len(original_ml) == 2, "add_playbook_mapping does not mutate input list")


# ===========================================================================
# 19. Integration Helpers
# ===========================================================================
print("\n[19] Integration Helpers")

class _FakeTech:
    mitreId     = "t1059"
    techniqueId = "uuid-tech-1"

class _FakeTechNoMitreId:
    techniqueId = "uuid-tech-fallback"

class _FakeTechEmpty:
    pass

class _FakeCVE:
    cveId    = "cve-2023-1234"
    recordId = "uuid-cve-1"

class _FakeCVENoId:
    recordId = "uuid-cve-fallback"

class _FakeCVEEmpty:
    pass

class _FakeIOC:
    value = "192.168.1.100"
    iocId = "uuid-ioc-1"

class _FakeIOCNoValue:
    iocId = "uuid-ioc-fallback"

class _FakeIOCEmpty:
    pass

class _FakeThreat:
    name    = "APT28"
    actorId = "uuid-actor-1"

class _FakeThreatNoName:
    actorId = "uuid-actor-fallback"

class _FakeThreatEmpty:
    pass

# mitre_to_playbook_reference
_assert(mitre_to_playbook_reference(_FakeTech())        == "T1059",              "mitre ref uppercase")
_assert(mitre_to_playbook_reference(_FakeTechNoMitreId()) == "uuid-tech-fallback","mitre ref fallback techniqueId")
_assert(mitre_to_playbook_reference(_FakeTechEmpty())   == "",                   "mitre ref empty → ''")

# cve_to_playbook_reference
_assert(cve_to_playbook_reference(_FakeCVE())        == "CVE-2023-1234",      "cve ref uppercase")
_assert(cve_to_playbook_reference(_FakeCVENoId())    == "uuid-cve-fallback",  "cve ref fallback recordId")
_assert(cve_to_playbook_reference(_FakeCVEEmpty())   == "",                   "cve ref empty → ''")

# ioc_to_playbook_reference
_assert(ioc_to_playbook_reference(_FakeIOC())        == "192.168.1.100",      "ioc ref value")
_assert(ioc_to_playbook_reference(_FakeIOCNoValue()) == "uuid-ioc-fallback",  "ioc ref fallback iocId")
_assert(ioc_to_playbook_reference(_FakeIOCEmpty())   == "",                   "ioc ref empty → ''")

# threat_to_playbook_reference
_assert(threat_to_playbook_reference(_FakeThreat())        == "APT28",               "threat ref name")
_assert(threat_to_playbook_reference(_FakeThreatNoName())  == "uuid-actor-fallback", "threat ref fallback actorId")
_assert(threat_to_playbook_reference(_FakeThreatEmpty())   == "",                    "threat ref empty → ''")

# finding_to_playbook_mapping
class _FakeFinding:
    findingId = "finding-abc-123"

fm = finding_to_playbook_mapping(_FakeFinding(), [pb1], TS, confidence=80.0)
_assert(fm.findingId   == "finding-abc-123", "finding mapping findingId")
_assert(fm.alertId     == "",                "finding mapping alertId empty")
_assert(fm.reasoningId == "",                "finding mapping reasoningId empty")
_assert(fm.confidence  == 80.0,              "finding mapping confidence")

# alert_to_playbook_mapping
class _FakeAlert:
    alertId   = "alert-xyz-456"
    findingId = "finding-abc-123"

am = alert_to_playbook_mapping(_FakeAlert(), [pb1], TS, confidence=75.0)
_assert(am.alertId    == "alert-xyz-456",   "alert mapping alertId")
_assert(am.findingId  == "finding-abc-123", "alert mapping findingId")
_assert(am.reasoningId == "",               "alert mapping reasoningId empty")

# reasoning_to_playbook_mapping
class _FakeReasoning:
    reasoningId       = "reasoning-def-789"
    overallConfidence = 72.5

rm = reasoning_to_playbook_mapping(_FakeReasoning(), [pb1], TS,
                                   finding_id="finding-abc-123")
_assert(rm.reasoningId == "reasoning-def-789",  "reasoning mapping reasoningId")
_assert(rm.findingId   == "finding-abc-123",    "reasoning mapping findingId")
_assert(abs(rm.confidence - 72.5) < 0.001,      "reasoning mapping confidence from overallConfidence")
_assert(rm.alertId     == "",                    "reasoning mapping alertId empty")

# Determinism of integration helpers
fm2 = finding_to_playbook_mapping(_FakeFinding(), [pb1], TS, confidence=80.0)
_assert(fm.mappingId == fm2.mappingId, "finding_to_playbook_mapping deterministic")

am2 = alert_to_playbook_mapping(_FakeAlert(), [pb1], TS, confidence=75.0)
_assert(am.mappingId == am2.mappingId, "alert_to_playbook_mapping deterministic")


# ===========================================================================
# 20. Edge Cases
# ===========================================================================
print("\n[20] Edge Cases")

# Whitespace-only strings
_assert_raises(InvalidPlaybookStepError, validate_playbook_step, 1, "   ", PlaybookStepTypeEnum.MANUAL, TS,
               msg="whitespace title rejected")
_assert_raises(InvalidPlaybookError, validate_playbook, "   ", PlaybookSeverityEnum.HIGH, PlaybookStatusEnum.DRAFT, TS,
               msg="whitespace name rejected")
_assert_raises(InvalidPlaybookMappingError, validate_playbook_mapping, "  ", "  ", "  ", 50.0, TS,
               msg="whitespace-only source ids rejected")

# Empty related lists produce empty tuples
step_no_refs = build_playbook_step("pb-x", 1, "No Refs", PlaybookStepTypeEnum.MANUAL, TS)
_assert(step_no_refs.relatedTechniques == (), "empty techniques → empty tuple")
_assert(step_no_refs.relatedCVEs       == (), "empty CVEs → empty tuple")
_assert(step_no_refs.relatedIOCs       == (), "empty IOCs → empty tuple")

# None lists treated as empty
step_none_refs = build_playbook_step("pb-x", 1, "None Refs", PlaybookStepTypeEnum.MANUAL, TS,
                                     related_techniques=None, related_cves=None, related_iocs=None)
_assert(step_none_refs.relatedTechniques == (), "None techniques → empty tuple")
_assert(step_none_refs.relatedCVEs       == (), "None CVEs → empty tuple")
_assert(step_none_refs.relatedIOCs       == (), "None IOCs → empty tuple")

# Playbook with None steps
pb_none_steps = build_playbook("None Steps", PlaybookSeverityEnum.LOW, TS, steps=None)
_assert(pb_none_steps.steps == (), "None steps → empty tuple")

# Confidence boundary values exactly at limits
m_bound1 = build_playbook_mapping([pb1], TS, finding_id="f", confidence=0.0)
m_bound2 = build_playbook_mapping([pb1], TS, finding_id="f", confidence=100.0)
_assert(m_bound1.confidence == 0.0,   "confidence 0.0 accepted exactly")
_assert(m_bound2.confidence == 100.0, "confidence 100.0 accepted exactly")

# Step number 1 is minimum valid
step_min = build_playbook_step("pb-x", 1, "Min Step", PlaybookStepTypeEnum.MANUAL, TS)
_assert(step_min.stepNumber == 1, "stepNumber 1 is valid")

# Very large step number
step_large = build_playbook_step("pb-x", 9999, "Large Step", PlaybookStepTypeEnum.MANUAL, TS)
_assert(step_large.stepNumber == 9999, "large stepNumber accepted")

# Duplicate technique strings in same step → deduplicated
step_dedup = build_playbook_step("pb-x", 1, "Dedup", PlaybookStepTypeEnum.MANUAL, TS,
                                  related_techniques=["T1059", "T1059", "t1059"])
_assert(step_dedup.relatedTechniques == ("T1059",), "duplicate techniques deduplicated")

# Adding same step twice → idempotent
pb_idem = add_playbook_step(add_playbook_step(pb_empty, step_x), step_x)
_assert(len(pb_idem.steps) == 1, "add same step twice → 1 step")

# Removing from empty playbook
pb_remove_empty = remove_playbook_step(pb_empty, "non-existent")
_assert(len(pb_remove_empty.steps) == 0, "remove from empty playbook → empty")

# merge_playbooks with all duplicates
pb_all_dups = merge_playbooks([pb1, pb2], [pb1, pb2])
_assert(len(pb_all_dups) == 2, "merge all duplicates → 2 distinct")

# search in empty list
_assert(find_playbook([], playbook_id="x") is None,       "find in empty list → None")
_assert(find_playbook_step([], step_id="x") is None,      "find step in empty list → None")
_assert(find_playbook_mapping([], mapping_id="x") is None,"find mapping in empty list → None")

# Sorting empty list
_assert(sort_playbooks([])        == [], "sort empty playbooks → []")
_assert(sort_playbook_steps([])   == [], "sort empty steps → []")
_assert(sort_playbook_mappings([])== [], "sort empty mappings → []")

# Filtering empty list
_assert(filter_playbooks([])         == [], "filter empty playbooks → []")
_assert(filter_playbook_steps([])    == [], "filter empty steps → []")
_assert(filter_playbook_mappings([]) == [], "filter empty mappings → []")

# Grouping empty list
_assert(group_playbooks([])         == {}, "group empty playbooks → {}")
_assert(group_playbook_steps([])    == {}, "group empty steps → {}")
_assert(group_playbook_mappings([]) == {}, "group empty mappings → {}")


# ===========================================================================
# 21. Zero Randomness / Deterministic Fingerprints
# ===========================================================================
print("\n[21] Zero Randomness / Deterministic Fingerprints")

# Run builders 3 times with identical inputs — all IDs must be equal
for i in range(3):
    s = build_playbook_step("pb-det", 5, "Det Step", PlaybookStepTypeEnum.RECOVERY, TS)
    _assert(s.stepId  == build_playbook_step("pb-det", 5, "Det Step", PlaybookStepTypeEnum.RECOVERY, TS).stepId,
            f"stepId deterministic run {i}")

for i in range(3):
    p = build_playbook("Det PB", PlaybookSeverityEnum.HIGH, TS, confidence=50.0)
    _assert(p.playbookId == build_playbook("Det PB", PlaybookSeverityEnum.HIGH, TS, confidence=50.0).playbookId,
            f"playbookId deterministic run {i}")

for i in range(3):
    m = build_playbook_mapping([pb1, pb2], TS, finding_id="fid-det", confidence=50.0)
    _assert(m.mappingId == build_playbook_mapping([pb2, pb1], TS, finding_id="fid-det", confidence=50.0).mappingId,
            f"mappingId deterministic run {i}")
    _assert(m.mappingFingerprint == build_playbook_mapping([pb2, pb1], TS, finding_id="fid-det", confidence=50.0).mappingFingerprint,
            f"mappingFingerprint deterministic run {i}")

# Different inputs must yield different IDs (collision resistance)
det_step_1 = build_playbook_step("pb-001", 1, "A", PlaybookStepTypeEnum.MANUAL, TS)
det_step_2 = build_playbook_step("pb-001", 2, "A", PlaybookStepTypeEnum.MANUAL, TS)
det_step_3 = build_playbook_step("pb-002", 1, "A", PlaybookStepTypeEnum.MANUAL, TS)
_assert(det_step_1.stepId != det_step_2.stepId, "different stepNumber → different stepId")
_assert(det_step_1.stepId != det_step_3.stepId, "different playbookId → different stepId")
_assert(det_step_2.stepId != det_step_3.stepId, "all three distinct stepIds")

det_pb_1 = build_playbook("PB Alpha", PlaybookSeverityEnum.HIGH,     TS)
det_pb_2 = build_playbook("PB Alpha", PlaybookSeverityEnum.CRITICAL,  TS)
det_pb_3 = build_playbook("PB Beta",  PlaybookSeverityEnum.HIGH,      TS)
_assert(det_pb_1.playbookId != det_pb_2.playbookId, "different severity → different playbookId")
_assert(det_pb_1.playbookId != det_pb_3.playbookId, "different name → different playbookId")

det_m_1 = build_playbook_mapping([det_pb_1], TS, finding_id="f1", confidence=50.0)
det_m_2 = build_playbook_mapping([det_pb_2], TS, finding_id="f1", confidence=50.0)
_assert(det_m_1.mappingId != det_m_2.mappingId, "different playbooks → different mappingId")
_assert(det_m_1.mappingFingerprint != det_m_2.mappingFingerprint, "different playbooks → different fingerprint")


# ===========================================================================
# 22. Large Dataset Stability
# ===========================================================================
print("\n[22] Large Dataset Stability")

import hashlib

# Build 100 playbooks
large_pbs: list = []
for i in range(100):
    sev = [PlaybookSeverityEnum.LOW, PlaybookSeverityEnum.MEDIUM,
           PlaybookSeverityEnum.HIGH, PlaybookSeverityEnum.CRITICAL][i % 4]
    st  = [PlaybookStatusEnum.DRAFT, PlaybookStatusEnum.ACTIVE,
           PlaybookStatusEnum.DEPRECATED, PlaybookStatusEnum.ARCHIVED][i % 4]
    pb_i = build_playbook(
        name       = f"Playbook {i:03d}",
        severity   = sev,
        created_at = TS,
        status     = st,
        confidence = float(i % 101),
    )
    large_pbs.append(pb_i)

_assert(len(large_pbs) == 100, "large dataset: 100 playbooks built")

# All IDs distinct
all_large_ids = [p.playbookId for p in large_pbs]
_assert(len(set(all_large_ids)) == 100, "large dataset: all playbookIds distinct")

# add_playbook with all 100
l_list: list = []
for pb_i in large_pbs:
    l_list = add_playbook(l_list, pb_i)
_assert(len(l_list) == 100, "large: all 100 added")

# Adding all again → still 100 (idempotent)
for pb_i in large_pbs:
    l_list = add_playbook(l_list, pb_i)
_assert(len(l_list) == 100, "large: duplicates not re-added")

# merge with split halves
half_a = large_pbs[:50]
half_b = large_pbs[50:]
overlap = large_pbs[25:75]  # 25 overlap with each half
merged_large = merge_playbooks(merge_playbooks(half_a, overlap), half_b)
_assert(len(merged_large) == 100, "large: merge with overlap → 100 distinct")

# Statistics on 100 playbooks
stats_large = build_playbook_statistics(large_pbs)
_assert(stats_large.totalPlaybooks == 100, "large stats: total=100")
_assert(stats_large.activePlaybooks + stats_large.draftPlaybooks +
        stats_large.deprecatedPlaybooks + stats_large.archivedPlaybooks == 100,
        "large stats: status counts sum to 100")
sev_sum = sum(stats_large.severityCounts.values())
_assert(sev_sum == 100, "large stats: severityCounts sum to 100")

# Sorting stability — sorted result is stable (same IDs on repeat)
sorted_large_1 = sort_playbooks(large_pbs, by="severity", ascending=False)
sorted_large_2 = sort_playbooks(large_pbs, by="severity", ascending=False)
_assert([p.playbookId for p in sorted_large_1] == [p.playbookId for p in sorted_large_2],
        "large: sort is stable and deterministic")

# Build 100 steps for a single playbook and merge them
large_step_pbs = []
anchor_pb_id = "anchor-large-pb"
for i in range(1, 51):
    s = build_playbook_step(anchor_pb_id, i, f"Step {i}", PlaybookStepTypeEnum.MANUAL, TS)
    large_step_pbs.append(s)

pb_large_steps = build_playbook("Large Step PB", PlaybookSeverityEnum.LOW, TS, steps=large_step_pbs[:25])
for s in large_step_pbs[25:]:
    pb_large_steps = add_playbook_step(pb_large_steps, s)
_assert(len(pb_large_steps.steps) == 50, "large: 50 steps in playbook")
nums = [s.stepNumber for s in pb_large_steps.steps]
_assert(nums == sorted(nums), "large: steps sorted by stepNumber")

# Statistics on large with duplicates
stats_dup_large = build_playbook_statistics(large_pbs * 3)  # 300 items, 100 distinct
_assert(stats_dup_large.totalPlaybooks == 100, "large stats dedup: total=100")


# ===========================================================================
# 23. Additional Coverage — update_playbook_step field isolation
# ===========================================================================
print("\n[23] Additional step/playbook field isolation")

pb_iso = build_playbook("Isolation PB", PlaybookSeverityEnum.MEDIUM, TS,
                         steps=[step_t1])

# Update only description — stepType unchanged
pb_iso2 = update_playbook_step(pb_iso, step_t1.stepId, description="New description only")
updated_s = pb_iso2.steps[0]
_assert(updated_s.description == "New description only", "update: description changed")
_assert(updated_s.stepType    == step_t1.stepType,       "update: stepType unchanged")
_assert(updated_s.title       == step_t1.title,          "update: title unchanged")
_assert(updated_s.relatedTechniques == step_t1.relatedTechniques, "update: techniques unchanged")

# Update only expected_outcome
pb_iso3 = update_playbook_step(pb_iso, step_t1.stepId, expected_outcome="New outcome")
_assert(pb_iso3.steps[0].expectedOutcome == "New outcome", "update: expectedOutcome changed")
_assert(pb_iso3.steps[0].description     == step_t1.description, "update: description unchanged")

# Update related_cves and related_iocs
pb_iso4 = update_playbook_step(pb_iso, step_t1.stepId,
                                related_cves=["CVE-2022-1234", "CVE-2022-1234"],
                                related_iocs=["1.2.3.4"])
_assert(pb_iso4.steps[0].relatedCVEs == ("CVE-2022-1234",), "update: CVEs deduped")
_assert(pb_iso4.steps[0].relatedIOCs == ("1.2.3.4",),       "update: IOCs set")

# update_playbook — change related_campaigns
pb_upd_camp = [build_playbook("Camp PB", PlaybookSeverityEnum.LOW, TS,
                               related_campaigns=["Campaign A"])]
pb_upd_camp2 = update_playbook(pb_upd_camp, pb_upd_camp[0].playbookId, TS2,
                                related_campaigns=["Campaign B", "Campaign A"])
_assert(pb_upd_camp2[0].relatedCampaigns == ("Campaign A", "Campaign B"),
        "update: campaigns sorted and deduped")

# update_playbook — change related_threat_actors
pb_upd_ta = [build_playbook("TA PB", PlaybookSeverityEnum.LOW, TS,
                              related_threat_actors=["Alpha"])]
pb_upd_ta2 = update_playbook(pb_upd_ta, pb_upd_ta[0].playbookId, TS2,
                               related_threat_actors=["Beta", "Alpha"])
_assert(pb_upd_ta2[0].relatedThreatActors == ("Alpha", "Beta"),
        "update: threat actors sorted and deduped")

# Verify that remove_playbook_step on middle step re-sorts correctly
pb_three = build_playbook("Three Steps", PlaybookSeverityEnum.LOW, TS,
                           steps=[step_x, step_y, step_z])
pb_mid_rem = remove_playbook_step(pb_three, step_y.stepId)
_assert(len(pb_mid_rem.steps) == 2, "remove middle step → 2 steps")
step_nums_after = [s.stepNumber for s in pb_mid_rem.steps]
_assert(step_nums_after == sorted(step_nums_after), "steps remain sorted after middle removal")


# ===========================================================================
# 24. Key/ID Namespace Isolation
# ===========================================================================
print("\n[24] Namespace isolation")

# All IDs from different model types must not collide with each other
step_id_val    = build_playbook_step("pb-ns", 1, "NS Step", PlaybookStepTypeEnum.MANUAL, TS).stepId
pb_id_val      = build_playbook("NS PB", PlaybookSeverityEnum.LOW, TS).playbookId
mapping_id_val = build_playbook_mapping(
    [build_playbook("NS PB2", PlaybookSeverityEnum.LOW, TS)],
    TS, finding_id="fid-ns"
).mappingId

_assert(step_id_val    != pb_id_val,      "stepId ≠ playbookId")
_assert(step_id_val    != mapping_id_val, "stepId ≠ mappingId")
_assert(pb_id_val      != mapping_id_val, "playbookId ≠ mappingId")

# Keys are all 32 hex chars lowercase
_assert(all(c in "0123456789abcdef" for c in stepKey("p", 1)),      "stepKey is hex")
_assert(all(c in "0123456789abcdef" for c in playbookKey("n", PlaybookSeverityEnum.LOW, ())), "playbookKey is hex")
_assert(all(c in "0123456789abcdef" for c in mappingKey("f","a","r",())), "mappingKey is hex")

# ===========================================================================
# 25. Mapping — reasoning_id only source
# ===========================================================================
print("\n[25] Mapping — reasoning_id only source")

m_rid = build_playbook_mapping([pb1], TS, reasoning_id="rid-solo-001")
_assert(m_rid.reasoningId == "rid-solo-001", "reasoningId-only mapping")
_assert(m_rid.findingId   == "",             "findingId empty")
_assert(m_rid.alertId     == "",             "alertId empty")

m_rid2 = build_playbook_mapping([pb1], TS, reasoning_id="rid-solo-001")
_assert(m_rid.mappingId == m_rid2.mappingId, "reasoning-only mapping deterministic")

# alert_id only
m_aidonly = build_playbook_mapping([pb2], TS, alert_id="aid-solo")
_assert(m_aidonly.alertId    == "aid-solo", "alert-only mapping")
_assert(m_aidonly.findingId  == "",         "findingId empty in alert-only")
_assert(m_aidonly.reasoningId == "",        "reasoningId empty in alert-only")


# ===========================================================================
# 26. Sorting tie-breaking determinism
# ===========================================================================
print("\n[26] Sort tie-breaking determinism")

# Build playbooks with same severity — tie broken by playbookId
pb_tie1 = build_playbook("Alpha", PlaybookSeverityEnum.HIGH, TS, confidence=50.0)
pb_tie2 = build_playbook("Beta",  PlaybookSeverityEnum.HIGH, TS, confidence=50.0)
pb_tie3 = build_playbook("Gamma", PlaybookSeverityEnum.HIGH, TS, confidence=50.0)

sorted_ties = sort_playbooks([pb_tie3, pb_tie1, pb_tie2], by="severity")
ids_sorted = [p.playbookId for p in sorted_ties]
# ascending=False → primary key DESC, tie broken by playbookId ASC (secondary always ASC)
# verify the IDs are consistently ordered (stable deterministic order)
sorted_ties_check = sort_playbooks([pb_tie1, pb_tie2, pb_tie3], by="severity")
_assert([p.playbookId for p in sorted_ties] == [p.playbookId for p in sorted_ties_check],
        "tie broken consistently regardless of input order")

# Repeated sorts are identical
sorted_ties2 = sort_playbooks([pb_tie2, pb_tie3, pb_tie1], by="severity")
_assert([p.playbookId for p in sorted_ties] == [p.playbookId for p in sorted_ties2],
        "tie-breaking is stable across different input orders")

# Steps with same stepNumber (tie-breaking by stepId)
step_tie1 = build_playbook_step("p-t", 5, "Tie Step A", PlaybookStepTypeEnum.MANUAL, TS)
step_tie2 = build_playbook_step("p-t", 5, "Tie Step B", PlaybookStepTypeEnum.MANUAL, TS2)
# Note: same playbookId + stepNumber → same key (identical). Use different timestamps to vary content only
# Actually stepKey depends only on playbookId+stepNumber so step_tie1.stepId == step_tie2.stepId
# Use different playbook_id to make them distinct
step_tie1x = build_playbook_step("p-t1", 5, "Tie", PlaybookStepTypeEnum.MANUAL, TS)
step_tie2x = build_playbook_step("p-t2", 5, "Tie", PlaybookStepTypeEnum.MANUAL, TS)
sorted_step_ties = sort_playbook_steps([step_tie2x, step_tie1x], by="stepNumber")
step_ids_t = [s.stepId for s in sorted_step_ties]
_assert(step_ids_t == sorted(step_ids_t), "step tie broken by stepId ASC")

# ===========================================================================
# 27. Filter cascade (multiple criteria ANDed)
# ===========================================================================
print("\n[27] Filter cascade")

pb_cas1 = build_playbook("Cascade 1", PlaybookSeverityEnum.CRITICAL, TS,
                          status=PlaybookStatusEnum.ACTIVE, confidence=85.0,
                          related_threat_actors=["APT29"])
pb_cas2 = build_playbook("Cascade 2", PlaybookSeverityEnum.CRITICAL, TS,
                          status=PlaybookStatusEnum.DRAFT, confidence=85.0,
                          related_threat_actors=["APT29"])
pb_cas3 = build_playbook("Cascade 3", PlaybookSeverityEnum.HIGH, TS,
                          status=PlaybookStatusEnum.ACTIVE, confidence=85.0,
                          related_threat_actors=["APT29"])

cascade_pool = [pb_cas1, pb_cas2, pb_cas3]

r_cas = filter_playbooks(cascade_pool,
                          severity=PlaybookSeverityEnum.CRITICAL,
                          status=PlaybookStatusEnum.ACTIVE,
                          threat_actor="APT29")
_assert(len(r_cas) == 1 and r_cas[0].playbookId == pb_cas1.playbookId,
        "cascade filter: 3 criteria → 1 result")

r_cas2 = filter_playbooks(cascade_pool,
                           severity=PlaybookSeverityEnum.CRITICAL,
                           threat_actor="APT29")
_assert(len(r_cas2) == 2, "cascade filter: 2 criteria → 2 results")

r_cas3 = filter_playbooks(cascade_pool, min_confidence=90.0, threat_actor="APT29")
_assert(len(r_cas3) == 0, "cascade filter: min_confidence too high → 0 results")


# ===========================================================================
# 28. Model Field Types
# ===========================================================================
print("\n[28] Model field types")

_assert(isinstance(step_a.stepId,            str),   "stepId is str")
_assert(isinstance(step_a.stepKey,           str),   "stepKey is str")
_assert(isinstance(step_a.stepNumber,        int),   "stepNumber is int")
_assert(isinstance(step_a.title,             str),   "title is str")
_assert(isinstance(step_a.description,       str),   "description is str")
_assert(isinstance(step_a.stepType,          PlaybookStepTypeEnum), "stepType is enum")
_assert(isinstance(step_a.expectedOutcome,   str),   "expectedOutcome is str")
_assert(isinstance(step_a.relatedTechniques, tuple), "relatedTechniques is tuple")
_assert(isinstance(step_a.relatedCVEs,       tuple), "relatedCVEs is tuple")
_assert(isinstance(step_a.relatedIOCs,       tuple), "relatedIOCs is tuple")
_assert(isinstance(step_a.createdAt,         str),   "createdAt is str")

_assert(isinstance(pb1.playbookId,          str),   "playbookId is str")
_assert(isinstance(pb1.playbookKey,         str),   "playbookKey is str")
_assert(isinstance(pb1.name,                str),   "name is str")
_assert(isinstance(pb1.description,         str),   "description is str")
_assert(isinstance(pb1.severity,            PlaybookSeverityEnum), "severity is enum")
_assert(isinstance(pb1.status,              PlaybookStatusEnum),   "status is enum")
_assert(isinstance(pb1.steps,               tuple), "steps is tuple")
_assert(isinstance(pb1.relatedThreatActors, tuple), "relatedThreatActors is tuple")
_assert(isinstance(pb1.relatedCampaigns,    tuple), "relatedCampaigns is tuple")
_assert(isinstance(pb1.confidence,          float), "confidence is float")
_assert(isinstance(pb1.createdAt,           str),   "createdAt is str")

_assert(isinstance(m1.mappingId,          str),   "mappingId is str")
_assert(isinstance(m1.mappingKey,         str),   "mappingKey is str")
_assert(isinstance(m1.mappingFingerprint, str),   "mappingFingerprint is str")
_assert(isinstance(m1.findingId,          str),   "findingId is str")
_assert(isinstance(m1.alertId,            str),   "alertId is str")
_assert(isinstance(m1.reasoningId,        str),   "reasoningId is str")
_assert(isinstance(m1.playbooks,          tuple), "playbooks is tuple")
_assert(isinstance(m1.confidence,         float), "mapping confidence is float")
_assert(isinstance(m1.createdAt,          str),   "mapping createdAt is str")

_assert(isinstance(stats.totalPlaybooks,      int),   "stats totalPlaybooks int")
_assert(isinstance(stats.averageConfidence,   float), "stats avgConf float")
_assert(isinstance(stats.averageSteps,        float), "stats avgSteps float")
_assert(isinstance(stats.severityCounts,      dict),  "stats severityCounts dict")
_assert(isinstance(stats.statusCounts,        dict),  "stats statusCounts dict")


# ===========================================================================
# 29. validate=False bypass
# ===========================================================================
print("\n[29] validate=False bypass")

# build_playbook_step with invalid step_number — validate=False bypasses check
step_inv = build_playbook_step("p", 0, "T", PlaybookStepTypeEnum.MANUAL, TS, validate=False)
_assert(step_inv.stepNumber == 0, "validate=False: invalid stepNumber accepted")

# build_playbook with empty name — validate=False bypasses check
pb_inv = build_playbook("", PlaybookSeverityEnum.HIGH, TS, validate=False)
_assert(pb_inv.name == "", "validate=False: empty name accepted")

# build_playbook_mapping with no sources — validate=False bypasses check
m_inv = build_playbook_mapping([pb1], TS, validate=False)
_assert(m_inv.findingId == "", "validate=False: no source accepted")

# ===========================================================================
# 30. Grouping — unknown attribute fallback
# ===========================================================================
print("\n[30] Grouping unknown attribute fallback")

g_unk = group_playbooks([pb1], group_by="nonexistent_field")
_assert("unknown" in g_unk, "group_playbooks unknown field → 'unknown' key")

g_unk_s = group_playbook_steps([step_a], group_by="nonexistent_field")
_assert("unknown" in g_unk_s, "group_steps unknown field → 'unknown' key")

g_unk_m = group_playbook_mappings([m_a], group_by="nonexistent_field")
_assert("unknown" in g_unk_m, "group_mappings unknown field → 'unknown' key")


# ===========================================================================
# Final Report
# ===========================================================================
print("\n" + "=" * 60)
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
