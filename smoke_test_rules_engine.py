"""
Smoke Test — Rules Engine
==========================
Phase A4.5.1 — Comprehensive deterministic test suite.

Covers
------
- Enumerations: RuleSeverityEnum, RuleStatusEnum, RuleActionEnum
- Engine version constant
- Exception hierarchy
- Deterministic IDs: conditionKey, ruleKey, mappingKey, mappingFingerprint
- Models: RuleCondition, Rule, RuleMapping, RuleStatistics
- Builders: build_rule_condition, build_rule, build_rule_mapping,
  build_rule_statistics (with severityCounts + actionCounts)
- Validators: validate_rule_condition, validate_rule, validate_rule_mapping
- Rule Operations: add_rule, update_rule, remove_rule, merge_rules
- Condition Operations: add_rule_condition, update_rule_condition,
  remove_rule_condition, merge_rule_conditions
- Mapping Operations: add_rule_mapping, remove_rule_mapping,
  merge_rule_mappings
- Search: find_rule, find_rule_condition, find_rule_mapping
- Sorting: sort_rules, sort_rule_conditions, sort_rule_mappings
- Filtering: filter_rules, filter_rule_conditions, filter_rule_mappings
- Grouping: group_rules, group_rule_conditions, group_rule_mappings
- Statistics: extended fields (severityCounts, actionCounts)
- Serialization: model_dump round-trip
- Immutability: frozen model enforcement
- Integration helpers
- Edge cases, zero randomness, deterministic fingerprints, large dataset stability

Target: 500+ assertions
"""

from __future__ import annotations

import sys

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
from services.rules_engine_service import (
    # Engine version
    RULES_ENGINE_VERSION,
    # Enums
    RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
    # Exceptions
    RulesEngineError, InvalidRuleError,
    InvalidRuleConditionError, InvalidRuleMappingError,
    # Models
    RuleCondition, Rule, RuleMapping, RuleStatistics,
    # Key derivation
    conditionKey, ruleKey, mappingKey, mappingFingerprint,
    # Validators
    validate_rule_condition, validate_rule, validate_rule_mapping,
    # Builders
    build_rule_condition, build_rule, build_rule_mapping,
    build_rule_statistics,
    # Rule operations
    add_rule, update_rule, remove_rule, merge_rules,
    # Condition operations
    add_rule_condition, update_rule_condition,
    remove_rule_condition, merge_rule_conditions,
    # Mapping operations
    add_rule_mapping, remove_rule_mapping, merge_rule_mappings,
    # Search
    find_rule, find_rule_condition, find_rule_mapping,
    # Sorting
    sort_rules, sort_rule_conditions, sort_rule_mappings,
    # Filtering
    filter_rules, filter_rule_conditions, filter_rule_mappings,
    # Grouping
    group_rules, group_rule_conditions, group_rule_mappings,
    # Integration helpers
    finding_to_rule_mapping, alert_to_rule_mapping,
    reasoning_to_rule_mapping, playbook_to_rule_reference,
    threat_to_rule_reference,
)

TS  = "2026-07-02T00:00:00Z"
TS2 = "2026-07-03T00:00:00Z"

print("=" * 60)
print("Rules Engine Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. Engine Version
# ===========================================================================
print("\n[1] Engine Version")
_assert(RULES_ENGINE_VERSION == "rules-engine-v1", "engine version value")
_assert(isinstance(RULES_ENGINE_VERSION, str),      "engine version is str")

# ===========================================================================
# 2. Enumerations
# ===========================================================================
print("\n[2] Enumerations")
_assert(RuleSeverityEnum.LOW.value      == "LOW",      "sev LOW")
_assert(RuleSeverityEnum.MEDIUM.value   == "MEDIUM",   "sev MEDIUM")
_assert(RuleSeverityEnum.HIGH.value     == "HIGH",     "sev HIGH")
_assert(RuleSeverityEnum.CRITICAL.value == "CRITICAL", "sev CRITICAL")
_assert(len(list(RuleSeverityEnum)) == 4, "4 severity values")

_assert(RuleStatusEnum.DRAFT.value    == "DRAFT",    "status DRAFT")
_assert(RuleStatusEnum.ACTIVE.value   == "ACTIVE",   "status ACTIVE")
_assert(RuleStatusEnum.DISABLED.value == "DISABLED", "status DISABLED")
_assert(RuleStatusEnum.ARCHIVED.value == "ARCHIVED", "status ARCHIVED")
_assert(len(list(RuleStatusEnum)) == 4, "4 status values")

_assert(RuleActionEnum.CREATE_FINDING.value     == "CREATE_FINDING",     "action CREATE_FINDING")
_assert(RuleActionEnum.CREATE_ALERT.value       == "CREATE_ALERT",       "action CREATE_ALERT")
_assert(RuleActionEnum.UPDATE_SEVERITY.value    == "UPDATE_SEVERITY",    "action UPDATE_SEVERITY")
_assert(RuleActionEnum.TAG_INVESTIGATION.value  == "TAG_INVESTIGATION",  "action TAG_INVESTIGATION")
_assert(RuleActionEnum.START_PLAYBOOK.value     == "START_PLAYBOOK",     "action START_PLAYBOOK")
_assert(RuleActionEnum.ADD_TIMELINE_EVENT.value == "ADD_TIMELINE_EVENT", "action ADD_TIMELINE_EVENT")
_assert(len(list(RuleActionEnum)) == 6, "6 action values")

# ===========================================================================
# 3. Exception Hierarchy
# ===========================================================================
print("\n[3] Exception Hierarchy")
_assert(issubclass(InvalidRuleError,          RulesEngineError), "InvalidRuleError is subclass")
_assert(issubclass(InvalidRuleConditionError, RulesEngineError), "InvalidRuleConditionError is subclass")
_assert(issubclass(InvalidRuleMappingError,   RulesEngineError), "InvalidRuleMappingError is subclass")
_assert(issubclass(RulesEngineError,          Exception),        "RulesEngineError is Exception subclass")

# ===========================================================================
# 4. Deterministic ID Helpers
# ===========================================================================
print("\n[4] Deterministic ID Helpers")

# conditionKey
ck1 = conditionKey("severity", "eq", "HIGH")
ck2 = conditionKey("severity", "eq", "HIGH")
ck3 = conditionKey("severity", "eq", "LOW")
_assert(ck1 == ck2,       "conditionKey deterministic")
_assert(ck1 != ck3,       "conditionKey different value differs")
_assert(len(ck1) == 32,   "conditionKey length 32")
_assert(ck1.islower(),    "conditionKey lowercase hex")

ck_field_diff = conditionKey("protocol", "eq", "HIGH")
_assert(ck1 != ck_field_diff, "conditionKey different field differs")
ck_op_diff = conditionKey("severity", "gt", "HIGH")
_assert(ck1 != ck_op_diff,    "conditionKey different operator differs")

# ruleKey
c_a = build_rule_condition("severity", "eq", "HIGH", TS)
c_b = build_rule_condition("protocol", "contains", "TLS", TS)

rk1 = ruleKey("Rule A", RuleSeverityEnum.HIGH, (c_a.conditionId,), (RuleActionEnum.CREATE_ALERT,))
rk2 = ruleKey("Rule A", RuleSeverityEnum.HIGH, (c_a.conditionId,), (RuleActionEnum.CREATE_ALERT,))
rk3 = ruleKey("Rule B", RuleSeverityEnum.HIGH, (c_a.conditionId,), (RuleActionEnum.CREATE_ALERT,))
_assert(rk1 == rk2,     "ruleKey deterministic")
_assert(rk1 != rk3,     "ruleKey different name differs")
_assert(len(rk1) == 32, "ruleKey length 32")

# ruleKey order-independent over condition IDs
rk_ord1 = ruleKey("R", RuleSeverityEnum.LOW, (c_a.conditionId, c_b.conditionId), ())
rk_ord2 = ruleKey("R", RuleSeverityEnum.LOW, (c_b.conditionId, c_a.conditionId), ())
_assert(rk_ord1 == rk_ord2, "ruleKey order-independent over conditionIds")

# ruleKey order-independent over actions
rk_act1 = ruleKey("R", RuleSeverityEnum.LOW, (), (RuleActionEnum.CREATE_ALERT, RuleActionEnum.CREATE_FINDING))
rk_act2 = ruleKey("R", RuleSeverityEnum.LOW, (), (RuleActionEnum.CREATE_FINDING, RuleActionEnum.CREATE_ALERT))
_assert(rk_act1 == rk_act2, "ruleKey order-independent over actions")

# mappingKey
mk1 = mappingKey("fid-1", "aid-1", "rid-1", ("rule-a", "rule-b"))
mk2 = mappingKey("fid-1", "aid-1", "rid-1", ("rule-b", "rule-a"))
mk3 = mappingKey("fid-2", "aid-1", "rid-1", ("rule-a", "rule-b"))
_assert(mk1 == mk2,     "mappingKey order-independent")
_assert(mk1 != mk3,     "mappingKey different findingId differs")
_assert(len(mk1) == 32, "mappingKey length 32")

# mappingFingerprint
fp1 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("rule-a", "rule-b"))
fp2 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("rule-b", "rule-a"))
fp3 = mappingFingerprint(mk1, "fid-1", "aid-1", "rid-1", ("rule-a", "rule-c"))
_assert(fp1 == fp2,     "mappingFingerprint order-independent")
_assert(fp1 != fp3,     "mappingFingerprint different ids differ")
_assert(len(fp1) == 32, "mappingFingerprint length 32")
_assert(mk1 != fp1,     "mappingKey and mappingFingerprint differ")


# ===========================================================================
# 5. Validators
# ===========================================================================
print("\n[5] Validators")

# validate_rule_condition — happy path
validate_rule_condition("severity", "eq", "HIGH", TS)
_assert(True, "validate_rule_condition happy path")

_assert_raises(InvalidRuleConditionError, validate_rule_condition, "",         "eq", "HIGH", TS,  msg="empty field rejected")
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "  ",       "eq", "HIGH", TS,  msg="whitespace field rejected")
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "severity", "",   "HIGH", TS,  msg="empty operator rejected")
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "severity", "eq", "",    TS,   msg="empty value rejected")
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "severity", "eq", "HIGH", "",  msg="empty createdAt rejected")
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "severity", "eq", "  ",  TS,   msg="whitespace value rejected")

# validate_rule — happy path
validate_rule("My Rule", RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 10, TS)
_assert(True, "validate_rule happy path")

_assert_raises(InvalidRuleError, validate_rule, "",         RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 10, TS,   msg="empty name rejected")
_assert_raises(InvalidRuleError, validate_rule, "  ",       RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 10, TS,   msg="whitespace name rejected")
_assert_raises(InvalidRuleError, validate_rule, "R",        "BAD",                 RuleStatusEnum.ACTIVE, 10, TS,   msg="bad severity rejected")
_assert_raises(InvalidRuleError, validate_rule, "R",        RuleSeverityEnum.HIGH, "BAD",                 10, TS,   msg="bad status rejected")
_assert_raises(InvalidRuleError, validate_rule, "R",        RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 0,  TS,   msg="priority 0 rejected")
_assert_raises(InvalidRuleError, validate_rule, "R",        RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, -1, TS,   msg="priority -1 rejected")
_assert_raises(InvalidRuleError, validate_rule, "R",        RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 10, "",   msg="empty createdAt rejected")

# validate_rule_mapping — happy path
validate_rule_mapping("fid-1", "", "", 50.0, TS)
_assert(True, "validate_rule_mapping happy path (findingId only)")

validate_rule_mapping("", "aid-1", "", 50.0, TS)
_assert(True, "validate_rule_mapping happy path (alertId only)")

validate_rule_mapping("", "", "rid-1", 50.0, TS)
_assert(True, "validate_rule_mapping happy path (reasoningId only)")

_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "",    "",    "",    50.0,  TS, msg="all empty sources rejected")
_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "  ",  "  ", "  ",  50.0,  TS, msg="whitespace-only sources rejected")
_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "fid", "",   "",    -1.0,  TS, msg="confidence -1 rejected")
_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "fid", "",   "",    101.0, TS, msg="confidence 101 rejected")
_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "fid", "",   "",    50.0,  "", msg="empty createdAt rejected")

# ===========================================================================
# 6. Builder: build_rule_condition
# ===========================================================================
print("\n[6] build_rule_condition")

cond1 = build_rule_condition("severity", "eq", "HIGH", TS)
cond1b = build_rule_condition("severity", "eq", "HIGH", TS)
cond2  = build_rule_condition("protocol", "contains", "TLS", TS)
cond3  = build_rule_condition("packet_count", "gt", "100", TS2)

_assert(isinstance(cond1, RuleCondition),      "cond1 is RuleCondition")
_assert(cond1.conditionId  == cond1b.conditionId,  "conditionId deterministic")
_assert(cond1.conditionKey == cond1b.conditionKey, "conditionKey deterministic")
_assert(len(cond1.conditionId)  == 36, "conditionId is UUID")
_assert(len(cond1.conditionKey) == 32, "conditionKey is 32 chars")
_assert(cond1.field    == "severity", "field preserved")
_assert(cond1.operator == "eq",       "operator preserved")
_assert(cond1.value    == "HIGH",     "value preserved")
_assert(cond1.createdAt == TS,        "createdAt preserved")

_assert(cond1.conditionId != cond2.conditionId, "different field → different ID")
_assert(cond1.conditionId != cond3.conditionId, "different value+ts → different ID")

# Whitespace stripping
cond_ws = build_rule_condition("  severity  ", "  eq  ", "  HIGH  ", TS)
_assert(cond_ws.field    == "severity", "field stripped")
_assert(cond_ws.operator == "eq",       "operator stripped")
_assert(cond_ws.value    == "HIGH",     "value stripped")
_assert(cond_ws.conditionId == cond1.conditionId, "stripped condition matches")

# validate=False skips validation
cond_noval = build_rule_condition("", "eq", "x", TS, validate=False)
_assert(cond_noval.field == "", "validate=False allows empty field")

_assert_raises(InvalidRuleConditionError, build_rule_condition, "", "eq", "v", TS,
               msg="build_rule_condition validates empty field")

# ===========================================================================
# 7. Builder: build_rule
# ===========================================================================
print("\n[7] build_rule")

rule1 = build_rule(
    name        = "High Severity TLS",
    severity    = RuleSeverityEnum.HIGH,
    created_at  = TS,
    description = "Fires on HIGH severity with TLS traffic.",
    status      = RuleStatusEnum.ACTIVE,
    conditions  = [cond1, cond2],
    actions     = [RuleActionEnum.CREATE_ALERT, RuleActionEnum.TAG_INVESTIGATION],
    priority    = 10,
)
rule1_dup = build_rule(
    name        = "High Severity TLS",
    severity    = RuleSeverityEnum.HIGH,
    created_at  = TS,
    conditions  = [cond2, cond1],   # reversed order
    actions     = [RuleActionEnum.TAG_INVESTIGATION, RuleActionEnum.CREATE_ALERT],  # reversed
    priority    = 10,
)
_assert(isinstance(rule1, Rule),            "rule1 is Rule")
_assert(rule1.ruleId  == rule1_dup.ruleId,  "ruleId deterministic")
_assert(rule1.ruleKey == rule1_dup.ruleKey, "ruleKey deterministic")
_assert(len(rule1.ruleId)  == 36, "ruleId is UUID")
_assert(len(rule1.ruleKey) == 32, "ruleKey is 32 chars")
_assert(rule1.name        == "High Severity TLS", "name preserved")
_assert(rule1.severity    == RuleSeverityEnum.HIGH,    "severity preserved")
_assert(rule1.status      == RuleStatusEnum.ACTIVE,    "status preserved")
_assert(rule1.priority    == 10,                       "priority preserved")
_assert(rule1.createdAt   == TS,                       "createdAt preserved")
_assert(len(rule1.conditions) == 2, "two conditions stored")
_assert(len(rule1.actions)    == 2, "two actions stored")

# Conditions sorted by conditionId ASC
_assert(rule1.conditions[0].conditionId <= rule1.conditions[1].conditionId,
        "conditions sorted by conditionId ASC")

# Actions sorted by value ASC
action_vals = [a.value for a in rule1.actions]
_assert(action_vals == sorted(action_vals), "actions sorted by value ASC")

# Duplicate actions are deduplicated
rule_dedup_actions = build_rule(
    "R", RuleSeverityEnum.LOW, TS,
    actions=[RuleActionEnum.CREATE_ALERT, RuleActionEnum.CREATE_ALERT, RuleActionEnum.CREATE_FINDING],
)
_assert(len(rule_dedup_actions.actions) == 2, "duplicate actions deduplicated")

# Default status is DRAFT
rule_draft = build_rule("Draft Rule", RuleSeverityEnum.MEDIUM, TS)
_assert(rule_draft.status == RuleStatusEnum.DRAFT, "default status DRAFT")

# Default priority is 100
rule_default_prio = build_rule("P Rule", RuleSeverityEnum.LOW, TS)
_assert(rule_default_prio.priority == 100, "default priority 100")

# Empty conditions / actions
rule_empty = build_rule("Empty Rule", RuleSeverityEnum.LOW, TS)
_assert(rule_empty.conditions == (), "empty conditions tuple")
_assert(rule_empty.actions    == (), "empty actions tuple")

# Different severity → different ID
rule_crit = build_rule("High Severity TLS", RuleSeverityEnum.CRITICAL, TS,
                        conditions=[cond1, cond2],
                        actions=[RuleActionEnum.CREATE_ALERT, RuleActionEnum.TAG_INVESTIGATION],
                        priority=10)
_assert(rule_crit.ruleId != rule1.ruleId, "different severity → different ruleId")

# Confidence clamping via priority bounds
_assert_raises(InvalidRuleError, build_rule, "R", RuleSeverityEnum.LOW, TS, priority=0,
               msg="priority 0 rejected by build_rule")

# validate=False skips validation
rule_noval = build_rule("", RuleSeverityEnum.LOW, TS, validate=False)
_assert(rule_noval.name == "", "validate=False allows empty name")

# ===========================================================================
# 8. Builder: build_rule_mapping
# ===========================================================================
print("\n[8] build_rule_mapping")

rule2 = build_rule("DNS Flood", RuleSeverityEnum.CRITICAL, TS,
                   actions=[RuleActionEnum.CREATE_FINDING, RuleActionEnum.START_PLAYBOOK],
                   status=RuleStatusEnum.ACTIVE, priority=5)
rule3 = build_rule("Low Priority Rule", RuleSeverityEnum.LOW, TS,
                   actions=[RuleActionEnum.ADD_TIMELINE_EVENT], priority=200)

m1 = build_rule_mapping(
    matched_rules = [rule1, rule2],
    created_at    = TS,
    finding_id    = "fid-001",
    alert_id      = "aid-001",
    confidence    = 80.0,
)
m1_dup = build_rule_mapping(
    matched_rules = [rule2, rule1],  # reversed
    created_at    = TS,
    finding_id    = "fid-001",
    alert_id      = "aid-001",
    confidence    = 80.0,
)
_assert(isinstance(m1, RuleMapping),              "m1 is RuleMapping")
_assert(m1.mappingId  == m1_dup.mappingId,        "mappingId deterministic")
_assert(m1.mappingKey == m1_dup.mappingKey,        "mappingKey deterministic")
_assert(m1.mappingFingerprint == m1_dup.mappingFingerprint, "mappingFingerprint deterministic")
_assert(len(m1.mappingId)          == 36, "mappingId is UUID")
_assert(len(m1.mappingKey)         == 32, "mappingKey is 32 chars")
_assert(len(m1.mappingFingerprint) == 32, "mappingFingerprint is 32 chars")
_assert(m1.findingId   == "fid-001", "findingId preserved")
_assert(m1.alertId     == "aid-001", "alertId preserved")
_assert(m1.reasoningId == "",        "reasoningId empty when not supplied")
_assert(m1.confidence  == 80.0,      "confidence preserved")
_assert(len(m1.matchedRules) == 2,   "both rules in mapping")
_assert(m1.mappingKey != m1.mappingFingerprint, "key and fingerprint differ")

# Rules sorted by priority ASC then ruleId ASC
# rule2 has priority=5, rule1 has priority=10 → rule2 first
_assert(m1.matchedRules[0].ruleId == rule2.ruleId, "lowest priority rule first in mapping")
_assert(m1.matchedRules[1].ruleId == rule1.ruleId, "higher priority rule second")

# Different content → different fingerprint
m2 = build_rule_mapping([rule2], TS, finding_id="fid-001", alert_id="aid-001", confidence=80.0)
_assert(m1.mappingFingerprint != m2.mappingFingerprint, "different rules → different fingerprint")

# Confidence clamping
m_hi = build_rule_mapping([rule1], TS, finding_id="f", confidence=200.0)
m_lo = build_rule_mapping([rule1], TS, finding_id="f", confidence=-5.0)
_assert(m_hi.confidence == 100.0, "confidence clamped to 100")
_assert(m_lo.confidence == 0.0,   "confidence clamped to 0")

# Boundary values
m_100 = build_rule_mapping([rule1], TS, finding_id="f", confidence=100.0)
m_0   = build_rule_mapping([rule1], TS, finding_id="f", confidence=0.0)
_assert(m_100.confidence == 100.0, "confidence 100.0 accepted")
_assert(m_0.confidence   == 0.0,   "confidence 0.0 accepted")

# No source ID → validation error
_assert_raises(InvalidRuleMappingError, build_rule_mapping, [rule1], TS,
               msg="no source id rejected")

# reasoning_id only
m_r = build_rule_mapping([rule1], TS, reasoning_id="rid-xyz")
_assert(m_r.reasoningId == "rid-xyz", "reasoning_id only mapping accepted")
_assert(m_r.findingId   == "",        "findingId empty")
_assert(m_r.alertId     == "",        "alertId empty")

# ===========================================================================
# 9. Rule Operations: add_rule, update_rule, remove_rule, merge_rules
# ===========================================================================
print("\n[9] Rule Operations")

rule4 = build_rule("Archive Rule",  RuleSeverityEnum.MEDIUM,   TS, status=RuleStatusEnum.ARCHIVED, priority=50)
rule5 = build_rule("Disabled Rule", RuleSeverityEnum.CRITICAL, TS, status=RuleStatusEnum.DISABLED, priority=1)

# add_rule
rl = []
rl = add_rule(rl, rule1)
_assert(len(rl) == 1, "add first rule")
rl = add_rule(rl, rule2)
_assert(len(rl) == 2, "add second rule")
rl_dup = add_rule(rl, rule1)
_assert(len(rl_dup) == 2, "duplicate not added")
# Result sorted by ruleId
_assert(rl[0].ruleId <= rl[1].ruleId, "add_rule returns sorted list")
# Does not mutate input
orig = [rule1]
add_rule(orig, rule2)
_assert(len(orig) == 1, "add_rule does not mutate input list")

# remove_rule
rl2 = remove_rule(rl, rule1.ruleId)
_assert(len(rl2) == 1,                     "rule removed")
_assert(rl2[0].ruleId == rule2.ruleId,     "correct rule remains")
rl3 = remove_rule(rl2, rule1.ruleId)       # idempotent
_assert(len(rl3) == 1, "remove non-existent is idempotent")
# Does not mutate input
orig2 = [rule1, rule2]
remove_rule(orig2, rule1.ruleId)
_assert(len(orig2) == 2, "remove_rule does not mutate input list")

# update_rule — description only (identity preserved)
rl4 = add_rule([], rule1)
rl5 = update_rule(rl4, rule1.ruleId, TS2, description="Updated description")
_assert(len(rl5) == 1,                           "update returns same count")
_assert(rl5[0].description == "Updated description", "description updated")
_assert(rl5[0].ruleId  == rule1.ruleId,          "ruleId preserved on metadata-only update")
_assert(rl5[0].ruleKey == rule1.ruleKey,          "ruleKey preserved on metadata-only update")
_assert(rl5[0].name    == rule1.name,             "name unchanged")

# update_rule — status only (identity preserved)
rl6 = update_rule(rl4, rule1.ruleId, TS2, status=RuleStatusEnum.ARCHIVED)
_assert(rl6[0].status  == RuleStatusEnum.ARCHIVED, "status updated")
_assert(rl6[0].ruleId  == rule1.ruleId,            "ruleId preserved on status update")

# update_rule — priority only (identity preserved)
rl7 = update_rule(rl4, rule1.ruleId, TS2, priority=5)
_assert(rl7[0].priority == 5,          "priority updated")
_assert(rl7[0].ruleId   == rule1.ruleId, "ruleId preserved on priority update")

# update_rule — name change recomputes identity
rl8 = update_rule(rl4, rule1.ruleId, TS2, name="New Rule Name")
_assert(rl8[0].name   == "New Rule Name",       "name updated")
_assert(rl8[0].ruleId != rule1.ruleId,          "ruleId recomputed on name change")

# update_rule — severity change recomputes identity
rl9 = update_rule(rl4, rule1.ruleId, TS2, severity=RuleSeverityEnum.CRITICAL)
_assert(rl9[0].severity == RuleSeverityEnum.CRITICAL, "severity updated")
_assert(rl9[0].ruleId   != rule1.ruleId,              "ruleId recomputed on severity change")

# update_rule — not found returns unchanged list
rl_nf = update_rule(rl4, "non-existent-id", TS2, description="X")
_assert(len(rl_nf) == 1,                 "update not-found: list unchanged count")
_assert(rl_nf[0].ruleId == rule1.ruleId, "update not-found: original preserved")

# Does not mutate input list
orig3 = [rule1]
update_rule(orig3, rule1.ruleId, TS2, description="X")
_assert(orig3[0].description == rule1.description, "update_rule does not mutate input")

# merge_rules
base_rl     = [rule1, rule4]
incoming_rl = [rule4, rule5]  # rule4 is dup
merged_rl   = merge_rules(base_rl, incoming_rl)
_assert(len(merged_rl) == 3,              "merge: 3 unique rules")
ids_in_merge = {r.ruleId for r in merged_rl}
_assert(rule1.ruleId in ids_in_merge,     "merge: rule1 present")
_assert(rule4.ruleId in ids_in_merge,     "merge: rule4 present (base wins)")
_assert(rule5.ruleId in ids_in_merge,     "merge: rule5 added from incoming")
# Base wins for duplicate
base_rule4 = next(r for r in merged_rl if r.ruleId == rule4.ruleId)
_assert(base_rule4.name == rule4.name,    "merge: base version preserved for duplicate")
# Sorted
_assert(all(merged_rl[i].ruleId <= merged_rl[i+1].ruleId
            for i in range(len(merged_rl)-1)), "merge result sorted by ruleId")

# Merge empty cases
_assert(len(merge_rules([], [])) == 0,          "merge empty+empty → 0")
_assert(len(merge_rules([rule1], [])) == 1,      "merge base+empty → 1")
_assert(len(merge_rules([], [rule1])) == 1,      "merge empty+incoming → 1")
# Merge all duplicates
_assert(len(merge_rules([rule1, rule2], [rule1, rule2])) == 2, "merge all dups → 2")

# ===========================================================================
# 10. Condition Operations
# ===========================================================================
print("\n[10] Condition Operations")

base_rule = build_rule("Condition Test Rule", RuleSeverityEnum.HIGH, TS, priority=20)
_assert(len(base_rule.conditions) == 0, "base_rule starts with no conditions")

# add_rule_condition
r_with_c1 = add_rule_condition(base_rule, cond1)
_assert(len(r_with_c1.conditions) == 1, "first condition added")
_assert(r_with_c1.conditions[0].conditionId == cond1.conditionId, "correct condition added")
_assert(r_with_c1.ruleId != base_rule.ruleId, "ruleId recomputed after add_rule_condition")
_assert(r_with_c1.name == base_rule.name, "name preserved after add")

r_with_c1c2 = add_rule_condition(r_with_c1, cond2)
_assert(len(r_with_c1c2.conditions) == 2, "second condition added")
# Conditions sorted by conditionId ASC
cids = [c.conditionId for c in r_with_c1c2.conditions]
_assert(cids == sorted(cids), "conditions remain sorted after add")

# Idempotent: duplicate conditionId not added
r_dup_c = add_rule_condition(r_with_c1, cond1)
_assert(len(r_dup_c.conditions) == 1,           "duplicate condition not added")
_assert(r_dup_c.ruleId == r_with_c1.ruleId,     "ruleId unchanged on duplicate add")

# Does not mutate original rule
_assert(len(base_rule.conditions) == 0, "add_rule_condition does not mutate original rule")

# update_rule_condition — change value
r_updated_c = update_rule_condition(r_with_c1c2, cond1.conditionId, value="CRITICAL")
updated_c1 = next(c for c in r_updated_c.conditions if c.field == "severity")
_assert(updated_c1.value == "CRITICAL",           "condition value updated")
_assert(updated_c1.field == "severity",           "condition field unchanged")
_assert(updated_c1.operator == "eq",              "condition operator unchanged")
# conditionId changes because value changed (identity-defining)
_assert(updated_c1.conditionId != cond1.conditionId, "conditionId recomputed on value change")
# ruleId changes
_assert(r_updated_c.ruleId != r_with_c1c2.ruleId, "ruleId recomputed on condition update")

# update_rule_condition — not found returns original rule
r_nf_c = update_rule_condition(r_with_c1c2, "non-existent-condition-id", value="X")
_assert(r_nf_c.ruleId == r_with_c1c2.ruleId, "update not-found condition: rule unchanged")

# remove_rule_condition
r_c1_removed = remove_rule_condition(r_with_c1c2, cond1.conditionId)
_assert(len(r_c1_removed.conditions) == 1, "condition removed")
_assert(r_c1_removed.conditions[0].conditionId == cond2.conditionId, "correct condition remains")
_assert(r_c1_removed.ruleId != r_with_c1c2.ruleId, "ruleId recomputed after remove")

# Idempotent remove
r_noop_remove = remove_rule_condition(r_c1_removed, cond1.conditionId)
_assert(r_noop_remove.ruleId == r_c1_removed.ruleId, "remove not-found condition: rule unchanged")
_assert(len(r_noop_remove.conditions) == 1, "condition count unchanged on noop remove")

# merge_rule_conditions
r_merge_base     = add_rule_condition(base_rule, cond1)
r_merged_conds   = merge_rule_conditions(r_merge_base, [cond1, cond2, cond3])
_assert(len(r_merged_conds.conditions) == 3,   "merge_conditions: 3 unique conditions")
all_cids = {c.conditionId for c in r_merged_conds.conditions}
_assert(cond1.conditionId in all_cids, "merge_conds: cond1 present (existing wins)")
_assert(cond2.conditionId in all_cids, "merge_conds: cond2 added")
_assert(cond3.conditionId in all_cids, "merge_conds: cond3 added")
# ruleId recomputed
_assert(r_merged_conds.ruleId != r_merge_base.ruleId, "merge_conds recomputes ruleId")

# merge_rule_conditions no-op: all incoming already present
r_noop_merge = merge_rule_conditions(r_merged_conds, [cond1, cond2, cond3])
_assert(r_noop_merge.ruleId == r_merged_conds.ruleId, "merge_conds noop returns original")

# ===========================================================================
# 11. Mapping Operations
# ===========================================================================
print("\n[11] Mapping Operations")

m_a = build_rule_mapping([rule1], TS, finding_id="fid-a", confidence=70.0)
m_b = build_rule_mapping([rule2], TS, finding_id="fid-b", confidence=60.0)
m_c = build_rule_mapping([rule3], TS, alert_id="aid-c",   confidence=55.0)

# add_rule_mapping
ml = []
ml = add_rule_mapping(ml, m_a)
_assert(len(ml) == 1, "first mapping added")
ml = add_rule_mapping(ml, m_b)
_assert(len(ml) == 2, "second mapping added")
ml_dup = add_rule_mapping(ml, m_a)
_assert(len(ml_dup) == 2, "duplicate mapping not added")
# Sorted by mappingId
_assert(ml[0].mappingId <= ml[1].mappingId, "add_rule_mapping returns sorted list")
# Does not mutate input
orig_ml = [m_a]
add_rule_mapping(orig_ml, m_b)
_assert(len(orig_ml) == 1, "add_rule_mapping does not mutate input list")

# remove_rule_mapping
ml2 = remove_rule_mapping(ml, m_a.mappingId)
_assert(len(ml2) == 1,                        "mapping removed")
_assert(ml2[0].mappingId == m_b.mappingId,    "correct mapping remains")
ml3 = remove_rule_mapping(ml2, m_a.mappingId) # idempotent
_assert(len(ml3) == 1, "remove non-existent mapping is idempotent")
# Does not mutate input
orig_ml2 = [m_a, m_b]
remove_rule_mapping(orig_ml2, m_a.mappingId)
_assert(len(orig_ml2) == 2, "remove_rule_mapping does not mutate input list")

# merge_rule_mappings
base_ml     = [m_a, m_b]
incoming_ml = [m_b, m_c]  # m_b is dup
merged_ml   = merge_rule_mappings(base_ml, incoming_ml)
_assert(len(merged_ml) == 3,              "merge: 3 unique mappings")
mid_set = {m.mappingId for m in merged_ml}
_assert(m_a.mappingId in mid_set,         "merge: m_a present")
_assert(m_b.mappingId in mid_set,         "merge: m_b present (base wins)")
_assert(m_c.mappingId in mid_set,         "merge: m_c added")
# Sorted
_assert(all(merged_ml[i].mappingId <= merged_ml[i+1].mappingId
            for i in range(len(merged_ml)-1)), "merged mappings sorted by mappingId")

# merge empty cases
_assert(len(merge_rule_mappings([], []))     == 0, "merge mappings empty+empty")
_assert(len(merge_rule_mappings([m_a], []))  == 1, "merge mappings base+empty")
_assert(len(merge_rule_mappings([], [m_a]))  == 1, "merge mappings empty+incoming")
# All duplicates
_assert(len(merge_rule_mappings([m_a, m_b], [m_a, m_b])) == 2, "merge all dups → 2")

# ===========================================================================
# 12. Search Utilities
# ===========================================================================
print("\n[12] Search Utilities")

all_rules = [rule1, rule2, rule3, rule4, rule5]

# find_rule by ruleId
found_r = find_rule(all_rules, rule_id=rule1.ruleId)
_assert(found_r is not None,             "find_rule by ruleId found")
_assert(found_r.ruleId == rule1.ruleId,  "find_rule by ruleId correct")

# find_rule by ruleKey
found_r_key = find_rule(all_rules, rule_key=rule2.ruleKey)
_assert(found_r_key is not None,               "find_rule by ruleKey found")
_assert(found_r_key.ruleId == rule2.ruleId,    "find_rule by ruleKey correct")

# find_rule not found
not_found_r = find_rule(all_rules, rule_id="non-existent")
_assert(not_found_r is None, "find_rule returns None for missing ruleId")

# find_rule no criteria
not_found_r2 = find_rule(all_rules)
_assert(not_found_r2 is None, "find_rule with no criteria returns None")

# find_rule in empty list
_assert(find_rule([], rule_id=rule1.ruleId) is None, "find_rule in empty list → None")

# find_rule_condition
rules_with_conds = [r_with_c1c2, rule1]  # r_with_c1c2 has cond1 and cond2
found_c = find_rule_condition(rules_with_conds, condition_id=cond1.conditionId)
_assert(found_c is not None,                    "find_rule_condition by conditionId found")
_assert(found_c.conditionId == cond1.conditionId, "find_rule_condition correct condition")

found_c_key = find_rule_condition(rules_with_conds, condition_key=cond2.conditionKey)
_assert(found_c_key is not None,                     "find_rule_condition by conditionKey found")
_assert(found_c_key.conditionId == cond2.conditionId, "find_rule_condition by conditionKey correct")

not_found_c = find_rule_condition(rules_with_conds, condition_id="non-existent-cond")
_assert(not_found_c is None, "find_rule_condition returns None for missing id")

not_found_c2 = find_rule_condition(rules_with_conds)  # no criteria
_assert(not_found_c2 is None, "find_rule_condition no criteria returns None")

_assert(find_rule_condition([], condition_id="x") is None, "find_rule_condition empty list → None")

# find_rule_mapping
all_ml_search = [m_a, m_b, m_c]
found_m = find_rule_mapping(all_ml_search, mapping_id=m_b.mappingId)
_assert(found_m is not None,               "find_rule_mapping found")
_assert(found_m.mappingId == m_b.mappingId, "find_rule_mapping correct")

not_found_m = find_rule_mapping(all_ml_search, mapping_id="non-existent")
_assert(not_found_m is None, "find_rule_mapping returns None for missing")

not_found_m2 = find_rule_mapping(all_ml_search)  # no criteria
_assert(not_found_m2 is None, "find_rule_mapping no criteria returns None")

_assert(find_rule_mapping([], mapping_id="x") is None, "find_rule_mapping empty list → None")

# ===========================================================================
# 13. Sorting
# ===========================================================================
print("\n[13] Sorting")

# Build pool: rule1=HIGH/ACTIVE/prio=10, rule2=CRITICAL/ACTIVE/prio=5,
#             rule3=LOW/DRAFT/prio=200,  rule4=MEDIUM/ARCHIVED/prio=50,
#             rule5=CRITICAL/DISABLED/prio=1
sort_pool = [rule1, rule2, rule3, rule4, rule5]

# sort_rules by priority ASC (default)
sorted_prio_asc = sort_rules(sort_pool, by="priority", ascending=True)
prios = [r.priority for r in sorted_prio_asc]
_assert(prios == sorted(prios), "sort priority ASC")
_assert(sorted_prio_asc[0].priority == 1, "priority ASC: lowest first (prio=1)")

# sort_rules by priority DESC
sorted_prio_desc = sort_rules(sort_pool, by="priority", ascending=False)
prios_d = [r.priority for r in sorted_prio_desc]
_assert(prios_d == sorted(prios_d, reverse=True), "sort priority DESC")

# sort_rules by severity DESC (highest first)
sorted_sev_desc = sort_rules(sort_pool, by="severity", ascending=False)
_assert(sorted_sev_desc[0].severity == RuleSeverityEnum.CRITICAL, "severity DESC: CRITICAL first")

# sort_rules by severity ASC (lowest first)
sorted_sev_asc = sort_rules(sort_pool, by="severity", ascending=True)
_assert(sorted_sev_asc[0].severity == RuleSeverityEnum.LOW, "severity ASC: LOW first")

# sort_rules by status DESC (ACTIVE first)
sorted_st_desc = sort_rules(sort_pool, by="status", ascending=False)
_assert(sorted_st_desc[0].status == RuleStatusEnum.ACTIVE, "status DESC: ACTIVE first")

# sort_rules by name ASC
sorted_name = sort_rules(sort_pool, by="name", ascending=True)
names = [r.name for r in sorted_name]
_assert(names == sorted(names), "sort name ASC")

# sort_rules by createdAt
sorted_ts = sort_rules(sort_pool, by="createdAt", ascending=True)
_assert(len(sorted_ts) == 5, "sort createdAt returns all rules")

# Invalid key raises ValueError
_assert_raises(ValueError, sort_rules, sort_pool, "invalid_key",
               msg="invalid sort key raises ValueError")

# Determinism: same result on repeated calls
s1 = sort_rules(sort_pool, by="priority")
s2 = sort_rules(sort_pool, by="priority")
_assert([r.ruleId for r in s1] == [r.ruleId for r in s2], "sort_rules deterministic")

# sort_rule_conditions
cond_pool = [cond1, cond2, cond3]

sorted_c_field = sort_rule_conditions(cond_pool, by="field", ascending=True)
fields = [c.field for c in sorted_c_field]
_assert(fields == sorted(fields), "sort conditions by field ASC")

sorted_c_field_desc = sort_rule_conditions(cond_pool, by="field", ascending=False)
fields_d = [c.field for c in sorted_c_field_desc]
_assert(fields_d == sorted(fields_d, reverse=True), "sort conditions by field DESC")

sorted_c_op = sort_rule_conditions(cond_pool, by="operator", ascending=True)
ops = [c.operator for c in sorted_c_op]
_assert(ops == sorted(ops), "sort conditions by operator ASC")

sorted_c_val = sort_rule_conditions(cond_pool, by="value", ascending=True)
vals = [c.value for c in sorted_c_val]
_assert(vals == sorted(vals), "sort conditions by value ASC")

_assert_raises(ValueError, sort_rule_conditions, cond_pool, "bad_key",
               msg="invalid condition sort key raises ValueError")

# Determinism
sc1 = sort_rule_conditions(cond_pool, by="field")
sc2 = sort_rule_conditions(cond_pool, by="field")
_assert([c.conditionId for c in sc1] == [c.conditionId for c in sc2],
        "sort_rule_conditions deterministic")

# sort_rule_mappings by confidence DESC (default)
all_ml_sort = [m_a, m_b, m_c]  # confs: 70, 60, 55
sorted_ml = sort_rule_mappings(all_ml_sort, by="confidence", ascending=False)
confs = [m.confidence for m in sorted_ml]
_assert(confs == sorted(confs, reverse=True), "mapping sort confidence DESC")
_assert(sorted_ml[0].confidence == 70.0, "confidence DESC: 70 first")

sorted_ml_asc = sort_rule_mappings(all_ml_sort, by="confidence", ascending=True)
confs_asc = [m.confidence for m in sorted_ml_asc]
_assert(confs_asc == sorted(confs_asc), "mapping sort confidence ASC")

sorted_ml_ts = sort_rule_mappings(all_ml_sort, by="createdAt", ascending=True)
_assert(len(sorted_ml_ts) == 3, "sort mappings by createdAt returns all")

_assert_raises(ValueError, sort_rule_mappings, all_ml_sort, "bad_key",
               msg="invalid mapping sort key raises ValueError")

# ===========================================================================
# 14. Filtering
# ===========================================================================
print("\n[14] Filtering")

# filter_rules
# sort_pool: rule1=HIGH/ACTIVE/prio=10, rule2=CRITICAL/ACTIVE/prio=5,
#            rule3=LOW/DRAFT/prio=200,  rule4=MEDIUM/ARCHIVED/prio=50,
#            rule5=CRITICAL/DISABLED/prio=1

# filter by severity
r_sev = filter_rules(sort_pool, severity=RuleSeverityEnum.CRITICAL)
_assert(len(r_sev) == 2, "filter severity CRITICAL → 2 rules (rule2 + rule5)")
_assert(all(r.severity == RuleSeverityEnum.CRITICAL for r in r_sev), "all filtered are CRITICAL")

r_sev_none = filter_rules(sort_pool, severity=RuleSeverityEnum.MEDIUM)
_assert(len(r_sev_none) == 1, "filter severity MEDIUM → 1 rule")

# filter by status
r_st = filter_rules(sort_pool, status=RuleStatusEnum.ACTIVE)
_assert(len(r_st) == 2, "filter status ACTIVE → 2 rules")
_assert(all(r.status == RuleStatusEnum.ACTIVE for r in r_st), "all filtered are ACTIVE")

r_st_arch = filter_rules(sort_pool, status=RuleStatusEnum.ARCHIVED)
_assert(len(r_st_arch) == 1 and r_st_arch[0].ruleId == rule4.ruleId, "filter ARCHIVED → rule4")

# filter by priority range
r_prio = filter_rules(sort_pool, min_priority=5, max_priority=50)
prios_f = [r.priority for r in r_prio]
_assert(all(5 <= p <= 50 for p in prios_f), "filter priority range [5,50]")

r_min = filter_rules(sort_pool, min_priority=100)
_assert(len(r_min) == 1 and r_min[0].ruleId == rule3.ruleId, "filter min_priority=100 → rule3(200)")

r_max = filter_rules(sort_pool, max_priority=5)
_assert(len(r_max) == 2, "filter max_priority=5 → rule2(5) + rule5(1)")

# filter by action
r_act = filter_rules(sort_pool, action=RuleActionEnum.CREATE_ALERT)
_assert(len(r_act) >= 1, "filter by CREATE_ALERT finds at least rule1")
_assert(all(RuleActionEnum.CREATE_ALERT in r.actions for r in r_act), "all have CREATE_ALERT")

r_act_none = filter_rules(sort_pool, action=RuleActionEnum.UPDATE_SEVERITY)
_assert(len(r_act_none) == 0, "filter by UPDATE_SEVERITY → 0 (none have it)")

# combined filter
r_comb = filter_rules(sort_pool, severity=RuleSeverityEnum.CRITICAL, status=RuleStatusEnum.ACTIVE)
_assert(len(r_comb) == 1 and r_comb[0].ruleId == rule2.ruleId,
        "filter combined severity+status: only rule2")

# empty input
_assert(len(filter_rules([], severity=RuleSeverityEnum.HIGH)) == 0, "filter empty input → []")

# filter_rule_conditions
# cond1: field="severity", op="eq", value="HIGH"
# cond2: field="protocol", op="contains", value="TLS"
# cond3: field="packet_count", op="gt", value="100"
cond_filter_pool = [cond1, cond2, cond3]

r_cf = filter_rule_conditions(cond_filter_pool, field="severity")
_assert(len(r_cf) == 1 and r_cf[0].conditionId == cond1.conditionId, "filter conds by field substring")

r_cf_op = filter_rule_conditions(cond_filter_pool, operator="eq")
_assert(len(r_cf_op) == 1 and r_cf_op[0].conditionId == cond1.conditionId, "filter conds by operator")

r_cf_op_ci = filter_rule_conditions(cond_filter_pool, operator="EQ")  # case-insensitive
_assert(len(r_cf_op_ci) == 1, "filter conds operator case-insensitive")

r_cf_val = filter_rule_conditions(cond_filter_pool, value="100")
_assert(len(r_cf_val) == 1 and r_cf_val[0].conditionId == cond3.conditionId, "filter conds by value substring")

r_cf_val_sub = filter_rule_conditions(cond_filter_pool, value="TL")  # substring
_assert(len(r_cf_val_sub) == 1 and r_cf_val_sub[0].conditionId == cond2.conditionId, "filter conds value substring")

r_cf_none = filter_rule_conditions(cond_filter_pool, field="non_existent_field")
_assert(len(r_cf_none) == 0, "filter conds no match → []")

r_cf_combined = filter_rule_conditions(cond_filter_pool, field="severity", operator="eq")
_assert(len(r_cf_combined) == 1, "filter conds combined AND")

_assert(len(filter_rule_conditions([], field="severity")) == 0, "filter conds empty input → []")

# filter_rule_mappings
# m_a: fid=fid-a, conf=70; m_b: fid=fid-b, conf=60; m_c: aid=aid-c, conf=55
all_ml_filter = [m_a, m_b, m_c]

r_mf = filter_rule_mappings(all_ml_filter, finding_id="fid-a")
_assert(len(r_mf) == 1 and r_mf[0].mappingId == m_a.mappingId, "filter mapping by findingId")

r_mf_alert = filter_rule_mappings(all_ml_filter, alert_id="aid-c")
_assert(len(r_mf_alert) == 1 and r_mf_alert[0].mappingId == m_c.mappingId, "filter mapping by alertId")

r_mf_rid = filter_rule_mappings(all_ml_filter, reasoning_id="rid-xyz")
_assert(len(r_mf_rid) == 0, "filter mapping by reasoningId no match → []")

r_mf_min = filter_rule_mappings(all_ml_filter, min_confidence=65.0)
_assert(len(r_mf_min) == 1 and r_mf_min[0].mappingId == m_a.mappingId, "filter mapping min_confidence=65")

r_mf_max = filter_rule_mappings(all_ml_filter, max_confidence=60.0)
_assert(len(r_mf_max) == 2, "filter mapping max_confidence=60 → 2 (60+55)")

r_mf_range = filter_rule_mappings(all_ml_filter, min_confidence=56.0, max_confidence=65.0)
_assert(len(r_mf_range) == 1 and r_mf_range[0].mappingId == m_b.mappingId,
        "filter mapping confidence range")

# filter by severity of matched rules
r_mf_sev = filter_rule_mappings(all_ml_filter, severity=RuleSeverityEnum.CRITICAL)
# rule2 is CRITICAL, appears in m1 (but m_a uses rule1=HIGH)
# m_a has rule1=HIGH; m_b has rule2=CRITICAL; m_c has rule3=LOW
_assert(len(r_mf_sev) == 1 and r_mf_sev[0].mappingId == m_b.mappingId,
        "filter mapping by severity of matched rules")

r_mf_sev_none = filter_rule_mappings(all_ml_filter, severity=RuleSeverityEnum.MEDIUM)
_assert(len(r_mf_sev_none) == 0, "filter mapping by MEDIUM severity → 0")

_assert(len(filter_rule_mappings([], finding_id="f")) == 0, "filter mappings empty input → []")

# ===========================================================================
# 15. Grouping
# ===========================================================================
print("\n[15] Grouping")

# sort_pool: rule1=HIGH/ACTIVE/prio=10/actions=[CREATE_ALERT,TAG_INVESTIGATION]
#            rule2=CRITICAL/ACTIVE/prio=5 /actions=[CREATE_FINDING,START_PLAYBOOK]
#            rule3=LOW/DRAFT/prio=200     /actions=[ADD_TIMELINE_EVENT]
#            rule4=MEDIUM/ARCHIVED/prio=50/actions=[]
#            rule5=CRITICAL/DISABLED/prio=1/actions=[]

# group by severity
g_sev = group_rules(sort_pool, group_by="severity")
_assert("HIGH"     in g_sev, "group_sev has HIGH")
_assert("CRITICAL" in g_sev, "group_sev has CRITICAL")
_assert("LOW"      in g_sev, "group_sev has LOW")
_assert("MEDIUM"   in g_sev, "group_sev has MEDIUM")
_assert(len(g_sev["CRITICAL"]) == 2, "CRITICAL group has 2 rules (rule2+rule5)")
_assert(len(g_sev["HIGH"])     == 1, "HIGH group has 1 rule")
# Each group sorted by ruleId ASC
for key, grp in g_sev.items():
    ids = [r.ruleId for r in grp]
    _assert(ids == sorted(ids), f"group_sev[{key}] sorted by ruleId")

# group by status
g_st = group_rules(sort_pool, group_by="status")
_assert("ACTIVE"   in g_st, "group_status has ACTIVE")
_assert("DRAFT"    in g_st, "group_status has DRAFT")
_assert("ARCHIVED" in g_st, "group_status has ARCHIVED")
_assert("DISABLED" in g_st, "group_status has DISABLED")
_assert(len(g_st["ACTIVE"]) == 2, "ACTIVE group has 2")

# group by priority
g_prio = group_rules(sort_pool, group_by="priority")
_assert("10" in g_prio, "group_priority has '10'")
_assert("5"  in g_prio, "group_priority has '5'")
_assert(len(g_prio["200"]) == 1, "priority 200 group has 1")

# group by action (multi-group)
g_act = group_rules(sort_pool, group_by="action")
_assert("CREATE_ALERT"       in g_act, "group_action has CREATE_ALERT")
_assert("TAG_INVESTIGATION"  in g_act, "group_action has TAG_INVESTIGATION")
_assert("CREATE_FINDING"     in g_act, "group_action has CREATE_FINDING")
_assert("START_PLAYBOOK"     in g_act, "group_action has START_PLAYBOOK")
_assert("ADD_TIMELINE_EVENT" in g_act, "group_action has ADD_TIMELINE_EVENT")
# rule1 appears in CREATE_ALERT and TAG_INVESTIGATION
_assert(any(r.ruleId == rule1.ruleId for r in g_act["CREATE_ALERT"]),
        "rule1 in CREATE_ALERT group")
_assert(any(r.ruleId == rule1.ruleId for r in g_act["TAG_INVESTIGATION"]),
        "rule1 in TAG_INVESTIGATION group")
# rules with no actions → "unknown"
_assert("unknown" in g_act, "rules with no actions go to 'unknown' group")
_assert(len(g_act["unknown"]) == 2, "2 rules with no actions in unknown group (rule4+rule5)")

# group_rule_conditions
cond_group_pool = [cond1, cond2, cond3]
# cond1: field=severity, op=eq; cond2: field=protocol, op=contains; cond3: field=packet_count, op=gt

g_cfield = group_rule_conditions(cond_group_pool, group_by="field")
_assert("severity"     in g_cfield, "group_conditions has 'severity'")
_assert("protocol"     in g_cfield, "group_conditions has 'protocol'")
_assert("packet_count" in g_cfield, "group_conditions has 'packet_count'")
for key, grp in g_cfield.items():
    ids = [c.conditionId for c in grp]
    _assert(ids == sorted(ids), f"group_conds[{key}] sorted by conditionId")

g_cop = group_rule_conditions(cond_group_pool, group_by="operator")
_assert("eq"       in g_cop, "group_conditions_op has 'eq'")
_assert("contains" in g_cop, "group_conditions_op has 'contains'")
_assert("gt"       in g_cop, "group_conditions_op has 'gt'")

g_cval = group_rule_conditions(cond_group_pool, group_by="value")
_assert("HIGH" in g_cval, "group_conditions_val has 'HIGH'")
_assert("TLS"  in g_cval, "group_conditions_val has 'TLS'")
_assert("100"  in g_cval, "group_conditions_val has '100'")

# group_rule_mappings by severity of matchedRules
# m_a → rule1=HIGH, m_b → rule2=CRITICAL, m_c → rule3=LOW
all_ml_group = [m_a, m_b, m_c]

g_msev = group_rule_mappings(all_ml_group, group_by="severity")
_assert("HIGH"     in g_msev, "group_mappings has HIGH severity")
_assert("CRITICAL" in g_msev, "group_mappings has CRITICAL severity")
_assert("LOW"      in g_msev, "group_mappings has LOW severity")
_assert(len(g_msev["HIGH"])     == 1, "HIGH group: 1 mapping (m_a)")
_assert(len(g_msev["CRITICAL"]) == 1, "CRITICAL group: 1 mapping (m_b)")
for key, grp in g_msev.items():
    ids = [m.mappingId for m in grp]
    _assert(ids == sorted(ids), f"group_mappings_sev[{key}] sorted by mappingId")

g_mst = group_rule_mappings(all_ml_group, group_by="status")
_assert("ACTIVE" in g_mst, "group_mappings_status has ACTIVE (rule1+rule2 are ACTIVE)")

# mapping with no matched rules → unknown
m_empty = build_rule_mapping([], TS, finding_id="fid-empty", validate=False)
g_empty = group_rule_mappings([m_empty], group_by="severity")
_assert("unknown" in g_empty, "mapping with no matchedRules → unknown group")

# group by action
g_mact = group_rule_mappings(all_ml_group, group_by="action")
_assert("CREATE_ALERT"   in g_mact or "CREATE_FINDING" in g_mact,
        "group_mappings by action finds action keys")

# Verify each mapping group is sorted by mappingId
g_mst2 = group_rule_mappings(all_ml_group, group_by="status")
for key, grp in g_mst2.items():
    ids = [m.mappingId for m in grp]
    _assert(ids == sorted(ids), f"group_mappings_status[{key}] sorted by mappingId")

# group by priority of matched rules
g_mprio = group_rule_mappings(all_ml_group, group_by="priority")
_assert(len(g_mprio) >= 1, "group_mappings by priority has entries")
_assert(all(isinstance(k, str) for k in g_mprio), "group_mappings priority keys are strings")

# group_rule_conditions: group by unknown attr → all go to 'unknown'  
g_cunknown = group_rule_conditions(cond_group_pool, group_by="nonexistent_attr")
_assert("unknown" in g_cunknown, "unknown attr → 'unknown' group for conditions")
_assert(len(g_cunknown["unknown"]) == 3, "all 3 conditions in unknown group")

# ===========================================================================
# 16. Statistics (Extended)
# ===========================================================================
print("\n[16] Statistics")

# Empty input
stats_empty = build_rule_statistics([])
_assert(stats_empty.totalRules      == 0,   "empty stats: total=0")
_assert(stats_empty.activeRules     == 0,   "empty stats: active=0")
_assert(stats_empty.draftRules      == 0,   "empty stats: draft=0")
_assert(stats_empty.disabledRules   == 0,   "empty stats: disabled=0")
_assert(stats_empty.archivedRules   == 0,   "empty stats: archived=0")
_assert(stats_empty.averagePriority == 0.0, "empty stats: avgPriority=0")
_assert(stats_empty.severityCounts  == {},  "empty stats: severityCounts={}")
_assert(stats_empty.actionCounts    == {},  "empty stats: actionCounts={}")

# Normal pool: rule1=HIGH/ACTIVE/prio=10, rule2=CRITICAL/ACTIVE/prio=5,
#              rule3=LOW/DRAFT/prio=200,   rule4=MEDIUM/ARCHIVED/prio=50,
#              rule5=CRITICAL/DISABLED/prio=1
stat_pool = [rule1, rule2, rule3, rule4, rule5]
stats = build_rule_statistics(stat_pool)
_assert(stats.totalRules    == 5, "stats total=5")
_assert(stats.activeRules   == 2, "stats active=2 (rule1+rule2)")
_assert(stats.draftRules    == 1, "stats draft=1 (rule3)")
_assert(stats.disabledRules == 1, "stats disabled=1 (rule5)")
_assert(stats.archivedRules == 1, "stats archived=1 (rule4)")
expected_avg_prio = round((10+5+200+50+1)/5, 4)
_assert(abs(stats.averagePriority - expected_avg_prio) < 0.001, "stats averagePriority")

# severityCounts
_assert("HIGH"     in stats.severityCounts, "severityCounts has HIGH")
_assert("CRITICAL" in stats.severityCounts, "severityCounts has CRITICAL")
_assert("LOW"      in stats.severityCounts, "severityCounts has LOW")
_assert("MEDIUM"   in stats.severityCounts, "severityCounts has MEDIUM")
_assert(stats.severityCounts["HIGH"]     == 1, "severityCounts HIGH=1")
_assert(stats.severityCounts["CRITICAL"] == 2, "severityCounts CRITICAL=2")
_assert(stats.severityCounts["LOW"]      == 1, "severityCounts LOW=1")
_assert(stats.severityCounts["MEDIUM"]   == 1, "severityCounts MEDIUM=1")

# actionCounts — rule1 has CREATE_ALERT+TAG_INVESTIGATION,
#                rule2 has CREATE_FINDING+START_PLAYBOOK, rule3 has ADD_TIMELINE_EVENT
_assert("CREATE_ALERT"       in stats.actionCounts, "actionCounts has CREATE_ALERT")
_assert("TAG_INVESTIGATION"  in stats.actionCounts, "actionCounts has TAG_INVESTIGATION")
_assert("CREATE_FINDING"     in stats.actionCounts, "actionCounts has CREATE_FINDING")
_assert("START_PLAYBOOK"     in stats.actionCounts, "actionCounts has START_PLAYBOOK")
_assert("ADD_TIMELINE_EVENT" in stats.actionCounts, "actionCounts has ADD_TIMELINE_EVENT")
_assert(stats.actionCounts["CREATE_ALERT"]       == 1, "actionCounts CREATE_ALERT=1")
_assert(stats.actionCounts["TAG_INVESTIGATION"]  == 1, "actionCounts TAG_INVESTIGATION=1")
_assert(stats.actionCounts["CREATE_FINDING"]     == 1, "actionCounts CREATE_FINDING=1")
_assert("UPDATE_SEVERITY" not in stats.actionCounts, "UPDATE_SEVERITY omitted (count=0)")

# Deduplication
stats_dup = build_rule_statistics([rule1, rule1, rule2])
_assert(stats_dup.totalRules  == 2, "stats dedup: 2 distinct rules")
_assert(stats_dup.activeRules == 2, "stats dedup: 2 active")

# Determinism — order-independent
stats_a = build_rule_statistics([rule1, rule2, rule3, rule4, rule5])
stats_b = build_rule_statistics([rule5, rule3, rule1, rule4, rule2])
_assert(stats_a.totalRules      == stats_b.totalRules,      "stats order-independent total")
_assert(stats_a.averagePriority == stats_b.averagePriority, "stats order-independent avgPriority")
_assert(stats_a.severityCounts  == stats_b.severityCounts,  "stats order-independent severityCounts")
_assert(stats_a.actionCounts    == stats_b.actionCounts,    "stats order-independent actionCounts")
_assert(stats_a.activeRules     == stats_b.activeRules,     "stats order-independent activeRules")

# Single rule
stats_one = build_rule_statistics([rule2])
_assert(stats_one.totalRules      == 1,     "stats single rule: total=1")
_assert(stats_one.averagePriority == 5.0,   "stats single rule: avgPriority=5")
_assert(stats_one.severityCounts.get("CRITICAL") == 1, "single rule CRITICAL count=1")

# ===========================================================================
# 17. Serialization (model_dump round-trip)
# ===========================================================================
print("\n[17] Serialization")

# RuleCondition round-trip
d_cond = cond1.model_dump()
_assert(isinstance(d_cond, dict),                        "cond.model_dump() returns dict")
_assert(d_cond["conditionId"]  == cond1.conditionId,     "cond dump conditionId")
_assert(d_cond["conditionKey"] == cond1.conditionKey,    "cond dump conditionKey")
_assert(d_cond["field"]        == "severity",            "cond dump field")
_assert(d_cond["operator"]     == "eq",                  "cond dump operator")
_assert(d_cond["value"]        == "HIGH",                "cond dump value")
_assert(d_cond["createdAt"]    == TS,                    "cond dump createdAt")

cond_rt = RuleCondition(**d_cond)
_assert(cond_rt.conditionId == cond1.conditionId, "RuleCondition round-trip from dict")

# Rule round-trip
d_rule = rule1.model_dump()
_assert(isinstance(d_rule, dict),                    "rule.model_dump() returns dict")
_assert(d_rule["ruleId"]   == rule1.ruleId,          "rule dump ruleId")
_assert(d_rule["ruleKey"]  == rule1.ruleKey,          "rule dump ruleKey")
_assert(d_rule["name"]     == rule1.name,             "rule dump name")
_assert(d_rule["severity"] == "HIGH",                 "rule dump severity value")
_assert(d_rule["status"]   == "ACTIVE",               "rule dump status value")
_assert(d_rule["priority"] == 10,                     "rule dump priority")
_assert(isinstance(d_rule["conditions"], (list, tuple)), "rule dump conditions is sequence")
_assert(isinstance(d_rule["actions"],    (list, tuple)), "rule dump actions is sequence")
_assert(len(d_rule["conditions"]) == len(rule1.conditions), "rule dump conditions length matches")
_assert(len(d_rule["actions"])    == len(rule1.actions),    "rule dump actions length matches")

# RuleMapping round-trip
d_m = m1.model_dump()
_assert(isinstance(d_m, dict),                             "mapping.model_dump() returns dict")
_assert(d_m["mappingId"]          == m1.mappingId,         "mapping dump mappingId")
_assert(d_m["mappingFingerprint"] == m1.mappingFingerprint,"mapping dump fingerprint")
_assert(d_m["findingId"]          == "fid-001",            "mapping dump findingId")
_assert(d_m["confidence"]         == 80.0,                 "mapping dump confidence")
_assert(isinstance(d_m["matchedRules"], (list, tuple)),    "mapping dump matchedRules is sequence")

# RuleStatistics round-trip
d_stats = stats.model_dump()
_assert(isinstance(d_stats, dict),                         "stats.model_dump() returns dict")
_assert(d_stats["totalRules"]      == 5,                   "stats dump totalRules")
_assert(d_stats["activeRules"]     == 2,                   "stats dump activeRules")
_assert(isinstance(d_stats["severityCounts"], dict),       "stats dump severityCounts is dict")
_assert(isinstance(d_stats["actionCounts"],   dict),       "stats dump actionCounts is dict")
_assert(d_stats["severityCounts"]["HIGH"]     == 1,        "stats dump severityCounts[HIGH]")
_assert(d_stats["actionCounts"]["CREATE_ALERT"] == 1,      "stats dump actionCounts[CREATE_ALERT]")

# ===========================================================================
# 18. Immutability
# ===========================================================================
print("\n[18] Immutability")

try:
    cond1.field = "mutated"  # type: ignore
    _assert(False, "RuleCondition should be immutable")
except Exception:
    _assert(True, "RuleCondition is immutable (frozen)")

try:
    rule1.name = "mutated"  # type: ignore
    _assert(False, "Rule should be immutable")
except Exception:
    _assert(True, "Rule is immutable (frozen)")

try:
    m1.confidence = 99.0  # type: ignore
    _assert(False, "RuleMapping should be immutable")
except Exception:
    _assert(True, "RuleMapping is immutable (frozen)")

try:
    stats.totalRules = 999  # type: ignore
    _assert(False, "RuleStatistics should be immutable")
except Exception:
    _assert(True, "RuleStatistics is immutable (frozen)")

# Operations return NEW objects, not mutations
original_conds = rule1.conditions
new_rule_c = add_rule_condition(rule1, cond3)
_assert(rule1.conditions == original_conds, "add_rule_condition does not mutate original rule")

original_list = [rule1, rule2]
_ = add_rule(original_list, rule3)
_assert(len(original_list) == 2, "add_rule does not mutate input list")

original_ml2 = [m_a, m_b]
_ = add_rule_mapping(original_ml2, m_c)
_assert(len(original_ml2) == 2, "add_rule_mapping does not mutate input list")

# ===========================================================================
# 19. Integration Helpers
# ===========================================================================
print("\n[19] Integration Helpers")

class _FakeFinding:
    findingId = "finding-abc-123"

class _FakeFindingNoId:
    pass

class _FakeAlert:
    alertId   = "alert-xyz-456"
    findingId = "finding-abc-123"

class _FakeAlertNoFinding:
    alertId = "alert-only-789"

class _FakeReasoning:
    reasoningId = "reasoning-def-789"

class _FakePlaybook:
    playbookId = "playbook-pb-001"

class _FakePlaybookNoId:
    pass

class _FakeThreatActor:
    actorId = "actor-001"

class _FakeThreatCampaign:
    campaignId = "campaign-001"

class _FakeThreatEmpty:
    pass

# finding_to_rule_mapping
fm = finding_to_rule_mapping(_FakeFinding(), [rule1], TS, confidence=80.0)
_assert(fm.findingId   == "finding-abc-123", "finding mapping findingId")
_assert(fm.alertId     == "",                "finding mapping alertId empty")
_assert(fm.reasoningId == "",                "finding mapping reasoningId empty")
_assert(fm.confidence  == 80.0,              "finding mapping confidence")
_assert(len(fm.matchedRules) == 1,           "finding mapping has 1 rule")

# Determinism
fm2 = finding_to_rule_mapping(_FakeFinding(), [rule1], TS, confidence=80.0)
_assert(fm.mappingId == fm2.mappingId, "finding_to_rule_mapping deterministic")
_assert(fm.mappingFingerprint == fm2.mappingFingerprint, "finding mapping fingerprint deterministic")

# Missing findingId attribute → empty string → raises InvalidRuleMappingError
_assert_raises(InvalidRuleMappingError, finding_to_rule_mapping,
               _FakeFindingNoId(), [rule1], TS, confidence=50.0,
               msg="missing findingId attribute → no source → validation error")

# alert_to_rule_mapping
am = alert_to_rule_mapping(_FakeAlert(), [rule1], TS, confidence=75.0)
_assert(am.alertId    == "alert-xyz-456",    "alert mapping alertId")
_assert(am.findingId  == "finding-abc-123",  "alert mapping findingId from alert.findingId")
_assert(am.reasoningId == "",                "alert mapping reasoningId empty")
_assert(am.confidence == 75.0,              "alert mapping confidence")

# Alert with no findingId
am2 = alert_to_rule_mapping(_FakeAlertNoFinding(), [rule1], TS, confidence=60.0)
_assert(am2.alertId   == "alert-only-789", "alert mapping alertId (no findingId)")
_assert(am2.findingId == "",               "alert mapping findingId empty when missing")

# Determinism
am3 = alert_to_rule_mapping(_FakeAlert(), [rule1], TS, confidence=75.0)
_assert(am.mappingId == am3.mappingId, "alert_to_rule_mapping deterministic")

# reasoning_to_rule_mapping
rm = reasoning_to_rule_mapping(_FakeReasoning(), [rule1], TS, confidence=65.0)
_assert(rm.reasoningId == "reasoning-def-789", "reasoning mapping reasoningId")
_assert(rm.findingId   == "",                  "reasoning mapping findingId empty")
_assert(rm.alertId     == "",                  "reasoning mapping alertId empty")
_assert(rm.confidence  == 65.0,               "reasoning mapping confidence")

rm2 = reasoning_to_rule_mapping(_FakeReasoning(), [rule1], TS, confidence=65.0)
_assert(rm.mappingId == rm2.mappingId, "reasoning_to_rule_mapping deterministic")

# playbook_to_rule_reference
pb_ref = playbook_to_rule_reference(_FakePlaybook())
_assert(pb_ref == "playbook:playbook-pb-001", "playbook_to_rule_reference correct")
_assert(pb_ref.startswith("playbook:"),        "playbook ref starts with 'playbook:'")

pb_ref_empty = playbook_to_rule_reference(_FakePlaybookNoId())
_assert(pb_ref_empty == "playbook:", "missing playbookId → 'playbook:'")

# threat_to_rule_reference — ThreatActor (prefers actorId)
ta_ref = threat_to_rule_reference(_FakeThreatActor())
_assert(ta_ref == "threat:actor-001", "threat ref for ThreatActor correct")
_assert(ta_ref.startswith("threat:"),  "threat ref starts with 'threat:'")

# threat_to_rule_reference — ThreatCampaign (falls back to campaignId)
tc_ref = threat_to_rule_reference(_FakeThreatCampaign())
_assert(tc_ref == "threat:campaign-001", "threat ref for ThreatCampaign correct")

# threat_to_rule_reference — empty
te_ref = threat_to_rule_reference(_FakeThreatEmpty())
_assert(te_ref == "threat:", "missing threat id → 'threat:'")

# ===========================================================================
# 20. Edge Cases
# ===========================================================================
print("\n[20] Edge Cases")

# Whitespace-only strings rejected
_assert_raises(InvalidRuleConditionError, validate_rule_condition, "  ", "eq", "v", TS,
               msg="whitespace field rejected")
_assert_raises(InvalidRuleError, validate_rule, "  ", RuleSeverityEnum.HIGH, RuleStatusEnum.ACTIVE, 10, TS,
               msg="whitespace name rejected")
_assert_raises(InvalidRuleMappingError, validate_rule_mapping, "  ", "  ", "  ", 50.0, TS,
               msg="whitespace-only source ids rejected")

# Priority exactly 1 is valid
rule_prio1 = build_rule("P1 Rule", RuleSeverityEnum.LOW, TS, priority=1)
_assert(rule_prio1.priority == 1, "priority=1 is valid")

# Very large priority accepted
rule_prio_large = build_rule("BigPrio", RuleSeverityEnum.LOW, TS, priority=99999)
_assert(rule_prio_large.priority == 99999, "large priority accepted")

# Empty condition list → empty tuple
rule_no_conds = build_rule("No Conds", RuleSeverityEnum.LOW, TS, conditions=None)
_assert(rule_no_conds.conditions == (), "None conditions → empty tuple")

# None actions → empty tuple
rule_no_acts = build_rule("No Acts", RuleSeverityEnum.LOW, TS, actions=None)
_assert(rule_no_acts.actions == (), "None actions → empty tuple")

# Confidence boundary exactly 0.0 and 100.0
m_bound_lo = build_rule_mapping([rule1], TS, finding_id="f", confidence=0.0)
m_bound_hi = build_rule_mapping([rule1], TS, finding_id="f", confidence=100.0)
_assert(m_bound_lo.confidence == 0.0,   "confidence 0.0 exact boundary")
_assert(m_bound_hi.confidence == 100.0, "confidence 100.0 exact boundary")

# remove from empty lists
empty_rules = remove_rule([], "non-existent")
_assert(len(empty_rules) == 0, "remove from empty rules list → []")

empty_mappings = remove_rule_mapping([], "non-existent")
_assert(len(empty_mappings) == 0, "remove from empty mappings list → []")

# remove condition from rule with no conditions
r_no_c = remove_rule_condition(rule_no_conds, "non-existent-cond-id")
_assert(r_no_c.ruleId == rule_no_conds.ruleId, "remove cond from rule with no conds → unchanged")

# merge empty conditions into rule
r_merge_empty = merge_rule_conditions(rule1, [])
_assert(r_merge_empty.ruleId == rule1.ruleId, "merge empty conditions → original rule unchanged")

# merge_rules with empty incoming
merged_e = merge_rules([rule1], [])
_assert(len(merged_e) == 1 and merged_e[0].ruleId == rule1.ruleId, "merge empty incoming preserves base")

# add_rule_mapping to empty list
ml_from_empty = add_rule_mapping([], m_a)
_assert(len(ml_from_empty) == 1, "add_rule_mapping to empty list")

# Same conditionKey after whitespace strip
ck_stripped = conditionKey("  severity  ", "  eq  ", "  HIGH  ")
_assert(ck_stripped == conditionKey("severity", "eq", "HIGH"), "conditionKey strips whitespace")

# update_rule with conditions change recomputes identity
new_cond_for_update = build_rule_condition("new_field", "eq", "new_val", TS)
rl_update_conds = add_rule([], rule1)
rl_after_cond_update = update_rule(rl_update_conds, rule1.ruleId, TS2,
                                    conditions=[new_cond_for_update])
_assert(rl_after_cond_update[0].ruleId != rule1.ruleId,
        "update with conditions change recomputes ruleId")
_assert(len(rl_after_cond_update[0].conditions) == 1, "updated rule has 1 condition")
_assert(rl_after_cond_update[0].conditions[0].conditionId == new_cond_for_update.conditionId,
        "updated rule has new condition")

# update_rule with actions change recomputes identity
rl_after_act_update = update_rule(rl_update_conds, rule1.ruleId, TS2,
                                   actions=[RuleActionEnum.UPDATE_SEVERITY])
_assert(rl_after_act_update[0].ruleId != rule1.ruleId,
        "update with actions change recomputes ruleId")
_assert(RuleActionEnum.UPDATE_SEVERITY in rl_after_act_update[0].actions,
        "updated rule has new action")

# Duplicate ruleIds impossible when adding to list
r_same_content = build_rule("High Severity TLS", RuleSeverityEnum.HIGH, TS,
                             conditions=[cond1, cond2],
                             actions=[RuleActionEnum.CREATE_ALERT, RuleActionEnum.TAG_INVESTIGATION],
                             priority=10)
_assert(r_same_content.ruleId == rule1.ruleId, "same content → same ruleId")
rl_test_dup = add_rule([rule1], r_same_content)
_assert(len(rl_test_dup) == 1, "identical content rule not added as duplicate")

# sort_rule_mappings by findingId
m_fid1 = build_rule_mapping([rule1], TS, finding_id="aaa-001")
m_fid2 = build_rule_mapping([rule2], TS, finding_id="zzz-999")
sorted_fid = sort_rule_mappings([m_fid2, m_fid1], by="findingId", ascending=True)
_assert(sorted_fid[0].findingId == "aaa-001", "sort mappings by findingId ASC: aaa first")
sorted_fid_d = sort_rule_mappings([m_fid2, m_fid1], by="findingId", ascending=False)
_assert(sorted_fid_d[0].findingId == "zzz-999", "sort mappings by findingId DESC: zzz first")

# validate_rule_mapping with all three source ids populated
validate_rule_mapping("fid-1", "aid-1", "rid-1", 50.0, TS)
_assert(True, "all three source ids populated is valid")

# build_rule preserves description
rule_with_desc = build_rule("Desc Rule", RuleSeverityEnum.LOW, TS,
                             description="This is a detailed description.")
_assert(rule_with_desc.description == "This is a detailed description.", "description preserved")

# Statistics with only active rules
active_only = [r for r in sort_pool if r.status == RuleStatusEnum.ACTIVE]
stats_active = build_rule_statistics(active_only)
_assert(stats_active.activeRules  == 2,   "active-only stats: activeRules=2")
_assert(stats_active.draftRules   == 0,   "active-only stats: draftRules=0")
_assert(stats_active.archivedRules == 0,  "active-only stats: archivedRules=0")
_assert(stats_active.disabledRules == 0,  "active-only stats: disabledRules=0")

# merge_rule_mappings preserves base on collision
m_base_dup = build_rule_mapping([rule1], TS, finding_id="fid-a", confidence=70.0)  # same as m_a
m_incoming_dup = build_rule_mapping([rule1], TS, finding_id="fid-a", confidence=70.0)
assert m_base_dup.mappingId == m_a.mappingId, "sanity: same content → same mappingId"
merged_dup_ml = merge_rule_mappings([m_a], [m_incoming_dup])
_assert(len(merged_dup_ml) == 1, "merge identical mappings → 1 unique")
_assert(merged_dup_ml[0].mappingId == m_a.mappingId, "merge: base mapping preserved")

# ===========================================================================
# 21. Zero Randomness & Deterministic Fingerprints
# ===========================================================================
print("\n[21] Zero Randomness & Deterministic Fingerprints")

# Same inputs → same outputs across 3 independent rebuilds
for i in range(3):
    _c = build_rule_condition("severity", "eq", "HIGH", TS)
    _assert(_c.conditionId == cond1.conditionId, f"conditionId deterministic pass {i+1}")
    _assert(_c.conditionKey == cond1.conditionKey, f"conditionKey deterministic pass {i+1}")

for i in range(3):
    _r = build_rule("High Severity TLS", RuleSeverityEnum.HIGH, TS,
                    conditions=[cond1, cond2],
                    actions=[RuleActionEnum.CREATE_ALERT, RuleActionEnum.TAG_INVESTIGATION],
                    priority=10)
    _assert(_r.ruleId  == rule1.ruleId,  f"ruleId deterministic pass {i+1}")
    _assert(_r.ruleKey == rule1.ruleKey, f"ruleKey deterministic pass {i+1}")

for i in range(3):
    _m = build_rule_mapping([rule1, rule2], TS, finding_id="fid-001", alert_id="aid-001", confidence=80.0)
    _assert(_m.mappingId          == m1.mappingId,          f"mappingId deterministic pass {i+1}")
    _assert(_m.mappingFingerprint == m1.mappingFingerprint, f"mappingFingerprint deterministic pass {i+1}")

# Fingerprint changes when content changes
m_fid_change = build_rule_mapping([rule1], TS, finding_id="fid-DIFFERENT", confidence=80.0)
_assert(m_fid_change.mappingFingerprint != m1.mappingFingerprint, "fingerprint changes on findingId change")

m_rule_change = build_rule_mapping([rule3], TS, finding_id="fid-001", alert_id="aid-001", confidence=80.0)
_assert(m_rule_change.mappingFingerprint != m1.mappingFingerprint, "fingerprint changes on rule change")

# ===========================================================================
# 22. Large Dataset Stability
# ===========================================================================
print("\n[22] Large Dataset Stability")

# Build 100 distinct rules and verify stats are stable
large_rules = []
for i in range(100):
    sev = [RuleSeverityEnum.LOW, RuleSeverityEnum.MEDIUM,
           RuleSeverityEnum.HIGH, RuleSeverityEnum.CRITICAL][i % 4]
    st  = [RuleStatusEnum.DRAFT, RuleStatusEnum.ACTIVE,
           RuleStatusEnum.DISABLED, RuleStatusEnum.ARCHIVED][i % 4]
    large_rules.append(build_rule(
        name       = f"Rule {i:03d}",
        severity   = sev,
        created_at = TS,
        status     = st,
        priority   = (i % 10) + 1,
    ))

_assert(len(large_rules) == 100, "100 distinct rules built")
# All ruleIds distinct
_assert(len({r.ruleId for r in large_rules}) == 100, "all 100 ruleIds unique")

large_stats = build_rule_statistics(large_rules)
_assert(large_stats.totalRules == 100, "large stats: total=100")
_assert(large_stats.activeRules + large_stats.draftRules +
        large_stats.disabledRules + large_stats.archivedRules == 100,
        "large stats: status counts sum to total")
_assert(sum(large_stats.severityCounts.values()) == 100,
        "large stats: severityCounts sum to 100")

# Order-independent: same stats from reversed list
large_stats_rev = build_rule_statistics(list(reversed(large_rules)))
_assert(large_stats.totalRules      == large_stats_rev.totalRules,      "large stats order-independent: total")
_assert(large_stats.averagePriority == large_stats_rev.averagePriority, "large stats order-independent: avgPriority")
_assert(large_stats.severityCounts  == large_stats_rev.severityCounts,  "large stats order-independent: severityCounts")
_assert(large_stats.actionCounts    == large_stats_rev.actionCounts,    "large stats order-independent: actionCounts")

# Sort all 100 rules deterministically
sorted_large = sort_rules(large_rules, by="priority", ascending=True)
_assert(len(sorted_large) == 100, "sort 100 rules: count preserved")
prios_large = [r.priority for r in sorted_large]
_assert(all(prios_large[i] <= prios_large[i+1] for i in range(len(prios_large)-1)),
        "sort 100 rules: ascending priority order")

# Merge 100-rule lists with 50 duplicates
half = large_rules[:50]
other = large_rules[25:75]   # 25 overlap + 25 new
merged_large = merge_rules(half, other)
_assert(len(merged_large) == 75, "merge large: 75 unique rules")
# Sorted
_assert(all(merged_large[i].ruleId <= merged_large[i+1].ruleId
            for i in range(len(merged_large)-1)), "merge large: result sorted")

# Build 100 mappings and verify all mappingIds are unique
large_mappings = []
for i, r in enumerate(large_rules[:100]):
    large_mappings.append(
        build_rule_mapping([r], TS, finding_id=f"fid-{i:03d}")
    )
_assert(len({m.mappingId for m in large_mappings}) == 100,
        "100 distinct mappings: all mappingIds unique")

# Filter large pool
filt_large = filter_rules(large_rules, severity=RuleSeverityEnum.HIGH)
_assert(len(filt_large) == 25, "filter large: 25 HIGH rules (100/4)")
_assert(all(r.severity == RuleSeverityEnum.HIGH for r in filt_large),
        "filter large: all HIGH")

# Group large pool
g_large = group_rules(large_rules, group_by="severity")
_assert(len(g_large) == 4, "group large: 4 severity groups")
_assert(sum(len(v) for v in g_large.values()) == 100, "group large: all 100 rules covered")

# ===========================================================================
# Final Report
# ===========================================================================
print("\n" + "=" * 60)
print(f"Results: {_PASS} passed, {_FAIL} failed")
print("=" * 60)

if _ERRORS:
    print("\nFailed assertions:")
    for e in _ERRORS:
        print(f"  {e}")
    sys.exit(1)
else:
    print(f"\nALL {_PASS} ASSERTIONS PASSED [OK]")
    sys.exit(0)
