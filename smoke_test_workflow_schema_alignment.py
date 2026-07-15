"""
Workflow Domain Schema Alignment Smoke Test
============================================
Verifies that:
  1. Canonical enum values match Prisma exactly (no "INACTIVE", no "SUCCESS",
     no "INVESTIGATION" step type defaults).
  2. All four Pydantic model layers (Create/Update/Response) load without error.
  3. Normalizers correctly translate legacy values to canonical Prisma values.
  4. Router helper functions (find, sort, filter, stats, summary) work correctly.
  5. CRUD round-trip: build → store → normalize → respond works for each entity.
  6. Execution status is "COMPLETED" (not "SUCCESS") for Automation and CaseFlow.
  7. projectId is required in Playbook, Rule, Automation; both projectId AND
     investigationId are required in CaseFlow.
  8. relatedThreatActors / relatedCampaigns round-trip through metadata on Playbook.
  9. CaseStepTypeEnum CONTAINED / ERADICATED are valid in both Python and Prisma.
"""

import sys
import unittest.mock as _mock

# ---------------------------------------------------------------------------
# Stub out api.persistence BEFORE any router or model imports so that
# RepositoryBackedDict / *ExecutionsStore instantiation never hits localhost.
# ---------------------------------------------------------------------------
class _FakeDict(dict):
    """dict-backed drop-in for RepositoryBackedDict (no HTTP required)."""
    def __init__(self, *args, **kwargs):
        super().__init__()

    def clear(self):
        super().clear()

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

class _FakeExecStore(dict):
    def __init__(self, *args, **kwargs):
        super().__init__()
    def clear(self):
        super().clear()
    def get(self, key, default=None):
        return super().get(key, default)
    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

_persistence_stub = _mock.MagicMock()
_persistence_stub.RepositoryBackedDict.side_effect = _FakeDict
_persistence_stub.AutomationExecutionsStore.side_effect = _FakeExecStore
_persistence_stub.CaseFlowExecutionsStore.side_effect = _FakeExecStore
_persistence_stub.map_playbook   = lambda x: x
_persistence_stub.map_rule       = lambda x: x
_persistence_stub.map_automation = lambda x: x
_persistence_stub.map_case_flow  = lambda x: x
sys.modules["api.persistence"] = _persistence_stub

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        print(f"  PASS  {label}")
        PASS += 1
    else:
        msg = f"  FAIL  {label}"
        if detail:
            msg += f"\n        {detail}"
        print(msg)
        FAIL += 1


# ---------------------------------------------------------------------------
# 1. Models import cleanly
# ---------------------------------------------------------------------------
print("\n=== 1. Model imports ===")
try:
    from api.workflow.playbook_models import (
        CreatePlaybookRequest, UpdatePlaybookRequest,
        PlaybookResponse, PlaybookStepRequest, PlaybookStepResponse,
    )
    check("playbook_models import", True)
except Exception as e:
    check("playbook_models import", False, str(e))

try:
    from api.workflow.rules_models import (
        CreateRuleRequest, UpdateRuleRequest,
        RuleResponse, RuleConditionRequest, RuleActionRequest,
    )
    check("rules_models import", True)
except Exception as e:
    check("rules_models import", False, str(e))

try:
    from api.workflow.automation_models import (
        CreateAutomationRequest, UpdateAutomationRequest,
        AutomationResponse, AutomationStepRequest,
    )
    check("automation_models import", True)
except Exception as e:
    check("automation_models import", False, str(e))

try:
    from api.workflow.case_flow_models import (
        CreateCaseFlowRequest, UpdateCaseFlowRequest,
        CaseFlowResponse, CaseFlowStepRequest,
    )
    check("case_flow_models import", True)
except Exception as e:
    check("case_flow_models import", False, str(e))

# ---------------------------------------------------------------------------
# 2. Normalizers — canonical default fixes
# ---------------------------------------------------------------------------
print("\n=== 2. Normalizer canonical defaults ===")
from api.workflow.normalizers import (
    normalize_playbook, normalize_rule,
    normalize_automation, normalize_automation_execution,
    normalize_case_flow, normalize_case_flow_execution,
)

# Playbook: stepType "INVESTIGATION" → "MANUAL"
pb_raw = {"name": "Test PB", "steps": [{"stepType": "INVESTIGATION", "stepNumber": 1,
           "title": "T", "createdAt": "2026-01-01T00:00:00Z"}]}
pb_n = normalize_playbook(pb_raw)
check("Playbook stepType INVESTIGATION→MANUAL",
      pb_n["steps"][0]["stepType"] == "MANUAL",
      f"got {pb_n['steps'][0]['stepType']}")

# Playbook: default severity MEDIUM, status DRAFT
pb_n2 = normalize_playbook({"name": "X"})
check("Playbook default severity MEDIUM", pb_n2["severity"] == "MEDIUM")
check("Playbook default status DRAFT",    pb_n2["status"] == "DRAFT")

# Automation: legacy "INACTIVE" → "DRAFT"
auto_n = normalize_automation({"name": "A", "status": "INACTIVE"})
check("Automation INACTIVE→DRAFT", auto_n["status"] == "DRAFT",
      f"got {auto_n['status']}")

# Automation: default status DRAFT (no legacy)
auto_n2 = normalize_automation({"name": "A"})
check("Automation default status DRAFT", auto_n2["status"] == "DRAFT")

# Automation step action: "ALERT" → "CREATE_ALERT"
auto_step_raw = {"name": "A", "steps": [{"action": "ALERT", "stepNumber": 1,
                  "name": "s", "createdAt": "2026-01-01T00:00:00Z"}]}
auto_n3 = normalize_automation(auto_step_raw)
check("AutomationStep ALERT→CREATE_ALERT",
      auto_n3["steps"][0]["action"] == "CREATE_ALERT",
      f"got {auto_n3['steps'][0]['action']}")

# AutomationExecution: "SUCCESS" → "COMPLETED"
exec_n = normalize_automation_execution({"status": "SUCCESS"})
check("AutomationExecution SUCCESS→COMPLETED",
      exec_n["status"] == "COMPLETED", f"got {exec_n['status']}")

# CaseFlowExecution: "SUCCESS" → "COMPLETED"
cf_exec_n = normalize_case_flow_execution({"status": "SUCCESS"})
check("CaseFlowExecution SUCCESS→COMPLETED",
      cf_exec_n["status"] == "COMPLETED", f"got {cf_exec_n['status']}")

# CaseFlow: default status OPEN, priority MEDIUM
cf_n = normalize_case_flow({"title": "C"})
check("CaseFlow default status OPEN",      cf_n["status"] == "OPEN")
check("CaseFlow default priority MEDIUM",  cf_n["priority"] == "MEDIUM")

# ---------------------------------------------------------------------------
# 3. Enum validation — required fields and enum sets
# ---------------------------------------------------------------------------
print("\n=== 3. Request validation ===")

# Playbook: projectId required
req = CreatePlaybookRequest(
    name="P", severity="MEDIUM", status="DRAFT",
    projectId="",   # empty — should fail
    confidence=80.0, createdAt="2026-01-01T00:00:00Z",
)
errs = req.validate_request()
check("Playbook empty projectId → error",
      any("projectId" in e for e in errs), str(errs))

# Playbook: valid request passes
req_ok = CreatePlaybookRequest(
    name="P", severity="MEDIUM", status="DRAFT",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    confidence=80.0, createdAt="2026-01-01T00:00:00Z",
)
errs_ok = req_ok.validate_request()
check("Playbook valid request → no errors", errs_ok == [], str(errs_ok))

# Playbook: invalid severity → error
req_bad_sev = CreatePlaybookRequest(
    name="P", severity="EXTREME", status="DRAFT",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    confidence=80.0, createdAt="2026-01-01T00:00:00Z",
)
errs_bs = req_bad_sev.validate_request()
check("Playbook invalid severity → error",
      any("severity" in e for e in errs_bs), str(errs_bs))

# PlaybookStep: invalid stepType → error
step_bad = PlaybookStepRequest(
    stepNumber=1, title="T", stepType="INVESTIGATION",
    createdAt="2026-01-01T00:00:00Z",
)
errs_step = step_bad.validate_request()
check("PlaybookStep invalid INVESTIGATION → error",
      any("stepType" in e for e in errs_step), str(errs_step))

# PlaybookStep: valid step passes
step_ok = PlaybookStepRequest(
    stepNumber=1, title="T", stepType="MANUAL",
    createdAt="2026-01-01T00:00:00Z",
)
check("PlaybookStep MANUAL → valid", step_ok.validate_request() == [])

# Rule: projectId required
rule_bad = CreateRuleRequest(
    name="R", severity="HIGH", status="DRAFT",
    projectId="",  createdAt="2026-01-01T00:00:00Z",
)
check("Rule empty projectId → error",
      any("projectId" in e for e in rule_bad.validate_request()))

# Automation: status INACTIVE → error (not a valid AutomationStatus)
auto_bad = CreateAutomationRequest(
    name="A", status="INACTIVE", trigger="MANUAL",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    createdAt="2026-01-01T00:00:00Z",
)
check("Automation INACTIVE status → validation error",
      any("status" in e for e in auto_bad.validate_request()))

# Automation: DRAFT status → valid
auto_ok = CreateAutomationRequest(
    name="A", status="DRAFT", trigger="MANUAL",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    createdAt="2026-01-01T00:00:00Z",
)
check("Automation DRAFT status → valid", auto_ok.validate_request() == [])

# CaseFlow: investigationId required
cf_bad = CreateCaseFlowRequest(
    title="C", status="OPEN", priority="MEDIUM",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    investigationId="",   # empty — should fail
    createdAt="2026-01-01T00:00:00Z",
)
check("CaseFlow empty investigationId → error",
      any("investigationId" in e for e in cf_bad.validate_request()))

# CaseFlow: valid request passes
cf_ok = CreateCaseFlowRequest(
    title="C", status="OPEN", priority="MEDIUM",
    projectId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    investigationId="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    createdAt="2026-01-01T00:00:00Z",
)
check("CaseFlow valid request → no errors", cf_ok.validate_request() == [])

# CaseFlow step: CONTAINED now valid
cf_step = CaseFlowStepRequest(
    stepNumber=1, stepType="CONTAINED", title="Contain",
    createdAt="2026-01-01T00:00:00Z",
)
check("CaseFlowStep CONTAINED → valid", cf_step.validate_request() == [])

# CaseFlow step: ERADICATED now valid
cf_step2 = CaseFlowStepRequest(
    stepNumber=2, stepType="ERADICATED", title="Eradicate",
    createdAt="2026-01-01T00:00:00Z",
)
check("CaseFlowStep ERADICATED → valid", cf_step2.validate_request() == [])

# ---------------------------------------------------------------------------
# 4. Service-layer objects — build and round-trip through normalizer
# ---------------------------------------------------------------------------
print("\n=== 4. Service build + normalizer round-trip ===")

# --- Playbook ---
try:
    from services.playbook_service import (
        build_playbook_step, build_playbook,
        PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum,
    )
    step = build_playbook_step(
        "pb-parent", step_number=1, title="Step 1",
        step_type=PlaybookStepTypeEnum.MANUAL,
        created_at="2026-01-01T00:00:00Z",
        expected_outcome="done",
    )
    pb = build_playbook(
        name="FireIR", severity=PlaybookSeverityEnum.HIGH,
        status=PlaybookStatusEnum.ACTIVE, steps=[step],
        created_at="2026-01-01T00:00:00Z", confidence=90.0,
    )
    # simulate store dict
    store = {
        "playbookId": pb.playbookId, "playbookKey": pb.playbookKey,
        "name": pb.name, "description": pb.description,
        "severity": pb.severity.value, "status": pb.status.value,
        "projectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "investigationId": "",
        "steps": [{
            "stepId": step.stepId, "stepKey": step.stepKey,
            "stepNumber": step.stepNumber, "title": step.title,
            "description": step.description, "stepType": step.stepType.value,
            "expectedOutcome": step.expectedOutcome,
            "relatedTechniques": [], "relatedCVEs": [], "relatedIOCs": [],
            "createdAt": step.createdAt,
        }],
        "relatedThreatActors": ["APT29"], "relatedCampaigns": ["Cozy Bear"],
        "confidence": pb.confidence, "createdAt": pb.createdAt,
        "enabled": True, "priority": 1, "category": "", "author": "",
    }
    n = normalize_playbook(store)
    check("Playbook build+normalize: name preserved",      n["name"] == "FireIR")
    check("Playbook build+normalize: severity HIGH",       n["severity"] == "HIGH")
    check("Playbook build+normalize: status ACTIVE",       n["status"] == "ACTIVE")
    check("Playbook build+normalize: stepType MANUAL",     n["steps"][0]["stepType"] == "MANUAL")
    check("Playbook build+normalize: relatedThreatActors", n["relatedThreatActors"] == ["APT29"])
    check("Playbook build+normalize: relatedCampaigns",    n["relatedCampaigns"] == ["Cozy Bear"])
    check("Playbook build+normalize: confidence 90",       abs(n["confidence"] - 90.0) < 0.01)

    # Response model construction
    resp = PlaybookResponse(
        playbookId=n["playbookId"],   playbookKey=n["playbookKey"],
        name=n["name"],               description=n["description"],
        severity=n["severity"],       status=n["status"],
        projectId=n["projectId"],     investigationId=n["investigationId"],
        steps=[PlaybookStepResponse(
            stepId=s["stepId"],          stepKey=s["stepKey"],
            stepNumber=s["stepNumber"],  title=s["title"],
            description=s["description"], stepType=s["stepType"],
            expectedOutcome=s["expectedOutcome"],
            relatedTechniques=s["relatedTechniques"],
            relatedCVEs=s["relatedCVEs"], relatedIOCs=s["relatedIOCs"],
            createdAt=s["createdAt"],
        ) for s in n["steps"]],
        relatedThreatActors=n["relatedThreatActors"],
        relatedCampaigns=n["relatedCampaigns"],
        confidence=n["confidence"],   createdAt=n["createdAt"],
        enabled=n["enabled"],         priority=n["priority"],
        category=n["category"],       author=n["author"],
    )
    d = resp.model_dump()
    check("Playbook PlaybookResponse.model_dump() works",   isinstance(d, dict))
    check("Playbook response has relatedThreatActors field", "relatedThreatActors" in d)
    check("Playbook response has projectId field",          d["projectId"] != "")
except Exception as e:
    check("Playbook service round-trip", False, str(e))

# --- Rule ---
try:
    from services.rules_engine_service import (
        build_rule_condition, build_rule,
        RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
    )
    cond = build_rule_condition("severity", "eq", "HIGH", "2026-01-01T00:00:00Z")
    rule = build_rule(
        name="SevFilter", severity=RuleSeverityEnum.CRITICAL,
        status=RuleStatusEnum.ACTIVE, conditions=[cond],
        actions=[RuleActionEnum.CREATE_ALERT],
        priority=10, created_at="2026-01-01T00:00:00Z",
    )
    store_r = {
        "ruleId": rule.ruleId, "ruleKey": rule.ruleKey,
        "name": rule.name, "description": rule.description,
        "severity": rule.severity.value, "status": rule.status.value,
        "projectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "investigationId": "",
        "conditions": [{"conditionId": cond.conditionId,
                         "conditionKey": cond.conditionKey,
                         "field": cond.field, "operator": cond.operator,
                         "value": cond.value, "createdAt": cond.createdAt}],
        "actions": [{"actionId": "act-1", "actionType": "CREATE_ALERT", "parameters": {}}],
        "priority": rule.priority, "createdAt": rule.createdAt,
        "enabled": True, "category": "", "author": "",
    }
    nr = normalize_rule(store_r)
    check("Rule build+normalize: severity CRITICAL",  nr["severity"] == "CRITICAL")
    check("Rule build+normalize: status ACTIVE",      nr["status"] == "ACTIVE")
    check("Rule build+normalize: 1 condition",        len(nr["conditions"]) == 1)
    check("Rule build+normalize: 1 action",           len(nr["actions"]) == 1)
    check("Rule build+normalize: action CREATE_ALERT",
          nr["actions"][0]["actionType"] == "CREATE_ALERT")
    check("Rule build+normalize: projectId present",  nr["projectId"] != "")
except Exception as e:
    check("Rule service round-trip", False, str(e))

# --- Automation ---
try:
    from services.automation_engine_service import (
        build_automation_step, build_automation,
        AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
    )
    astep = build_automation_step(
        "auto-parent", step_number=1, name="Create alert",
        action=AutomationActionEnum.CREATE_ALERT,
        created_at="2026-01-01T00:00:00Z",
    )
    auto = build_automation(
        name="AlertOnRule", trigger=AutomationTriggerEnum.RULE_MATCHED,
        status=AutomationStatusEnum.ACTIVE, steps=[astep],
        created_at="2026-01-01T00:00:00Z", priority=50,
    )
    store_a = {
        "automationId": auto.automationId, "automationKey": auto.automationKey,
        "name": auto.name, "description": auto.description,
        "status": auto.status.value, "trigger": auto.trigger.value,
        "projectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "investigationId": "", "playbookId": "", "ruleId": "",
        "steps": [{"stepId": astep.stepId, "stepKey": astep.stepKey,
                   "stepNumber": astep.stepNumber, "name": astep.name,
                   "description": astep.description,
                   "action": astep.action.value,
                   "parameters": {}, "createdAt": astep.createdAt}],
        "priority": auto.priority, "createdAt": auto.createdAt,
        "enabled": True, "category": "", "author": "",
    }
    na = normalize_automation(store_a)
    check("Automation build+normalize: status ACTIVE",         na["status"] == "ACTIVE")
    check("Automation build+normalize: trigger RULE_MATCHED",  na["trigger"] == "RULE_MATCHED")
    check("Automation build+normalize: action CREATE_ALERT",   na["steps"][0]["action"] == "CREATE_ALERT")

    # Test execution status
    exec_raw = {"executionId": "e1", "automationId": auto.automationId,
                "status": "SUCCESS", "startedAt": "2026-01-01T00:00:00Z",
                "completedAt": "2026-01-01T00:00:01Z", "stepResults": []}
    en = normalize_automation_execution(exec_raw)
    check("AutomationExecution SUCCESS→COMPLETED in normalize", en["status"] == "COMPLETED")
except Exception as e:
    check("Automation service round-trip", False, str(e))

# --- CaseFlow ---
try:
    from services.case_flow_service import (
        build_case_step, build_case,
        CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
    )
    # Test CONTAINED and ERADICATED are valid
    check("CaseStepTypeEnum has CONTAINED",  hasattr(CaseStepTypeEnum, "CONTAINED"))
    check("CaseStepTypeEnum has ERADICATED", hasattr(CaseStepTypeEnum, "ERADICATED"))

    cstep = build_case_step(
        "case-parent", step_number=1,
        step_type=CaseStepTypeEnum.INVESTIGATED,
        title="Investigate", created_at="2026-01-01T00:00:00Z",
    )
    cs = build_case(
        title="Ransomware IR", priority=CasePriorityEnum.CRITICAL,
        status=CaseStatusEnum.OPEN, steps=[cstep],
        created_at="2026-01-01T00:00:00Z", confidence=95.0,
    )
    store_cf = {
        "caseFlowId": cs.caseId, "caseFlowKey": cs.caseKey,
        "caseNumber": cs.caseNumber, "title": cs.title,
        "description": cs.description,
        "status": cs.status.value, "priority": cs.priority.value,
        "projectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "investigationId": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
        "playbookId": "", "automationId": "",
        "steps": [{"stepId": cstep.stepId, "stepKey": cstep.stepKey,
                   "stepNumber": cstep.stepNumber, "stepType": cstep.stepType.value,
                   "title": cstep.title, "description": cstep.description,
                   "assignedTo": "", "createdAt": cstep.createdAt}],
        "findingIds": ["f1"], "alertIds": [], "evidenceIds": [], "playbookIds": [],
        "assignedTo": "", "owner": "analyst1",
        "confidence": cs.confidence, "createdAt": cs.createdAt,
    }
    ncf = normalize_case_flow(store_cf)
    check("CaseFlow build+normalize: title preserved",        ncf["title"] == "Ransomware IR")
    check("CaseFlow build+normalize: priority CRITICAL",      ncf["priority"] == "CRITICAL")
    check("CaseFlow build+normalize: status OPEN",            ncf["status"] == "OPEN")
    check("CaseFlow build+normalize: stepType INVESTIGATED",  ncf["steps"][0]["stepType"] == "INVESTIGATED")
    check("CaseFlow build+normalize: investigationId present", ncf["investigationId"] != "")
    check("CaseFlow build+normalize: findingIds round-trip",  ncf["findingIds"] == ["f1"])

    # Execution status fix
    cf_exec = {"executionId": "e2", "caseFlowId": cs.caseId,
               "status": "SUCCESS", "startedAt": "2026-01-01T00:00:00Z",
               "completedAt": "2026-01-01T00:00:01Z", "stepResults": []}
    cfe_n = normalize_case_flow_execution(cf_exec)
    check("CaseFlowExecution SUCCESS→COMPLETED in normalize", cfe_n["status"] == "COMPLETED")
except Exception as e:
    check("CaseFlow service round-trip", False, str(e))

# ---------------------------------------------------------------------------
# 5. Router helper functions (no DB calls needed)
# ---------------------------------------------------------------------------
print("\n=== 5. Router helper functions ===")

# Playbook router helpers
try:
    from api.workflow.playbook_router import (
        _find as pb_find, _sort as pb_sort,
        _filter as pb_filter, _stats as pb_stats, _summary as pb_summary,
        _search as pb_search,
    )

    sample_pbs = [
        {"playbookId": "pb-001", "playbookKey": "key1", "name": "Alpha",
         "description": "d", "severity": "HIGH", "status": "ACTIVE",
         "projectId": "proj-1", "investigationId": "",
         "steps": [{"stepId":"s1","stepKey":"sk1","stepNumber":1,"title":"T",
                    "description":"","stepType":"MANUAL","expectedOutcome":"",
                    "relatedTechniques":[],"relatedCVEs":[],"relatedIOCs":[],
                    "createdAt":"2026-01-01T00:00:00Z"}],
         "relatedThreatActors": [], "relatedCampaigns": [],
         "confidence": 85.0, "createdAt": "2026-01-01T00:00:00Z",
         "updatedAt": None, "enabled": True, "priority": 2,
         "category": "IR", "author": "alice"},
        {"playbookId": "pb-002", "playbookKey": "key2", "name": "Beta",
         "description": "d", "severity": "MEDIUM", "status": "DRAFT",
         "projectId": "proj-1", "investigationId": "",
         "steps": [], "relatedThreatActors": [], "relatedCampaigns": [],
         "confidence": 50.0, "createdAt": "2026-02-01T00:00:00Z",
         "updatedAt": None, "enabled": False, "priority": 5,
         "category": "Threat Hunt", "author": "bob"},
    ]

    found = pb_find(sample_pbs, "pb-001")
    check("pb_find by playbookId",   found is not None and found["name"] == "Alpha")
    found2 = pb_find(sample_pbs, "beta")
    check("pb_find by name (case-insensitive)", found2 is not None and found2["name"] == "Beta")
    not_found = pb_find(sample_pbs, "zzz")
    check("pb_find miss → None", not_found is None)

    sorted_asc = pb_sort(sample_pbs, "playbookName", "asc")
    check("pb_sort name asc: Alpha first", sorted_asc[0]["name"] == "Alpha")
    sorted_desc = pb_sort(sample_pbs, "playbookName", "desc")
    check("pb_sort name desc: Beta first", sorted_desc[0]["name"] == "Beta")

    filtered_enabled = pb_filter(sample_pbs, enabled=True)
    check("pb_filter enabled=True → 1", len(filtered_enabled) == 1)
    filtered_cat = pb_filter(sample_pbs, category="IR")
    check("pb_filter category=IR → 1", len(filtered_cat) == 1)
    filtered_pri = pb_filter(sample_pbs, minimumSteps=1)
    check("pb_filter minimumSteps=1 → 1 (Alpha has 1 step)", len(filtered_pri) == 1)

    stats = pb_stats(sample_pbs)
    check("pb_stats totalPlaybooks=2",    stats["totalPlaybooks"] == 2)
    check("pb_stats enabledPlaybooks=1",  stats["enabledPlaybooks"] == 1)
    check("pb_stats disabledPlaybooks=1", stats["disabledPlaybooks"] == 1)
    check("pb_stats averageSteps=0.5",    abs(stats["averageSteps"] - 0.5) < 0.01)
    check("pb_stats categoryCounts has IR", "IR" in stats["categoryCounts"])

    summ = pb_summary(sample_pbs[0])
    check("pb_summary has playbookId", "playbookId" in summ)
    check("pb_summary text non-empty", len(summ["summaryText"]) > 10)

    searched = pb_search(sample_pbs, "alpha")
    check("pb_search 'alpha' → 1 result", len(searched) == 1)
    searched_all = pb_search(sample_pbs, "")
    check("pb_search '' → all results",   len(searched_all) == 2)
except Exception as e:
    check("Playbook router helpers", False, str(e))

# Rule router helpers
try:
    from api.workflow.rules_router import (
        _find as r_find, _sort as r_sort, _filter as r_filter,
        _stats as r_stats, _summary as r_summary,
    )
    sample_rules = [
        {"ruleId": "r-001", "ruleKey": "rk1", "name": "HighSev",
         "description": "", "severity": "HIGH", "status": "ACTIVE",
         "projectId": "p1", "investigationId": "",
         "conditions": [{"conditionId":"c1","conditionKey":"ck1",
                          "field":"sev","operator":"eq","value":"HIGH",
                          "createdAt":"2026-01-01T00:00:00Z"}],
         "actions": [{"actionId":"a1","actionType":"CREATE_ALERT","parameters":{}}],
         "priority": 10, "createdAt": "2026-01-01T00:00:00Z",
         "updatedAt": None, "enabled": True, "category": "Detection", "author": ""},
        {"ruleId": "r-002", "ruleKey": "rk2", "name": "LowSev",
         "description": "", "severity": "LOW", "status": "DRAFT",
         "projectId": "p1", "investigationId": "",
         "conditions": [], "actions": [],
         "priority": 100, "createdAt": "2026-02-01T00:00:00Z",
         "updatedAt": None, "enabled": False, "category": "", "author": ""},
    ]
    check("r_find by ruleId",  r_find(sample_rules, "r-001") is not None)
    check("r_find miss → None", r_find(sample_rules, "zzz") is None)
    check("r_sort name asc", r_sort(sample_rules,"ruleName","asc")[0]["name"]=="HighSev")
    check("r_filter enabled", len(r_filter(sample_rules, enabled=True)) == 1)
    check("r_filter severity HIGH", len(r_filter(sample_rules, severity="HIGH")) == 1)
    check("r_filter minimumConditions=1",
          len(r_filter(sample_rules, minimumConditions=1)) == 1)
    rs = r_stats(sample_rules)
    check("r_stats totalRules=2", rs["totalRules"] == 2)
    check("r_stats averageConditions=0.5", abs(rs["averageConditions"] - 0.5) < 0.01)
    summ_r = r_summary(sample_rules[0])
    check("r_summary conditionCount=1", summ_r["conditionCount"] == 1)
    check("r_summary actionCount=1",    summ_r["actionCount"] == 1)
except Exception as e:
    check("Rule router helpers", False, str(e))

# Automation router helpers
try:
    from api.workflow.automation_router import (
        _find as a_find, _sort as a_sort, _filter as a_filter,
        _stats as a_stats, _summary as a_summary,
    )
    sample_autos = [
        {"automationId": "a-001", "automationKey": "ak1", "name": "AlertAuto",
         "description": "", "status": "ACTIVE", "trigger": "RULE_MATCHED",
         "projectId": "p1", "investigationId": "", "playbookId": "", "ruleId": "",
         "steps": [{"stepId":"st1","stepKey":"stk1","stepNumber":1,"name":"CreateAlert",
                    "description":"","action":"CREATE_ALERT","parameters":{},
                    "createdAt":"2026-01-01T00:00:00Z"}],
         "priority": 50, "createdAt": "2026-01-01T00:00:00Z",
         "updatedAt": None, "enabled": True, "category": "", "author": ""},
    ]
    check("a_find by automationId", a_find(sample_autos,"a-001") is not None)
    check("a_find miss → None",     a_find(sample_autos,"zzz") is None)
    check("a_filter enabled=True",  len(a_filter(sample_autos, enabled=True)) == 1)
    as_ = a_stats(sample_autos)
    check("a_stats totalAutomations=1", as_["totalAutomations"] == 1)
    check("a_stats averageSteps=1.0",   abs(as_["averageSteps"] - 1.0) < 0.01)
    summ_a = a_summary(sample_autos[0])
    check("a_summary trigger RULE_MATCHED", "RULE_MATCHED" in summ_a["summaryText"])
except Exception as e:
    check("Automation router helpers", False, str(e))

# CaseFlow router helpers
try:
    from api.workflow.case_flow_router import (
        _find as cf_find, _sort as cf_sort, _filter as cf_filter,
        _stats as cf_stats, _summary as cf_summary,
    )
    sample_cases = [
        {"caseFlowId": "cf-001", "caseFlowKey": "cfk1",
         "caseNumber": "CASE-001", "title": "Ransomware",
         "description": "", "status": "OPEN", "priority": "CRITICAL",
         "projectId": "p1", "investigationId": "inv-1",
         "playbookId": "", "automationId": "",
         "steps": [], "findingIds": ["f1"], "alertIds": [],
         "evidenceIds": [], "playbookIds": [],
         "assignedTo": "alice", "owner": "alice",
         "confidence": 95.0, "createdAt": "2026-01-01T00:00:00Z", "updatedAt": None},
        {"caseFlowId": "cf-002", "caseFlowKey": "cfk2",
         "caseNumber": "CASE-002", "title": "Phishing",
         "description": "", "status": "CLOSED", "priority": "LOW",
         "projectId": "p1", "investigationId": "inv-2",
         "playbookId": "", "automationId": "",
         "steps": [], "findingIds": [], "alertIds": [],
         "evidenceIds": [], "playbookIds": [],
         "assignedTo": "", "owner": "bob",
         "confidence": 60.0, "createdAt": "2026-02-01T00:00:00Z", "updatedAt": None},
    ]
    check("cf_find by caseFlowId",    cf_find(sample_cases,"cf-001") is not None)
    check("cf_find by title",         cf_find(sample_cases,"phishing") is not None)
    check("cf_find miss → None",      cf_find(sample_cases,"zzz") is None)
    check("cf_filter status=OPEN",    len(cf_filter(sample_cases,status="OPEN"))==1)
    check("cf_filter status=CLOSED",  len(cf_filter(sample_cases,status="CLOSED"))==1)
    check("cf_filter priority=CRITICAL", len(cf_filter(sample_cases,priority="CRITICAL"))==1)
    cfs = cf_stats(sample_cases)
    check("cf_stats totalCases=2",    cfs["totalCases"] == 2)
    check("cf_stats openCases=1",     cfs["openCases"] == 1)
    check("cf_stats closedCases=1",   cfs["closedCases"] == 1)
    summ_cf = cf_summary(sample_cases[0])
    check("cf_summary has caseFlowId", "caseFlowId" in summ_cf)
    check("cf_summary confidence 95",  abs(summ_cf["confidence"] - 95.0) < 0.01)
except Exception as e:
    check("CaseFlow router helpers", False, str(e))

# ---------------------------------------------------------------------------
# 6. Prisma enum alignment checks (Prisma StepType via schema inspection)
# ---------------------------------------------------------------------------
print("\n=== 6. Prisma schema enum alignment ===")

import pathlib, re

schema_text = pathlib.Path("prisma/schema.prisma").read_text(encoding="utf-8")

def prisma_enum_values(name: str) -> set:
    """Extract member names from a Prisma enum block."""
    m = re.search(rf"enum\s+{name}\s*\{{([^}}]+)\}}", schema_text)
    if not m: return set()
    lines = m.group(1).strip().splitlines()
    return {l.strip().split()[0] for l in lines
            if l.strip() and not l.strip().startswith("//")}

step_type_values = prisma_enum_values("StepType")
check("Prisma StepType has MANUAL",              "MANUAL"              in step_type_values)
check("Prisma StepType has AUTOMATED",           "AUTOMATED"           in step_type_values)
check("Prisma StepType has VERIFICATION",        "VERIFICATION"        in step_type_values)
check("Prisma StepType has CONTAINMENT",         "CONTAINMENT"         in step_type_values)
check("Prisma StepType has ERADICATION",         "ERADICATION"         in step_type_values)
check("Prisma StepType has RECOVERY",            "RECOVERY"            in step_type_values)
check("Prisma StepType has CREATED",             "CREATED"             in step_type_values)
check("Prisma StepType has ASSIGNED",            "ASSIGNED"            in step_type_values)
check("Prisma StepType has INVESTIGATED",        "INVESTIGATED"        in step_type_values)
check("Prisma StepType has CONTAINED (new)",     "CONTAINED"           in step_type_values)
check("Prisma StepType has ERADICATED (new)",    "ERADICATED"          in step_type_values)
check("Prisma StepType has RECOVERED",           "RECOVERED"           in step_type_values)
check("Prisma StepType has CLOSED",              "CLOSED"              in step_type_values)
check("Prisma StepType has CREATE_ALERT",        "CREATE_ALERT"        in step_type_values)
check("Prisma StepType has CREATE_TIMELINE_EVENT","CREATE_TIMELINE_EVENT" in step_type_values)
check("Prisma StepType has START_PLAYBOOK",      "START_PLAYBOOK"      in step_type_values)
check("Prisma StepType has UPDATE_FINDING",      "UPDATE_FINDING"      in step_type_values)
check("Prisma StepType has UPDATE_ALERT",        "UPDATE_ALERT"        in step_type_values)
check("Prisma StepType has TAG_INVESTIGATION",   "TAG_INVESTIGATION"   in step_type_values)

playbook_status = prisma_enum_values("PlaybookStatus")
check("Prisma PlaybookStatus has DRAFT",         "DRAFT"      in playbook_status)
check("Prisma PlaybookStatus has ACTIVE",        "ACTIVE"     in playbook_status)
check("Prisma PlaybookStatus has DEPRECATED",    "DEPRECATED" in playbook_status)
check("Prisma PlaybookStatus has ARCHIVED",      "ARCHIVED"   in playbook_status)

rule_status = prisma_enum_values("RuleStatus")
check("Prisma RuleStatus has DRAFT",             "DRAFT"    in rule_status)
check("Prisma RuleStatus has ACTIVE",            "ACTIVE"   in rule_status)
check("Prisma RuleStatus has DISABLED",          "DISABLED" in rule_status)
check("Prisma RuleStatus has ARCHIVED",          "ARCHIVED" in rule_status)

auto_status = prisma_enum_values("AutomationStatus")
check("Prisma AutomationStatus has DRAFT",       "DRAFT"    in auto_status)
check("Prisma AutomationStatus has ACTIVE",      "ACTIVE"   in auto_status)
check("Prisma AutomationStatus has DISABLED",    "DISABLED" in auto_status)
check("Prisma AutomationStatus has ARCHIVED",    "ARCHIVED" in auto_status)
check("Prisma AutomationStatus no INACTIVE",     "INACTIVE" not in auto_status)

auto_exec_status = prisma_enum_values("AutomationExecutionStatus")
check("Prisma AutomationExecutionStatus has PENDING",   "PENDING"   in auto_exec_status)
check("Prisma AutomationExecutionStatus has ACTIVE",    "ACTIVE"    in auto_exec_status)
check("Prisma AutomationExecutionStatus has COMPLETED", "COMPLETED" in auto_exec_status)
check("Prisma AutomationExecutionStatus has FAILED",    "FAILED"    in auto_exec_status)
check("Prisma AutomationExecutionStatus no SUCCESS",    "SUCCESS"   not in auto_exec_status)

case_exec_status = prisma_enum_values("CaseExecutionStatus")
check("Prisma CaseExecutionStatus has PENDING",   "PENDING"   in case_exec_status)
check("Prisma CaseExecutionStatus has ACTIVE",    "ACTIVE"    in case_exec_status)
check("Prisma CaseExecutionStatus has COMPLETED", "COMPLETED" in case_exec_status)
check("Prisma CaseExecutionStatus has FAILED",    "FAILED"    in case_exec_status)
check("Prisma CaseExecutionStatus no SUCCESS",    "SUCCESS"   not in case_exec_status)

case_status = prisma_enum_values("CaseStatus")
check("Prisma CaseStatus has OPEN",        "OPEN"        in case_status)
check("Prisma CaseStatus has IN_PROGRESS", "IN_PROGRESS" in case_status)
check("Prisma CaseStatus has ON_HOLD",     "ON_HOLD"     in case_status)
check("Prisma CaseStatus has RESOLVED",    "RESOLVED"    in case_status)
check("Prisma CaseStatus has CLOSED",      "CLOSED"      in case_status)

trig_type = prisma_enum_values("AutomationTriggerType")
check("Prisma AutomationTriggerType has FINDING_CREATED",   "FINDING_CREATED"   in trig_type)
check("Prisma AutomationTriggerType has ALERT_CREATED",     "ALERT_CREATED"     in trig_type)
check("Prisma AutomationTriggerType has RULE_MATCHED",      "RULE_MATCHED"      in trig_type)
check("Prisma AutomationTriggerType has PLAYBOOK_SELECTED", "PLAYBOOK_SELECTED" in trig_type)
check("Prisma AutomationTriggerType has TIMELINE_EVENT",    "TIMELINE_EVENT"    in trig_type)
check("Prisma AutomationTriggerType has MANUAL",            "MANUAL"            in trig_type)

# ---------------------------------------------------------------------------
# 7. Python ↔ Prisma enum symmetry checks
# ---------------------------------------------------------------------------
print("\n=== 7. Python ↔ Prisma enum symmetry ===")

from services.playbook_service   import PlaybookStatusEnum, PlaybookSeverityEnum, PlaybookStepTypeEnum
from services.rules_engine_service import RuleStatusEnum, RuleSeverityEnum
from services.automation_engine_service import AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum
from services.case_flow_service  import CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum

py_pb_status = {e.value for e in PlaybookStatusEnum}
check("PlaybookStatusEnum ⊆ Prisma PlaybookStatus",
      py_pb_status.issubset(playbook_status), str(py_pb_status - playbook_status))

py_sev = {e.value for e in PlaybookSeverityEnum}
prisma_sev = prisma_enum_values("RuleSeverity")
check("PlaybookSeverityEnum ⊆ Prisma RuleSeverity",
      py_sev.issubset(prisma_sev), str(py_sev - prisma_sev))

py_rule_status = {e.value for e in RuleStatusEnum}
check("RuleStatusEnum ⊆ Prisma RuleStatus",
      py_rule_status.issubset(rule_status), str(py_rule_status - rule_status))

py_rule_sev = {e.value for e in RuleSeverityEnum}
check("RuleSeverityEnum ⊆ Prisma RuleSeverity",
      py_rule_sev.issubset(prisma_sev), str(py_rule_sev - prisma_sev))

py_auto_status = {e.value for e in AutomationStatusEnum}
check("AutomationStatusEnum ⊆ Prisma AutomationStatus",
      py_auto_status.issubset(auto_status), str(py_auto_status - auto_status))
check("AutomationStatusEnum has no INACTIVE",
      "INACTIVE" not in py_auto_status)

py_trig = {e.value for e in AutomationTriggerEnum}
check("AutomationTriggerEnum ⊆ Prisma AutomationTriggerType",
      py_trig.issubset(trig_type), str(py_trig - trig_type))

py_action = {e.value for e in AutomationActionEnum}
check("AutomationActionEnum ⊆ Prisma StepType",
      py_action.issubset(step_type_values), str(py_action - step_type_values))

py_case_status = {e.value for e in CaseStatusEnum}
check("CaseStatusEnum ⊆ Prisma CaseStatus",
      py_case_status.issubset(case_status), str(py_case_status - case_status))

py_case_pri = {e.value for e in CasePriorityEnum}
prisma_case_pri = prisma_enum_values("CasePriority")
check("CasePriorityEnum ⊆ Prisma CasePriority",
      py_case_pri.issubset(prisma_case_pri), str(py_case_pri - prisma_case_pri))

py_step = {e.value for e in CaseStepTypeEnum}
check("CaseStepTypeEnum ⊆ Prisma StepType (all values including CONTAINED/ERADICATED)",
      py_step.issubset(step_type_values), str(py_step - step_type_values))

pb_step = {e.value for e in PlaybookStepTypeEnum}
check("PlaybookStepTypeEnum ⊆ Prisma StepType",
      pb_step.issubset(step_type_values), str(pb_step - step_type_values))

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print(f"  PASSED: {PASS}")
print(f"  FAILED: {FAIL}")
print(f"  TOTAL : {PASS + FAIL}")
print("=" * 60)

if FAIL > 0:
    sys.exit(1)
