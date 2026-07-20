"""
Workflow Domain Normalizers
============================
Single canonical normalization layer for every workflow entity.

Every `_normalize_*` function:
  - Accepts both raw Prisma DB records (id, camelCase columns) and
    legacy metadata-backed dicts (entityId, stored in metadata blob).
  - Returns a dict with the API field names that routers and response
    models expect.
  - Applies correct default enum values that match Prisma enums exactly.
  - Correctly round-trips metadata-stored fields
    (relatedThreatActors, relatedCampaigns, playbookKey, ruleKey,
     automationKey, caseFlowKey, caseNumber).

Canonical Prisma enum defaults used here:
  Playbook.status    → DRAFT         (PlaybookStatus)
  Playbook.severity  → MEDIUM        (RuleSeverity)
  Rule.status        → DRAFT         (RuleStatus)
  Rule.severity      → MEDIUM        (RuleSeverity)
  Automation.status  → DRAFT         (AutomationStatus)  ← was "INACTIVE" (wrong)
  Automation.trigger → MANUAL        (AutomationTriggerType)
  AutomationStep.action → CREATE_ALERT  (StepType automation subset)
  AutomationExecution.status → COMPLETED  ← was "SUCCESS" (wrong)
  CaseFlow.status    → OPEN          (CaseStatus)
  CaseFlow.priority  → MEDIUM        (CasePriority)
  CaseFlowExecution.status → COMPLETED  ← was "SUCCESS" (wrong)
  PlaybookStep.stepType → MANUAL     ← was "INVESTIGATION" (wrong)
  CaseFlowStep.stepType → CREATED    (StepType case-flow subset)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_dt(val: Any) -> Optional[str]:
    """Safely format a datetime / str to ISO string."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if hasattr(val, "isoformat"):
        try:
            return val.isoformat()
        except Exception:
            return str(val)
    return str(val)


def _to_list(val: Any) -> List[str]:
    """Coerce a DB value (list, JSON string, None) to a clean string list."""
    if not val:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        except Exception:
            pass
    return []


def _pull_metadata(raw: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    """
    Extract fields from a Prisma metadata Json blob.
    Returns dict of {key: value} for any keys found in metadata.
    """
    meta = raw.get("metadata")
    if not isinstance(meta, dict):
        # metadata may be a JSON string
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        else:
            meta = {}
    return {k: meta.get(k) for k in keys if k in meta}


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Playbook normalizer
# ---------------------------------------------------------------------------

def normalize_playbook(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes both Prisma DB record and legacy metadata-backed dicts.
    Canonical output has API field names expected by PlaybookResponse.
    """
    playbook_id = raw.get("playbookId") or raw.get("id") or ""
    name = raw.get("name") or ""

    # playbookKey: prefer stored value → derive from name
    playbook_key = (
        raw.get("playbookKey")
        or _pull_metadata(raw, "playbookKey").get("playbookKey")
        or (_md5(name) if name else playbook_id)
    )

    # relatedThreatActors / relatedCampaigns: stored in metadata Json
    meta_extras = _pull_metadata(raw, "relatedThreatActors", "relatedCampaigns")
    related_threat_actors = _to_list(
        raw.get("relatedThreatActors")
        or meta_extras.get("relatedThreatActors")
    )
    related_campaigns = _to_list(
        raw.get("relatedCampaigns")
        or meta_extras.get("relatedCampaigns")
    )

    # Steps
    raw_steps = raw.get("steps") or _pull_metadata(raw, "steps").get("steps") or []
    if isinstance(raw_steps, str):
        try:
            raw_steps = json.loads(raw_steps)
        except Exception:
            raw_steps = []

    steps: List[Dict[str, Any]] = []
    for s in raw_steps:
        if not isinstance(s, dict):
            continue
        # stepType defaults to MANUAL (valid PlaybookStep StepType)
        step_type = (s.get("stepType") or "MANUAL").upper()
        if step_type == "INVESTIGATION":          # legacy wrong default fix
            step_type = "MANUAL"
        title = s.get("title") or ""
        desc = s.get("description") or ""

        executor = s.get("executor")
        if executor is None:
            executor = s.get("executorType")
        
        if not executor:
            title_lower = title.lower()
            desc_lower = desc.lower()
            if step_type == "AUTOMATED":
                if (
                    "ai summary" in title_lower or "ai summary" in desc_lower or
                    "investigation" in title_lower or "investigation" in desc_lower or
                    "ai_investigation" in title_lower or "ai_investigation" in desc_lower or
                    "ai_summary" in title_lower or "ai_summary" in desc_lower
                ):
                    executor = "ai_investigation"
                elif "nmap" in title_lower or "nmap" in desc_lower or "scan" in title_lower or "scan" in desc_lower:
                    executor = "nmap"
                elif "analyze pcap" in title_lower or "pcap analysis" in title_lower or "analyze pcap" in desc_lower or "pcap analysis" in desc_lower:
                    executor = "pcap_analysis"
                elif "capture" in title_lower or "capture" in desc_lower or "network capture" in title_lower or "pcap" in title_lower:
                    executor = "packet_capture"
                else:
                    executor = "manual"
            else:
                executor = "manual"

        step_meta = s.get("metadata") or {}
        if isinstance(step_meta, str):
            try:
                step_meta = json.loads(step_meta)
            except Exception:
                step_meta = {}
        config = s.get("config") or (step_meta.get("config") if isinstance(step_meta, dict) else None) or {}

        steps.append({
            "stepId":            s.get("stepId") or s.get("id") or "",
            "stepKey":           s.get("stepKey") or s.get("stepId") or "",
            "stepNumber":        s.get("stepNumber") or 1,
            "title":             title,
            "description":       desc,
            "stepType":          step_type,
            "executor":          executor,
            "expectedOutcome":   s.get("expectedOutcome") or "",
            "relatedTechniques": _to_list(s.get("relatedTechniques")),
            "relatedCVEs":       _to_list(s.get("relatedCVEs")),
            "relatedIOCs":       _to_list(s.get("relatedIOCs")),
            "createdAt":         _fmt_dt(s.get("createdAt")) or "",
            "config":            config,
        })

    return {
        "playbookId":          playbook_id,
        "playbookKey":         playbook_key,
        "name":                name,
        "description":         raw.get("description") or "",
        "severity":            (raw.get("severity") or "MEDIUM").upper(),
        "status":              (raw.get("status") or "DRAFT").upper(),
        "projectId":           raw.get("projectId") or "",
        "investigationId":     raw.get("investigationId") or "",
        "steps":               steps,
        "relatedThreatActors": related_threat_actors,
        "relatedCampaigns":    related_campaigns,
        "confidence":          float(raw.get("confidence") or 100.0),
        "createdAt":           _fmt_dt(raw.get("createdAt")) or "",
        "updatedAt":           _fmt_dt(raw.get("updatedAt")),
        "enabled":             bool(raw.get("enabled", True)),
        "priority":            int(raw.get("priority") or 1),
        "category":            raw.get("category") or "",
        "author":              raw.get("author") or "",
    }


# ---------------------------------------------------------------------------
# Rule normalizer
# ---------------------------------------------------------------------------

def normalize_rule(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes both Prisma DB record and legacy metadata dicts for Rule."""
    rule_id = raw.get("ruleId") or raw.get("id") or ""
    name = raw.get("name") or ""
    rule_key = (
        raw.get("ruleKey")
        or _pull_metadata(raw, "ruleKey").get("ruleKey")
        or (_md5(name) if name else rule_id)
    )

    # Conditions — may be embedded list or JSON string
    raw_conds = raw.get("conditions") or []
    if isinstance(raw_conds, str):
        try:
            raw_conds = json.loads(raw_conds)
        except Exception:
            raw_conds = []

    conditions: List[Dict[str, Any]] = []
    for c in raw_conds:
        if not isinstance(c, dict):
            continue
        conditions.append({
            "conditionId":  c.get("conditionId") or c.get("id") or "",
            "conditionKey": c.get("conditionKey") or c.get("conditionId") or "",
            "field":        c.get("field") or "",
            "operator":     c.get("operator") or "eq",
            "value":        c.get("value") or "",
            "createdAt":    _fmt_dt(c.get("createdAt")) or "",
        })

    # Actions — may be embedded list or JSON string
    raw_actions = raw.get("actions") or []
    if isinstance(raw_actions, str):
        try:
            raw_actions = json.loads(raw_actions)
        except Exception:
            raw_actions = []

    actions: List[Dict[str, Any]] = []
    for a in raw_actions:
        if not isinstance(a, dict):
            continue
        actions.append({
            "actionId":   a.get("actionId") or a.get("id") or "",
            "actionType": a.get("actionType") or "",
            "parameters": a.get("parameters") or {},
        })

    return {
        "ruleId":          rule_id,
        "ruleKey":         rule_key,
        "name":            name,
        "description":     raw.get("description") or "",
        "severity":        (raw.get("severity") or "MEDIUM").upper(),
        "status":          (raw.get("status") or "DRAFT").upper(),
        "projectId":       raw.get("projectId") or "",
        "investigationId": raw.get("investigationId") or "",
        "conditions":      conditions,
        "actions":         actions,
        "priority":        int(raw.get("priority") or 100),
        "createdAt":       _fmt_dt(raw.get("createdAt")) or "",
        "updatedAt":       _fmt_dt(raw.get("updatedAt")),
        "enabled":         bool(raw.get("enabled", True)),
        "category":        raw.get("category") or "",
        "author":          raw.get("author") or "",
    }


# ---------------------------------------------------------------------------
# Automation normalizer
# ---------------------------------------------------------------------------

def normalize_automation(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes both Prisma DB record and legacy metadata dicts for Automation.
    Fixes:
      - status default "INACTIVE" → "DRAFT"  (Prisma AutomationStatus)
      - stepType action default "ALERT" → "CREATE_ALERT"
    """
    automation_id = raw.get("automationId") or raw.get("id") or ""
    name = raw.get("name") or ""
    automation_key = (
        raw.get("automationKey")
        or _pull_metadata(raw, "automationKey").get("automationKey")
        or (_md5(name) if name else automation_id)
    )

    # Status: map legacy "INACTIVE" → "DRAFT"
    raw_status = (raw.get("status") or "DRAFT").upper()
    if raw_status == "INACTIVE":
        raw_status = "DRAFT"

    raw_steps = raw.get("steps") or []
    if isinstance(raw_steps, str):
        try:
            raw_steps = json.loads(raw_steps)
        except Exception:
            raw_steps = []

    steps: List[Dict[str, Any]] = []
    for s in raw_steps:
        if not isinstance(s, dict):
            continue
        action = (s.get("action") or "CREATE_ALERT").upper()
        # legacy "ALERT" → "CREATE_ALERT"
        if action == "ALERT":
            action = "CREATE_ALERT"
        steps.append({
            "stepId":      s.get("stepId") or s.get("id") or "",
            "stepKey":     s.get("stepKey") or s.get("stepId") or "",
            "stepNumber":  s.get("stepNumber") or 1,
            "name":        s.get("name") or "",
            "description": s.get("description") or "",
            "action":      action,
            "parameters":  s.get("parameters") or {},
            "createdAt":   _fmt_dt(s.get("createdAt")) or "",
        })

    return {
        "automationId":    automation_id,
        "automationKey":   automation_key,
        "name":            name,
        "description":     raw.get("description") or "",
        "status":          raw_status,
        "trigger":         (raw.get("trigger") or "MANUAL").upper(),
        "projectId":       raw.get("projectId") or "",
        "investigationId": raw.get("investigationId") or "",
        "playbookId":      raw.get("playbookId") or "",
        "ruleId":          raw.get("ruleId") or "",
        "steps":           steps,
        "priority":        int(raw.get("priority") or 100),
        "createdAt":       _fmt_dt(raw.get("createdAt")) or "",
        "updatedAt":       _fmt_dt(raw.get("updatedAt")),
        "enabled":         bool(raw.get("enabled", True)),
        "category":        raw.get("category") or "",
        "author":          raw.get("author") or "",
    }


def normalize_automation_execution(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes AutomationExecution.
    Maps legacy "SUCCESS" status → "COMPLETED" (Prisma AutomationExecutionStatus).
    """
    status = (raw.get("status") or "COMPLETED").upper()
    if status == "SUCCESS":
        status = "COMPLETED"
    return {
        "executionId":  raw.get("executionId") or raw.get("id") or "",
        "automationId": raw.get("automationId") or "",
        "status":       status,
        "startedAt":    _fmt_dt(raw.get("startedAt")) or "",
        "completedAt":  _fmt_dt(raw.get("completedAt")) or "",
        "stepResults":  raw.get("stepResults") or [],
    }


# ---------------------------------------------------------------------------
# CaseFlow normalizer
# ---------------------------------------------------------------------------

def normalize_case_flow(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes both Prisma DB record and legacy metadata dicts for CaseFlow."""
    case_flow_id = raw.get("caseFlowId") or raw.get("id") or ""
    title = raw.get("title") or ""

    meta_extras = _pull_metadata(raw, "caseFlowKey", "caseNumber")
    case_flow_key = (
        raw.get("caseFlowKey")
        or meta_extras.get("caseFlowKey")
        or (_md5(title) if title else case_flow_id)
    )
    case_number = (
        raw.get("caseNumber")
        or meta_extras.get("caseNumber")
        or (f"CASE-{_md5(title)[:8].upper()}" if title else f"CASE-{case_flow_id[:8].upper()}")
    )

    raw_steps = raw.get("steps") or []
    if isinstance(raw_steps, str):
        try:
            raw_steps = json.loads(raw_steps)
        except Exception:
            raw_steps = []

    steps: List[Dict[str, Any]] = []
    for s in raw_steps:
        if not isinstance(s, dict):
            continue
        steps.append({
            "stepId":      s.get("stepId") or s.get("id") or "",
            "stepKey":     s.get("stepKey") or s.get("stepId") or "",
            "stepNumber":  s.get("stepNumber") or 1,
            "stepType":    (s.get("stepType") or "CREATED").upper(),
            "title":       s.get("title") or "",
            "description": s.get("description") or "",
            "assignedTo":  s.get("assignedTo") or "",
            "createdAt":   _fmt_dt(s.get("createdAt")) or "",
        })

    return {
        "caseFlowId":      case_flow_id,
        "caseFlowKey":     case_flow_key,
        "caseNumber":      case_number,
        "title":           title,
        "description":     raw.get("description") or "",
        "status":          (raw.get("status") or "OPEN").upper(),
        "priority":        (raw.get("priority") or "MEDIUM").upper(),
        "projectId":       raw.get("projectId") or "",
        "investigationId": raw.get("investigationId") or "",
        "playbookId":      raw.get("playbookId") or "",
        "automationId":    raw.get("automationId") or "",
        "steps":           steps,
        "findingIds":      _to_list(raw.get("findingIds")),
        "alertIds":        _to_list(raw.get("alertIds")),
        "evidenceIds":     _to_list(raw.get("evidenceIds")),
        "playbookIds":     _to_list(raw.get("playbookIds")),
        "assignedTo":      raw.get("assignedTo") or "",
        "owner":           raw.get("owner") or "",
        "confidence":      float(raw.get("confidence") or 100.0),
        "createdAt":       _fmt_dt(raw.get("createdAt")) or "",
        "updatedAt":       _fmt_dt(raw.get("updatedAt")),
    }


def normalize_case_flow_execution(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes CaseFlowExecution.
    Maps legacy "SUCCESS" status → "COMPLETED" (Prisma CaseExecutionStatus).
    """
    status = (raw.get("status") or "COMPLETED").upper()
    if status == "SUCCESS":
        status = "COMPLETED"
    return {
        "executionId": raw.get("executionId") or raw.get("id") or "",
        "caseFlowId":  raw.get("caseFlowId") or "",
        "status":      status,
        "startedAt":   _fmt_dt(raw.get("startedAt")) or "",
        "completedAt": _fmt_dt(raw.get("completedAt")) or "",
        "stepResults": raw.get("stepResults") or [],
    }
