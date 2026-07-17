import os
import uuid
import requests
import copy
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, date
from core.config import PRISMA_API_BASE_URL

def is_valid_uuid(val: str) -> bool:
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False

import dataclasses
try:
    from pydantic import BaseModel
except ImportError:
    BaseModel = None

def serialize_value(obj: Any) -> Any:
    if obj is None:
        return None
    # 1. Pydantic models
    if BaseModel and isinstance(obj, BaseModel):
        if hasattr(obj, "model_dump"):
            return serialize_value(obj.model_dump())
        else:
            return serialize_value(obj.dict())
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return serialize_value(obj.dict())
        except Exception:
            pass
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        try:
            return serialize_value(obj.to_dict())
        except Exception:
            pass
    # 2. Dataclasses
    if dataclasses.is_dataclass(obj):
        return serialize_value(dataclasses.asdict(obj))
    # 3. Standard dates and datetimes
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    # 4. Standard list, tuple, set
    if isinstance(obj, (list, tuple, set)):
        return [serialize_value(x) for x in obj]
    # 5. Standard dicts
    if isinstance(obj, dict):
        return {k: serialize_value(v) for k, v in obj.items()}
    # 6. Objects with __dict__ (custom classes like ProviderDefinition)
    if hasattr(obj, "__dict__"):
        # Exclude internal python attributes
        return {k: serialize_value(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    # 7. Basic types
    return obj

def call_repository(repo_name: str, method_name: str, *args) -> Any:
    print("CALL_REPOSITORY EXECUTED")
    url = f"{PRISMA_API_BASE_URL}/api/repository/{repo_name}/{method_name}"
    serialized_args = serialize_value(list(args))
    resp = requests.post(url, json={"args": serialized_args}, timeout=30)
    if resp.status_code >= 400:
        raise Exception(f"Repository call failed [repo: {repo_name}, method: {method_name}]: {resp.text}")
        
    return resp.json()
    
 
def ensure_uuid(val: Any) -> Any:
    if val is None or val == "":
        return None
    val_str = str(val)
    if is_valid_uuid(val_str):
        return val_str
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, val_str))

UNIQUE_FIELDS = {
    "provider": "providerName",
    "cve": "cveId",
    "ioc": "iocId",
    "mitre": "mitreId",
    "threatActor": "threatId",
    "threatCampaign": "campaignId"
}

class RepositoryBackedDict(dict):
    def __init__(self, repo_name: str, id_field: str, mapping_fn=None):
        self.repo_name = repo_name
        self.id_field = id_field
        self.mapping_fn = mapping_fn
        super().__init__()

    def _resolve_db_id(self, key: str, mapped_data: Optional[Dict] = None) -> str:
        unique_field = UNIQUE_FIELDS.get(self.repo_name)
        
        # 1. Prioritize looking up by unique field from mapped data if available
        if mapped_data and unique_field and unique_field in mapped_data:
            try:
                records = call_repository(self.repo_name, "findMany", {
                    "filter": {unique_field: mapped_data[unique_field]}
                })
                if records:
                    return records[0]["id"]
            except Exception:
                pass

        # 2. Then try to look up by unique field using key itself if key is not a UUID
        if not is_valid_uuid(key):
            if unique_field:
                try:
                    records = call_repository(self.repo_name, "findMany", {
                        "filter": {unique_field: key}
                    })
                    if records:
                        return records[0]["id"]
                except Exception:
                    pass

            # 3. Metadata fallback
            try:
                records = call_repository(self.repo_name, "findMany", {
                    "filter": {
                        "metadata": {
                            "path": [self.id_field],
                            "equals": key
                        }
                    }
                })
                if records:
                    return records[0]["id"]
            except Exception:
                pass

        # 4. Fallback to key if valid UUID, else generate a deterministic UUID
        return key if is_valid_uuid(key) else str(uuid.uuid5(uuid.NAMESPACE_DNS, str(key)))

    def _get_merged_record(self, record: Dict) -> Dict:
        meta = record.get("metadata")
        if isinstance(meta, dict):
            merged = copy.deepcopy(record)
            merged.update(meta)
            for field in ["steps", "artifacts", "executions"]:
                if field in record:
                    merged[field] = record[field]
            return merged
        else:
            return record

    def __getitem__(self, key: str) -> Any:
        db_id = self._resolve_db_id(key)
        try:
            record = call_repository(self.repo_name, "findById", db_id)
            if record:
                return self._get_merged_record(record)
        except Exception:
            pass
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key: str, value: Any) -> None:
        if not isinstance(value, dict):
            value = {"data": value}

        mapped = {}
        if self.mapping_fn:
            mapped = self.mapping_fn(value)

        db_id = self._resolve_db_id(key, mapped)

        # Do NOT duplicate steps, artifacts, or executions into metadata.
        meta_value = copy.deepcopy(value)
        for field in ["steps", "artifacts", "executions"]:
            if field in meta_value:
                del meta_value[field]

        input_data = {
            "id": db_id,
            "createdBy": "test-user",
            "updatedBy": "test-user",
            "metadata": meta_value
        }
        input_data.update(mapped)

        try:
            exists = call_repository(self.repo_name, "exists", {"id": db_id})
            if exists:
                call_repository(self.repo_name, "update", db_id, input_data)
            else:
                call_repository(self.repo_name, "create", input_data)
        except Exception as err:
            try:
                call_repository(self.repo_name, "create", input_data)
            except Exception:
                call_repository(self.repo_name, "update", db_id, input_data)

    def __delitem__(self, key: str) -> None:
        db_id = self._resolve_db_id(key)
        try:
            call_repository(self.repo_name, "delete", db_id)
        except Exception:
            pass

    def pop(self, key: str, default: Any = None) -> Any:
        try:
            val = self[key]
            del self[key]
            return val
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        if is_valid_uuid(key):
            try:
                return call_repository(self.repo_name, "exists", {"id": key})
            except Exception:
                return False

        unique_field = UNIQUE_FIELDS.get(self.repo_name)
        if unique_field:
            try:
                count = call_repository(self.repo_name, "count", {
                    unique_field: key
                })
                if count > 0:
                    return True
            except Exception:
                pass

        try:
            count = call_repository(self.repo_name, "count", {
                "metadata": {
                    "path": [self.id_field],
                    "equals": key
                }
            })
            return count > 0
        except Exception:
            return False

    def clear(self) -> None:
        try:
            records = call_repository(self.repo_name, "findMany", {"filter": {}})
            for r in records:
                try:
                    call_repository(self.repo_name, "delete", r["id"])
                except Exception:
                    pass
        except Exception as e:
            # Safely log using repr to prevent unicode encode errors in Windows terminal
            print(f"Clear failed for {self.repo_name}: {repr(e)}")

    def values(self) -> List[Any]:
        try:
            records = call_repository(self.repo_name, "findMany", {"filter": {"deletedAt": None}})
            results: List[Any] = []
            for r in records:
                results.append(self._get_merged_record(r))
            return results
        except Exception:
            return []

    def keys(self) -> List[str]:
        try:
            records = call_repository(self.repo_name, "findMany", {"filter": {"deletedAt": None}})
            keys_list: List[str] = []
            for r in records:
                merged = self._get_merged_record(r)
                keys_list.append(merged.get(self.id_field) or merged.get("id"))
            return keys_list
        except Exception:
            return []

    def items(self) -> List[Tuple[str, Any]]:
        try:
            records = call_repository(self.repo_name, "findMany", {"filter": {"deletedAt": None}})
            items_list = []
            for r in records:
                merged = self._get_merged_record(r)
                key = merged.get(self.id_field) or merged.get("id")
                items_list.append((key, merged))
            return items_list
        except Exception:
            return []

    def __len__(self) -> int:
        try:
            return call_repository(self.repo_name, "count", {"deletedAt": None})
        except Exception:
            return 0

    def __iter__(self):
        return iter(self.keys())

class CaseFlowExecutionsStore(dict):
    def clear(self):
        try:
            call_repository("caseFlowExecution", "deleteMany", {"where": {}})
        except Exception:
            pass

    def get(self, case_id: str, default: Any = None) -> List[Dict[str, Any]]:
        try:
            records = call_repository("caseFlowExecution", "findMany", {
                "where": {"caseFlowId": ensure_uuid(case_id)}
            })
            mapped = []
            for r in records:
                mapped.append({
                    "executionId": r["id"],
                    "caseFlowId": r["caseFlowId"],
                    "status": r["status"],
                    "startedAt": r["startedAt"],
                    "completedAt": r["completedAt"],
                    "stepResults": r["stepResults"]
                })
            return mapped
        except Exception:
            return default if default is not None else []

    def setdefault(self, case_id: str, default: Any = None) -> Any:
        class AppendProxyList(list):
            def __init__(self, case_id, items):
                self.case_id = case_id
                super().__init__(items)

            def append(self, item):
                super().append(item)
                db_id = item.get("executionId") or item.get("id") or str(uuid.uuid4())
                try:
                    call_repository("caseFlowExecution", "create", {
                        "data": {
                            "id": ensure_uuid(db_id),
                            "caseFlowId": ensure_uuid(self.case_id),
                            "status": item.get("status") or "PENDING",
                            "startedAt": item.get("startedAt") or datetime.utcnow().isoformat() + "Z",
                            "completedAt": item.get("completedAt"),
                            "stepResults": item.get("stepResults") or []
                        }
                    })
                except Exception as err:
                    print("Error creating case flow execution:", err)
        
        return AppendProxyList(case_id, self.get(case_id))

    def __delitem__(self, case_id: str) -> None:
        try:
            call_repository("caseFlowExecution", "deleteMany", {
                "where": {"caseFlowId": ensure_uuid(case_id)}
            })
        except Exception:
            pass

    def __contains__(self, case_id: str) -> bool:
        try:
            count = call_repository("caseFlowExecution", "count", {
                "where": {"caseFlowId": ensure_uuid(case_id)}
            })
            return count > 0
        except Exception:
            return False

class AutomationExecutionsStore(dict):
    def clear(self):
        try:
            call_repository("automationExecution", "deleteMany", {"where": {}})
        except Exception:
            pass

    def get(self, automation_id: str, default: Any = None) -> List[Dict[str, Any]]:
        try:
            records = call_repository("automationExecution", "findMany", {
                "where": {"automationId": ensure_uuid(automation_id)}
            })
            mapped = []
            for r in records:
                mapped.append({
                    "executionId": r["id"],
                    "automationId": r["automationId"],
                    "status": r["status"],
                    "startedAt": r["startedAt"],
                    "completedAt": r["completedAt"],
                    "stepResults": r["stepResults"]
                })
            return mapped
        except Exception:
            return default if default is not None else []

    def setdefault(self, automation_id: str, default: Any = None) -> Any:
        class AppendProxyList(list):
            def __init__(self, automation_id, items):
                self.automation_id = automation_id
                super().__init__(items)

            def append(self, item):
                super().append(item)
                db_id = item.get("executionId") or item.get("id") or str(uuid.uuid4())
                try:
                    call_repository("automationExecution", "create", {
                        "data": {
                            "id": ensure_uuid(db_id),
                            "automationId": ensure_uuid(self.automation_id),
                            "status": item.get("status") or "PENDING",
                            "startedAt": item.get("startedAt") or datetime.utcnow().isoformat() + "Z",
                            "completedAt": item.get("completedAt"),
                            "stepResults": item.get("stepResults") or []
                        }
                    })
                except Exception as err:
                    print("Error creating automation execution:", err)
        
        return AppendProxyList(automation_id, self.get(automation_id))

    def __delitem__(self, automation_id: str) -> None:
        try:
            call_repository("automationExecution", "deleteMany", {
                "where": {"automationId": ensure_uuid(automation_id)}
            })
        except Exception:
            pass

    def __contains__(self, automation_id: str) -> bool:
        try:
            count = call_repository("automationExecution", "count", {
                "where": {"automationId": ensure_uuid(automation_id)}
            })
            return count > 0
        except Exception:
            return False

class WorkflowExecutionsStore(dict):
    """Persistence store for WorkflowExecution records keyed by executionId."""

    def clear(self):
        try:
            call_repository("workflowExecution", "deleteMany", {"where": {}})
        except Exception:
            pass

    def get_by_id(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single execution record by its executionId."""
        try:
            db_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, execution_id)) if not is_valid_uuid(execution_id) else execution_id
            records = call_repository("workflowExecution", "findMany", {
                "filter": {"id": db_id}
            })
            if records:
                r = records[0]
                return self._map_record(r)
            return None
        except Exception:
            return None

    def get_by_playbook(self, playbook_id: str) -> List[Dict[str, Any]]:
        """Fetch all executions for a given playbook."""
        try:
            records = call_repository("workflowExecution", "findMany", {
                "filter": {"playbookId": ensure_uuid(playbook_id)}
            })
            return [self._map_record(r) for r in records]
        except Exception:
            return []

    def get_all(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all executions, optionally filtered by project ID."""
        try:
            filt = {}
            if project_id:
                filt = {"playbook": {"projectId": ensure_uuid(project_id)}}
            records = call_repository("workflowExecution", "findMany", {
                "filter": filt
            })
            return [self._map_record(r) for r in records]
        except Exception:
            return []

    def create(self, execution: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new WorkflowExecution record."""
        execution_id = execution.get("executionId") or str(uuid.uuid4())
        db_id = ensure_uuid(execution_id)
        playbook_id = ensure_uuid(execution.get("playbookId", ""))
        payload = {
            "id": db_id,
            "playbookId": playbook_id,
            "status": execution.get("status", "QUEUED"),
            "progress": int(execution.get("progress", 0)),
            "logs": execution.get("logs", []),
            "startedAt": execution.get("startedAt") or datetime.utcnow().isoformat() + "Z",
            "finishedAt": execution.get("finishedAt"),
            "triggeredBy": execution.get("triggeredBy"),
            "totalSteps": int(execution.get("totalSteps", 0)),
            "completedSteps": int(execution.get("completedSteps", 0)),
            "failedSteps": int(execution.get("failedSteps", 0)),
            "currentStep": execution.get("currentStep"),
            "stepResults": execution.get("stepResults"),
            "createdBy": execution.get("createdBy", "system"),
            "updatedBy": execution.get("updatedBy", "system"),
            "metadata": execution.get("metadata"),
        }
        try:
            call_repository("workflowExecution", "create", {"data": payload})
        except Exception as err:
            safe_err = str(err).encode('ascii', errors='replace').decode('ascii')
            print("Error creating workflow execution:", safe_err)
            raise
        return {"executionId": db_id, **execution}

    def update(self, execution_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing WorkflowExecution record by its executionId."""
        db_id = ensure_uuid(execution_id)
        try:
            # Build minimal update payload — never mutate playbookId/createdAt
            update_data: Dict[str, Any] = {"updatedBy": "system"}
            for field in ("status", "progress", "logs", "finishedAt",
                          "completedSteps", "failedSteps", "currentStep", "stepResults", "metadata"):
                if field in updates:
                    update_data[field] = updates[field]
            call_repository("workflowExecution", "update", db_id, update_data)
            return True
        except Exception as err:
            safe_err = str(err).encode('ascii', errors='replace').decode('ascii')
            print("Error updating workflow execution:", safe_err)
            return False

    @staticmethod
    def _map_record(r: Dict[str, Any]) -> Dict[str, Any]:
        meta = r.get("metadata")
        if isinstance(meta, dict) and "executionId" in meta:
            meta.setdefault("id", meta.get("executionId"))
            meta.setdefault("refId", meta.get("playbookId"))
            meta.setdefault("name", meta.get("playbookName", "Playbook Execution"))
            meta.setdefault("type", "playbook")
            meta.setdefault("completedAt", meta.get("finishedAt"))
            return meta
        return {
            "id": r.get("id"),
            "name": "Playbook Execution",
            "type": "playbook",
            "refId": r.get("playbookId"),
            "completedAt": r.get("finishedAt"),
            
            "executionId": r.get("id"),
            "playbookId": r.get("playbookId"),
            "status": r.get("status", "QUEUED"),
            "progress": r.get("progress", 0),
            "logs": r.get("logs") or [],
            "startedAt": r.get("startedAt"),
            "finishedAt": r.get("finishedAt"),
            "triggeredBy": r.get("triggeredBy"),
            "totalSteps": r.get("totalSteps", 0),
            "completedSteps": r.get("completedSteps", 0),
            "failedSteps": r.get("failedSteps", 0),
            "currentStep": r.get("currentStep"),
            "stepResults": r.get("stepResults"),
        }

# Mapping functions for standard database columns
def map_playbook(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId")) if v.get("investigationId") else None,
        "name": v.get("name") or "Unnamed Playbook",
        "description": v.get("description") or "",
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "status": (v.get("status") or "DRAFT").upper(),
        "confidence": float(v.get("confidence") if v.get("confidence") is not None else 100.0),
        "enabled": bool(v.get("enabled", True)),
        "priority": int(v.get("priority") or 1),
        "category": v.get("category") or "",
        "author": v.get("author") or "",
        "steps": v.get("steps") or []
    }

def map_rule(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "name": v.get("name") or "Unnamed Rule",
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "status": (v.get("status") or "DRAFT").upper()
    }

def map_automation(v):
    # status: map legacy "INACTIVE" → "DRAFT" to match Prisma AutomationStatus enum
    raw_status = (v.get("status") or "DRAFT").upper()
    if raw_status == "INACTIVE":
        raw_status = "DRAFT"
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "name":      v.get("name") or "Unnamed Automation",
        "trigger":   (v.get("trigger") or "MANUAL").upper(),
        "status":    raw_status,
    }

def map_case_flow(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "title": v.get("title") or "Unnamed Case",
        "status": (v.get("status") or "OPEN").upper(),
        "priority": (v.get("priority") or "MEDIUM").upper()
    }

def map_workflow_execution(v):
    return {
        "playbookId": ensure_uuid(v.get("playbookId") or ""),
        "status": (v.get("status") or "RUNNING").upper(),
        "progress": int(v.get("progress") or 0),
    }

def map_threat_actor(v):
    return {
        "threatId": v.get("threatId") or v.get("id") or "APT_UNKNOWN",
        "name": v.get("name") or "Unnamed Actor",
        "confidence": v.get("confidence") or "MEDIUM",
        "severity": (v.get("severity") or v.get("threatLevel") or "MEDIUM").upper(),
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_threat_campaign(v):
    return {
        "campaignId": v.get("campaignId") or v.get("id") or "CAMP_UNKNOWN",
        "name": v.get("name") or "Unnamed Campaign",
        "confidence": v.get("confidence") or "MEDIUM",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_mitre_technique(v):
    return {
        "mitreId": v.get("mitreId") or v.get("id") or "T_UNKNOWN",
        "name": v.get("name") or "Unnamed Technique"
    }

def map_ioc(v):
    return {
        "iocId": v.get("iocId") or v.get("id") or "IOC_UNKNOWN",
        "value": v.get("value") or "unknown",
        "iocType": (v.get("iocType") or v.get("type") or "IP").upper(),
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "status": (v.get("status") or "ACTIVE").upper(),
        "confidence": v.get("confidence") or "MEDIUM"
    }

def map_cve(v):
    return {
        "cveId": v.get("cveId") or v.get("id") or "CVE_UNKNOWN",
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "cvssScore": float(v.get("cvssScore") or v.get("baseScore") or 0.0)
    }

def map_timeline_event(v):
    t_type = (v.get("type") or "OBSERVED").upper()
    valid_types = {
        "OBSERVED", "IDENTITY_MATCH", "IDENTITY_CREATED", "RELATIONSHIP_CREATED",
        "RELATIONSHIP_UPDATED", "EVIDENCE_ADDED", "HISTORY_CREATED", "ALERT_GENERATED",
        "FINDING_CREATED", "MITRE_MAPPED", "ATTACK_PATTERN", "ATTACK_CHAIN",
        "BLAST_RADIUS", "LATERAL_MOVEMENT", "PIVOT", "CHOKE_POINT", "MANUAL_ACTION"
    }
    if t_type not in valid_types:
        t_type = "HISTORY_CREATED"
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9a001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "title": v.get("title") or "Unnamed Event",
        "type": t_type,
        "eventTimestamp": v.get("eventTimestamp") or v.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    }

def map_finding(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "assetId": ensure_uuid(v.get("assetId")) if v.get("assetId") else None,
        "title": v.get("title") or "Unnamed Finding",
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "status": (v.get("status") or "OPEN").upper()
    }

def map_evidence(v):
    source_obj = v.get("source") or {}
    source_type = source_obj.get("sourceType") or v.get("sourceType") or "UNKNOWN"
    confidence_val = v.get("confidence") or source_obj.get("confidence") or 100
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "assetId": ensure_uuid(v.get("assetId")) if v.get("assetId") else None,
        "fieldName": v.get("fieldName") or "payload",
        "fieldValue": v.get("fieldValue") or "unknown",
        "sourceType": source_type,
        "type": (v.get("type") or "PACKET").upper(),
        "confidence": int(confidence_val)
    }

def map_asset(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "macAddress": v.get("macAddress") or v.get("mac_address"),
        "hostname": v.get("hostname"),
        "deviceName": v.get("deviceName") or v.get("device_name") or v.get("name"),
        "vendor": v.get("vendor"),
        "operatingSystem": v.get("operatingSystem") or v.get("os") or v.get("operating_system"),
        "currentIp": v.get("currentIp") or v.get("ipAddress") or v.get("current_ip"),
        "currentStatus": v.get("currentStatus") or v.get("status") or "ACTIVE",
        "type": (v.get("type") or v.get("deviceType") or "UNKNOWN").upper(),
        "riskScore": float(v.get("riskScore") or v.get("risk_score") or 0.0),
        "confidence": float(v.get("confidence") or 100.0)
    }

def map_alert(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "title": v.get("title") or "Unnamed Alert",
        "severity": (v.get("severity") or "MEDIUM").upper(),
        "status": (v.get("status") or "OPEN").upper()
    }

def map_streaming(v):
    return {
        "executionId": ensure_uuid(v.get("executionId")) if v.get("executionId") else None,
        "status": (v.get("status") or "ACTIVE").upper(),
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user"
    }

def map_session_memory(v):
    return {
        "conversationId": ensure_uuid(v.get("conversationId")) if v.get("conversationId") else None,
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_reasoning(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_provider(v):
    return {
        "providerName": v.get("providerName") or v.get("providerId") or v.get("id") or "UNKNOWN_PROV",
        "displayName": v.get("displayName") or "Unnamed Provider",
        "apiVersion": v.get("apiVersion") or "v1",
        "endpoint": v.get("endpoint") or "http://localhost",
        "defaultModel": v.get("defaultModel") or "unknown",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_prompt_assembly(v):
    return {
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user",
        "systemPrompt": v.get("systemPrompt") or "system",
        "userPrompt": v.get("userPrompt") or "user",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_execution(v):
    return {
        "providerId": ensure_uuid(v.get("providerId")) if v.get("providerId") else None,
        "systemPrompt": v.get("systemPrompt") or "system",
        "userPrompt": v.get("userPrompt") or "user",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_conversation(v):
    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user",
        "title": v.get("title") or "Unnamed Conversation",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_context_window(v):
    return {
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "userId": ensure_uuid(v.get("userId")) if v.get("userId") else "test-user",
        "status": (v.get("status") or "ACTIVE").upper()
    }

def map_copilot_session(v):
    return map_session_memory(v)

def map_attack_graph_node(v):
    return {
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "label": v.get("label") or v.get("name") or "Unnamed Node",
        "type": (v.get("type") or "ASSET").upper()
    }

def map_attack_graph_edge(v):
    return {
        "investigationId": ensure_uuid(v.get("investigationId") or "2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101"),
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "sourceNodeId": ensure_uuid(v.get("sourceNodeId") or v.get("sourceId") or "node-1"),
        "targetNodeId": ensure_uuid(v.get("targetNodeId") or v.get("targetId") or "node-2"),
        "relationshipType": v.get("relationshipType") or "communicates_with"
    }

def map_investigation(v):
    status = (v.get("status") or "OPEN").upper()
    status_mapping = {
        "COMPLETED": "CLOSED",
        "ACTIVE": "IN_PROGRESS",
        "PAUSED": "PENDING_REVIEW"
    }
    status = status_mapping.get(status, status)
    if status not in ("OPEN", "IN_PROGRESS", "PENDING_REVIEW", "RESOLVED", "CLOSED", "ARCHIVED"):
        status = "OPEN"
    
    prio = v.get("priority") or 2
    if isinstance(prio, str):
        mapping = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
        prio = mapping.get(prio.upper(), 2)
    elif prio is not None:
        try:
            prio = int(prio)
        except ValueError:
            prio = 2
    else:
        prio = 2

    return {
        "projectId": ensure_uuid(v.get("projectId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001"),
        "ownerId": ensure_uuid(v.get("ownerId") or "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e999"),
        "title": v.get("title") or "Unnamed Investigation",
        "description": v.get("description") or "",
        "status": status,
        "priority": prio,
        "tags": list(v.get("tags") or [])
    }

