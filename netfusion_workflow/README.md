# NetFusion Investigation Workflow & Case Management Module

Enterprise-grade Investigation Workflow & Case Management module for the NetFusion platform (`netfusion_workflow`). Governs security operations center (SOC) case lifecycles, task management, evidence chain of custody, automated timeline building, risk scoring, audit trail recording, cross-domain search, and reporting metadata generation.

---

## Architecture

The workflow engine is designed as a decoupled enterprise service layer that integrates seamlessly with frozen NetFusion components (`InvestigationContext`, `Runtime SDK`, `Collector Event Bus`, `Canonical Data Model`, and Ingestion Collectors):

```
+-------------------------------------------------------------------------+
|                         WorkflowService API                              |
+-------------+---------------+-------------+--------------+--------------+
              |               |             |              |
+-------------v----+   +------v------+  +---v-------+  +---v----------+
|  LifecycleEngine |   | Evidence    |  | Timeline  |  | SearchEngine |
|  State Machine   |   | Manager     |  | Engine    |  | Cross-Domain |
+------------------+   +-------------+  +-----------+  +--------------+
              |               |             |              |
+-------------v---------------+-------------v--------------v--------------+
|                  18 Canonical Domain Objects                             |
| (Case, Investigation, Task, Evidence, TimelineEvent, AnalystNote, etc.)  |
+-------------------------------------------------------------------------+
              |                                            |
+-------------v------------------+         +---------------+--------------+
| AuditLogger (Append-Only)      |         | WorkflowEventPublisher       |
+--------------------------------+         +------------------------------+
```

---

## Domain Model (18 Entities)

| Entity | Description |
|---|---|
| **Case** | Top-level incident container holding one or more linked investigations. |
| **Investigation** | Primary investigation entity containing findings, verdict, timeline, tasks, and evidence. |
| **Task** | Actionable SOC task supporting assignees, due dates, dependencies, and completion status. |
| **Evidence** | Artifact encapsulation linking canonical data objects, raw files, PCAPs, EVTXs, scans, and hashes. |
| **TimelineEvent** | Chronological event entry in an investigation timeline. |
| **AnalystNote** | Rich text & markdown note supporting IOC/MITRE references, @mentions, and versioning. |
| **Comment** | Discussion item on tasks, evidence, or notes. |
| **Assignment** | Governs owner, multi-analyst assignees, reviewer, manager, and escalations. |
| **Tag** | Multi-category tag (Asset, Evidence, Case, User, Threat Actor, Campaign, Malware, MITRE, Custom). |
| **Attachment** | Media or document file attachment. |
| **Recommendation** | Actionable remediation or mitigation recommendation. |
| **ReportReference** | Snapshot link to generated executive or technical reports. |
| **MITREMapping** | Explicit mapping to MITRE ATT&CK tactics, techniques, and sub-techniques. |
| **RiskAssessment** | Quantitative score calculation (0-100), confidence rating, impact, likelihood, and affected systems. |
| **Approval** | Multi-tier approval request tracking with reviewer comments. |
| **Bookmark** | Quick analyst shortcut to evidence, timeline events, or notes. |
| **Notification** | Notification alert triggered by assignment, escalation, or status change. |
| **AuditRecord** | Immutable audit log record capturing every system operation and user action. |

---

## Case Lifecycle (11 States)

Investigations and Cases transition deterministically across 11 states:

1. `NEW`
2. `TRIAGED`
3. `IN_PROGRESS`
4. `WAITING_FOR_INFORMATION`
5. `ESCALATED`
6. `CONTAINMENT`
7. `ERADICATION`
8. `RECOVERY`
9. `VALIDATION`
10. `CLOSED`
11. `FALSE_POSITIVE`

State transitions are governed by `LifecycleEngine` and validated against allowed transition paths. Closing an investigation requires a final verdict and root cause summary.

---

## Timeline Engine

The `TimelineEngine` automatically ingests events from:
- Collector events (`TShark`, `Nmap`, `Sysmon`, `Threat Intelligence`)
- Canonical domain objects
- Analyst Notes
- Tasks
- Evidence additions
- Lifecycle status transitions
- AI Assistant findings
- Manual analyst entries

Features:
- **Sorting**: Ascending / Descending by timestamp.
- **Filtering**: By event type, source, severity, actor, tags, time range.
- **Grouping**: By event type, source, actor, severity, or date.
- **Search**: Keyword search across summaries, descriptions, and raw payloads.

---

## Evidence Management & Chain of Custody

All digital evidence items support:
- Multi-hash integrity calculation (SHA256, MD5, SHA1).
- Append-only Chain of Custody logging (Timestamp, Actor, Action, Location, Notes).
- Verification via `EvidenceManager.verify_integrity(evidence)`.
- References to canonical data objects, raw byte/file payloads, PCAPs, EVTX logs, Nmap XML scans, and Threat Intel IOCs.

---

## Code Examples

### Initializing Service & Creating an Investigation

```python
from netfusion_workflow import (
    WorkflowService,
    Priority,
    Severity,
    CaseLifecycle,
    EvidenceSource,
)

# Initialize service facade
service = WorkflowService()

# Create a Case and Investigation
case = service.create_case(
    title="Phishing Campaign - Financial Ops",
    priority=Priority.HIGH,
    severity=Severity.HIGH,
    owner="analyst_jane",
)

inv = service.create_investigation(
    title="Malicious Attachment Execution",
    case_id=case.case_id,
    priority=Priority.HIGH,
    severity=Severity.HIGH,
    owner="analyst_jane",
    affected_assets=["10.0.4.15", "FIN-WORKSTATION-01"],
    affected_users=["user_bob@company.com"],
)

# Transition lifecycle to IN_PROGRESS
service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="analyst_jane")
```

### Adding Evidence & Chain of Custody

```python
# Ingest PCAP artifact evidence
evidence = service.add_evidence(
    investigation_id=inv.investigation_id,
    name="Suspicious PCAP Capture",
    description="Network capture containing C2 callback traffic",
    source=EvidenceSource.TSHARK,
    raw_artifact=b"PCAP_BINARY_STREAM_DATA...",
    actor="tshark_collector",
)

# Verify integrity
from netfusion_workflow import EvidenceManager
EvidenceManager.verify_integrity(evidence)
```

### Adding Tasks with Dependencies

```python
task1 = service.create_task(
    investigation_id=inv.investigation_id,
    title="Isolate Host FIN-WORKSTATION-01",
    assignee="analyst_john",
    priority=Priority.CRITICAL,
)

task2 = service.create_task(
    investigation_id=inv.investigation_id,
    title="Perform Memory Acquisition",
    assignee="analyst_john",
    priority=Priority.HIGH,
    dependencies=[task1.task_id],
)

# Complete task 1
service.update_task_status(inv.investigation_id, task1.task_id, TaskStatus.COMPLETED, actor="analyst_john")
```

---

## Configuration & Integration

Module configuration is zero-setup for in-memory operation and integrates natively with `CollectorContext` from `netfusion_collector_sdk` and canonical events from `netfusion_canonical`.

---

## Enterprise Best Practices

- **Strict Auditability**: Every operation generates an immutable `AuditRecord`.
- **Integrity First**: Checksums are computed at ingestion time and validated prior to report compilation.
- **Fail-Safe Transitions**: Invalid state transitions raise `InvalidLifecycleTransitionError`.
