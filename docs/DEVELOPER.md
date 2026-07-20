# NetFusion Developer Guide & API Reference

## Overview
This document serves as the authoritative developer reference for extending, testing, and integrating with NetFusion Phase v1.0 RC1.

---

## Repository Structure

```
NetFusion-Agent/
├── api/                    # FastAPI REST controllers & OpenAPI request/response models
├── core/                   # Platform security, path protection, secret masking, logging
├── identity/               # Auth (JWT, API keys) and RBAC authorization engine
├── netfusion_ai/           # AI Assistant copilot, MITRE reasoner, prompt & report engines
├── netfusion_canonical/    # Canonical Data Model (CDM) and validation pipeline
├── netfusion_collector_sdk/# BaseCollector & collector runtime execution engine
├── netfusion_collectors/   # Implemented collectors (Sysmon, TShark, Nmap, Threat Intel)
├── netfusion_platform/    # Platform orchestrator, observability, circuit breaker
├── netfusion_workflow/    # Case management, timeline engine, evidence custody, audit log
├── parsers/                # Log and packet parsers
├── services/               # Workflow, investigation, and execution services
├── tests/                  # Unit, integration, real-world, and performance test suites
└── docs/                   # Platform documentation
```

---

## Developer Setup & Workflow

### 1. Virtual Environment Initialization
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/macOS
source venv/bin/activate
```

### 2. Running Test Suites
```bash
# Execute unit and integration tests
python -m pytest -v

# Run real-world investigation validation tests
python -m pytest tests/test_real_world_investigations.py -v

# Run performance and security benchmarks
python -m pytest tests/test_performance_and_security.py -v
```

---

## REST API Reference

### 1. Workflow & Case Management

#### `POST /api/v2/workflow/cases`
Creates a new security incident case.
- **Request Body**:
  ```json
  {
    "title": "Suspicious RDP Login Campaign",
    "summary": "Multiple failed logins followed by successful RDP session",
    "priority": "HIGH",
    "severity": "HIGH",
    "owner": "soc_analyst_1"
  }
  ```
- **Response `201 Created`**:
  ```json
  {
    "success": true,
    "data": {
      "case_id": "CASE-104928",
      "status": "NEW",
      "created_at": "2026-07-20T10:00:00Z"
    }
  }
  ```

#### `POST /api/v2/workflow/investigations`
Creates an investigation attached to a case.

#### `POST /api/v2/workflow/playbooks/{playbook_id}/execute`
Triggers automated playbook execution.

---

### 2. AI Investigation Assistant

#### `POST /ai/detective`
Interrogates the AI Assistant regarding a specific investigation session context.
- **Request Body**:
  ```json
  {
    "projectId": "6a40c592-1873-4a60-afb7-57abdb51a9d2",
    "question": "Summarize key MITRE ATT&CK techniques identified"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "answer": "Identified T1566.002 (Spearphishing Link) and T1486 (Data Encrypted for Impact).",
    "confidence": 0.92,
    "sources": ["phishing_email.eml", "sysmon_vss_deletion.evtx"]
  }
  ```

---

## Extension Guidelines

> [!CAUTION]
> **Architecture Freeze**: Core interfaces in `netfusion_canonical`, `netfusion_collector_sdk`, and `netfusion_workflow` are frozen. To extend functionality, subclass `BaseCollector` or register custom provider adapters in `netfusion_ai/providers/`.
