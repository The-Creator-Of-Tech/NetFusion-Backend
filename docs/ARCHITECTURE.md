# NetFusion Platform Architecture Guide & ADRs

## Status: v1.0.0-rc1 Architecture Freeze (STABLE)

> [!IMPORTANT]
> **ARCHITECTURE FREEZE MANDATE**: As of Phase v1.0 RC1 release, all core modules (`netfusion_canonical`, `netfusion_collector_sdk`, `netfusion_collectors`, `netfusion_workflow`, `netfusion_ai`, `netfusion_platform`) are declared **STABLE**. No public API changes, database schema redesigns, or canonical object redesigns are permitted.

---

## Overview
NetFusion is an enterprise-grade, unified cyber investigation platform designed for Security Operations Centers (SOC). It correlates multi-collector telemetry (Sysmon, TShark, Nmap, Threat Intelligence) through a canonical data model, workflow case engine, AI investigation assistant, and multi-section report generator.

---

## System Component Architecture

```
+-----------------------------------------------------------------------+
|                         NetFusion Platform                            |
+-----------------------------------------------------------------------+
|                                                                       |
|  Collectors:      [ Sysmon ]  [ TShark ]  [ Nmap ]  [ Threat Intel ]   |
|                      |           |           |             |          |
|                      v           v           v             v          |
|  Canonical Engine: [ Universal Canonical Object & Normalization ]     |
|                      |                                                |
|                      v                                                |
|  Event Bus:        [ EventPublisher & DeadLetterQueue ]               |
|                      |                                                |
|                      v                                                |
|  Workflow Service: [ Case Management, Timelines, Evidence, Audit Log ] |
|                      |                                                |
|                      v                                                |
|  AI Assistant:     [ ContextBuilder -> AI Analysis & MITRE Reasoner ] |
|                      |                                                |
|                      v                                                |
|  Reporting Engine: [ Multi-Section Executive & Technical Reports ]    |
|                                                                       |
+-----------------------------------------------------------------------+
```

---

## Architectural Principles
1. **Open/Closed Integration**: Core SDKs and canonical data models are frozen and extended only via non-invasive integration bridges.
2. **Zero-Log Secret Leakage**: `SecretLogMasker` dynamically sanitizes logs against registered API keys and credentials.
3. **Resilient Operation**: Stateful Circuit Breakers (`CLOSED`, `OPEN`, `HALF_OPEN`), exponential backoff retries, and bounded queue load-shedding protect third-party dependencies.
4. **Deterministic Validation**: All collector event streams undergo schema validation before reaching the event bus or storage layers.

---

## Architectural Decision Records (ADRs)

### ADR-001: Monolithic Agent Framework with Decoupled Micro-Modules
- **Context**: Cyber investigation workflows require zero-dependency offline capabilities combined with cloud AI capabilities.
- **Decision**: Adopt a modular Python architecture (`netfusion_*`) with strict domain boundaries and unified FastAPI presentation layer.
- **Status**: Accepted & Implemented.

### ADR-002: Universal Canonical Data Model (CDM)
- **Context**: Heterogeneous collectors (Sysmon EVTX, TShark PCAP, Nmap XML, Threat Intel APIs) emit disjoint schema objects.
- **Decision**: Standardize all ingestion outputs into `CanonicalEvent`, `CanonicalHost`, `CanonicalNetworkFlow`, and `CanonicalThreatIndicator`.
- **Status**: Accepted & Frozen.

### ADR-003: Multi-Provider AI Copilot with Strict Guardrails
- **Context**: Enterprise deployments require flexibility across OpenAI, Anthropic, Gemini, Groq, Ollama, and offline mock providers.
- **Decision**: Implement `AIAssistant` facade wrapping adapter pattern with `SafetyEngine` enforcing strict non-fabrication constraints.
- **Status**: Accepted & Implemented.

### ADR-004: Evidence Custody & Immutable Hashing
- **Context**: Digital forensics requires verifiable chain of custody for legal and compliance audits.
- **Decision**: Calculate SHA-256 hashes on evidence ingestion and record all custody handoffs in an append-only audit trail.
- **Status**: Accepted & Implemented.
