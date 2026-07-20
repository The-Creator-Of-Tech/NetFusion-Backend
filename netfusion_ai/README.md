# NetFusion AI Investigation Assistant (`netfusion_ai`)

Production-Ready Enterprise SOC Analyst Copilot for NetFusion.

The `netfusion_ai` engine consumes structured multi-collector investigation telemetry and canonical workflow context to generate explainable, non-fabricating analytical outputs, hypotheses, risk assessments, MITRE ATT&CK inferences, recommendations, and multi-narrative security reports.

---

## 1. Core Architecture

The system is designed with strict separation of concerns, zero evidence mutation, and modular reasoning components:

- **`AIAssistant`**: Main top-level facade exposing unified SOC copilot API services.
- **`AIAnalysisEngine`**: Primary analytical orchestrator driving investigation summaries, correlation, and root cause analysis.
- **`PromptBuilder`**: Specialized security prompt engine supporting 11 SOC task templates.
- **`ContextBuilder`**: 15-source context aggregation and token budget manager.
- **`EvidenceSelector`**: Relevance scoring, integrity filtering, and evidence ranking engine.
- **`SafetyEngine`**: Non-fabrication guardrail and claim classifier (Facts, Inferences, Hypotheses, Recommendations).
- **`ConfidenceEngine`**: Multi-factor confidence metric breakdown.
- **`ExplanationEngine`**: Structured transparency generator for AI conclusions.
- **`MITREReasoner`**: ATT&CK tactic, technique, and sub-technique inference engine.
- **`HypothesisEngine`**: Competing hypothesis generation engine (never outputs single hypothesis under uncertainty).
- **`RiskEngine`**: Multi-dimensional risk score, impact, and priority calculator.
- **`RecommendationEngine`**: Categorized remediation advice engine (Containment, Eradication, Recovery, Monitoring, Further Investigation, Hardening).
- **`MemoryManager`**: Investigation-scoped conversation history, context, and cache store.
- **`ReportEngine`**: Multi-narrative report generator (Executive, Technical, Incident, Timeline, Evidence).
- **`ProviderAdapter`**: Provider registry, health monitor, and failover router.
- **`AIHealthChecker`**: Subsystem diagnostics engine.

---

## 2. Provider Abstraction

Supports six interchangeable LLM providers alongside a deterministic Mock provider via `BaseAIProvider`:

1. **OpenAI**: `OpenAIProvider` (GPT-4o, GPT-4 Turbo)
2. **Azure OpenAI**: `AzureOpenAIProvider` (Azure deployment endpoints)
3. **Anthropic Claude**: `AnthropicProvider` (Claude 3.5 Sonnet)
4. **Google Gemini**: `GeminiProvider` (Gemini 1.5 Pro)
5. **Groq Cloud**: `GroqProvider` (Groq LLaMA-3.3-70B acceleration)
6. **Local LLM (Ollama)**: `OllamaProvider` (Offline / Local LLaMA 3 execution)
7. **Mock Provider**: `MockAIProvider` (Deterministic offline unit testing)

### Failover Router
`ProviderAdapter` routes calls through healthy providers and automatically fails over if an API endpoint becomes unreachable or encounters rate limits.

---

## 3. Prompt System

`PromptBuilder` implements 11 security prompt templates with mandatory safety guardrails:

- `INCIDENT_SUMMARY`
- `THREAT_HUNTING`
- `IOC_ANALYSIS`
- `MITRE_ANALYSIS`
- `MALWARE_ANALYSIS`
- `EXECUTIVE_REPORT`
- `TECHNICAL_REPORT`
- `NEXT_INVESTIGATION_STEPS`
- `ROOT_CAUSE_ANALYSIS`
- `FALSE_POSITIVE_REVIEW`
- `CONTAINMENT_ADVICE`

---

## 4. Safety Principles

The AI Investigation Assistant enforces non-negotiable safety guardrails:
1. **Never Fabricates Evidence**: All mentioned file hashes, IPs, domains, and timestamps must exist within the input context.
2. **Never Invents IOC Values**: IOC statements are strictly ground-verified.
3. **Explicit Claim Categorization**: Every output line is classified into:
   - **FACT**: Grounded directly in verified telemetry.
   - **INFERENCE**: Logical deduction derived from facts.
   - **HYPOTHESIS**: Explanatory model requiring further validation steps.
   - **RECOMMENDATION**: Actionable remediation or investigation step.

---

## 5. Context Building (15 Sources)

`ContextBuilder` aggregates telemetry across all 15 investigation sources:
1. `Investigation` metadata
2. `Timeline` events
3. `Evidence` artifacts
4. `Canonical Objects` (IPAddress, NetworkFlow, HostDiscovered, etc.)
5. `IOC` records
6. `Threat Intelligence` enrichments
7. `Sysmon` host EVTX event logs
8. `Nmap` port scan discoveries
9. `TShark` network flow captures
10. `Tasks`
11. `Notes`
12. `Risk` assessments
13. `MITRE` mappings
14. `Configuration` settings
15. `Summary Metadata`

---

## 6. Memory Scoping

`MemoryManager` scopes all conversation turns, context containers, prompt caches, and AI responses per `investigation_id`. Memory isolation guarantees zero cross-investigation data leaks.

---

## 7. Python Usage Example

```python
from netfusion_ai import (
    AIAssistant,
    ContextBuilder,
    AnalysisCategory,
    MockAIProvider,
)
from netfusion_workflow import Investigation

# 1. Initialize Assistant with preferred provider
assistant = AIAssistant(provider=MockAIProvider())

# 2. Build Context Container
context_builder = ContextBuilder()
context = context_builder.build_context(
    investigation={"investigation_id": "INV-2026-001", "title": "Ransomware Intrusion", "severity": "HIGH"},
    timeline=[{"timestamp": "2026-07-20T10:00:00Z", "title": "PowerShell Execution", "summary": "sysmon eventid 1"}],
    iocs=[{"type": "ip", "value": "192.168.1.100", "confidence": "HIGH"}],
)

# 3. Analyze Investigation
result = assistant.analyze_investigation(context, category=AnalysisCategory.INCIDENT_SUMMARY)
print("Summary:", result.summary)
print("Confidence:", result.confidence.overall_score)

# 4. Generate Multi-Narrative Report
report = assistant.generate_report(context, title="Executive Incident Report")
print("Executive Summary:", report.executive_summary)
```
