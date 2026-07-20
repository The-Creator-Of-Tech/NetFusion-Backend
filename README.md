# NetFusion Cyber Investigation Platform (v1.0 RC1)

[![CI Build](https://github.com/netfusion/netfusion-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/netfusion/netfusion-agent/actions/workflows/ci.yml)
[![Release v1.0.0-rc1](https://img.shields.io/badge/release-v1.0.0--rc1-blue.svg)](https://github.com/netfusion/netfusion-agent/releases/tag/v1.0.0-rc1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Audited](https://img.shields.io/badge/security-audited-brightgreen.svg)](SECURITY.md)

NetFusion is an enterprise-grade, unified cyber investigation platform designed for Security Operations Centers (SOC). It correlates multi-collector telemetry (Sysmon, TShark, Nmap, Threat Intelligence) through a canonical data model, workflow case engine, AI investigation assistant, and multi-section report generator.

---

## Key Features

- **Multi-Collector Telemetry Ingestion**: Live & offline ingestion for Sysmon EVTX, TShark PCAP, Nmap XML scans, and Threat Intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus).
- **Universal Canonical Data Model (CDM)**: Strict validation pipeline mapping raw logs to normalized `CanonicalEvent`, `CanonicalHost`, `CanonicalNetworkFlow`, and `CanonicalThreatIndicator` objects.
- **Workflow & Case Management Engine**: Complete lifecycle engine (New, Triaged, In Progress, Containment, Eradication, Recovery, Validation, Closed) with evidence chain of custody and immutable SHA-256 hashing.
- **AI Investigation Assistant**: Multi-provider LLM copilot (OpenAI, Azure OpenAI, Anthropic, Gemini, Groq, Ollama, Offline Mock) featuring MITRE ATT&CK reasoner, risk calculation, hypothesis generator, and safety guardrails.
- **Multi-Section Report Engine**: Executive summaries, technical breakdowns, timeline analysis, and customizable PDF/Markdown export.
- **Enterprise Resilience & Security**: Stateful circuit breakers, exponential backoff retries, secret log redactor (`SecretLogMasker`), JWT authentication, RBAC, and path traversal hardening.

---

## Quickstart Guide

### Installation
```bash
# Clone the repository
git clone https://github.com/netfusion/netfusion-agent.git
cd netfusion-agent

# Install dependencies
python -m pip install -r requirements.txt
```

### Running Tests
```bash
# Execute unit and integration tests
python -m pytest -v

# Run real-world investigation scenarios
python -m pytest tests/test_real_world_investigations.py -v

# Run performance and security benchmarks
python -m pytest tests/test_performance_and_security.py -v
```

### Running Platform REST API Server
```bash
python main.py
```

---

## Documentation Links

- 📐 [Architecture Guide & ADRs](docs/ARCHITECTURE.md)
- 🚀 [Deployment & Administrator Guide](docs/DEPLOYMENT.md)
- 💻 [Developer Guide & API Reference](docs/DEVELOPER.md)
- 🛡️ [SOC Analyst Guide & Threat Runbooks](docs/ANALYST_GUIDE.md)
- 📋 [Operational Runbooks](docs/RUNBOOKS.md)
- 🔒 [Security Policy](SECURITY.md)
- 🤝 [Contributing Guidelines](CONTRIBUTING.md)
- 📜 [Code of Conduct](CODE_OF_CONDUCT.md)
- 🗺️ [Platform Roadmap](ROADMAP.md)

---

## Release Version
**v1.0.0-rc1** — Released July 2026 under the MIT License.
