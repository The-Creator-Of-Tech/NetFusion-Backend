# Changelog

All notable changes to the **NetFusion Cyber Investigation Platform** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-rc1] - 2026-07-20

### Added
- **Core Architecture Freeze**: Declared all core packages (`netfusion_canonical`, `netfusion_collector_sdk`, `netfusion_workflow`, `netfusion_ai`, `netfusion_platform`) stable and frozen for v1.0 release.
- **Real-World Investigation Test Suite**: Integrated automated end-to-end scenario validation tests for Phishing, Ransomware, Insider Threat, Lateral Movement, Malware Beaconing, and Data Exfiltration in `tests/test_real_world_investigations.py`.
- **Performance & Security Review Suite**: Added `tests/test_performance_and_security.py` benchmarking startup latency (<500ms), memory allocation, PCAP/EVTX throughput, JWT auth, RBAC enforcement, secret log redactor (`SecretLogMasker`), and path traversal safety.
- **Multi-Collector Telemetry**: Full live and offline ingestion support for Microsoft Sysmon Event IDs 1-26, TShark PCAP/PDML/EK-JSON, Nmap XML service/OS/NSE scans, and Threat Intelligence providers (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus).
- **AI Investigation Assistant**: Production copilot supporting OpenAI, Azure OpenAI, Anthropic, Gemini, Groq, Ollama, and Mock providers with MITRE ATT&CK reasoner, risk calculation, hypothesis engine, and strict safety guardrails.
- **Workflow & Case Management Engine**: Complete lifecycle engine with task dependencies, analyst notes, timeline event sorting/filtering, evidence chain of custody, and SHA-256 integrity validation.
- **Release Documentation Suite**: Created comprehensive Architecture Guide (`ARCHITECTURE.md`), Deployment & Admin Guide (`DEPLOYMENT.md`), Developer Guide & API Reference (`DEVELOPER.md`), SOC Analyst Guide (`ANALYST_GUIDE.md`), Runbooks (`RUNBOOKS.md`), Security Policy (`SECURITY.md`), Contributing Guide (`CONTRIBUTING.md`), Code of Conduct (`CODE_OF_CONDUCT.md`), and Roadmap (`ROADMAP.md`).
- **GitHub Preparation**: Configured Issue Templates (`bug_report.md`, `investigation_request.md`, `security_report.md`), Pull Request Template (`PULL_REQUEST_TEMPLATE.md`), and GitHub Actions workflows (`ci.yml`, `release.yml`, `security.yml`).

### Fixed
- Test suite mock fixture handling for offline `localhost:8000` REST API calls during test discovery.
- Deprecation warnings and path traversal hardening validations.
