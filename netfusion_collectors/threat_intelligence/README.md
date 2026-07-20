# NetFusion Threat Intelligence Collector

The **Threat Intelligence Collector** is an enterprise-grade ingestion and enrichment collector for NetFusion. It enriches telemetry and observations from other collectors (such as TShark and Nmap) with multi-provider threat intelligence.

---

## Architecture Overview

The Threat Intelligence Collector extends `BaseCollector` from the NetFusion Collector SDK and integrates seamlessly into the NetFusion Runtime Engine, Canonical Data Model, Normalization Pipeline, Event Bus, and InvestigationContext.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ThreatIntelCollector                              │
└──────┬──────────────────────────────────┬───────────────────────────┬───────┘
       │                                  │                           │
┌──────▼────────────────┐      ┌──────────▼──────────┐     ┌──────────▼────────┐
│  ThreatIntelRunner    │      │  ThreatIntelCache   │     │ ThreatCorrelator  │
│  (Async Concurrency)  │      │  (L1 Mem + L2 DB)   │     │  (Entities & MITRE)│
└──────┬────────────────┘      └─────────────────────┘     └──────────┬────────┘
       │                                                              │
       ├─► AbuseIPDBProvider ──────────┐                               │
       ├─► VirusTotalProvider ─────────┤                               │
       ├─► AlienVaultOTXProvider ──────┼─► ProviderResponse ───────────┤
       ├─► URLHausProvider ────────────┤                               │
       ├─► MISPProvider ───────────────┤                               │
       └─► OpenCTIProvider ────────────┘                               │
                                                                      │
                                                               ┌──────▼────────┐
                                                               │  Canonical    │
                                                               │  Validator    │
                                                               └──────┬────────┘
                                                                      │
                                                               ┌──────▼────────┐
                                                               │ EventPublisher│
                                                               └───────────────┘
```

---

## Supported Input Types & Providers

### Provider Integrations
- **AbuseIPDB**: IP abuse confidence, report counts, categories, country of origin.
- **VirusTotal (v3)**: File hash, domain, IP, and URL detection ratios across engines.
- **AlienVault OTX**: Threat pulse indicators, tags, and adversary attribution.
- **URLhaus**: Malware distribution URL and payload hash queries.
- **MISP**: Private / community MISP instance attribute & event searches.
- **OpenCTI**: STIX2 observables, indicators, and threat actor scoring.

### Supported Input Types
- `IPv4`
- `IPv6`
- `Domain`
- `URL`
- `FileHash` (MD5, SHA1, SHA256)
- `Email`
- `CVE`
- `CPE`

---

## Configuration

Configuration is managed via `ThreatIntelConfig`:

```python
from netfusion_collectors.threat_intelligence import ThreatIntelConfig, ThreatIntelCollector
from netfusion_collector_sdk import CollectorContext

config = ThreatIntelConfig(
    api_timeout=10.0,
    concurrent_lookups=10,
    batch_size=50,
    cache_ttl=86400,  # 24 hours
    iocs=[
        {"value": "1.1.1.1", "type": "IPv4"},
        {"value": "malicious.example.com", "type": "Domain"},
        {"value": "44d88612fea8a8f36de82e1278abb02f", "type": "FileHash"}
    ],
    abuseipdb={"enabled": True, "api_key": "YOUR_ABUSEIPDB_KEY"},
    virustotal={"enabled": True, "api_key": "YOUR_VIRUSTOTAL_KEY"},
    alienvault_otx={"enabled": True, "api_key": "YOUR_OTX_KEY"},
    urlhaus={"enabled": True},
    misp={"enabled": False, "base_url": "https://misp.local", "api_key": "YOUR_MISP_KEY"},
    opencti={"enabled": False, "base_url": "https://opencti.local", "api_key": "YOUR_TOKEN"}
)

collector = ThreatIntelCollector(context=CollectorContext(investigation_id="inv-101"))
collector.configure(config.model_dump())
```

---

## Caching Strategy

The collector implements a **Unified Two-Tier Caching System**:

1. **L1 Memory Cache**: Thread-safe in-memory cache for ultra-fast repeated lookups.
2. **L2 Persistent Cache**: SQLite-backed storage (`cache.db`) preserving data across runs.
3. **Negative Cache**: Caches non-threat lookups with configurable shorter TTL (default 1 hour) to avoid unnecessary provider API hammering.
4. **Provider Isolation**: All keys are namespaced as `{provider}:{ioc_type}:{ioc_value}`.

---

## Automated Entity Correlation

Raw responses are automatically transformed into canonical domain objects and linked:
- **IP ↔ Domain**: Generates `RelationshipObserved` (RESOLVES_TO).
- **Hash ↔ Malware**: Generates `MalwareObserved` and `RelationshipObserved` (INDICATES).
- **CVE ↔ Exploit**: Generates `ExploitObserved`.
- **Technique ↔ MITRE**: Generates `MITREMappingObserved`.
- **Actor ↔ Campaign**: Generates `ThreatActorObserved` and `CampaignObserved`.

---

## Security Considerations

1. **Credential Isolation**: API keys and OAuth tokens are strictly confined to individual provider classes inside `providers/`.
2. **Secret Masking**: All exception tracebacks and logs pass through secret masking (`_mask_secret()`) to prevent leaking API keys.
3. **TLS Verification**: Enabled by default for all HTTPS requests (`tls_verification=True`).

---

## Troubleshooting

- **Health Checks**: Run `collector.health_checker.run_all()` to inspect network connectivity, SSL certificates, and active provider credentials.
- **Cache Invalidation**: Call `cache.clear()` or `cache.invalidate(provider, ioc_type, ioc_value)` to purge cached records.
- **DLQ Routing**: Invalid canonical objects are automatically safely routed to the Dead Letter Queue without interrupting batch processing.







# Appendix A — Threat Intelligence Provider Capability Matrix

## Purpose

This matrix documents the capabilities of each supported Threat Intelligence provider.

It serves as an architectural reference for provider selection, future integrations, maintenance, and debugging.

The matrix is documentation only.

The Runtime SDK and Collector MUST NOT use this matrix for runtime decision-making.

Provider capabilities are implemented by the Provider interface and configuration.

---

| Capability        | AbuseIPDB | VT | OTX     | URLhaus | MISP    | OpenCTI |
| ----------------- | --------- | -- | ------- | ------- | ------- | ------- |
| IP Reputation     | ✅         | ✅  | ✅       | ❌  | ✅       | ✅       |
| Domain Reputation | ❌         | ✅  | ✅       | ❌  | ✅       | ✅       |
| URL Reputation    | ❌         | ✅  | ✅       | ✅  | ✅       | ✅       |
| Hash Reputation   | ❌         | ✅  | ✅       | ✅  | ✅       | ✅       |
| Malware           | ❌         | ✅  | ✅       | ✅  | ✅       | ✅       |
| Threat Actor      | ❌         | ❌  | ✅       | ❌  | ✅       | ✅       |
| Campaign          | ❌         | ❌  | ✅       | ❌  | ✅       | ✅       |
| MITRE Mapping     | ❌         | ❌  | Partial   | ❌  | Partial | ✅       |


## Recommended Usage

### AbuseIPDB
Primary purpose:
- Malicious IP reputation

Avoid using for:
- Malware intelligence
- Threat actor attribution

---

### VirusTotal

Primary purpose:
- File hash reputation
- URL analysis
- Domain intelligence

Avoid using as the only threat intelligence source.

---

### AlienVault OTX

Primary purpose:
- IOC enrichment
- Threat campaigns
- Community intelligence

---

### URLhaus

Primary purpose:
- Malicious URLs
- Malware download infrastructure

---

### MISP

Primary purpose:
- Enterprise IOC sharing
- Internal threat intelligence
- CVEs
- Threat relationships

---

### OpenCTI

Primary purpose:
- Knowledge graph
- Threat actor intelligence
- Campaign intelligence
- MITRE ATT&CK mapping
- Long-term investigation context

---

## Provider Selection Strategy

Recommended lookup order:

IP Address:
1. AbuseIPDB
2. VirusTotal
3. AlienVault OTX
4. MISP
5. OpenCTI

File Hash:
1. VirusTotal
2. AlienVault OTX
3. MISP
4. OpenCTI

Domain:
1. VirusTotal
2. AlienVault OTX
3. MISP
4. OpenCTI

URL:
1. URLhaus
2. VirusTotal
3. AlienVault OTX

Threat Actor:
1. OpenCTI
2. MISP
3. AlienVault OTX

Campaign:
1. OpenCTI
2. MISP
3. AlienVault OTX

MITRE ATT&CK:
1. OpenCTI
2. MISP

---

## Future Providers

The provider architecture is intentionally extensible.

Potential future integrations include:

- GreyNoise
- Cisco Talos Intelligence
- Shodan
- Pulsedive
- ThreatFox
- Spamhaus
- IBM X-Force Exchange
- CrowdStrike Falcon Intelligence
- Recorded Future
- Microsoft Defender Threat Intelligence
- Google Threat Intelligence
- CISA Known Exploited Vulnerabilities (KEV)
- CIRCL CVE Search

New providers SHOULD extend `BaseThreatProvider` and be documented in this matrix without requiring changes to existing providers.