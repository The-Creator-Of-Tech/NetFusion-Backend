# IL-7 IOC Enterprise Intelligence Pipeline

NetFusion Indicator of Compromise (IOC) Intelligence Pipeline — production-grade ingestion, normalization, validation, correlation, reputation, sighting, and knowledge-graph integration for threat indicators.

---

## Overview

IL-7 transforms NetFusion into an enterprise-grade threat intelligence platform by ingesting IOCs from multiple authoritative sources, normalizing them into canonical entities, and correlating them across the full knowledge graph (ATT&CK → CAPEC → CWE → CVE).

Every IOC becomes a first-class **Canonical IOC Entity** within CIIL (Canonical Intelligence Identity Layer). Duplicate indicators across providers are merged — never duplicated.

---

## Supported IOC Types

| Category | Types |
|---|---|
| Network | `ipv4`, `ipv6`, `domain`, `hostname`, `url`, `uri` |
| Identity | `email` |
| Hashes | `md5`, `sha1`, `sha256`, `sha512` |
| TLS/Fingerprints | `tls_cert_fingerprint`, `ja3`, `ja3s` |
| Host Artifacts | `mutex`, `registry_key`, `windows_service_name`, `windows_event_id`, `file_name`, `file_path`, `user_agent`, `process_name`, `command_line`, `scheduled_task`, `named_pipe` |
| Detection Rules | `yara_rule_ref`, `sigma_rule_ref`, `suricata_sid`, `snort_sid` |
| ATT&CK | `attack_data_source` |
| Threat Intel | `malware_family`, `campaign`, `threat_actor_ref` |

---

## Data Sources / Provider Framework

| Provider | Format | Class |
|---|---|---|
| MISP | REST API / JSON export | `MispProvider` |
| OpenCTI | GraphQL export / JSON | `OpenCtiExportProvider` |
| STIX 2.1 | JSON bundle | `StixBundleProvider` |
| TAXII 2.x | Collection API | `TaxiiCollectionProvider` |
| CSV | Configurable columns | `CsvProvider` |
| JSON | List or envelope | `JsonProvider` |
| YAML | Any structure | `YamlProvider` |
| Offline | Pre-loaded Python object | `OfflineImportProvider` |

All providers implement `IocProviderInterface`. New providers require only implementing `fetch()`.

---

## Architecture

```
Providers (MISP / OpenCTI / STIX / TAXII / CSV / JSON / YAML / Offline)
    ↓
IocDownloader          — aggregates raw payloads, strips non-serializable objects
    ↓
IocParser              — dispatches to format-specific sub-parser
    ↓
IocNormalizer          — type-specific value normalization + fingerprint deduplication
    ↓
IocValidator           — format rules, cross-reference rules, confidence range
    ↓
IocFeed.store()        — IocRepository → ioc_indicator + ioc_reputation tables
    ↓
IocCorrelationEngine   — IOC→ATT&CK, CAPEC, CWE, CVE, Malware, Campaign, Actor, IOC↔IOC
    ↓
IocRepository          — ioc_relationship, ioc_sighting, ioc_source tables
    ↓
IocUpdater             — dataset version activation / rollback
    ↓
CIIL                   — CanonicalEntity registration via IocMapper
    ↓
KnowledgeGraphService  — IOC knowledge card traversal
    ↓
REST API               — /intelligence/ioc/* endpoints
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `ioc_indicator` | Primary IOC store — one row per canonical (type, value) per version |
| `ioc_alias` | Alternative values / known aliases |
| `ioc_relationship` | IOC-to-IOC and IOC-to-entity relationships |
| `ioc_reputation` | Reputation scores, FP score, contributing sources |
| `ioc_sighting` | Sighting observations with source, org, location, count |
| `ioc_source` | Per-provider contribution records |
| `ioc_provider` | Registered provider registry |

All domain tables use `(dataset_version_id, ioc_id)` as compound unique key — enabling full versioning and rollback.

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/intelligence/ioc` | List IOCs with optional filters |
| `GET` | `/intelligence/ioc/search` | Multi-parameter search |
| `GET` | `/intelligence/ioc/statistics` | Dataset statistics |
| `GET` | `/intelligence/ioc/version` | Active dataset version |
| `GET` | `/intelligence/ioc/{id}` | Get single IOC by ID |
| `GET` | `/intelligence/ioc/{id}/reputation` | Reputation record |
| `GET` | `/intelligence/ioc/{id}/sightings` | Sighting observations |
| `GET` | `/intelligence/ioc/{id}/correlation` | All relationships |
| `GET` | `/intelligence/ioc/{id}/knowledge` | Full knowledge graph card |

### Search Parameters

`ioc_type`, `value`, `hash_value`, `ip`, `domain`, `threat_actor`, `campaign`, `malware`, `attack_technique`, `capec_id`, `cwe_id`, `cve_id`, `provider`, `min_confidence`, `min_reputation`, `first_seen_start/end`, `last_seen_start/end`

---

## Reputation Engine

Each IOC stores:

| Field | Range | Description |
|---|---|---|
| `confidence` | 0.0–1.0 | Probability the indicator is malicious |
| `reputation_score` | 0.0–10.0 | Composite maliciousness score |
| `false_positive_score` | 0.0–1.0 | Historical FP signal |
| `severity` | critical/high/medium/low/info/unknown | Classification |
| `priority` | 1–5 | Operational response priority |
| `source_count` | int | Number of independent sources |
| `first_seen` | ISO timestamp | Earliest observation |
| `last_seen` | ISO timestamp | Most recent observation |
| `expiration` | ISO timestamp | Indicator expiry |

Reputation score formula: `base(confidence × severity_weight × 5) + boost(log(sources) + log(sightings)) - penalty(FP × 5)`, clamped to [0, 10].

---

## Normalization Rules

| IOC Type | Normalization Applied |
|---|---|
| IPv4 | Canonicalize via `ipaddress`, strip port |
| IPv6 | Canonicalize via `ipaddress` |
| Domain | Lowercase, strip protocol/port/path, Punycode IDN |
| URL | Lowercase scheme+netloc, unicode NFC |
| Email | Lowercase, validate `user@domain` format |
| MD5/SHA1/SHA256/SHA512 | Uppercase, validate hex length |
| Registry Key | Expand hive abbreviations (HKLM→HKEY_LOCAL_MACHINE) |
| File Path | Unicode NFC, normalize backslash sequences |
| All | Unicode NFC normalization, whitespace strip |

Deduplication uses SHA-256 fingerprint of `type::lowercase(normalized_value)`.

---

## Knowledge Graph Integration

```
IOC
 ├─→ Malware Family
 ├─→ Campaign
 ├─→ Threat Actor
 ├─→ ATT&CK Technique → Sub-technique
 ├─→ CAPEC Attack Pattern
 ├─→ CWE Weakness
 └─→ CVE Vulnerability
```

`GET /intelligence/ioc/{id}/knowledge` returns the full traversal with nodes and edges.

---

## Quick Start

```python
from netfusion_intelligence.feeds.ioc.feed import IocFeed
from netfusion_intelligence.feeds.ioc.providers import MispProvider, StixBundleProvider
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.config import EngineConfig

# Configure providers
misp = MispProvider(url="https://your-misp/", api_key="YOUR_KEY", confidence=0.85)
stix = StixBundleProvider(url="https://your-stix-feed/bundle.json")

# Build and register feed
engine = IntelligenceEngine(config=EngineConfig(db_url="sqlite:///netfusion.db"))
feed = IocFeed(repository=engine.repository, providers=[misp, stix])
engine.register_feed(feed)

# Sync (use lifecycle_runner.execute directly if prerequisite feeds not registered)
engine.lifecycle_runner.execute(feed)
```

---

## Running Tests

```bash
python -m pytest netfusion_intelligence/feeds/ioc/tests/ -v
```

**188 tests, 188 passing.**
