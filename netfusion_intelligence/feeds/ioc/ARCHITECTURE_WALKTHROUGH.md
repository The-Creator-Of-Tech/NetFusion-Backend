# IL-7 IOC Enterprise Intelligence Pipeline — Architecture Walkthrough

## Design Principles

IL-7 follows the same SOLID + Clean Architecture patterns as IL-1 through IL-6:

- **Single Responsibility** — each module (downloader, parser, normalizer, validator, correlator, reputation, confidence) has exactly one job
- **Open/Closed** — new IOC types and new provider formats are added without modifying existing code
- **Liskov Substitution** — `IocProviderInterface` guarantees all providers are interchangeable
- **Interface Segregation** — `IocRepository` facade exposes only IOC-domain methods; it does not leak infrastructure details
- **Dependency Inversion** — `IocFeed` depends on abstractions (`IntelligenceRepositoryInterface`, `IocProviderInterface`), never on concrete classes

---

## Module Map

```
feeds/ioc/
├── __init__.py           package marker
├── manifest.py           FeedManifest declaration (entity types, relationships, schedule, dependencies)
├── models.py             Frozen domain dataclasses: IocEntity, IocRelationship, IocReputation,
│                           IocSighting, IocSource, IocProvider, IocType enum, IocSeverity enum
├── providers.py          IocProviderInterface + concrete: MispProvider, StixBundleProvider,
│                           OpenCtiExportProvider, TaxiiCollectionProvider, CsvProvider,
│                           JsonProvider, YamlProvider, OfflineImportProvider
├── downloader.py         Orchestrates multi-provider fetch; strips non-JSON-serializable objects
├── verifier.py           SHA-256 checksum computation and structural sanity check
├── parser.py             Format dispatchers: MISP, STIX 2.1, OpenCTI, CSV, YAML, JSON/generic;
│                           STIX pattern extraction via regex; type inference heuristics
├── normalizer.py         Type-specific value normalization (ipaddress, Punycode, hash validation,
│                           URL canonicalization, registry key hive expansion); fingerprint dedup
├── validator.py          ValidationResult errors/warnings: format rules per type, confidence range,
│                           ATT&CK/CAPEC/CWE/CVE cross-reference format validation
├── mapper.py             IocEntity → CanonicalEntity (CIIL) mapping with proper
│                           ExternalIdentifier, EntityProvenance, tags, metadata
├── correlation.py        IOC→entity and IOC↔IOC relationship derivation; dedup by (src,tgt,type)
├── reputation.py         IocReputation computation: severity-weighted score, source boost,
│                           sighting boost, FP penalty; update merging
├── confidence.py         IocConfidenceEngine: provider trust weighting, multi-source noisy-OR,
│                           temporal decay, TLP boost, FP reduction
├── events.py             Domain events: IocImportStarted/Completed, CanonicalIocCreated,
│                           IocMerged, IocCorrelated, SightingRecorded, ReputationUpdated,
│                           IocDatasetActivated
├── repository.py         IocRepository facade — domain queries delegated to platform repo
├── updater.py            Version comparison, activation, rollback
├── statistics.py         IocStatistics.calculate_statistics() — full coverage metrics
├── feed.py               IocFeed — FeedInterface implementation, all 10 lifecycle methods
└── tests/
    ├── conftest.py
    ├── test_downloader.py   (6 tests)
    ├── test_parser.py       (21 tests)
    ├── test_normalizer.py   (24 tests)
    ├── test_validator.py    (13 tests)
    ├── test_correlation.py  (12 tests)
    ├── test_reputation.py   (22 tests)
    ├── test_repository.py   (19 tests)
    ├── test_search.py       (20 tests)
    ├── test_feed.py         (20 tests)
    ├── test_rollback.py     (8 tests)
    └── test_knowledge_graph.py (11 tests)
```

---

## IL-1 Lifecycle Integration (13 Steps)

```
Step  1  Initialize         FeedInterface.config.enabled check → publish FeedStarted
Step  2  Secure Download    IocDownloader.download() → list of JSON-safe provider payloads
Step  3  TLS Verification   TrustPolicyEngine.transport_verifier (passes for local feeds)
Step  4  Signature Verify   TrustPolicyEngine.signature_verifier
Step  5  Checksum Verify    IocVerifier.compute_checksum(raw_data) → SHA-256 of serialized list
Step  6  Trust Evaluation   TrustPolicyEngine.evaluate() → TrustDecision.TRUSTED
Step  7  Parse              IocFeed.parse() → IocParser.parse_all() → merged indicator dicts
Step  8  Normalize          IocFeed.normalize() → IocNormalizer.normalize() → IocEntity dict
Step  9  Validate           IocFeed.validate() → IocValidator.validate() → ValidationResult
Step 10  Store              IocFeed.store() → IocRepository.store_indicators() + store_reputations()
Step 11  Relationship Build IocFeed.build_relationships() → IocCorrelationEngine → store_relationships()
Step 12  Activate Dataset   IocUpdater.activate_dataset() if auto_activate=True
Step 13  Publish Events     FeedCompleted → AuditLog → HealthMonitor
```

---

## CIIL Integration

Every `IocEntity` is mapped to a `CanonicalEntity` via `IocMapper`:

```
IocEntity.ioc_type   → CanonicalEntityType (IP_ADDRESS / DOMAIN / URL / HASH / EMAIL / IOC / ...)
IocEntity.value      → ExternalIdentifier.identifier
IocEntity.provider   → ExternalIdentifier.source
IocEntity.confidence → ExternalIdentifier.confidence + CanonicalEntity.confidence
IocEntity.ioc_id     → EntityProvenance.original_object_id
FEED_ID              → EntityProvenance.feed
```

The `entity_type` mapping table ensures granularity:
- `ipv4 / ipv6` → `IP_ADDRESS`
- `domain / hostname` → `DOMAIN`
- `url / uri` → `URL`
- `md5 / sha1 / sha256 / sha512` → `HASH`
- `email` → `EMAIL`
- `tls_cert_fingerprint` → `CERTIFICATE`
- `ja3 / ja3s / suricata_sid / snort_sid` → `SIGNATURE`
- `yara_rule_ref / sigma_rule_ref` → `RULE`
- `malware_family` → `MALWARE`
- `campaign` → `ATTACK_CAMPAIGN`
- `threat_actor_ref` → `THREAT_ACTOR`
- All others → `IOC`

---

## Deduplication Strategy

The normalizer computes a SHA-256 fingerprint: `sha256(f"{type}::{lowercase(normalized_value)}")`.

Across a single pipeline run, the first occurrence wins. If a later occurrence has higher confidence, it replaces the earlier one. Across runs (different dataset versions), the repository upserts by `(dataset_version_id, ioc_id)` — so indicators carry forward with updated scores.

For cross-provider canonical merging, CIIL's `IdentityRepository.find_by_identifier_value()` detects existing canonical UUIDs so `IocMapper` can reuse them instead of creating new ones.

---

## Correlation Engine

Relationships are derived from entity attribution fields during `build_relationships()`:

```
IocEntity.attack_technique_ids  → ioc_to_attack_technique (one per technique)
IocEntity.capec_ids             → ioc_to_capec
IocEntity.cwe_ids               → ioc_to_cwe
IocEntity.cve_ids               → ioc_to_cve
IocEntity.malware_families      → ioc_to_malware
IocEntity.campaigns             → ioc_to_campaign
IocEntity.threat_actors         → ioc_to_threat_actor
```

**IOC-to-IOC co-observation**: two IOCs from the same `(provider, provider_id)` event are structurally related. The relationship type is inferred from their types:
- `(ipv4, domain)` → `ip_to_domain`
- `(domain, url)` → `domain_to_url`
- `(url, sha256)` → `url_to_hash`
- `(sha256, file_name)` → `hash_to_file`
- Default → `ioc_to_ioc`

Deduplication uses a `seen: set` keyed on `f"{src}::{tgt}::{rel_type}"`.

---

## Reputation Scoring

```
severity_weight = {critical: 1.0, high: 0.8, medium: 0.5, low: 0.25, info: 0.1}
base   = confidence × severity_weight × 5.0
boost  = log1p(source_count) × 0.5 + log1p(sighting_count) × 0.3
penalty = false_positive_score × 5.0
score  = clamp(base + boost - penalty, 0.0, 10.0)
```

A critical, high-confidence indicator from 5 sources scores ~9.3/10. A low-confidence, high-FP indicator scores near 0.

---

## Confidence Scoring

```
provider_trust = {misp:0.85, opencti:0.80, stix:0.75, taxii:0.75, csv:0.55, ...}
score  = base_confidence × 0.6 + provider_trust × 0.4
score += min(0.15, log1p(source_count - 1) × 0.07)   # multi-source boost
score += min(0.10, log1p(sightings) × 0.05)           # sighting boost
score += 0.05 if TLP:RED / 0.03 if TLP:AMBER          # TLP boost
score *= max(0.3, exp(-0.01 × (age_days - 30)))       # temporal decay after 30 days
score -= false_positive_score × 0.5                    # FP penalty
score  = clamp(score, 0.0, 1.0)
```

Multi-source merging uses noisy-OR blend: `0.6 × (1 - ∏(1-pᵢ)) + 0.4 × avg(pᵢ)`.

---

## Provider JSON-Serialization Safety

The IL-1 `compute_checksum()` utility serializes `raw_data` via `json.dumps()`. The `IocDownloader` intentionally omits the `IocProviderInterface` object from its output dict — only JSON-safe primitives are included (`provider_id`, `provider_type`, `provider_name`, `default_confidence`, `default_tlp`). This ensures the checksum step never raises `TypeError`.

---

## Extending IL-7

### Adding a new provider

```python
from netfusion_intelligence.feeds.ioc.providers import IocProviderInterface

class MyCustomProvider(IocProviderInterface):
    @property
    def provider_id(self): return "my_custom"
    @property
    def provider_name(self): return "My Custom Feed"
    @property
    def provider_type(self): return "json"     # reuses JSON parser
    def fetch(self):
        return requests.get("https://my-feed/iocs.json").json()

feed.add_provider(MyCustomProvider())
```

### Adding a new IOC type

1. Add to `IocType` enum in `models.py`
2. Add normalization in `IocNormalizer._normalize_value()`
3. Add validation in `IocValidator._validate_by_type()`
4. Add `_TYPE_MAP` entry in `IocMapper`
5. Update `manifest.py` entity_types list
