# IL-6 MITRE CAPEC Enterprise Intelligence Pipeline

## Overview

The CAPEC feed implements the MITRE Common Attack Pattern Enumeration and Classification pipeline as part of NetFusion IL-6. It ingests every attack pattern from the official MITRE CAPEC XML catalog, stores it in the canonical intelligence platform, and builds bidirectional cross-references to CWE weaknesses and MITRE ATT&CK techniques.

## Official Source

- **URL**: https://capec.mitre.org/data/xml/capec_latest.xml
- **Format**: Raw XML (namespace: `http://capec.mitre.org/capec-3`)
- **Feed ID**: `mitre_capec_xml`
- **Schedule**: Weekly Sunday 02:00 UTC
- **Dependency**: `mitre_cwe_xml` (CWE must be loaded first)

## Pipeline Steps

```
Download → Verify → Parse → Normalize → Validate → Store → Build Relationships → Activate
```

| Step | Class | Description |
|------|-------|-------------|
| Download | `CapecDownloader` | HTTPS fetch, ZIP decompression, offline support |
| Verify | `CapecVerifier` | SHA256 checksum + XML structural validation |
| Parse | `CapecParser` | Full XML namespace parser, every field including execution flows |
| Normalize | `CapecNormalizer` | Immutable `CapecEntity` + `CapecRelationship` + `CapecCweMapping` |
| Validate | `CapecValidator` | ID uniqueness, referential integrity, cross-reference integrity |
| Store | `CapecRepository` → `SQLAlchemyIntelligenceRepository` | Upsert to all CAPEC tables |
| Relationships | `CapecFeed.build_relationships` | Persists CAPEC→CAPEC graph edges |
| Activate | `CapecUpdater.activate_dataset` | Atomic version activation |

## Supported Fields

Every available field from the MITRE CAPEC XML is captured:

- **Identity**: `capec_id`, `name`, `abstraction`, `status`
- **Risk**: `likelihood_of_attack`, `typical_severity`
- **Content**: `description`, `extended_description`
- **Attack Details**: `execution_flow` (step-by-step with phases and techniques)
- **Prerequisites**: `prerequisites`, `skills_required`, `resources_required`
- **Indicators**: `indicators`
- **Consequences**: scope, impact, notes, likelihood
- **Defense**: `mitigations` (strategy, phase, effectiveness), `detection` (method, effectiveness)
- **Examples**: `example_instances`
- **Relationships**: `related_attack_patterns` (ChildOf, ParentOf, CanPrecede, etc.)
- **Cross-references**: `related_weaknesses` (CWE IDs), `taxonomy_mappings` (ATT&CK IDs)
- **References**: author, title, URL, publication year
- **Metadata**: `notes`, `source_version`, `url`

## Database Tables

| Table | Purpose |
|-------|---------|
| `capec_attack_pattern` | All CAPEC fields per dataset version |
| `capec_relationship` | CAPEC→CAPEC graph edges |
| `capec_cwe` | CAPEC↔CWE cross-reference (bidirectional) |
| `capec_attack` | CAPEC↔ATT&CK technique cross-reference |

## ATT&CK Technique Extraction

ATT&CK technique IDs (e.g. `T1190`) are automatically extracted from `taxonomy_mappings` where `taxonomy_name` contains both `"mitre"` and `"att"`. They are stored in:
- `capec_attack_pattern.attack_technique_ids_json` for direct lookup
- `capec_attack` table for cross-reference queries

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/intelligence/capec` | List with filters (abstraction, status, severity, limit, offset) |
| GET | `/intelligence/capec/{id}` | Single pattern by ID (auto-normalizes `66` → `CAPEC-66`) |
| GET | `/intelligence/capec/search` | Search (q, capec_id, abstraction, severity, cwe_id, attack_technique_id) |
| GET | `/intelligence/capec/statistics` | Dataset statistics including CWE and ATT&CK mapping counts |
| GET | `/intelligence/capec/version` | Active dataset version |

## Integration with Knowledge Graph

CAPEC is the bridge between weaknesses and adversary techniques:
```
CWE → CAPEC (via capec_cwe bidirectional lookup)
       ↓ execution_flow (step-by-step attack procedure)
       ↓ mitigations + detection guidance
       ↓ ATT&CK technique IDs → ATT&CK lookup
```

The knowledge graph service uses both directions:
1. `CWE.related_attack_patterns` → direct CAPEC ID reference
2. `capec_cwe` table → reverse lookup from CAPEC's CWE references

## Tests

266 tests covering downloader, verifier, parser, normalizer, validator, statistics, repository, updater, feed pipeline, relationship resolution, and domain models.

```bash
pytest netfusion_intelligence/feeds/capec/tests/ -v
```
