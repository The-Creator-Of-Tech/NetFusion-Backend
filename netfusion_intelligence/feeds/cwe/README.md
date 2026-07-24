# IL-6 MITRE CWE Enterprise Intelligence Pipeline

## Overview

The CWE feed implements the MITRE Common Weakness Enumeration pipeline as part of NetFusion IL-6. It ingests every weakness from the official MITRE CWE XML catalog and stores it in the canonical intelligence platform, fully integrated with the knowledge graph.

## Official Source

- **URL**: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
- **Format**: ZIP-compressed XML (namespace: `http://cwe.mitre.org/cwe-7`)
- **Feed ID**: `mitre_cwe_xml`
- **Schedule**: Weekly Sunday 01:00 UTC

## Pipeline Steps

```
Download → Verify → Parse → Normalize → Validate → Store → Build Relationships → Activate
```

| Step | Class | Description |
|------|-------|-------------|
| Download | `CweDownloader` | HTTPS fetch of ZIP-compressed XML, offline support |
| Verify | `CweVerifier` | SHA256 checksum + XML structural check |
| Parse | `CweParser` | Full XML namespace parser, extracts every field |
| Normalize | `CweNormalizer` | Immutable `CweEntity` domain models + relationship graph |
| Validate | `CweValidator` | ID uniqueness, referential integrity |
| Store | `CweRepository` → `SQLAlchemyIntelligenceRepository` | Upsert to `cwe_weakness` + `cwe_relationship` tables |
| Relationships | `CweFeed.build_relationships` | Persists CWE→CWE graph edges |
| Activate | `CweUpdater.activate_dataset` | Atomic version activation |

## Supported Fields

Every available field from the MITRE CWE XML is captured:

- **Identity**: `cwe_id`, `name`, `abstraction`, `structure`, `status`
- **Content**: `description`, `extended_description`, `background_details`
- **Risk**: `likelihood_of_exploit`
- **Technical**: `modes_of_introduction`, `applicable_platforms`
- **Consequences**: scope, impact, notes, likelihood
- **Detection**: method, description, effectiveness
- **Mitigations**: phase, description, strategy, effectiveness
- **Relationships**: `related_weaknesses` (ChildOf, ParentOf, etc.)
- **Cross-references**: `related_attack_patterns` (CAPEC IDs), `taxonomy_mappings`
- **References**: author, title, URL, publication year
- **Metadata**: `affected_resources`, `functional_areas`, `mapping_notes`, `notes`

## Database Tables

| Table | Purpose |
|-------|---------|
| `cwe_weakness` | All CWE weakness fields per dataset version |
| `cwe_relationship` | CWE→CWE graph edges (ChildOf, ParentOf, etc.) |
| `cve_cwe` | CVE→CWE cross-reference (populated by NVD pipeline) |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/intelligence/cwe` | List with filters (abstraction, status, limit, offset) |
| GET | `/intelligence/cwe/{id}` | Single weakness by ID (auto-normalizes `79` → `CWE-79`) |
| GET | `/intelligence/cwe/search` | Full-text search (q, cwe_id, abstraction, status) |
| GET | `/intelligence/cwe/statistics` | Dataset statistics |
| GET | `/intelligence/cwe/version` | Active dataset version |

## Integration with Knowledge Graph

CWE feeds into the unified knowledge graph traversal:
```
CVE → CWE (via cve_cwe table)
         ↓ mitigations + detection guidance
         ↓ related_attack_patterns → CAPEC lookup
```

## Tests

235 tests covering downloader, verifier, parser, normalizer, validator, statistics, repository, updater, feed pipeline, and domain models.

```bash
pytest netfusion_intelligence/feeds/cwe/tests/ -v
```
