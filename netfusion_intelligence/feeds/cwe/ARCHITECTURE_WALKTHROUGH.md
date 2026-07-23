# CWE Enterprise Intelligence Pipeline — Architecture Walkthrough

## Component Map

```
CweFeed (FeedInterface)
│
├── CweDownloader          # HTTPS fetch + ZIP decompression
├── CweVerifier            # SHA256 + XML structure check
├── CweParser              # xml.etree.ElementTree, namespace http://cwe.mitre.org/cwe-7
├── CweNormalizer          # raw dict → CweEntity (frozen dataclass)
├── CweValidator           # ValidatorInterface: ID uniqueness + referential integrity
├── CweRepository          # Facade over IntelligenceRepositoryInterface
├── CweUpdater             # Version comparison, activation, rollback
├── CweStatistics          # Coverage metrics, distribution counts
├── CweMapper              # CweEntity → CanonicalEntity (CIIL)
└── CweEvents              # Domain events for the IL-1 Event Bus
```

## Data Flow

### Step 1 — Registration
```python
engine = IntelligenceEngine()
feed = CweFeed(repository=engine.repository)
engine.register_feed(feed)
```
Publishes `FeedRegistered` event. Stores feed record in `intelligence_feed` table.

### Step 2 — Download
```python
raw: bytes = feed.fetch_raw_data()
# → CweDownloader.download()
#   → urllib.request.urlopen (HTTPS with TLS verification)
#   → _decompress_if_needed() auto-decompresses ZIP (PK magic bytes)
```

### Step 3 — Verify
```python
ok: bool = feed.verify_checksum(raw)
# → CweVerifier.verify_checksum(raw, expected_checksum)
# → SHA256 hex comparison (case-insensitive)
# → No expected checksum? Always returns True
```

### Step 4 — Parse
```python
parsed: dict = feed.parse(raw)
# → CweParser.parse(raw)
# → ET.fromstring(raw) with CWE namespace
# Returns:
# {
#   "catalog_version": "4.15",
#   "weaknesses": [{...}, ...],          # every XML field as raw dicts
#   "categories": [...],
#   "views": [...],
#   "external_references": [...],         # reference ID → metadata
#   "total_weaknesses": 947,
# }
```

### Step 5 — Normalize
```python
normalized: dict = feed.normalize(parsed)
# → CweNormalizer.normalize(parsed)
# → _build_ref_index(ext_refs) for O(1) reference enrichment
# → _map_weakness(raw, ref_index) → CweEntity (frozen dataclass)
# → Build CweRelationship objects from related_weaknesses
# Returns:
# {
#   "entities": {"CWE-79": CweEntity(...), ...},
#   "relationships": [CweRelationship(...), ...],
#   "catalog_version": "4.15",
#   "record_count": 947,
#   "relationship_count": 1847,
# }
```

### Step 6 — Validate
```python
result: ValidationResult = feed.validate(normalized)
# → CweValidator.validate(normalized)
# Checks:
#   - dataset is a dict
#   - entities is non-empty
#   - every entity has cwe_id and name
#   - no duplicate cwe_ids
#   - relationship sources/targets exist (warnings for cross-dataset refs)
```

### Step 7 — Store
```python
import_result = feed.store(dataset_version, normalized)
# → CweRepository.store_weaknesses(version_id, entities)
#   → repo.save_cwe_weaknesses(version_id, entities)
#     → CweWeaknessModel upsert (INSERT or UPDATE by cwe_id + version_id)
```

#### CweEntity → Database mapping
| Domain field | DB column |
|---|---|
| `cwe_id` | `cwe_id` |
| `name` | `name` |
| `abstraction` | `abstraction` |
| `structure` | `structure` |
| `status` | `status` |
| `description` | `description` |
| `extended_description` | `extended_description` |
| `likelihood_of_exploit` | `likelihood_of_exploit` |
| `background_details` | `background_details` |
| `alternate_terms` | `alternate_terms_json` |
| `modes_of_introduction` | `modes_of_introduction_json` |
| `applicable_platforms` | `applicable_platforms_json` |
| `consequences` | `consequences_json` |
| `detection_methods` | `detection_methods_json` |
| `mitigations` | `mitigations_json` |
| `related_weaknesses` | `related_weaknesses_json` |
| `taxonomy_mappings` | `taxonomy_mappings_json` |
| `references` | `references_json` |
| `related_attack_patterns` | `related_attack_patterns_json` |
| `affected_resources` | `affected_resources_json` |
| `functional_areas` | `functional_areas_json` |
| `mapping_notes` | `mapping_notes` |
| `notes` | `notes` |
| `source_version` | `source_version` |
| `url` | `url` |

### Step 8 — Build Relationships
```python
count: int = feed.build_relationships(dataset_version)
# → CweRepository.store_relationships(version_id, relationships)
#   → CweRelationshipModel INSERT (deduplicated by source+target+nature)
# Stores every CWE→CWE edge:
#   source_cwe_id, target_cwe_id, nature, view_id, ordinal
```

### Step 9 — Activate
```python
feed.on_activate(dataset_version)
# → CweUpdater.activate_dataset(dataset_version)
#   → repo.set_active_dataset_version("mitre_cwe_xml", version_id)
#     → Atomically sets old ACTIVE → ARCHIVED, new → ACTIVE
# Publishes: DatasetActivated event
```

## CIIL Integration

`CweMapper` maps `CweEntity` → `CanonicalEntity` for CIIL registration:

```python
canonical = CanonicalEntity(
    entity_type="CWE",
    display_name=entity.name,
    external_identifiers=(ExternalIdentifier(
        source="MITRE CWE",
        identifier=entity.cwe_id,
        identifier_type="CWE_ID",
    ),),
    tags=("cwe", "weakness", "abstraction:base", ...),
)
```

The `IdentityResolver` deduplicates: if a canonical CWE already exists, it merges the incoming data rather than creating a duplicate.

## Version Management

```
Version states: CREATED → VALIDATED → ACTIVATING → ACTIVE → ARCHIVED
                                                          ↑ rollback target
```

`CweUpdater.compare_versions(new_checksum)` checks whether the new download differs from the active version. If checksums match, the import is skipped. This enables true incremental updates — only changed catalogs trigger a new dataset version.

## Rollback

```python
updater = CweUpdater(repo)
updater.rollback_dataset(target_version_id="cwe-v001")
# → Sets cwe-v001 back to ACTIVE
# → Old active version moves to ARCHIVED
# → All previous data still queryable by version_id
```

## Knowledge Graph Position

```
CVE
 │ (cve_cwe table — populated by NVD pipeline)
 ▼
CWE ─── mitigations ──────────────────────────────▶ Mitigation Guidance
 │ ─── detection_methods ───────────────────────▶ Detection Guidance
 │ ─── related_attack_patterns ─────────────────▶ CAPEC IDs
 │                                                    │
 │ (cwe_relationship table)                           │ (capec_cwe table — reverse)
 ▼                                                    ▼
CWE ◀─── ChildOf / ParentOf / PeerOf ──────────── CAPEC
                                                    │
                                                    ▼
                                               ATT&CK Technique
```

## Event Publishing

| Event | When Published |
|-------|---------------|
| `CweImportStarted` | Pipeline begins |
| `CweImportCompleted` | Pipeline completes successfully |
| `CweImportFailed` | Any stage fails |
| `CanonicalCweCreated` | New CWE registered in CIIL |
| `CweRelationshipCreated` | New CWE→CWE edge created |
| `CweDatasetActivated` | Dataset version activated |
| `KnowledgeGraphUpdated` | After relationships built |

All events are persisted to the `event_audit` table via the IL-1 Event Bus.
