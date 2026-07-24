# CAPEC Enterprise Intelligence Pipeline — Architecture Walkthrough

## Component Map

```
CapecFeed (FeedInterface)
│
├── CapecDownloader        # HTTPS fetch + ZIP/raw XML support
├── CapecVerifier          # SHA256 + XML structure check
├── CapecParser            # xml.etree.ElementTree, namespace http://capec.mitre.org/capec-3
├── CapecNormalizer        # raw dict → CapecEntity + CapecRelationship + CapecCweMapping
├── CapecValidator         # ID uniqueness + referential integrity + CWE cross-ref
├── CapecRepository        # Facade over IntelligenceRepositoryInterface
├── CapecUpdater           # Version comparison, activation, rollback
├── CapecStatistics        # Coverage metrics (execution_flow, mitigations, ATT&CK)
├── CapecMapper            # CapecEntity → CanonicalEntity (CIIL)
└── CapecEvents            # Domain events for the IL-1 Event Bus
```

## Domain Models

```
CapecEntity (frozen dataclass)
├── capec_id: str
├── name: str
├── execution_flow: Tuple[CapecExecutionFlowStep, ...]
│   └── CapecExecutionFlowStep: step_number, phase, description, techniques
├── consequences: Tuple[CapecConsequence, ...]
├── mitigations: Tuple[CapecMitigation, ...]
│   └── strategy, phase, effectiveness
├── detection: Tuple[CapecDetection, ...]
├── skills_required: Tuple[CapecSkillRequired, ...]
├── related_attack_patterns: Tuple[CapecRelatedAttackPattern, ...]  ← CAPEC→CAPEC
├── related_weaknesses: Tuple[str, ...]                              ← CWE IDs
├── taxonomy_mappings: Tuple[dict, ...]                              ← ATT&CK IDs here
└── to_dict() → includes attack_technique_ids extracted from taxonomy_mappings

CapecRelationship (frozen dataclass)
├── source_capec_id, target_capec_id, nature, view_id

CapecCweMapping (frozen dataclass)
└── capec_id, cwe_id, nature
```

## Data Flow

### Step 4 — Parse
```python
parsed = feed.parse(raw)
# Extracts per attack pattern:
#   execution_flow → list of {step_number, phase, description, techniques[]}
#   prerequisites → list of strings
#   skills_required → list of {level, description}
#   resources_required → list of strings
#   indicators → list of strings
#   consequences → list of {scope[], impact[], note, likelihood}
#   mitigations → list of {description, phase[], strategy, effectiveness}
#   detection → list of {method, description, effectiveness, effectiveness_notes}
#   example_instances → list of strings
#   related_attack_patterns → list of {capec_id, nature, view_id}
#   related_weaknesses → list of CWE IDs (e.g. "CWE-89")
#   taxonomy_mappings → list of {taxonomy_name, entry_id, entry_name, mapping_fit}
#   references → enriched with external_references data
```

### ATT&CK Extraction

```python
# CapecEntity.to_dict() extracts from taxonomy_mappings automatically:
attack_technique_ids = []
for tm in self.taxonomy_mappings:
    tax_name = (tm.get("taxonomy_name") or "").lower()
    if "mitre" in tax_name and "att" in tax_name:
        entry_id = tm.get("entry_id")
        if entry_id:
            attack_technique_ids.append(entry_id)
# Result stored in:
#   capec_attack_pattern.attack_technique_ids_json
#   capec_attack table (for reverse lookup)
```

### Step 7 — Store

Three tables populated per entity:

```
CapecEntity
    │
    ├─────────────────────────────────▶ capec_attack_pattern
    │                                      (all fields including attack_technique_ids_json)
    │
    ├─ for each related_weakness ─────▶ capec_cwe
    │      (capec_id, cwe_id, nature)
    │
    └─ for each attack_technique_id ──▶ capec_attack
           (capec_id, attack_technique_id, taxonomy_name)
```

### Step 8 — Build Relationships

```python
count = feed.build_relationships(dataset_version)
# → CapecRepository.store_relationships(version_id, relationships)
# → CapecRelationshipModel INSERT
# Stores CAPEC→CAPEC edges with deduplication
```

## Database Tables

### `capec_attack_pattern`
```sql
capec_id               VARCHAR(20)   NOT NULL  -- e.g. CAPEC-66
dataset_version_id     VARCHAR(100)  NOT NULL
name                   VARCHAR(255)
abstraction            VARCHAR(50)   -- Meta, Standard, Detailed
status                 VARCHAR(50)
likelihood_of_attack   VARCHAR(50)
typical_severity       VARCHAR(50)
execution_flow_json    TEXT          -- [{step_number, phase, description, techniques[]}]
prerequisites_json     TEXT
skills_required_json   TEXT
resources_required_json TEXT
indicators_json        TEXT
consequences_json      TEXT
mitigations_json       TEXT
detection_json         TEXT
example_instances_json TEXT
related_attack_patterns_json TEXT    -- CAPEC→CAPEC references
related_weaknesses_json      TEXT    -- CWE IDs
taxonomy_mappings_json       TEXT    -- includes ATT&CK entries
attack_technique_ids_json    TEXT    -- extracted ATT&CK IDs [T1190, ...]
references_json              TEXT
notes                  TEXT
source_version         VARCHAR(50)
url                    VARCHAR(500)
-- UNIQUE INDEX: (dataset_version_id, capec_id)
```

### `capec_relationship`
```sql
dataset_version_id     VARCHAR(100)
source_capec_id        VARCHAR(20)
target_capec_id        VARCHAR(20)
nature                 VARCHAR(50)   -- ChildOf, ParentOf, CanPrecede, etc.
view_id                VARCHAR(20)
-- UNIQUE INDEX: (dataset_version_id, source_capec_id, target_capec_id, nature)
```

### `capec_cwe`
```sql
dataset_version_id     VARCHAR(100)
capec_id               VARCHAR(20)
cwe_id                 VARCHAR(20)
nature                 VARCHAR(50)   -- "Exploits"
-- UNIQUE INDEX: (dataset_version_id, capec_id, cwe_id)
```

### `capec_attack`
```sql
dataset_version_id     VARCHAR(100)
capec_id               VARCHAR(20)
attack_technique_id    VARCHAR(50)   -- e.g. T1190
taxonomy_name          VARCHAR(100)
-- UNIQUE INDEX: (dataset_version_id, capec_id, attack_technique_id)
```

## Bidirectional CWE→CAPEC Lookup

The knowledge graph supports two traversal paths:

**Path 1** — from CWE's XML data:
```
CWE.related_attack_patterns → ["CAPEC-86", "CAPEC-198"]
```

**Path 2** — from CAPEC's CWE references (reverse lookup):
```
capec_cwe table WHERE cwe_id = "CWE-89" → CAPEC-66, CAPEC-7, ...
```

`KnowledgeGraphService.get_cve_knowledge` uses both paths to ensure complete graph traversal regardless of which direction the cross-reference was defined.

## Version Management and Rollback

```
Pipeline run creates:
  dataset_version (CREATED → ACTIVE)
  capec_attack_pattern rows tagged with version_id
  capec_relationship rows tagged with version_id
  capec_cwe rows tagged with version_id
  capec_attack rows tagged with version_id

Rollback:
  set_active_dataset_version("mitre_capec_xml", "capec-v001")
  → old version ACTIVE, new version ARCHIVED
  → queries without version_id automatically use the active version
```

## Knowledge Graph Position

```
CVE
 │
 ▼
CWE ─── related_attack_patterns ──────────────────▶ CAPEC (direct)
         │
         │ (capec_cwe reverse)
         ▼
        CAPEC
         │
         ├── execution_flow ────────────────────────▶ Step-by-step attack procedure
         ├── mitigations ───────────────────────────▶ Mitigation guidance
         ├── detection ─────────────────────────────▶ Detection methods
         ├── related_attack_patterns (CAPEC→CAPEC) ──▶ Abstraction hierarchy
         └── attack_technique_ids ──────────────────▶ ATT&CK techniques
                                                          │
                                                          ▼
                                                     ATT&CK technique
                                                     (via mitre_attack_object table)
```

## Statistics Coverage

| Metric | Description |
|--------|-------------|
| `execution_flow_coverage_pct` | % of patterns with execution flow steps |
| `mitigation_coverage_pct` | % of patterns with mitigations |
| `cwe_coverage_pct` | % of patterns with CWE references |
| `attack_coverage_pct` | % of patterns with ATT&CK references |
| `by_abstraction` | Count by Meta/Standard/Detailed |
| `by_typical_severity` | Count by High/Medium/Low |
| `by_likelihood_of_attack` | Count by High/Medium/Low |
| `total_execution_steps` | Total steps across all execution flows |

## Event Publishing

| Event | When Published |
|-------|---------------|
| `CapecImportStarted` | Pipeline begins |
| `CapecImportCompleted` | Pipeline completes successfully |
| `CapecImportFailed` | Any stage fails |
| `CanonicalCapecCreated` | New CAPEC registered in CIIL |
| `CapecCweMappingCreated` | New CAPEC→CWE cross-reference created |
| `CapecDatasetActivated` | Dataset version activated |
| `KnowledgeGraphUpdated` | After relationships and mappings built |
