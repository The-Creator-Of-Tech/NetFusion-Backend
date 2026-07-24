# IL-8 — Unified Threat Knowledge Graph (UTKG)

> **NetFusion Enterprise Intelligence Layer 8**
> The central intelligence backbone connecting every canonical entity from IL-1 through IL-7.

---

## Overview

The Unified Threat Knowledge Graph (UTKG) is a fully SQL-backed, schema-free graph layer that materialises every intelligence object from the existing NetFusion pipelines as canonical graph nodes and directed edges. It becomes the single reasoning layer for:

- Graph traversal and multi-hop correlation
- Relationship discovery across all intelligence domains
- Shortest-path and attack-chain reconstruction
- AI-assisted investigation enrichment
- Risk and confidence propagation
- Frontend visualisation (Cytoscape.js, React Flow, D3.js, Sigma.js, Neo4j Browser)
- Export to JSON, GraphML, GEXF, CSV, DOT, Mermaid

---

## Module Structure

```
netfusion_intelligence/graph/
├── __init__.py           — Public API exports
├── models.py             — Domain models: GraphNode, GraphEdge, GraphPath, …
├── tables.py             — SQLAlchemy ORM tables (graph_nodes, graph_edges, …)
├── repository.py         — GraphRepository — SQL-backed persistence, upsert, versioning
├── traversal.py          — GraphTraversalEngine — BFS, DFS, K-Hop, components, cycles
├── pathfinder.py         — GraphPathFinder — shortest path, Dijkstra, all-simple, ranking
├── search.py             — GraphSearchEngine — full-text, investigation queries, AI context
├── relationships.py      — GraphRelationshipManager — edge lifecycle, confidence propagation
├── statistics.py         — GraphStatisticsEngine — topology metrics, degree distribution
├── export.py             — GraphExportService — JSON/GraphML/GEXF/CSV/DOT/Mermaid
├── visualization.py      — GraphVisualizationBuilder — Cytoscape/ReactFlow/D3/Sigma/Neo4j
├── fusion.py             — KnowledgeFusionEngine — IL-1..IL-7 → graph materialisation
├── events.py             — UTKG domain events (GraphNodeCreated, GraphMerged, …)
├── service.py            — UnifiedThreatKnowledgeGraph — high-level facade
├── api.py                — FastAPI router under /intelligence/graph/*
└── tests/
    ├── conftest.py
    ├── test_repository.py
    ├── test_traversal.py
    ├── test_pathfinder.py
    ├── test_search.py
    ├── test_statistics.py
    ├── test_export.py
    ├── test_visualization.py
    ├── test_fusion.py
    ├── test_rollback.py
    ├── test_api.py
    └── test_service.py
```

---

## Node Types

All 50+ node types are defined in `GraphNodeType`. Key types:

| Category | Node Types |
|---|---|
| Asset / Infrastructure | `asset`, `host`, `device`, `network`, `software`, `os`, `application`, `package`, `service`, `port`, `protocol` |
| Identity | `user`, `identity`, `group`, `organization` |
| Investigation | `project`, `investigation`, `alert`, `detection`, `finding` |
| IOC (IL-7) | `ioc`, `domain`, `url`, `ip`, `hash`, `email`, `certificate`, `ja3` |
| Threat Intel | `malware`, `campaign`, `threat_actor`, `attack_group` |
| MITRE (IL-2) | `attack_technique`, `attack_tactic` |
| CAPEC (IL-6) | `capec` |
| CWE (IL-6) | `cwe` |
| CVE/KEV/EPSS | `cve`, `kev`, `epss_record` |
| Evidence | `evidence`, `packet`, `flow`, `dns_record`, `http_session`, `tls_session`, `process`, `registry`, `file` |
| Workflow | `playbook`, `workflow`, `rule`, `case`, `timeline_event`, `report` |

---

## Edge Types

30+ edge types covering the full intelligence relationship vocabulary. Key edges:

`USES`, `TARGETS`, `EXPLOITS`, `OBSERVED_ON`, `COMMUNICATES_WITH`, `HOSTS`, `CONNECTS_TO`, `RESOLVES_TO`, `GENERATES`, `DOWNLOADS`, `DROPS`, `CREATES`, `EXECUTES`, `MODIFIES`, `READS`, `WRITES`, `BELONGS_TO`, `RELATED_TO`, `DETECTED_BY`, `MITIGATED_BY`, `REFERENCES`, `PART_OF`, `ASSOCIATED_WITH`, `AFFECTS`, `HAS_EVIDENCE`, `USES_TECHNIQUE`, `USES_WEAKNESS`, `USES_ATTACK_PATTERN`, `LINKED_TO`, `HAS_WEAKNESS`, `EXPLOITED_BY`, `MAPS_TO`, `HAS_KEV`, `HAS_EPSS`, `IOC_TO_MALWARE`, `IOC_TO_CAMPAIGN`, `IOC_TO_TECHNIQUE`, `IOC_TO_CAPEC`, `IOC_TO_CWE`, `IOC_TO_CVE`, `PARENT_OF`, `CHILD_OF`, `SUBTECHNIQUE_OF`

Every edge stores: `confidence`, `weight`, `evidence_count`, `source_feed`, `version`, `created_at`, `updated_at`.

---

## Database Schema

Six new tables, all extending the shared SQLAlchemy `Base`:

| Table | Purpose |
|---|---|
| `graph_nodes` | All graph vertices with canonical_id, node_type, label, properties |
| `graph_edges` | All directed edges with type, confidence, weight, evidence_count |
| `graph_versions` | Version snapshots for rollback support |
| `graph_statistics` | Persisted topology statistics snapshots |
| `graph_paths` | Cached computed paths for investigation acceleration |
| `graph_exports` | Record of completed export operations |

Key constraints:
- `graph_nodes`: `UNIQUE(canonical_id, node_type)` — no duplicate canonical entities
- `graph_edges`: `UNIQUE(source_node_id, target_node_id, edge_type)` — no duplicate edges
- All tables are indexed for high-performance lookup by type, feed, confidence, and timestamps

---

## Knowledge Fusion Chain

`KnowledgeFusionEngine.fuse_all()` runs the full pipeline:

```
ATT&CK (IL-2)
    ↓  MAPS_TO
CAPEC (IL-6)
    ↓  USES_WEAKNESS
CWE (IL-6)
    ↑  HAS_WEAKNESS
CVE (IL-3)
    ↓  LINKED_TO
KEV (IL-4)  ←→  EPSS (IL-5)
    ↑
IOC (IL-7)
    ↓
Malware → Campaign → Threat Actor → ATT&CK
```

All fusion operations are **idempotent** — running twice produces the same graph. Canonical IDs are stable across runs:
- CVE nodes: `canonical_id = "cve-{cve_id}"`
- KEV nodes: `canonical_id = "kev-{cve_id}"`, `external_id = "KEV:{cve_id}"`
- IOC nodes: `canonical_id = "{ioc_type}:{value}"`

---

## REST API

All endpoints mounted at `/intelligence/graph/` (registered in `netfusion_intelligence/api/routes.py`):

### Core
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/node/{id}` | Get a single node |
| `GET` | `/graph/node/{id}/neighbors` | Get neighbors + edges |
| `POST` | `/graph/nodes` | Add/update a node |
| `POST` | `/graph/edges` | Add/update an edge |

### Algorithms
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/traverse` | BFS/DFS/K-Hop from a start node |
| `GET` | `/graph/path` | Shortest / Dijkstra / all-simple path |
| `GET` | `/graph/subgraph` | Extract bounded subgraph |
| `GET` | `/graph/search` | Full-text node search |

### Analytics
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/statistics` | Topology statistics |
| `GET` | `/graph/statistics/nodes` | Node type breakdown |
| `GET` | `/graph/statistics/edges` | Edge type breakdown |
| `GET` | `/graph/statistics/hub-nodes` | Top-N most-connected nodes |

### Export & Visualisation
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/export` | Export in JSON/GraphML/GEXF/CSV/DOT/Mermaid |
| `GET` | `/graph/visualization` | Frontend payload (Cytoscape/ReactFlow/D3/Sigma/Neo4j) |

### Investigation Queries
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/query/iocs-for-cve/{cve_id}` | All IOCs linked to a CVE |
| `GET` | `/graph/query/techniques-for-actor/{actor_id}` | ATT&CK techniques for an actor |
| `GET` | `/graph/query/campaigns-for-ioc` | Campaigns related to an IOC |
| `GET` | `/graph/query/assets-exposed-to-kev/{cve_id}` | Assets exposed to a KEV |
| `GET` | `/graph/query/investigations-for-ioc` | Investigations containing an IOC |
| `GET` | `/graph/query/evidence-for-report/{node_id}` | Evidence for a report |
| `GET` | `/graph/query/attack-chain/{node_id}` | Full attack chain reconstruction |
| `GET` | `/graph/query/shortest-path` | Shortest path between two nodes |

### Knowledge Fusion
| Method | Path | Description |
|---|---|---|
| `POST` | `/graph/fusion` | Full IL-1..IL-7 fusion |
| `POST` | `/graph/fusion/{layer}` | Single-layer fusion |

### Versioning
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/versions` | List all versions |
| `POST` | `/graph/versions` | Create a new version snapshot |
| `POST` | `/graph/versions/{id}/rollback` | Rollback to a previous version |

### AI Foundation
| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/ai/expand-context/{node_id}` | Expand context for LLM reasoning |
| `GET` | `/graph/ai/related-entities/{node_id}` | Find related entities by type |
| `GET` | `/graph/ai/rank-relationships/{node_id}` | Top-N ranked relationships |
| `GET` | `/graph/ai/confidence-propagation/{node_id}` | Propagate confidence outward |

---

## Supported Graph Algorithms

| Algorithm | Class | Notes |
|---|---|---|
| Breadth-First Search | `GraphTraversalEngine.bfs()` | Default traversal |
| Depth-First Search | `GraphTraversalEngine.dfs()` | Iterative, no stack overflow |
| K-Hop Traversal | `GraphTraversalEngine.k_hop()` | Exactly k hops away |
| Neighborhood Search | `GraphTraversalEngine.neighborhood()` | Within radius r |
| Reachability | `GraphTraversalEngine.can_reach()` | Boolean check |
| Connected Components | `GraphTraversalEngine.find_connected_components()` | BFS-based |
| Cycle Detection | `GraphTraversalEngine.has_cycle()` | DFS with back-edge detection |
| Relationship Expansion | `GraphTraversalEngine.expand_relationships()` | Grouped by edge type |
| Shortest Path (BFS) | `GraphPathFinder.shortest_path()` | Unweighted |
| Shortest Path (Dijkstra) | `GraphPathFinder.shortest_path_weighted()` | Edge-weight aware |
| All Simple Paths | `GraphPathFinder.all_simple_paths()` | Up to configurable limit |
| Path Ranking | `GraphPathFinder.rank_paths()` | By length, confidence, weight |
| Attack Chain Reconstruction | `GraphPathFinder.reconstruct_attack_chain()` | Investigation-specific |

---

## Visualisation Support

The `GraphVisualizationBuilder` produces ready-to-use payloads for five graph rendering libraries:

| Library | Method | Format |
|---|---|---|
| **Cytoscape.js** | `build_cytoscape()` | `{elements: {nodes, edges}}` with style |
| **React Flow** | `build_react_flow()` | `{nodes, edges}` with positions |
| **D3.js** | `build_d3_force()` | `{nodes, links}` with group/color |
| **Sigma.js** | `build_sigma()` | `{nodes, edges}` with x/y coordinates |
| **Neo4j Browser** | `build_neo4j_browser()` | `{nodes, edges, cypher_create}` |

Positions are computed with a radial layout algorithm (center node at origin, outer rings for neighbors).
Node colors are defined per type (red=CVE, purple=malware, blue=ATT&CK, green=IOC, etc.).

---

## Domain Events

The UTKG publishes events to the shared `EventBus`:

| Event | Trigger |
|---|---|
| `GraphNodeCreated` | New node inserted |
| `GraphEdgeCreated` | New edge inserted |
| `GraphMerged` | Fusion run completed |
| `GraphTraversalExecuted` | Traversal operation completed |
| `GraphExported` | Export completed |
| `GraphStatisticsUpdated` | Statistics recomputed |
| `GraphVersionCreated` | New version snapshot |
| `GraphRolledBack` | Rollback to previous version |

---

## Configuration

| Constant | Default | Description |
|---|---|---|
| `UTKG_ENGINE_VERSION` | `utkg-engine-v1` | Engine version string |
| `UTKG_DEFAULT_MAX_DEPTH` | `3` | Default BFS/DFS depth |
| `UTKG_DEFAULT_NODE_LIMIT` | `500` | Default node limit per traversal |
| `UTKG_CONFIDENCE_DECAY` | `0.8` | Per-hop confidence decay factor |
| `UTKG_STATS_SAMPLE_SIZE` | `5000` | Node sample for statistics |
| `UTKG_PATH_CACHE_LIMIT` | `10000` | Max cached paths in DB |
| `UTKG_DB_URL` (env) | `sqlite:///./utkg.db` | Database URL override |

---

## Quick Start

```python
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph

# Wire up
repo = GraphRepository(db_url="sqlite:///./utkg.db")
utkg = UnifiedThreatKnowledgeGraph(
    graph_repository=repo,
    intelligence_repository=intel_repo,   # SQLAlchemyIntelligenceRepository
)

# Run knowledge fusion (IL-1..IL-7 → graph)
result = utkg.run_fusion()

# Investigation queries
iocs = utkg.iocs_for_cve("CVE-2021-44228")
chain = utkg.reconstruct_attack_chain(investigation_node_id)
path  = utkg.find_path(host_node_id, malware_node_id)

# AI reasoning
context = utkg.expand_context(node_id, depth=3)
ranked  = utkg.rank_relationships(node_id)
```

---

## Testing

```bash
python -m pytest netfusion_intelligence/graph/tests/ -v
```

214 tests covering repository, traversal, path-finding, search, statistics, export, visualisation, fusion, rollback, API, and service integration.
