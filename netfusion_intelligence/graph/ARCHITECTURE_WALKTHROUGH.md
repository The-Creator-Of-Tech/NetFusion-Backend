# IL-8 UTKG — Architecture Walkthrough

> **NetFusion Unified Threat Knowledge Graph**
> Deep-dive into every architectural decision, data flow, and integration point.

---

## 1. Design Philosophy

The UTKG is intentionally **not** a native graph database. It is a **SQL-backed graph layer** built on the same SQLAlchemy infrastructure that already powers IL-1 through IL-7. This decision preserves:

- **Zero new infrastructure dependencies** — runs on the same SQLite (dev) or PostgreSQL (production) instance already in use
- **Transactional consistency** — every node and edge write participates in ACID transactions
- **Backward compatibility** — no existing APIs, tables, or services are touched
- **Operational simplicity** — no Neo4j, JanusGraph, or ArangoDB to operate
- **Scalability path** — the schema is designed to migrate to a dedicated graph DB if needed in future (GraphML and GEXF exports make this straightforward)

The graph scales to millions of nodes via:
- Composite index on `(canonical_id, node_type)` for O(1) deduplication
- Index on `(source_node_id, target_node_id, edge_type)` for O(1) edge deduplication
- SQL aggregation for statistics (no in-memory full-graph loading)
- Sampling strategies for topology metrics (degree distribution, APL) on large graphs
- BFS/DFS implemented with SQL adjacency lookups per hop — only the active frontier is ever in memory

---

## 2. Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         REST API Layer                           │
│              /intelligence/graph/* (FastAPI router)              │
│                           api.py                                 │
└─────────────────────────────┬───────────────────────────────────┘
                               │
┌─────────────────────────────▼───────────────────────────────────┐
│                    Service Facade Layer                           │
│               UnifiedThreatKnowledgeGraph                        │
│                         service.py                               │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┬───────┘
   │          │          │          │          │          │
┌──▼──┐ ┌────▼───┐ ┌────▼────┐ ┌───▼───┐ ┌───▼───┐ ┌────▼────┐
│Trav-│ │  Path  │ │ Search │ │Stats │ │Export│ │  Viz   │
│ersal│ │ Finder │ │ Engine │ │Engine│ │ Svc  │ │Builder │
└──┬──┘ └────┬───┘ └────┬────┘ └───┬───┘ └───┬───┘ └────┬────┘
   │          │          │          │          │          │
┌──▼──────────▼──────────▼──────────▼──────────▼──────────▼──────┐
│                    Graph Repository Layer                         │
│                       GraphRepository                             │
│              Upsert · Versioning · Rollback · Cache              │
└─────────────────────────────┬───────────────────────────────────┘
                               │
┌─────────────────────────────▼───────────────────────────────────┐
│                      Database Layer                               │
│      graph_nodes · graph_edges · graph_versions                  │
│      graph_statistics · graph_paths · graph_exports             │
│              SQLAlchemy ORM  (SQLite / PostgreSQL)               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  Knowledge Fusion Engine                          │
│                       fusion.py                                   │
│   IL-2 ATT&CK → IL-6 CAPEC → IL-6 CWE → IL-3 CVE               │
│   → IL-4 KEV → IL-5 EPSS → IL-7 IOC → Cross-Layer Edges        │
│          Reads from: SQLAlchemyIntelligenceRepository            │
│          Writes to:  GraphRepository                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Model Deep Dive

### 3.1 GraphNode

Every intelligence object becomes a `GraphNode`. The two identity fields are critical:

```
canonical_id  ←  CIIL UUID (globally unique across NetFusion)
node_id       ←  Graph-internal stable UUID (assigned at first insert)
external_id   ←  Human-readable ID (CVE-2021-44228, T1059, CWE-502, KEV:CVE-…)
```

Deduplication key: `UNIQUE(canonical_id, node_type)`.
- Two entities with the same `canonical_id` but different `node_type` are distinct nodes
- This handles cases like CVE-2021-44228 appearing as both a `cve` node and having an associated `kev` node and `epss_record` node — three different node types, three distinct records

The `properties` JSON blob stores type-specific metadata without polluting the schema with nullable columns.

### 3.2 GraphEdge

Every relationship is a directed `GraphEdge`:

```
source_node_id  →  target_node_id   (via edge_type)
```

Deduplication key: `UNIQUE(source_node_id, target_node_id, edge_type)`.
When the same edge is inserted twice, `upsert_edge` takes the higher confidence, accumulates `evidence_count`, and increments `version`.

The `weight` field controls path-finding cost in Dijkstra: higher weight = stronger relationship = cheaper path.

### 3.3 Canonical Identity Contract

Every node MUST reference an existing canonical UUID from the CIIL layer. The `KnowledgeFusionEngine` enforces this by deriving stable canonical IDs from source entity identifiers:

| Source | Canonical ID Pattern |
|---|---|
| ATT&CK Technique | `stix_id` (from STIX 2.1) |
| CVE | `cve-{cve_id}` |
| CWE | `cwe-{cwe_id}` |
| CAPEC | `capec-{capec_id}` |
| KEV | `kev-{cve_id}` |
| EPSS | `epss-{cve_id}` |
| IOC | `{ioc_type}:{value}` |
| Malware (IOC-derived) | `malware-{name-slug}` |
| Campaign (IOC-derived) | `campaign-{name-slug}` |

This scheme ensures:
- Re-running fusion produces identical canonical IDs → upsert semantics → no duplicates
- The same CVE referenced by NVD, KEV, and EPSS all create edges to the same `cve` node

---

## 4. Knowledge Fusion Pipeline

### 4.1 Fusion Order

Fusion layers are ordered by dependency — each layer's edges require prior layers' nodes:

```
1. fuse_mitre()    → ATT&CK Technique, Tactic, Group, Malware, Campaign nodes
                     STIX relationship edges between them
2. fuse_capec()    → CAPEC nodes + MAPS_TO→ATT&CK + USES_WEAKNESS→CWE edges
3. fuse_cwe()      → CWE nodes + PARENT_OF/RELATED_TO edges between CWEs
4. fuse_cve()      → CVE nodes + HAS_WEAKNESS→CWE edges
5. fuse_kev()      → KEV nodes + HAS_KEV→CVE edges
6. fuse_epss()     → EPSS_RECORD nodes + HAS_EPSS→CVE edges
7. fuse_ioc()      → IOC/IP/Domain/Hash/Email/Cert nodes
                     IOC_TO_MALWARE, IOC_TO_CAMPAIGN, IOC_TO_TECHNIQUE, IOC_TO_CVE
8. fuse_cross()    → Ensures CVE↔KEV bidirectional edges are complete
                     CAPEC→ATT&CK cross-reference verification
```

### 4.2 Idempotency Guarantee

Every fusion operation uses `upsert_node` and `upsert_edge`:
- Nodes: `UPSERT ON (canonical_id, node_type)` — updates existing, inserts new
- Edges: `UPSERT ON (source_node_id, target_node_id, edge_type)` — accumulates evidence, takes max confidence

Running `fuse_all()` twice produces identical node and edge counts.

### 4.3 `fuse_intelligence_nodes` Helper

`GraphRelationshipManager.fuse_intelligence_nodes()` is the bridge between domain IDs and graph node IDs:

```python
def fuse_intelligence_nodes(
    source_external_id, source_type,
    target_external_id, target_type,
    edge_type, confidence, source_feed
) -> Optional[Tuple[GraphEdge, bool]]:
```

1. Resolves `source_external_id` → `GraphNode` via `get_node_by_external_id()`
2. Resolves `target_external_id` → `GraphNode` via `get_node_by_external_id()`
3. If either node doesn't exist yet → returns `None` (graceful degradation)
4. Creates the edge between the two resolved node IDs

This means fusion is **order-independent for edges** — if the target node doesn't exist yet, the edge is simply skipped. Running fusion again after the target layer populates that node will then create the edge.

---

## 5. Graph Repository — Persistence Layer

### 5.1 Session Management

Every repository method opens a new SQLAlchemy session via `self._s()` and uses it as a context manager. Sessions are auto-committed on success and rolled back on exception. No session is shared across method calls — this prevents connection leakage and is safe for concurrent access.

### 5.2 Upsert Semantics

```python
# Node upsert — dedup key: (canonical_id, node_type)
existing = session.query(GraphNodeModel).filter_by(
    canonical_id=node.canonical_id,
    node_type=node.node_type,
).first()

if existing:
    # Update all fields, increment version
else:
    # Insert new record
```

```python
# Edge upsert — dedup key: (source_node_id, target_node_id, edge_type)
existing = session.query(GraphEdgeModel).filter_by(
    source_node_id=edge.source_node_id,
    target_node_id=edge.target_node_id,
    edge_type=edge.edge_type,
).first()

if existing:
    # Take max(confidence), accumulate evidence_count, increment version
else:
    # Insert new record
```

### 5.3 Version Management

```
create_version() → sets new version ACTIVE, marks all others INACTIVE
rollback_to_version(vid) → marks target ACTIVE, marks current INACTIVE
list_versions() → ordered by version_number DESC
```

Version records track `node_count` and `edge_count` at time of snapshot. The graph data itself is not snapshotted per-version — versioning tracks **which version is the logical current state**. A full point-in-time snapshot requires exporting the graph at the desired version (use `export_graph()`).

---

## 6. Traversal Engine — Algorithm Design

### 6.1 SQL-Backed BFS

Instead of loading the entire adjacency list into memory, each BFS iteration makes a SQL query for the current node's edges:

```
queue = [(start_node, depth=0)]
while queue:
    current, depth = queue.popleft()
    if depth >= max_depth: continue
    edges = repo.get_edges_for_node(current.node_id)   # SQL query per hop
    for edge in edges:
        neighbor_id = edge.target if outgoing else edge.source
        if neighbor_id not in visited:
            visited[neighbor_id] = depth + 1
            queue.append((neighbor, depth + 1))
```

**Trade-off**: More SQL queries than in-memory BFS, but memory usage is O(frontier) not O(graph). For investigation-depth traversals (max_depth=3–5), this is extremely efficient.

### 6.2 Path Caching

Computed paths are stored in `graph_paths` table. `shortest_path(use_cache=True)` checks the cache before computing. Cache entries are keyed on `(source_node_id, target_node_id)`. The most recent computation wins.

### 6.3 Cycle Detection

DFS with an `in_stack` set (iterative, not recursive) detects back-edges. A back-edge from a node to an ancestor in the current DFS stack indicates a cycle:

```python
in_stack = set()
visited = set()

def dfs(node_id, depth):
    if node_id in in_stack: return True   # back-edge = cycle
    if node_id in visited: return False
    in_stack.add(node_id)
    for edge in outgoing_edges(node_id):
        if dfs(edge.target, depth+1): return True
    in_stack.remove(node_id)
    return False
```

---

## 7. Path Finder — Algorithm Design

### 7.1 BFS Shortest Path

Standard BFS guarantees the shortest path in an unweighted graph. The `parent` map tracks `{node_id: (parent_id, edge_id)}` for path reconstruction.

### 7.2 Dijkstra Weighted Path

Edge cost = `1.0 / max(weight, 0.001)` — inverting weight so higher-weight edges are **cheaper** (preferred). This means "stronger" relationships (higher trust/evidence) form the preferred path, which is semantically correct for intelligence traversal.

### 7.3 Path Ranking

Paths are ranked by a composite key:
```python
key = (length ASC, -avg_confidence DESC, -total_weight DESC)
```

Shorter, higher-confidence, higher-evidence paths rank first.

### 7.4 Attack Chain Reconstruction

```
investigation_node → BFS(max_depth=8) → all reachable nodes
                                         ↓ classify by node_type
        evidence | ioc | malware | campaign | threat_actor
        attack_technique | capec | cwe | cve | kev | epss
```

This gives the analyst a complete, layered view of the attack from network evidence through to the vulnerability intelligence chain.

---

## 8. Search Engine — Investigation Queries

All investigation queries follow the same pattern:

1. Resolve the seed entity (by `external_id` or text search)
2. Run BFS up to the required depth
3. Filter the traversal result by target node type(s)
4. Return structured result with counts and node dicts

The `expand_context()` method groups traversal results by `node_type` — this is the primary AI reasoning primitive, giving the LLM a structured neighborhood view:

```json
{
  "node_id": "...",
  "context_by_type": {
    "cwe": [...],
    "attack_technique": [...],
    "ioc": [...]
  },
  "total_context_nodes": 47
}
```

---

## 9. Statistics Engine — Topology Metrics

### 9.1 Fast Metrics (SQL aggregation)

- `node_count` / `edge_count`: `SELECT COUNT(*)`
- `node_types` / `edge_types`: `GROUP BY type`
- `average_degree`: `2 * edge_count / node_count`
- `relationship_density`: `edge_count / (node_count * (node_count - 1))`

### 9.2 Sampled Metrics (in-memory, bounded)

- **Degree distribution**: Sample up to `UTKG_STATS_SAMPLE_SIZE` nodes, compute degree for each via SQL count
- **Connected components**: BFS-based on a sample of up to 2000 nodes
- **Average path length**: BFS from up to 20 random nodes, average their depth sums

These use bounded samples to maintain O(1) memory for large production graphs. The sample sizes are configurable via constants.

---

## 10. Export Engine — Format Details

| Format | Use Case | Tool |
|---|---|---|
| **JSON** | API integration, programmatic consumption | Any JSON parser |
| **GraphML** | Industry-standard XML graph interchange | yEd, Gephi, NetworkX |
| **GEXF** | Gephi native format with rich metadata | Gephi |
| **CSV** | Spreadsheet analysis, data pipelines | Excel, Pandas |
| **DOT** | Graphviz static rendering | `dot -Tpng graph.dot -o graph.png` |
| **Mermaid** | Inline diagram in Markdown / documentation | GitHub, GitLab, Notion |

XML formats (GraphML, GEXF) escape special characters with `_xml_escape()` to prevent injection.
DOT format colour-codes nodes by type for visual clarity.
Mermaid export limits to 50 nodes / 80 edges to keep diagrams readable.

---

## 11. Visualisation Builder — Layout Algorithm

The radial layout used by React Flow and Sigma.js:

```
Center node (the seed)  →  position (0, 0)
Ring 1 (6 nodes max)    →  radius = 200, evenly spaced angles
Ring 2 (12 nodes max)   →  radius = 400, evenly spaced angles
Ring k (k*6 nodes max)  →  radius = k*200
```

This produces a clean, scalable layout without requiring a force-directed simulation on the server. The frontend can optionally apply physics simulation on top of these seed positions.

---

## 12. API Integration — Route Registration

The UTKG router is mounted inside the existing intelligence routes file with zero modification to existing routes:

```python
# netfusion_intelligence/api/routes.py (addition only)
from netfusion_intelligence.graph.api import router as utkg_router, set_utkg

# Lazy singleton init — wires graph repo to intel repo
_utkg_service_instance = None
def _get_or_init_utkg():
    # Creates GraphRepository with UTKG_DB_URL env var
    # Wires intelligence_repository = get_intelligence_engine().repository
    ...

# Override the module-level getter for test isolation
_utkg_api_module.get_utkg = _patched_get_utkg

# Mount under /intelligence prefix
router.include_router(utkg_router)
```

All UTKG endpoints are thus accessible at `/intelligence/graph/*`.

---

## 13. AI Foundation — Reasoning Services

The following services are exposed by `UnifiedThreatKnowledgeGraph` specifically for AI reasoning layers:

| Service | Method | AI Use Case |
|---|---|---|
| **Context Expansion** | `expand_context(node_id, depth)` | Build LLM prompt context from neighborhood |
| **Related Entities** | `find_related_entities(node_id, target_type)` | "What malware is associated with this CVE?" |
| **Relationship Ranking** | `rank_relationships(node_id, top_n)` | Identify the most significant connections |
| **Confidence Propagation** | `propagate_confidence(node_id, decay)` | Score risk across connected nodes |
| **Attack Chain** | `reconstruct_attack_chain(inv_id)` | Build full investigation context |
| **Reachability** | `can_reach(source, target)` | "Is this host connected to this malware?" |

The confidence propagation algorithm:
```
C(node) = C(parent) × decay × edge.confidence
```
Starting from a high-confidence seed (e.g., a confirmed IOC), confidence flows outward with each hop, decaying by the configured factor. This models "guilt by association" for risk scoring.

---

## 14. Backward Compatibility

The UTKG is **strictly additive**:

- No existing table is modified
- No existing API route is changed
- No existing service is altered
- The existing `KnowledgeGraphService` (IL-6 in-memory graph) continues to operate unchanged
- The new UTKG co-exists with and complements the existing service
- The intelligence `SQLAlchemyIntelligenceRepository` is consumed read-only by the fusion engine

---

## 15. File Inventory

| File | LOC (approx) | Purpose |
|---|---|---|
| `models.py` | 390 | Domain entities |
| `tables.py` | 130 | SQLAlchemy ORM |
| `repository.py` | 420 | SQL persistence |
| `traversal.py` | 280 | BFS/DFS/K-Hop/Components/Cycles |
| `pathfinder.py` | 290 | Shortest/Dijkstra/All-Simple/Ranking |
| `search.py` | 290 | Full-text + investigation queries |
| `relationships.py` | 170 | Edge lifecycle + confidence propagation |
| `statistics.py` | 230 | Topology metrics |
| `export.py` | 290 | 6 export formats |
| `visualization.py` | 350 | 5 visualization targets |
| `fusion.py` | 380 | IL-1..IL-7 → graph materialisation |
| `events.py` | 60 | Domain events |
| `service.py` | 300 | High-level facade |
| `api.py` | 380 | 34 REST endpoints |
| `tests/` | ~1 300 | 214 automated tests |
| `README.md` | — | User documentation |
| `ARCHITECTURE_WALKTHROUGH.md` | — | This document |
| `VERIFICATION_REPORT.md` | — | Test results and coverage |

**Total: ~4 500 lines of production code + ~1 300 lines of tests**
