"""
IL-8 UTKG — Domain Models
===========================
Immutable dataclasses representing every graph entity.
All nodes reference canonical CIIL UUIDs.  No duplicate identities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import uuid


# ---------------------------------------------------------------------------
# Node Type Taxonomy  (canonical — matches every IL-1 … IL-7 entity)
# ---------------------------------------------------------------------------

class GraphNodeType(str, Enum):
    # Asset / Infrastructure
    ASSET            = "asset"
    HOST             = "host"
    DEVICE           = "device"
    NETWORK          = "network"
    SOFTWARE         = "software"
    OPERATING_SYSTEM = "operating_system"
    APPLICATION      = "application"
    PACKAGE          = "package"
    SERVICE          = "service"
    PORT             = "port"
    PROTOCOL         = "protocol"
    # Identity
    USER             = "user"
    IDENTITY         = "identity"
    GROUP            = "group"
    ORGANIZATION     = "organization"
    # Investigation
    PROJECT          = "project"
    INVESTIGATION    = "investigation"
    ALERT            = "alert"
    DETECTION        = "detection"
    FINDING          = "finding"
    # IOC variants (IL-7)
    IOC              = "ioc"
    DOMAIN           = "domain"
    URL              = "url"
    IP               = "ip"
    HASH             = "hash"
    EMAIL            = "email"
    CERTIFICATE      = "certificate"
    JA3              = "ja3"
    # Threat intelligence
    MALWARE          = "malware"
    CAMPAIGN         = "campaign"
    THREAT_ACTOR     = "threat_actor"
    ATTACK_GROUP     = "attack_group"
    # MITRE (IL-2)
    ATTACK_TECHNIQUE = "attack_technique"
    ATTACK_TACTIC    = "attack_tactic"
    # CAPEC (IL-6)
    CAPEC            = "capec"
    # CWE (IL-6)
    CWE              = "cwe"
    # CVE / KEV / EPSS (IL-3 / IL-4 / IL-5)
    CVE              = "cve"
    KEV              = "kev"
    EPSS_RECORD      = "epss_record"
    # Evidence / Network
    EVIDENCE         = "evidence"
    PACKET           = "packet"
    FLOW             = "flow"
    DNS_RECORD       = "dns_record"
    HTTP_SESSION     = "http_session"
    TLS_SESSION      = "tls_session"
    PROCESS          = "process"
    REGISTRY         = "registry"
    FILE             = "file"
    # Workflow / Automation
    PLAYBOOK         = "playbook"
    WORKFLOW         = "workflow"
    RULE             = "rule"
    CASE             = "case"
    TIMELINE_EVENT   = "timeline_event"
    REPORT           = "report"
    # Generic
    UNKNOWN          = "unknown"


# ---------------------------------------------------------------------------
# Edge Type Taxonomy
# ---------------------------------------------------------------------------

class GraphEdgeType(str, Enum):
    USES                = "USES"
    TARGETS             = "TARGETS"
    EXPLOITS            = "EXPLOITS"
    OBSERVED_ON         = "OBSERVED_ON"
    COMMUNICATES_WITH   = "COMMUNICATES_WITH"
    HOSTS               = "HOSTS"
    CONNECTS_TO         = "CONNECTS_TO"
    RESOLVES_TO         = "RESOLVES_TO"
    GENERATES           = "GENERATES"
    DOWNLOADS           = "DOWNLOADS"
    DROPS               = "DROPS"
    CREATES             = "CREATES"
    EXECUTES            = "EXECUTES"
    MODIFIES            = "MODIFIES"
    READS               = "READS"
    WRITES              = "WRITES"
    BELONGS_TO          = "BELONGS_TO"
    RELATED_TO          = "RELATED_TO"
    DETECTED_BY         = "DETECTED_BY"
    MITIGATED_BY        = "MITIGATED_BY"
    REFERENCES          = "REFERENCES"
    PART_OF             = "PART_OF"
    ASSOCIATED_WITH     = "ASSOCIATED_WITH"
    AFFECTS             = "AFFECTS"
    HAS_EVIDENCE        = "HAS_EVIDENCE"
    USES_TECHNIQUE      = "USES_TECHNIQUE"
    USES_WEAKNESS       = "USES_WEAKNESS"
    USES_ATTACK_PATTERN = "USES_ATTACK_PATTERN"
    LINKED_TO           = "LINKED_TO"
    # IL-specific fusion edges
    HAS_WEAKNESS        = "HAS_WEAKNESS"
    EXPLOITED_BY        = "EXPLOITED_BY"
    MAPS_TO             = "MAPS_TO"
    HAS_KEV             = "HAS_KEV"
    HAS_EPSS            = "HAS_EPSS"
    IOC_TO_MALWARE      = "IOC_TO_MALWARE"
    IOC_TO_CAMPAIGN     = "IOC_TO_CAMPAIGN"
    IOC_TO_TECHNIQUE    = "IOC_TO_TECHNIQUE"
    IOC_TO_CAPEC        = "IOC_TO_CAPEC"
    IOC_TO_CWE          = "IOC_TO_CWE"
    IOC_TO_CVE          = "IOC_TO_CVE"
    PARENT_OF           = "PARENT_OF"
    CHILD_OF            = "CHILD_OF"
    SUBTECHNIQUE_OF     = "SUBTECHNIQUE_OF"
    UNKNOWN             = "UNKNOWN"


# ---------------------------------------------------------------------------
# Core Graph Entities
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """
    A vertex in the Unified Threat Knowledge Graph.
    canonical_id = CIIL UUID — the only identity used across the graph.
    """
    node_id: str                         # Internal graph UUID (stable)
    canonical_id: str                    # CIIL canonical UUID
    node_type: str                       # GraphNodeType value
    label: str                           # Human-readable short label
    name: Optional[str] = None
    description: Optional[str] = None
    source_feed: Optional[str] = None    # IL that contributed this node
    external_id: Optional[str] = None    # CVE-ID, T1059, CWE-79, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "canonical_id": self.canonical_id,
            "node_type": self.node_type,
            "label": self.label,
            "name": self.name,
            "description": self.description,
            "source_feed": self.source_feed,
            "external_id": self.external_id,
            "properties": self.properties,
            "tags": self.tags,
            "confidence": self.confidence,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GraphNode":
        return cls(
            node_id=d.get("node_id") or str(uuid.uuid4()),
            canonical_id=d.get("canonical_id", ""),
            node_type=d.get("node_type", GraphNodeType.UNKNOWN.value),
            label=d.get("label", ""),
            name=d.get("name"),
            description=d.get("description"),
            source_feed=d.get("source_feed"),
            external_id=d.get("external_id"),
            properties=d.get("properties", {}),
            tags=d.get("tags", []),
            confidence=float(d.get("confidence", 1.0)),
            version=int(d.get("version", 1)),
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=d.get("updated_at", datetime.now(timezone.utc).isoformat()),
            is_active=bool(d.get("is_active", True)),
        )

    @classmethod
    def create(
        cls,
        canonical_id: str,
        node_type: str,
        label: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        source_feed: Optional[str] = None,
        external_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
    ) -> "GraphNode":
        return cls(
            node_id=str(uuid.uuid4()),
            canonical_id=canonical_id,
            node_type=node_type,
            label=label,
            name=name,
            description=description,
            source_feed=source_feed,
            external_id=external_id,
            properties=properties or {},
            tags=tags or [],
            confidence=confidence,
        )


@dataclass
class GraphEdge:
    """
    A directed edge between two graph nodes.
    Stores confidence, weight, evidence count, and full provenance.
    """
    edge_id: str
    source_node_id: str                  # GraphNode.node_id
    target_node_id: str                  # GraphNode.node_id
    source_canonical_id: str             # CIIL UUID of source
    target_canonical_id: str             # CIIL UUID of target
    edge_type: str                       # GraphEdgeType value
    confidence: float = 1.0
    weight: float = 1.0
    evidence_count: int = 0
    source_feed: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "source_canonical_id": self.source_canonical_id,
            "target_canonical_id": self.target_canonical_id,
            "edge_type": self.edge_type,
            "confidence": self.confidence,
            "weight": self.weight,
            "evidence_count": self.evidence_count,
            "source_feed": self.source_feed,
            "properties": self.properties,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GraphEdge":
        return cls(
            edge_id=d.get("edge_id") or str(uuid.uuid4()),
            source_node_id=d.get("source_node_id", ""),
            target_node_id=d.get("target_node_id", ""),
            source_canonical_id=d.get("source_canonical_id", ""),
            target_canonical_id=d.get("target_canonical_id", ""),
            edge_type=d.get("edge_type", GraphEdgeType.RELATED_TO.value),
            confidence=float(d.get("confidence", 1.0)),
            weight=float(d.get("weight", 1.0)),
            evidence_count=int(d.get("evidence_count", 0)),
            source_feed=d.get("source_feed"),
            properties=d.get("properties", {}),
            version=int(d.get("version", 1)),
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=d.get("updated_at", datetime.now(timezone.utc).isoformat()),
            is_active=bool(d.get("is_active", True)),
        )

    @classmethod
    def create(
        cls,
        source_node_id: str,
        target_node_id: str,
        source_canonical_id: str,
        target_canonical_id: str,
        edge_type: str,
        confidence: float = 1.0,
        weight: float = 1.0,
        evidence_count: int = 0,
        source_feed: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> "GraphEdge":
        return cls(
            edge_id=str(uuid.uuid4()),
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            source_canonical_id=source_canonical_id,
            target_canonical_id=target_canonical_id,
            edge_type=edge_type,
            confidence=confidence,
            weight=weight,
            evidence_count=evidence_count,
            source_feed=source_feed,
            properties=properties or {},
        )


# ---------------------------------------------------------------------------
# Graph Statistics
# ---------------------------------------------------------------------------

@dataclass
class GraphStatistics:
    """Snapshot of graph topology metrics."""
    node_count: int = 0
    edge_count: int = 0
    node_types: Dict[str, int] = field(default_factory=dict)
    edge_types: Dict[str, int] = field(default_factory=dict)
    degree_distribution: Dict[int, int] = field(default_factory=dict)
    largest_component_size: int = 0
    connected_components_count: int = 0
    relationship_density: float = 0.0
    average_path_length: float = 0.0
    average_degree: float = 0.0
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "node_types": self.node_types,
            "edge_types": self.edge_types,
            "degree_distribution": {str(k): v for k, v in self.degree_distribution.items()},
            "largest_component_size": self.largest_component_size,
            "connected_components_count": self.connected_components_count,
            "relationship_density": self.relationship_density,
            "average_path_length": self.average_path_length,
            "average_degree": self.average_degree,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Graph Path
# ---------------------------------------------------------------------------

@dataclass
class GraphPath:
    """A path through the graph — ordered list of nodes and edges."""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    length: int = 0                      # Number of edges
    total_weight: float = 0.0
    avg_confidence: float = 1.0
    algorithm: str = "bfs"
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "nodes": self.nodes,
            "edges": self.edges,
            "length": self.length,
            "total_weight": self.total_weight,
            "avg_confidence": self.avg_confidence,
            "algorithm": self.algorithm,
            "computed_at": self.computed_at,
        }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class GraphExportFormat(str, Enum):
    JSON    = "json"
    GRAPHML = "graphml"
    GEXF    = "gexf"
    CSV     = "csv"
    DOT     = "dot"
    MERMAID = "mermaid"


@dataclass
class GraphExportRecord:
    """Metadata record for a completed graph export."""
    export_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    format: str = GraphExportFormat.JSON.value
    node_count: int = 0
    edge_count: int = 0
    filter_query: Optional[str] = None
    file_path: Optional[str] = None
    content: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "export_id": self.export_id,
            "format": self.format,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "filter_query": self.filter_query,
            "file_path": self.file_path,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

@dataclass
class GraphVersion:
    """Snapshot version record for the graph state."""
    version_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version_number: int = 1
    node_count: int = 0
    edge_count: int = 0
    description: Optional[str] = None
    is_active: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "version_number": self.version_number,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Traversal / Search Results
# ---------------------------------------------------------------------------

@dataclass
class TraversalResult:
    """Result of a graph traversal operation."""
    traversal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    algorithm: str = "bfs"
    start_node_id: str = ""
    max_depth: int = 3
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    depth_map: Dict[str, int] = field(default_factory=dict)  # node_id -> depth
    duration_ms: float = 0.0
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "traversal_id": self.traversal_id,
            "algorithm": self.algorithm,
            "start_node_id": self.start_node_id,
            "max_depth": self.max_depth,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": self.nodes,
            "edges": self.edges,
            "depth_map": self.depth_map,
            "duration_ms": self.duration_ms,
            "computed_at": self.computed_at,
        }


@dataclass
class SearchResult:
    """Result of a graph search operation."""
    search_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    query: str = ""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    total_count: int = 0
    duration_ms: float = 0.0
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "search_id": self.search_id,
            "query": self.query,
            "total_count": self.total_count,
            "nodes": self.nodes,
            "duration_ms": self.duration_ms,
            "computed_at": self.computed_at,
        }


@dataclass
class SubgraphResult:
    """A bounded subgraph extracted around a set of seed nodes."""
    subgraph_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    seed_nodes: List[str] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    depth: int = 1
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subgraph_id": self.subgraph_id,
            "seed_nodes": self.seed_nodes,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": self.nodes,
            "edges": self.edges,
            "depth": self.depth,
            "computed_at": self.computed_at,
        }
