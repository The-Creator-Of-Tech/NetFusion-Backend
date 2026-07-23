"""
Identity Repository for NetFusion CIIL.
Provides SQLite / DB storage for canonical entities, external identifiers, relationships, aliases, provenance, and merge history.
Includes indexes on UUID, external identifiers, entity type, and source.
"""

from datetime import datetime, timezone
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from netfusion_intelligence.identity.models import (
    CanonicalEntity,
    EntityMergeRecord,
    EntityProvenance,
    ExternalIdentifier,
)
from netfusion_intelligence.identity.relationship import CanonicalRelationship


class IdentityRepository:
    """
    Thread-safe SQLite implementation for NetFusion CIIL persistence.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            
            # Canonical Entity Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canonical_entity (
                    canonical_uuid TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    description TEXT,
                    created TEXT NOT NULL,
                    modified TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    source_count INTEGER NOT NULL,
                    relationship_count INTEGER NOT NULL,
                    tags TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
            """)

            # External Identifier Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS external_identifier (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    canonical_uuid TEXT NOT NULL,
                    source TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    identifier_type TEXT NOT NULL,
                    url TEXT,
                    version TEXT,
                    confidence REAL NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    FOREIGN KEY (canonical_uuid) REFERENCES canonical_entity(canonical_uuid) ON DELETE CASCADE
                )
            """)

            # Canonical Relationship Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canonical_relationship (
                    relationship_id TEXT PRIMARY KEY,
                    source_canonical_uuid TEXT NOT NULL,
                    target_canonical_uuid TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    originating_source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    created TEXT NOT NULL,
                    modified TEXT NOT NULL,
                    version TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    originating_sources TEXT NOT NULL,
                    FOREIGN KEY (source_canonical_uuid) REFERENCES canonical_entity(canonical_uuid) ON DELETE CASCADE,
                    FOREIGN KEY (target_canonical_uuid) REFERENCES canonical_entity(canonical_uuid) ON DELETE CASCADE
                )
            """)

            # Entity Alias Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_alias (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    canonical_uuid TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    FOREIGN KEY (canonical_uuid) REFERENCES canonical_entity(canonical_uuid) ON DELETE CASCADE
                )
            """)

            # Entity Provenance Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_provenance (
                    provenance_id TEXT PRIMARY KEY,
                    canonical_uuid TEXT NOT NULL,
                    feed TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    original_object_id TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    trust_score REAL NOT NULL,
                    FOREIGN KEY (canonical_uuid) REFERENCES canonical_entity(canonical_uuid) ON DELETE CASCADE
                )
            """)

            # Entity Merge History Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_merge_history (
                    merge_id TEXT PRIMARY KEY,
                    target_canonical_uuid TEXT NOT NULL,
                    merged_canonical_uuid TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    provenance_transferred INTEGER NOT NULL,
                    merged_by TEXT NOT NULL
                )
            """)

            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_type ON canonical_entity(entity_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_active ON canonical_entity(active)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ext_source_id ON external_identifier(source, identifier)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ext_id ON external_identifier(identifier)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ext_type ON external_identifier(identifier_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alias ON entity_alias(alias)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON canonical_relationship(source_canonical_uuid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON canonical_relationship(target_canonical_uuid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_type ON canonical_relationship(relationship_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_prov_uuid ON entity_provenance(canonical_uuid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_prov_feed ON entity_provenance(feed)")

            self._conn.commit()

    def save_entity(
        self,
        entity: CanonicalEntity,
        provenance: Optional[EntityProvenance] = None,
    ) -> None:
        """Saves or updates a CanonicalEntity and its child records."""
        with self._lock:
            cursor = self._conn.cursor()
            created_str = entity.created.isoformat() if isinstance(entity.created, datetime) else entity.created
            modified_str = entity.modified.isoformat() if isinstance(entity.modified, datetime) else entity.modified

            cursor.execute("""
                INSERT OR REPLACE INTO canonical_entity (
                    canonical_uuid, entity_type, display_name, description, created, modified,
                    confidence, status, active, source_count, relationship_count, tags, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entity.canonical_uuid,
                entity.entity_type,
                entity.display_name,
                entity.description,
                created_str,
                modified_str,
                entity.confidence,
                entity.status,
                1 if entity.active else 0,
                entity.source_count,
                entity.relationship_count,
                json.dumps(list(entity.tags)),
                json.dumps(entity.metadata),
            ))

            # Update External Identifiers
            cursor.execute("DELETE FROM external_identifier WHERE canonical_uuid = ?", (entity.canonical_uuid,))
            for ext in entity.external_identifiers:
                fs_str = ext.first_seen.isoformat() if ext.first_seen else None
                ls_str = ext.last_seen.isoformat() if ext.last_seen else None
                cursor.execute("""
                    INSERT INTO external_identifier (
                        canonical_uuid, source, identifier, identifier_type, url, version, confidence, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entity.canonical_uuid,
                    ext.source,
                    ext.identifier,
                    ext.identifier_type,
                    ext.url,
                    ext.version,
                    ext.confidence,
                    fs_str,
                    ls_str,
                ))

            # Update Aliases
            cursor.execute("DELETE FROM entity_alias WHERE canonical_uuid = ?", (entity.canonical_uuid,))
            for alias in entity.aliases:
                cursor.execute("INSERT INTO entity_alias (canonical_uuid, alias) VALUES (?, ?)", (entity.canonical_uuid, alias))

            # Save Provenance if provided
            if provenance:
                ts_str = provenance.timestamp.isoformat() if isinstance(provenance.timestamp, datetime) else provenance.timestamp
                cursor.execute("""
                    INSERT OR REPLACE INTO entity_provenance (
                        provenance_id, canonical_uuid, feed, dataset_version, timestamp, original_object_id, verification_status, trust_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    provenance.provenance_id,
                    provenance.canonical_uuid,
                    provenance.feed,
                    provenance.dataset_version,
                    ts_str,
                    provenance.original_object_id,
                    provenance.verification_status,
                    provenance.trust_score,
                ))

            self._conn.commit()

    def get_entity(self, canonical_uuid: str) -> Optional[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT * FROM canonical_entity WHERE canonical_uuid = ?", (canonical_uuid,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._build_entity_from_row(row)

    def _build_entity_from_row(self, row: sqlite3.Row) -> CanonicalEntity:
        cursor = self._conn.cursor()
        uuid_val = row["canonical_uuid"]

        # Fetch External Identifiers
        cursor.execute("SELECT * FROM external_identifier WHERE canonical_uuid = ?", (uuid_val,))
        ext_rows = cursor.fetchall()
        ext_ids = []
        for r in ext_rows:
            fs = datetime.fromisoformat(r["first_seen"]) if r["first_seen"] else None
            ls = datetime.fromisoformat(r["last_seen"]) if r["last_seen"] else None
            ext_ids.append(ExternalIdentifier(
                source=r["source"],
                identifier=r["identifier"],
                identifier_type=r["identifier_type"],
                url=r["url"],
                version=r["version"],
                confidence=r["confidence"],
                first_seen=fs,
                last_seen=ls,
            ))

        # Fetch Aliases
        cursor.execute("SELECT alias FROM entity_alias WHERE canonical_uuid = ?", (uuid_val,))
        alias_rows = cursor.fetchall()
        aliases = [r["alias"] for r in alias_rows]

        return CanonicalEntity(
            canonical_uuid=uuid_val,
            entity_type=row["entity_type"],
            display_name=row["display_name"],
            aliases=tuple(aliases),
            description=row["description"],
            created=datetime.fromisoformat(row["created"]),
            modified=datetime.fromisoformat(row["modified"]),
            confidence=row["confidence"],
            status=row["status"],
            active=bool(row["active"]),
            source_count=row["source_count"],
            relationship_count=row["relationship_count"],
            tags=tuple(json.loads(row["tags"] or "[]")),
            metadata=json.loads(row["metadata"] or "{}"),
            external_identifiers=tuple(ext_ids),
        )

    def find_by_external_id(self, source: str, identifier: str) -> List[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT DISTINCT canonical_uuid FROM external_identifier
                WHERE LOWER(source) = LOWER(?) AND LOWER(identifier) = LOWER(?)
            """, (source, identifier))
            uuids = [r["canonical_uuid"] for r in cursor.fetchall()]

        results = []
        for u in uuids:
            ent = self.get_entity(u)
            if ent:
                results.append(ent)
        return results

    def find_by_identifier_value(self, identifier: str) -> List[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT DISTINCT canonical_uuid FROM external_identifier
                WHERE LOWER(identifier) = LOWER(?)
            """, (identifier,))
            uuids = [r["canonical_uuid"] for r in cursor.fetchall()]

        results = []
        for u in uuids:
            ent = self.get_entity(u)
            if ent:
                results.append(ent)
        return results

    def find_by_alias(self, alias: str) -> List[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT DISTINCT canonical_uuid FROM entity_alias WHERE LOWER(alias) = LOWER(?)", (alias,))
            uuids = [r["canonical_uuid"] for r in cursor.fetchall()]

        results = []
        for u in uuids:
            ent = self.get_entity(u)
            if ent:
                results.append(ent)
        return results

    def find_by_type(self, entity_type: str) -> List[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT canonical_uuid FROM canonical_entity WHERE UPPER(entity_type) = UPPER(?)", (entity_type,))
            uuids = [r["canonical_uuid"] for r in cursor.fetchall()]

        results = []
        for u in uuids:
            ent = self.get_entity(u)
            if ent:
                results.append(ent)
        return results

    def search(
        self,
        query: Optional[str] = None,
        entity_type: Optional[str] = None,
        feed_source: Optional[str] = None,
        limit: int = 100,
    ) -> List[CanonicalEntity]:
        with self._lock:
            cursor = self._conn.cursor()
            sql = "SELECT DISTINCT c.canonical_uuid FROM canonical_entity c"
            joins = []
            where_clauses = []
            params: List[Any] = []

            if feed_source:
                joins.append("JOIN entity_provenance p ON c.canonical_uuid = p.canonical_uuid")
                where_clauses.append("LOWER(p.feed) = LOWER(?)")
                params.append(feed_source)

            if entity_type:
                where_clauses.append("UPPER(c.entity_type) = UPPER(?)")
                params.append(entity_type)

            if query:
                joins.append("LEFT JOIN entity_alias a ON c.canonical_uuid = a.canonical_uuid")
                joins.append("LEFT JOIN external_identifier e ON c.canonical_uuid = e.canonical_uuid")
                q_clause = "(LOWER(c.display_name) LIKE ? OR LOWER(c.description) LIKE ? OR LOWER(a.alias) LIKE ? OR LOWER(e.identifier) LIKE ?)"
                like_param = f"%{query.lower()}%"
                where_clauses.append(q_clause)
                params.extend([like_param, like_param, like_param, like_param])

            full_sql = sql
            if joins:
                full_sql += " " + " ".join(joins)
            if where_clauses:
                full_sql += " WHERE " + " AND ".join(where_clauses)
            full_sql += " LIMIT ?"
            params.append(limit)

            cursor.execute(full_sql, params)
            uuids = [r["canonical_uuid"] for r in cursor.fetchall()]

        results = []
        for u in uuids:
            ent = self.get_entity(u)
            if ent:
                results.append(ent)
        return results

    def save_relationship(self, relationship: CanonicalRelationship) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            c_str = relationship.created.isoformat() if isinstance(relationship.created, datetime) else relationship.created
            m_str = relationship.modified.isoformat() if isinstance(relationship.modified, datetime) else relationship.modified

            cursor.execute("""
                INSERT OR REPLACE INTO canonical_relationship (
                    relationship_id, source_canonical_uuid, target_canonical_uuid, relationship_type,
                    originating_source, confidence, created, modified, version, metadata, originating_sources
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                relationship.relationship_id,
                relationship.source_canonical_uuid,
                relationship.target_canonical_uuid,
                relationship.relationship_type,
                relationship.originating_source,
                relationship.confidence,
                c_str,
                m_str,
                relationship.version,
                json.dumps(relationship.metadata),
                json.dumps(list(relationship.originating_sources)),
            ))
            self._conn.commit()

    def get_relationships(
        self,
        canonical_uuid: str,
        direction: str = "both",
        relationship_type: Optional[str] = None,
    ) -> List[CanonicalRelationship]:
        with self._lock:
            cursor = self._conn.cursor()
            sql = "SELECT * FROM canonical_relationship WHERE "
            clauses = []
            params = []

            if direction == "source":
                clauses.append("source_canonical_uuid = ?")
                params.append(canonical_uuid)
            elif direction == "target":
                clauses.append("target_canonical_uuid = ?")
                params.append(canonical_uuid)
            else:
                clauses.append("(source_canonical_uuid = ? OR target_canonical_uuid = ?)")
                params.extend([canonical_uuid, canonical_uuid])

            if relationship_type:
                clauses.append("UPPER(relationship_type) = UPPER(?)")
                params.append(relationship_type)

            sql += " AND ".join(clauses)
            cursor.execute(sql, params)
            rows = cursor.fetchall()

        results = []
        for r in rows:
            sources = tuple(json.loads(r["originating_sources"] or "[]"))
            results.append(CanonicalRelationship(
                relationship_id=r["relationship_id"],
                source_canonical_uuid=r["source_canonical_uuid"],
                target_canonical_uuid=r["target_canonical_uuid"],
                relationship_type=r["relationship_type"],
                originating_source=r["originating_source"],
                confidence=r["confidence"],
                created=datetime.fromisoformat(r["created"]),
                modified=datetime.fromisoformat(r["modified"]),
                version=r["version"],
                metadata=json.loads(r["metadata"] or "{}"),
                originating_sources=sources,
            ))
        return results

    def save_merge_record(self, record: EntityMergeRecord) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            ts_str = record.timestamp.isoformat() if isinstance(record.timestamp, datetime) else record.timestamp
            cursor.execute("""
                INSERT INTO entity_merge_history (
                    merge_id, target_canonical_uuid, merged_canonical_uuid, timestamp, reason, provenance_transferred, merged_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.merge_id,
                record.target_canonical_uuid,
                record.merged_canonical_uuid,
                ts_str,
                record.reason,
                record.provenance_transferred,
                record.merged_by,
            ))
            self._conn.commit()

    def get_merge_history(self, canonical_uuid: str) -> List[EntityMergeRecord]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT * FROM entity_merge_history
                WHERE target_canonical_uuid = ? OR merged_canonical_uuid = ?
                ORDER BY timestamp DESC
            """, (canonical_uuid, canonical_uuid))
            rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append(EntityMergeRecord(
                merge_id=r["merge_id"],
                target_canonical_uuid=r["target_canonical_uuid"],
                merged_canonical_uuid=r["merged_canonical_uuid"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                reason=r["reason"],
                provenance_transferred=r["provenance_transferred"],
                merged_by=r["merged_by"],
            ))
        return results

    def get_provenance(self, canonical_uuid: str) -> List[EntityProvenance]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT * FROM entity_provenance WHERE canonical_uuid = ?", (canonical_uuid,))
            rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append(EntityProvenance(
                provenance_id=r["provenance_id"],
                canonical_uuid=r["canonical_uuid"],
                feed=r["feed"],
                dataset_version=r["dataset_version"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                original_object_id=r["original_object_id"],
                verification_status=r["verification_status"],
                trust_score=r["trust_score"],
            ))
        return results

    def delete_entity(self, canonical_uuid: str) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM canonical_entity WHERE canonical_uuid = ?", (canonical_uuid,))
            cursor.execute("DELETE FROM external_identifier WHERE canonical_uuid = ?", (canonical_uuid,))
            cursor.execute("DELETE FROM entity_alias WHERE canonical_uuid = ?", (canonical_uuid,))
            cursor.execute("DELETE FROM entity_provenance WHERE canonical_uuid = ?", (canonical_uuid,))
            self._conn.commit()

    def transfer_provenance(self, source_uuid: str, target_uuid: str) -> int:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("UPDATE entity_provenance SET canonical_uuid = ? WHERE canonical_uuid = ?", (target_uuid, source_uuid))
            count = cursor.rowcount
            self._conn.commit()
            return count

    def list_sources(self) -> List[str]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT DISTINCT source FROM external_identifier UNION SELECT DISTINCT feed FROM entity_provenance")
            sources = [r[0] for r in cursor.fetchall() if r[0]]
            return sorted(sources)

    def list_aliases(self, canonical_uuid: str) -> List[str]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT alias FROM entity_alias WHERE canonical_uuid = ?", (canonical_uuid,))
            return [r["alias"] for r in cursor.fetchall()]

    def count_entities(self) -> int:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM canonical_entity")
            return cursor.fetchone()[0]

    def get_counts(self) -> Dict[str, Any]:
        with self._lock:
            cursor = self._conn.cursor()
            total_entities = cursor.execute("SELECT COUNT(*) FROM canonical_entity").fetchone()[0]
            active_entities = cursor.execute("SELECT COUNT(*) FROM canonical_entity WHERE active = 1").fetchone()[0]
            merged_entities = cursor.execute("SELECT COUNT(*) FROM canonical_entity WHERE status = 'MERGED'").fetchone()[0]
            total_ext_ids = cursor.execute("SELECT COUNT(*) FROM external_identifier").fetchone()[0]
            total_relationships = cursor.execute("SELECT COUNT(*) FROM canonical_relationship").fetchone()[0]
            
            cursor.execute("SELECT entity_type, COUNT(*) FROM canonical_entity GROUP BY entity_type")
            types_breakdown = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "total_entities": total_entities,
                "active_entities": active_entities,
                "merged_entities": merged_entities,
                "total_external_identifiers": total_ext_ids,
                "total_relationships": total_relationships,
                "entity_types_breakdown": types_breakdown,
            }
