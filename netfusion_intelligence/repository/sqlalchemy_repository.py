"""
Production SQLAlchemy repository implementation of IntelligenceRepositoryInterface.
Supports SQLite (in-memory & file) and PostgreSQL.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.models.audit import AuditLogEntry
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion, ValidationStatus
from netfusion_intelligence.models.health import FeedHealth, FeedHealthStatus
from netfusion_intelligence.models.import_result import ImportLogEntry, ImportResult, ImportStatus
from netfusion_intelligence.models.statistics import FeedStatistics, IntelligenceStatistics
from netfusion_intelligence.repository.base import deserialize_json, serialize_json
from netfusion_intelligence.repository.tables import (
    Base,
    DatasetImportModel,
    DatasetVersionModel,
    EventAuditModel,
    FeedHealthModel,
    FeedScheduleModel,
    IntelligenceFeedModel,
    ImportLogModel,
    MitreAttackObjectModel,
    MitreAttackRelationshipModel,
    NvdCveModel,
    KevEntryModel,
    KevReferenceModel,
    KevHistoryModel,
    EpssScoreModel,
    EpssHistoryModel,
    EpssDatasetModel,
    # IL-6: CWE / CAPEC
    CweWeaknessModel,
    CweRelationshipModel,
    CapecAttackPatternModel,
    CapecRelationshipModel,
    CapecCweMappingModel,
    CapecAttackMappingModel,
    CveCweMappingModel,
)



class SQLAlchemyIntelligenceRepository(IntelligenceRepositoryInterface):
    """
    SQLAlchemy implementation of IntelligenceRepositoryInterface.
    Provides complete isolation over intelligence tables.
    """

    def __init__(self, db_url: str = "sqlite:///:memory:", engine: Any = None):
        if engine is not None:
            self.engine = engine
        else:
            if db_url in ("sqlite:///:memory:", "sqlite://"):
                self.engine = create_engine(
                    db_url,
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                )
            elif db_url.startswith("sqlite"):
                self.engine = create_engine(
                    db_url,
                    connect_args={"check_same_thread": False},
                )
            else:
                self.engine = create_engine(db_url)

        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _get_session(self) -> Session:
        return self.SessionLocal()

    def _session_factory(self) -> Session:
        """Alias for _get_session — used by EPSS repository methods."""
        return self.SessionLocal()

    def save_feed_record(self, feed_id: str, name: str, description: str, config_data: Dict[str, Any], enabled: bool = True) -> Dict[str, Any]:
        with self._get_session() as session:
            record = session.query(IntelligenceFeedModel).filter_by(feed_id=feed_id).first()
            if not record:
                record = IntelligenceFeedModel(
                    feed_id=feed_id,
                    name=name,
                    description=description,
                    config_json=serialize_json(config_data),
                    enabled=enabled,
                )
                session.add(record)
            else:
                record.name = name
                record.description = description
                record.config_json = serialize_json(config_data)
                record.enabled = enabled
                record.updated_at = datetime.now(timezone.utc)
            session.commit()
            return {
                "feed_id": record.feed_id,
                "name": record.name,
                "description": record.description,
                "config": deserialize_json(record.config_json),
                "enabled": record.enabled,
            }

    def get_feed_record(self, feed_id: str) -> Optional[Dict[str, Any]]:
        with self._get_session() as session:
            record = session.query(IntelligenceFeedModel).filter_by(feed_id=feed_id).first()
            if not record:
                return None
            return {
                "feed_id": record.feed_id,
                "name": record.name,
                "description": record.description,
                "config": deserialize_json(record.config_json),
                "enabled": record.enabled,
            }

    def list_feed_records(self) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            records = session.query(IntelligenceFeedModel).all()
            return [
                {
                    "feed_id": r.feed_id,
                    "name": r.name,
                    "description": r.description,
                    "config": deserialize_json(r.config_json),
                    "enabled": r.enabled,
                }
                for r in records
            ]

    def save_dataset_version(self, dataset_version: DatasetVersion) -> DatasetVersion:
        with self._get_session() as session:
            record = session.query(DatasetVersionModel).filter_by(version_id=dataset_version.version_id).first()
            
            imp_at = datetime.fromisoformat(dataset_version.imported_at) if isinstance(dataset_version.imported_at, str) else dataset_version.imported_at
            act_at = datetime.fromisoformat(dataset_version.activated_at) if dataset_version.activated_at else None

            v_status = dataset_version.validation_status.value if isinstance(dataset_version.validation_status, ValidationStatus) else dataset_version.validation_status
            d_status = dataset_version.status.value if isinstance(dataset_version.status, DatasetStatus) else dataset_version.status

            if not record:
                record = DatasetVersionModel(
                    feed_id=dataset_version.feed_id,
                    version_id=dataset_version.version_id,
                    checksum=dataset_version.checksum,
                    source_version=dataset_version.source_version,
                    status=d_status,
                    validation_status=v_status,
                    record_count=dataset_version.record_count,
                    duration=dataset_version.duration,
                    imported_at=imp_at,
                    activated_at=act_at,
                    error_message=dataset_version.error_message,
                )
                session.add(record)
            else:
                record.status = d_status
                record.validation_status = v_status
                record.checksum = dataset_version.checksum
                record.source_version = dataset_version.source_version
                record.record_count = dataset_version.record_count
                record.duration = dataset_version.duration
                record.activated_at = act_at
                record.error_message = dataset_version.error_message
            session.commit()
            return dataset_version

    def get_dataset_version(self, version_id: str) -> Optional[DatasetVersion]:
        with self._get_session() as session:
            r = session.query(DatasetVersionModel).filter_by(version_id=version_id).first()
            if not r:
                return None
            return DatasetVersion(
                feed_id=r.feed_id,
                version_id=r.version_id,
                checksum=r.checksum or "",
                imported_at=r.imported_at.isoformat() if r.imported_at else datetime.now(timezone.utc).isoformat(),
                source_version=r.source_version,
                duration=r.duration,
                record_count=r.record_count,
                validation_status=ValidationStatus(r.validation_status),
                status=DatasetStatus(r.status),
                activated_at=r.activated_at.isoformat() if r.activated_at else None,
                error_message=r.error_message,
            )

    def get_active_dataset_version(self, feed_id: str) -> Optional[DatasetVersion]:
        with self._get_session() as session:
            r = session.query(DatasetVersionModel).filter_by(
                feed_id=feed_id, status=DatasetStatus.ACTIVE.value
            ).order_by(DatasetVersionModel.activated_at.desc()).first()
            if not r:
                return None
            return DatasetVersion(
                feed_id=r.feed_id,
                version_id=r.version_id,
                checksum=r.checksum or "",
                imported_at=r.imported_at.isoformat() if r.imported_at else datetime.now(timezone.utc).isoformat(),
                source_version=r.source_version,
                duration=r.duration,
                record_count=r.record_count,
                validation_status=ValidationStatus(r.validation_status),
                status=DatasetStatus(r.status),
                activated_at=r.activated_at.isoformat() if r.activated_at else None,
                error_message=r.error_message,
            )

    def list_dataset_versions(self, feed_id: Optional[str] = None) -> List[DatasetVersion]:
        with self._get_session() as session:
            query = session.query(DatasetVersionModel)
            if feed_id:
                query = query.filter_by(feed_id=feed_id)
            records = query.order_by(DatasetVersionModel.imported_at.desc()).all()
            return [
                DatasetVersion(
                    feed_id=r.feed_id,
                    version_id=r.version_id,
                    checksum=r.checksum or "",
                    imported_at=r.imported_at.isoformat() if r.imported_at else datetime.now(timezone.utc).isoformat(),
                    source_version=r.source_version,
                    duration=r.duration,
                    record_count=r.record_count,
                    validation_status=ValidationStatus(r.validation_status),
                    status=DatasetStatus(r.status),
                    activated_at=r.activated_at.isoformat() if r.activated_at else None,
                    error_message=r.error_message,
                )
                for r in records
            ]

    def set_active_dataset_version(self, feed_id: str, version_id: str) -> bool:
        with self._get_session() as session:
            # Deactivate currently active version for this feed
            active_versions = session.query(DatasetVersionModel).filter_by(
                feed_id=feed_id, status=DatasetStatus.ACTIVE.value
            ).all()
            for av in active_versions:
                av.status = DatasetStatus.ARCHIVED.value

            target = session.query(DatasetVersionModel).filter_by(version_id=version_id).first()
            if not target:
                session.rollback()
                return False
            
            target.status = DatasetStatus.ACTIVE.value
            target.activated_at = datetime.now(timezone.utc)
            session.commit()
            return True

    def save_import_result(self, result: ImportResult) -> ImportResult:
        with self._get_session() as session:
            rec = session.query(DatasetImportModel).filter_by(import_id=result.import_id).first()
            started_dt = datetime.fromisoformat(result.started_at) if isinstance(result.started_at, str) else result.started_at
            finished_dt = datetime.fromisoformat(result.finished_at) if result.finished_at else None
            status_str = result.status.value if isinstance(result.status, ImportStatus) else result.status

            if not rec:
                rec = DatasetImportModel(
                    import_id=result.import_id,
                    feed_id=result.feed_id,
                    version_id=result.version_id,
                    status=status_str,
                    started_at=started_dt,
                    finished_at=finished_dt,
                    duration=result.duration_seconds,
                    records_downloaded=result.records_downloaded,
                    records_parsed=result.records_parsed,
                    records_processed=result.records_processed,
                    records_inserted=result.records_inserted,
                    records_updated=result.records_updated,
                    records_deleted=result.records_deleted,
                    duplicate_records=result.duplicate_records,
                    validation_errors=result.validation_errors,
                    relationship_count=result.relationship_count,
                    download_size=result.download_size,
                    checksum=result.checksum,
                    source_version=result.source_version,
                    warnings_json=serialize_json(result.warnings),
                    trigger=result.trigger,
                    user=result.user,
                    rollback_status=result.rollback_status,
                    validation_result_json=serialize_json(result.validation_details),
                    validation_summary_json=serialize_json(result.validation_summary),
                    error_log=result.error_message,
                )
                session.add(rec)
            else:
                rec.status = status_str
                rec.version_id = result.version_id
                rec.finished_at = finished_dt
                rec.duration = result.duration_seconds
                rec.records_downloaded = result.records_downloaded
                rec.records_parsed = result.records_parsed
                rec.records_processed = result.records_processed
                rec.records_inserted = result.records_inserted
                rec.records_updated = result.records_updated
                rec.records_deleted = result.records_deleted
                rec.duplicate_records = result.duplicate_records
                rec.validation_errors = result.validation_errors
                rec.relationship_count = result.relationship_count
                rec.download_size = result.download_size
                rec.checksum = result.checksum
                rec.source_version = result.source_version
                rec.warnings_json = serialize_json(result.warnings)
                rec.trigger = result.trigger
                rec.user = result.user
                rec.rollback_status = result.rollback_status
                rec.validation_result_json = serialize_json(result.validation_details)
                rec.validation_summary_json = serialize_json(result.validation_summary)
                rec.error_log = result.error_message
            session.commit()
            return result

    def list_import_results(
        self,
        feed_id: Optional[str] = None,
        status: Optional[str] = None,
        trigger: Optional[str] = None,
        limit: int = 100,
    ) -> List[ImportResult]:
        with self._get_session() as session:
            query = session.query(DatasetImportModel)
            if feed_id:
                query = query.filter_by(feed_id=feed_id)
            if status:
                query = query.filter_by(status=status)
            if trigger:
                query = query.filter_by(trigger=trigger)
            records = query.order_by(DatasetImportModel.started_at.desc()).limit(limit).all()
            return [
                ImportResult(
                    import_id=r.import_id,
                    feed_id=r.feed_id,
                    version_id=r.version_id,
                    status=ImportStatus(r.status),
                    started_at=r.started_at.isoformat() if r.started_at else datetime.now(timezone.utc).isoformat(),
                    finished_at=r.finished_at.isoformat() if r.finished_at else None,
                    duration_seconds=r.duration,
                    execution_time=r.duration,
                    records_downloaded=r.records_downloaded or 0,
                    records_parsed=r.records_parsed or 0,
                    records_processed=r.records_processed or 0,
                    records_inserted=r.records_inserted or 0,
                    records_updated=r.records_updated or 0,
                    records_deleted=r.records_deleted or 0,
                    duplicate_records=r.duplicate_records or 0,
                    validation_errors=r.validation_errors or 0,
                    relationship_count=r.relationship_count or 0,
                    download_size=r.download_size or 0,
                    checksum=r.checksum,
                    source_version=r.source_version,
                    warnings=deserialize_json(r.warnings_json) if r.warnings_json else [],
                    trigger=r.trigger or "manual",
                    user=r.user or "system",
                    rollback_status=r.rollback_status or "NOT_APPLICABLE",
                    validation_passed=(r.status == ImportStatus.COMPLETED.value or r.status == ImportStatus.ACTIVATING.value),
                    validation_details=deserialize_json(r.validation_result_json) if r.validation_result_json else {},
                    validation_summary=deserialize_json(r.validation_summary_json) if r.validation_summary_json else {},
                    error_message=r.error_log,
                )
                for r in records
            ]

    def save_feed_health(self, health: FeedHealth) -> FeedHealth:
        with self._get_session() as session:
            rec = session.query(FeedHealthModel).filter_by(feed_id=health.feed_id).first()
            last_sync_dt = datetime.fromisoformat(health.last_sync_at) if health.last_sync_at else None
            next_sync_dt = datetime.fromisoformat(health.next_sync_at) if health.next_sync_at else None
            last_succ_dt = datetime.fromisoformat(health.last_success_at) if health.last_success_at else None
            last_fail_dt = datetime.fromisoformat(health.last_failure_at) if health.last_failure_at else None
            status_str = health.status.value if isinstance(health.status, FeedHealthStatus) else health.status

            if not rec:
                rec = FeedHealthModel(
                    feed_id=health.feed_id,
                    health_status=status_str,
                    availability=health.availability,
                    last_sync_at=last_sync_dt,
                    next_sync_at=next_sync_dt,
                    last_success_at=last_succ_dt,
                    last_failure_at=last_fail_dt,
                    consecutive_failures=health.consecutive_failures,
                    total_sync_count=health.total_sync_count,
                    successful_sync_count=health.successful_sync_count,
                    failed_sync_count=health.failed_sync_count,
                    last_error=health.last_error,
                    validation_state=health.validation_state,
                    validation_health=health.validation_health,
                    active_dataset_version=health.active_dataset_version,
                    last_execution_duration_sec=health.last_execution_duration_sec,
                    average_execution_time=health.average_execution_time,
                    dependency_health=health.dependency_health,
                )
                session.add(rec)
            else:
                rec.health_status = status_str
                rec.availability = health.availability
                rec.last_sync_at = last_sync_dt
                rec.next_sync_at = next_sync_dt
                rec.last_success_at = last_succ_dt
                rec.last_failure_at = last_fail_dt
                rec.consecutive_failures = health.consecutive_failures
                rec.total_sync_count = health.total_sync_count
                rec.successful_sync_count = health.successful_sync_count
                rec.failed_sync_count = health.failed_sync_count
                rec.last_error = health.last_error
                rec.validation_state = health.validation_state
                rec.validation_health = health.validation_health
                rec.active_dataset_version = health.active_dataset_version
                rec.last_execution_duration_sec = health.last_execution_duration_sec
                rec.average_execution_time = health.average_execution_time
                rec.dependency_health = health.dependency_health
                rec.updated_at = datetime.now(timezone.utc)
            session.commit()
            return health

    def get_feed_health(self, feed_id: str) -> Optional[FeedHealth]:
        with self._get_session() as session:
            rec = session.query(FeedHealthModel).filter_by(feed_id=feed_id).first()
            if not rec:
                return None
            return FeedHealth(
                feed_id=rec.feed_id,
                status=FeedHealthStatus(rec.health_status),
                availability=rec.availability,
                last_sync_at=rec.last_sync_at.isoformat() if rec.last_sync_at else None,
                next_sync_at=rec.next_sync_at.isoformat() if rec.next_sync_at else None,
                last_success_at=rec.last_success_at.isoformat() if rec.last_success_at else None,
                last_failure_at=rec.last_failure_at.isoformat() if rec.last_failure_at else None,
                consecutive_failures=rec.consecutive_failures,
                total_sync_count=rec.total_sync_count,
                successful_sync_count=rec.successful_sync_count,
                failed_sync_count=rec.failed_sync_count,
                last_error=rec.last_error,
                validation_state=rec.validation_state,
                validation_health=rec.validation_health or "PASSED",
                active_dataset_version=rec.active_dataset_version,
                last_execution_duration_sec=rec.last_execution_duration_sec,
                average_execution_time=rec.average_execution_time or 0.0,
                dependency_health=rec.dependency_health or "HEALTHY",
                updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
            )

    def list_feed_healths(self) -> List[FeedHealth]:
        with self._get_session() as session:
            records = session.query(FeedHealthModel).all()
            return [
                FeedHealth(
                    feed_id=rec.feed_id,
                    status=FeedHealthStatus(rec.health_status),
                    availability=rec.availability,
                    last_sync_at=rec.last_sync_at.isoformat() if rec.last_sync_at else None,
                    next_sync_at=rec.next_sync_at.isoformat() if rec.next_sync_at else None,
                    last_success_at=rec.last_success_at.isoformat() if rec.last_success_at else None,
                    last_failure_at=rec.last_failure_at.isoformat() if rec.last_failure_at else None,
                    consecutive_failures=rec.consecutive_failures,
                    total_sync_count=rec.total_sync_count,
                    successful_sync_count=rec.successful_sync_count,
                    failed_sync_count=rec.failed_sync_count,
                    last_error=rec.last_error,
                    validation_state=rec.validation_state,
                    validation_health=rec.validation_health or "PASSED",
                    active_dataset_version=rec.active_dataset_version,
                    last_execution_duration_sec=rec.last_execution_duration_sec,
                    average_execution_time=rec.average_execution_time or 0.0,
                    dependency_health=rec.dependency_health or "HEALTHY",
                    updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
                )
                for rec in records
            ]

    def save_import_logs(self, import_id: str, feed_id: str, logs: List[ImportLogEntry]) -> None:
        with self._get_session() as session:
            for entry in logs:
                ts = datetime.fromisoformat(entry.timestamp) if isinstance(entry.timestamp, str) else entry.timestamp
                model = ImportLogModel(
                    import_id=import_id,
                    feed_id=feed_id,
                    level=entry.level,
                    message=entry.message,
                    details_json=serialize_json(entry.details),
                    timestamp=ts,
                )
                session.add(model)
            session.commit()

    def get_statistics(self) -> IntelligenceStatistics:
        with self._get_session() as session:
            feeds = session.query(IntelligenceFeedModel).all()
            total_feeds = len(feeds)
            active_feeds = len([f for f in feeds if f.enabled])

            total_datasets = session.query(func.count(DatasetVersionModel.id)).scalar() or 0
            
            proc_stats = session.query(
                func.sum(DatasetImportModel.records_processed),
                func.sum(DatasetImportModel.records_inserted),
                func.sum(DatasetImportModel.records_updated),
            ).first()

            total_proc = proc_stats[0] or 0
            total_ins = proc_stats[1] or 0
            total_upd = proc_stats[2] or 0

            healths = session.query(FeedHealthModel).all()
            healthy_count = len([h for h in healths if h.health_status == FeedHealthStatus.HEALTHY.value])
            overall_score = (healthy_count / len(healths) * 100.0) if healths else 100.0

            feed_stats: Dict[str, FeedStatistics] = {}
            for f in feeds:
                fh = next((h for h in healths if h.feed_id == f.feed_id), None)
                active_v = session.query(DatasetVersionModel).filter_by(
                    feed_id=f.feed_id, status=DatasetStatus.ACTIVE.value
                ).first()

                feed_stats[f.feed_id] = FeedStatistics(
                    feed_id=f.feed_id,
                    feed_name=f.name,
                    total_syncs=fh.total_sync_count if fh else 0,
                    successful_syncs=fh.successful_sync_count if fh else 0,
                    failed_syncs=fh.failed_sync_count if fh else 0,
                    total_records_ingested=total_ins,
                    total_datasets_created=session.query(func.count(DatasetVersionModel.id)).filter_by(feed_id=f.feed_id).scalar() or 0,
                    active_version_id=active_v.version_id if active_v else None,
                    last_sync_duration_seconds=fh.last_execution_duration_sec if fh else 0.0,
                    last_sync_timestamp=fh.last_sync_at.isoformat() if (fh and fh.last_sync_at) else None,
                )

            return IntelligenceStatistics(
                total_feeds_registered=total_feeds,
                active_feeds_count=active_feeds,
                total_datasets_managed=total_datasets,
                total_records_processed=total_proc,
                total_records_inserted=total_ins,
                total_records_updated=total_upd,
                overall_health_score=overall_score,
                feed_stats=feed_stats,
                generated_at=datetime.now(timezone.utc).isoformat(),
            )

    def save_audit_event(self, entry: AuditLogEntry) -> AuditLogEntry:
        with self._get_session() as session:
            ts = datetime.fromisoformat(entry.timestamp) if isinstance(entry.timestamp, str) else entry.timestamp
            rec = EventAuditModel(
                audit_id=entry.audit_id,
                event_id=entry.event_id,
                event_type=entry.event_type,
                feed_id=entry.feed_id,
                payload_json=serialize_json(entry.payload),
                timestamp=ts,
            )
            session.add(rec)
            session.commit()
            return entry

    def list_audit_events(
        self, event_type: Optional[str] = None, feed_id: Optional[str] = None, limit: int = 100
    ) -> List[AuditLogEntry]:
        with self._get_session() as session:
            query = session.query(EventAuditModel)
            if event_type:
                query = query.filter_by(event_type=event_type)
            if feed_id:
                query = query.filter_by(feed_id=feed_id)
            records = query.order_by(EventAuditModel.timestamp.desc()).limit(limit).all()
            return [
                AuditLogEntry(
                    audit_id=r.audit_id,
                    event_id=r.event_id,
                    event_type=r.event_type,
                    feed_id=r.feed_id,
                    timestamp=r.timestamp.isoformat() if r.timestamp else datetime.now(timezone.utc).isoformat(),
                    payload=deserialize_json(r.payload_json) if r.payload_json else {},
                )
                for r in records
            ]

    # -------------------------------------------------------------------------
    # MITRE ATT&CK Enterprise STIX 2.1 Repository Operations
    # -------------------------------------------------------------------------

    def save_mitre_objects(self, version_id: str, entities: List[Any]) -> Dict[str, int]:
        """
        Saves normalized MITRE entities for dataset version_id.
        Returns dict with counts of inserted, updated, and duplicates.
        """
        inserted = 0
        updated = 0
        duplicates = 0

        with self._get_session() as session:
            for ent in entities:
                stix_id = ent.stix_id if hasattr(ent, "stix_id") else ent.get("stix_id")
                e_type = ent.type if hasattr(ent, "type") else ent.get("type")
                attack_id = ent.attack_id if hasattr(ent, "attack_id") else ent.get("attack_id")
                name = ent.name if hasattr(ent, "name") else ent.get("name")
                desc = ent.description if hasattr(ent, "description") else ent.get("description")
                is_sub = ent.is_subtechnique if hasattr(ent, "is_subtechnique") else ent.get("is_subtechnique", False)
                parent_id = ent.parent_technique_id if hasattr(ent, "parent_technique_id") else ent.get("parent_technique_id")
                
                tactics = list(ent.tactics) if hasattr(ent, "tactics") else ent.get("tactics", [])
                platforms = list(ent.platforms) if hasattr(ent, "platforms") else ent.get("platforms", [])
                aliases = list(ent.aliases) if hasattr(ent, "aliases") else ent.get("aliases", [])
                kc_phases = list(ent.kill_chain_phases) if hasattr(ent, "kill_chain_phases") else ent.get("kill_chain_phases", [])
                perms = list(ent.permissions_required) if hasattr(ent, "permissions_required") else ent.get("permissions_required", [])
                sys_reqs = list(ent.system_requirements) if hasattr(ent, "system_requirements") else ent.get("system_requirements", [])
                detection = ent.detection if hasattr(ent, "detection") else ent.get("detection")
                contribs = list(ent.contributors) if hasattr(ent, "contributors") else ent.get("contributors", [])
                ext_refs = list(ent.external_references) if hasattr(ent, "external_references") else ent.get("external_references", [])
                
                url = ent.url if hasattr(ent, "url") else ent.get("url")
                version = ent.version if hasattr(ent, "version") else ent.get("version")
                created = ent.created if hasattr(ent, "created") else ent.get("created")
                modified = ent.modified if hasattr(ent, "modified") else ent.get("modified")
                revoked = ent.revoked if hasattr(ent, "revoked") else ent.get("revoked", False)
                deprecated = ent.deprecated if hasattr(ent, "deprecated") else ent.get("deprecated", False)
                raw_stix = ent.raw_stix if hasattr(ent, "raw_stix") else ent.get("raw_stix", {})

                existing = session.query(MitreAttackObjectModel).filter_by(
                    dataset_version_id=version_id, stix_id=stix_id
                ).first()

                if not existing:
                    model = MitreAttackObjectModel(
                        stix_id=stix_id,
                        dataset_version_id=version_id,
                        type=e_type,
                        attack_id=attack_id,
                        name=name,
                        description=desc,
                        is_subtechnique=is_sub,
                        parent_technique_id=parent_id,
                        tactics_json=serialize_json(tactics),
                        platforms_json=serialize_json(platforms),
                        aliases_json=serialize_json(aliases),
                        kill_chain_phases_json=serialize_json(kc_phases),
                        permissions_required_json=serialize_json(perms),
                        system_requirements_json=serialize_json(sys_reqs),
                        detection=detection,
                        contributors_json=serialize_json(contribs),
                        external_references_json=serialize_json(ext_refs),
                        url=url,
                        version=version,
                        created=created,
                        modified=modified,
                        revoked=revoked,
                        deprecated=deprecated,
                        raw_stix_json=serialize_json(raw_stix),
                    )
                    session.add(model)
                    inserted += 1
                else:
                    existing.type = e_type
                    existing.attack_id = attack_id
                    existing.name = name
                    existing.description = desc
                    existing.is_subtechnique = is_sub
                    existing.parent_technique_id = parent_id
                    existing.tactics_json = serialize_json(tactics)
                    existing.platforms_json = serialize_json(platforms)
                    existing.aliases_json = serialize_json(aliases)
                    existing.kill_chain_phases_json = serialize_json(kc_phases)
                    existing.permissions_required_json = serialize_json(perms)
                    existing.system_requirements_json = serialize_json(sys_reqs)
                    existing.detection = detection
                    existing.contributors_json = serialize_json(contribs)
                    existing.external_references_json = serialize_json(ext_refs)
                    existing.url = url
                    existing.version = version
                    existing.created = created
                    existing.modified = modified
                    existing.revoked = revoked
                    existing.deprecated = deprecated
                    existing.raw_stix_json = serialize_json(raw_stix)
                    updated += 1
                    duplicates += 1

            session.commit()
            return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def save_mitre_relationships(self, version_id: str, relationships: List[Any]) -> int:
        """
        Saves STIX relationship objects for dataset version_id.
        Returns count of saved relationships.
        """
        count = 0
        with self._get_session() as session:
            for rel in relationships:
                stix_id = rel.stix_id if hasattr(rel, "stix_id") else rel.get("stix_id")
                src_ref = rel.source_ref if hasattr(rel, "source_ref") else rel.get("source_ref")
                tgt_ref = rel.target_ref if hasattr(rel, "target_ref") else rel.get("target_ref")
                rel_type = rel.relationship_type if hasattr(rel, "relationship_type") else rel.get("relationship_type")
                src_atk = rel.source_attack_id if hasattr(rel, "source_attack_id") else rel.get("source_attack_id")
                src_type = rel.source_type if hasattr(rel, "source_type") else rel.get("source_type")
                tgt_atk = rel.target_attack_id if hasattr(rel, "target_attack_id") else rel.get("target_attack_id")
                tgt_type = rel.target_type if hasattr(rel, "target_type") else rel.get("target_type")
                desc = rel.description if hasattr(rel, "description") else rel.get("description")
                conf = rel.confidence if hasattr(rel, "confidence") else rel.get("confidence")
                created = rel.created if hasattr(rel, "created") else rel.get("created")
                modified = rel.modified if hasattr(rel, "modified") else rel.get("modified")
                ext_refs = list(rel.external_references) if hasattr(rel, "external_references") else rel.get("external_references", [])
                revoked = rel.revoked if hasattr(rel, "revoked") else rel.get("revoked", False)

                existing = session.query(MitreAttackRelationshipModel).filter_by(
                    dataset_version_id=version_id, stix_id=stix_id
                ).first()

                if not existing:
                    model = MitreAttackRelationshipModel(
                        stix_id=stix_id,
                        dataset_version_id=version_id,
                        source_ref=src_ref,
                        source_attack_id=src_atk,
                        source_type=src_type,
                        target_ref=tgt_ref,
                        target_attack_id=tgt_atk,
                        target_type=tgt_type,
                        relationship_type=rel_type,
                        description=desc,
                        confidence=conf,
                        created=created,
                        modified=modified,
                        external_references_json=serialize_json(ext_refs),
                        revoked=revoked,
                    )
                    session.add(model)
                    count += 1
                else:
                    existing.source_ref = src_ref
                    existing.source_attack_id = src_atk
                    existing.source_type = src_type
                    existing.target_ref = tgt_ref
                    existing.target_attack_id = tgt_atk
                    existing.target_type = tgt_type
                    existing.relationship_type = rel_type
                    existing.description = desc
                    existing.confidence = conf
                    existing.created = created
                    existing.modified = modified
                    existing.external_references_json = serialize_json(ext_refs)
                    existing.revoked = revoked

            session.commit()
            return count

    def _resolve_mitre_version_id(self, version_id: Optional[str] = None, feed_id: str = "mitre_attack_enterprise") -> Optional[str]:
        if version_id:
            return version_id
        active_ver = self.get_active_dataset_version(feed_id)
        if active_ver:
            return active_ver.version_id
        latest_vers = self.list_dataset_versions(feed_id)
        return latest_vers[0].version_id if latest_vers else None

    def _to_mitre_dict(self, model: MitreAttackObjectModel) -> Dict[str, Any]:
        return {
            "stix_id": model.stix_id,
            "dataset_version_id": model.dataset_version_id,
            "type": model.type,
            "attack_id": model.attack_id,
            "name": model.name,
            "description": model.description,
            "is_subtechnique": model.is_subtechnique,
            "parent_technique_id": model.parent_technique_id,
            "tactics": deserialize_json(model.tactics_json) if model.tactics_json else [],
            "platforms": deserialize_json(model.platforms_json) if model.platforms_json else [],
            "aliases": deserialize_json(model.aliases_json) if model.aliases_json else [],
            "kill_chain_phases": deserialize_json(model.kill_chain_phases_json) if model.kill_chain_phases_json else [],
            "permissions_required": deserialize_json(model.permissions_required_json) if model.permissions_required_json else [],
            "system_requirements": deserialize_json(model.system_requirements_json) if model.system_requirements_json else [],
            "detection": model.detection,
            "contributors": deserialize_json(model.contributors_json) if model.contributors_json else [],
            "external_references": deserialize_json(model.external_references_json) if model.external_references_json else [],
            "url": model.url,
            "version": model.version,
            "created": model.created,
            "modified": model.modified,
            "revoked": model.revoked,
            "deprecated": model.deprecated,
        }

    def _to_rel_dict(self, model: MitreAttackRelationshipModel) -> Dict[str, Any]:
        return {
            "stix_id": model.stix_id,
            "dataset_version_id": model.dataset_version_id,
            "source_ref": model.source_ref,
            "source_attack_id": model.source_attack_id,
            "source_type": model.source_type,
            "target_ref": model.target_ref,
            "target_attack_id": model.target_attack_id,
            "target_type": model.target_type,
            "relationship_type": model.relationship_type,
            "description": model.description,
            "confidence": model.confidence,
            "created": model.created,
            "modified": model.modified,
            "external_references": deserialize_json(model.external_references_json) if model.external_references_json else [],
            "revoked": model.revoked,
        }

    def get_mitre_object(self, identifier: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Fetches a MITRE object by ATT&CK ID (e.g. T1059) or STIX ID (e.g. attack-pattern--...).
        """
        vid = self._resolve_mitre_version_id(version_id)
        with self._get_session() as session:
            query = session.query(MitreAttackObjectModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            
            res = query.filter(
                (MitreAttackObjectModel.attack_id == identifier) | (MitreAttackObjectModel.stix_id == identifier)
            ).first()

            if not res:
                return None
            return self._to_mitre_dict(res)

    def list_mitre_objects(
        self, type: Optional[str] = None, version_id: Optional[str] = None, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Lists MITRE objects filtered by type."""
        vid = self._resolve_mitre_version_id(version_id)
        with self._get_session() as session:
            query = session.query(MitreAttackObjectModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            if type:
                query = query.filter_by(type=type)
            records = query.limit(limit).all()
            return [self._to_mitre_dict(r) for r in records]

    def list_mitre_relationships(
        self,
        source_ref: Optional[str] = None,
        target_ref: Optional[str] = None,
        relationship_type: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Lists STIX relationships filtered by source, target, or relationship_type."""
        vid = self._resolve_mitre_version_id(version_id)
        with self._get_session() as session:
            query = session.query(MitreAttackRelationshipModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            if source_ref:
                query = query.filter(
                    (MitreAttackRelationshipModel.source_ref == source_ref) | (MitreAttackRelationshipModel.source_attack_id == source_ref)
                )
            if target_ref:
                query = query.filter(
                    (MitreAttackRelationshipModel.target_ref == target_ref) | (MitreAttackRelationshipModel.target_attack_id == target_ref)
                )
            if relationship_type:
                query = query.filter_by(relationship_type=relationship_type)
            records = query.limit(limit).all()
            return [self._to_rel_dict(r) for r in records]

    def search_mitre_objects(
        self,
        query: str = "",
        technique_id: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        alias: Optional[str] = None,
        entity_type: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Searches MITRE objects by keyword, technique ID, tactic, platform, alias, or entity_type.
        """
        vid = self._resolve_mitre_version_id(version_id)
        with self._get_session() as session:
            q = session.query(MitreAttackObjectModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)

            if technique_id:
                q = q.filter(
                    (MitreAttackObjectModel.attack_id == technique_id) | (MitreAttackObjectModel.parent_technique_id == technique_id)
                )
            if entity_type:
                q = q.filter_by(type=entity_type)
            if tactic:
                t_lower = tactic.lower()
                q = q.filter(MitreAttackObjectModel.tactics_json.ilike(f"%{t_lower}%"))
            if platform:
                p_lower = platform.lower()
                q = q.filter(MitreAttackObjectModel.platforms_json.ilike(f"%{p_lower}%"))
            if alias:
                a_lower = alias.lower()
                q = q.filter(MitreAttackObjectModel.aliases_json.ilike(f"%{a_lower}%"))

            if query:
                kw = f"%{query}%"
                q = q.filter(
                    (MitreAttackObjectModel.name.ilike(kw))
                    | (MitreAttackObjectModel.attack_id.ilike(kw))
                    | (MitreAttackObjectModel.description.ilike(kw))
                    | (MitreAttackObjectModel.aliases_json.ilike(kw))
                )

            records = q.limit(limit).all()
            return [self._to_mitre_dict(r) for r in records]

    def get_mitre_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Calculates breakdown statistics for MITRE dataset version."""
        vid = self._resolve_mitre_version_id(version_id)
        with self._get_session() as session:
            if not vid:
                return {
                    "version_id": None,
                    "total_objects": 0,
                    "total_relationships": 0,
                    "techniques_count": 0,
                    "subtechniques_count": 0,
                    "tactics_count": 0,
                    "groups_count": 0,
                    "software_count": 0,
                    "campaigns_count": 0,
                    "mitigations_count": 0,
                    "data_sources_count": 0,
                }

            total_obj = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid).scalar() or 0
            total_rel = session.query(func.count(MitreAttackRelationshipModel.id)).filter_by(dataset_version_id=vid).scalar() or 0

            tactics_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="x-mitre-tactic").scalar() or 0
            tech_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="attack-pattern", is_subtechnique=False).scalar() or 0
            subtech_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="attack-pattern", is_subtechnique=True).scalar() or 0
            groups_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="intrusion-set").scalar() or 0
            malware_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="malware").scalar() or 0
            tools_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="tool").scalar() or 0
            campaigns_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="campaign").scalar() or 0
            mitigations_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="course-of-action").scalar() or 0
            datasources_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="x-mitre-data-source").scalar() or 0
            datacomponents_cnt = session.query(func.count(MitreAttackObjectModel.id)).filter_by(dataset_version_id=vid, type="x-mitre-data-component").scalar() or 0

            return {
                "version_id": vid,
                "total_objects": total_obj,
                "total_relationships": total_rel,
                "tactics_count": tactics_cnt,
                "techniques_count": tech_cnt,
                "subtechniques_count": subtech_cnt,
                "groups_count": groups_cnt,
                "software_count": malware_cnt + tools_cnt,
                "malware_count": malware_cnt,
                "tools_count": tools_cnt,
                "campaigns_count": campaigns_cnt,
                "mitigations_count": mitigations_cnt,
                "data_sources_count": datasources_cnt,
                "data_components_count": datacomponents_cnt,
            }

    # -------------------------------------------------------------------------
    # NVD Enterprise CVE JSON 2.0 Repository Operations
    # -------------------------------------------------------------------------

    def save_nvd_cves(self, version_id: str, cves: List[Any]) -> Dict[str, int]:
        """
        Saves normalized NvdCve objects for dataset version_id.
        Returns dict with counts of inserted, updated, and duplicates.
        """
        inserted = 0
        updated = 0
        duplicates = 0

        with self._get_session() as session:
            for cve in cves:
                cve_dict = cve.to_dict() if hasattr(cve, "to_dict") else cve
                cve_id = cve_dict.get("cve_id")
                if not cve_id:
                    continue

                existing = session.query(NvdCveModel).filter_by(
                    dataset_version_id=version_id, cve_id=cve_id
                ).first()

                src_id = cve_dict.get("source_identifier")
                pub = cve_dict.get("published")
                mod = cve_dict.get("last_modified")
                v_stat = cve_dict.get("vuln_status")
                title = cve_dict.get("title")
                desc = cve_dict.get("description")
                sev = cve_dict.get("severity", "UNKNOWN")
                cvss_score = float(cve_dict.get("cvss_score", 0.0))

                descs_json = serialize_json(cve_dict.get("descriptions_map", {}))
                v2_json = serialize_json(cve_dict.get("cvss_v2", {}))
                v30_json = serialize_json(cve_dict.get("cvss_v30", {}))
                v31_json = serialize_json(cve_dict.get("cvss_v31", {}))
                v40_json = serialize_json(cve_dict.get("cvss_v40", {}))

                weaknesses_json = serialize_json(cve_dict.get("weaknesses", []))
                cwes_json = serialize_json(cve_dict.get("cwes", []))
                configs_json = serialize_json(cve_dict.get("configurations", []))
                cpe_matches_json = serialize_json(cve_dict.get("cpe_matches", []))
                vendors_json = serialize_json(cve_dict.get("vendors", []))
                products_json = serialize_json(cve_dict.get("products", []))
                references_json = serialize_json(cve_dict.get("references", []))
                comments_json = serialize_json(cve_dict.get("vendor_comments", []))
                raw_nvd_json = serialize_json(cve_dict.get("raw_nvd", {}))

                if not existing:
                    model = NvdCveModel(
                        cve_id=cve_id,
                        dataset_version_id=version_id,
                        source_identifier=src_id,
                        published=pub,
                        last_modified=mod,
                        vuln_status=v_stat,
                        title=title,
                        description=desc,
                        severity=sev,
                        cvss_score=cvss_score,
                        descriptions_json=descs_json,
                        cvss_v2_json=v2_json,
                        cvss_v30_json=v30_json,
                        cvss_v31_json=v31_json,
                        cvss_v40_json=v40_json,
                        weaknesses_json=weaknesses_json,
                        cwes_json=cwes_json,
                        configurations_json=configs_json,
                        cpe_matches_json=cpe_matches_json,
                        vendors_json=vendors_json,
                        products_json=products_json,
                        references_json=references_json,
                        vendor_comments_json=comments_json,
                        raw_nvd_json=raw_nvd_json,
                    )
                    session.add(model)
                    inserted += 1
                else:
                    existing.source_identifier = src_id
                    existing.published = pub
                    existing.last_modified = mod
                    existing.vuln_status = v_stat
                    existing.title = title
                    existing.description = desc
                    existing.severity = sev
                    existing.cvss_score = cvss_score
                    existing.descriptions_json = descs_json
                    existing.cvss_v2_json = v2_json
                    existing.cvss_v30_json = v30_json
                    existing.cvss_v31_json = v31_json
                    existing.cvss_v40_json = v40_json
                    existing.weaknesses_json = weaknesses_json
                    existing.cwes_json = cwes_json
                    existing.configurations_json = configs_json
                    existing.cpe_matches_json = cpe_matches_json
                    existing.vendors_json = vendors_json
                    existing.products_json = products_json
                    existing.references_json = references_json
                    existing.vendor_comments_json = comments_json
                    existing.raw_nvd_json = raw_nvd_json
                    updated += 1
                    duplicates += 1

            session.commit()
            return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def _resolve_nvd_version_id(self, version_id: Optional[str] = None, feed_id: str = "nvd_cve_2.0") -> Optional[str]:
        if version_id:
            return version_id
        active_ver = self.get_active_dataset_version(feed_id)
        if active_ver:
            return active_ver.version_id
        latest_vers = self.list_dataset_versions(feed_id)
        return latest_vers[0].version_id if latest_vers else None

    def _to_nvd_dict(self, model: NvdCveModel) -> Dict[str, Any]:
        return {
            "cve_id": model.cve_id,
            "dataset_version_id": model.dataset_version_id,
            "source_identifier": model.source_identifier,
            "published": model.published,
            "last_modified": model.last_modified,
            "vuln_status": model.vuln_status,
            "title": model.title,
            "description": model.description,
            "severity": model.severity,
            "cvss_score": model.cvss_score,
            "descriptions_map": deserialize_json(model.descriptions_json) if model.descriptions_json else {},
            "cvss_v2": deserialize_json(model.cvss_v2_json) if model.cvss_v2_json else None,
            "cvss_v30": deserialize_json(model.cvss_v30_json) if model.cvss_v30_json else None,
            "cvss_v31": deserialize_json(model.cvss_v31_json) if model.cvss_v31_json else None,
            "cvss_v40": deserialize_json(model.cvss_v40_json) if model.cvss_v40_json else None,
            "weaknesses": deserialize_json(model.weaknesses_json) if model.weaknesses_json else [],
            "cwes": deserialize_json(model.cwes_json) if model.cwes_json else [],
            "configurations": deserialize_json(model.configurations_json) if model.configurations_json else [],
            "cpe_matches": deserialize_json(model.cpe_matches_json) if model.cpe_matches_json else [],
            "vendors": deserialize_json(model.vendors_json) if model.vendors_json else [],
            "products": deserialize_json(model.products_json) if model.products_json else [],
            "references": deserialize_json(model.references_json) if model.references_json else [],
            "vendor_comments": deserialize_json(model.vendor_comments_json) if model.vendor_comments_json else [],
        }

    def get_nvd_cve(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            query = session.query(NvdCveModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rec = query.filter(NvdCveModel.cve_id.ilike(cve_id.strip())).first()
            if not rec:
                return None
            return self._to_nvd_dict(rec)

    def list_nvd_cves(
        self,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            query = session.query(NvdCveModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            if severity:
                query = query.filter(NvdCveModel.severity.ilike(severity.strip()))
            if vendor:
                v_lower = vendor.lower()
                query = query.filter(NvdCveModel.vendors_json.ilike(f"%{v_lower}%"))
            if product:
                p_lower = product.lower()
                query = query.filter(NvdCveModel.products_json.ilike(f"%{p_lower}%"))

            records = query.order_by(NvdCveModel.cvss_score.desc()).offset(offset).limit(limit).all()
            return [self._to_nvd_dict(r) for r in records]

    def search_nvd_cves(
        self,
        query: str = "",
        cve_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        cwe: Optional[str] = None,
        severity: Optional[str] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
        pub_start: Optional[str] = None,
        pub_end: Optional[str] = None,
        mod_start: Optional[str] = None,
        mod_end: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            q = session.query(NvdCveModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)

            if cve_id:
                q = q.filter(NvdCveModel.cve_id.ilike(f"%{cve_id.strip()}%"))
            if severity:
                q = q.filter(NvdCveModel.severity.ilike(severity.strip()))
            if vendor:
                v_lower = vendor.lower()
                q = q.filter(NvdCveModel.vendors_json.ilike(f"%{v_lower}%"))
            if product:
                p_lower = product.lower()
                q = q.filter(NvdCveModel.products_json.ilike(f"%{p_lower}%"))
            if cwe:
                cwe_upper = cwe.upper()
                q = q.filter(NvdCveModel.cwes_json.ilike(f"%{cwe_upper}%"))
            if min_cvss is not None:
                q = q.filter(NvdCveModel.cvss_score >= float(min_cvss))
            if max_cvss is not None:
                q = q.filter(NvdCveModel.cvss_score <= float(max_cvss))
            if pub_start:
                q = q.filter(NvdCveModel.published >= pub_start)
            if pub_end:
                q = q.filter(NvdCveModel.published <= pub_end)
            if mod_start:
                q = q.filter(NvdCveModel.last_modified >= mod_start)
            if mod_end:
                q = q.filter(NvdCveModel.last_modified <= mod_end)

            if query:
                kw = f"%{query}%"
                q = q.filter(
                    (NvdCveModel.cve_id.ilike(kw))
                    | (NvdCveModel.description.ilike(kw))
                    | (NvdCveModel.title.ilike(kw))
                    | (NvdCveModel.vendors_json.ilike(kw))
                    | (NvdCveModel.products_json.ilike(kw))
                    | (NvdCveModel.cwes_json.ilike(kw))
                )

            records = q.order_by(NvdCveModel.cvss_score.desc()).limit(limit).all()
            return [self._to_nvd_dict(r) for r in records]

    def list_nvd_vendors(self, version_id: Optional[str] = None) -> List[str]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            query = session.query(NvdCveModel.vendors_json)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rows = query.all()
            vendors_set = set()
            for r in rows:
                if r[0]:
                    v_list = deserialize_json(r[0])
                    if isinstance(v_list, list):
                        vendors_set.update(v_list)
            return sorted(vendors_set)

    def list_nvd_products(self, version_id: Optional[str] = None) -> List[str]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            query = session.query(NvdCveModel.products_json)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rows = query.all()
            products_set = set()
            for r in rows:
                if r[0]:
                    p_list = deserialize_json(r[0])
                    if isinstance(p_list, list):
                        products_set.update(p_list)
            return sorted(products_set)

    def list_nvd_cwes(self, version_id: Optional[str] = None) -> List[str]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            query = session.query(NvdCveModel.cwes_json)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rows = query.all()
            cwes_set = set()
            for r in rows:
                if r[0]:
                    c_list = deserialize_json(r[0])
                    if isinstance(c_list, list):
                        cwes_set.update(c_list)
            return sorted(cwes_set)

    def get_nvd_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        vid = self._resolve_nvd_version_id(version_id)
        with self._get_session() as session:
            if not vid:
                return {
                    "version_id": None,
                    "total_cves": 0,
                    "cves_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                    "average_cvss": 0.0,
                }

            total_cves = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid).scalar() or 0
            avg_cvss = session.query(func.avg(NvdCveModel.cvss_score)).filter_by(dataset_version_id=vid).scalar() or 0.0

            crit = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid, severity="CRITICAL").scalar() or 0
            high = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid, severity="HIGH").scalar() or 0
            med = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid, severity="MEDIUM").scalar() or 0
            low = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid, severity="LOW").scalar() or 0
            unkn = session.query(func.count(NvdCveModel.id)).filter_by(dataset_version_id=vid, severity="UNKNOWN").scalar() or 0

            return {
                "version_id": vid,
                "total_cves": total_cves,
                "average_cvss": round(float(avg_cvss), 2),
                "cves_by_severity": {
                    "CRITICAL": crit,
                    "HIGH": high,
                    "MEDIUM": med,
                    "LOW": low,
                    "UNKNOWN": unkn,
                },
            }

    # -------------------------------------------------------------------------
    # CISA KEV Pipeline (IL-4) Repository Methods
    # -------------------------------------------------------------------------

    def _resolve_kev_version_id(self, version_id: Optional[str]) -> Optional[str]:
        if version_id:
            return version_id
        active = self.get_active_dataset_version("cisa_kev_1.0")
        if active:
            return active.version_id
        return None

    def store_kev_records(self, version_id: str, records: List[Any]) -> Dict[str, int]:
        inserted = 0
        updated = 0
        duplicates = 0
        with self._get_session() as session:
            for rec in records:
                cve_id = rec.cve_id if hasattr(rec, "cve_id") else rec.get("cve_id")
                vendor = rec.vendor_project if hasattr(rec, "vendor_project") else rec.get("vendor_project")
                prod = rec.product if hasattr(rec, "product") else rec.get("product")
                vname = rec.vulnerability_name if hasattr(rec, "vulnerability_name") else rec.get("vulnerability_name")
                date_add = rec.date_added if hasattr(rec, "date_added") else rec.get("date_added")
                sdesc = rec.short_description if hasattr(rec, "short_description") else rec.get("short_description")
                req_act = rec.required_action if hasattr(rec, "required_action") else rec.get("required_action")
                due = rec.due_date if hasattr(rec, "due_date") else rec.get("due_date")
                ransom = rec.known_ransomware_campaign_use if hasattr(rec, "known_ransomware_campaign_use") else rec.get("known_ransomware_campaign_use")
                notes = rec.notes if hasattr(rec, "notes") else rec.get("notes")
                cat_ver = rec.catalog_version if hasattr(rec, "catalog_version") else rec.get("catalog_version")
                cwes = list(rec.cwes) if hasattr(rec, "cwes") else (rec.get("cwes", []) if hasattr(rec, "get") else [])
                refs = list(rec.reference_urls) if hasattr(rec, "reference_urls") else (rec.get("reference_urls", []) if hasattr(rec, "get") else [])

                existing = session.query(KevEntryModel).filter_by(
                    dataset_version_id=version_id, cve_id=cve_id
                ).first()

                if existing:
                    duplicates += 1
                    updated += 1
                    existing.vendor_project = vendor
                    existing.product = prod
                    existing.vulnerability_name = vname
                    existing.date_added = date_add
                    existing.short_description = sdesc
                    existing.required_action = req_act
                    existing.due_date = due
                    existing.known_ransomware_campaign_use = ransom
                    existing.notes = notes
                    existing.catalog_version = cat_ver
                    existing.cwes_json = serialize_json(cwes)
                    existing.reference_urls_json = serialize_json(refs)
                else:
                    inserted += 1
                    model = KevEntryModel(
                        cve_id=cve_id,
                        dataset_version_id=version_id,
                        vendor_project=vendor,
                        product=prod,
                        vulnerability_name=vname,
                        date_added=date_add,
                        short_description=sdesc,
                        required_action=req_act,
                        due_date=due,
                        known_ransomware_campaign_use=ransom,
                        notes=notes,
                        catalog_version=cat_ver,
                        cwes_json=serialize_json(cwes),
                        reference_urls_json=serialize_json(refs),
                        metadata_json=serialize_json({"catalog_version": cat_ver, "notes": notes}),
                    )
                    session.add(model)

                    # Store references
                    for url in refs:
                        ref_model = KevReferenceModel(
                            cve_id=cve_id,
                            dataset_version_id=version_id,
                            url=url
                        )
                        session.add(ref_model)

                    # Store audit history
                    hist = KevHistoryModel(
                        cve_id=cve_id,
                        dataset_version_id=version_id,
                        change_type="CREATED",
                        details_json=serialize_json({"vendor": vendor, "product": prod, "due_date": due}),
                    )
                    session.add(hist)

            session.commit()
        return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def list_kev_records(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        ransomware: Optional[str] = None,
        due_date: Optional[str] = None,
        date_added: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            query = session.query(KevEntryModel)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            if vendor:
                query = query.filter(func.lower(KevEntryModel.vendor_project).contains(vendor.lower()))
            if product:
                query = query.filter(func.lower(KevEntryModel.product).contains(product.lower()))
            if ransomware:
                query = query.filter(func.lower(KevEntryModel.known_ransomware_campaign_use).contains(ransomware.lower()))
            if due_date:
                query = query.filter(KevEntryModel.due_date == due_date)
            if date_added:
                query = query.filter(KevEntryModel.date_added == date_added)

            query = query.offset(offset).limit(limit)
            rows = query.all()
            return [self._kev_model_to_dict(r) for r in rows]

    def get_kev_record(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            query = session.query(KevEntryModel).filter(KevEntryModel.cve_id == cve_id)
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            row = query.first()
            if row:
                return self._kev_model_to_dict(row)
            return None

    def list_kev_vendors(self, version_id: Optional[str] = None) -> List[str]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            query = session.query(KevEntryModel.vendor_project).distinct()
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rows = query.all()
            return sorted([r[0] for r in rows if r[0]])

    def list_kev_products(self, version_id: Optional[str] = None) -> List[str]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            query = session.query(KevEntryModel.product).distinct()
            if vid:
                query = query.filter_by(dataset_version_id=vid)
            rows = query.all()
            return sorted([r[0] for r in rows if r[0]])

    def search_kev_records(
        self,
        query: str = "",
        cve_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        due_date: Optional[str] = None,
        ransomware: Optional[str] = None,
        exploitation_status: Optional[str] = None,
        date_added: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            q = session.query(KevEntryModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            if cve_id:
                q = q.filter(KevEntryModel.cve_id == cve_id)
            if vendor:
                q = q.filter(func.lower(KevEntryModel.vendor_project).contains(vendor.lower()))
            if product:
                q = q.filter(func.lower(KevEntryModel.product).contains(product.lower()))
            if due_date:
                q = q.filter(KevEntryModel.due_date == due_date)
            if ransomware:
                q = q.filter(func.lower(KevEntryModel.known_ransomware_campaign_use).contains(ransomware.lower()))
            if date_added:
                q = q.filter(KevEntryModel.date_added == date_added)
            if query:
                pattern = f"%{query.lower()}%"
                q = q.filter(
                    func.lower(KevEntryModel.cve_id).like(pattern) |
                    func.lower(KevEntryModel.vulnerability_name).like(pattern) |
                    func.lower(KevEntryModel.short_description).like(pattern) |
                    func.lower(KevEntryModel.vendor_project).like(pattern) |
                    func.lower(KevEntryModel.product).like(pattern) |
                    func.lower(KevEntryModel.required_action).like(pattern)
                )

            q = q.limit(limit)
            rows = q.all()
            return [self._kev_model_to_dict(r) for r in rows]

    def get_kev_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        vid = self._resolve_kev_version_id(version_id)
        with self._get_session() as session:
            if not vid:
                return {
                    "version_id": None,
                    "total_entries": 0,
                    "vendors_count": 0,
                    "products_count": 0,
                    "ransomware_count": 0,
                    "upcoming_due_dates_count": 0,
                    "overdue_count": 0,
                    "catalog_versions": [],
                }

            total = session.query(func.count(KevEntryModel.id)).filter_by(dataset_version_id=vid).scalar() or 0
            vendors_cnt = session.query(func.count(func.distinct(KevEntryModel.vendor_project))).filter_by(dataset_version_id=vid).scalar() or 0
            products_cnt = session.query(func.count(func.distinct(KevEntryModel.product))).filter_by(dataset_version_id=vid).scalar() or 0
            ransom_cnt = session.query(func.count(KevEntryModel.id)).filter(
                KevEntryModel.dataset_version_id == vid,
                func.lower(KevEntryModel.known_ransomware_campaign_use).contains("known")
            ).scalar() or 0

            # Date statistics
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            overdue_cnt = session.query(func.count(KevEntryModel.id)).filter(
                KevEntryModel.dataset_version_id == vid,
                KevEntryModel.due_date < today_str
            ).scalar() or 0

            upcoming_cnt = session.query(func.count(KevEntryModel.id)).filter(
                KevEntryModel.dataset_version_id == vid,
                KevEntryModel.due_date >= today_str
            ).scalar() or 0

            cat_vers = session.query(KevEntryModel.catalog_version).filter_by(dataset_version_id=vid).distinct().all()
            catalog_versions = sorted([r[0] for r in cat_vers if r[0]])

            return {
                "version_id": vid,
                "total_entries": total,
                "vendors_count": vendors_cnt,
                "products_count": products_cnt,
                "ransomware_count": ransom_cnt,
                "upcoming_due_dates_count": upcoming_cnt,
                "overdue_count": overdue_cnt,
                "catalog_versions": catalog_versions,
            }

    def _kev_model_to_dict(self, model: KevEntryModel) -> Dict[str, Any]:
        return {
            "cve_id": model.cve_id,
            "dataset_version_id": model.dataset_version_id,
            "vendor_project": model.vendor_project,
            "product": model.product,
            "vulnerability_name": model.vulnerability_name,
            "date_added": model.date_added,
            "short_description": model.short_description,
            "required_action": model.required_action,
            "due_date": model.due_date,
            "known_ransomware_campaign_use": model.known_ransomware_campaign_use,
            "notes": model.notes,
            "catalog_version": model.catalog_version,
            "cwes": deserialize_json(model.cwes_json or "[]"),
            "reference_urls": deserialize_json(model.reference_urls_json or "[]"),
            "status": model.status,
            "created_at": model.created_at.isoformat() if model.created_at else None,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }




    # =========================================================================
    # EPSS (Exploit Prediction Scoring System) Repository Methods
    # =========================================================================

    def save_epss_scores(self, version_id: str, records: list) -> Dict[str, int]:
        """
        Stores normalized EpssRecord objects for a given dataset version_id.
        Performs upsert: updates existing records, inserts new ones.
        """
        inserted = 0
        updated = 0
        duplicates = 0

        with self._session_factory() as session:
            for rec in records:
                existing = session.query(EpssScoreModel).filter_by(
                    dataset_version_id=version_id,
                    cve_id=rec.cve_id,
                ).first()

                if existing:
                    existing.epss_score = rec.current_score
                    existing.epss_percentile = rec.current_percentile
                    existing.publication_date = rec.publication_date
                    existing.model_version = rec.model_version
                    existing.trend = rec.trend
                    existing.moving_avg_7d = rec.moving_avg_7d
                    existing.moving_avg_30d = rec.moving_avg_30d
                    existing.historical_high = rec.historical_high
                    existing.historical_low = rec.historical_low
                    existing.observation_count = rec.observation_count
                    existing.status = rec.status
                    existing.metadata_json = serialize_json(rec.metadata or {})
                    existing.last_updated = datetime.now(timezone.utc)
                    updated += 1
                else:
                    from datetime import datetime as _dt
                    first_obs = None
                    if rec.first_observed:
                        try:
                            first_obs = _dt.fromisoformat(rec.first_observed.replace("Z", "+00:00"))
                        except Exception:
                            first_obs = datetime.now(timezone.utc)

                    model = EpssScoreModel(
                        cve_id=rec.cve_id,
                        dataset_version_id=version_id,
                        epss_score=rec.current_score,
                        epss_percentile=rec.current_percentile,
                        publication_date=rec.publication_date,
                        model_version=rec.model_version,
                        trend=rec.trend,
                        moving_avg_7d=rec.moving_avg_7d,
                        moving_avg_30d=rec.moving_avg_30d,
                        historical_high=rec.historical_high,
                        historical_low=rec.historical_low,
                        first_observed=first_obs,
                        last_updated=datetime.now(timezone.utc),
                        observation_count=rec.observation_count,
                        status=rec.status,
                        metadata_json=serialize_json(rec.metadata or {}),
                    )
                    session.add(model)
                    inserted += 1

            session.commit()

        return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def save_epss_history(self, version_id: str, historical_scores: list) -> Dict[str, int]:
        """
        Stores EpssHistoricalScore snapshots for a given dataset version_id.
        Skips duplicates (same cve_id + dataset_version_id + score_date).
        """
        inserted = 0
        duplicates = 0

        with self._session_factory() as session:
            for snap in historical_scores:
                existing = session.query(EpssHistoryModel).filter_by(
                    dataset_version_id=version_id,
                    cve_id=snap.cve_id,
                    score_date=snap.date,
                ).first()

                if existing:
                    duplicates += 1
                    continue

                model = EpssHistoryModel(
                    cve_id=snap.cve_id,
                    dataset_version_id=version_id,
                    epss_score=snap.epss_score,
                    epss_percentile=snap.epss_percentile,
                    score_date=snap.date,
                    model_version=snap.model_version,
                    daily_delta_score=snap.daily_delta_score,
                    daily_delta_percentile=snap.daily_delta_percentile,
                )
                session.add(model)
                inserted += 1

            session.commit()

        return {"inserted": inserted, "updated": 0, "duplicates": duplicates}

    def get_epss_score(self, cve_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves the current EPSS score for a specific CVE ID.
        If version_id is None, uses the active dataset version.
        """
        with self._session_factory() as session:
            vid = version_id or self._get_active_version_id("first_epss_1.0", session)
            if not vid:
                return None

            model = session.query(EpssScoreModel).filter_by(
                dataset_version_id=vid,
                cve_id=cve_id.upper(),
            ).first()

            return self._epss_score_model_to_dict(model) if model else None

    def get_epss_history(self, cve_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves historical EPSS scores for a specific CVE, ordered by date descending.
        """
        with self._session_factory() as session:
            records = (
                session.query(EpssHistoryModel)
                .filter(EpssHistoryModel.cve_id == cve_id.upper())
                .order_by(EpssHistoryModel.score_date.desc())
                .limit(limit)
                .all()
            )
            return [self._epss_history_model_to_dict(r) for r in records]

    def list_epss_scores(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists EPSS scores with optional filters."""
        with self._session_factory() as session:
            vid = version_id or self._get_active_version_id("first_epss_1.0", session)
            if not vid:
                return []

            q = session.query(EpssScoreModel).filter(
                EpssScoreModel.dataset_version_id == vid
            )

            if min_score is not None:
                q = q.filter(EpssScoreModel.epss_score >= min_score)
            if max_score is not None:
                q = q.filter(EpssScoreModel.epss_score <= max_score)
            if min_percentile is not None:
                q = q.filter(EpssScoreModel.epss_percentile >= min_percentile)
            if max_percentile is not None:
                q = q.filter(EpssScoreModel.epss_percentile <= max_percentile)
            if trend:
                q = q.filter(EpssScoreModel.trend == trend)

            records = q.order_by(EpssScoreModel.epss_score.desc()).offset(offset).limit(limit).all()
            return [self._epss_score_model_to_dict(r) for r in records]

    def search_epss_scores(
        self,
        cve_id: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        publication_date: Optional[str] = None,
        model_version: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Multi-parameter search across EPSS scores."""
        with self._session_factory() as session:
            vid = version_id or self._get_active_version_id("first_epss_1.0", session)
            if not vid:
                return []

            q = session.query(EpssScoreModel).filter(
                EpssScoreModel.dataset_version_id == vid
            )

            if cve_id:
                q = q.filter(EpssScoreModel.cve_id == cve_id.upper())
            if min_score is not None:
                q = q.filter(EpssScoreModel.epss_score >= min_score)
            if max_score is not None:
                q = q.filter(EpssScoreModel.epss_score <= max_score)
            if min_percentile is not None:
                q = q.filter(EpssScoreModel.epss_percentile >= min_percentile)
            if max_percentile is not None:
                q = q.filter(EpssScoreModel.epss_percentile <= max_percentile)
            if trend:
                q = q.filter(EpssScoreModel.trend == trend)
            if publication_date:
                q = q.filter(EpssScoreModel.publication_date == publication_date)
            if model_version:
                q = q.filter(EpssScoreModel.model_version == model_version)

            records = q.order_by(EpssScoreModel.epss_score.desc()).limit(limit).all()
            return [self._epss_score_model_to_dict(r) for r in records]

    def get_trending_epss_cves(
        self,
        trend_type: str = "INCREASING",
        limit: int = 100,
        version_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves CVEs with a specific trend classification, ordered by score descending."""
        with self._session_factory() as session:
            vid = version_id or self._get_active_version_id("first_epss_1.0", session)
            if not vid:
                return []

            records = (
                session.query(EpssScoreModel)
                .filter(
                    EpssScoreModel.dataset_version_id == vid,
                    EpssScoreModel.trend == trend_type,
                )
                .order_by(EpssScoreModel.epss_score.desc())
                .limit(limit)
                .all()
            )
            return [self._epss_score_model_to_dict(r) for r in records]

    def get_epss_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns EPSS dataset breakdown statistics."""
        with self._session_factory() as session:
            vid = version_id or self._get_active_version_id("first_epss_1.0", session)
            if not vid:
                return {}

            total = session.query(func.count(EpssScoreModel.id)).filter_by(
                dataset_version_id=vid
            ).scalar() or 0

            avg_score = session.query(func.avg(EpssScoreModel.epss_score)).filter_by(
                dataset_version_id=vid
            ).scalar() or 0.0

            avg_percentile = session.query(func.avg(EpssScoreModel.epss_percentile)).filter_by(
                dataset_version_id=vid
            ).scalar() or 0.0

            high_prob = session.query(func.count(EpssScoreModel.id)).filter(
                EpssScoreModel.dataset_version_id == vid,
                EpssScoreModel.epss_score >= 0.5,
            ).scalar() or 0

            critical = session.query(func.count(EpssScoreModel.id)).filter(
                EpssScoreModel.dataset_version_id == vid,
                EpssScoreModel.epss_score >= 0.7,
            ).scalar() or 0

            # Trend distribution
            trend_rows = (
                session.query(EpssScoreModel.trend, func.count(EpssScoreModel.id))
                .filter(EpssScoreModel.dataset_version_id == vid)
                .group_by(EpssScoreModel.trend)
                .all()
            )
            trend_distribution = {row[0]: row[1] for row in trend_rows}

            # Top 10 highest scoring CVEs
            top_records = (
                session.query(EpssScoreModel)
                .filter(EpssScoreModel.dataset_version_id == vid)
                .order_by(EpssScoreModel.epss_score.desc())
                .limit(10)
                .all()
            )
            top_cves = [
                {
                    "cve_id": r.cve_id,
                    "epss_score": r.epss_score,
                    "epss_percentile": r.epss_percentile,
                    "trend": r.trend,
                }
                for r in top_records
            ]

            # Model versions in this dataset
            model_versions = [
                r[0] for r in session.query(EpssScoreModel.model_version)
                .filter_by(dataset_version_id=vid)
                .distinct()
                .all()
                if r[0]
            ]

            return {
                "version_id": vid,
                "total_records": total,
                "average_score": round(float(avg_score), 6),
                "average_percentile": round(float(avg_percentile), 6),
                "high_probability_cves": high_prob,
                "critical_cves": critical,
                "trend_distribution": trend_distribution,
                "top_cves": top_cves,
                "model_versions": model_versions,
            }

    def _get_active_version_id(self, feed_id: str, session: Session) -> Optional[str]:
        """Helper to retrieve active dataset version ID for a feed."""
        health = session.query(FeedHealthModel).filter_by(feed_id=feed_id).first()
        if health and health.active_dataset_version:
            return health.active_dataset_version
        # Fall back to most recent ACTIVATED version
        ver = (
            session.query(DatasetVersionModel)
            .filter_by(feed_id=feed_id, status="ACTIVE")
            .order_by(DatasetVersionModel.activated_at.desc())
            .first()
        )
        return ver.version_id if ver else None

    def _epss_score_model_to_dict(self, model: EpssScoreModel) -> Dict[str, Any]:
        return {
            "cve_id": model.cve_id,
            "dataset_version_id": model.dataset_version_id,
            "epss_score": model.epss_score,
            "epss_percentile": model.epss_percentile,
            "publication_date": model.publication_date,
            "model_version": model.model_version,
            "trend": model.trend,
            "moving_avg_7d": model.moving_avg_7d,
            "moving_avg_30d": model.moving_avg_30d,
            "historical_high": model.historical_high,
            "historical_low": model.historical_low,
            "first_observed": model.first_observed.isoformat() if model.first_observed else None,
            "last_updated": model.last_updated.isoformat() if model.last_updated else None,
            "observation_count": model.observation_count,
            "status": model.status,
            "metadata": deserialize_json(model.metadata_json or "{}"),
            "created_at": model.created_at.isoformat() if model.created_at else None,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }

    def _epss_history_model_to_dict(self, model: EpssHistoryModel) -> Dict[str, Any]:
        return {
            "cve_id": model.cve_id,
            "dataset_version_id": model.dataset_version_id,
            "epss_score": model.epss_score,
            "epss_percentile": model.epss_percentile,
            "date": model.score_date,
            "model_version": model.model_version,
            "daily_delta_score": model.daily_delta_score,
            "daily_delta_percentile": model.daily_delta_percentile,
            "timestamp": model.timestamp.isoformat() if model.timestamp else None,
        }

    # =====================================================================
    # IL-6: CWE Repository Methods
    # =====================================================================

    def save_cwe_weaknesses(self, version_id: str, entities: list) -> Dict[str, int]:
        """Persists CweEntity objects into the cwe_weakness table."""
        inserted = 0
        updated = 0
        duplicates = 0
        with self._get_session() as session:
            for ent in entities:
                d = ent.to_dict() if hasattr(ent, "to_dict") else ent
                existing = session.query(CweWeaknessModel).filter_by(
                    dataset_version_id=version_id,
                    cwe_id=d.get("cwe_id", ""),
                ).first()
                if existing:
                    existing.name = d.get("name", "")
                    existing.abstraction = d.get("abstraction")
                    existing.structure = d.get("structure")
                    existing.status = d.get("status")
                    existing.description = d.get("description")
                    existing.extended_description = d.get("extended_description")
                    existing.likelihood_of_exploit = d.get("likelihood_of_exploit")
                    existing.background_details = d.get("background_details")
                    existing.alternate_terms_json = serialize_json(d.get("alternate_terms", []))
                    existing.modes_of_introduction_json = serialize_json(d.get("modes_of_introduction", []))
                    existing.applicable_platforms_json = serialize_json(d.get("applicable_platforms", []))
                    existing.consequences_json = serialize_json(d.get("consequences", []))
                    existing.detection_methods_json = serialize_json(d.get("detection_methods", []))
                    existing.mitigations_json = serialize_json(d.get("mitigations", []))
                    existing.related_weaknesses_json = serialize_json(d.get("related_weaknesses", []))
                    existing.taxonomy_mappings_json = serialize_json(d.get("taxonomy_mappings", []))
                    existing.references_json = serialize_json(d.get("references", []))
                    existing.related_attack_patterns_json = serialize_json(d.get("related_attack_patterns", []))
                    existing.affected_resources_json = serialize_json(d.get("affected_resources", []))
                    existing.functional_areas_json = serialize_json(d.get("functional_areas", []))
                    existing.mapping_notes = d.get("mapping_notes")
                    existing.notes = d.get("notes")
                    existing.source_version = d.get("source_version")
                    existing.url = d.get("url")
                    updated += 1
                else:
                    session.add(CweWeaknessModel(
                        cwe_id=d.get("cwe_id", ""),
                        dataset_version_id=version_id,
                        name=d.get("name", ""),
                        abstraction=d.get("abstraction"),
                        structure=d.get("structure"),
                        status=d.get("status"),
                        description=d.get("description"),
                        extended_description=d.get("extended_description"),
                        likelihood_of_exploit=d.get("likelihood_of_exploit"),
                        background_details=d.get("background_details"),
                        alternate_terms_json=serialize_json(d.get("alternate_terms", [])),
                        modes_of_introduction_json=serialize_json(d.get("modes_of_introduction", [])),
                        applicable_platforms_json=serialize_json(d.get("applicable_platforms", [])),
                        consequences_json=serialize_json(d.get("consequences", [])),
                        detection_methods_json=serialize_json(d.get("detection_methods", [])),
                        mitigations_json=serialize_json(d.get("mitigations", [])),
                        related_weaknesses_json=serialize_json(d.get("related_weaknesses", [])),
                        taxonomy_mappings_json=serialize_json(d.get("taxonomy_mappings", [])),
                        references_json=serialize_json(d.get("references", [])),
                        related_attack_patterns_json=serialize_json(d.get("related_attack_patterns", [])),
                        affected_resources_json=serialize_json(d.get("affected_resources", [])),
                        functional_areas_json=serialize_json(d.get("functional_areas", [])),
                        mapping_notes=d.get("mapping_notes"),
                        notes=d.get("notes"),
                        source_version=d.get("source_version"),
                        url=d.get("url"),
                    ))
                    inserted += 1
            session.commit()
        return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def save_cwe_relationships(self, version_id: str, relationships: list) -> int:
        """Persists CweRelationship objects into the cwe_relationship table."""
        count = 0
        with self._get_session() as session:
            for rel in relationships:
                d = rel.to_dict() if hasattr(rel, "to_dict") else rel
                existing = session.query(CweRelationshipModel).filter_by(
                    dataset_version_id=version_id,
                    source_cwe_id=d.get("source_cwe_id", ""),
                    target_cwe_id=d.get("target_cwe_id", ""),
                    nature=d.get("nature", ""),
                ).first()
                if not existing:
                    session.add(CweRelationshipModel(
                        dataset_version_id=version_id,
                        source_cwe_id=d.get("source_cwe_id", ""),
                        target_cwe_id=d.get("target_cwe_id", ""),
                        nature=d.get("nature", ""),
                        view_id=d.get("view_id"),
                        ordinal=d.get("ordinal"),
                    ))
                    count += 1
            session.commit()
        return count

    def get_cwe_weakness(self, cwe_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a single CWE weakness by ID."""
        with self._get_session() as session:
            resolved_vid = self._resolve_cwe_version_id(version_id, session)
            q = session.query(CweWeaknessModel).filter(CweWeaknessModel.cwe_id == cwe_id)
            if resolved_vid:
                q = q.filter(CweWeaknessModel.dataset_version_id == resolved_vid)
            model = q.first()
            return self._cwe_model_to_dict(model) if model else None

    def list_cwe_weaknesses(
        self,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_cwe_version_id(version_id, session)
            q = session.query(CweWeaknessModel)
            if resolved_vid:
                q = q.filter(CweWeaknessModel.dataset_version_id == resolved_vid)
            if abstraction:
                q = q.filter(CweWeaknessModel.abstraction.ilike(f"%{abstraction}%"))
            if status:
                q = q.filter(CweWeaknessModel.status.ilike(f"%{status}%"))
            q = q.order_by(CweWeaknessModel.cwe_id).offset(offset).limit(limit)
            return [self._cwe_model_to_dict(m) for m in q.all()]

    def search_cwe_weaknesses(
        self,
        query: str = "",
        cwe_id: Optional[str] = None,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_cwe_version_id(version_id, session)
            q = session.query(CweWeaknessModel)
            if resolved_vid:
                q = q.filter(CweWeaknessModel.dataset_version_id == resolved_vid)
            if cwe_id:
                q = q.filter(CweWeaknessModel.cwe_id.ilike(f"%{cwe_id}%"))
            if abstraction:
                q = q.filter(CweWeaknessModel.abstraction.ilike(f"%{abstraction}%"))
            if status:
                q = q.filter(CweWeaknessModel.status.ilike(f"%{status}%"))
            if query:
                q = q.filter(
                    CweWeaknessModel.name.ilike(f"%{query}%")
                    | CweWeaknessModel.description.ilike(f"%{query}%")
                    | CweWeaknessModel.cwe_id.ilike(f"%{query}%")
                )
            q = q.limit(limit)
            return [self._cwe_model_to_dict(m) for m in q.all()]

    def list_cwe_relationships(
        self,
        cwe_id: Optional[str] = None,
        nature: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_cwe_version_id(version_id, session)
            q = session.query(CweRelationshipModel)
            if resolved_vid:
                q = q.filter(CweRelationshipModel.dataset_version_id == resolved_vid)
            if cwe_id:
                q = q.filter(
                    (CweRelationshipModel.source_cwe_id == cwe_id)
                    | (CweRelationshipModel.target_cwe_id == cwe_id)
                )
            if nature:
                q = q.filter(CweRelationshipModel.nature == nature)
            q = q.limit(limit)
            return [
                {
                    "source_cwe_id": m.source_cwe_id,
                    "target_cwe_id": m.target_cwe_id,
                    "nature": m.nature,
                    "view_id": m.view_id,
                    "ordinal": m.ordinal,
                }
                for m in q.all()
            ]

    def get_cwe_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        with self._get_session() as session:
            resolved_vid = self._resolve_cwe_version_id(version_id, session)
            if not resolved_vid:
                return {}
            total = session.query(func.count(CweWeaknessModel.id)).filter(
                CweWeaknessModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            rel_total = session.query(func.count(CweRelationshipModel.id)).filter(
                CweRelationshipModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            return {
                "total_weaknesses": total,
                "total_relationships": rel_total,
                "dataset_version_id": resolved_vid,
            }

    def _resolve_cwe_version_id(self, version_id: Optional[str], session: Session = None) -> Optional[str]:
        if version_id:
            return version_id
        active = self.get_active_dataset_version("mitre_cwe_xml")
        return active.version_id if active else None

    def _cwe_model_to_dict(self, model: CweWeaknessModel) -> Dict[str, Any]:
        return {
            "cwe_id": model.cwe_id,
            "name": model.name,
            "abstraction": model.abstraction,
            "structure": model.structure,
            "status": model.status,
            "description": model.description,
            "extended_description": model.extended_description,
            "likelihood_of_exploit": model.likelihood_of_exploit,
            "background_details": model.background_details,
            "alternate_terms": deserialize_json(model.alternate_terms_json or "[]"),
            "modes_of_introduction": deserialize_json(model.modes_of_introduction_json or "[]"),
            "applicable_platforms": deserialize_json(model.applicable_platforms_json or "[]"),
            "consequences": deserialize_json(model.consequences_json or "[]"),
            "detection_methods": deserialize_json(model.detection_methods_json or "[]"),
            "mitigations": deserialize_json(model.mitigations_json or "[]"),
            "related_weaknesses": deserialize_json(model.related_weaknesses_json or "[]"),
            "taxonomy_mappings": deserialize_json(model.taxonomy_mappings_json or "[]"),
            "references": deserialize_json(model.references_json or "[]"),
            "related_attack_patterns": deserialize_json(model.related_attack_patterns_json or "[]"),
            "affected_resources": deserialize_json(model.affected_resources_json or "[]"),
            "functional_areas": deserialize_json(model.functional_areas_json or "[]"),
            "mapping_notes": model.mapping_notes,
            "notes": model.notes,
            "source_version": model.source_version,
            "url": model.url,
        }

    # =====================================================================
    # IL-6: CAPEC Repository Methods
    # =====================================================================

    def save_capec_attack_patterns(self, version_id: str, entities: list) -> Dict[str, int]:
        """Persists CapecEntity objects into the capec_attack_pattern table."""
        inserted = 0
        updated = 0
        with self._get_session() as session:
            for ent in entities:
                d = ent.to_dict() if hasattr(ent, "to_dict") else ent
                props = d.get("properties", d)  # support both raw dict and canonical dict
                existing = session.query(CapecAttackPatternModel).filter_by(
                    dataset_version_id=version_id,
                    capec_id=d.get("capec_id", ""),
                ).first()

                attack_ids = props.get("attack_technique_ids", []) if isinstance(props, dict) else []

                if existing:
                    existing.name = d.get("name", "")
                    existing.abstraction = d.get("abstraction")
                    existing.status = d.get("status")
                    existing.description = d.get("description")
                    existing.extended_description = d.get("extended_description")
                    existing.likelihood_of_attack = d.get("likelihood_of_attack")
                    existing.typical_severity = d.get("typical_severity")
                    existing.execution_flow_json = serialize_json(d.get("execution_flow", []))
                    existing.prerequisites_json = serialize_json(d.get("prerequisites", []))
                    existing.skills_required_json = serialize_json(d.get("skills_required", []))
                    existing.resources_required_json = serialize_json(d.get("resources_required", []))
                    existing.indicators_json = serialize_json(d.get("indicators", []))
                    existing.consequences_json = serialize_json(d.get("consequences", []))
                    existing.mitigations_json = serialize_json(d.get("mitigations", []))
                    existing.detection_json = serialize_json(d.get("detection", []))
                    existing.example_instances_json = serialize_json(d.get("example_instances", []))
                    existing.related_attack_patterns_json = serialize_json(d.get("related_attack_patterns", []))
                    existing.related_weaknesses_json = serialize_json(d.get("related_weaknesses", []))
                    existing.taxonomy_mappings_json = serialize_json(d.get("taxonomy_mappings", []))
                    existing.attack_technique_ids_json = serialize_json(attack_ids)
                    existing.references_json = serialize_json(d.get("references", []))
                    existing.notes = d.get("notes")
                    existing.source_version = d.get("source_version")
                    existing.url = d.get("url")
                    updated += 1
                else:
                    session.add(CapecAttackPatternModel(
                        capec_id=d.get("capec_id", ""),
                        dataset_version_id=version_id,
                        name=d.get("name", ""),
                        abstraction=d.get("abstraction"),
                        status=d.get("status"),
                        description=d.get("description"),
                        extended_description=d.get("extended_description"),
                        likelihood_of_attack=d.get("likelihood_of_attack"),
                        typical_severity=d.get("typical_severity"),
                        execution_flow_json=serialize_json(d.get("execution_flow", [])),
                        prerequisites_json=serialize_json(d.get("prerequisites", [])),
                        skills_required_json=serialize_json(d.get("skills_required", [])),
                        resources_required_json=serialize_json(d.get("resources_required", [])),
                        indicators_json=serialize_json(d.get("indicators", [])),
                        consequences_json=serialize_json(d.get("consequences", [])),
                        mitigations_json=serialize_json(d.get("mitigations", [])),
                        detection_json=serialize_json(d.get("detection", [])),
                        example_instances_json=serialize_json(d.get("example_instances", [])),
                        related_attack_patterns_json=serialize_json(d.get("related_attack_patterns", [])),
                        related_weaknesses_json=serialize_json(d.get("related_weaknesses", [])),
                        taxonomy_mappings_json=serialize_json(d.get("taxonomy_mappings", [])),
                        attack_technique_ids_json=serialize_json(attack_ids),
                        references_json=serialize_json(d.get("references", [])),
                        notes=d.get("notes"),
                        source_version=d.get("source_version"),
                        url=d.get("url"),
                    ))
                    # Also store ATT&CK technique cross-references
                    for tech_id in attack_ids:
                        tax_name = "MITRE ATT&CK"
                        atk_existing = session.query(CapecAttackMappingModel).filter_by(
                            dataset_version_id=version_id,
                            capec_id=d.get("capec_id", ""),
                            attack_technique_id=tech_id,
                        ).first()
                        if not atk_existing:
                            session.add(CapecAttackMappingModel(
                                dataset_version_id=version_id,
                                capec_id=d.get("capec_id", ""),
                                attack_technique_id=tech_id,
                                taxonomy_name=tax_name,
                            ))
                    inserted += 1
            session.commit()
        return {"inserted": inserted, "updated": updated, "duplicates": 0}

    def save_capec_relationships(self, version_id: str, relationships: list) -> int:
        count = 0
        with self._get_session() as session:
            for rel in relationships:
                d = rel.to_dict() if hasattr(rel, "to_dict") else rel
                existing = session.query(CapecRelationshipModel).filter_by(
                    dataset_version_id=version_id,
                    source_capec_id=d.get("source_capec_id", ""),
                    target_capec_id=d.get("target_capec_id", ""),
                    nature=d.get("nature", ""),
                ).first()
                if not existing:
                    session.add(CapecRelationshipModel(
                        dataset_version_id=version_id,
                        source_capec_id=d.get("source_capec_id", ""),
                        target_capec_id=d.get("target_capec_id", ""),
                        nature=d.get("nature", ""),
                        view_id=d.get("view_id"),
                    ))
                    count += 1
            session.commit()
        return count

    def save_capec_cwe_mappings(self, version_id: str, mappings: list) -> int:
        count = 0
        with self._get_session() as session:
            for m in mappings:
                d = m.to_dict() if hasattr(m, "to_dict") else m
                existing = session.query(CapecCweMappingModel).filter_by(
                    dataset_version_id=version_id,
                    capec_id=d.get("capec_id", ""),
                    cwe_id=d.get("cwe_id", ""),
                ).first()
                if not existing:
                    session.add(CapecCweMappingModel(
                        dataset_version_id=version_id,
                        capec_id=d.get("capec_id", ""),
                        cwe_id=d.get("cwe_id", ""),
                        nature=d.get("nature"),
                    ))
                    count += 1
            session.commit()
        return count

    def get_capec_attack_pattern(self, capec_id: str, version_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecAttackPatternModel).filter(CapecAttackPatternModel.capec_id == capec_id)
            if resolved_vid:
                q = q.filter(CapecAttackPatternModel.dataset_version_id == resolved_vid)
            model = q.first()
            return self._capec_model_to_dict(model) if model else None

    def list_capec_attack_patterns(
        self,
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecAttackPatternModel)
            if resolved_vid:
                q = q.filter(CapecAttackPatternModel.dataset_version_id == resolved_vid)
            if abstraction:
                q = q.filter(CapecAttackPatternModel.abstraction.ilike(f"%{abstraction}%"))
            if status:
                q = q.filter(CapecAttackPatternModel.status.ilike(f"%{status}%"))
            if severity:
                q = q.filter(CapecAttackPatternModel.typical_severity.ilike(f"%{severity}%"))
            q = q.order_by(CapecAttackPatternModel.capec_id).offset(offset).limit(limit)
            return [self._capec_model_to_dict(m) for m in q.all()]

    def search_capec_attack_patterns(
        self,
        query: str = "",
        capec_id: Optional[str] = None,
        abstraction: Optional[str] = None,
        severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        attack_technique_id: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecAttackPatternModel)
            if resolved_vid:
                q = q.filter(CapecAttackPatternModel.dataset_version_id == resolved_vid)
            if capec_id:
                q = q.filter(CapecAttackPatternModel.capec_id.ilike(f"%{capec_id}%"))
            if abstraction:
                q = q.filter(CapecAttackPatternModel.abstraction.ilike(f"%{abstraction}%"))
            if severity:
                q = q.filter(CapecAttackPatternModel.typical_severity.ilike(f"%{severity}%"))
            if query:
                q = q.filter(
                    CapecAttackPatternModel.name.ilike(f"%{query}%")
                    | CapecAttackPatternModel.description.ilike(f"%{query}%")
                    | CapecAttackPatternModel.capec_id.ilike(f"%{query}%")
                )
            if cwe_id:
                q = q.filter(CapecAttackPatternModel.related_weaknesses_json.ilike(f"%{cwe_id}%"))
            if attack_technique_id:
                q = q.filter(CapecAttackPatternModel.attack_technique_ids_json.ilike(f"%{attack_technique_id}%"))
            q = q.limit(limit)
            return [self._capec_model_to_dict(m) for m in q.all()]

    def list_capec_by_cwe(self, cwe_id: str, version_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecCweMappingModel).filter(CapecCweMappingModel.cwe_id == cwe_id)
            if resolved_vid:
                q = q.filter(CapecCweMappingModel.dataset_version_id == resolved_vid)
            capec_ids = [m.capec_id for m in q.all()]
            results = []
            for cid in capec_ids:
                rec = self.get_capec_attack_pattern(cid, version_id=version_id)
                if rec:
                    results.append(rec)
            return results

    def list_capec_by_attack_technique(self, technique_id: str, version_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecAttackMappingModel).filter(CapecAttackMappingModel.attack_technique_id == technique_id)
            if resolved_vid:
                q = q.filter(CapecAttackMappingModel.dataset_version_id == resolved_vid)
            capec_ids = [m.capec_id for m in q.all()]
            results = []
            for cid in capec_ids:
                rec = self.get_capec_attack_pattern(cid, version_id=version_id)
                if rec:
                    results.append(rec)
            return results

    def list_capec_relationships(
        self,
        capec_id: Optional[str] = None,
        nature: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            q = session.query(CapecRelationshipModel)
            if resolved_vid:
                q = q.filter(CapecRelationshipModel.dataset_version_id == resolved_vid)
            if capec_id:
                q = q.filter(
                    (CapecRelationshipModel.source_capec_id == capec_id)
                    | (CapecRelationshipModel.target_capec_id == capec_id)
                )
            if nature:
                q = q.filter(CapecRelationshipModel.nature == nature)
            q = q.limit(limit)
            return [
                {
                    "source_capec_id": m.source_capec_id,
                    "target_capec_id": m.target_capec_id,
                    "nature": m.nature,
                    "view_id": m.view_id,
                }
                for m in q.all()
            ]

    def get_capec_statistics_for_version(self, version_id: Optional[str] = None) -> Dict[str, Any]:
        with self._get_session() as session:
            resolved_vid = self._resolve_capec_version_id(version_id, session)
            if not resolved_vid:
                return {}
            total = session.query(func.count(CapecAttackPatternModel.id)).filter(
                CapecAttackPatternModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            rel_total = session.query(func.count(CapecRelationshipModel.id)).filter(
                CapecRelationshipModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            cwe_map_total = session.query(func.count(CapecCweMappingModel.id)).filter(
                CapecCweMappingModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            atk_map_total = session.query(func.count(CapecAttackMappingModel.id)).filter(
                CapecAttackMappingModel.dataset_version_id == resolved_vid
            ).scalar() or 0
            return {
                "total_attack_patterns": total,
                "total_relationships": rel_total,
                "total_cwe_mappings": cwe_map_total,
                "total_attack_mappings": atk_map_total,
                "dataset_version_id": resolved_vid,
            }

    def _resolve_capec_version_id(self, version_id: Optional[str], session: Session = None) -> Optional[str]:
        if version_id:
            return version_id
        active = self.get_active_dataset_version("mitre_capec_xml")
        return active.version_id if active else None

    def _capec_model_to_dict(self, model: CapecAttackPatternModel) -> Dict[str, Any]:
        return {
            "capec_id": model.capec_id,
            "name": model.name,
            "abstraction": model.abstraction,
            "status": model.status,
            "description": model.description,
            "extended_description": model.extended_description,
            "likelihood_of_attack": model.likelihood_of_attack,
            "typical_severity": model.typical_severity,
            "execution_flow": deserialize_json(model.execution_flow_json or "[]"),
            "prerequisites": deserialize_json(model.prerequisites_json or "[]"),
            "skills_required": deserialize_json(model.skills_required_json or "[]"),
            "resources_required": deserialize_json(model.resources_required_json or "[]"),
            "indicators": deserialize_json(model.indicators_json or "[]"),
            "consequences": deserialize_json(model.consequences_json or "[]"),
            "mitigations": deserialize_json(model.mitigations_json or "[]"),
            "detection": deserialize_json(model.detection_json or "[]"),
            "example_instances": deserialize_json(model.example_instances_json or "[]"),
            "related_attack_patterns": deserialize_json(model.related_attack_patterns_json or "[]"),
            "related_weaknesses": deserialize_json(model.related_weaknesses_json or "[]"),
            "taxonomy_mappings": deserialize_json(model.taxonomy_mappings_json or "[]"),
            "attack_technique_ids": deserialize_json(model.attack_technique_ids_json or "[]"),
            "references": deserialize_json(model.references_json or "[]"),
            "notes": model.notes,
            "source_version": model.source_version,
            "url": model.url,
        }

    # =====================================================================
    # IL-6: CVE-to-CWE Enrichment Methods
    # =====================================================================

    def save_cve_cwe_mappings(self, cve_id: str, cwe_ids: List[str], source: str = "NVD") -> int:
        """Upserts CVE-to-CWE cross-references (derived from NVD weakness fields)."""
        count = 0
        with self._get_session() as session:
            for cwe_id in cwe_ids:
                if not cwe_id:
                    continue
                existing = session.query(CveCweMappingModel).filter_by(
                    cve_id=cve_id, cwe_id=cwe_id
                ).first()
                if not existing:
                    session.add(CveCweMappingModel(cve_id=cve_id, cwe_id=cwe_id, source=source))
                    count += 1
            session.commit()
        return count

    def get_cwe_for_cve(self, cve_id: str) -> List[str]:
        """Returns all CWE IDs associated with a given CVE."""
        with self._get_session() as session:
            rows = session.query(CveCweMappingModel).filter_by(cve_id=cve_id).all()
            return [r.cwe_id for r in rows]

    def get_cves_for_cwe(self, cwe_id: str, limit: int = 200) -> List[str]:
        """Returns all CVE IDs associated with a given CWE."""
        with self._get_session() as session:
            rows = session.query(CveCweMappingModel).filter_by(cwe_id=cwe_id).limit(limit).all()
            return [r.cve_id for r in rows]


    # =========================================================================
    # IL-7: IOC Enterprise Intelligence Repository Methods
    # =========================================================================

    def _import_ioc_models(self):
        from netfusion_intelligence.repository.tables import (
            IocIndicatorModel, IocAliasModel, IocRelationshipModel,
            IocReputationModel, IocSightingModel, IocSourceModel, IocProviderModel,
        )
        return (IocIndicatorModel, IocAliasModel, IocRelationshipModel,
                IocReputationModel, IocSightingModel, IocSourceModel, IocProviderModel)

    def _resolve_ioc_version_id(self, version_id=None):
        if version_id:
            return version_id
        active = self.get_active_dataset_version("netfusion_ioc_v1")
        if active:
            return active.version_id
        latest = self.list_dataset_versions("netfusion_ioc_v1")
        return latest[0].version_id if latest else None

    def save_ioc_indicators(self, version_id: str, entities: list) -> dict:
        """Upserts IocEntity objects into ioc_indicator table. Returns counts."""
        IocIndicatorModel, *_ = self._import_ioc_models()
        inserted = updated = duplicates = 0
        with self._get_session() as session:
            for ent in entities:
                d = ent.to_dict() if hasattr(ent, "to_dict") else ent
                existing = session.query(IocIndicatorModel).filter_by(
                    dataset_version_id=version_id, ioc_id=d.get("ioc_id", "")
                ).first()
                if existing:
                    existing.ioc_type = d.get("ioc_type", "")
                    existing.value = d.get("value", "")
                    existing.value_raw = d.get("value_raw", "")
                    existing.severity = d.get("severity", "unknown")
                    existing.confidence = float(d.get("confidence", 0.5))
                    existing.priority = int(d.get("priority", 3))
                    existing.status = d.get("status", "active")
                    existing.reputation_score = float(d.get("reputation_score", 0.0))
                    existing.false_positive_score = float(d.get("false_positive_score", 0.0))
                    existing.source_count = int(d.get("source_count", 1))
                    existing.first_seen = d.get("first_seen")
                    existing.last_seen = d.get("last_seen")
                    existing.last_updated = d.get("last_updated")
                    existing.expiration = d.get("expiration")
                    existing.malware_families_json = serialize_json(d.get("malware_families", []))
                    existing.campaigns_json = serialize_json(d.get("campaigns", []))
                    existing.threat_actors_json = serialize_json(d.get("threat_actors", []))
                    existing.attack_technique_ids_json = serialize_json(d.get("attack_technique_ids", []))
                    existing.capec_ids_json = serialize_json(d.get("capec_ids", []))
                    existing.cwe_ids_json = serialize_json(d.get("cwe_ids", []))
                    existing.cve_ids_json = serialize_json(d.get("cve_ids", []))
                    existing.tags_json = serialize_json(d.get("tags", []))
                    existing.aliases_json = serialize_json(d.get("aliases", []))
                    existing.description = d.get("description")
                    existing.tlp = d.get("tlp")
                    existing.provider = d.get("provider")
                    existing.provider_id = d.get("provider_id")
                    existing.source_url = d.get("source_url")
                    updated += 1
                    duplicates += 1
                else:
                    session.add(IocIndicatorModel(
                        ioc_id=d.get("ioc_id", ""),
                        dataset_version_id=version_id,
                        ioc_type=d.get("ioc_type", ""),
                        value=d.get("value", ""),
                        value_raw=d.get("value_raw", ""),
                        severity=d.get("severity", "unknown"),
                        confidence=float(d.get("confidence", 0.5)),
                        priority=int(d.get("priority", 3)),
                        status=d.get("status", "active"),
                        reputation_score=float(d.get("reputation_score", 0.0)),
                        false_positive_score=float(d.get("false_positive_score", 0.0)),
                        source_count=int(d.get("source_count", 1)),
                        first_seen=d.get("first_seen"),
                        last_seen=d.get("last_seen"),
                        last_updated=d.get("last_updated"),
                        expiration=d.get("expiration"),
                        malware_families_json=serialize_json(d.get("malware_families", [])),
                        campaigns_json=serialize_json(d.get("campaigns", [])),
                        threat_actors_json=serialize_json(d.get("threat_actors", [])),
                        attack_technique_ids_json=serialize_json(d.get("attack_technique_ids", [])),
                        capec_ids_json=serialize_json(d.get("capec_ids", [])),
                        cwe_ids_json=serialize_json(d.get("cwe_ids", [])),
                        cve_ids_json=serialize_json(d.get("cve_ids", [])),
                        tags_json=serialize_json(d.get("tags", [])),
                        aliases_json=serialize_json(d.get("aliases", [])),
                        description=d.get("description"),
                        tlp=d.get("tlp"),
                        provider=d.get("provider"),
                        provider_id=d.get("provider_id"),
                        source_url=d.get("source_url"),
                    ))
                    inserted += 1
            session.commit()
        return {"inserted": inserted, "updated": updated, "duplicates": duplicates}

    def get_ioc_indicator(self, ioc_id: str, version_id=None) -> dict:
        IocIndicatorModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocIndicatorModel).filter_by(ioc_id=ioc_id)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            m = q.first()
            return self._ioc_model_to_dict(m) if m else None

    def list_ioc_indicators(self, ioc_type=None, status=None, min_confidence=None,
                             min_reputation=None, provider=None, severity=None,
                             version_id=None, limit=100, offset=0) -> list:
        IocIndicatorModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocIndicatorModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            if ioc_type:
                q = q.filter(IocIndicatorModel.ioc_type == ioc_type.lower())
            if status:
                q = q.filter(IocIndicatorModel.status == status.lower())
            if severity:
                q = q.filter(IocIndicatorModel.severity == severity.lower())
            if min_confidence is not None:
                q = q.filter(IocIndicatorModel.confidence >= float(min_confidence))
            if min_reputation is not None:
                q = q.filter(IocIndicatorModel.reputation_score >= float(min_reputation))
            if provider:
                q = q.filter(IocIndicatorModel.provider.ilike(f"%{provider}%"))
            records = q.order_by(IocIndicatorModel.reputation_score.desc()).offset(offset).limit(limit).all()
            return [self._ioc_model_to_dict(r) for r in records]

    def search_ioc_indicators(self, query="", ioc_type=None, value=None, hash_value=None,
                               ip=None, domain=None, threat_actor=None, campaign=None,
                               malware=None, attack_technique=None, capec_id=None,
                               cwe_id=None, cve_id=None, provider=None,
                               min_confidence=None, min_reputation=None,
                               first_seen_start=None, first_seen_end=None,
                               last_seen_start=None, last_seen_end=None,
                               version_id=None, limit=100) -> list:
        IocIndicatorModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocIndicatorModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            if ioc_type:
                q = q.filter(IocIndicatorModel.ioc_type == ioc_type.lower())
            if value:
                q = q.filter(IocIndicatorModel.value.ilike(f"%{value}%"))
            if hash_value:
                q = q.filter(IocIndicatorModel.value.ilike(f"%{hash_value.upper()}%"))
            if ip:
                q = q.filter(IocIndicatorModel.value.ilike(f"%{ip}%"),
                             IocIndicatorModel.ioc_type.in_(["ipv4", "ipv6"]))
            if domain:
                q = q.filter(IocIndicatorModel.value.ilike(f"%{domain.lower()}%"),
                             IocIndicatorModel.ioc_type.in_(["domain", "hostname"]))
            if threat_actor:
                q = q.filter(IocIndicatorModel.threat_actors_json.ilike(f"%{threat_actor}%"))
            if campaign:
                q = q.filter(IocIndicatorModel.campaigns_json.ilike(f"%{campaign}%"))
            if malware:
                q = q.filter(IocIndicatorModel.malware_families_json.ilike(f"%{malware}%"))
            if attack_technique:
                q = q.filter(IocIndicatorModel.attack_technique_ids_json.ilike(f"%{attack_technique}%"))
            if capec_id:
                q = q.filter(IocIndicatorModel.capec_ids_json.ilike(f"%{capec_id}%"))
            if cwe_id:
                q = q.filter(IocIndicatorModel.cwe_ids_json.ilike(f"%{cwe_id}%"))
            if cve_id:
                q = q.filter(IocIndicatorModel.cve_ids_json.ilike(f"%{cve_id}%"))
            if provider:
                q = q.filter(IocIndicatorModel.provider.ilike(f"%{provider}%"))
            if min_confidence is not None:
                q = q.filter(IocIndicatorModel.confidence >= float(min_confidence))
            if min_reputation is not None:
                q = q.filter(IocIndicatorModel.reputation_score >= float(min_reputation))
            if first_seen_start:
                q = q.filter(IocIndicatorModel.first_seen >= first_seen_start)
            if first_seen_end:
                q = q.filter(IocIndicatorModel.first_seen <= first_seen_end)
            if last_seen_start:
                q = q.filter(IocIndicatorModel.last_seen >= last_seen_start)
            if last_seen_end:
                q = q.filter(IocIndicatorModel.last_seen <= last_seen_end)
            if query:
                kw = f"%{query}%"
                q = q.filter(
                    IocIndicatorModel.value.ilike(kw) |
                    IocIndicatorModel.description.ilike(kw) |
                    IocIndicatorModel.malware_families_json.ilike(kw) |
                    IocIndicatorModel.campaigns_json.ilike(kw) |
                    IocIndicatorModel.threat_actors_json.ilike(kw) |
                    IocIndicatorModel.tags_json.ilike(kw)
                )
            return [self._ioc_model_to_dict(r) for r in q.order_by(
                IocIndicatorModel.reputation_score.desc()).limit(limit).all()]

    def save_ioc_relationships(self, version_id: str, relationships: list) -> int:
        _, _, IocRelationshipModel, *_ = self._import_ioc_models()
        count = 0
        with self._get_session() as session:
            for rel in relationships:
                d = rel.to_dict() if hasattr(rel, "to_dict") else rel
                existing = session.query(IocRelationshipModel).filter_by(
                    dataset_version_id=version_id,
                    source_ioc_id=d.get("source_ioc_id", ""),
                    target_id=d.get("target_id", ""),
                    relationship_type=d.get("relationship_type", ""),
                ).first()
                if not existing:
                    session.add(IocRelationshipModel(
                        relationship_id=d.get("relationship_id", ""),
                        dataset_version_id=version_id,
                        source_ioc_id=d.get("source_ioc_id", ""),
                        target_id=d.get("target_id", ""),
                        target_type=d.get("target_type", ""),
                        relationship_type=d.get("relationship_type", ""),
                        confidence=float(d.get("confidence", 1.0)),
                        first_seen=d.get("first_seen"),
                        last_seen=d.get("last_seen"),
                        description=d.get("description"),
                        provider=d.get("provider"),
                    ))
                    count += 1
            session.commit()
        return count

    def get_ioc_relationships(self, ioc_id: str, version_id=None, direction="both", limit=200) -> list:
        _, _, IocRelationshipModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocRelationshipModel)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            if direction == "source":
                q = q.filter_by(source_ioc_id=ioc_id)
            elif direction == "target":
                q = q.filter_by(target_id=ioc_id)
            else:
                q = q.filter(
                    (IocRelationshipModel.source_ioc_id == ioc_id) |
                    (IocRelationshipModel.target_id == ioc_id)
                )
            return [
                {"relationship_id": r.relationship_id, "source_ioc_id": r.source_ioc_id,
                 "target_id": r.target_id, "target_type": r.target_type,
                 "relationship_type": r.relationship_type, "confidence": r.confidence,
                 "first_seen": r.first_seen, "last_seen": r.last_seen,
                 "description": r.description, "provider": r.provider}
                for r in q.limit(limit).all()
            ]

    def save_ioc_reputations(self, version_id: str, reputations: list) -> int:
        _, _, _, IocReputationModel, *_ = self._import_ioc_models()
        count = 0
        with self._get_session() as session:
            for rep in reputations:
                d = rep.to_dict() if hasattr(rep, "to_dict") else rep
                existing = session.query(IocReputationModel).filter_by(
                    dataset_version_id=version_id, ioc_id=d.get("ioc_id", "")
                ).first()
                if existing:
                    existing.reputation_score = float(d.get("reputation_score", 0.0))
                    existing.false_positive_score = float(d.get("false_positive_score", 0.0))
                    existing.confidence = float(d.get("confidence", 0.5))
                    existing.severity = d.get("severity", "unknown")
                    existing.source_count = int(d.get("source_count", 1))
                    existing.last_updated = d.get("last_updated")
                    existing.contributing_sources_json = serialize_json(d.get("contributing_sources", []))
                else:
                    session.add(IocReputationModel(
                        ioc_id=d.get("ioc_id", ""),
                        dataset_version_id=version_id,
                        reputation_score=float(d.get("reputation_score", 0.0)),
                        false_positive_score=float(d.get("false_positive_score", 0.0)),
                        confidence=float(d.get("confidence", 0.5)),
                        severity=d.get("severity", "unknown"),
                        priority=int(d.get("priority", 3)),
                        source_count=int(d.get("source_count", 1)),
                        first_seen=d.get("first_seen"),
                        last_seen=d.get("last_seen"),
                        last_updated=d.get("last_updated"),
                        expiration=d.get("expiration"),
                        contributing_sources_json=serialize_json(d.get("contributing_sources", [])),
                        reputation_notes=d.get("reputation_notes"),
                    ))
                    count += 1
            session.commit()
        return count

    def get_ioc_reputation(self, ioc_id: str, version_id=None) -> dict:
        _, _, _, IocReputationModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocReputationModel).filter_by(ioc_id=ioc_id)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            m = q.first()
            if not m:
                return None
            return {
                "ioc_id": m.ioc_id, "reputation_score": m.reputation_score,
                "false_positive_score": m.false_positive_score, "confidence": m.confidence,
                "severity": m.severity, "priority": m.priority, "source_count": m.source_count,
                "first_seen": m.first_seen, "last_seen": m.last_seen, "last_updated": m.last_updated,
                "expiration": m.expiration,
                "contributing_sources": deserialize_json(m.contributing_sources_json or "[]"),
                "reputation_notes": m.reputation_notes,
            }

    def save_ioc_sightings(self, version_id: str, sightings: list) -> int:
        _, _, _, _, IocSightingModel, *_ = self._import_ioc_models()
        count = 0
        with self._get_session() as session:
            for s in sightings:
                d = s.to_dict() if hasattr(s, "to_dict") else s
                existing = session.query(IocSightingModel).filter_by(
                    sighting_id=d.get("sighting_id", "")
                ).first()
                if not existing:
                    session.add(IocSightingModel(
                        sighting_id=d.get("sighting_id", ""),
                        ioc_id=d.get("ioc_id", ""),
                        dataset_version_id=version_id,
                        observed_at=d.get("observed_at", ""),
                        observation_source=d.get("observation_source", ""),
                        organization=d.get("organization"),
                        location=d.get("location"),
                        environment=d.get("environment"),
                        count=int(d.get("count", 1)),
                        description=d.get("description"),
                        provider=d.get("provider"),
                        confidence=float(d.get("confidence", 1.0)),
                    ))
                    count += 1
            session.commit()
        return count

    def get_ioc_sightings(self, ioc_id: str, version_id=None, limit=100) -> list:
        _, _, _, _, IocSightingModel, *_ = self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        with self._get_session() as session:
            q = session.query(IocSightingModel).filter_by(ioc_id=ioc_id)
            if vid:
                q = q.filter_by(dataset_version_id=vid)
            return [
                {"sighting_id": r.sighting_id, "ioc_id": r.ioc_id,
                 "observed_at": r.observed_at, "observation_source": r.observation_source,
                 "organization": r.organization, "location": r.location,
                 "environment": r.environment, "count": r.count,
                 "description": r.description, "provider": r.provider,
                 "confidence": r.confidence}
                for r in q.order_by(IocSightingModel.observed_at.desc()).limit(limit).all()
            ]

    def get_ioc_statistics_for_version(self, version_id=None) -> dict:
        IocIndicatorModel, _, IocRelationshipModel, IocReputationModel, IocSightingModel, *_ = \
            self._import_ioc_models()
        vid = self._resolve_ioc_version_id(version_id)
        if not vid:
            return {"version_id": None, "total_indicators": 0}
        with self._get_session() as session:
            total = session.query(func.count(IocIndicatorModel.id)).filter_by(
                dataset_version_id=vid).scalar() or 0
            type_rows = session.query(
                IocIndicatorModel.ioc_type, func.count(IocIndicatorModel.id)
            ).filter_by(dataset_version_id=vid).group_by(IocIndicatorModel.ioc_type).all()
            by_type = {r[0]: r[1] for r in type_rows}

            sev_rows = session.query(
                IocIndicatorModel.severity, func.count(IocIndicatorModel.id)
            ).filter_by(dataset_version_id=vid).group_by(IocIndicatorModel.severity).all()
            by_severity = {r[0]: r[1] for r in sev_rows}

            avg_conf = session.query(func.avg(IocIndicatorModel.confidence)).filter_by(
                dataset_version_id=vid).scalar() or 0.0
            avg_rep = session.query(func.avg(IocIndicatorModel.reputation_score)).filter_by(
                dataset_version_id=vid).scalar() or 0.0

            total_rels = session.query(func.count(IocRelationshipModel.id)).filter_by(
                dataset_version_id=vid).scalar() or 0
            total_sightings = session.query(func.count(IocSightingModel.id)).filter_by(
                dataset_version_id=vid).scalar() or 0

            high_conf = session.query(func.count(IocIndicatorModel.id)).filter(
                IocIndicatorModel.dataset_version_id == vid,
                IocIndicatorModel.confidence >= 0.8,
            ).scalar() or 0
            high_rep = session.query(func.count(IocIndicatorModel.id)).filter(
                IocIndicatorModel.dataset_version_id == vid,
                IocIndicatorModel.reputation_score >= 7.0,
            ).scalar() or 0

            top_rep = session.query(IocIndicatorModel).filter_by(
                dataset_version_id=vid).order_by(
                IocIndicatorModel.reputation_score.desc()).limit(10).all()

            provider_rows = session.query(
                IocIndicatorModel.provider, func.count(IocIndicatorModel.id)
            ).filter_by(dataset_version_id=vid).group_by(
                IocIndicatorModel.provider).order_by(func.count(IocIndicatorModel.id).desc()).limit(10).all()

            return {
                "version_id": vid,
                "total_indicators": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "average_confidence": round(float(avg_conf), 4),
                "average_reputation_score": round(float(avg_rep), 3),
                "high_confidence_count": high_conf,
                "high_reputation_count": high_rep,
                "total_relationships": total_rels,
                "total_sightings": total_sightings,
                "top_by_reputation": [
                    {"ioc_id": r.ioc_id, "ioc_type": r.ioc_type,
                     "value": r.value[:100], "reputation_score": r.reputation_score}
                    for r in top_rep
                ],
                "top_providers": [{"provider": r[0], "count": r[1]} for r in provider_rows],
            }

    def _ioc_model_to_dict(self, m) -> dict:
        return {
            "ioc_id": m.ioc_id,
            "dataset_version_id": m.dataset_version_id,
            "ioc_type": m.ioc_type,
            "value": m.value,
            "value_raw": m.value_raw,
            "severity": m.severity,
            "confidence": m.confidence,
            "priority": m.priority,
            "status": m.status,
            "reputation_score": m.reputation_score,
            "false_positive_score": m.false_positive_score,
            "source_count": m.source_count,
            "first_seen": m.first_seen,
            "last_seen": m.last_seen,
            "last_updated": m.last_updated,
            "expiration": m.expiration,
            "malware_families": deserialize_json(m.malware_families_json or "[]"),
            "campaigns": deserialize_json(m.campaigns_json or "[]"),
            "threat_actors": deserialize_json(m.threat_actors_json or "[]"),
            "attack_technique_ids": deserialize_json(m.attack_technique_ids_json or "[]"),
            "capec_ids": deserialize_json(m.capec_ids_json or "[]"),
            "cwe_ids": deserialize_json(m.cwe_ids_json or "[]"),
            "cve_ids": deserialize_json(m.cve_ids_json or "[]"),
            "tags": deserialize_json(m.tags_json or "[]"),
            "aliases": deserialize_json(m.aliases_json or "[]"),
            "description": m.description,
            "tlp": m.tlp,
            "provider": m.provider,
            "provider_id": m.provider_id,
            "source_url": m.source_url,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "updated_at": m.updated_at.isoformat() if m.updated_at else None,
        }
