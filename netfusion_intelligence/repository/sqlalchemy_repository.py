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
