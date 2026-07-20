"""
SQLAlchemy ORM tables for intelligence subsystem infrastructure.
"""

from datetime import datetime, timezone
import json
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Index, Integer, String, Text, UniqueConstraint
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def default_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IntelligenceFeedModel(Base):
    __tablename__ = "intelligence_feed"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    config_json = Column(Text, nullable=False, default="{}")
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)


class DatasetVersionModel(Base):
    __tablename__ = "dataset_version"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(String(100), nullable=False, index=True)
    version_id = Column(String(100), unique=True, nullable=False, index=True)
    checksum = Column(String(128), nullable=True)
    source_version = Column(String(100), nullable=True)
    status = Column(String(50), nullable=False, default="CREATED")
    validation_status = Column(String(50), nullable=False, default="PENDING")
    record_count = Column(Integer, default=0, nullable=False)
    duration = Column(Float, default=0.0, nullable=False)
    imported_at = Column(DateTime, default=default_utc_now, nullable=False)
    activated_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_dataset_feed_status", "feed_id", "status"),
    )


class DatasetImportModel(Base):
    __tablename__ = "dataset_import"

    id = Column(Integer, primary_key=True, autoincrement=True)
    import_id = Column(String(100), unique=True, nullable=False, index=True)
    feed_id = Column(String(100), nullable=False, index=True)
    version_id = Column(String(100), nullable=True, index=True)
    status = Column(String(50), nullable=False, default="STARTED")
    started_at = Column(DateTime, default=default_utc_now, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    duration = Column(Float, default=0.0, nullable=False)

    # 13 Extended Import Statistics Metrics
    records_downloaded = Column(Integer, default=0, nullable=False)
    records_parsed = Column(Integer, default=0, nullable=False)
    records_processed = Column(Integer, default=0, nullable=False)
    records_inserted = Column(Integer, default=0, nullable=False)
    records_updated = Column(Integer, default=0, nullable=False)
    records_deleted = Column(Integer, default=0, nullable=False)
    duplicate_records = Column(Integer, default=0, nullable=False)
    validation_errors = Column(Integer, default=0, nullable=False)
    relationship_count = Column(Integer, default=0, nullable=False)
    download_size = Column(Integer, default=0, nullable=False)
    checksum = Column(String(128), nullable=True)
    source_version = Column(String(100), nullable=True)
    warnings_json = Column(Text, nullable=True, default="[]")

    # Historical Tracking Metadata
    trigger = Column(String(50), default="manual", nullable=False)
    user = Column(String(100), nullable=True, default="system")
    rollback_status = Column(String(50), default="NOT_APPLICABLE", nullable=False)
    validation_result_json = Column(Text, nullable=True, default="{}")
    validation_summary_json = Column(Text, nullable=True, default="{}")
    error_log = Column(Text, nullable=True)


class FeedHealthModel(Base):
    __tablename__ = "feed_health"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(String(100), unique=True, nullable=False, index=True)
    health_status = Column(String(50), nullable=False, default="UNKNOWN")
    availability = Column(Float, default=100.0, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    next_sync_at = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_failure_at = Column(DateTime, nullable=True)
    consecutive_failures = Column(Integer, default=0, nullable=False)
    total_sync_count = Column(Integer, default=0, nullable=False)
    successful_sync_count = Column(Integer, default=0, nullable=False)
    failed_sync_count = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, nullable=True)
    validation_state = Column(String(50), default="N/A", nullable=False)
    validation_health = Column(String(50), default="PASSED", nullable=False)
    active_dataset_version = Column(String(100), nullable=True)
    last_execution_duration_sec = Column(Float, default=0.0, nullable=False)
    average_execution_time = Column(Float, default=0.0, nullable=False)
    dependency_health = Column(String(50), default="HEALTHY", nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)


class FeedScheduleModel(Base):
    __tablename__ = "feed_schedule"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(String(100), unique=True, nullable=False, index=True)
    cron_expression = Column(String(100), nullable=True)
    interval_seconds = Column(Float, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="IDLE", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)


class ImportLogModel(Base):
    __tablename__ = "import_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    import_id = Column(String(100), nullable=False, index=True)
    feed_id = Column(String(100), nullable=False, index=True)
    level = Column(String(20), nullable=False, default="INFO")
    message = Column(Text, nullable=False)
    details_json = Column(Text, nullable=True, default="{}")
    timestamp = Column(DateTime, default=default_utc_now, nullable=False)


class EventAuditModel(Base):
    __tablename__ = "event_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(100), unique=True, nullable=False, index=True)
    event_id = Column(String(100), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    feed_id = Column(String(100), nullable=True, index=True)
    payload_json = Column(Text, nullable=True, default="{}")
    timestamp = Column(DateTime, default=default_utc_now, nullable=False)
