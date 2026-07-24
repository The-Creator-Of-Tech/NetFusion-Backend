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


class MitreAttackObjectModel(Base):
    __tablename__ = "mitre_attack_object"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stix_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)
    attack_id = Column(String(50), nullable=True, index=True)
    name = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=True)
    is_subtechnique = Column(Boolean, default=False, nullable=False)
    parent_technique_id = Column(String(50), nullable=True, index=True)
    tactics_json = Column(Text, nullable=True, default="[]")
    platforms_json = Column(Text, nullable=True, default="[]")
    aliases_json = Column(Text, nullable=True, default="[]")
    kill_chain_phases_json = Column(Text, nullable=True, default="[]")
    permissions_required_json = Column(Text, nullable=True, default="[]")
    system_requirements_json = Column(Text, nullable=True, default="[]")
    detection = Column(Text, nullable=True)
    contributors_json = Column(Text, nullable=True, default="[]")
    external_references_json = Column(Text, nullable=True, default="[]")
    url = Column(String(500), nullable=True)
    version = Column(String(50), nullable=True)
    created = Column(String(50), nullable=True)
    modified = Column(String(50), nullable=True)
    revoked = Column(Boolean, default=False, nullable=False)
    deprecated = Column(Boolean, default=False, nullable=False)
    raw_stix_json = Column(Text, nullable=True, default="{}")

    __table_args__ = (
        Index("idx_mitre_obj_ver_stix", "dataset_version_id", "stix_id", unique=True),
        Index("idx_mitre_obj_ver_type", "dataset_version_id", "type"),
        Index("idx_mitre_obj_ver_attack_id", "dataset_version_id", "attack_id"),
    )


class MitreAttackRelationshipModel(Base):
    __tablename__ = "mitre_attack_relationship"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stix_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    source_ref = Column(String(100), nullable=False, index=True)
    source_attack_id = Column(String(50), nullable=True, index=True)
    source_type = Column(String(50), nullable=True, index=True)
    target_ref = Column(String(100), nullable=False, index=True)
    target_attack_id = Column(String(50), nullable=True, index=True)
    target_type = Column(String(50), nullable=True, index=True)
    relationship_type = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    confidence = Column(Integer, nullable=True)
    created = Column(String(50), nullable=True)
    modified = Column(String(50), nullable=True)
    external_references_json = Column(Text, nullable=True, default="[]")
    revoked = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("idx_mitre_rel_ver_stix", "dataset_version_id", "stix_id", unique=True),
        Index("idx_mitre_rel_ver_source", "dataset_version_id", "source_ref"),
        Index("idx_mitre_rel_ver_target", "dataset_version_id", "target_ref"),
        Index("idx_mitre_rel_ver_reltype", "dataset_version_id", "relationship_type"),
    )


class NvdCveModel(Base):
    __tablename__ = "nvd_cve"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    source_identifier = Column(String(100), nullable=True)
    published = Column(String(50), nullable=True, index=True)
    last_modified = Column(String(50), nullable=True, index=True)
    vuln_status = Column(String(50), nullable=True)
    title = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String(50), nullable=True, index=True)
    cvss_score = Column(Float, default=0.0, nullable=False, index=True)
    descriptions_json = Column(Text, nullable=True, default="{}")
    cvss_v2_json = Column(Text, nullable=True, default="{}")
    cvss_v30_json = Column(Text, nullable=True, default="{}")
    cvss_v31_json = Column(Text, nullable=True, default="{}")
    cvss_v40_json = Column(Text, nullable=True, default="{}")
    weaknesses_json = Column(Text, nullable=True, default="[]")
    cwes_json = Column(Text, nullable=True, default="[]")
    configurations_json = Column(Text, nullable=True, default="[]")
    cpe_matches_json = Column(Text, nullable=True, default="[]")
    vendors_json = Column(Text, nullable=True, default="[]")
    products_json = Column(Text, nullable=True, default="[]")
    references_json = Column(Text, nullable=True, default="[]")
    vendor_comments_json = Column(Text, nullable=True, default="[]")
    raw_nvd_json = Column(Text, nullable=True, default="{}")

    __table_args__ = (
        Index("idx_nvd_cve_ver_cveid", "dataset_version_id", "cve_id", unique=True),
        Index("idx_nvd_cve_ver_severity", "dataset_version_id", "severity"),
        Index("idx_nvd_cve_ver_cvss", "dataset_version_id", "cvss_score"),
    )


class KevEntryModel(Base):
    __tablename__ = "kev_entry"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    vendor_project = Column(String(255), nullable=True, index=True)
    product = Column(String(255), nullable=True, index=True)
    vulnerability_name = Column(Text, nullable=True)
    date_added = Column(String(50), nullable=True, index=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(Text, nullable=True)
    due_date = Column(String(50), nullable=True, index=True)
    known_ransomware_campaign_use = Column(String(100), nullable=True, index=True)
    notes = Column(Text, nullable=True)
    catalog_version = Column(String(100), nullable=True)
    cwes_json = Column(Text, nullable=True, default="[]")
    reference_urls_json = Column(Text, nullable=True, default="[]")
    metadata_json = Column(Text, nullable=True, default="{}")
    status = Column(String(50), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_kev_entry_ver_cveid", "dataset_version_id", "cve_id", unique=True),
        Index("idx_kev_entry_vendor", "dataset_version_id", "vendor_project"),
        Index("idx_kev_entry_product", "dataset_version_id", "product"),
        Index("idx_kev_entry_due_date", "dataset_version_id", "due_date"),
        Index("idx_kev_entry_ransomware", "dataset_version_id", "known_ransomware_campaign_use"),
    )


class KevReferenceModel(Base):
    __tablename__ = "kev_reference"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    url = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_kev_ref_ver_cve", "dataset_version_id", "cve_id"),
    )


class KevHistoryModel(Base):
    __tablename__ = "kev_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    change_type = Column(String(50), nullable=False)
    details_json = Column(Text, nullable=True, default="{}")
    timestamp = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_kev_hist_ver_cve", "dataset_version_id", "cve_id"),
    )


class EpssScoreModel(Base):
    __tablename__ = "epss_score"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    epss_score = Column(Float, nullable=False, index=True)
    epss_percentile = Column(Float, nullable=False, index=True)
    publication_date = Column(String(50), nullable=True, index=True)
    model_version = Column(String(100), nullable=True, index=True)
    trend = Column(String(50), nullable=False, default="INSUFFICIENT_DATA", index=True)
    moving_avg_7d = Column(Float, nullable=True)
    moving_avg_30d = Column(Float, nullable=True)
    historical_high = Column(Float, nullable=True)
    historical_low = Column(Float, nullable=True)
    first_observed = Column(DateTime, nullable=True)
    last_updated = Column(DateTime, nullable=True)
    observation_count = Column(Integer, default=1, nullable=False)
    status = Column(String(50), nullable=False, default="ACTIVE")
    metadata_json = Column(Text, nullable=True, default="{}")
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_epss_score_ver_cveid", "dataset_version_id", "cve_id", unique=True),
        Index("idx_epss_score_ver_score", "dataset_version_id", "epss_score"),
        Index("idx_epss_score_ver_percentile", "dataset_version_id", "epss_percentile"),
        Index("idx_epss_score_ver_trend", "dataset_version_id", "trend"),
        Index("idx_epss_score_ver_pub_date", "dataset_version_id", "publication_date"),
    )


class EpssHistoryModel(Base):
    __tablename__ = "epss_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    epss_score = Column(Float, nullable=False)
    epss_percentile = Column(Float, nullable=False)
    score_date = Column(String(50), nullable=False, index=True)
    model_version = Column(String(100), nullable=True)
    daily_delta_score = Column(Float, default=0.0, nullable=False)
    daily_delta_percentile = Column(Float, default=0.0, nullable=False)
    timestamp = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_epss_hist_ver_cve_date", "dataset_version_id", "cve_id", "score_date", unique=True),
        Index("idx_epss_hist_cve_date", "cve_id", "score_date"),
    )


class EpssDatasetModel(Base):
    __tablename__ = "epss_dataset"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_version_id = Column(String(100), unique=True, nullable=False, index=True)
    model_version = Column(String(100), nullable=True)
    publication_date = Column(String(50), nullable=True, index=True)
    score_date = Column(String(50), nullable=True, index=True)
    total_cves = Column(Integer, default=0, nullable=False)
    status = Column(String(50), nullable=False, default="CREATED")
    activated_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, nullable=True, default="{}")
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)


# ============================================================
# IL-6: CWE Enterprise Intelligence Tables
# ============================================================

class CweWeaknessModel(Base):
    """Stores every available field from the MITRE CWE XML catalog per weakness."""
    __tablename__ = "cwe_weakness"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cwe_id = Column(String(20), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    abstraction = Column(String(50), nullable=True, index=True)
    structure = Column(String(50), nullable=True, index=True)
    status = Column(String(50), nullable=True, index=True)
    description = Column(Text, nullable=True)
    extended_description = Column(Text, nullable=True)
    likelihood_of_exploit = Column(String(50), nullable=True, index=True)
    background_details = Column(Text, nullable=True)
    alternate_terms_json = Column(Text, nullable=True, default="[]")
    modes_of_introduction_json = Column(Text, nullable=True, default="[]")
    applicable_platforms_json = Column(Text, nullable=True, default="[]")
    consequences_json = Column(Text, nullable=True, default="[]")
    detection_methods_json = Column(Text, nullable=True, default="[]")
    mitigations_json = Column(Text, nullable=True, default="[]")
    related_weaknesses_json = Column(Text, nullable=True, default="[]")
    taxonomy_mappings_json = Column(Text, nullable=True, default="[]")
    references_json = Column(Text, nullable=True, default="[]")
    related_attack_patterns_json = Column(Text, nullable=True, default="[]")
    affected_resources_json = Column(Text, nullable=True, default="[]")
    functional_areas_json = Column(Text, nullable=True, default="[]")
    mapping_notes = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    source_version = Column(String(50), nullable=True)
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_cwe_ver_cweid", "dataset_version_id", "cwe_id", unique=True),
        Index("idx_cwe_ver_abstraction", "dataset_version_id", "abstraction"),
        Index("idx_cwe_ver_status", "dataset_version_id", "status"),
    )


class CweRelationshipModel(Base):
    """Stores CWE-to-CWE graph relationships."""
    __tablename__ = "cwe_relationship"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    source_cwe_id = Column(String(20), nullable=False, index=True)
    target_cwe_id = Column(String(20), nullable=False, index=True)
    nature = Column(String(50), nullable=False, index=True)
    view_id = Column(String(20), nullable=True)
    ordinal = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_cwe_rel_ver_src", "dataset_version_id", "source_cwe_id"),
        Index("idx_cwe_rel_ver_tgt", "dataset_version_id", "target_cwe_id"),
        Index("idx_cwe_rel_ver_src_tgt_nature", "dataset_version_id", "source_cwe_id", "target_cwe_id", "nature", unique=True),
    )


# ============================================================
# IL-6: CAPEC Enterprise Intelligence Tables
# ============================================================

class CapecAttackPatternModel(Base):
    """Stores every available field from the MITRE CAPEC XML catalog per attack pattern."""
    __tablename__ = "capec_attack_pattern"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capec_id = Column(String(20), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    abstraction = Column(String(50), nullable=True, index=True)
    status = Column(String(50), nullable=True, index=True)
    description = Column(Text, nullable=True)
    extended_description = Column(Text, nullable=True)
    likelihood_of_attack = Column(String(50), nullable=True, index=True)
    typical_severity = Column(String(50), nullable=True, index=True)
    execution_flow_json = Column(Text, nullable=True, default="[]")
    prerequisites_json = Column(Text, nullable=True, default="[]")
    skills_required_json = Column(Text, nullable=True, default="[]")
    resources_required_json = Column(Text, nullable=True, default="[]")
    indicators_json = Column(Text, nullable=True, default="[]")
    consequences_json = Column(Text, nullable=True, default="[]")
    mitigations_json = Column(Text, nullable=True, default="[]")
    detection_json = Column(Text, nullable=True, default="[]")
    example_instances_json = Column(Text, nullable=True, default="[]")
    related_attack_patterns_json = Column(Text, nullable=True, default="[]")
    related_weaknesses_json = Column(Text, nullable=True, default="[]")  # CWE IDs
    taxonomy_mappings_json = Column(Text, nullable=True, default="[]")   # includes ATT&CK refs
    attack_technique_ids_json = Column(Text, nullable=True, default="[]")  # extracted ATT&CK IDs
    references_json = Column(Text, nullable=True, default="[]")
    notes = Column(Text, nullable=True)
    source_version = Column(String(50), nullable=True)
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_capec_ver_capecid", "dataset_version_id", "capec_id", unique=True),
        Index("idx_capec_ver_abstraction", "dataset_version_id", "abstraction"),
        Index("idx_capec_ver_severity", "dataset_version_id", "typical_severity"),
        Index("idx_capec_ver_likelihood", "dataset_version_id", "likelihood_of_attack"),
    )


class CapecRelationshipModel(Base):
    """Stores CAPEC-to-CAPEC graph relationships."""
    __tablename__ = "capec_relationship"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    source_capec_id = Column(String(20), nullable=False, index=True)
    target_capec_id = Column(String(20), nullable=False, index=True)
    nature = Column(String(50), nullable=False, index=True)
    view_id = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_capec_rel_ver_src", "dataset_version_id", "source_capec_id"),
        Index("idx_capec_rel_ver_tgt", "dataset_version_id", "target_capec_id"),
        Index("idx_capec_rel_ver_src_tgt", "dataset_version_id", "source_capec_id", "target_capec_id", "nature", unique=True),
    )


class CapecCweMappingModel(Base):
    """Cross-reference table between CAPEC attack patterns and CWE weaknesses."""
    __tablename__ = "capec_cwe"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    capec_id = Column(String(20), nullable=False, index=True)
    cwe_id = Column(String(20), nullable=False, index=True)
    nature = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_capec_cwe_ver_capec", "dataset_version_id", "capec_id"),
        Index("idx_capec_cwe_ver_cwe", "dataset_version_id", "cwe_id"),
        Index("idx_capec_cwe_ver_pair", "dataset_version_id", "capec_id", "cwe_id", unique=True),
    )


class CapecAttackMappingModel(Base):
    """Cross-reference table between CAPEC attack patterns and MITRE ATT&CK techniques."""
    __tablename__ = "capec_attack"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    capec_id = Column(String(20), nullable=False, index=True)
    attack_technique_id = Column(String(50), nullable=False, index=True)
    taxonomy_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_capec_atk_ver_capec", "dataset_version_id", "capec_id"),
        Index("idx_capec_atk_ver_tech", "dataset_version_id", "attack_technique_id"),
        Index("idx_capec_atk_ver_pair", "dataset_version_id", "capec_id", "attack_technique_id", unique=True),
    )


class CveCweMappingModel(Base):
    """Cross-reference table linking CVEs (from NVD) to CWE weaknesses via canonical IDs."""
    __tablename__ = "cve_cwe"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    cwe_id = Column(String(20), nullable=False, index=True)
    source = Column(String(50), nullable=True, default="NVD")
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_cve_cwe_pair", "cve_id", "cwe_id", unique=True),
        Index("idx_cve_cwe_cve", "cve_id"),
        Index("idx_cve_cwe_cwe", "cwe_id"),
    )





# ============================================================
# IL-7: IOC Enterprise Intelligence Tables
# ============================================================

class IocIndicatorModel(Base):
    """
    Primary IOC indicator table.
    One row per canonical (type, normalized_value) pair per dataset version.
    """
    __tablename__ = "ioc_indicator"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)

    ioc_type = Column(String(60), nullable=False, index=True)
    value = Column(Text, nullable=False)
    value_raw = Column(Text, nullable=True)

    severity = Column(String(30), nullable=False, default="unknown", index=True)
    confidence = Column(Float, nullable=False, default=0.5, index=True)
    priority = Column(Integer, nullable=False, default=3, index=True)
    status = Column(String(30), nullable=False, default="active", index=True)
    reputation_score = Column(Float, nullable=False, default=0.0, index=True)
    false_positive_score = Column(Float, nullable=False, default=0.0)
    source_count = Column(Integer, nullable=False, default=1)

    first_seen = Column(String(50), nullable=True, index=True)
    last_seen = Column(String(50), nullable=True, index=True)
    last_updated = Column(String(50), nullable=True)
    expiration = Column(String(50), nullable=True)

    malware_families_json = Column(Text, nullable=True, default="[]")
    campaigns_json = Column(Text, nullable=True, default="[]")
    threat_actors_json = Column(Text, nullable=True, default="[]")
    attack_technique_ids_json = Column(Text, nullable=True, default="[]")
    capec_ids_json = Column(Text, nullable=True, default="[]")
    cwe_ids_json = Column(Text, nullable=True, default="[]")
    cve_ids_json = Column(Text, nullable=True, default="[]")
    tags_json = Column(Text, nullable=True, default="[]")
    aliases_json = Column(Text, nullable=True, default="[]")

    description = Column(Text, nullable=True)
    tlp = Column(String(30), nullable=True)
    provider = Column(String(200), nullable=True, index=True)
    provider_id = Column(String(200), nullable=True)
    source_url = Column(Text, nullable=True)

    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_ver_iocid", "dataset_version_id", "ioc_id", unique=True),
        Index("idx_ioc_ver_type", "dataset_version_id", "ioc_type"),
        Index("idx_ioc_ver_type_value", "dataset_version_id", "ioc_type", "value"),
        Index("idx_ioc_ver_confidence", "dataset_version_id", "confidence"),
        Index("idx_ioc_ver_severity", "dataset_version_id", "severity"),
        Index("idx_ioc_ver_reputation", "dataset_version_id", "reputation_score"),
        Index("idx_ioc_ver_provider", "dataset_version_id", "provider"),
    )


class IocAliasModel(Base):
    """Alternative values / known aliases for a canonical IOC."""
    __tablename__ = "ioc_alias"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    alias = Column(Text, nullable=False)
    alias_type = Column(String(60), nullable=True)  # e.g. "domain", "ipv4"
    provider = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_alias_ver_ioc", "dataset_version_id", "ioc_id"),
    )


class IocRelationshipModel(Base):
    """IOC-to-IOC and IOC-to-entity relationships."""
    __tablename__ = "ioc_relationship"

    id = Column(Integer, primary_key=True, autoincrement=True)
    relationship_id = Column(String(100), unique=True, nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    source_ioc_id = Column(String(100), nullable=False, index=True)
    target_id = Column(String(200), nullable=False, index=True)
    target_type = Column(String(60), nullable=False, index=True)
    relationship_type = Column(String(100), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    first_seen = Column(String(50), nullable=True)
    last_seen = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    provider = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_rel_ver_src", "dataset_version_id", "source_ioc_id"),
        Index("idx_ioc_rel_ver_tgt", "dataset_version_id", "target_id"),
        Index("idx_ioc_rel_ver_type", "dataset_version_id", "relationship_type"),
        Index("idx_ioc_rel_ver_src_tgt_type",
              "dataset_version_id", "source_ioc_id", "target_id", "relationship_type",
              unique=True),
    )


class IocReputationModel(Base):
    """Reputation record per IOC indicator."""
    __tablename__ = "ioc_reputation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    reputation_score = Column(Float, nullable=False, default=0.0, index=True)
    false_positive_score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=False, default=0.5)
    severity = Column(String(30), nullable=False, default="unknown")
    priority = Column(Integer, nullable=False, default=3)
    source_count = Column(Integer, nullable=False, default=1)
    first_seen = Column(String(50), nullable=True)
    last_seen = Column(String(50), nullable=True)
    last_updated = Column(String(50), nullable=True)
    expiration = Column(String(50), nullable=True)
    contributing_sources_json = Column(Text, nullable=True, default="[]")
    reputation_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_rep_ver_iocid", "dataset_version_id", "ioc_id", unique=True),
        Index("idx_ioc_rep_ver_score", "dataset_version_id", "reputation_score"),
    )


class IocSightingModel(Base):
    """Sighting observation records for IOC indicators."""
    __tablename__ = "ioc_sighting"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sighting_id = Column(String(100), unique=True, nullable=False, index=True)
    ioc_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    observed_at = Column(String(50), nullable=False, index=True)
    observation_source = Column(String(200), nullable=False)
    organization = Column(String(200), nullable=True)
    location = Column(String(100), nullable=True)
    environment = Column(String(100), nullable=True)
    count = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=True)
    provider = Column(String(200), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_sight_ver_ioc", "dataset_version_id", "ioc_id"),
        Index("idx_ioc_sight_ver_date", "dataset_version_id", "observed_at"),
    )


class IocSourceModel(Base):
    """Per-provider source contribution record for each IOC."""
    __tablename__ = "ioc_source"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_id = Column(String(100), unique=True, nullable=False, index=True)
    ioc_id = Column(String(100), nullable=False, index=True)
    dataset_version_id = Column(String(100), nullable=False, index=True)
    provider = Column(String(200), nullable=False, index=True)
    provider_type = Column(String(60), nullable=False)
    provider_indicator_id = Column(String(200), nullable=True)
    confidence = Column(Float, nullable=False, default=0.5)
    tlp = Column(String(30), nullable=True)
    contributed_at = Column(String(50), nullable=True)
    source_url = Column(Text, nullable=True)
    raw_value = Column(Text, nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)

    __table_args__ = (
        Index("idx_ioc_src_ver_ioc", "dataset_version_id", "ioc_id"),
        Index("idx_ioc_src_ver_provider", "dataset_version_id", "provider"),
    )


class IocProviderModel(Base):
    """Registry of configured IOC intelligence providers."""
    __tablename__ = "ioc_provider"

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    provider_type = Column(String(60), nullable=False, index=True)
    description = Column(Text, nullable=True)
    url = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    default_confidence = Column(Float, nullable=False, default=0.5)
    default_tlp = Column(String(30), nullable=True)
    tags_json = Column(Text, nullable=True, default="[]")
    version = Column(String(100), nullable=True)
    last_synced = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=default_utc_now, nullable=False)
    updated_at = Column(DateTime, default=default_utc_now, onupdate=default_utc_now, nullable=False)
