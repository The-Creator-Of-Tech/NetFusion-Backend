"""
13-Step Enterprise Feed Pipeline Lifecycle Execution Engine.
Orchestrates:
Initialize -> Secure Download -> TLS Verification -> Signature Verification -> Checksum Verification -> Trust Evaluation -> Parse -> Normalize -> Validate -> Store -> Relationship Build -> Activate Dataset -> Publish Events.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, Optional, Tuple
import uuid

from netfusion_intelligence.core.events import (
    CertificateValidated,
    ChecksumVerified,
    DomainEvent,
    EventBus,
    FeedCompleted,
    FeedFailed,
    FeedStarted,
    SignatureVerified,
    TrustFailed,
    TrustVerified,
    ValidationFailed,
    ValidationPassed,
)
from netfusion_intelligence.core.exceptions import (
    ChecksumVerificationError,
    FeedExecutionError,
    NormalizationError,
    ParsingError,
    TrustPolicyViolationError,
    ValidationError,
)
from netfusion_intelligence.core.health import HealthMonitor
from netfusion_intelligence.core.version import DatasetVersionManager
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetStatus, DatasetVersion, ValidationStatus
from netfusion_intelligence.models.import_result import ImportLogEntry, ImportResult, ImportStatus
from netfusion_intelligence.security.audit import TrustAuditRepository
from netfusion_intelligence.security.policy_engine import TrustDecision, TrustEvaluationResult, TrustPolicyEngine
from netfusion_intelligence.security.trust_model import TrustLevel, TrustProfile
from netfusion_intelligence.utils.checksum import compute_checksum
from netfusion_intelligence.utils.logging import get_structured_logger, log_sync_summary

logger = get_structured_logger(__name__)


class FeedLifecycleRunner:
    """
    Executes the standard 13-step lifecycle for an intelligence feed plugin.
    Includes comprehensive security, transport, signature, checksum, and trust policy evaluation.
    """

    def __init__(
        self,
        repository: IntelligenceRepositoryInterface,
        version_manager: DatasetVersionManager,
        health_monitor: HealthMonitor,
        event_bus: EventBus,
        policy_engine: Optional[TrustPolicyEngine] = None,
        audit_repository: Optional[TrustAuditRepository] = None,
    ):
        self.repository = repository
        self.version_manager = version_manager
        self.health_monitor = health_monitor
        self.event_bus = event_bus
        self.policy_engine = policy_engine or TrustPolicyEngine()
        self.audit_repository = audit_repository or TrustAuditRepository()

    def execute(self, feed: FeedInterface) -> ImportResult:
        """
        Executes the exact 13-step feed ingestion lifecycle.
        """
        import_id = str(uuid.uuid4())
        feed_id = feed.feed_id
        start_time_dt = datetime.now(timezone.utc)
        start_time_iso = start_time_dt.isoformat()
        start_ticks = time.time()

        logs: list[ImportLogEntry] = []

        def add_log(level: str, msg: str, details: Optional[Dict[str, Any]] = None):
            entry = ImportLogEntry(import_id=import_id, feed_id=feed_id, level=level, message=msg, details=details or {})
            logs.append(entry)

        result = ImportResult(
            import_id=import_id,
            feed_id=feed_id,
            status=ImportStatus.STARTED,
            started_at=start_time_iso,
        )

        dataset_version: Optional[DatasetVersion] = None

        # Resolve Trust Profile for feed
        trust_profile = getattr(feed, "trust_profile", None)
        if not trust_profile:
            meta = feed.metadata
            url = getattr(meta, "url", "https://localhost/feed") or "https://localhost/feed"
            publisher = getattr(meta, "publisher", "NetFusion Security Team") or "NetFusion Security Team"
            organization = getattr(meta, "organization", "NetFusion") or "NetFusion"
            expected_domain = getattr(meta, "expected_domain", "") or ""
            trust_profile = TrustProfile(
                publisher=publisher,
                organization=organization,
                official_url=url,
                expected_domain=expected_domain,
                trust_level=TrustLevel.HIGH,
            )

        try:
            # -------------------------------------------------------------
            # STEP 1: INITIALIZE
            # -------------------------------------------------------------
            add_log("INFO", f"Step 1/13: Initializing synchronization pipeline for feed '{feed_id}'")
            if not feed.config.enabled:
                raise FeedExecutionError(f"Feed '{feed_id}' is disabled in configuration")

            self.event_bus.publish(FeedStarted(feed_id=feed_id, import_id=import_id))
            self.repository.save_import_result(result)

            # -------------------------------------------------------------
            # STEP 2: SECURE DOWNLOAD
            # -------------------------------------------------------------
            result.status = ImportStatus.SECURE_DOWNLOADING
            add_log("INFO", f"Step 2/13: Securely fetching raw intelligence feed data for feed '{feed_id}'")
            raw_data = feed.fetch_raw_data()
            if raw_data is None:
                raise FeedExecutionError("Feed returned None for raw data download")

            if isinstance(raw_data, (bytes, str)):
                result.download_size = len(raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data)
            elif hasattr(raw_data, "__len__"):
                result.download_size = len(raw_data)
            else:
                result.download_size = 100

            checksum = compute_checksum(raw_data)
            result.checksum = checksum
            add_log("INFO", f"Downloaded raw data securely (SHA-256: {checksum[:12]}...)")

            # Create immutable DatasetVersion record
            dataset_version = self.version_manager.create_version(
                feed_id=feed_id,
                checksum=checksum,
                duration=0.0,
            )
            result.version_id = dataset_version.version_id
            self.repository.save_import_result(result)

            # -------------------------------------------------------------
            # STEP 3: TLS VERIFICATION
            # -------------------------------------------------------------
            result.status = ImportStatus.TLS_VERIFYING
            add_log("INFO", f"Step 3/13: Verifying TLS transport & certificate validity for feed '{feed_id}'")
            url = getattr(feed, "url", trust_profile.official_url)
            cert_info = getattr(feed, "cert_info", None)
            
            # Transport check
            try:
                t_report = self.policy_engine.transport_verifier.verify_transport(url, trust_profile, cert_info)
                self.event_bus.publish(CertificateValidated(feed_id=feed_id, hostname=t_report.get("hostname", ""), status="VALID"))
                add_log("INFO", f"TLS & Hostname verified for {url}")
            except Exception as te:
                self.event_bus.publish(CertificateValidated(feed_id=feed_id, hostname=url, status="FAILED"))
                raise te

            # -------------------------------------------------------------
            # STEP 4: SIGNATURE VERIFICATION
            # -------------------------------------------------------------
            result.status = ImportStatus.SIGNATURE_VERIFYING
            add_log("INFO", f"Step 4/13: Verifying payload signatures for feed '{feed_id}'")
            signature = getattr(feed, "signature", None)
            manifest_data = getattr(feed, "manifest_data", None)
            
            s_report = self.policy_engine.signature_verifier.verify_signature(
                raw_data=raw_data,
                signature=signature,
                trust_profile=trust_profile,
                manifest=manifest_data,
            )
            self.event_bus.publish(
                SignatureVerified(
                    feed_id=feed_id,
                    algorithm=s_report.get("algorithm", "GPG"),
                    verified=s_report.get("verified", True),
                )
            )

            # -------------------------------------------------------------
            # STEP 5: CHECKSUM VERIFICATION
            # -------------------------------------------------------------
            result.status = ImportStatus.CHECKSUM_VERIFYING
            add_log("INFO", f"Step 5/13: Verifying payload checksum & integrity for feed '{feed_id}'")
            expected_chk = getattr(feed, "expected_checksum", None)
            chk_required = getattr(feed.config, "checksum_required", True)
            
            if chk_required or expected_chk:
                chk_report = self.policy_engine.checksum_verifier.verify_checksum(
                    feed_id=feed_id,
                    raw_data=raw_data,
                    expected_checksum=expected_chk or checksum,
                    algorithm=trust_profile.verification_requirements.checksum_algorithm,
                    required=chk_required,
                )
                self.event_bus.publish(
                    ChecksumVerified(
                        feed_id=feed_id,
                        algorithm=chk_report.get("algorithm", "SHA256"),
                        checksum=chk_report.get("computed_checksum", checksum),
                    )
                )

            # -------------------------------------------------------------
            # STEP 6: TRUST EVALUATION
            # -------------------------------------------------------------
            result.status = ImportStatus.TRUST_EVALUATING
            add_log("INFO", f"Step 6/13: Evaluating TrustPolicyEngine policies for feed '{feed_id}'")
            redirect_chain = getattr(feed, "redirect_chain", None)
            
            trust_eval: TrustEvaluationResult = self.policy_engine.evaluate(
                feed_id=feed_id,
                trust_profile=trust_profile,
                raw_data=raw_data,
                url=url,
                cert_info=cert_info,
                signature=signature,
                manifest=manifest_data,
                expected_checksum=expected_chk or checksum,
                redirect_chain=redirect_chain,
            )

            # Persist Audit Entry
            self.audit_repository.record_evaluation(trust_eval)

            # Record Health Verification Status
            passed = trust_eval.decision in (TrustDecision.TRUSTED, TrustDecision.PARTIALLY_TRUSTED)
            self.health_monitor.record_trust_verification(
                feed_id=feed_id,
                trust_status=trust_eval.overall_trust,
                cert_status=trust_eval.certificate_status,
                sig_status=trust_eval.signature_status,
                passed=passed,
            )

            if passed:
                self.event_bus.publish(
                    TrustVerified(
                        feed_id=feed_id,
                        overall_trust=trust_eval.overall_trust,
                        trust_score=trust_eval.trust_score,
                        publisher=trust_profile.publisher,
                    )
                )
                add_log("INFO", f"Trust Policy Evaluation PASSED (Decision: {trust_eval.overall_trust}, Score: {trust_eval.trust_score})")
            else:
                self.event_bus.publish(
                    TrustFailed(
                        feed_id=feed_id,
                        overall_trust=trust_eval.overall_trust,
                        reason="; ".join(trust_eval.reasons),
                    )
                )
                raise TrustPolicyViolationError(f"Trust policy violation for feed '{feed_id}': {'; '.join(trust_eval.reasons)}")

            # -------------------------------------------------------------
            # STEP 7: PARSE
            # -------------------------------------------------------------
            result.status = ImportStatus.PARSING
            add_log("INFO", f"Step 7/13: Parsing raw feed data for feed '{feed_id}'")
            try:
                parsed_data = feed.parse(raw_data)
            except Exception as pe:
                raise ParsingError(f"Parsing raw feed data failed: {pe}")

            if isinstance(parsed_data, list):
                result.records_parsed = len(parsed_data)
            elif isinstance(parsed_data, dict):
                result.records_parsed = len(parsed_data.get("items", [parsed_data]))
            else:
                result.records_parsed = 1
            result.records_downloaded = result.records_parsed

            # -------------------------------------------------------------
            # STEP 8: NORMALIZE
            # -------------------------------------------------------------
            result.status = ImportStatus.NORMALIZING
            add_log("INFO", f"Step 8/13: Normalizing parsed data for feed '{feed_id}'")
            try:
                normalized_data = feed.normalize(parsed_data)
            except Exception as ne:
                raise NormalizationError(f"Normalizing parsed feed data failed: {ne}")

            # Calculate record count
            if isinstance(normalized_data, list):
                record_count = len(normalized_data)
            elif isinstance(normalized_data, dict):
                record_count = len(normalized_data.get("items", [normalized_data]))
            else:
                record_count = 1

            result.records_processed = record_count
            dataset_version.record_count = record_count

            # -------------------------------------------------------------
            # STEP 9: VALIDATE
            # -------------------------------------------------------------
            result.status = ImportStatus.VALIDATING
            add_log("INFO", f"Step 9/13: Validating normalized dataset for feed '{feed_id}'")
            validation_res: ValidationResult = feed.validate(normalized_data)
            
            result.validation_details = validation_res.to_dict()
            result.validation_passed = validation_res.is_valid
            result.validation_errors = len(validation_res.errors)
            result.warnings = [getattr(w, "message", str(w)) for w in validation_res.warnings]
            result.validation_summary = {
                "is_valid": validation_res.is_valid,
                "total_checked": validation_res.total_checked,
                "errors_count": len(validation_res.errors),
                "warnings_count": len(validation_res.warnings),
            }

            if not validation_res.is_valid:
                dataset_version.validation_status = ValidationStatus.FAILED
                dataset_version.status = DatasetStatus.FAILED
                dataset_version.error_message = "Dataset validation failed"
                self.repository.save_dataset_version(dataset_version)

                self.event_bus.publish(
                    ValidationFailed(
                        feed_id=feed_id,
                        version_id=dataset_version.version_id,
                        errors_count=len(validation_res.errors),
                        error_details=[e.to_dict() for e in validation_res.errors],
                    )
                )

                raise ValidationError(f"Dataset validation failed with {len(validation_res.errors)} errors")

            dataset_version.validation_status = ValidationStatus.PASSED
            self.event_bus.publish(
                ValidationPassed(
                    feed_id=feed_id,
                    version_id=dataset_version.version_id,
                    total_checked=validation_res.total_checked,
                )
            )

            # -------------------------------------------------------------
            # STEP 10: STORE
            # -------------------------------------------------------------
            result.status = ImportStatus.STORING
            add_log("INFO", f"Step 10/13: Storing normalized dataset for feed '{feed_id}'")
            store_res = feed.store(dataset_version, normalized_data)
            
            result.records_inserted = getattr(store_res, "records_inserted", 0) or record_count
            result.records_updated = getattr(store_res, "records_updated", 0) or 0
            result.records_deleted = getattr(store_res, "records_deleted", 0) or 0
            result.duplicate_records = getattr(store_res, "duplicate_records", 0) or 0
            dataset_version.status = DatasetStatus.STORED
            self.repository.save_dataset_version(dataset_version)

            # -------------------------------------------------------------
            # STEP 11: RELATIONSHIP BUILD
            # -------------------------------------------------------------
            result.status = ImportStatus.RELATIONSHIPS_BUILDING
            add_log("INFO", f"Step 11/13: Building entity relationships for dataset version '{dataset_version.version_id}'")
            rel_count = feed.build_relationships(dataset_version)
            result.relationship_count = rel_count
            add_log("INFO", f"Created {rel_count} entity relationships")

            # -------------------------------------------------------------
            # STEP 12: ACTIVATE DATASET
            # -------------------------------------------------------------
            result.status = ImportStatus.ACTIVATING
            if feed.config.auto_activate:
                add_log("INFO", f"Step 12/13: Activating dataset version '{dataset_version.version_id}'")
                dataset_version = self.version_manager.activate_version(feed_id, dataset_version.version_id)
                feed.on_activate(dataset_version)
            else:
                add_log("INFO", "Step 12/13: Auto-activation disabled; dataset stored as STORED/VALIDATED")

            # -------------------------------------------------------------
            # STEP 13: PUBLISH EVENTS & HEALTH UPDATE
            # -------------------------------------------------------------
            finish_time_dt = datetime.now(timezone.utc)
            duration_sec = round(time.time() - start_ticks, 4)

            result.status = ImportStatus.COMPLETED
            result.finished_at = finish_time_dt.isoformat()
            result.duration_seconds = duration_sec
            result.execution_time = duration_sec

            dataset_version.duration = duration_sec
            self.repository.save_dataset_version(dataset_version)
            self.repository.save_import_result(result)

            self.health_monitor.record_sync_success(
                feed_id=feed_id,
                duration=duration_sec,
                active_version_id=dataset_version.version_id,
                validation_state="PASSED",
            )

            self.event_bus.publish(
                FeedCompleted(
                    feed_id=feed_id,
                    import_id=import_id,
                    version_id=dataset_version.version_id,
                    duration_seconds=duration_sec,
                    records_count=record_count,
                )
            )

            self.repository.save_import_logs(import_id, feed_id, logs)
            log_sync_summary(
                logger=logger,
                feed_id=feed_id,
                start_time=start_time_iso,
                finish_time=finish_time_dt.isoformat(),
                duration=duration_sec,
                records_processed=result.records_processed,
                records_inserted=result.records_inserted,
                records_updated=result.records_updated,
                validation_result=result.validation_details,
            )

            return result

        except Exception as ex:
            finish_time_dt = datetime.now(timezone.utc)
            duration_sec = round(time.time() - start_ticks, 4)
            err_msg = str(ex)

            add_log("ERROR", f"Synchronization failed for feed '{feed_id}': {err_msg}")

            result.status = ImportStatus.FAILED
            result.finished_at = finish_time_dt.isoformat()
            result.duration_seconds = duration_sec
            result.error_message = err_msg
            self.repository.save_import_result(result)

            if dataset_version:
                dataset_version.status = DatasetStatus.FAILED
                dataset_version.error_message = err_msg
                self.repository.save_dataset_version(dataset_version)
                try:
                    feed.on_rollback(dataset_version)
                except Exception:
                    pass

            self.health_monitor.record_sync_failure(
                feed_id=feed_id,
                error_message=err_msg,
                duration=duration_sec,
            )

            self.event_bus.publish(
                FeedFailed(
                    feed_id=feed_id,
                    import_id=import_id,
                    error_message=err_msg,
                )
            )

            self.repository.save_import_logs(import_id, feed_id, logs)
            log_sync_summary(
                logger=logger,
                feed_id=feed_id,
                start_time=start_time_iso,
                finish_time=finish_time_dt.isoformat(),
                duration=duration_sec,
                records_processed=result.records_processed,
                records_inserted=result.records_inserted,
                records_updated=result.records_updated,
                validation_result=result.validation_details,
                errors=[err_msg],
            )

            raise
