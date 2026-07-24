"""
Validator for FIRST EPSS normalized data.
Validates schema, range checks, CIIL resolution, and business rules.
"""

import logging
from typing import Any, Dict, List, Optional

from netfusion_intelligence.feeds.epss.models import EpssRecord
from netfusion_intelligence.interfaces.validator import ValidatorInterface, ValidationResult
from netfusion_intelligence.identity.repository import IdentityRepository

logger = logging.getLogger(__name__)


class EpssValidator(ValidatorInterface):
    """
    Validates normalized EPSS records against schema, business rules, and CIIL constraints.
    """

    def __init__(self, canonical_cve_checker: Optional[IdentityRepository] = None):
        self.canonical_cve_checker = canonical_cve_checker

    def validate(self, normalized_data: Any) -> ValidationResult:
        """
        Validates normalized EPSS data.
        Returns ValidationResult with is_valid, errors, and warnings.
        """
        if not normalized_data:
            return ValidationResult(
                is_valid=False,
                errors=["Normalized data is empty or None"],
                warnings=[],
            )

        entities: Dict[str, EpssRecord] = normalized_data.get("entities", {})
        metadata = normalized_data.get("metadata", {})

        if not entities:
            return ValidationResult(
                is_valid=False,
                errors=["No EPSS entities found in normalized data"],
                warnings=[],
            )

        errors: List[str] = []
        warnings: List[str] = []

        # Validate each record
        for cve_id, record in entities.items():
            record_errors = self._validate_record(record)
            if record_errors:
                errors.extend([f"{cve_id}: {err}" for err in record_errors])

            # Check for canonical CVE resolution
            if self.canonical_cve_checker:
                if not self._canonical_cve_exists(cve_id):
                    warnings.append(
                        f"{cve_id}: No canonical CVE entity found in CIIL - EPSS enrichment will be skipped"
                    )

        # Schema validation
        schema_errors = self._validate_schema(normalized_data)
        errors.extend(schema_errors)

        # Business rule validation
        business_errors, business_warnings = self._validate_business_rules(entities, metadata)
        errors.extend(business_errors)
        warnings.extend(business_warnings)

        is_valid = len(errors) == 0

        logger.info(
            f"EPSS validation complete: valid={is_valid}, "
            f"errors={len(errors)}, warnings={len(warnings)}"
        )

        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
        )

    def _validate_record(self, record: EpssRecord) -> List[str]:
        """Validates a single EpssRecord."""
        errors: List[str] = []

        # CVE ID format
        if not record.cve_id or not record.cve_id.startswith("CVE-"):
            errors.append(f"Invalid CVE ID format: {record.cve_id}")

        # Score range validation
        if not (0.0 <= record.current_score <= 1.0):
            errors.append(f"EPSS score out of range [0.0, 1.0]: {record.current_score}")

        # Percentile range validation
        if not (0.0 <= record.current_percentile <= 1.0):
            errors.append(f"EPSS percentile out of range [0.0, 1.0]: {record.current_percentile}")

        # Publication date format
        if not record.publication_date:
            errors.append("Publication date is missing")

        # Model version
        if not record.model_version:
            errors.append("Model version is missing")

        # Historical data consistency
        if record.historical_high is not None and record.historical_high < record.current_score:
            errors.append(
                f"historical_high ({record.historical_high}) < current_score ({record.current_score})"
            )

        if record.historical_low is not None and record.historical_low > record.current_score:
            errors.append(
                f"historical_low ({record.historical_low}) > current_score ({record.current_score})"
            )

        return errors

    def _validate_schema(self, normalized_data: Dict[str, Any]) -> List[str]:
        """Validates the overall schema of normalized data."""
        errors: List[str] = []

        required_keys = ["entities", "metadata"]
        for key in required_keys:
            if key not in normalized_data:
                errors.append(f"Missing required key in normalized data: {key}")

        return errors

    def _validate_business_rules(
        self,
        entities: Dict[str, EpssRecord],
        metadata: Dict[str, Any]
    ) -> tuple[List[str], List[str]]:
        """Validates business rules and data quality constraints."""
        errors: List[str] = []
        warnings: List[str] = []

        # Check for minimum record count (EPSS should have thousands of CVEs)
        if len(entities) < 100:
            warnings.append(
                f"EPSS dataset contains only {len(entities)} records - expected thousands. "
                f"This may indicate a partial download or parsing issue."
            )

        # Check for duplicate CVE IDs (should not happen if normalizer works correctly)
        cve_ids = [rec.cve_id for rec in entities.values()]
        if len(cve_ids) != len(set(cve_ids)):
            errors.append("Duplicate CVE IDs detected in normalized entities")

        # Validate model_version format
        model_version = metadata.get("model_version", "")
        if model_version and not model_version.startswith("v"):
            warnings.append(f"Unexpected model_version format: {model_version}")

        return errors, warnings

    def _canonical_cve_exists(self, cve_id: str) -> bool:
        """
        Checks if a canonical CVE entity exists in CIIL for the given CVE ID.
        Returns True if found, False otherwise.
        """
        if not self.canonical_cve_checker:
            return True  # Assume valid if no checker configured

        try:
            # Search for CVE in CIIL by external identifier
            entities = self.canonical_cve_checker.find_by_identifier_value(cve_id)
            return len(entities) > 0
        except Exception as e:
            logger.warning(f"Error checking canonical CVE existence for {cve_id}: {e}")
            return True  # Don't fail validation due to lookup error
