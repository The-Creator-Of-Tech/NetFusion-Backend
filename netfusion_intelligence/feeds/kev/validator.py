"""
Validator for CISA KEV Enterprise Intelligence Pipeline.
Enforces structural, schema, date format, catalog version, reference, and orphan entity rules.
"""

from datetime import datetime
import re
from typing import Any, Dict, List, Optional, Set
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.feeds.kev.models import KevRecord

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class CisaKevValidator:
    """
    Validates normalized CISA KEV dataset against domain and structural rules.
    Supports validating orphan entities against existing Canonical CVE entities in CIIL repository.
    """

    def __init__(self, canonical_cve_checker: Optional[Any] = None):
        self.canonical_cve_checker = canonical_cve_checker

    def validate(self, normalized_data: Dict[str, Any]) -> ValidationResult:
        """
        Validates normalized dataset.
        normalized_data is expected to contain 'entities' (Dict[str, KevRecord]) and 'catalog_version'.
        """
        result = ValidationResult(is_valid=True)
        entities: Dict[str, KevRecord] = normalized_data.get("entities", {})
        catalog_ver = str(normalized_data.get("catalog_version", "1.0"))

        result.total_checked = len(entities)

        # Rule 1: Catalog Version check
        if not catalog_ver or catalog_ver == "0":
            result.add_error("INVALID_CATALOG_VERSION", "Catalog version is invalid or missing")
        else:
            result.rules_passed += 1

        seen_cves: Set[str] = set()

        for cve_id, rec in entities.items():
            # Rule 2: CVE ID format check
            if not rec.cve_id:
                result.add_error("MISSING_CVE_ID", "KEV entry is missing CVE ID", entity_id=cve_id, field_name="cve_id")
            elif not CVE_REGEX.match(rec.cve_id):
                result.add_error("MALFORMED_CVE_ID", f"CVE ID '{rec.cve_id}' has malformed format", entity_id=rec.cve_id, field_name="cve_id")
            else:
                result.rules_passed += 1

            # Rule 3: Duplicate KEV entry check in batch
            if rec.cve_id in seen_cves:
                result.add_error("DUPLICATE_KEV_ENTRY", f"Duplicate KEV entry for CVE '{rec.cve_id}'", entity_id=rec.cve_id)
            else:
                seen_cves.add(rec.cve_id)
                result.rules_passed += 1

            # Rule 4: Malformed date checks
            if rec.date_added and not DATE_REGEX.match(rec.date_added):
                try:
                    datetime.fromisoformat(rec.date_added)
                except ValueError:
                    result.add_error("MALFORMED_DATE_ADDED", f"date_added '{rec.date_added}' is malformed", entity_id=rec.cve_id, field_name="date_added")

            if rec.due_date and not DATE_REGEX.match(rec.due_date):
                try:
                    datetime.fromisoformat(rec.due_date)
                except ValueError:
                    result.add_error("MALFORMED_DUE_DATE", f"due_date '{rec.due_date}' is malformed", entity_id=rec.cve_id, field_name="due_date")

            # Rule 5: Broken / invalid reference URLs
            for url in rec.reference_urls:
                if not (url.startswith("http://") or url.startswith("https://")):
                    result.add_warning("BROKEN_REFERENCE_URL", f"Reference URL '{url}' is invalid or missing scheme", entity_id=rec.cve_id)

            # Rule 6: Orphan KEV entry check (must resolve against existing Canonical CVE)
            if self.canonical_cve_checker:
                exists = False
                if callable(self.canonical_cve_checker) and not hasattr(self.canonical_cve_checker, "find_by_external_id"):
                    exists = self.canonical_cve_checker(rec.cve_id)
                elif hasattr(self.canonical_cve_checker, "exists_cve"):
                    exists = self.canonical_cve_checker.exists_cve(rec.cve_id)
                elif hasattr(self.canonical_cve_checker, "find_by_external_id"):
                    matches = self.canonical_cve_checker.find_by_external_id("NVD", rec.cve_id)
                    if not matches and hasattr(self.canonical_cve_checker, "find_by_identifier_value"):
                        matches = self.canonical_cve_checker.find_by_identifier_value(rec.cve_id)
                    if not matches and hasattr(self.canonical_cve_checker, "find_by_alias"):
                        matches = self.canonical_cve_checker.find_by_alias(rec.cve_id)
                    exists = bool(matches)

                if not exists:
                    result.add_error("ORPHAN_KEV_ENTRY", f"KEV entry for '{rec.cve_id}' cannot resolve against existing Canonical CVE entity in CIIL", entity_id=rec.cve_id)

        return result
