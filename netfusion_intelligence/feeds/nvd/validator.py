"""
NVD Dataset Validator for NetFusion IL-3 NVD Pipeline.
Validates normalized NVD dataset objects against strict domain and structural integrity rules.
"""

from typing import Any, Dict, List
from netfusion_intelligence.interfaces.validator import ValidationResult, ValidatorInterface
from netfusion_intelligence.feeds.nvd.models import NvdCve


class NvdValidator(ValidatorInterface):
    """
    Validates normalized NVD CVE dataset.
    Flags/rejects:
    - Missing or malformed CVE IDs
    - Duplicate CVE IDs in dataset
    - Out-of-range CVSS scores (<0.0 or >10.0)
    - Malformed CVSS vector strings
    - Invalid CPE formatted strings
    - Broken reference URLs
    - Empty descriptions
    """

    def validate(self, normalized_data: Any) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        if not isinstance(normalized_data, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Normalized data is not a dictionary")
            return result

        entities = normalized_data.get("entities", {})
        if not isinstance(entities, dict):
            result.add_error("STRUCTURAL_VALIDATION", "Entities in normalized data is not a dictionary")
            return result

        seen_ids = set()
        result.total_checked = len(entities)

        for cve_id, cve in entities.items():
            if not isinstance(cve, NvdCve):
                result.add_error("TYPE_VALIDATION", f"Entity '{cve_id}' is not an instance of NvdCve", entity_id=cve_id)
                continue

            # 1. Check CVE ID presence & format
            if not cve.cve_id:
                result.add_error("MISSING_ID", "CVE record is missing cve_id", entity_id=cve_id, field_name="cve_id")
            elif cve.cve_id in seen_ids:
                result.add_error("DUPLICATE_ID", f"Duplicate CVE ID found: {cve.cve_id}", entity_id=cve.cve_id, field_name="cve_id")
            else:
                seen_ids.add(cve.cve_id)

            if not cve.cve_id.upper().startswith("CVE-"):
                result.add_warning("MALFORMED_CVE_ID", f"CVE ID '{cve.cve_id}' does not start with CVE-", entity_id=cve.cve_id)

            # 2. Check CVSS Scores & Vectors
            if cve.cvss_score < 0.0 or cve.cvss_score > 10.0:
                result.add_error(
                    "INVALID_CVSS_SCORE",
                    f"CVSS score {cve.cvss_score} out of valid range [0.0, 10.0]",
                    entity_id=cve.cve_id,
                    field_name="cvss_score",
                )

            for cvss in (cve.cvss_v40, cve.cvss_v31, cve.cvss_v30, cve.cvss_v2):
                if cvss:
                    if cvss.base_score < 0.0 or cvss.base_score > 10.0:
                        result.add_error(
                            "INVALID_CVSS_SCORE",
                            f"CVSS v{cvss.version} base score {cvss.base_score} is out of bounds",
                            entity_id=cve.cve_id,
                            field_name=f"cvss_v{cvss.version}",
                        )
                    if cvss.vector_string and not (cvss.vector_string.startswith("CVSS:") or cvss.vector_string.startswith("AV:")):
                        result.add_warning(
                            "MALFORMED_CVSS_VECTOR",
                            f"CVSS vector '{cvss.vector_string}' has unusual format",
                            entity_id=cve.cve_id,
                        )

            # 3. Check Descriptions
            if not cve.description:
                result.add_warning("EMPTY_DESCRIPTION", f"CVE '{cve.cve_id}' has no primary description", entity_id=cve.cve_id)

            # 4. Check CPE Matches
            for match in cve.cpe_matches:
                if not match.criteria or not match.criteria.startswith("cpe:"):
                    result.add_warning(
                        "BROKEN_CPE_TREE",
                        f"CPE match criteria '{match.criteria}' is malformed",
                        entity_id=cve.cve_id,
                    )

            # 5. Check References
            for ref in cve.references:
                if not ref.url or not (ref.url.startswith("http://") or ref.url.startswith("https://") or ref.url.startswith("ftp://")):
                    result.add_warning(
                        "INVALID_REFERENCE",
                        f"Reference URL '{ref.url}' is malformed",
                        entity_id=cve.cve_id,
                    )

            result.rules_passed += 1

        return result
