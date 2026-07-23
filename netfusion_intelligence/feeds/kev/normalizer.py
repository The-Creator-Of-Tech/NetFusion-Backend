"""
Normalizer for CISA KEV Intelligence Pipeline.
Converts parsed catalog structures into typed KevCatalog and KevRecord domain models.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
from netfusion_intelligence.feeds.kev.models import KevCatalog, KevRecord

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CisaKevNormalizer:
    """
    Normalizes parsed CISA KEV JSON/CSV dictionaries into strongly-typed KevRecord domain objects.
    """

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes parsed dictionary into KevCatalog and a map of KevRecord objects.
        Returns dict containing 'catalog' (KevCatalog) and 'entities' (Dict[str, KevRecord]).
        """
        raw_vulns = parsed_data.get("vulnerabilities", [])
        title = parsed_data.get("title", "CISA Known Exploited Vulnerabilities Catalog")
        cat_ver = str(parsed_data.get("catalogVersion", "1.0"))
        date_released = parsed_data.get("dateReleased", "")

        records_map: Dict[str, KevRecord] = {}

        for item in raw_vulns:
            rec = self.normalize_record(item, catalog_version=cat_ver)
            if rec and rec.cve_id:
                # Deduplicate by CVE ID in normalized batch
                records_map[rec.cve_id] = rec

        catalog = KevCatalog(
            title=title,
            catalog_version=cat_ver,
            date_released=date_released or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            count=len(records_map),
            records=records_map,
        )

        return {
            "catalog": catalog,
            "entities": records_map,
            "count": len(records_map),
            "catalog_version": cat_ver,
        }

    def normalize_record(self, raw_item: Dict[str, Any], catalog_version: str = "1.0") -> Optional[KevRecord]:
        """
        Normalizes a single raw item dict into a KevRecord.
        """
        cve_raw = (
            raw_item.get("cveID") or
            raw_item.get("cve_id") or
            raw_item.get("cveId") or
            ""
        ).strip().upper()

        if not cve_raw:
            return None

        # Standardize CVE format if matching regex
        match = CVE_REGEX.search(cve_raw)
        cve_id = match.group(0).upper() if match else cve_raw

        vendor = (raw_item.get("vendorProject") or raw_item.get("vendor_project") or raw_item.get("vendor") or "").strip()
        product = (raw_item.get("product") or raw_item.get("product_name") or "").strip()
        vname = (raw_item.get("vulnerabilityName") or raw_item.get("vulnerability_name") or raw_item.get("title") or "").strip()
        date_add = (raw_item.get("dateAdded") or raw_item.get("date_added") or "").strip()
        sdesc = (raw_item.get("shortDescription") or raw_item.get("short_description") or raw_item.get("description") or "").strip()
        req_act = (raw_item.get("requiredAction") or raw_item.get("required_action") or raw_item.get("remediation") or "").strip()
        due_date = (raw_item.get("dueDate") or raw_item.get("due_date") or "").strip()

        ransom = (raw_item.get("knownRansomwareCampaignUse") or raw_item.get("known_ransomware_campaign_use") or raw_item.get("ransomware") or "Unknown").strip()

        notes = (raw_item.get("notes") or "").strip()

        # Handle reference URLs / CWES if present
        ref_urls: List[str] = []
        if notes and (notes.startswith("http://") or notes.startswith("https://")):
            ref_urls.append(notes)

        raw_refs = raw_item.get("reference_urls") or raw_item.get("references") or []
        if isinstance(raw_refs, list):
            ref_urls.extend([r for r in raw_refs if isinstance(r, str)])
        elif isinstance(raw_refs, str) and raw_refs:
            ref_urls.append(raw_refs)

        cwes: List[str] = []
        raw_cwes = raw_item.get("cwes") or raw_item.get("cwes_list") or []
        if isinstance(raw_cwes, list):
            cwes.extend([c for c in raw_cwes if isinstance(c, str)])

        return KevRecord(
            cve_id=cve_id,
            vendor_project=vendor,
            product=product,
            vulnerability_name=vname,
            date_added=date_add,
            short_description=sdesc,
            required_action=req_act,
            due_date=due_date,
            known_ransomware_campaign_use=ransom,
            notes=notes,
            cwes=tuple(cwes),
            reference_urls=tuple(dict.fromkeys(ref_urls)),  # deduplicate preserves order
            catalog_version=catalog_version,
            source="CISA KEV",
            created=datetime.now(timezone.utc).isoformat(),
            modified=datetime.now(timezone.utc).isoformat(),
            status="ACTIVE",
        )
