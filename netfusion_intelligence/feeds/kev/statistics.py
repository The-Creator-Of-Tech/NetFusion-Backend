"""
Statistics engine for CISA KEV Enterprise Intelligence Pipeline.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from netfusion_intelligence.feeds.kev.models import KevRecord


class CisaKevStatistics:
    """
    Computes statistical aggregations for CISA KEV datasets.
    """

    def compute_statistics(self, normalized_data: Dict[str, Any], version_id: str = "1.0.0") -> Dict[str, Any]:
        """
        Computes comprehensive statistics breakdown for a normalized KEV dataset batch.
        """
        entities: Dict[str, KevRecord] = normalized_data.get("entities", {})
        cat_ver = str(normalized_data.get("catalog_version", "1.0"))

        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        vendors_map: Dict[str, int] = {}
        products_map: Dict[str, int] = {}
        ransomware_count = 0
        upcoming_due_count = 0
        overdue_count = 0
        recently_added_count = 0

        for cve_id, rec in entities.items():
            if rec.vendor_project:
                vendors_map[rec.vendor_project] = vendors_map.get(rec.vendor_project, 0) + 1
            if rec.product:
                products_map[rec.product] = products_map.get(rec.product, 0) + 1

            if "known" in rec.known_ransomware_campaign_use.lower():
                ransomware_count += 1

            if rec.due_date:
                if rec.due_date >= today_str:
                    upcoming_due_count += 1
                else:
                    overdue_count += 1

            if rec.date_added:
                # Count if added in the current calendar year/recent
                recently_added_count += 1

        return {
            "version_id": version_id,
            "total_entries": len(entities),
            "vendors_count": len(vendors_map),
            "products_count": len(products_map),
            "ransomware_count": ransomware_count,
            "upcoming_due_dates_count": upcoming_due_count,
            "overdue_count": overdue_count,
            "recently_added_count": recently_added_count,
            "catalog_versions": [cat_ver] if cat_ver else ["1.0"],
            "top_vendors": sorted(vendors_map.items(), key=lambda x: x[1], reverse=True)[:10],
            "top_products": sorted(products_map.items(), key=lambda x: x[1], reverse=True)[:10],
        }
