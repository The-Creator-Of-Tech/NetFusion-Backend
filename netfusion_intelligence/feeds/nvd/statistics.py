"""
NVD Vulnerability Intelligence Statistics Engine.
Calculates dataset breakdown, severity distribution, vendor/product exposure,
CWE weakness frequencies, and risk metrics.
"""

from collections import Counter
from typing import Any, Dict, List, Optional
from netfusion_intelligence.feeds.nvd.models import NvdCve


class NvdStatistics:
    """
    Computes analytics and intelligence statistics for NVD datasets.
    """

    def compute_statistics(self, cves: List[NvdCve]) -> Dict[str, Any]:
        """
        Computes detailed statistics for a list of NvdCve objects.
        """
        total = len(cves)
        if total == 0:
            return {
                "total_cves": 0,
                "cves_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                "average_cvss": 0.0,
                "cves_by_vendor": {},
                "cves_by_product": {},
                "cves_by_cwe": {},
                "cves_by_year": {},
                "highest_risk_products": [],
                "most_common_weaknesses": [],
            }

        severities = Counter()
        vendors = Counter()
        products = Counter()
        cwes = Counter()
        years = Counter()

        total_cvss = 0.0
        cvss_count = 0

        product_scores: Dict[str, List[float]] = {}

        for cve in cves:
            severities[cve.severity.upper()] += 1
            
            if cve.cvss_score > 0.0:
                total_cvss += cve.cvss_score
                cvss_count += 1

            for v in cve.vendors:
                vendors[v] += 1

            for p in cve.products:
                products[p] += 1
                if p not in product_scores:
                    product_scores[p] = []
                if cve.cvss_score > 0.0:
                    product_scores[p].append(cve.cvss_score)

            for cwe in cve.cwes:
                cwes[cwe] += 1

            if cve.published and len(cve.published) >= 4:
                year = cve.published[:4]
                if year.isdigit():
                    years[year] += 1

        avg_cvss = round(total_cvss / cvss_count, 2) if cvss_count > 0 else 0.0

        # Calculate highest risk products (by avg CVSS score & count)
        top_risk_products = []
        for p, scores in product_scores.items():
            if scores:
                p_avg = round(sum(scores) / len(scores), 2)
                p_max = max(scores)
                top_risk_products.append({"product": p, "cve_count": len(scores), "avg_cvss": p_avg, "max_cvss": p_max})

        top_risk_products.sort(key=lambda x: (x["max_cvss"], x["avg_cvss"], x["cve_count"]), reverse=True)

        return {
            "total_cves": total,
            "cves_by_severity": {
                "CRITICAL": severities.get("CRITICAL", 0),
                "HIGH": severities.get("HIGH", 0),
                "MEDIUM": severities.get("MEDIUM", 0),
                "LOW": severities.get("LOW", 0),
                "UNKNOWN": severities.get("UNKNOWN", 0),
            },
            "average_cvss": avg_cvss,
            "cves_by_vendor": dict(vendors.most_common(50)),
            "cves_by_product": dict(products.most_common(50)),
            "cves_by_cwe": dict(cwes.most_common(50)),
            "cves_by_year": dict(sorted(years.items())),
            "highest_risk_products": top_risk_products[:10],
            "most_common_weaknesses": [{"cwe_id": k, "count": v} for k, v in cwes.most_common(10)],
        }
