"""
NVD Data Normalizer for NetFusion IL-3 NVD Pipeline.
Transforms raw parsed NVD CVE dictionaries into normalized immutable NvdCve domain models.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from netfusion_intelligence.feeds.nvd.cpe_matcher import CpeParser
from netfusion_intelligence.feeds.nvd.cvss import CvssParser
from netfusion_intelligence.feeds.nvd.models import (
    ConfigurationNode,
    CpeMatchItem,
    CvssMetric,
    NvdCve,
    ReferenceItem,
    VendorComment,
    WeaknessItem,
)


class NvdNormalizer:
    """
    Normalizes parsed NVD CVE JSON 2.0 objects into NvdCve domain models with zero data loss.
    """

    def __init__(self, cvss_parser: Optional[CvssParser] = None, cpe_parser: Optional[CpeParser] = None):
        self.cvss_parser = cvss_parser or CvssParser()
        self.cpe_parser = cpe_parser or CpeParser()

    def normalize_cpe_match(self, raw_match: Dict[str, Any]) -> CpeMatchItem:
        """Normalizes a raw cpeMatch dictionary into CpeMatchItem."""
        return CpeMatchItem(
            vulnerable=bool(raw_match.get("vulnerable", True)),
            criteria=str(raw_match.get("criteria", "")).strip(),
            match_criteria_id=raw_match.get("matchCriteriaId"),
            version_start_including=raw_match.get("versionStartIncluding"),
            version_start_excluding=raw_match.get("versionStartExcluding"),
            version_end_including=raw_match.get("versionEndIncluding"),
            version_end_excluding=raw_match.get("versionEndExcluding"),
        )

    def normalize_config_node(self, raw_node: Dict[str, Any]) -> Tuple[ConfigurationNode, List[CpeMatchItem]]:
        """
        Normalizes a raw configuration node into ConfigurationNode and extracts flattened list of CPE match items.
        """
        operator = str(raw_node.get("operator", "OR")).upper()
        negate = bool(raw_node.get("negate", False))

        raw_matches = raw_node.get("cpeMatch", [])
        node_matches = []
        all_matches = []

        if isinstance(raw_matches, list):
            for rm in raw_matches:
                if isinstance(rm, dict):
                    m_item = self.normalize_cpe_match(rm)
                    node_matches.append(m_item)
                    all_matches.append(m_item)

        raw_children = raw_node.get("children", [])
        child_nodes = []
        if isinstance(raw_children, list):
            for rc in raw_children:
                if isinstance(rc, dict):
                    child_node, child_matches = self.normalize_config_node(rc)
                    child_nodes.append(child_node)
                    all_matches.extend(child_matches)

        node = ConfigurationNode(
            operator=operator,
            negate=negate,
            cpe_matches=tuple(node_matches),
            children=tuple(child_nodes),
        )

        return node, all_matches

    def normalize_cve(self, raw_item: Dict[str, Any]) -> NvdCve:
        """
        Normalizes a single raw CVE object dict into an NvdCve domain model.
        """
        cve_id = str(raw_item.get("id", "")).strip()
        published = str(raw_item.get("published", "")).strip()
        last_modified = str(raw_item.get("lastModified", "")).strip()
        source_id = raw_item.get("sourceIdentifier")
        vuln_status = raw_item.get("vulnStatus")

        # Descriptions & Titles
        descriptions_raw = raw_item.get("descriptions", [])
        desc_map = {}
        primary_desc = ""
        if isinstance(descriptions_raw, list):
            for d in descriptions_raw:
                if isinstance(d, dict):
                    lang = str(d.get("lang", "en")).lower()
                    val = str(d.get("value", "")).strip()
                    desc_map[lang] = val
                    if lang == "en" and not primary_desc:
                        primary_desc = val

        if not primary_desc and desc_map:
            primary_desc = next(iter(desc_map.values()))

        # Metrics (CVSS v2, v3.0, v3.1, v4.0)
        metrics_raw = raw_item.get("metrics", {})
        if not isinstance(metrics_raw, dict):
            metrics_raw = {}

        cvss_v2 = None
        cvss_v30 = None
        cvss_v31 = None
        cvss_v40 = None

        if "cvssMetricV40" in metrics_raw and isinstance(metrics_raw["cvssMetricV40"], list) and metrics_raw["cvssMetricV40"]:
            cvss_v40 = self.cvss_parser.parse_cvss_metric(metrics_raw["cvssMetricV40"][0], version="4.0")
        if "cvssMetricV31" in metrics_raw and isinstance(metrics_raw["cvssMetricV31"], list) and metrics_raw["cvssMetricV31"]:
            cvss_v31 = self.cvss_parser.parse_cvss_metric(metrics_raw["cvssMetricV31"][0], version="3.1")
        if "cvssMetricV30" in metrics_raw and isinstance(metrics_raw["cvssMetricV30"], list) and metrics_raw["cvssMetricV30"]:
            cvss_v30 = self.cvss_parser.parse_cvss_metric(metrics_raw["cvssMetricV30"][0], version="3.0")
        if "cvssMetricV2" in metrics_raw and isinstance(metrics_raw["cvssMetricV2"], list) and metrics_raw["cvssMetricV2"]:
            cvss_v2 = self.cvss_parser.parse_cvss_metric(metrics_raw["cvssMetricV2"][0], version="2.0")

        # Highest CVSS Score & Severity Selection
        highest_score = 0.0
        severity = "UNKNOWN"

        for metric in (cvss_v40, cvss_v31, cvss_v30, cvss_v2):
            if metric:
                if metric.base_score > highest_score:
                    highest_score = metric.base_score

        if highest_score > 0.0:
            severity = CvssParser.derive_severity_v3(highest_score)


        # Weaknesses (CWEs)
        weaknesses_raw = raw_item.get("weaknesses", [])
        weakness_items = []
        cwes_set = set()

        if isinstance(weaknesses_raw, list):
            for w in weaknesses_raw:
                if isinstance(w, dict):
                    w_source = str(w.get("source", "nvd@nist.gov"))
                    w_type = str(w.get("type", "Primary"))
                    descs = w.get("description", [])
                    cwe_ids = []
                    if isinstance(descs, list):
                        for cd in descs:
                            if isinstance(cd, dict):
                                val = str(cd.get("value", "")).strip()
                                if val.upper().startswith("CWE-"):
                                    cwe_ids.append(val.upper())
                                    cwes_set.add(val.upper())
                    weakness_items.append(WeaknessItem(source=w_source, type=w_type, cwe_ids=tuple(cwe_ids)))

        # Configurations & CPE Matches
        configs_raw = raw_item.get("configurations", [])
        config_nodes = []
        all_cpe_matches = []
        vendors_set = set()
        products_set = set()

        if isinstance(configs_raw, list):
            for c_group in configs_raw:
                if isinstance(c_group, dict):
                    nodes_list = c_group.get("nodes", [c_group]) if "nodes" in c_group else [c_group]
                    for rn in nodes_list:
                        if isinstance(rn, dict):
                            node, node_matches = self.normalize_config_node(rn)
                            config_nodes.append(node)
                            all_cpe_matches.extend(node_matches)

        for match in all_cpe_matches:
            cpe_obj = self.cpe_parser.parse(match.criteria)
            if cpe_obj.vendor and cpe_obj.vendor not in ("*", "-", "any", "na"):
                vendors_set.add(cpe_obj.vendor)
            if cpe_obj.product and cpe_obj.product not in ("*", "-", "any", "na"):
                products_set.add(cpe_obj.product)

        # References
        refs_raw = raw_item.get("references", [])
        ref_items = []
        if isinstance(refs_raw, list):
            for r in refs_raw:
                if isinstance(r, dict):
                    r_url = str(r.get("url", "")).strip()
                    r_src = r.get("source")
                    r_tags = tuple([str(t) for t in r.get("tags", []) if t])
                    if r_url:
                        ref_items.append(ReferenceItem(url=r_url, source=r_src, tags=r_tags))

        # Vendor Comments
        comments_raw = raw_item.get("vendorComments", [])
        comment_items = []
        if isinstance(comments_raw, list):
            for vc in comments_raw:
                if isinstance(vc, dict):
                    c_org = str(vc.get("organization", ""))
                    c_text = str(vc.get("comment", ""))
                    c_mod = vc.get("lastModified")
                    if c_org or c_text:
                        comment_items.append(VendorComment(organization=c_org, comment=c_text, last_modified=c_mod))

        return NvdCve(
            cve_id=cve_id,
            published=published,
            last_modified=last_modified,
            description=primary_desc,
            source_identifier=source_id,
            vuln_status=vuln_status,
            title=raw_item.get("title"),
            severity=severity,
            cvss_score=highest_score,
            descriptions_map=desc_map,
            cvss_v2=cvss_v2,
            cvss_v30=cvss_v30,
            cvss_v31=cvss_v31,
            cvss_v40=cvss_v40,
            weaknesses=tuple(weakness_items),
            cwes=tuple(sorted(cwes_set)),
            configurations=tuple(config_nodes),
            cpe_matches=tuple(all_cpe_matches),
            vendors=tuple(sorted(vendors_set)),
            products=tuple(sorted(products_set)),
            references=tuple(ref_items),
            vendor_comments=tuple(comment_items),
            raw_nvd=raw_item,
        )

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes a parsed NVD dictionary payload containing an 'items' list into domain models.
        """
        items = parsed_data.get("items", [])
        normalized_cves: Dict[str, NvdCve] = {}

        for item in items:
            cve = self.normalize_cve(item)
            normalized_cves[cve.cve_id] = cve

        return {
            "format": parsed_data.get("format", "NVD_CVE"),
            "version": parsed_data.get("version", "2.0"),
            "count": len(normalized_cves),
            "items": list(normalized_cves.values()),
            "entities": normalized_cves,
        }
