"""
NetFusion Knowledge Graph Service (IL-6 Foundation).
Traverses the unified CVE → CWE → CAPEC → ATT&CK → Detection → Mitigation graph.
Modular and reusable — no feed-specific logic hardcoded.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface


class KnowledgeGraphService:
    """
    Provides traversal and enrichment over the unified NetFusion Knowledge Graph.

    Supports:
        CVE → CWE → CAPEC → ATT&CK Technique → Detection → Mitigation

    All lookups delegate to the repository interface for persistence transparency.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface):
        self.repository = repository

    # ------------------------------------------------------------------
    # CVE Knowledge Card
    # ------------------------------------------------------------------

    def get_cve_knowledge(self, cve_id: str) -> Dict[str, Any]:
        """
        Returns a unified knowledge card for a CVE:
        - CVE metadata (NVD)
        - EPSS score
        - KEV status
        - Related CWE weaknesses (with full enrichment)
        - Related CAPEC patterns (via CWE)
        - Related ATT&CK techniques (via CAPEC)
        - Consolidated mitigations
        - Consolidated detection guidance
        """
        result: Dict[str, Any] = {
            "cve_id": cve_id,
            "cve": None,
            "epss": None,
            "kev": None,
            "weaknesses": [],
            "attack_patterns": [],
            "attack_techniques": [],
            "mitigations": [],
            "detection_methods": [],
            "knowledge_graph": {
                "nodes": [],
                "edges": [],
            },
        }

        # --- CVE metadata ---
        if hasattr(self.repository, "get_nvd_cve"):
            result["cve"] = self.repository.get_nvd_cve(cve_id)

        # --- EPSS score ---
        if hasattr(self.repository, "get_epss_score"):
            result["epss"] = self.repository.get_epss_score(cve_id)

        # --- KEV status ---
        if hasattr(self.repository, "get_kev_record"):
            result["kev"] = self.repository.get_kev_record(cve_id)

        # --- CWE IDs from CVE-CWE mapping table ---
        cwe_ids: List[str] = []
        if hasattr(self.repository, "get_cwe_for_cve"):
            cwe_ids = self.repository.get_cwe_for_cve(cve_id)

        # If not in mapping table, extract from NVD CVE weaknesses_json
        if not cwe_ids and result["cve"]:
            raw_weaknesses = result["cve"].get("weaknesses_json") or result["cve"].get("weaknesses") or []
            if isinstance(raw_weaknesses, str):
                import json
                try:
                    raw_weaknesses = json.loads(raw_weaknesses)
                except Exception:
                    raw_weaknesses = []
            for w in raw_weaknesses:
                if isinstance(w, dict):
                    wid = w.get("cwe_id") or w.get("value") or ""
                    if wid.startswith("CWE-") and wid not in cwe_ids:
                        cwe_ids.append(wid)

        # --- Enrich CWE weaknesses ---
        seen_capec_ids: List[str] = []
        all_mitigations: List[Dict[str, Any]] = []
        all_detection: List[Dict[str, Any]] = []

        if hasattr(self.repository, "get_cwe_weakness"):
            for cwe_id in cwe_ids:
                cwe_data = self.repository.get_cwe_weakness(cwe_id)
                if cwe_data:
                    result["weaknesses"].append(cwe_data)
                    # Collect mitigations and detection
                    for m in cwe_data.get("mitigations", []):
                        m["source"] = cwe_id
                        m["source_type"] = "CWE"
                        all_mitigations.append(m)
                    for d in cwe_data.get("detection_methods", []):
                        d["source"] = cwe_id
                        d["source_type"] = "CWE"
                        all_detection.append(d)
                    # Collect CAPEC IDs referenced by this CWE (from CWE's related_attack_patterns field)
                    for capec_id in cwe_data.get("related_attack_patterns", []):
                        if capec_id not in seen_capec_ids:
                            seen_capec_ids.append(capec_id)

        # --- Also look up CAPEC via the capec_cwe cross-reference table (bidirectional) ---
        if hasattr(self.repository, "list_capec_by_cwe"):
            for cwe_id in cwe_ids:
                for capec_record in self.repository.list_capec_by_cwe(cwe_id):
                    capec_id = capec_record.get("capec_id")
                    if capec_id and capec_id not in seen_capec_ids:
                        seen_capec_ids.append(capec_id)

        # --- Enrich CAPEC attack patterns ---
        seen_attack_ids: List[str] = []
        if hasattr(self.repository, "get_capec_attack_pattern"):
            for capec_id in seen_capec_ids:
                capec_data = self.repository.get_capec_attack_pattern(capec_id)
                if capec_data:
                    result["attack_patterns"].append(capec_data)
                    # Collect mitigations and detection
                    for m in capec_data.get("mitigations", []):
                        m["source"] = capec_id
                        m["source_type"] = "CAPEC"
                        all_mitigations.append(m)
                    for d in capec_data.get("detection", []):
                        d["source"] = capec_id
                        d["source_type"] = "CAPEC"
                        all_detection.append(d)
                    # Collect ATT&CK technique IDs
                    for tech_id in capec_data.get("attack_technique_ids", []):
                        if tech_id not in seen_attack_ids:
                            seen_attack_ids.append(tech_id)

        # --- Enrich ATT&CK techniques ---
        if hasattr(self.repository, "get_mitre_object"):
            for tech_id in seen_attack_ids:
                tech_data = self.repository.get_mitre_object(tech_id)
                if tech_data:
                    result["attack_techniques"].append(tech_data)

        result["mitigations"] = all_mitigations
        result["detection_methods"] = all_detection

        # --- Build knowledge graph nodes and edges ---
        result["knowledge_graph"] = self._build_graph(
            cve_id=cve_id,
            cwe_ids=[w.get("cwe_id") for w in result["weaknesses"] if w.get("cwe_id")],
            capec_ids=[c.get("capec_id") for c in result["attack_patterns"] if c.get("capec_id")],
            attack_ids=[t.get("attack_id") for t in result["attack_techniques"] if t.get("attack_id")],
        )

        return result

    # ------------------------------------------------------------------
    # Weaknesses for a CAPEC
    # ------------------------------------------------------------------

    def get_capec_knowledge(self, capec_id: str) -> Dict[str, Any]:
        """Returns enriched view of a CAPEC with linked CWEs and ATT&CK techniques."""
        result: Dict[str, Any] = {
            "capec_id": capec_id,
            "attack_pattern": None,
            "weaknesses": [],
            "attack_techniques": [],
        }

        if hasattr(self.repository, "get_capec_attack_pattern"):
            result["attack_pattern"] = self.repository.get_capec_attack_pattern(capec_id)

        if result["attack_pattern"]:
            if hasattr(self.repository, "get_cwe_weakness"):
                for cwe_id in result["attack_pattern"].get("related_weaknesses", []):
                    cwe_data = self.repository.get_cwe_weakness(cwe_id)
                    if cwe_data:
                        result["weaknesses"].append(cwe_data)
            if hasattr(self.repository, "get_mitre_object"):
                for tech_id in result["attack_pattern"].get("attack_technique_ids", []):
                    tech = self.repository.get_mitre_object(tech_id)
                    if tech:
                        result["attack_techniques"].append(tech)

        return result

    # ------------------------------------------------------------------
    # Graph Builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_graph(
        cve_id: str,
        cwe_ids: List[str],
        capec_ids: List[str],
        attack_ids: List[str],
    ) -> Dict[str, Any]:
        """Constructs a lightweight node/edge graph representation."""
        nodes = []
        edges = []

        cve_node = {"id": cve_id, "type": "CVE", "label": cve_id}
        nodes.append(cve_node)

        for cwe_id in cwe_ids:
            nodes.append({"id": cwe_id, "type": "CWE", "label": cwe_id})
            edges.append({"source": cve_id, "target": cwe_id, "relationship": "has_weakness"})

        for capec_id in capec_ids:
            nodes.append({"id": capec_id, "type": "CAPEC", "label": capec_id})
            for cwe_id in cwe_ids:
                edges.append({"source": cwe_id, "target": capec_id, "relationship": "exploited_by"})

        for tech_id in attack_ids:
            nodes.append({"id": tech_id, "type": "ATT&CK", "label": tech_id})
            for capec_id in capec_ids:
                edges.append({"source": capec_id, "target": tech_id, "relationship": "maps_to"})

        return {"nodes": nodes, "edges": edges}


    # ------------------------------------------------------------------
    # IL-7 IOC Knowledge Traversal
    # ------------------------------------------------------------------

    def get_ioc_knowledge(self, ioc_id: str) -> Dict[str, Any]:
        """
        Returns a full knowledge card for an IOC traversing the graph:
        IOC → Malware → Campaign → Threat Actor → ATT&CK → CAPEC → CWE → CVE
        """
        result: Dict[str, Any] = {
            "ioc_id": ioc_id,
            "indicator": None,
            "reputation": None,
            "sightings": [],
            "relationships": [],
            "malware": [],
            "campaigns": [],
            "threat_actors": [],
            "attack_techniques": [],
            "attack_patterns": [],
            "weaknesses": [],
            "cves": [],
            "knowledge_graph": {"nodes": [], "edges": []},
        }

        # Base indicator
        if hasattr(self.repository, "get_ioc_indicator"):
            result["indicator"] = self.repository.get_ioc_indicator(ioc_id)

        if not result["indicator"]:
            return result

        ind = result["indicator"]

        # Reputation
        if hasattr(self.repository, "get_ioc_reputation"):
            result["reputation"] = self.repository.get_ioc_reputation(ioc_id)

        # Sightings (most recent 10)
        if hasattr(self.repository, "get_ioc_sightings"):
            result["sightings"] = self.repository.get_ioc_sightings(ioc_id, limit=10)

        # Relationships
        if hasattr(self.repository, "get_ioc_relationships"):
            result["relationships"] = self.repository.get_ioc_relationships(ioc_id, limit=100)

        # ATT&CK techniques
        if hasattr(self.repository, "get_mitre_object"):
            for tech_id in ind.get("attack_technique_ids", []):
                tech = self.repository.get_mitre_object(tech_id)
                if tech:
                    result["attack_techniques"].append(tech)

        # CAPEC patterns
        if hasattr(self.repository, "get_capec_attack_pattern"):
            for capec_id in ind.get("capec_ids", []):
                pat = self.repository.get_capec_attack_pattern(capec_id)
                if pat:
                    result["attack_patterns"].append(pat)

        # CWE weaknesses
        if hasattr(self.repository, "get_cwe_weakness"):
            for cwe_id in ind.get("cwe_ids", []):
                weakness = self.repository.get_cwe_weakness(cwe_id)
                if weakness:
                    result["weaknesses"].append(weakness)

        # CVEs
        if hasattr(self.repository, "get_nvd_cve"):
            for cve_id in ind.get("cve_ids", []):
                cve = self.repository.get_nvd_cve(cve_id)
                if cve:
                    result["cves"].append(cve)

        # Build graph
        result["knowledge_graph"] = self._build_ioc_graph(
            ioc_id=ioc_id,
            ioc_type=ind.get("ioc_type", "ioc"),
            attack_ids=[t.get("attack_id") for t in result["attack_techniques"] if t.get("attack_id")],
            capec_ids=[p.get("capec_id") for p in result["attack_patterns"] if p.get("capec_id")],
            cwe_ids=[w.get("cwe_id") for w in result["weaknesses"] if w.get("cwe_id")],
            cve_ids=[c.get("cve_id") for c in result["cves"] if c.get("cve_id")],
            malware=ind.get("malware_families", []),
            campaigns=ind.get("campaigns", []),
        )
        return result

    def get_iocs_for_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Returns all IOCs correlated to a given ATT&CK technique."""
        if hasattr(self.repository, "search_ioc_indicators"):
            return self.repository.search_ioc_indicators(
                attack_technique=technique_id, limit=200
            )
        return []

    def get_iocs_for_malware(self, malware_family: str) -> List[Dict[str, Any]]:
        """Returns all IOCs correlated to a given malware family."""
        if hasattr(self.repository, "search_ioc_indicators"):
            return self.repository.search_ioc_indicators(
                malware=malware_family, limit=200
            )
        return []

    @staticmethod
    def _build_ioc_graph(
        ioc_id: str,
        ioc_type: str,
        attack_ids: List[str],
        capec_ids: List[str],
        cwe_ids: List[str],
        cve_ids: List[str],
        malware: List[str],
        campaigns: List[str],
    ) -> Dict[str, Any]:
        nodes, edges = [], []
        nodes.append({"id": ioc_id, "type": ioc_type.upper(), "label": ioc_id[:60]})

        for mf in malware:
            nodes.append({"id": mf, "type": "MALWARE", "label": mf})
            edges.append({"source": ioc_id, "target": mf, "relationship": "ioc_to_malware"})
        for camp in campaigns:
            nodes.append({"id": camp, "type": "CAMPAIGN", "label": camp})
            edges.append({"source": ioc_id, "target": camp, "relationship": "ioc_to_campaign"})
        for tech_id in attack_ids:
            nodes.append({"id": tech_id, "type": "ATT&CK", "label": tech_id})
            edges.append({"source": ioc_id, "target": tech_id, "relationship": "ioc_to_attack_technique"})
        for capec_id in capec_ids:
            nodes.append({"id": capec_id, "type": "CAPEC", "label": capec_id})
            edges.append({"source": ioc_id, "target": capec_id, "relationship": "ioc_to_capec"})
        for cwe_id in cwe_ids:
            nodes.append({"id": cwe_id, "type": "CWE", "label": cwe_id})
            edges.append({"source": ioc_id, "target": cwe_id, "relationship": "ioc_to_cwe"})
        for cve_id in cve_ids:
            nodes.append({"id": cve_id, "type": "CVE", "label": cve_id})
            edges.append({"source": ioc_id, "target": cve_id, "relationship": "ioc_to_cve"})

        return {"nodes": nodes, "edges": edges}
