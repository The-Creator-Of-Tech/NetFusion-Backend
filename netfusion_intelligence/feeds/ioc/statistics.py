"""
IL-7 IOC Statistics Engine.
Computes comprehensive coverage, distribution, and quality metrics
for the normalized IOC dataset.
"""

from typing import Any, Dict, List
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocSeverity, IocType


class IocStatistics:
    """
    Computes statistical metrics for normalized IOC datasets.
    """

    @staticmethod
    def calculate_statistics(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute structured statistics from a normalized IOC dataset dict.
        Input must contain {"entities": {fp: IocEntity, ...}}.
        """
        if not isinstance(normalized_data, dict):
            return {}

        entities: Dict[str, IocEntity] = normalized_data.get("entities", {})
        if not entities:
            return {
                "total_indicators": 0, "by_type": {}, "by_severity": {},
                "average_confidence": 0.0, "average_reputation_score": 0.0,
                "duplicate_count": normalized_data.get("duplicate_count", 0),
            }

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_tlp: Dict[str, int] = {}
        by_provider: Dict[str, int] = {}
        total_confidence = 0.0
        total_reputation = 0.0
        has_malware = has_campaign = has_actor = has_attack = 0
        top_malware: Dict[str, int] = {}
        top_campaigns: Dict[str, int] = {}
        top_actors: Dict[str, int] = {}
        top_attack: Dict[str, int] = {}
        top_domains: List[str] = []
        top_ips: List[str] = []
        top_hashes: List[str] = []
        high_conf: int = 0
        low_conf: int = 0

        domain_types = {IocType.DOMAIN.value, IocType.HOSTNAME.value}
        ip_types = {IocType.IPV4.value, IocType.IPV6.value}
        hash_types = {IocType.MD5.value, IocType.SHA1.value, IocType.SHA256.value, IocType.SHA512.value}

        for ent in entities.values():
            # By type
            by_type[ent.ioc_type] = by_type.get(ent.ioc_type, 0) + 1
            # By severity
            by_severity[ent.severity] = by_severity.get(ent.severity, 0) + 1
            # By TLP
            tlp = ent.tlp or "UNKNOWN"
            by_tlp[tlp] = by_tlp.get(tlp, 0) + 1
            # By provider
            prov = ent.provider or "unknown"
            by_provider[prov] = by_provider.get(prov, 0) + 1

            total_confidence += ent.confidence
            total_reputation += ent.reputation_score

            if ent.confidence >= 0.8:
                high_conf += 1
            elif ent.confidence < 0.3:
                low_conf += 1

            # Attribution counters
            if ent.malware_families:
                has_malware += 1
                for mf in ent.malware_families:
                    top_malware[mf] = top_malware.get(mf, 0) + 1
            if ent.campaigns:
                has_campaign += 1
                for c in ent.campaigns:
                    top_campaigns[c] = top_campaigns.get(c, 0) + 1
            if ent.threat_actors:
                has_actor += 1
                for a in ent.threat_actors:
                    top_actors[a] = top_actors.get(a, 0) + 1
            if ent.attack_technique_ids:
                has_attack += 1
                for t in ent.attack_technique_ids:
                    top_attack[t] = top_attack.get(t, 0) + 1

            # Sample top values per class
            if ent.ioc_type in domain_types and len(top_domains) < 10:
                top_domains.append(ent.value)
            if ent.ioc_type in ip_types and len(top_ips) < 10:
                top_ips.append(ent.value)
            if ent.ioc_type in hash_types and len(top_hashes) < 10:
                top_hashes.append(ent.value)

        total = len(entities)

        def top_n(d: Dict[str, int], n: int = 10) -> List[Dict[str, Any]]:
            return [{"name": k, "count": v}
                    for k, v in sorted(d.items(), key=lambda x: -x[1])[:n]]

        return {
            "total_indicators": total,
            "duplicate_count": normalized_data.get("duplicate_count", 0),
            "by_type": by_type,
            "by_severity": by_severity,
            "by_tlp": by_tlp,
            "top_providers": top_n(by_provider),
            "average_confidence": round(total_confidence / total, 4) if total else 0.0,
            "average_reputation_score": round(total_reputation / total, 3) if total else 0.0,
            "high_confidence_count": high_conf,
            "low_confidence_count": low_conf,
            "indicators_with_malware": has_malware,
            "indicators_with_campaign": has_campaign,
            "indicators_with_actor": has_actor,
            "indicators_with_attack": has_attack,
            "top_malware_families": top_n(top_malware),
            "top_campaigns": top_n(top_campaigns),
            "top_actors": top_n(top_actors),
            "top_attack_techniques": top_n(top_attack),
            "sample_domains": top_domains,
            "sample_ips": top_ips,
            "sample_hashes": top_hashes,
            "malware_attribution_pct": round(has_malware / total * 100, 2) if total else 0.0,
            "campaign_attribution_pct": round(has_campaign / total * 100, 2) if total else 0.0,
            "actor_attribution_pct": round(has_actor / total * 100, 2) if total else 0.0,
            "attack_mapping_pct": round(has_attack / total * 100, 2) if total else 0.0,
        }
