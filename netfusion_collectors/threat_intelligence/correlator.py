import re
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk import CollectorContext
from .canonical import (
    IOCObserved,
    ThreatIntelMatched,
    ThreatActorObserved,
    CampaignObserved,
    MalwareObserved,
    ExploitObserved,
    RelationshipObserved,
    MITREMappingObserved,
    EvidenceLineage,
)
from .providers import ProviderResponse


class ThreatCorrelator:
    """
    Automated Correlation Engine for Threat Intelligence.
    Links telemetry across IP ↔ Domain, Hash ↔ Malware, CVE ↔ Exploit, Actor ↔ Campaign, Technique ↔ MITRE.
    """

    CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    MITRE_REGEX = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)

    def __init__(self):
        pass

    def correlate_provider_response(
        self,
        resp: ProviderResponse,
        context: CollectorContext,
    ) -> List[Any]:
        """
        Processes a raw ProviderResponse and generates correlated Canonical Objects.
        """
        canonical_objects: List[Any] = []
        investigation_id = context.investigation_id or context.correlation_id

        lineage = [
            {
                "provider": resp.provider_name,
                "lookup_timestamp": context.start_time,
                "raw_reference": resp.references[0] if resp.references else "",
                "verification_method": "API_QUERY",
                "collector_id": context.collector_id,
                "investigation_id": investigation_id,
            }
        ]

        # 1. Primary IOCObserved
        ioc_obj = IOCObserved(
            ioc_type=resp.ioc_type,
            ioc_value=resp.ioc_value,
            provider=resp.provider_name,
            confidence=resp.confidence,
            evidence_lineage=lineage,
            source_references=resp.references,
            investigation_correlation=investigation_id,
            first_seen=resp.first_seen,
            last_seen=resp.last_seen,
            threat_types=resp.categories,
            risk_score=resp.confidence,
        )
        ioc_obj.collector_id = context.collector_id
        ioc_obj.correlation_id = context.correlation_id
        canonical_objects.append(ioc_obj)

        # 2. ThreatIntelMatched if threat detected
        if resp.is_threat:
            matched_obj = ThreatIntelMatched(
                ioc_value=resp.ioc_value,
                ioc_type=resp.ioc_type,
                provider=resp.provider_name,
                match_severity=resp.severity,
                confidence=resp.confidence,
                threat_name=resp.threat_name,
                category="Threat Match",
                description=f"Threat match confirmed by {resp.provider_name}",
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
                raw_response=resp.raw_data,
            )
            matched_obj.collector_id = context.collector_id
            matched_obj.correlation_id = context.correlation_id
            canonical_objects.append(matched_obj)

        # 3. IP ↔ Domain Correlation
        if resp.metadata and "domain" in resp.metadata and resp.metadata["domain"]:
            domain_val = resp.metadata["domain"]
            rel_obj = RelationshipObserved(
                source_id=resp.ioc_value,
                source_type=resp.ioc_type,
                relationship_type="RESOLVES_TO",
                target_id=domain_val,
                target_type="Domain",
                provider=resp.provider_name,
                confidence=resp.confidence,
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
            )
            rel_obj.collector_id = context.collector_id
            rel_obj.correlation_id = context.correlation_id
            canonical_objects.append(rel_obj)

        # 4. Hash ↔ Malware Correlation
        if resp.ioc_type.lower() in ("filehash", "hash", "md5", "sha256") and resp.is_threat:
            malware_name = resp.metadata.get("malware_family") or f"Malware-{resp.ioc_value[:8]}"
            mal_obj = MalwareObserved(
                malware_name=malware_name,
                malware_type="Malware Sample",
                hashes={resp.ioc_type.lower(): resp.ioc_value},
                provider=resp.provider_name,
                confidence=resp.confidence,
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
            )
            mal_obj.collector_id = context.collector_id
            mal_obj.correlation_id = context.correlation_id
            canonical_objects.append(mal_obj)

            rel_mal = RelationshipObserved(
                source_id=resp.ioc_value,
                source_type="FileHash",
                relationship_type="INDICATES",
                target_id=mal_obj.object_id,
                target_type="MalwareObserved",
                provider=resp.provider_name,
                confidence=resp.confidence,
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
            )
            rel_mal.collector_id = context.collector_id
            rel_mal.correlation_id = context.correlation_id
            canonical_objects.append(rel_mal)

        # 5. CVE ↔ Exploit Correlation
        cve_matches = self.CVE_REGEX.findall(str(resp.raw_data) + " " + resp.threat_name)
        for cve_id in set(cve_matches):
            exp_obj = ExploitObserved(
                exploit_id=f"EXPLOIT-{cve_id}",
                cve_id=cve_id,
                exploit_type="Vulnerability Exploit",
                provider=resp.provider_name,
                confidence=resp.confidence,
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
            )
            exp_obj.collector_id = context.collector_id
            exp_obj.correlation_id = context.correlation_id
            canonical_objects.append(exp_obj)

        # 6. Technique ↔ MITRE Mapping
        mitre_matches = self.MITRE_REGEX.findall(str(resp.raw_data) + " " + " ".join(resp.categories))
        for tech_id in set(mitre_matches):
            mitre_obj = MITREMappingObserved(
                technique_id=tech_id.upper(),
                technique_name=f"MITRE Technique {tech_id.upper()}",
                tactic="Threat Tactics",
                provider=resp.provider_name,
                confidence=resp.confidence,
                evidence_lineage=lineage,
                source_references=resp.references,
                investigation_correlation=investigation_id,
            )
            mitre_obj.collector_id = context.collector_id
            mitre_obj.correlation_id = context.correlation_id
            canonical_objects.append(mitre_obj)

        # 7. Threat Actor ↔ Campaign Linkage
        if resp.metadata and "adversaries" in resp.metadata:
            for actor in resp.metadata["adversaries"]:
                actor_obj = ThreatActorObserved(
                    actor_name=actor,
                    provider=resp.provider_name,
                    confidence=resp.confidence,
                    evidence_lineage=lineage,
                    source_references=resp.references,
                    investigation_correlation=investigation_id,
                )
                actor_obj.collector_id = context.collector_id
                actor_obj.correlation_id = context.correlation_id
                canonical_objects.append(actor_obj)

        return canonical_objects
