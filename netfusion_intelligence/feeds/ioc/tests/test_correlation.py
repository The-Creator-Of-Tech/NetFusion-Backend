"""Tests for IL-7 IocCorrelationEngine."""

import uuid
import pytest
from netfusion_intelligence.feeds.ioc.correlation import IocCorrelationEngine
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocType


def make_entity(**kwargs) -> IocEntity:
    defaults = dict(
        ioc_id=str(uuid.uuid4()), ioc_type="ipv4", value="1.2.3.4",
        confidence=0.8, provider="test",
    )
    defaults.update(kwargs)
    return IocEntity(**defaults)


class TestIocCorrelationEngine:

    def setup_method(self):
        self.engine = IocCorrelationEngine()

    def test_no_entities_no_relationships(self):
        rels = self.engine.build_relationships({})
        assert rels == []

    def test_ioc_to_attack_technique(self):
        ent = make_entity(attack_technique_ids=("T1059",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "T1059" and r.relationship_type == "ioc_to_attack_technique"
                   for r in rels)

    def test_ioc_to_capec(self):
        ent = make_entity(capec_ids=("CAPEC-66",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "CAPEC-66" and r.relationship_type == "ioc_to_capec"
                   for r in rels)

    def test_ioc_to_cwe(self):
        ent = make_entity(cwe_ids=("CWE-89",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "CWE-89" and r.relationship_type == "ioc_to_cwe"
                   for r in rels)

    def test_ioc_to_cve(self):
        ent = make_entity(cve_ids=("CVE-2021-44228",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "CVE-2021-44228" and r.relationship_type == "ioc_to_cve"
                   for r in rels)

    def test_ioc_to_malware(self):
        ent = make_entity(malware_families=("Emotet",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "Emotet" and r.relationship_type == "ioc_to_malware"
                   for r in rels)

    def test_ioc_to_campaign(self):
        ent = make_entity(campaigns=("PhishWave",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "PhishWave" and r.relationship_type == "ioc_to_campaign"
                   for r in rels)

    def test_ioc_to_threat_actor(self):
        ent = make_entity(threat_actors=("Lazarus",))
        rels = self.engine.build_relationships({"fp1": ent})
        assert any(r.target_id == "Lazarus" and r.relationship_type == "ioc_to_threat_actor"
                   for r in rels)

    def test_multiple_attributions(self):
        ent = make_entity(
            attack_technique_ids=("T1059", "T1071"),
            malware_families=("AgentTesla",),
            cve_ids=("CVE-2021-1234",),
        )
        rels = self.engine.build_relationships({"fp1": ent})
        rel_types = {r.relationship_type for r in rels}
        assert "ioc_to_attack_technique" in rel_types
        assert "ioc_to_malware" in rel_types
        assert "ioc_to_cve" in rel_types
        assert len(rels) == 4   # 2 attack + 1 malware + 1 cve

    def test_ioc_to_ioc_co_observed(self):
        """Two different IOCs from the same provider event should be co-related."""
        shared_prov_id = "evt-999"
        ip_ent = make_entity(
            ioc_id=str(uuid.uuid4()), ioc_type=IocType.IPV4.value,
            value="10.0.0.1", provider="misp", provider_id=shared_prov_id,
        )
        dom_ent = make_entity(
            ioc_id=str(uuid.uuid4()), ioc_type=IocType.DOMAIN.value,
            value="malicious.com", provider="misp", provider_id=shared_prov_id,
        )
        rels = self.engine.build_relationships({"fp1": ip_ent, "fp2": dom_ent})
        assert any(r.relationship_type == "ip_to_domain" for r in rels)

    def test_no_duplicate_relationships(self):
        """Same (source, target, type) must not produce duplicate entries."""
        ent = make_entity(attack_technique_ids=("T1059", "T1059"))  # repeated
        rels = self.engine.build_relationships({"fp1": ent})
        attack_rels = [r for r in rels if r.relationship_type == "ioc_to_attack_technique"]
        assert len(attack_rels) == 1

    def test_relationship_has_confidence(self):
        ent = make_entity(confidence=0.75, malware_families=("TrickBot",))
        rels = self.engine.build_relationships({"fp1": ent})
        malware_rel = next(r for r in rels if r.relationship_type == "ioc_to_malware")
        assert malware_rel.confidence == 0.75
