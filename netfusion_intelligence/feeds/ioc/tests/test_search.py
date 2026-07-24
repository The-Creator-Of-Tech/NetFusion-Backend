"""Tests for IL-7 IOC Search — all search dimensions."""

import uuid
import pytest
from netfusion_intelligence.feeds.ioc.repository import IocRepository
from netfusion_intelligence.feeds.ioc.models import IocEntity
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


VID = "search-v-001"


def _ent(**kwargs) -> IocEntity:
    defaults = dict(
        ioc_id=str(uuid.uuid4()), ioc_type="ipv4", value="1.2.3.4",
        confidence=0.7, severity="medium", source_count=1,
    )
    defaults.update(kwargs)
    return IocEntity(**defaults)


@pytest.fixture
def populated_repo():
    raw = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    repo = IocRepository(raw)
    entities = [
        _ent(ioc_type="ipv4", value="10.0.0.1", confidence=0.9, severity="critical",
             malware_families=("Emotet",), campaigns=("PhishWave",),
             threat_actors=("Lazarus",), attack_technique_ids=("T1059",),
             capec_ids=("CAPEC-66",), cwe_ids=("CWE-79",), cve_ids=("CVE-2021-44228",),
             provider="misp", provider_id="p1"),
        _ent(ioc_type="domain", value="evil-c2.com", confidence=0.8, severity="high",
             malware_families=("TrickBot",), provider="opencti"),
        _ent(ioc_type="sha256", value="a" * 64, confidence=0.95, severity="critical",
             malware_families=("AgentTesla",)),
        _ent(ioc_type="url", value="https://phish.example.com/login", confidence=0.6),
        _ent(ioc_type="email", value="attacker@spam.net", confidence=0.5),
        _ent(ioc_type="md5", value="b" * 32, confidence=0.4, severity="low"),
    ]
    repo.store_indicators(VID, entities)
    return repo


class TestIocSearch:

    def test_search_by_ioc_type_ipv4(self, populated_repo):
        results = populated_repo.search(ioc_type="ipv4", version_id=VID)
        assert all(r["ioc_type"] == "ipv4" for r in results)
        assert len(results) == 1

    def test_search_by_ioc_type_domain(self, populated_repo):
        results = populated_repo.search(ioc_type="domain", version_id=VID)
        assert len(results) == 1

    def test_search_by_hash_type(self, populated_repo):
        results = populated_repo.search(ioc_type="sha256", version_id=VID)
        assert len(results) == 1

    def test_search_by_value_partial(self, populated_repo):
        results = populated_repo.search(value="evil-c2", version_id=VID)
        assert len(results) >= 1
        assert any("evil-c2" in r["value"] for r in results)

    def test_search_by_ip(self, populated_repo):
        results = populated_repo.search(ip="10.0.0.1", version_id=VID)
        assert len(results) >= 1

    def test_search_by_domain(self, populated_repo):
        results = populated_repo.search(domain="evil-c2", version_id=VID)
        assert len(results) >= 1

    def test_search_by_hash_value(self, populated_repo):
        results = populated_repo.search(hash_value="a" * 64, version_id=VID)
        assert len(results) >= 1

    def test_search_by_malware(self, populated_repo):
        results = populated_repo.search(malware="Emotet", version_id=VID)
        assert len(results) >= 1

    def test_search_by_campaign(self, populated_repo):
        results = populated_repo.search(campaign="PhishWave", version_id=VID)
        assert len(results) >= 1

    def test_search_by_threat_actor(self, populated_repo):
        results = populated_repo.search(threat_actor="Lazarus", version_id=VID)
        assert len(results) >= 1

    def test_search_by_attack_technique(self, populated_repo):
        results = populated_repo.search(attack_technique="T1059", version_id=VID)
        assert len(results) >= 1

    def test_search_by_capec_id(self, populated_repo):
        results = populated_repo.search(capec_id="CAPEC-66", version_id=VID)
        assert len(results) >= 1

    def test_search_by_cwe_id(self, populated_repo):
        results = populated_repo.search(cwe_id="CWE-79", version_id=VID)
        assert len(results) >= 1

    def test_search_by_cve_id(self, populated_repo):
        results = populated_repo.search(cve_id="CVE-2021-44228", version_id=VID)
        assert len(results) >= 1

    def test_search_by_provider(self, populated_repo):
        results = populated_repo.search(provider="misp", version_id=VID)
        assert all("misp" in (r.get("provider") or "") for r in results)

    def test_search_by_min_confidence(self, populated_repo):
        results = populated_repo.search(min_confidence=0.85, version_id=VID)
        assert all(float(r["confidence"]) >= 0.85 for r in results)

    def test_search_by_min_reputation(self, populated_repo):
        results = populated_repo.search(min_reputation=0.0, version_id=VID)
        assert len(results) == 6  # all

    def test_search_keyword_across_fields(self, populated_repo):
        results = populated_repo.search(query="Emotet", version_id=VID)
        assert len(results) >= 1

    def test_search_no_results_for_unknown(self, populated_repo):
        results = populated_repo.search(malware="Bogus_Malware_XYZ", version_id=VID)
        assert results == []

    def test_search_limit_respected(self, populated_repo):
        results = populated_repo.search(version_id=VID, limit=2)
        assert len(results) <= 2
