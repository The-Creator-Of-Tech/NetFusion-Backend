"""Tests for IL-7 IocRepository — storage, retrieval, search, sightings, reputation."""

import uuid
import pytest
from netfusion_intelligence.feeds.ioc.repository import IocRepository
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocReputation, IocSighting, IocRelationship
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


VERSION_ID = "test-version-001"


def make_entity(ioc_type="ipv4", value="1.2.3.4", confidence=0.8, severity="high",
                malware_families=(), provider="misp", attack_ids=()):
    return IocEntity(
        ioc_id=str(uuid.uuid4()),
        ioc_type=ioc_type,
        value=value,
        value_raw=value,
        confidence=confidence,
        severity=severity,
        malware_families=tuple(malware_families),
        attack_technique_ids=tuple(attack_ids),
        provider=provider,
        source_count=1,
    )


@pytest.fixture
def repo():
    raw = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    return IocRepository(raw)


@pytest.fixture
def stored_entity(repo):
    ent = make_entity()
    repo.store_indicators(VERSION_ID, [ent])
    return ent


class TestIocRepository:

    def test_store_and_retrieve_indicator(self, repo):
        ent = make_entity(ioc_type="domain", value="evil.com")
        repo.store_indicators(VERSION_ID, [ent])
        result = repo.get_indicator(ent.ioc_id, version_id=VERSION_ID)
        assert result is not None
        assert result["value"] == "evil.com"
        assert result["ioc_type"] == "domain"

    def test_store_returns_counts(self, repo):
        entities = [make_entity() for _ in range(5)]
        res = repo.store_indicators(VERSION_ID, entities)
        assert res["inserted"] == 5
        assert res["updated"] == 0

    def test_upsert_updates_existing(self, repo):
        ent = make_entity(value="10.0.0.1")
        repo.store_indicators(VERSION_ID, [ent])
        # Store again — should update
        res = repo.store_indicators(VERSION_ID, [ent])
        assert res["duplicates"] >= 1

    def test_list_indicators_by_type(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(ioc_type="ipv4", value="5.5.5.5"),
            make_entity(ioc_type="domain", value="bad.com"),
        ])
        ips = repo.list_indicators(ioc_type="ipv4", version_id=VERSION_ID)
        assert all(i["ioc_type"] == "ipv4" for i in ips)
        assert len(ips) == 1

    def test_list_indicators_by_severity(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(severity="critical", value="1.1.1.1"),
            make_entity(severity="low", value="2.2.2.2"),
        ])
        crits = repo.list_indicators(severity="critical", version_id=VERSION_ID)
        assert all(i["severity"] == "critical" for i in crits)

    def test_list_indicators_min_confidence(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(confidence=0.9, value="3.3.3.3"),
            make_entity(confidence=0.3, value="4.4.4.4"),
        ])
        high = repo.list_indicators(min_confidence=0.8, version_id=VERSION_ID)
        assert all(float(i["confidence"]) >= 0.8 for i in high)

    def test_search_by_value(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(value="malicious-host.com", ioc_type="domain"),
        ])
        results = repo.search(value="malicious", version_id=VERSION_ID)
        assert len(results) >= 1

    def test_search_by_malware(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(malware_families=("Emotet",), value="6.6.6.6"),
        ])
        results = repo.search(malware="Emotet", version_id=VERSION_ID)
        assert len(results) >= 1

    def test_search_by_attack_technique(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(attack_ids=("T1059",), value="7.7.7.7"),
        ])
        results = repo.search(attack_technique="T1059", version_id=VERSION_ID)
        assert len(results) >= 1

    def test_get_nonexistent_returns_none(self, repo):
        result = repo.get_indicator("nonexistent-id", version_id=VERSION_ID)
        assert result is None

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def test_store_and_retrieve_relationship(self, repo, stored_entity):
        rel = IocRelationship.create(
            source_ioc_id=stored_entity.ioc_id,
            target_id="T1059",
            target_type="attack_technique",
            relationship_type="ioc_to_attack_technique",
            confidence=0.9,
        )
        count = repo.store_relationships(VERSION_ID, [rel])
        assert count == 1

        rels = repo.get_relationships(stored_entity.ioc_id, version_id=VERSION_ID)
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "ioc_to_attack_technique"

    def test_duplicate_relationship_not_stored(self, repo, stored_entity):
        rel = IocRelationship.create(
            source_ioc_id=stored_entity.ioc_id,
            target_id="T1059",
            target_type="attack_technique",
            relationship_type="ioc_to_attack_technique",
        )
        repo.store_relationships(VERSION_ID, [rel])
        count2 = repo.store_relationships(VERSION_ID, [rel])
        assert count2 == 0  # already exists, not duplicated

    # ------------------------------------------------------------------
    # Reputation
    # ------------------------------------------------------------------

    def test_store_and_retrieve_reputation(self, repo, stored_entity):
        rep = IocReputation(
            ioc_id=stored_entity.ioc_id,
            reputation_score=7.5,
            false_positive_score=0.1,
            confidence=0.85,
            severity="high",
            priority=2,
            source_count=3,
        )
        repo.store_reputations(VERSION_ID, [rep])
        retrieved = repo.get_reputation(stored_entity.ioc_id, version_id=VERSION_ID)
        assert retrieved is not None
        assert retrieved["reputation_score"] == 7.5

    def test_get_reputation_nonexistent_returns_none(self, repo):
        assert repo.get_reputation("no-such-ioc", version_id=VERSION_ID) is None

    # ------------------------------------------------------------------
    # Sightings
    # ------------------------------------------------------------------

    def test_store_and_retrieve_sightings(self, repo, stored_entity):
        sight = IocSighting.create(
            ioc_id=stored_entity.ioc_id,
            observed_at="2024-06-01T12:00:00Z",
            observation_source="SIEM",
            organization="Acme Corp",
            count=3,
        )
        count = repo.store_sightings(VERSION_ID, [sight])
        assert count == 1
        sightings = repo.get_sightings(stored_entity.ioc_id, version_id=VERSION_ID)
        assert len(sightings) == 1
        assert sightings[0]["observation_source"] == "SIEM"
        assert sightings[0]["count"] == 3

    def test_no_duplicate_sightings(self, repo, stored_entity):
        sight = IocSighting.create(
            ioc_id=stored_entity.ioc_id,
            observed_at="2024-01-01T00:00:00Z",
            observation_source="EDR",
        )
        repo.store_sightings(VERSION_ID, [sight])
        count2 = repo.store_sightings(VERSION_ID, [sight])
        assert count2 == 0

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def test_statistics_returns_counts(self, repo):
        repo.store_indicators(VERSION_ID, [
            make_entity(ioc_type="ipv4", value="1.1.1.1", severity="critical", confidence=0.9),
            make_entity(ioc_type="domain", value="a.com", severity="high", confidence=0.7),
            make_entity(ioc_type="sha256", value="a" * 64, severity="medium", confidence=0.5),
        ])
        stats = repo.get_statistics(version_id=VERSION_ID)
        assert stats["total_indicators"] == 3
        assert "ipv4" in stats["by_type"]
        assert "critical" in stats["by_severity"]

    def test_statistics_empty_version_returns_zero(self, repo):
        stats = repo.get_statistics(version_id="nonexistent-version")
        assert stats.get("total_indicators", 0) == 0

    def test_active_version_none_when_not_set(self, repo):
        assert repo.get_active_version() is None
