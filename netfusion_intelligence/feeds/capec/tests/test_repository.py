"""
Tests for CapecRepository facade and the underlying SQLAlchemy persistence methods.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.capec.repository import CapecRepository
from netfusion_intelligence.feeds.capec.models import CapecEntity, CapecRelationship, CapecCweMapping
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def capec_repo(repo):
    return CapecRepository(repo)


@pytest.fixture
def version_id():
    return "capec-test-v001"


@pytest.fixture
def two_entities(sample_capec_entity, sample_capec_entity_86):
    return [sample_capec_entity, sample_capec_entity_86]


@pytest.fixture
def one_relationship():
    return CapecRelationship(
        source_capec_id="CAPEC-66",
        target_capec_id="CAPEC-248",
        nature="ChildOf",
        view_id="1000",
    )


@pytest.fixture
def one_cwe_mapping():
    return CapecCweMapping(capec_id="CAPEC-66", cwe_id="CWE-89", nature="Exploits")


def _activate_version(repo, version_id, feed_id="mitre_capec_xml"):
    dv = DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum="abc",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version="3.9",
        status=DatasetStatus.ACTIVE,
        validation_status=ValidationStatus.PASSED,
    )
    repo.save_dataset_version(dv)
    repo.set_active_dataset_version(feed_id, version_id)


# ---------------------------------------------------------------------------
# Store attack patterns
# ---------------------------------------------------------------------------

class TestCapecRepositoryStoreAttackPatterns:

    def test_store_returns_counts(self, capec_repo, version_id, two_entities):
        result = capec_repo.store_attack_patterns(version_id, two_entities)
        assert isinstance(result, dict)
        assert result["inserted"] == 2
        assert result["updated"] == 0

    def test_store_upsert_on_second_write(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        result2 = capec_repo.store_attack_patterns(version_id, two_entities)
        assert result2["updated"] == 2

    def test_store_empty_list(self, capec_repo, version_id):
        result = capec_repo.store_attack_patterns(version_id, [])
        assert result["inserted"] == 0


# ---------------------------------------------------------------------------
# Retrieve attack pattern
# ---------------------------------------------------------------------------

class TestCapecRepositoryGetAttackPattern:

    def test_get_existing_pattern_with_version(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        result = capec_repo.get_attack_pattern("CAPEC-66", version_id=version_id)
        assert result is not None
        assert result["capec_id"] == "CAPEC-66"

    def test_get_existing_pattern_via_active_version(self, capec_repo, repo, version_id, two_entities):
        _activate_version(repo, version_id)
        capec_repo.store_attack_patterns(version_id, two_entities)
        result = capec_repo.get_attack_pattern("CAPEC-66")
        assert result is not None
        assert result["capec_id"] == "CAPEC-66"

    def test_get_nonexistent_returns_none(self, capec_repo, version_id):
        result = capec_repo.get_attack_pattern("CAPEC-9999")
        assert result is None

    def test_get_pattern_fields_present(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        result = capec_repo.get_attack_pattern("CAPEC-66", version_id=version_id)
        assert "name" in result
        assert "description" in result
        assert "execution_flow" in result
        assert "mitigations" in result
        assert "detection" in result
        assert "related_weaknesses" in result
        assert "attack_technique_ids" in result


# ---------------------------------------------------------------------------
# List attack patterns
# ---------------------------------------------------------------------------

class TestCapecRepositoryListAttackPatterns:

    def test_list_returns_all(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.list_attack_patterns(version_id=version_id)
        assert len(results) == 2

    def test_list_filter_by_abstraction(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.list_attack_patterns(abstraction="Standard", version_id=version_id)
        assert len(results) == 1
        assert results[0]["capec_id"] == "CAPEC-66"

    def test_list_filter_by_status(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.list_attack_patterns(status="Draft", version_id=version_id)
        assert len(results) == 1
        assert results[0]["capec_id"] == "CAPEC-86"

    def test_list_filter_by_severity(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.list_attack_patterns(severity="High", version_id=version_id)
        assert len(results) == 1
        assert results[0]["capec_id"] == "CAPEC-66"

    def test_list_with_offset_and_limit(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.list_attack_patterns(version_id=version_id, limit=1, offset=0)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

class TestCapecRepositorySearch:

    def test_search_by_keyword(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.search(query="SQL", version_id=version_id)
        assert any(r["capec_id"] == "CAPEC-66" for r in results)

    def test_search_by_capec_id(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.search(capec_id="CAPEC-66", version_id=version_id)
        assert len(results) == 1
        assert results[0]["capec_id"] == "CAPEC-66"

    def test_search_by_cwe_id(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.search(cwe_id="CWE-89", version_id=version_id)
        assert any(r["capec_id"] == "CAPEC-66" for r in results)

    def test_search_by_attack_technique_id(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        # CAPEC-66 has T1190 mapped via taxonomy
        results = capec_repo.search(attack_technique_id="T1190", version_id=version_id)
        assert any(r["capec_id"] == "CAPEC-66" for r in results)

    def test_search_no_results(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        results = capec_repo.search(query="ZZZNONEXISTENT", version_id=version_id)
        assert results == []


# ---------------------------------------------------------------------------
# CWE-cross reference queries
# ---------------------------------------------------------------------------

class TestCapecRepositoryByCwe:

    def test_get_by_cwe(self, capec_repo, version_id, two_entities, one_cwe_mapping):
        capec_repo.store_attack_patterns(version_id, two_entities)
        capec_repo.store_cwe_mappings(version_id, [one_cwe_mapping])
        results = capec_repo.get_by_cwe("CWE-89", version_id=version_id)
        assert any(r["capec_id"] == "CAPEC-66" for r in results)

    def test_get_by_cwe_no_mapping_returns_empty(self, capec_repo, version_id):
        results = capec_repo.get_by_cwe("CWE-9999", version_id=version_id)
        assert results == []


# ---------------------------------------------------------------------------
# ATT&CK technique cross-reference queries
# ---------------------------------------------------------------------------

class TestCapecRepositoryByAttackTechnique:

    def test_get_by_attack_technique(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        # T1190 should have been stored automatically when CAPEC-66 was stored
        results = capec_repo.get_by_attack_technique("T1190", version_id=version_id)
        assert any(r["capec_id"] == "CAPEC-66" for r in results)

    def test_get_by_unknown_technique_returns_empty(self, capec_repo, version_id):
        results = capec_repo.get_by_attack_technique("T9999", version_id=version_id)
        assert results == []


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

class TestCapecRepositoryRelationships:

    def test_store_relationships_returns_count(self, capec_repo, version_id, one_relationship):
        count = capec_repo.store_relationships(version_id, [one_relationship])
        assert count == 1

    def test_store_relationships_idempotent(self, capec_repo, version_id, one_relationship):
        capec_repo.store_relationships(version_id, [one_relationship])
        count2 = capec_repo.store_relationships(version_id, [one_relationship])
        assert count2 == 0

    def test_get_relationships_for_capec(self, capec_repo, version_id, one_relationship):
        capec_repo.store_relationships(version_id, [one_relationship])
        rels = capec_repo.get_relationships(capec_id="CAPEC-66", version_id=version_id)
        assert len(rels) == 1
        assert rels[0]["source_capec_id"] == "CAPEC-66"
        assert rels[0]["target_capec_id"] == "CAPEC-248"
        assert rels[0]["nature"] == "ChildOf"

    def test_get_relationships_empty_when_none_stored(self, capec_repo):
        rels = capec_repo.get_relationships(capec_id="CAPEC-9999")
        assert rels == []


# ---------------------------------------------------------------------------
# CWE Mappings
# ---------------------------------------------------------------------------

class TestCapecRepositoryCweMappings:

    def test_store_cwe_mappings_returns_count(self, capec_repo, version_id, one_cwe_mapping):
        count = capec_repo.store_cwe_mappings(version_id, [one_cwe_mapping])
        assert count == 1

    def test_store_cwe_mappings_idempotent(self, capec_repo, version_id, one_cwe_mapping):
        capec_repo.store_cwe_mappings(version_id, [one_cwe_mapping])
        count2 = capec_repo.store_cwe_mappings(version_id, [one_cwe_mapping])
        assert count2 == 0


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestCapecRepositoryStatistics:

    def test_statistics_returns_dict(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        stats = capec_repo.get_statistics(version_id=version_id)
        assert isinstance(stats, dict)

    def test_statistics_total_attack_patterns(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        stats = capec_repo.get_statistics(version_id=version_id)
        assert stats["total_attack_patterns"] == 2

    def test_statistics_total_cwe_mappings(self, capec_repo, version_id, two_entities, one_cwe_mapping):
        capec_repo.store_attack_patterns(version_id, two_entities)
        capec_repo.store_cwe_mappings(version_id, [one_cwe_mapping])
        stats = capec_repo.get_statistics(version_id=version_id)
        assert stats["total_cwe_mappings"] >= 1

    def test_statistics_total_attack_mappings(self, capec_repo, version_id, two_entities):
        capec_repo.store_attack_patterns(version_id, two_entities)
        stats = capec_repo.get_statistics(version_id=version_id)
        # T1190 should have been auto-stored for CAPEC-66
        assert stats["total_attack_mappings"] >= 1


# ---------------------------------------------------------------------------
# Active version
# ---------------------------------------------------------------------------

class TestCapecRepositoryActiveVersion:

    def test_get_active_version_returns_none_when_no_version(self, capec_repo):
        result = capec_repo.get_active_version()
        assert result is None
