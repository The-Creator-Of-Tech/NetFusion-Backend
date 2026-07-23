"""
Tests for CweRepository facade and the underlying SQLAlchemy persistence methods.
"""

import pytest

from netfusion_intelligence.feeds.cwe.repository import CweRepository
from netfusion_intelligence.feeds.cwe.models import CweEntity, CweRelationship
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo() -> SQLAlchemyIntelligenceRepository:
    """In-memory SQLite repository, schema auto-created."""
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture
def cwe_repo(repo) -> CweRepository:
    return CweRepository(repo)


@pytest.fixture
def version_id() -> str:
    return "cwe-test-v001"


@pytest.fixture
def two_entities(sample_cwe_entity, sample_cwe_entity_89):
    return [sample_cwe_entity, sample_cwe_entity_89]


@pytest.fixture
def one_relationship() -> CweRelationship:
    return CweRelationship(
        source_cwe_id="CWE-79",
        target_cwe_id="CWE-74",
        nature="ChildOf",
        view_id="1000",
        ordinal="Primary",
    )


# ---------------------------------------------------------------------------
# Store weaknesses
# ---------------------------------------------------------------------------

class TestCweRepositoryStoreWeaknesses:

    def test_store_returns_counts(self, cwe_repo, version_id, two_entities):
        result = cwe_repo.store_weaknesses(version_id, two_entities)
        assert isinstance(result, dict)
        assert result["inserted"] == 2
        assert result["updated"] == 0

    def test_store_upsert_on_second_write(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        result2 = cwe_repo.store_weaknesses(version_id, two_entities)
        assert result2["updated"] == 2

    def test_store_empty_list(self, cwe_repo, version_id):
        result = cwe_repo.store_weaknesses(version_id, [])
        assert result["inserted"] == 0


# ---------------------------------------------------------------------------
# Retrieve weakness
# ---------------------------------------------------------------------------

class TestCweRepositoryGetWeakness:

    def test_get_existing_weakness(self, cwe_repo, repo, version_id, two_entities):
        from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
        import datetime, uuid
        # Register an active dataset version so the active version resolver works
        dv = DatasetVersion(
            feed_id="mitre_cwe_xml",
            version_id=version_id,
            checksum="abc",
            imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_version="4.15",
            status=DatasetStatus.ACTIVE,
            validation_status=ValidationStatus.PASSED,
        )
        repo.save_dataset_version(dv)
        repo.set_active_dataset_version("mitre_cwe_xml", version_id)
        cwe_repo.store_weaknesses(version_id, two_entities)

        result = cwe_repo.get_weakness("CWE-79")
        assert result is not None
        assert result["cwe_id"] == "CWE-79"

    def test_get_nonexistent_returns_none(self, cwe_repo, version_id):
        result = cwe_repo.get_weakness("CWE-9999")
        assert result is None

    def test_get_weakness_with_explicit_version_id(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        result = cwe_repo.get_weakness("CWE-89", version_id=version_id)
        assert result is not None
        assert result["cwe_id"] == "CWE-89"


# ---------------------------------------------------------------------------
# List weaknesses
# ---------------------------------------------------------------------------

class TestCweRepositoryListWeaknesses:

    def test_list_returns_all(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.list_weaknesses(version_id=version_id)
        assert len(results) == 2

    def test_list_filter_by_abstraction(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.list_weaknesses(abstraction="Base", version_id=version_id)
        assert len(results) == 2
        for r in results:
            assert r["abstraction"] == "Base"

    def test_list_filter_by_status(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.list_weaknesses(status="Stable", version_id=version_id)
        assert len(results) == 2

    def test_list_with_offset_and_limit(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.list_weaknesses(version_id=version_id, limit=1, offset=0)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

class TestCweRepositorySearch:

    def test_search_by_keyword(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.search(query="SQL", version_id=version_id)
        assert any(r["cwe_id"] == "CWE-89" for r in results)

    def test_search_by_cwe_id(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.search(cwe_id="CWE-79", version_id=version_id)
        assert len(results) == 1
        assert results[0]["cwe_id"] == "CWE-79"

    def test_search_by_abstraction(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.search(abstraction="Base", version_id=version_id)
        assert len(results) == 2

    def test_search_no_results(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        results = cwe_repo.search(query="ZZZNONEXISTENT", version_id=version_id)
        assert results == []


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

class TestCweRepositoryRelationships:

    def test_store_relationships_returns_count(self, cwe_repo, version_id, one_relationship):
        count = cwe_repo.store_relationships(version_id, [one_relationship])
        assert count == 1

    def test_store_relationships_idempotent(self, cwe_repo, version_id, one_relationship):
        cwe_repo.store_relationships(version_id, [one_relationship])
        count2 = cwe_repo.store_relationships(version_id, [one_relationship])
        # Duplicate should not be inserted
        assert count2 == 0

    def test_get_relationships_for_cwe(self, cwe_repo, version_id, one_relationship):
        cwe_repo.store_relationships(version_id, [one_relationship])
        rels = cwe_repo.get_relationships(cwe_id="CWE-79", version_id=version_id)
        assert len(rels) == 1
        assert rels[0]["source_cwe_id"] == "CWE-79"
        assert rels[0]["target_cwe_id"] == "CWE-74"
        assert rels[0]["nature"] == "ChildOf"

    def test_get_relationships_empty_when_none_stored(self, cwe_repo):
        rels = cwe_repo.get_relationships(cwe_id="CWE-9999")
        assert rels == []


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestCweRepositoryStatistics:

    def test_statistics_returns_dict(self, cwe_repo, version_id, two_entities, one_relationship):
        cwe_repo.store_weaknesses(version_id, two_entities)
        cwe_repo.store_relationships(version_id, [one_relationship])
        stats = cwe_repo.get_statistics(version_id=version_id)
        assert isinstance(stats, dict)

    def test_statistics_total_weaknesses(self, cwe_repo, version_id, two_entities):
        cwe_repo.store_weaknesses(version_id, two_entities)
        stats = cwe_repo.get_statistics(version_id=version_id)
        assert stats["total_weaknesses"] == 2

    def test_statistics_total_relationships(self, cwe_repo, version_id, two_entities, one_relationship):
        cwe_repo.store_weaknesses(version_id, two_entities)
        cwe_repo.store_relationships(version_id, [one_relationship])
        stats = cwe_repo.get_statistics(version_id=version_id)
        assert stats["total_relationships"] == 1


# ---------------------------------------------------------------------------
# Active version
# ---------------------------------------------------------------------------

class TestCweRepositoryActiveVersion:

    def test_get_active_version_returns_none_when_no_version(self, cwe_repo):
        result = cwe_repo.get_active_version()
        assert result is None
