"""
Tests for CAPEC relationship resolution — CAPEC↔CWE, CAPEC↔ATT&CK, CAPEC↔CAPEC graph traversal.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.capec.feed import CapecFeed
from netfusion_intelligence.feeds.cwe.feed import CweFeed
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


def _run_feed(repo, feed_class, xml_data, feed_id, version_id, source_version="1.0"):
    dv = DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum="test",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version=source_version,
        status=DatasetStatus.CREATED,
        validation_status=ValidationStatus.PASSED,
    )
    repo.save_dataset_version(dv)
    feed = feed_class(repository=repo, offline_data=xml_data)
    raw = feed.fetch_raw_data()
    parsed = feed.parse(raw)
    normalized = feed.normalize(parsed)
    feed.store(dv, normalized)
    feed.build_relationships(dv)
    feed.on_activate(dv)
    return dv


class TestCapecCweRelationshipResolution:

    def test_capec_linked_to_cwe_89(self, repo):
        """After storing CAPEC data, CWE-89 is linked to CAPEC-66 via capec_cwe table."""
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        capecs = repo.list_capec_by_cwe("CWE-89", version_id=dv.version_id)
        assert any(c["capec_id"] == "CAPEC-66" for c in capecs)

    def test_capec_linked_to_cwe_79(self, repo):
        """After storing CAPEC data, CWE-79 is linked to CAPEC-86."""
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        capecs = repo.list_capec_by_cwe("CWE-79", version_id=dv.version_id)
        assert any(c["capec_id"] == "CAPEC-86" for c in capecs)

    def test_no_capec_for_unknown_cwe(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        capecs = repo.list_capec_by_cwe("CWE-9999")
        assert capecs == []


class TestCapecAttackTechniqueResolution:

    def test_capec66_mapped_to_t1190(self, repo):
        """CAPEC-66 has ATT&CK taxonomy mapping to T1190 which is stored in capec_attack."""
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        capecs = repo.list_capec_by_attack_technique("T1190", version_id=dv.version_id)
        assert any(c["capec_id"] == "CAPEC-66" for c in capecs)

    def test_attack_technique_ids_in_pattern_dict(self, repo):
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        pattern = repo.get_capec_attack_pattern("CAPEC-66", version_id=dv.version_id)
        assert "T1190" in pattern["attack_technique_ids"]


class TestCapecCapecRelationships:

    def test_capec66_childof_248_relationship_stored(self, repo):
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        rels = repo.list_capec_relationships(capec_id="CAPEC-66", version_id=dv.version_id)
        assert any(r["target_capec_id"] == "CAPEC-248" and r["nature"] == "ChildOf" for r in rels)

    def test_relationship_count_nonzero(self, repo):
        dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        rels = repo.list_capec_relationships(version_id=dv.version_id)
        assert len(rels) >= 1


class TestCweCapecBidirectionalLookup:

    def test_cwe_references_capec_in_related_attack_patterns(self, repo):
        """CWE-79 references CAPEC-86 and CAPEC-198 in its related_attack_patterns field."""
        dv = _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        weakness = repo.get_cwe_weakness("CWE-79", version_id=dv.version_id)
        assert weakness is not None
        assert "CAPEC-86" in weakness["related_attack_patterns"]
        assert "CAPEC-198" in weakness["related_attack_patterns"]

    def test_cwe_and_capec_both_stored_independently(self, repo):
        """CWE and CAPEC pipelines can run independently without interfering."""
        cwe_dv = _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        capec_dv = _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")

        cwe = repo.get_cwe_weakness("CWE-79", version_id=cwe_dv.version_id)
        capec = repo.get_capec_attack_pattern("CAPEC-66", version_id=capec_dv.version_id)

        assert cwe is not None
        assert capec is not None
        assert cwe["cwe_id"] == "CWE-79"
        assert capec["capec_id"] == "CAPEC-66"
