"""
Tests for incremental updates and dataset rollback — CWE and CAPEC pipelines.
Verifies version management, dataset switching, and rollback behavior.
"""

import datetime
import pytest

from netfusion_intelligence.feeds.cwe.feed import CweFeed
from netfusion_intelligence.feeds.capec.feed import CapecFeed
from netfusion_intelligence.feeds.cwe.updater import CweUpdater
from netfusion_intelligence.feeds.capec.updater import CapecUpdater
from netfusion_intelligence.models.dataset import DatasetVersion, DatasetStatus, ValidationStatus
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML


# ---------------------------------------------------------------------------
# Modified datasets for v2 (add one weakness/pattern)
# ---------------------------------------------------------------------------

CWE_XML_V2 = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.16" Date="2024-09-01">
  <Weaknesses>
    <Weakness ID="79" Name="XSS" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>Cross-site scripting.</Description>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>SQL injection.</Description>
    </Weakness>
    <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class" Structure="Simple" Status="Stable">
      <Description>Input validation weakness.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

CAPEC_XML_V2 = b"""<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Name="CAPEC" Version="3.10" Date="2024-09-01">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Stable"
                    Likelihood_Of_Attack="High" Typical_Severity="High">
      <Description>SQL injection attack pattern.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="86" Name="XSS via HTTP Query Strings" Abstraction="Detailed" Status="Draft"
                    Likelihood_Of_Attack="High" Typical_Severity="Medium">
      <Description>XSS pattern.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Blind SQL Injection" Abstraction="Detailed" Status="Stable"
                    Likelihood_Of_Attack="Medium" Typical_Severity="High">
      <Description>Blind SQL injection variant.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def _make_version(feed_id, version_id, source_version="1.0", status=DatasetStatus.CREATED):
    return DatasetVersion(
        feed_id=feed_id,
        version_id=version_id,
        checksum=f"checksum-{version_id}",
        imported_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_version=source_version,
        status=status,
        validation_status=ValidationStatus.PASSED,
    )


def _run_feed(repo, feed_class, xml_data, feed_id, version_id, source_version="1.0"):
    dv = _make_version(feed_id, version_id, source_version)
    repo.save_dataset_version(dv)
    feed = feed_class(repository=repo, offline_data=xml_data)
    raw = feed.fetch_raw_data()
    parsed = feed.parse(raw)
    normalized = feed.normalize(parsed)
    feed.store(dv, normalized)
    feed.build_relationships(dv)
    feed.on_activate(dv)
    return dv


@pytest.fixture
def repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


# ---------------------------------------------------------------------------
# CWE incremental updates
# ---------------------------------------------------------------------------

class TestCweIncrementalUpdate:

    def test_v1_then_v2_active_version_changes(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active.version_id == "cwe-v002"

    def test_v2_has_more_weaknesses(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        stats_v1 = repo.get_cwe_statistics_for_version("cwe-v001")
        stats_v2 = repo.get_cwe_statistics_for_version("cwe-v002")
        assert stats_v2["total_weaknesses"] > stats_v1["total_weaknesses"]

    def test_both_versions_independently_queryable(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        # CWE-79 exists in both versions
        v1_w = repo.get_cwe_weakness("CWE-79", version_id="cwe-v001")
        v2_w = repo.get_cwe_weakness("CWE-79", version_id="cwe-v002")
        assert v1_w is not None
        assert v2_w is not None

    def test_new_weakness_only_in_v2(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        # CWE-20 only in v2
        v1_w = repo.get_cwe_weakness("CWE-20", version_id="cwe-v001")
        v2_w = repo.get_cwe_weakness("CWE-20", version_id="cwe-v002")
        assert v1_w is None
        assert v2_w is not None

    def test_dataset_versions_list_shows_both(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        versions = repo.list_dataset_versions("mitre_cwe_xml")
        version_ids = [v.version_id for v in versions]
        assert "cwe-v001" in version_ids
        assert "cwe-v002" in version_ids


# ---------------------------------------------------------------------------
# CWE rollback
# ---------------------------------------------------------------------------

class TestCweRollback:

    def test_rollback_reverts_active_version(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        updater = CweUpdater(repo)
        updater.rollback_dataset(target_version_id="cwe-v001")

        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active.version_id == "cwe-v001"

    def test_after_rollback_data_from_v1_is_active(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        _run_feed(repo, CweFeed, CWE_XML_V2, "mitre_cwe_xml", "cwe-v002", "4.16")

        updater = CweUpdater(repo)
        updater.rollback_dataset(target_version_id="cwe-v001")

        # Active version should now point to v1 data
        active = repo.get_active_dataset_version("mitre_cwe_xml")
        assert active.version_id == "cwe-v001"
        # CWE-20 (only in v2) should not be found when querying active version
        stats = repo.get_cwe_statistics_for_version("cwe-v001")
        assert stats["total_weaknesses"] == 2  # Only v1 has 2

    def test_rollback_to_nonexistent_version_raises(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        updater = CweUpdater(repo)
        with pytest.raises(ValueError):
            updater.rollback_dataset(target_version_id="nonexistent-version")

    def test_checksum_comparison_detects_unchanged_data(self, repo):
        _run_feed(repo, CweFeed, MINIMAL_CWE_XML, "mitre_cwe_xml", "cwe-v001", "4.15")
        updater = CweUpdater(repo)

        # Compute the checksum of the v1 data
        import hashlib
        checksum_v1 = hashlib.sha256(MINIMAL_CWE_XML).hexdigest()
        # Manually set it
        active = repo.get_active_dataset_version("mitre_cwe_xml")
        # Force the checksum into the version record
        from netfusion_intelligence.models.dataset import DatasetStatus, ValidationStatus
        dv = DatasetVersion(
            feed_id="mitre_cwe_xml",
            version_id=active.version_id,
            checksum=checksum_v1,
            imported_at=active.imported_at,
            source_version=active.source_version,
            status=active.status,
            validation_status=active.validation_status,
        )
        repo.save_dataset_version(dv)
        result = updater.compare_versions(checksum_v1)
        assert result["update_required"] is False


# ---------------------------------------------------------------------------
# CAPEC incremental updates
# ---------------------------------------------------------------------------

class TestCapecIncrementalUpdate:

    def test_v1_then_v2_active_version_changes(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == "capec-v002"

    def test_v2_has_more_patterns(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        stats_v1 = repo.get_capec_statistics_for_version("capec-v001")
        stats_v2 = repo.get_capec_statistics_for_version("capec-v002")
        assert stats_v2["total_attack_patterns"] > stats_v1["total_attack_patterns"]

    def test_new_pattern_only_in_v2(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        v1_p = repo.get_capec_attack_pattern("CAPEC-7", version_id="capec-v001")
        v2_p = repo.get_capec_attack_pattern("CAPEC-7", version_id="capec-v002")
        assert v1_p is None
        assert v2_p is not None

    def test_both_versions_independently_queryable(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        v1_p = repo.get_capec_attack_pattern("CAPEC-66", version_id="capec-v001")
        v2_p = repo.get_capec_attack_pattern("CAPEC-66", version_id="capec-v002")
        assert v1_p is not None
        assert v2_p is not None


# ---------------------------------------------------------------------------
# CAPEC rollback
# ---------------------------------------------------------------------------

class TestCapecRollback:

    def test_rollback_reverts_active_version(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        updater = CapecUpdater(repo)
        updater.rollback_dataset(target_version_id="capec-v001")

        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == "capec-v001"

    def test_after_rollback_v2_only_data_not_in_active(self, repo):
        _run_feed(repo, CapecFeed, MINIMAL_CAPEC_XML, "mitre_capec_xml", "capec-v001", "3.9")
        _run_feed(repo, CapecFeed, CAPEC_XML_V2, "mitre_capec_xml", "capec-v002", "3.10")

        updater = CapecUpdater(repo)
        updater.rollback_dataset(target_version_id="capec-v001")

        # After rollback, CAPEC-7 (v2 only) should not be in active version
        active = repo.get_active_dataset_version("mitre_capec_xml")
        assert active.version_id == "capec-v001"
        stats = repo.get_capec_statistics_for_version("capec-v001")
        assert stats["total_attack_patterns"] == 2  # v1 only has 2
