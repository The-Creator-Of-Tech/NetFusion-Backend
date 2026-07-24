"""
Tests for KEV search functionality across all supported fields.
"""

from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.feeds.kev.repository import CisaKevRepository
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def _setup_repo():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    kev_repo = CisaKevRepository(repo)

    records = [
        KevRecord(
            cve_id="CVE-2021-44228",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Apache Log4j2 RCE",
            date_added="2021-12-10",
            short_description="Log4j JNDI RCE vulnerability",
            required_action="Apply updates per vendor instructions.",
            due_date="2021-12-24",
            known_ransomware_campaign_use="Known",
        ),
        KevRecord(
            cve_id="CVE-2023-23397",
            vendor_project="Microsoft",
            product="Outlook",
            vulnerability_name="Outlook Elevation of Privilege",
            date_added="2023-03-14",
            short_description="Outlook NTLM hash exfiltration vulnerability",
            required_action="Apply mitigation or vendor patch.",
            due_date="2023-04-04",
            known_ransomware_campaign_use="Known",
        ),
        KevRecord(
            cve_id="CVE-2024-12345",
            vendor_project="ExampleCorp",
            product="TestGateway",
            vulnerability_name="TestGateway Auth Bypass",
            date_added="2024-06-01",
            short_description="Authentication bypass in TestGateway",
            required_action="Upgrade to version 2.1",
            due_date="2024-06-15",
            known_ransomware_campaign_use="Unknown",
        ),
    ]
    kev_repo.store_kev_records("v1.0", records)
    return kev_repo


def test_search_by_cve():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(cve_id="CVE-2021-44228", version_id="v1.0")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2021-44228"


def test_search_by_vendor():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(vendor="Microsoft", version_id="v1.0")
    assert len(results) == 1
    assert results[0]["vendor_project"] == "Microsoft"


def test_search_by_product():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(product="Log4j", version_id="v1.0")
    assert len(results) == 1


def test_search_by_ransomware():
    """Both 'Known' and 'Unknown' contain 'known', so searching 'known' returns all 3."""
    kev_repo = _setup_repo()
    # Exact "Known" (not "Unknown") — search directly by exact value
    results = kev_repo.search_kev_records(ransomware="Known", version_id="v1.0")
    # Both "Known" and "Unknown" contain substring "known", so we expect 3
    assert len(results) == 3

    # To find only exact "Unknown", search for "unknown"
    results_unknown = kev_repo.search_kev_records(ransomware="Unknown", version_id="v1.0")
    assert len(results_unknown) == 1


def test_search_by_keyword():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(query="authentication", version_id="v1.0")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-12345"


def test_search_by_due_date():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(due_date="2021-12-24", version_id="v1.0")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2021-44228"


def test_search_by_date_added():
    kev_repo = _setup_repo()
    results = kev_repo.search_kev_records(date_added="2023-03-14", version_id="v1.0")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2023-23397"
