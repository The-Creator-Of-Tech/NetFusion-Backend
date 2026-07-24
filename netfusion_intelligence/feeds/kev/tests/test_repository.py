"""
Tests for CisaKevRepository persistence layer.
"""

from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.feeds.kev.repository import CisaKevRepository
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_repository_store_and_list():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    kev_repo = CisaKevRepository(repo)

    records = [
        KevRecord(cve_id="CVE-2021-44228", vendor_project="Apache", product="Log4j", due_date="2021-12-24"),
        KevRecord(cve_id="CVE-2023-23397", vendor_project="Microsoft", product="Outlook", due_date="2023-04-04"),
    ]

    res = kev_repo.store_kev_records("v1.0", records)
    assert res["inserted"] == 2

    listed = kev_repo.list_kev_records(version_id="v1.0")
    assert len(listed) == 2

    single = kev_repo.get_kev_record("CVE-2021-44228", version_id="v1.0")
    assert single is not None
    assert single["vendor_project"] == "Apache"

    vendors = kev_repo.list_kev_vendors("v1.0")
    assert "Apache" in vendors
    assert "Microsoft" in vendors

    products = kev_repo.list_kev_products("v1.0")
    assert "Log4j" in products
    assert "Outlook" in products
