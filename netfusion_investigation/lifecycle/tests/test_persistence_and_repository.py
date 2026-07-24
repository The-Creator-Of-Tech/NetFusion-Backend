"""
Tests for IL-10 FilePersistence and InvestigationRepository.
"""

import os
import shutil
import tempfile
import pytest

from netfusion_investigation.lifecycle.models import Investigation, InvestigationLinks, Priority, Severity
from netfusion_investigation.lifecycle.persistence import FilePersistence
from netfusion_investigation.lifecycle.repository import InvestigationRepository


@pytest.fixture
def temp_storage():
    tmp_dir = tempfile.mkdtemp()
    yield tmp_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_file_persistence_save_load_delete(temp_storage):
    fp = FilePersistence(storage_dir=temp_storage)
    inv = Investigation(
        id="inv-p1",
        case_id="CASE-P1",
        title="Persistence Test",
        description="Testing file serialization",
    )
    path = fp.save(inv)
    assert os.path.exists(path)

    loaded = fp.load("inv-p1")
    assert loaded is not None
    assert loaded.case_id == "CASE-P1"

    all_invs = fp.list_all()
    assert len(all_invs) == 1

    deleted = fp.delete("inv-p1")
    assert deleted is True
    assert fp.load("inv-p1") is None


def test_repository_crud_and_search(temp_storage):
    fp = FilePersistence(storage_dir=temp_storage)
    repo = InvestigationRepository(persistence=fp)

    inv1 = Investigation(
        id="inv-1",
        case_id="CASE-101",
        title="Phishing Campaign Alpha",
        description="Targeting finance team",
        owner="bob",
        labels=["Phishing", "Finance"],
        links=InvestigationLinks(
            ioc_values=["1.2.3.4", "malicious.com"],
            cve_ids=["CVE-2026-100"],
            asset_ids=["srv-finance-01"],
            threat_actors=["APT29"],
        ),
    )

    inv2 = Investigation(
        id="inv-2",
        case_id="CASE-102",
        title="Ransomware Outbreak",
        description="Encrypted file shares",
        owner="alice",
        labels=["Ransomware", "Critical"],
        links=InvestigationLinks(
            ioc_values=["5.6.7.8"],
            malware_families=["LockBit"],
            campaigns=["OpRansom"],
            workflow_ids=["wf-quarantine"],
        ),
    )

    repo.add(inv1)
    repo.add(inv2)

    assert repo.get("inv-1").title == "Phishing Campaign Alpha"
    assert repo.get_by_case_id("CASE-102").id == "inv-2"

    # Multi-field Search tests
    res_ioc = repo.search(ioc="1.2.3.4")
    assert len(res_ioc) == 1 and res_ioc[0].id == "inv-1"

    res_cve = repo.search(cve="CVE-2026-100")
    assert len(res_cve) == 1 and res_cve[0].id == "inv-1"

    res_asset = repo.search(asset="srv-finance-01")
    assert len(res_asset) == 1 and res_asset[0].id == "inv-1"

    res_ta = repo.search(threat_actor="APT29")
    assert len(res_ta) == 1 and res_ta[0].id == "inv-1"

    res_malware = repo.search(malware="LockBit")
    assert len(res_malware) == 1 and res_malware[0].id == "inv-2"

    res_campaign = repo.search(campaign="OpRansom")
    assert len(res_campaign) == 1 and res_campaign[0].id == "inv-2"

    res_wf = repo.search(workflow="wf-quarantine")
    assert len(res_wf) == 1 and res_wf[0].id == "inv-2"

    res_analyst = repo.search(analyst="alice")
    assert len(res_analyst) == 1 and res_analyst[0].id == "inv-2"

    res_tags = repo.search(tags=["Phishing"])
    assert len(res_tags) == 1 and res_tags[0].id == "inv-1"

    repo.delete("inv-1")
    assert repo.get("inv-1") is None
