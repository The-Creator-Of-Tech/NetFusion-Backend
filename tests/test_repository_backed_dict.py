from unittest.mock import patch

from api.persistence import RepositoryBackedDict, map_cve


def test_repository_backed_dict_reads_normalized_prisma_records():
    store = RepositoryBackedDict("cve", "cveId", map_cve)

    def fake_call_repository(repo_name, method_name, *args):
        assert repo_name == "cve"

        if method_name == "findMany":
            payload = args[0] if args else {}
            if isinstance(payload, dict) and payload.get("filter", {}).get("deletedAt") is None:
                return [{
                    "id": "db-cve-1",
                    "cveId": "CVE-2024-0001",
                    "severity": "CRITICAL",
                    "cvssScore": 9.8,
                }]
            if isinstance(payload, dict) and payload.get("filter", {}).get("cveId") == "CVE-2024-0001":
                return [{"id": "db-cve-1"}]
            if isinstance(payload, dict) and payload.get("filter", {}).get("metadata") is not None:
                return []
            return []

        if method_name == "findById":
            return {
                "id": "db-cve-1",
                "cveId": "CVE-2024-0001",
                "severity": "CRITICAL",
                "cvssScore": 9.8,
            }

        if method_name == "count":
            return 1

        if method_name == "exists":
            return True

        raise AssertionError(f"Unexpected repository call: {method_name}")

    with patch("api.persistence.call_repository", side_effect=fake_call_repository):
        values = store.values()
        items = store.items()
        keys = store.keys()
        record = store["CVE-2024-0001"]

    assert values[0]["cveId"] == "CVE-2024-0001"
    assert values[0]["severity"] == "CRITICAL"
    assert keys == ["CVE-2024-0001"]
    assert items[0][0] == "CVE-2024-0001"
    assert record["cveId"] == "CVE-2024-0001"
    assert record["cvssScore"] == 9.8


def test_repository_backed_dict_merges_metadata_and_preserves_relations():
    from api.persistence import map_playbook
    store = RepositoryBackedDict("playbook", "playbookId", map_playbook)

    def fake_call_repository(repo_name, method_name, *args):
        if method_name == "findById":
            return {
                "id": "playbook-123",
                "playbookId": "playbook-123",
                "name": "Original Name",
                "severity": "CRITICAL",
                "steps": [{"stepId": "step-1", "title": "Real Step"}],
                "executions": [{"executionId": "exec-1"}],
                "metadata": {
                    "name": "Metadata Name",
                    "severity": "HIGH",
                    "steps": [{"stepId": "stale-step", "title": "Stale Step"}]
                }
            }
        return None

    with patch("api.persistence.call_repository", side_effect=fake_call_repository):
        with patch("api.persistence.is_valid_uuid", return_value=True):
            record = store["playbook-123"]

    # Merged fields from metadata
    assert record["name"] == "Metadata Name"
    assert record["severity"] == "HIGH"
    # Preserved relational fields
    assert record["steps"] == [{"stepId": "step-1", "title": "Real Step"}]
    assert record["executions"] == [{"executionId": "exec-1"}]

