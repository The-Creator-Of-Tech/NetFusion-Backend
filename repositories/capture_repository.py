"""
Capture Repository — persistence for PcapInvestigation records.

Responsibilities:
  - Save / load PCAP investigation records (in-memory + Prisma API)
  - No business logic; database access only.

Dependency chain: main.py → services → capture_repository → Prisma API
"""

import requests

from core.config import PRISMA_API_BASE_URL, PRISMA_REQUEST_TIMEOUT

# ---------------------------------------------------------------------------
# In-memory store  (projectId -> list[investigation dict])
# ---------------------------------------------------------------------------
_pcap_investigations: dict = {}


# ---------------------------------------------------------------------------
# In-memory operations
# ---------------------------------------------------------------------------

def save_investigation(project_id: str, inv: dict):
    """
    Append a PcapInvestigation record to the in-memory store.
    Returns the record on success, None on invalid input.
    """
    if not project_id or not inv:
        return None
    if project_id not in _pcap_investigations:
        _pcap_investigations[project_id] = []
    _pcap_investigations[project_id].append(inv)
    return inv


def get_latest_investigation(project_id: str):
    """
    Return the most recently saved PcapInvestigation for a project, or None.
    Records are stored in append order; the last entry is the latest.
    """
    lst = _pcap_investigations.get(project_id) or []
    return lst[-1] if lst else None


# ---------------------------------------------------------------------------
# Prisma API operations
# ---------------------------------------------------------------------------

def persist_investigation_to_prisma(project_id: str, inv: dict):
    """
    POST a PcapInvestigation record to the Prisma-backed Node API.
    Returns the created record dict on success, None on failure.
    """
    if not project_id or not inv:
        return None

    url = f"{PRISMA_API_BASE_URL}/api/projects/{project_id}/pcaps"
    payload = {
        "filename":            inv.get("filename"),
        "summary":             inv.get("summary"),
        "findings":            inv.get("findings"),
        "alerts":              inv.get("alerts"),
        "iocs":                inv.get("iocs"),
        "timeline":            inv.get("timeline"),
        "mitre":               inv.get("mitre"),
        "riskRanking":         inv.get("riskRanking"),
        "correlations":        inv.get("correlations"),
        "trafficIntelligence": inv.get("trafficIntelligence"),
        "attackStory":         inv.get("attackStory"),
        "investigationPlan":   inv.get("investigationPlan"),
        "executiveReport":     inv.get("executiveReport"),
        "assets":              inv.get("assets"),
    }

    print(f"=== DEBUG: Calling PRISMA POST {url} for project={project_id} ===")
    try:
        print("=== DEBUG: Payload keys:", list(payload.keys()))
        response = requests.post(url, json=payload, timeout=PRISMA_REQUEST_TIMEOUT)
        print(f"=== DEBUG: PRISMA POST response status={response.status_code} ===")
        print("=== DEBUG: PRISMA POST response body ===")
        print(response.text)

        if response.status_code != 200:
            print(
                f"=== PRISMA PCAP SAVE FAILED "
                f"status={response.status_code} body={response.text} ==="
            )
            return None
        print("=== PRISMA PCAP INVESTIGATION SAVED SUCCESSFULLY ===")
        return response.json()
    except Exception as e:
        print(f"=== PRISMA PCAP SAVE EXCEPTION: {str(e)} ===")
        return None
