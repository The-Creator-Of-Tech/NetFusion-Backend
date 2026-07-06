"""
Session Repository — persistence for CaptureSession records.

Responsibilities:
  - In-memory session store (create / update / get / clear)
  - File-based session fallback (read / write / delete JSON files)
  - Prisma API session persistence (PUT / GET)
  - No business logic; database/storage access only.

Dependency chain: main.py → services → session_repository → Prisma API / filesystem
"""

import json
import os

import requests

from core.config import PRISMA_API_BASE_URL, PRISMA_REQUEST_TIMEOUT
from utils.time_utils import utc_iso_timestamp

# ---------------------------------------------------------------------------
# In-memory store  (projectId -> session dict)
# ---------------------------------------------------------------------------
_capture_sessions: dict = {}


# ---------------------------------------------------------------------------
# In-memory operations
# ---------------------------------------------------------------------------

def create_or_update_session(
    project_id: str,
    capture_id: str = None,
    extra: dict = None,
) -> dict:
    """
    Upsert a CaptureSession in the in-memory store.

    - Creates a default session structure when the project has no session yet.
    - Updates captureId if provided.
    - Merges all keys from *extra* (skipping None values).

    Returns the updated session dict, or None if project_id is missing.
    """
    if not project_id:
        return None

    session = _capture_sessions.get(project_id, {
        "projectId":        project_id,
        "captureId":        capture_id or "",
        "packetCount":      0,
        "analysis":         {},
        "timeline":         [],
        "alerts":           [],
        "iocs":             [],
        "correlations":     [],
        "mitre":            [],
        "riskRanking":      [],
        "attackStory":      {},
        "investigationPlan": {},
        "executiveReport":  "",
        "createdAt":        utc_iso_timestamp(),
    })

    if capture_id:
        session["captureId"] = capture_id

    if extra:
        for key, value in extra.items():
            if value is not None:
                session[key] = value

    _capture_sessions[project_id] = session
    print("=== CAPTURE SESSION SAVED ===")
    return session


def get_session(project_id: str) -> dict:
    """
    Return the in-memory CaptureSession for *project_id*, or None.
    """
    session = _capture_sessions.get(project_id)
    if session:
        print("=== CAPTURE SESSION RESTORED ===")
    return session


def clear_session(project_id: str) -> dict:
    """
    Remove the in-memory CaptureSession for *project_id*.
    Returns a status dict.
    """
    if project_id in _capture_sessions:
        del _capture_sessions[project_id]
    print("=== CAPTURE SESSION RESET ===")
    return {"status": "reset", "projectId": project_id}


# ---------------------------------------------------------------------------
# File-based session operations
# ---------------------------------------------------------------------------

def _session_filename(project_id: str) -> str:
    return f"session_{project_id}.json"


def load_session_from_file(project_id: str) -> dict:
    """
    Load a CaptureSession from a JSON file on disk.
    Returns the session dict, or None if the file does not exist / cannot be read.
    """
    filename = _session_filename(project_id)

    # Try cwd first, then the directory of this module
    candidates = [
        filename,
        os.path.join(os.path.dirname(__file__), filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"=== SESSION FILE READ ERROR {path}: {e} ===")
    return None


def save_session_to_file(project_id: str, data: dict) -> dict:
    """
    Write a CaptureSession dict to a JSON file on disk.
    Returns {"status": "saved"} on success, {"error": ...} on failure.
    """
    filename = _session_filename(project_id)
    try:
        with open(filename, "w") as f:
            json.dump(data, f)
        return {"status": "saved"}
    except Exception as e:
        return {"error": f"Failed to save session: {str(e)}"}


def delete_session_file(project_id: str) -> dict:
    """
    Delete the JSON session file for *project_id*.
    Returns {"status": "deleted"}, {"status": "no_session"}, or {"error": ...}.
    """
    filename = _session_filename(project_id)
    if os.path.exists(filename):
        try:
            os.remove(filename)
            return {"status": "deleted"}
        except Exception as e:
            return {"error": f"Failed to delete session file: {str(e)}"}
    return {"status": "no_session"}


def session_file_exists(project_id: str) -> bool:
    """Return True if a file-based session exists for *project_id*."""
    filename = _session_filename(project_id)
    return os.path.exists(filename) or os.path.exists(
        os.path.join(os.path.dirname(__file__), filename)
    )


# ---------------------------------------------------------------------------
# Prisma API operations
# ---------------------------------------------------------------------------

def persist_session_to_prisma(project_id: str, session: dict):
    """
    PUT the CaptureSession to the Prisma-backed Node API.
    Returns the response dict on success, None on failure.
    """
    if not project_id or not session:
        return None

    url = f"{PRISMA_API_BASE_URL}/api/projects/{project_id}/capture-session"
    payload = {
        "captureId":        session.get("captureId"),
        "packetCount":      session.get("packetCount", 0),
        "analysis":         session.get("analysis"),
        "assets":           session.get("assets") or (session.get("analysis") or {}).get("assets"),
        "timeline":         session.get("timeline"),
        "alerts":           session.get("alerts"),
        "iocs":             session.get("iocs"),
        "correlations":     session.get("correlations"),
        "mitre":            session.get("mitre"),
        "riskRanking":      session.get("riskRanking"),
        "attackStory":      session.get("attackStory"),
        "investigationPlan": session.get("investigationPlan"),
        "executiveReport":  session.get("executiveReport"),
    }

    print(f"=== DEBUG: Calling PRISMA PUT {url} for project={project_id} ===")
    try:
        print("=== DEBUG: Payload keys:", list(payload.keys()))
        response = requests.put(url, json=payload, timeout=PRISMA_REQUEST_TIMEOUT)
        print(f"=== DEBUG: PRISMA PUT response status={response.status_code} ===")
        print("=== DEBUG: PRISMA PUT response body ===")
        print(response.text)

        if response.status_code not in (200, 201):
            print(
                f"=== PRISMA CAPTURE SESSION SAVE FAILED "
                f"status={response.status_code} body={response.text} ==="
            )
            return None
        print("=== PRISMA CAPTURE SESSION SAVED SUCCESSFULLY ===")
        return response.json()
    except Exception as e:
        print(f"=== PRISMA CAPTURE SESSION SAVE EXCEPTION: {str(e)} ===")
        return None


def fetch_session_from_prisma(project_id: str) -> dict:
    """
    GET the CaptureSession from the Prisma-backed Node API.
    Returns the session dict on success, None on failure.
    """
    if not project_id:
        return None

    url = f"{PRISMA_API_BASE_URL}/api/projects/{project_id}/capture-session"
    try:
        response = requests.get(url, timeout=PRISMA_REQUEST_TIMEOUT)
        if response.status_code != 200:
            print(
                f"=== PRISMA CAPTURE SESSION FETCH FAILED "
                f"status={response.status_code} body={response.text} ==="
            )
            return None
        session = response.json()
        print(f"=== PRISMA CAPTURE SESSION LOADED for project {project_id} ===")
        return session
    except Exception as e:
        print(f"=== PRISMA CAPTURE SESSION FETCH EXCEPTION: {str(e)} ===")
        return None
