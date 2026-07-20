"""
NetFusion Backup & Recovery Engine
Database snapshots, configuration archives, workflow exports, investigation bundles, and restore procedures.
"""

import os
import shutil
import json
import time
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional

from netfusion_workflow.service import WorkflowService


class BackupRecoveryError(Exception):
    """Raised on backup or restore failure."""
    pass


class BackupManager:
    """Manages system backups, exports, and restoration procedures."""

    def __init__(self, backup_root: str = "backups"):
        self.backup_root = Path(backup_root)
        self.backup_root.mkdir(parents=True, exist_ok=True)

    def backup_database(self, db_path: str = "dev.db") -> Path:
        """Create a timestamped snapshot of the SQLite database."""
        src = Path(db_path)
        if not src.exists():
            raise BackupRecoveryError(f"Database file '{db_path}' not found")

        timestamp = int(time.time())
        dest = self.backup_root / f"db_backup_{timestamp}.db"
        shutil.copy2(src, dest)
        return dest

    def backup_configuration(self, config_dir: str = ".") -> Path:
        """Archive configuration files (netfusion.yaml, .env) into a backup zip."""
        timestamp = int(time.time())
        archive_path = self.backup_root / f"config_backup_{timestamp}.zip"

        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for candidate in ["netfusion.yaml", "netfusion.yml", "netfusion.json", ".env"]:
                if os.path.exists(candidate):
                    zf.write(candidate)

        return archive_path

    def export_investigation(self, workflow_service: WorkflowService, case_id: str) -> Path:
        """Export complete investigation bundle (Case, Investigation, Evidence, Timelines, Audit)."""
        case = workflow_service.get_case(case_id)
        if not case:
            raise BackupRecoveryError(f"Case '{case_id}' not found for export")

        inv = workflow_service.get_active_investigation_for_case(case_id)
        timeline = workflow_service.get_timeline(inv.id) if inv else []
        evidence = workflow_service.get_evidence_for_case(case_id)

        export_dict = {
            "case": case.__dict__,
            "investigation": inv.__dict__ if inv else None,
            "timeline": [t.__dict__ for t in timeline],
            "evidence": [e.__dict__ for e in evidence],
            "exported_at": time.time(),
        }

        timestamp = int(time.time())
        export_file = self.backup_root / f"investigation_export_{case_id[:8]}_{timestamp}.json"
        export_file.write_text(json.dumps(export_dict, default=str, indent=2), encoding="utf-8")
        return export_file

    def restore_database(self, backup_db_path: str, target_db_path: str = "dev.db") -> None:
        """Restore database from backup snapshot."""
        src = Path(backup_db_path)
        if not src.exists():
            raise BackupRecoveryError(f"Backup file '{backup_db_path}' does not exist")

        shutil.copy2(src, Path(target_db_path))
