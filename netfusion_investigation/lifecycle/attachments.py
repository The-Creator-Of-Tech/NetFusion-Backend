"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Attachment Manager

Dedicated module for managing investigation file attachments, content-type handling,
and checksum validation.
"""

from datetime import datetime, timezone
import hashlib
import os
import threading
from typing import Dict, List, Optional, Union
import uuid

from netfusion_investigation.lifecycle.models import Attachment


class AttachmentManager:
    """Manages file attachments attached to investigations."""

    def __init__(self, storage_dir: Optional[str] = None):
        self._storage_dir = storage_dir or os.path.join(os.getcwd(), "data", "attachments")
        os.makedirs(self._storage_dir, exist_ok=True)
        self._attachments: Dict[str, Attachment] = {}
        self._lock = threading.RLock()

    def _compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def add_attachment(
        self,
        investigation_id: str,
        filename: str,
        content: Union[str, bytes],
        content_type: str = "application/octet-stream",
        attached_by: str = "analyst",
    ) -> Attachment:
        with self._lock:
            data_bytes = content.encode("utf-8") if isinstance(content, str) else content
            checksum = self._compute_sha256(data_bytes)
            att_id = f"att-{uuid.uuid4().hex[:12]}"

            safe_filename = f"{att_id}_{filename.replace('/', '_').replace('\\', '_')}"
            storage_path = os.path.join(self._storage_dir, safe_filename)
            with open(storage_path, "wb") as f:
                f.write(data_bytes)

            attachment = Attachment(
                id=att_id,
                investigation_id=investigation_id,
                filename=filename,
                file_size=len(data_bytes),
                checksum_sha256=checksum,
                content_type=content_type,
                attached_by=attached_by,
                attached_at=datetime.now(timezone.utc).isoformat(),
                storage_path=storage_path,
            )
            self._attachments[att_id] = attachment
            return attachment

    def get_attachment(self, attachment_id: str) -> Optional[Attachment]:
        with self._lock:
            return self._attachments.get(attachment_id)

    def list_attachments(self, investigation_id: str) -> List[Attachment]:
        with self._lock:
            res = [a for a in self._attachments.values() if a.investigation_id == investigation_id]
            res.sort(key=lambda x: x.attached_at)
            return res

    def get_attachment_content(self, attachment_id: str) -> Optional[bytes]:
        with self._lock:
            att = self.get_attachment(attachment_id)
            if not att or not att.storage_path or not os.path.exists(att.storage_path):
                return None
            with open(att.storage_path, "rb") as f:
                return f.read()

    def verify_checksum(self, attachment_id: str) -> bool:
        with self._lock:
            att = self.get_attachment(attachment_id)
            if not att or not att.storage_path or not os.path.exists(att.storage_path):
                return False
            with open(att.storage_path, "rb") as f:
                data = f.read()
            return self._compute_sha256(data) == att.checksum_sha256

    def delete_attachment(self, attachment_id: str) -> bool:
        with self._lock:
            att = self._attachments.get(attachment_id)
            if not att:
                return False
            if att.storage_path and os.path.exists(att.storage_path):
                try:
                    os.remove(att.storage_path)
                except OSError:
                    pass
            del self._attachments[attachment_id]
            return True

    def clear(self) -> None:
        with self._lock:
            self._attachments.clear()
